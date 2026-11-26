//! Listener bind + h3 server boot.
//!
//! Wires the [`MsQuicEngine`] listener to an h3 server per accepted QUIC
//! connection. Each connection accepts requests in a loop: WS-over-H3
//! CONNECTs run side by side, and one WebTransport CONNECT to the configured
//! wisp-wt endpoint runs [`PreUpgradePolicy`], accepts the
//! [`WebTransportSession`], runs [`negotiate_handshake`] on the first bidi
//! and then [`SessionDispatch`] on it. Refused requests get a status.
//!
//! The actual TCP/UDP bridging hot path is handled by tasks spawned per
//! accepted bidi/uni/datagram from the WT session — see [`session_loop`].

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use h3::quic::{
    BidiStream as H3BidiStream, RecvStream as _, SendStream as _, SendStreamUnframed as _,
};
use h3::server::RequestStream;
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use http::{HeaderMap, Method, StatusCode};
use msquic::{Addr, BufferRef, Connection, Listener, ListenerEvent};
use parking_lot::Mutex;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};
use wisp_config::{
    endpoint_matches, endpoint_path_token, normalize_endpoint, token_principal, WispAuthRegistry,
    WispServerOptions, WispWtServerOptions, WISP_BASE_LIMIT_PROFILE,
};
use wisp_dos::{
    datagram_limit_decision, is_dns_resolution_allowed, is_tcp_stream_open_allowed,
    ConnectionDosGuard, ConnectionGuard, ConnectionLimiter, DatagramDecision, DosGuard,
    TcpByteLimiter,
};
use wisp_inspect::{InspectionDecision, Inspector};
use wisp_iphash::IpHashBans;
use wisp_proxy::{HostPolicy, TcpConnector};
use wisp_quic_msquic::adapter::MsQuicConnection;
use wisp_quic_msquic::engine::{EngineConfig, EngineError, MsQuicEngine};
use wisp_reports::{emit_report, ConnectionContext, ReportErrorType, ReportInput, Transport};
use wisp_tun::{Binding, TunnelService};
use wisp_wire::{
    datagram_class, datagram_kind, encode_control_frame, try_parse_bidi_stream_header,
    BidiStreamKind, Extension, IpTunnel, ProxyControl, TunnelClose, TunnelFrame, UdpClose,
    UdpOpenFrame, WebTransportProxy, WtProxyClose,
};
use wisp_wisp_server::{
    handle_proxy_control_text, ProxyController, ProxyControllerTemplate, ServerOptions,
};
use wisp_ws_h3::{serve_h3_websocket, H3WsContext};

use crate::control::{ControlOutcome, ControlSink, SessionDispatch};
use crate::handshake::{ControlIo, ControlIoError, HandshakeError};
use crate::policy::PreUpgradePolicy;
use crate::session::SessionContext;
use crate::tunnel_flow::{TunnelFlows, TunnelOutput, TunnelSession, UniDecoder, TUNNEL_UNI_QUEUE};
use crate::udp_flow::{UdpFlowHandle, UdpFlowRegistry};
use crate::wt_proxy::{WtProxyError, WtProxyRegistry, WtProxySession};

const ALPN_H3: &str = "h3";
/// Largest HTTP/3 field section (request header block) the server decodes.
/// h3 counts each field as its name and value plus 32 bytes (RFC 9114 section
/// 4.2.2) and answers a larger block with 431 before building a header map,
/// so a request cannot carry the tens of thousands of fields that make
/// `http::HeaderMap` panic. A wisp CONNECT needs well under 1 KiB.
const MAX_FIELD_SECTION_BYTES: u64 = 16 * 1024;
/// Hard cap on a single wisp-wt control-bidi frame body. The 4-byte length
/// prefix is attacker-controlled (up to ~4 GiB); without this bound a client
/// could declare a huge frame and force `rx_buf` to grow unbounded (or drip
/// bytes forever), an unauthenticated memory-exhaustion / slowloris vector.
/// Control messages are small; the data path uses separate streams/datagrams.
const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
const DATAGRAM_EGRESS_QUEUE_CAPACITY: usize =
    wisp_wire::WISP_WT_PROXY_UPSTREAM_DATAGRAM_HIGH_WATER_MARK as usize;
const UDP_FLOW_QUEUE_CAPACITY: usize = 64;
const RAW_CONNECTION_FALLBACK_CAP: u64 = 4096;
const RAW_CONNECTION_PER_IP_FALLBACK_CAP: u64 = 256;
/// How long a rejection response may take to go out before the stream is
/// dropped instead.
const REJECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a finished session waits for its stream, flow and proxy tasks to
/// observe cancellation before it releases its connection slot anyway.
const SESSION_TASK_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the uni-stream accept looks again for a stream it was not woken
/// for (see `accept_uni_streams`).
const UNI_ACCEPT_RETRY: Duration = Duration::from_millis(250);
/// Requests one connection may have refused before it is closed. Each refusal
/// can cost a token lookup, so a client must not keep one connection open
/// just to make them.
const MAX_REFUSED_REQUESTS: u32 = 8;
/// Wisp close reasons, also used as UDP_CLOSE reasons and stream reset codes.
const CLOSE_NETWORK_ERROR: u8 = 0x03;
const CLOSE_HOST_BLOCKED: u8 = 0x48;
const CLOSE_THROTTLED: u8 = 0x49;
/// Most client chunks one TCP bridge writes upstream together, and the most
/// bytes. See [`write_all_chunks`].
const WT_COALESCE_MAX_CHUNKS: usize = 64;
const WT_COALESCE_MAX_BYTES: usize = 256 * 1024;

/// Writes every chunk in order with as few vectored writes as the socket
/// allows, leaving `chunks` advanced past what was written on error.
async fn write_all_chunks<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    chunks: &mut [Bytes],
) -> std::io::Result<()> {
    let mut first = 0;
    while first < chunks.len() {
        let pending = &chunks[first..];
        let written = if pending.len() == 1 {
            writer.write(&pending[0]).await?
        } else {
            let count = pending.len().min(WT_COALESCE_MAX_CHUNKS);
            let slices: [std::io::IoSlice<'_>; WT_COALESCE_MAX_CHUNKS] =
                std::array::from_fn(|index| match pending.get(index) {
                    Some(chunk) if index < count => std::io::IoSlice::new(chunk),
                    _ => std::io::IoSlice::new(&[]),
                });
            writer.write_vectored(&slices[..count]).await?
        };
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let mut left = written;
        while left > 0 {
            let chunk = &mut chunks[first];
            if left < chunk.len() {
                chunk.advance(left);
                left = 0;
            } else {
                left -= chunk.len();
                first += 1;
            }
        }
    }
    Ok(())
}

type RequestBidi = <MsQuicConnection as h3::quic::OpenStreams<Bytes>>::BidiStream;

struct DatagramEgress {
    queued_at: Instant,
    frame: Bytes,
}

impl DatagramEgress {
    fn new(frame: Bytes) -> Self {
        Self {
            queued_at: Instant::now(),
            frame,
        }
    }
}

#[derive(Debug, Error)]
pub enum ServeError {
    #[error("engine: {0}")]
    Engine(#[from] EngineError),
    #[error("listener start: {0}")]
    Start(#[source] msquic::Status),
    #[error("missing TLS cert/key path in [wisp_wt]")]
    MissingTls,
}

/// Live serve state. Drop, or call [`ServeHandle::shutdown`], to stop the
/// listener and end every session.
///
/// Teardown asks msquic to close every connection first, then waits until it
/// has released them. Dropped on a multi-thread runtime it waits in
/// `block_in_place`, so the runtime keeps running the tasks that release the
/// connections; on a current-thread runtime the wait moves to its own thread.
/// [`ServeHandle::close_blocking`] waits on the calling thread instead, for a
/// caller already off the runtime.
pub struct ServeHandle {
    teardown: Option<Teardown>,
    cancel: CancellationToken,
}

/// The msquic handles a [`ServeHandle`] owns, closed in field order: the
/// listener before the engine, whose registration waits for every listener
/// and connection opened under it.
struct Teardown {
    listener: Listener,
    engine: Arc<MsQuicEngine>,
}

impl Teardown {
    /// Ask msquic to shut down every connection under the registration. Does
    /// not wait, and leaves nothing for the closes below to wait on but the
    /// tasks that hold the connection handles.
    fn begin(&self) {
        self.engine.registration.shutdown();
    }

    /// Close the listener, then the engine. Blocks until msquic has released
    /// every handle opened under the registration.
    fn finish(self) {
        drop(self.listener);
        drop(self.engine);
    }
}

impl ServeHandle {
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn shutdown(self) {
        self.cancel.cancel();
        if let Some(teardown) = self.teardown.as_ref() {
            teardown.listener.stop();
        }
    }

    /// Stop everything and wait, on the calling thread, until msquic has
    /// released every handle. Call it from a blocking thread such as
    /// `spawn_blocking`, never from an async task.
    pub fn close_blocking(mut self) {
        self.cancel.cancel();
        if let Some(teardown) = self.teardown.take() {
            teardown.begin();
            teardown.finish();
        }
    }
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        let Some(teardown) = self.teardown.take() else {
            return;
        };
        teardown.begin();
        match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
                tokio::task::block_in_place(|| teardown.finish());
            }
            // A current-thread runtime runs the tasks that release the
            // connections on this very thread, so waiting here would hang.
            Ok(_) => {
                std::thread::spawn(move || teardown.finish());
            }
            Err(_) => teardown.finish(),
        }
    }
}

/// Optional extras for [`serve`]. Defaults keep the listener WT-only with no
/// proxy-control template.
#[derive(Clone, Default)]
pub struct ServeExtras {
    pub proxy_template: Option<Arc<ProxyControllerTemplate>>,
    /// Banned client IP hashes. Checked when a QUIC connection arrives, before
    /// the handshake, so a banned address never gets a connection; the
    /// WebTransport and WS-over-H3 policies check them again per session.
    pub ip_bans: Arc<IpHashBans>,
    /// The IP tunnel engine (`[ip_tunnel]`). When set, sessions are offered
    /// the IP_TUNNEL extension.
    pub tunnels: Option<Arc<TunnelService>>,
}

/// Raw QUIC connection caps. Handshakes in progress and established
/// connections are counted apart: a slot under `established` is only taken
/// once the peer has finished the handshake, so peers that start handshakes
/// and never finish them cannot hold the slots real clients need.
struct RawAdmission {
    established: Arc<ConnectionLimiter>,
    handshakes: Arc<ConnectionLimiter>,
    total_cap: u64,
    per_ip_cap: u64,
}

impl RawAdmission {
    /// `true` when `client_ip` could take an established slot right now. Only
    /// a pre-check: the slot itself is taken at Connected.
    fn has_room(&self, client_ip: &str) -> bool {
        self.established
            .try_acquire(client_ip, self.total_cap, self.per_ip_cap)
            .is_some()
    }

    fn start_handshake(&self, client_ip: &str) -> Option<ConnectionGuard> {
        self.handshakes
            .try_acquire(client_ip, self.total_cap, self.per_ip_cap)
    }

    fn establish(&self, client_ip: &str) -> Option<ConnectionGuard> {
        self.established
            .try_acquire(client_ip, self.total_cap, self.per_ip_cap)
    }
}

fn client_ip_of(peer: Option<SocketAddr>) -> String {
    peer.map(|address| address.ip().to_string())
        .unwrap_or_else(|| "0.0.0.0".to_owned())
}

/// Ban check for a connection that has not started its handshake. Reports a
/// hit the way the session policies do.
fn refuse_banned(ip_bans: &IpHashBans, client_ip: &str) -> bool {
    let client_hash = wisp_iphash::hash_client_ip_keyed(Some(client_ip));
    if !ip_bans.is_banned(client_hash.as_deref()) {
        return false;
    }
    emit_report(
        ReportErrorType::IpHashBanned,
        ReportInput {
            context: Some(ConnectionContext {
                client_ip: Some(client_ip.to_owned()),
                client_ip_hash: client_hash,
                transport: Some(Transport::Wt),
                origin: None,
            }),
            ..Default::default()
        },
    );
    true
}

fn connection_refused() -> msquic::Status {
    msquic::Status::new(msquic::StatusCode::QUIC_STATUS_CONNECTION_REFUSED)
}

/// Bind the msquic listener and start dispatching sessions.
///
/// `ws_ctx`, when present, enables WS-over-H3 (RFC 9220) on the same
/// listener: requests with `:method = CONNECT` and `:protocol = websocket`
/// at the WS endpoint are dispatched to [`serve_h3_websocket`] instead of
/// the WT path. `None` keeps the listener WT-only.
#[allow(unsafe_code)]
pub async fn serve(
    options: Arc<WispWtServerOptions>,
    dos: Arc<DosGuard>,
    cancel: CancellationToken,
    ws_ctx: Option<Arc<H3WsContext>>,
    connection_limiter: Arc<ConnectionLimiter>,
    auth_registry: WispAuthRegistry,
    extras: ServeExtras,
) -> Result<ServeHandle, ServeError> {
    let cert_path = options.cert_path.clone().ok_or(ServeError::MissingTls)?;
    let key_path = options.key_path.clone().ok_or(ServeError::MissingTls)?;

    let engine_cfg = EngineConfig {
        registration_name: "wispd".to_owned(),
        alpns: vec![ALPN_H3.to_owned()],
        cert_path,
        key_path,
        // A session uses two bidi streams of its own (the CONNECT request and
        // the wisp-wt control stream) on top of its data streams.
        peer_bidi_stream_count: if options.base.stream_limit_total == 0 {
            EngineConfig::default().peer_bidi_stream_count
        } else {
            options
                .base
                .stream_limit_total
                .saturating_add(2)
                .min(u64::from(u16::MAX)) as u16
        },
        // 0 disables the idle timeout, which is msquic's meaning of 0 too.
        idle_timeout_ms: options.base.idle_timeout_ms.unwrap_or(60_000),
        ..EngineConfig::default()
    };
    let engine = Arc::new(MsQuicEngine::new(&engine_cfg)?);
    let configuration = engine.configuration.clone();

    let admission = Arc::new(RawAdmission {
        established: Arc::new(ConnectionLimiter::new()),
        handshakes: Arc::new(ConnectionLimiter::new()),
        total_cap: if options.base.max_connections == 0 {
            RAW_CONNECTION_FALLBACK_CAP
        } else {
            options.base.max_connections
        },
        per_ip_cap: if options.base.max_connections_per_ip == 0 {
            RAW_CONNECTION_PER_IP_FALLBACK_CAP
        } else {
            options.base.max_connections_per_ip
        },
    });
    let channel_capacity = usize::try_from(admission.total_cap)
        .unwrap_or(usize::MAX)
        .clamp(1, RAW_CONNECTION_FALLBACK_CAP as usize);
    let (conn_tx, conn_rx) =
        mpsc::channel::<(MsQuicConnection, Option<SocketAddr>, ConnectionGuard)>(channel_capacity);

    // The listener callback runs on an msquic worker thread with no Tokio
    // context, so hand it the runtime that `serve` was called on.
    let runtime = tokio::runtime::Handle::current();
    let listener_admission = admission.clone();
    let listener_bans = extras.ip_bans.clone();
    let engine_listener = engine.open_listener(move |_, ev| {
        if let ListenerEvent::NewConnection { info, connection } = ev {
            let peer = info.remote_address.as_socket();
            let client_ip = client_ip_of(peer);
            // Refusing returns an error without taking the handle, so msquic
            // closes the connection itself with CONNECTION_REFUSED. msquic
            // only gets here for a validated address: Retry is on for every
            // new address (see `EngineConfig::retry_memory_limit`).
            if refuse_banned(&listener_bans, &client_ip) {
                debug!(client_ip = %client_ip, "wisp: QUIC connection refused: banned IP hash");
                return Err(connection_refused());
            }
            if !listener_admission.has_room(&client_ip) {
                debug!(client_ip = %client_ip, "wisp: QUIC connection refused: connection cap");
                return Err(connection_refused());
            }
            let Some(handshake) = listener_admission.start_handshake(&client_ip) else {
                debug!(client_ip = %client_ip, "wisp: QUIC connection refused: handshake cap");
                return Err(connection_refused());
            };
            // SAFETY: msquic transferred ownership in the listener callback.
            // We own the handle from this point; MsQuicConnection holds it
            // inside an Arc<Connection> for the connection lifetime.
            let owned: Connection = unsafe { Connection::from_raw(connection.as_raw()) };
            if let Err(status) = owned.set_configuration(&configuration) {
                warn!(?status, "set_configuration failed; rejecting connection");
                drop(owned);
                return Ok(());
            }
            let ms_conn = MsQuicConnection::install(owned, runtime.clone());
            if conn_tx.try_send((ms_conn, peer, handshake)).is_err() {
                debug!("raw QUIC admission queue full; dropping new connection");
            }
        }
        Ok(())
    })?;

    let local_addr: SocketAddr = format!("{}:{}", options.host, options.port)
        .parse()
        .map_err(|_| {
            ServeError::Start(msquic::Status::new(
                msquic::StatusCode::QUIC_STATUS_INVALID_PARAMETER,
            ))
        })?;
    let alpn_refs = [BufferRef::from(ALPN_H3)];
    let handle = ServeHandle {
        teardown: Some(Teardown {
            listener: engine_listener,
            engine,
        }),
        cancel: cancel.clone(),
    };
    if let Some(teardown) = handle.teardown.as_ref() {
        teardown
            .listener
            .start(&alpn_refs, Some(&Addr::from(local_addr)))
            .map_err(ServeError::Start)?;
    }

    info!(addr = %local_addr, "wisp: listener bound");

    let acceptor_cancel = cancel.clone();
    tokio::spawn(connection_acceptor(
        conn_rx,
        admission,
        options,
        dos,
        acceptor_cancel,
        ws_ctx,
        connection_limiter,
        auth_registry,
        extras.proxy_template,
        extras.tunnels,
        extras.ip_bans,
    ));

    Ok(handle)
}

async fn connection_acceptor(
    mut rx: mpsc::Receiver<(MsQuicConnection, Option<SocketAddr>, ConnectionGuard)>,
    admission: Arc<RawAdmission>,
    options: Arc<WispWtServerOptions>,
    dos: Arc<DosGuard>,
    cancel: CancellationToken,
    ws_ctx: Option<Arc<H3WsContext>>,
    connection_limiter: Arc<ConnectionLimiter>,
    auth_registry: WispAuthRegistry,
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
    tunnels: Option<Arc<TunnelService>>,
    ip_bans: Arc<IpHashBans>,
) {
    let handshake_timeout =
        Duration::from_millis(options.base.handshake_timeout_ms.unwrap_or(10_000).max(1));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("wisp: cancel received, exiting acceptor");
                return;
            }
            maybe = rx.recv() => {
                let Some((ms_conn, peer, handshake)) = maybe else {
                    info!("wisp: connection channel closed");
                    return;
                };
                let admission = admission.clone();
                let opts = options.clone();
                let dos = dos.clone();
                let ws_ctx = ws_ctx.clone();
                let connection_limiter = connection_limiter.clone();
                let auth_registry = auth_registry.clone();
                let proxy_template = proxy_template.clone();
                let tunnels = tunnels.clone();
                let ip_bans = ip_bans.clone();
                let connection_cancel = cancel.child_token();
                tokio::spawn(async move {
                    let result = tokio::select! {
                        _ = connection_cancel.cancelled() => return,
                        result = async {
                            let client_ip = client_ip_of(peer);
                            let Some(raw_guard) = admit_connected(
                                &ms_conn,
                                &client_ip,
                                handshake,
                                &admission,
                                handshake_timeout,
                            )
                            .await
                            else {
                                return Ok(());
                            };
                            handle_connection(
                                ms_conn,
                                peer,
                                raw_guard,
                                opts,
                                dos,
                                ws_ctx,
                                connection_limiter,
                                auth_registry,
                                proxy_template,
                                tunnels,
                                ip_bans,
                            )
                            .await
                        } => result,
                    };
                    if let Err(e) = result {
                        debug!(error = %e, "wisp: connection handler ended");
                    }
                });
            }
        }
    }
}

/// Wait for the handshake, then trade the handshake slot for an established
/// one. `None` when the handshake failed or timed out, or when the caps filled
/// up meanwhile; the connection is then closed.
async fn admit_connected(
    ms_conn: &MsQuicConnection,
    client_ip: &str,
    handshake: ConnectionGuard,
    admission: &RawAdmission,
    handshake_timeout: Duration,
) -> Option<ConnectionGuard> {
    let connected = tokio::time::timeout(handshake_timeout, ms_conn.connected()).await;
    drop(handshake);
    if !matches!(connected, Ok(Ok(()))) {
        debug!(client_ip = %client_ip, "wisp: QUIC handshake did not complete");
        return None;
    }
    let guard = admission.establish(client_ip);
    if guard.is_none() {
        debug!(client_ip = %client_ip, "wisp: QUIC connection closed: connection cap");
        ms_conn.close_with_code(h3::error::Code::H3_EXCESSIVE_LOAD.value());
    }
    guard
}

/// Wait until the peer's SETTINGS frame has been read.
///
/// h3 hands out a request as soon as its stream opens, and the peer's control
/// stream is a separate stream that can arrive later. `WebTransportSession::accept`
/// checks the peer's settings, and before they arrive it sees h3's defaults,
/// which do not enable WebTransport, so it refuses a client that does support
/// it. SETTINGS must be the first frame on the control stream (RFC 9114
/// section 6.2.1), so this reads nothing past it.
async fn await_peer_settings(
    conn: &mut h3::server::Connection<MsQuicConnection, Bytes>,
) -> Result<(), h3::error::ConnectionError> {
    let shared = conn.inner.shared.clone();
    std::future::poll_fn(|cx| loop {
        // The shared settings are borrowed once the peer's have been stored
        // and an owned default until then.
        if matches!(
            h3::ConnectionState::settings(&*shared),
            std::borrow::Cow::Borrowed(_)
        ) {
            return std::task::Poll::Ready(Ok(()));
        }
        match conn.inner.poll_control(cx) {
            std::task::Poll::Ready(Ok(_)) => {}
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    })
    .await
}

/// Answer a request the server will not serve with `status` and end the
/// stream, so the client learns why instead of seeing a silent reset.
async fn reject_request(
    mut stream: RequestStream<RequestBidi, Bytes>,
    status: StatusCode,
    headers: HeaderMap,
) {
    let mut response = http::Response::new(());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    let _ = tokio::time::timeout(REJECT_RESPONSE_TIMEOUT, async {
        stream.send_response(response).await?;
        stream.finish().await
    })
    .await;
}

/// A WebTransport CONNECT that passed every pre-upgrade check.
struct AdmittedWt {
    request: http::Request<()>,
    stream: RequestStream<RequestBidi, Bytes>,
    options: Arc<WispServerOptions>,
    allowed_proxy_providers: Option<Vec<String>>,
    client_hash: Option<String>,
    conn_guard: ConnectionGuard,
}

/// Serves one QUIC connection. Requests are accepted in a loop: every
/// WS-over-H3 CONNECT gets its own task and connection slot, and a
/// WebTransport CONNECT takes over the connection (h3-webtransport supports
/// one session per connection), after which further requests are refused
/// with a status. The connection stays open until every session on it ends.
async fn handle_connection(
    ms_conn: MsQuicConnection,
    peer: Option<SocketAddr>,
    _raw_guard: ConnectionGuard,
    options: Arc<WispWtServerOptions>,
    dos: Arc<DosGuard>,
    ws_ctx: Option<Arc<H3WsContext>>,
    connection_limiter: Arc<ConnectionLimiter>,
    auth_registry: WispAuthRegistry,
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
    tunnels: Option<Arc<TunnelService>>,
    ip_bans: Arc<IpHashBans>,
) -> Result<(), HandlerError> {
    let handshake_timeout =
        Duration::from_millis(options.base.handshake_timeout_ms.unwrap_or(10_000).max(1));
    let mut h3_conn: h3::server::Connection<MsQuicConnection, Bytes> = tokio::time::timeout(
        handshake_timeout,
        h3::server::builder()
            .max_field_section_size(MAX_FIELD_SECTION_BYTES)
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(1)
            .build(ms_conn),
    )
    .await
    .map_err(|_| HandlerError::H3Build("timed out".to_owned()))?
    .map_err(|e| HandlerError::H3Build(format!("{e:?}")))?;

    let client_ip = client_ip_of(peer);
    let mut ws_sessions: JoinSet<()> = JoinSet::new();
    let mut refused = 0u32;
    let admitted = loop {
        if refused >= MAX_REFUSED_REQUESTS {
            debug!(client_ip = %client_ip, "wisp: too many refused requests on one connection");
            break None;
        }
        // With no session running, a connection that sends no request is
        // closed after the handshake timeout. While WS-over-H3 sessions run,
        // the next request may come at any time.
        let request_wait = if ws_sessions.is_empty() {
            handshake_timeout
        } else {
            Duration::MAX
        };
        let accepted = tokio::select! {
            Some(_) = ws_sessions.join_next(), if !ws_sessions.is_empty() => continue,
            accepted = tokio::time::timeout(request_wait, h3_conn.accept()) => accepted,
        };
        let resolver = match accepted {
            Ok(Ok(Some(resolver))) => resolver,
            Ok(Ok(None)) => break None,
            Ok(Err(e)) => {
                debug!(error = ?e, "wisp: h3 accept ended");
                break None;
            }
            Err(_) => {
                debug!(client_ip = %client_ip, "wisp: no request before the handshake timeout");
                break None;
            }
        };
        // A request stream that fails to resolve (431 for an oversized header
        // block, malformed headers) costs only that stream.
        let (request, stream) =
            match tokio::time::timeout(handshake_timeout, resolver.resolve_request()).await {
                Ok(Ok(resolved)) => resolved,
                Ok(Err(e)) => {
                    debug!(error = ?e, "wisp: h3 request rejected");
                    refused += 1;
                    continue;
                }
                Err(_) => {
                    debug!("wisp: h3 request headers timed out");
                    refused += 1;
                    continue;
                }
            };

        let protocol = request.extensions().get::<Protocol>();
        let is_connect = request.method() == Method::CONNECT;
        if is_connect && protocol == Some(&Protocol::WEBSOCKET) {
            match admit_ws(&request, &client_ip, ws_ctx.as_ref(), &dos).await {
                Ok((ctx, view, conn_guard, client_advertises_v2)) => {
                    debug!(client_ip = %client_ip, "wisp: dispatching WS-over-H3");
                    let client_ip = client_ip.clone();
                    ws_sessions.spawn(async move {
                        let _conn_guard = conn_guard;
                        if let Err(e) =
                            serve_h3_websocket(stream, client_ip, ctx, view, client_advertises_v2)
                                .await
                        {
                            debug!(error = %e, "wisp: WS-over-H3 session ended");
                        }
                    });
                }
                Err((status, headers)) => {
                    refused += 1;
                    reject_request(stream, status, headers).await;
                }
            }
            continue;
        }
        if is_connect && protocol == Some(&Protocol::WEB_TRANSPORT) {
            match admit_wt(
                &request,
                &client_ip,
                &options,
                &dos,
                &connection_limiter,
                &auth_registry,
                &ip_bans,
            )
            .await
            {
                Ok(admission) => {
                    break Some(AdmittedWt {
                        request,
                        stream,
                        options: admission.0,
                        allowed_proxy_providers: admission.1,
                        client_hash: admission.2,
                        conn_guard: admission.3,
                    })
                }
                Err((status, headers)) => {
                    refused += 1;
                    reject_request(stream, status, headers).await;
                }
            }
            continue;
        }
        refused += 1;
        debug!(method = ?request.method(), path = ?request.uri().path(), "rejecting non-wisp request");
        reject_request(stream, StatusCode::NOT_FOUND, HeaderMap::new()).await;
    };

    match admitted {
        Some(admitted) => {
            serve_webtransport(
                h3_conn,
                admitted,
                client_ip,
                &options,
                dos,
                proxy_template,
                tunnels,
                &mut ws_sessions,
                handshake_timeout,
            )
            .await
        }
        None => {
            // Keep the connection open for the WS sessions still running.
            while ws_sessions.join_next().await.is_some() {}
            drop(h3_conn);
            Ok(())
        }
    }
}

type WsAdmission = (
    H3WsContext,
    wisp_ws_h3::dispatch::H3WsConnectionView,
    ConnectionGuard,
    bool,
);

/// Pre-upgrade checks for a WS-over-H3 CONNECT. `Err` carries the status and
/// headers to answer with.
async fn admit_ws(
    request: &http::Request<()>,
    client_ip: &str,
    ws_ctx: Option<&Arc<H3WsContext>>,
    dos: &Arc<DosGuard>,
) -> Result<WsAdmission, (StatusCode, HeaderMap)> {
    let path = request.uri().path();
    let Some(ctx) = ws_ctx else {
        debug!(path = ?path, "wisp: WS-over-H3 request but ws_ctx not configured");
        return Err((StatusCode::NOT_FOUND, HeaderMap::new()));
    };
    let Some(view) = ctx.context_for_path(path).await else {
        debug!(path = ?path, "wisp: WS endpoint or authentication rejected");
        return Err((StatusCode::FORBIDDEN, HeaderMap::new()));
    };
    let policy =
        PreUpgradePolicy::new(view.options.clone(), dos.clone()).with_ip_bans(ctx.ip_bans.clone());
    if let Err(rej) = policy.check(request.headers(), client_ip) {
        debug!(reason = rej.reason, "wisp: WS pre-upgrade rejected");
        return Err((rej.status, rej.headers));
    }
    let client_advertises_v2 = request
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| {
                    s.split(',')
                        .any(|p| p.trim().eq_ignore_ascii_case("wisp-v2"))
                })
                .unwrap_or(false)
        });
    let Some(conn_guard) = ctx.connection_limiter.try_acquire(
        client_ip,
        view.options.max_connections,
        view.options.max_connections_per_ip,
    ) else {
        debug!(client_ip = %client_ip, "wisp: rejecting WS-over-H3 concurrency cap");
        return Err((StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new()));
    };
    Ok(((**ctx).clone(), view, conn_guard, client_advertises_v2))
}

type WtAdmission = (
    Arc<WispServerOptions>,
    Option<Vec<String>>,
    Option<String>,
    ConnectionGuard,
);

/// Pre-upgrade checks for a WebTransport CONNECT: endpoint, token, origin, IP
/// and connection caps. `Err` carries the status and headers to answer with.
async fn admit_wt(
    request: &http::Request<()>,
    client_ip: &str,
    options: &WispWtServerOptions,
    dos: &Arc<DosGuard>,
    connection_limiter: &Arc<ConnectionLimiter>,
    auth_registry: &WispAuthRegistry,
    ip_bans: &Arc<IpHashBans>,
) -> Result<WtAdmission, (StatusCode, HeaderMap)> {
    let endpoint = normalize_endpoint(&options.base.endpoint);
    let path = request.uri().path();
    let token = endpoint_path_token(path, &endpoint);
    if token.is_none() && !endpoint_matches(path, &endpoint) {
        debug!(path = ?path, "rejecting WebTransport request outside the endpoint");
        return Err((StatusCode::NOT_FOUND, HeaderMap::new()));
    }
    let (effective_options, allowed_proxy_providers) = if let Some(token) = token {
        if !options.base.auth.token_path {
            debug!("wisp: token paths are disabled");
            return Err((StatusCode::FORBIDDEN, HeaderMap::new()));
        }
        let timeout = Duration::from_millis(options.base.auth.resolver_timeout_ms);
        let resolved = tokio::time::timeout(
            timeout,
            auth_registry.resolve(token.to_owned(), &options.base),
        )
        .await
        .ok()
        .flatten();
        let Some(resolved) = resolved else {
            debug!("wisp: WebTransport authentication rejected");
            return Err((StatusCode::FORBIDDEN, HeaderMap::new()));
        };
        (
            Arc::new(resolved.options),
            resolved.policy.allowed_proxy_providers,
        )
    } else {
        if options.base.auth.required {
            debug!("wisp: WebTransport authentication required");
            return Err((StatusCode::FORBIDDEN, HeaderMap::new()));
        }
        let base = auth_registry
            .profile(WISP_BASE_LIMIT_PROFILE)
            .map(Arc::new)
            .unwrap_or_else(|| Arc::new(options.base.clone()));
        (base, None)
    };

    let policy =
        PreUpgradePolicy::new(effective_options.clone(), dos.clone()).with_ip_bans(ip_bans.clone());
    let client_hash = match policy.check(request.headers(), client_ip) {
        Ok(h) => h,
        Err(rej) => {
            debug!(reason = rej.reason, "wisp: pre-upgrade rejected");
            return Err((rej.status, rej.headers));
        }
    };

    let Some(conn_guard) = connection_limiter.try_acquire(
        client_ip,
        effective_options.max_connections,
        effective_options.max_connections_per_ip,
    ) else {
        debug!(client_ip = %client_ip, "wisp: rejecting: connection concurrency cap");
        return Err((StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new()));
    };
    Ok((
        effective_options,
        allowed_proxy_providers,
        client_hash,
        conn_guard,
    ))
}

/// Accept the admitted WebTransport session and run it to the end, then wait
/// for any WS-over-H3 sessions that were already running on the connection.
async fn serve_webtransport(
    mut h3_conn: h3::server::Connection<MsQuicConnection, Bytes>,
    admitted: AdmittedWt,
    client_ip: String,
    options: &WispWtServerOptions,
    dos: Arc<DosGuard>,
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
    tunnels: Option<Arc<TunnelService>>,
    ws_sessions: &mut JoinSet<()>,
    handshake_timeout: Duration,
) -> Result<(), HandlerError> {
    let AdmittedWt {
        request,
        stream,
        options: effective_options,
        allowed_proxy_providers,
        client_hash,
        conn_guard: _conn_guard,
    } = admitted;
    let principal = endpoint_path_token(
        request.uri().path(),
        &normalize_endpoint(&options.base.endpoint),
    )
    .map(token_principal);
    tokio::time::timeout(handshake_timeout, await_peer_settings(&mut h3_conn))
        .await
        .map_err(|_| HandlerError::WtAccept("peer SETTINGS timed out".to_owned()))?
        .map_err(|e| HandlerError::WtAccept(format!("{e:?}")))?;
    let session = Arc::new(
        WebTransportSession::accept(request, stream, h3_conn)
            .await
            .map_err(|e| HandlerError::WtAccept(format!("{e:?}")))?,
    );
    debug!(client_ip = %client_ip, "wisp: WebTransport session accepted");

    let mut ctx = SessionContext::new(client_ip, effective_options, dos)
        .with_client_hash(client_hash)
        .with_principal(principal);

    let result = session_loop(
        session.clone(),
        &mut ctx,
        SessionSettings {
            wt_proxy_enabled: options.webtransport_proxy_enabled,
            max_proxy_sessions: options.max_proxy_sessions_per_connection,
            max_proxy_substreams: options.max_proxy_substreams_per_session,
            max_datagram_bytes: options.max_datagram_bytes,
            proxy_control_enabled: options.proxy_control_enabled,
            allowed_proxy_providers,
        },
        proxy_template,
        tunnels,
    )
    .await;
    // The session owns the h3 connection, and dropping it closes the QUIC
    // connection, so it stays alive while a WS-over-H3 session still runs.
    while ws_sessions.join_next().await.is_some() {}
    drop(session);
    result
}

/// Per-session settings taken from `[wisp_wt]` and the token's policy.
struct SessionSettings {
    wt_proxy_enabled: bool,
    max_proxy_sessions: u32,
    max_proxy_substreams: u32,
    max_datagram_bytes: u32,
    proxy_control_enabled: bool,
    allowed_proxy_providers: Option<Vec<String>>,
}

async fn session_loop(
    session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    ctx: &mut SessionContext,
    settings: SessionSettings,
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
    tunnels: Option<Arc<TunnelService>>,
) -> Result<(), HandlerError> {
    let SessionSettings {
        wt_proxy_enabled,
        max_proxy_sessions,
        max_proxy_substreams,
        max_datagram_bytes,
        proxy_control_enabled,
        allowed_proxy_providers,
    } = settings;
    let handshake_timeout =
        Duration::from_millis(ctx.options.handshake_timeout_ms.unwrap_or(10_000).max(1));
    let accepted = tokio::time::timeout(handshake_timeout, session.accept_bi())
        .await
        .map_err(|_| HandlerError::ControlAccept("timed out".to_owned()))?
        .map_err(|e| HandlerError::ControlAccept(format!("{e:?}")))?;
    let bidi = match accepted {
        Some(AcceptedBi::BidiStream(_, bidi)) => bidi,
        Some(AcceptedBi::Request(_, stream)) => {
            reject_request(stream, StatusCode::BAD_REQUEST, HeaderMap::new()).await;
            return Err(HandlerError::ControlAccept(
                "first bidi was an HTTP request, not a WT bidi stream".into(),
            ));
        }
        None => return Ok(()),
    };

    let mut control_io: WtControlIo<MsQuicConnection, Bytes> = WtControlIo::new(bidi);
    let mut registry = if ctx.options.allow_udp_streams {
        crate::handshake::default_server_registry()
    } else {
        wisp_wire::ExtensionRegistry::new()
    };
    if wt_proxy_enabled {
        registry.register::<WebTransportProxy>();
    }
    let proxy_controller = if proxy_control_enabled {
        proxy_template.as_ref().map(|template| {
            let server_opts = ServerOptions::from_wisp(&ctx.options, true);
            // The token's provider grants and the per-IP budgets apply here
            // the same way they do on the WebSocket transports.
            let controller =
                template.spawn(server_opts.proxy_control_limits(), allowed_proxy_providers);
            controller.bind_client(&ctx.client_ip, None);
            controller.bind_ip_budget(ctx.client_ip.clone(), ctx.dos.clone());
            controller
        })
    } else {
        None
    };
    if proxy_controller.is_some() {
        registry.register_raw(ProxyControl::ID, Bytes::from_static(br#"{"version":1}"#));
    }
    if let Some(service) = &tunnels {
        registry.register_raw(
            IpTunnel::ID,
            Bytes::from(service.config().server_info(Binding::WebTransport).encode()),
        );
    }
    if let Err(e) = tokio::time::timeout(
        handshake_timeout,
        crate::handshake::negotiate_handshake_with(&mut control_io, ctx, &registry),
    )
    .await
    .map_err(|_| {
        HandlerError::Handshake(HandshakeError::Io(ControlIoError::Io(
            "timed out".to_owned(),
        )))
    })? {
        return Err(HandlerError::Handshake(e));
    }

    debug!(
        negotiated = ?ctx.negotiated.iter().collect::<Vec<_>>(),
        "wisp: handshake complete"
    );

    // Everything the session starts ends with it. `flow_shutdown` is
    // cancelled when the session ends, and also when this future is dropped
    // (the server shutting down), so no task keeps a stream, socket or
    // upstream open after the session's connection slot is released.
    let flow_shutdown = CancellationToken::new();
    let _cancel_on_drop = flow_shutdown.clone().drop_guard();
    let mut session_tasks: JoinSet<()> = JoinSet::new();
    let tasks = TaskTracker::new();

    let (bidi, rx_buf) = control_io.into_inner();
    let (mut control_send, control_recv) = H3BidiStream::<Bytes>::split(bidi);
    let (control_writer_tx, mut control_writer_rx) = mpsc::channel::<Bytes>(64);
    session_tasks.spawn(async move {
        while let Some(frame) = control_writer_rx.recv().await {
            let mut remaining = frame;
            while remaining.has_remaining() {
                let res =
                    std::future::poll_fn(|cx| control_send.poll_send(cx, &mut remaining)).await;
                match res {
                    Ok(0) => {
                        debug!("wisp: control writer zero-byte send, ending");
                        return;
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        debug!(error = ?e, "wisp: control writer send failed");
                        return;
                    }
                }
            }
        }
    });

    let mut control_reader: WtControlReader<MsQuicConnection, Bytes> =
        WtControlReader::new(control_recv, rx_buf);

    let tcp_connector = Arc::new(
        TcpConnector::from_options(&ctx.options)
            .map_err(|e| HandlerError::Control(format!("tcp connector: {e}")))?,
    );
    let udp_connector = Arc::new(
        wisp_proxy::UdpConnector::from_options(&ctx.options)
            .map_err(|e| HandlerError::Control(format!("udp connector: {e}")))?,
    );

    let udp_flows = Arc::new(UdpFlowRegistry::default());
    let datagram_reader = session.datagram_reader();
    let mut datagram_sender = session.datagram_sender();
    let (datagram_tx, mut datagram_rx) =
        mpsc::channel::<DatagramEgress>(DATAGRAM_EGRESS_QUEUE_CAPACITY);
    session_tasks.spawn(async move {
        while let Some(queued) = datagram_rx.recv().await {
            if queued.frame.len() > max_datagram_bytes as usize {
                debug!(
                    bytes = queued.frame.len(),
                    "wisp: oversized WT datagram dropped"
                );
                continue;
            }
            // A proxied or tunnelled datagram that waited this long is
            // worthless; the tunnel's TCP retransmits instead.
            let ages = matches!(
                queued.frame.get(1),
                Some(&datagram_kind::WT_PROXY) | Some(&datagram_kind::IP)
            );
            if ages
                && queued.queued_at.elapsed()
                    > Duration::from_millis(u64::from(
                        wisp_wire::WISP_WT_PROXY_UPSTREAM_DATAGRAM_MAX_AGE_MS,
                    ))
            {
                debug!("wisp: stale WT proxy datagram dropped");
                continue;
            }
            if let Err(e) = datagram_sender.send_datagram(queued.frame) {
                debug!(error = ?e, "wisp: WT datagram send failed");
            }
        }
    });

    let wt_proxies = if ctx.has::<WebTransportProxy>() {
        Some(Arc::new(
            WtProxyRegistry::new(
                &ctx.options,
                max_proxy_sessions,
                max_proxy_substreams,
                flow_shutdown.child_token(),
            )
            .map_err(|e| HandlerError::Control(format!("WT proxy setup: {e}")))?,
        ))
    } else {
        None
    };
    let session_limits = SessionLimits::from_ctx(ctx);
    let tunnel_flows = match (&tunnels, ctx.ip_tunnel) {
        (Some(service), Some(negotiated)) => Some(TunnelFlows::new(
            service.clone(),
            negotiated,
            TunnelSession {
                client_ip: ctx.client_ip.clone(),
                principal: ctx.principal.clone(),
                options: ctx.options.clone(),
                policy: Arc::new(HostPolicy::from_options(&ctx.options)),
                max_datagram_bytes: max_datagram_bytes as usize,
            },
            control_writer_tx.clone(),
            Arc::new(SessionTunnelOutput {
                datagrams: datagram_tx.clone(),
                session: session.clone(),
                tasks: tasks.clone(),
                shutdown: flow_shutdown.clone(),
            }),
            tasks.clone(),
        )),
        _ => None,
    };
    session_tasks.spawn(accept_streams_loop(
        session.clone(),
        tcp_connector.clone(),
        wt_proxies.clone(),
        proxy_controller.clone(),
        ctx.client_ip.clone(),
        session_limits.clone(),
        tasks.clone(),
        flow_shutdown.clone(),
    ));
    session_tasks.spawn(accept_uni_streams(
        session.clone(),
        tunnel_flows.clone(),
        tasks.clone(),
        flow_shutdown.clone(),
    ));

    let udp_negotiated = ctx.has::<wisp_wire::Udp>();
    session_tasks.spawn(datagram_demux_loop(
        datagram_reader,
        udp_flows.clone(),
        wt_proxies.clone(),
        tunnel_flows.clone(),
        session_limits.clone(),
        udp_negotiated,
        max_datagram_bytes,
        flow_shutdown.clone(),
    ));

    let sink_options = ctx.options.clone();
    let udp_slots = (sink_options.stream_limit_total != 0).then(|| {
        Arc::new(Semaphore::new(
            usize::try_from(sink_options.stream_limit_total).unwrap_or(usize::MAX),
        ))
    });
    let mut sink = BridgeSink {
        flows: udp_flows.clone(),
        udp_connector,
        datagram_tx,
        control_writer: control_writer_tx,
        options: sink_options,
        limits: session_limits,
        flow_shutdown: flow_shutdown.clone(),
        wt_proxies: wt_proxies.clone(),
        downstream_session: session.clone(),
        proxy_controller: proxy_controller.clone(),
        proxy_control_negotiated: ctx.has::<ProxyControl>(),
        udp_slots,
        udp_reply_tail: None,
        tasks: tasks.clone(),
        tunnels: tunnel_flows.clone(),
    };

    let dispatch = SessionDispatch::new(ctx);
    let outcome = tokio::select! {
        outcome = dispatch.run(&mut control_reader, &mut sink) => outcome,
        // The datagram path ends the session on abuse (see `datagram_demux_loop`).
        _ = flow_shutdown.cancelled() => {
            ControlOutcome::Error("session ended by the datagram path".to_owned())
        }
    };

    if let Some(flows) = &tunnel_flows {
        // Open tunnels wait out the resume grace period.
        flows.shutdown();
    }
    flow_shutdown.cancel();
    udp_flows.shutdown_all();
    if let Some(registry) = wt_proxies {
        registry.shutdown_all();
    }
    drop(sink);
    session_tasks.abort_all();
    while session_tasks.join_next().await.is_some() {}
    // Stream, flow and proxy tasks watch `flow_shutdown`; wait for them so the
    // connection's slot is only released once nothing runs for it.
    tasks.close();
    if tokio::time::timeout(SESSION_TASK_DRAIN_TIMEOUT, tasks.wait())
        .await
        .is_err()
    {
        debug!(
            remaining = tasks.len(),
            "wisp: session tasks still running after the drain timeout"
        );
    }

    match outcome {
        ControlOutcome::PeerClose { reason } => {
            debug!(reason = reason, "wisp: peer CLOSE");
            Ok(())
        }
        ControlOutcome::PeerEof => Ok(()),
        ControlOutcome::Error(e) => Err(HandlerError::Control(e)),
    }
}

/// The only unidirectional streams a wisp-wt client opens carry an IP
/// tunnel's packets when the tunnel does not use datagrams: prelude
/// `[tunnel_id:u32]`, then `[length:u16][packet]`. Any other is told to stop
/// sending, so it holds no flow-control credit or buffered data for the rest
/// of the session.
async fn accept_uni_streams(
    session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    tunnels: Option<Arc<TunnelFlows>>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
) {
    loop {
        // h3-webtransport keeps one waker for incoming uni streams, and the
        // bidi accept loop's control polling can queue a stream without
        // waking this task, so a session with tunnels looks again on a timer.
        let accepted = match &tunnels {
            Some(_) => loop {
                match tokio::time::timeout(UNI_ACCEPT_RETRY, session.accept_uni()).await {
                    Ok(accepted) => break accepted,
                    Err(_) => continue,
                }
            },
            None => session.accept_uni().await,
        };
        match accepted {
            Ok(Some((_, mut stream))) => {
                let Some(flows) = tunnels.clone() else {
                    stream.stop_sending(h3::error::Code::H3_NO_ERROR.value());
                    debug!("wisp: client unidirectional WT stream refused");
                    continue;
                };
                let shutdown = shutdown.clone();
                tasks.spawn(async move {
                    tokio::select! {
                        _ = shutdown.cancelled() => {}
                        _ = read_tunnel_uni(&mut stream, &flows) => {}
                    }
                    stream.stop_sending(h3::error::Code::H3_NO_ERROR.value());
                });
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// Feeds one client tunnel uni stream into its tunnel until it ends or turns
/// out not to belong to a uni-stream tunnel.
async fn read_tunnel_uni<S>(stream: &mut S, flows: &TunnelFlows)
where
    S: h3::quic::RecvStream,
{
    let mut decoder = UniDecoder::default();
    let mut handle = None;
    loop {
        if handle.is_none() {
            if let Some(tunnel_id) = decoder.tunnel_id() {
                match flows.accepts_uni(tunnel_id) {
                    Some(h) => handle = Some(h),
                    None => {
                        debug!(
                            tunnel_id,
                            "wisp: uni stream for no uni-stream tunnel refused"
                        );
                        return;
                    }
                }
            }
        }
        if let Some(h) = &handle {
            while let Some(packet) = decoder.next_packet() {
                h.forward(packet);
            }
        }
        // One chunk is at most a 16-bit length and its packet.
        if decoder.buffered() > 2 + usize::from(u16::MAX) {
            return;
        }
        match std::future::poll_fn(|cx| stream.poll_data(cx)).await {
            Ok(Some(mut chunk)) => {
                while chunk.has_remaining() {
                    let part = chunk.chunk();
                    decoder.push(part);
                    let n = part.len();
                    chunk.advance(n);
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// The QUIC side of a session's tunnel packets towards the client.
struct SessionTunnelOutput {
    datagrams: mpsc::Sender<DatagramEgress>,
    session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
}

impl TunnelOutput for SessionTunnelOutput {
    fn datagram(&self, frame: Bytes) -> bool {
        self.datagrams.try_send(DatagramEgress::new(frame)).is_ok()
    }

    fn uni(&self, tunnel_id: u32) -> mpsc::Sender<Bytes> {
        let (tx, mut rx) = mpsc::channel::<Bytes>(TUNNEL_UNI_QUEUE);
        let session = self.session.clone();
        let shutdown = self.shutdown.clone();
        self.tasks.spawn(async move {
            let mut stream = tokio::select! {
                _ = shutdown.cancelled() => return,
                opened = session.open_uni(session.session_id()) => match opened {
                    Ok(stream) => stream,
                    Err(error) => {
                        debug!(tunnel_id, error = ?error, "wisp: tunnel uni stream open failed");
                        return;
                    }
                },
            };
            let mut next = Some(Bytes::copy_from_slice(&tunnel_id.to_le_bytes()));
            loop {
                let mut frame = match next.take() {
                    Some(frame) => frame,
                    None => tokio::select! {
                        _ = shutdown.cancelled() => break,
                        chunk = rx.recv() => match chunk {
                            Some(chunk) => chunk,
                            None => break,
                        },
                    },
                };
                while frame.has_remaining() {
                    match std::future::poll_fn(|cx| stream.poll_send(cx, &mut frame)).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            }
            let _ = std::future::poll_fn(|cx| stream.poll_finish(cx)).await;
        });
        tx
    }
}

/// Per-session DoS accounting threaded into the stream/datagram pump tasks so
/// the WT/QUIC path enforces the same per-IP / per-connection rate limits the
/// WS path does. Cloneable (all fields are `Arc`/`String`).
#[derive(Clone)]
struct SessionLimits {
    client_ip: String,
    client_hash: Option<String>,
    options: Arc<WispServerOptions>,
    /// Destination policy, checked before any stream is bridged, exactly as
    /// the WebSocket path checks it before dialing.
    policy: Arc<HostPolicy>,
    dos: Arc<DosGuard>,
    conn_dos: Arc<ConnectionDosGuard>,
    tcp_bytes: Arc<TcpByteLimiter>,
    stream_caps: Arc<WtStreamCaps>,
}

#[derive(Default)]
struct WtStreamCapState {
    total: u64,
    per_host: HashMap<String, u64>,
}

struct WtStreamCaps {
    total_limit: u64,
    per_host_limit: Option<u64>,
    state: Mutex<WtStreamCapState>,
}

impl WtStreamCaps {
    fn new(options: &WispServerOptions) -> Self {
        Self {
            total_limit: options.stream_limit_total,
            per_host_limit: (options.stream_limit_per_host >= 0)
                .then_some(options.stream_limit_per_host as u64),
            state: Mutex::new(WtStreamCapState::default()),
        }
    }

    fn try_acquire(self: &Arc<Self>, key: String) -> Option<WtStreamGuard> {
        let mut state = self.state.lock();
        if self.total_limit != 0 && state.total >= self.total_limit {
            return None;
        }
        if let Some(limit) = self.per_host_limit {
            if state.per_host.get(&key).copied().unwrap_or(0) >= limit {
                return None;
            }
        }
        state.total = state.total.saturating_add(1);
        *state.per_host.entry(key.clone()).or_default() += 1;
        Some(WtStreamGuard {
            caps: self.clone(),
            key,
        })
    }

    fn release(&self, key: &str) {
        let mut state = self.state.lock();
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_host.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_host.remove(key);
            }
        }
    }
}

struct WtStreamGuard {
    caps: Arc<WtStreamCaps>,
    key: String,
}

impl Drop for WtStreamGuard {
    fn drop(&mut self) {
        self.caps.release(&self.key);
    }
}

impl SessionLimits {
    fn from_ctx(ctx: &SessionContext) -> Self {
        let tcp_bytes = Arc::new(TcpByteLimiter::new(
            &ctx.client_ip,
            &ctx.conn_dos,
            &ctx.options,
            &ctx.dos,
        ));
        Self {
            client_ip: ctx.client_ip.clone(),
            client_hash: ctx.client_hash.clone(),
            options: ctx.options.clone(),
            policy: Arc::new(HostPolicy::from_options(&ctx.options)),
            dos: ctx.dos.clone(),
            conn_dos: ctx.conn_dos.clone(),
            tcp_bytes,
            stream_caps: Arc::new(WtStreamCaps::new(&ctx.options)),
        }
    }

    /// Destination policy for a TCP stream, reported like the WebSocket path
    /// reports a blocked host.
    fn tcp_destination_allowed(&self, hostname: &str, port: u16) -> bool {
        let Err(error) = self.policy.check(hostname, port) else {
            return true;
        };
        debug!(host = ?hostname, port, error = ?error.to_string(), "wisp: WT TCP host policy reject");
        emit_report(
            ReportErrorType::HostPolicyBlocked,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some(self.client_ip.clone()),
                    client_ip_hash: self.client_hash.clone(),
                    transport: Some(Transport::Wt),
                    ..Default::default()
                }),
                hostname: Some(hostname.to_owned()),
                port: Some(port),
                stream_type: Some(wisp_reports::StreamType::Tcp),
                wisp_close_code: Some(i32::from(CLOSE_HOST_BLOCKED)),
                ..Default::default()
            },
        );
        false
    }

    fn tcp_open_allowed(&self, hostname: &str) -> bool {
        if !self.dns_allowed(hostname) {
            return false;
        }
        is_tcp_stream_open_allowed(&self.client_ip, &self.conn_dos, &self.options, &self.dos)
    }

    fn dns_allowed(&self, hostname: &str) -> bool {
        hostname.parse::<std::net::IpAddr>().is_ok()
            || is_dns_resolution_allowed(&self.client_ip, hostname, &self.options, &self.dos)
    }

    fn tcp_bytes_allowed(&self, bytes: u64) -> bool {
        self.tcp_bytes.is_allowed(bytes)
    }

    fn stream_open_allowed(&self) -> bool {
        is_tcp_stream_open_allowed(&self.client_ip, &self.conn_dos, &self.options, &self.dos)
    }

    fn try_admit_stream(&self, key: String) -> Option<WtStreamGuard> {
        self.stream_caps.try_acquire(key)
    }

    fn datagram_decision(&self, bytes: u64) -> DatagramDecision {
        datagram_limit_decision(
            &self.client_ip,
            &self.conn_dos,
            &self.options,
            bytes,
            &self.dos,
        )
    }
}

/// When a bridged stream or flow last moved data, in either direction. Both
/// pumps of a bridge share one, so a download that is still receiving keeps
/// the stream alive even though the client sends nothing.
struct Activity {
    started: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            last_ms: AtomicU64::new(0),
        })
    }

    fn touch(&self) {
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(now, Ordering::Relaxed);
    }

    fn quiet_for(&self) -> Duration {
        self.started
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last_ms.load(Ordering::Relaxed)))
    }
}

/// Resolves once `activity` has been quiet for `idle`. `None` (an idle
/// timeout of 0) never resolves.
async fn idle_expired(activity: &Activity, idle: Option<Duration>) {
    let Some(idle) = idle else {
        return std::future::pending().await;
    };
    loop {
        let quiet = activity.quiet_for();
        if quiet >= idle {
            return;
        }
        tokio::time::sleep(idle - quiet).await;
    }
}

/// An idle timeout from the config: `default_ms` when unset, none for 0.
fn idle_limit(configured_ms: Option<u64>, default_ms: u64) -> Option<Duration> {
    match configured_ms.unwrap_or(default_ms) {
        0 => None,
        ms => Some(Duration::from_millis(ms)),
    }
}

/// Hot loop: per-session, accept bidi streams and bridge to TCP/WT_PROXY_SUB.
async fn accept_streams_loop(
    session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    connector: Arc<TcpConnector>,
    wt_proxies: Option<Arc<WtProxyRegistry>>,
    proxy_controller: Option<Arc<ProxyController>>,
    client_ip: String,
    limits: SessionLimits,
    tasks: TaskTracker,
    cancel: CancellationToken,
) {
    loop {
        let accepted = match session.accept_bi().await {
            Ok(Some(a)) => a,
            Ok(None) => {
                debug!(client_ip = %client_ip, "wisp: bidi accept ended");
                return;
            }
            Err(e) => {
                debug!(client_ip = %client_ip, error = ?e, "wisp: accept_bi error");
                return;
            }
        };
        let bidi = match accepted {
            AcceptedBi::BidiStream(_, b) => b,
            AcceptedBi::Request(_, stream) => {
                // One WebTransport session per connection; a second CONNECT (or
                // any other request) gets an answer instead of a silent reset.
                tasks.spawn(reject_request(
                    stream,
                    StatusCode::TOO_MANY_REQUESTS,
                    HeaderMap::new(),
                ));
                continue;
            }
        };
        let connector = connector.clone();
        let client_ip = client_ip.clone();
        let limits = limits.clone();
        let wt_proxies = wt_proxies.clone();
        let proxy_controller = proxy_controller.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let bridged = tokio::select! {
                _ = cancel.cancelled() => return,
                bridged = bridge_one_stream(
                    bidi,
                    connector,
                    wt_proxies,
                    proxy_controller,
                    &limits,
                ) => bridged,
            };
            if let Err(e) = bridged {
                debug!(client_ip = %client_ip, error = %e, "wisp: stream bridge ended");
            }
        });
    }
}

/// Reset both halves of a stream the server refuses.
fn refuse_stream(send: &mut WtBidiSend, recv: &mut WtBidiRecv, code: u8) {
    send.reset(u64::from(code));
    recv.stop_sending(u64::from(code));
}

/// Reads the bidi header (priority + kind + tail) off the first bytes, then
/// bridges either a TCP destination or a negotiated upstream WT session.
async fn bridge_one_stream(
    bidi: h3_webtransport::stream::BidiStream<
        <MsQuicConnection as h3::quic::OpenStreams<Bytes>>::BidiStream,
        Bytes,
    >,
    connector: Arc<TcpConnector>,
    wt_proxies: Option<Arc<WtProxyRegistry>>,
    proxy_controller: Option<Arc<ProxyController>>,
    limits: &SessionLimits,
) -> Result<(), BridgeError> {
    let (mut send, mut recv) = H3BidiStream::<Bytes>::split(bidi);

    let header_timeout =
        Duration::from_millis(limits.options.handshake_timeout_ms.unwrap_or(10_000).max(1));
    let max_stream_header = usize::try_from(limits.options.max_host_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(16);
    let mut rx_buf = BytesMut::with_capacity(1024);
    let parsed = tokio::time::timeout(header_timeout, async {
        loop {
            match try_parse_bidi_stream_header(&rx_buf)
                .map_err(|e| BridgeError::BadHeader(e.to_string()))?
            {
                Some((h, n)) => return Ok::<_, BridgeError>(Some((h, n))),
                None => {
                    if rx_buf.len() >= max_stream_header {
                        return Err(BridgeError::BadHeader(
                            "stream header exceeds configured host limit".to_owned(),
                        ));
                    }
                    let chunk = std::future::poll_fn(|cx| recv.poll_data(cx))
                        .await
                        .map_err(|e| BridgeError::Io(format!("wt recv (header): {e:?}")))?;
                    match chunk {
                        Some(b) => rx_buf.extend_from_slice(b.chunk()),
                        None => return Ok(None),
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| BridgeError::Io("stream header read timed out".into()))??;
    let (header, consumed) = match parsed {
        Some(v) => v,
        None => return Ok(()),
    };
    let _ = rx_buf.split_to(consumed);
    let cap_key = match &header.kind {
        BidiStreamKind::Tcp { hostname, port } => {
            format!("{}:{port}", hostname.to_ascii_lowercase())
        }
        BidiStreamKind::WtProxySub { session_id } => format!("wt-proxy:{session_id}"),
    };
    let Some(_stream_guard) = limits.try_admit_stream(cap_key) else {
        send.reset(0x04);
        recv.stop_sending(0x04);
        return Err(BridgeError::Io(
            "WebTransport concurrent stream cap reached".to_owned(),
        ));
    };

    match header.kind {
        BidiStreamKind::Tcp { hostname, port } => {
            if !limits.options.allow_tcp_streams {
                refuse_stream(&mut send, &mut recv, CLOSE_HOST_BLOCKED);
                return Err(BridgeError::Proxy("TCP streams are disabled".to_owned()));
            }
            if !limits.tcp_destination_allowed(&hostname, port) {
                refuse_stream(&mut send, &mut recv, CLOSE_HOST_BLOCKED);
                return Err(BridgeError::Proxy(
                    "destination blocked by policy".to_owned(),
                ));
            }
            if !limits.tcp_open_allowed(&hostname) {
                debug!(
                    host = ?hostname,
                    port,
                    "wisp: TCP bridge rejected (stream-open / dns rate limit)"
                );
                refuse_stream(&mut send, &mut recv, CLOSE_THROTTLED);
                return Ok(());
            }
            debug!(
                host = ?hostname,
                port,
                priority = header.priority,
                "wisp: TCP bridge open"
            );
            if limits.options.protocol_inspection {
                let inspection_max = usize::try_from(limits.options.protocol_inspection_max_bytes)
                    .unwrap_or(usize::MAX);
                let inspection_timeout = Duration::from_millis(
                    limits
                        .options
                        .protocol_inspection_timeout_ms
                        .unwrap_or(10_000)
                        .max(1),
                );
                // Nothing is dialed until the client's first bytes are
                // classified, so a server-first service never gets to speak
                // before inspection, and the TLS SNI or HTTP Host must name
                // the host the stream asked for.
                let mut inspector = Inspector::new(Some(&hostname));
                tokio::time::timeout(inspection_timeout, async {
                    loop {
                        let inspected_len = rx_buf.len().min(inspection_max);
                        match inspector.feed(&rx_buf[..inspected_len], &limits.options) {
                            InspectionDecision::Allow(_) => {
                                return Ok::<(), BridgeError>(());
                            }
                            InspectionDecision::Block { reason } => {
                                return Err(BridgeError::BadHeader(format!(
                                    "protocol inspection rejected stream: {reason:?}"
                                )));
                            }
                            InspectionDecision::NeedMore if rx_buf.len() >= inspection_max => {
                                return Err(BridgeError::BadHeader(
                                    "protocol inspection buffer exhausted".to_owned(),
                                ));
                            }
                            InspectionDecision::NeedMore => {}
                        }
                        let chunk = std::future::poll_fn(|cx| recv.poll_data(cx))
                            .await
                            .map_err(|e| BridgeError::Io(format!("wt recv (inspection): {e:?}")))?;
                        match chunk {
                            Some(bytes) => rx_buf.extend_from_slice(bytes.chunk()),
                            None => {
                                return Err(BridgeError::BadHeader(
                                    "stream ended during protocol inspection".to_owned(),
                                ));
                            }
                        }
                    }
                })
                .await
                .map_err(|_| BridgeError::Io("protocol inspection timed out".to_owned()))?
                .inspect_err(|_| refuse_stream(&mut send, &mut recv, CLOSE_HOST_BLOCKED))?;
            }
            let leftover = rx_buf.split().freeze();
            if !leftover.is_empty() && !limits.tcp_bytes_allowed(leftover.len() as u64) {
                return Err(BridgeError::Io(
                    "client->upstream byte rate exceeded".to_owned(),
                ));
            }
            let dialed = match proxy_controller.as_ref() {
                Some(controller) => controller
                    .connect_tcp(&hostname, port, limits.options.force_proxy, &limits.policy)
                    .await
                    .map(|(stream, _)| stream)
                    .map_err(|e| BridgeError::Proxy(e.to_string())),
                None if limits.options.force_proxy => Err(BridgeError::Proxy(
                    "force_proxy requires proxy control".to_owned(),
                )),
                None => connector
                    .connect(&hostname, port)
                    .await
                    .map_err(|e| BridgeError::Proxy(e.to_string())),
            };
            let tcp = match dialed {
                Ok(tcp) => tcp,
                Err(error) => {
                    refuse_stream(&mut send, &mut recv, CLOSE_NETWORK_ERROR);
                    return Err(error);
                }
            };
            let (mut tcp_read, mut tcp_write) = tcp.into_split();

            if leftover.has_remaining() {
                tcp_write
                    .write_all(&leftover)
                    .await
                    .map_err(|e| BridgeError::Io(format!("tcp write (initial): {e}")))?;
            }

            let idle = idle_limit(limits.options.stream_idle_timeout_ms, 600_000);
            let activity = Activity::new();
            let up_activity = activity.clone();
            let limits_up = limits.clone();
            let wt_to_tcp = async move {
                let mut batch: Vec<Bytes> = Vec::with_capacity(WT_COALESCE_MAX_CHUNKS);
                loop {
                    let chunk = std::future::poll_fn(|cx| recv.poll_data(cx))
                        .await
                        .map_err(|e| BridgeError::Io(format!("wt recv: {e:?}")))?;
                    // Whatever else the stream already holds goes out in the
                    // same write: msquic hands over one receive at a time,
                    // often a single packet's worth, and each upstream write
                    // costs a system call. `end` is set when the stream is
                    // over; the chunks taken before it are written first.
                    let mut next = Ok(chunk);
                    let mut batch_bytes = 0;
                    let end = loop {
                        match next {
                            Ok(Some(mut b)) if b.has_remaining() => {
                                if !limits_up.tcp_bytes_allowed(b.remaining() as u64) {
                                    break Some(Err(BridgeError::Io(
                                        "client->upstream byte rate exceeded".into(),
                                    )));
                                }
                                batch_bytes += b.remaining();
                                batch.push(b.copy_to_bytes(b.remaining()));
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => break Some(Ok(())),
                            Err(e) => break Some(Err(BridgeError::Io(format!("wt recv: {e:?}")))),
                        }
                        if batch.len() >= WT_COALESCE_MAX_CHUNKS
                            || batch_bytes >= WT_COALESCE_MAX_BYTES
                        {
                            break None;
                        }
                        let polled = {
                            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
                            recv.poll_data(&mut cx)
                        };
                        next = match polled {
                            std::task::Poll::Ready(result) => result,
                            std::task::Poll::Pending => break None,
                        };
                    };
                    if !batch.is_empty() {
                        up_activity.touch();
                        write_all_chunks(&mut tcp_write, &mut batch)
                            .await
                            .map_err(|e| BridgeError::Io(format!("tcp write: {e}")))?;
                        batch.clear();
                    }
                    match end {
                        None => {}
                        Some(Ok(())) => {
                            let _ = tcp_write.shutdown().await;
                            return Ok::<(), BridgeError>(());
                        }
                        Some(Err(e)) => return Err(e),
                    }
                }
            };
            let down_activity = activity.clone();
            let limits_down = limits.clone();
            let tcp_to_wt = async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = tcp_read
                        .read(&mut buf)
                        .await
                        .map_err(|e| BridgeError::Io(format!("tcp read: {e}")))?;
                    if n == 0 {
                        // The upstream finished cleanly, so finish the stream
                        // too; dropping it would reset it, and the client would
                        // read a truncated response as an error.
                        std::future::poll_fn(|cx| send.poll_finish(cx))
                            .await
                            .map_err(|e| BridgeError::Io(format!("wt finish: {e:?}")))?;
                        return Ok::<(), BridgeError>(());
                    }
                    down_activity.touch();
                    if !limits_down.tcp_bytes_allowed(n as u64) {
                        return Err(BridgeError::Io(
                            "upstream->client byte rate exceeded".into(),
                        ));
                    }
                    let mut chunk = Bytes::copy_from_slice(&buf[..n]);
                    while chunk.has_remaining() {
                        let wrote = std::future::poll_fn(|cx| send.poll_send(cx, &mut chunk))
                            .await
                            .map_err(|e| BridgeError::Io(format!("wt send: {e:?}")))?;
                        if wrote == 0 {
                            return Err(BridgeError::Io("wt send returned 0".into()));
                        }
                    }
                }
            };

            tokio::select! {
                result = async {
                    let (a, b) = tokio::join!(wt_to_tcp, tcp_to_wt);
                    a?;
                    b
                } => result,
                _ = idle_expired(&activity, idle) => {
                    debug!(host = ?hostname, port, "wisp: TCP bridge idle, closing");
                    Ok(())
                }
            }
        }
        BidiStreamKind::WtProxySub { session_id } => {
            let Some(registry) = wt_proxies else {
                send.reset(0x04);
                recv.stop_sending(0x04);
                return Err(BridgeError::BadHeader(
                    "WebTransport proxy extension was not negotiated".to_owned(),
                ));
            };
            let Some(upstream) = registry.get(session_id) else {
                send.reset(0x04);
                recv.stop_sending(0x04);
                return Err(BridgeError::BadHeader(format!(
                    "unknown WT_PROXY_SUB session {session_id}"
                )));
            };
            bridge_downstream_to_upstream(
                (send, recv),
                rx_buf.freeze(),
                upstream,
                header.priority,
                limits,
            )
            .await
        }
    }
}

async fn bridge_downstream_to_upstream(
    (mut downstream_send, mut downstream_recv): (WtBidiSend, WtBidiRecv),
    initial: Bytes,
    upstream: Arc<WtProxySession>,
    priority: i32,
    limits: &SessionLimits,
) -> Result<(), BridgeError> {
    if !limits.stream_open_allowed() {
        downstream_send.reset(0x04);
        downstream_recv.stop_sending(0x04);
        return Err(BridgeError::Io(
            "WebTransport proxy stream-open rate exceeded".to_owned(),
        ));
    }
    let _permit = match upstream.stream_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            downstream_send.reset(0x04);
            downstream_recv.stop_sending(0x04);
            return Err(BridgeError::Io(
                "WebTransport proxy stream cap reached".to_owned(),
            ));
        }
    };
    let open_timeout =
        Duration::from_millis(limits.options.connect_timeout_ms.unwrap_or(10_000).max(1));
    let (mut upstream_send, mut upstream_recv) =
        match tokio::time::timeout(open_timeout, upstream.session.open_bi()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                downstream_send.reset(0x03);
                downstream_recv.stop_sending(0x03);
                return Err(BridgeError::Io(format!(
                    "upstream WebTransport stream open: {error}"
                )));
            }
            Err(_) => {
                downstream_send.reset(0x03);
                downstream_recv.stop_sending(0x03);
                return Err(BridgeError::Io(
                    "upstream WebTransport stream open timed out".to_owned(),
                ));
            }
        };
    let _ = upstream_send.set_priority(priority);

    if !initial.is_empty() {
        if !limits.tcp_bytes_allowed(initial.len() as u64) {
            return Err(BridgeError::Io(
                "client->upstream byte rate exceeded".to_owned(),
            ));
        }
        upstream_send
            .write_all(&initial)
            .await
            .map_err(|e| BridgeError::Io(format!("upstream WT initial write: {e}")))?;
    }

    let idle = idle_limit(limits.options.stream_idle_timeout_ms, 600_000);
    let activity = Activity::new();
    let up_activity = activity.clone();
    let upstream_cancel = upstream.cancel.clone();
    let up_limits = limits.clone();
    let downstream_to_upstream = async move {
        loop {
            let chunk = std::future::poll_fn(|cx| downstream_recv.poll_data(cx))
                .await
                .map_err(|e| BridgeError::Io(format!("downstream WT receive: {e:?}")))?;
            match chunk {
                Some(bytes) if bytes.has_remaining() => {
                    up_activity.touch();
                    if !up_limits.tcp_bytes_allowed(bytes.chunk().len() as u64) {
                        return Err(BridgeError::Io(
                            "client->upstream byte rate exceeded".to_owned(),
                        ));
                    }
                    upstream_send
                        .write_all(bytes.chunk())
                        .await
                        .map_err(|e| BridgeError::Io(format!("upstream WT write: {e}")))?;
                }
                Some(_) => {}
                None => {
                    upstream_send
                        .shutdown()
                        .await
                        .map_err(|e| BridgeError::Io(format!("upstream WT finish: {e}")))?;
                    return Ok::<(), BridgeError>(());
                }
            }
        }
    };
    let down_activity = activity.clone();
    let down_limits = limits.clone();
    let upstream_to_downstream = async move {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = tokio::io::AsyncReadExt::read(&mut upstream_recv, &mut buffer)
                .await
                .map_err(|e| BridgeError::Io(format!("upstream WT read: {e}")))?;
            if read == 0 {
                std::future::poll_fn(|cx| downstream_send.poll_finish(cx))
                    .await
                    .map_err(|e| BridgeError::Io(format!("downstream WT finish: {e:?}")))?;
                return Ok::<(), BridgeError>(());
            }
            down_activity.touch();
            if !down_limits.tcp_bytes_allowed(read as u64) {
                return Err(BridgeError::Io(
                    "upstream->client byte rate exceeded".to_owned(),
                ));
            }
            let mut chunk = Bytes::copy_from_slice(&buffer[..read]);
            while chunk.has_remaining() {
                let wrote = std::future::poll_fn(|cx| downstream_send.poll_send(cx, &mut chunk))
                    .await
                    .map_err(|e| BridgeError::Io(format!("downstream WT send: {e:?}")))?;
                if wrote == 0 {
                    return Err(BridgeError::Io("downstream WT send returned 0".to_owned()));
                }
            }
        }
    };

    tokio::select! {
        _ = upstream_cancel.cancelled() => Ok(()),
        _ = idle_expired(&activity, idle) => {
            Err(BridgeError::Io("WT proxy stream idle timeout".to_owned()))
        }
        result = async {
            let (a, b) = tokio::join!(downstream_to_upstream, upstream_to_downstream);
            a?;
            b
        } => result,
    }
}

fn pump_upstream_session(
    registry: Arc<WtProxyRegistry>,
    upstream: Arc<WtProxySession>,
    downstream: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    datagram_tx: mpsc::Sender<DatagramEgress>,
    limits: SessionLimits,
    tasks: TaskTracker,
) {
    let datagram_upstream = upstream.clone();
    let datagram_limits = limits.clone();
    tasks.spawn(async move {
        loop {
            let payload = tokio::select! {
                _ = datagram_upstream.cancel.cancelled() => return,
                result = datagram_upstream.session.read_datagram() => {
                    match result {
                        Ok(payload) => payload,
                        Err(error) => {
                            debug!(session_id = datagram_upstream.id, error = %error, "wisp: upstream WT datagram reader ended");
                            return;
                        }
                    }
                }
            };
            match datagram_limits.datagram_decision(payload.len() as u64) {
                DatagramDecision::Allow => {}
                DatagramDecision::Drop => continue,
                DatagramDecision::Close => {
                    datagram_upstream.close(0x04, b"datagram rate exceeded");
                    return;
                }
            }
            let frame = wisp_wire::encode_datagram(
                datagram_class::NORMAL,
                datagram_kind::WT_PROXY,
                datagram_upstream.id,
                &payload,
            );
            match datagram_tx.try_send(DatagramEgress::new(frame)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!(
                        session_id = datagram_upstream.id,
                        "wisp: WT proxy datagram egress queue full"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
    });

    let stream_upstream = upstream.clone();
    let stream_downstream = downstream.clone();
    let stream_limits = limits.clone();
    let stream_tasks = tasks.clone();
    tasks.spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = stream_upstream.cancel.cancelled() => return,
                result = stream_upstream.session.accept_bi() => result,
            };
            let (mut upstream_send, mut upstream_recv) = match accepted {
                Ok(stream) => stream,
                Err(error) => {
                    debug!(session_id = stream_upstream.id, error = %error, "wisp: upstream WT bidi accept ended");
                    return;
                }
            };
            if !stream_limits.stream_open_allowed() {
                debug!(
                    session_id = stream_upstream.id,
                    "wisp: upstream WT bidi rejected by stream-open limit"
                );
                let _ = upstream_send.reset(0x04);
                let _ = upstream_recv.stop(0x04);
                continue;
            }
            let permit = match stream_upstream.stream_slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    debug!(
                        session_id = stream_upstream.id,
                        "wisp: upstream WT bidi rejected by stream cap"
                    );
                    let _ = upstream_send.reset(0x04);
                    let _ = upstream_recv.stop(0x04);
                    continue;
                }
            };
            let downstream = stream_downstream.clone();
            let upstream = stream_upstream.clone();
            let limits = stream_limits.clone();
            let priority = upstream_send.priority().unwrap_or(0);
            stream_tasks.spawn(async move {
                let open_timeout = Duration::from_millis(
                    limits.options.connect_timeout_ms.unwrap_or(10_000).max(1),
                );
                let downstream_bidi = match tokio::time::timeout(
                    open_timeout,
                    downstream.open_bi(downstream.session_id()),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        debug!(session_id = upstream.id, error = ?error, "wisp: downstream WT bidi open failed");
                        return;
                    }
                    Err(_) => {
                        debug!(
                            session_id = upstream.id,
                            "wisp: downstream WT bidi open timed out"
                        );
                        return;
                    }
                };
                let (mut downstream_send, downstream_recv) =
                    H3BidiStream::<Bytes>::split(downstream_bidi);
                let mut header =
                    wisp_wire::encode_wt_proxy_sub_stream_header(upstream.id, priority);
                while header.has_remaining() {
                    match std::future::poll_fn(|cx| downstream_send.poll_send(cx, &mut header))
                        .await
                    {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
                if let Err(error) = bridge_upstream_to_downstream(
                    (upstream_send, upstream_recv),
                    (downstream_send, downstream_recv),
                    upstream,
                    limits,
                    permit,
                )
                .await
                {
                    debug!(error = %error, "wisp: upstream-initiated WT stream bridge ended");
                }
            });
        }
    });

    let uni_upstream = upstream.clone();
    tasks.spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = uni_upstream.cancel.cancelled() => return,
                result = uni_upstream.session.accept_uni() => result,
            };
            match accepted {
                Ok(mut stream) => {
                    let _ = stream.stop(0x04);
                    debug!(session_id = uni_upstream.id, "wisp: upstream unidirectional WT stream rejected; wisp-wt proxy carries bidi substreams");
                }
                Err(_) => return,
            }
        }
    });

    tasks.spawn(async move {
        let closed = upstream.session.closed().await;
        let (code, reason) = match closed {
            web_transport_quinn::SessionError::WebTransportError(
                web_transport_quinn::WebTransportError::Closed(code, reason),
            ) => (code, clamp_close_reason(&reason)),
            error => (0, clamp_close_reason(&error.to_string())),
        };
        registry.remove(upstream.id, code, reason.as_bytes());
        send_wt_uni_reply(
            downstream,
            wisp_wire::encode_wt_proxy_close_frame(upstream.id, code, &reason),
        )
        .await;
    });
}

async fn bridge_upstream_to_downstream(
    (mut upstream_send, mut upstream_recv): (
        web_transport_quinn::SendStream,
        web_transport_quinn::RecvStream,
    ),
    (mut downstream_send, mut downstream_recv): (WtBidiSend, WtBidiRecv),
    upstream: Arc<WtProxySession>,
    limits: SessionLimits,
    _permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), BridgeError> {
    let idle = idle_limit(limits.options.stream_idle_timeout_ms, 600_000);
    let activity = Activity::new();
    let up_activity = activity.clone();
    let up_limits = limits.clone();
    let downstream_to_upstream = async move {
        loop {
            let chunk = std::future::poll_fn(|cx| downstream_recv.poll_data(cx))
                .await
                .map_err(|e| BridgeError::Io(format!("downstream WT receive: {e:?}")))?;
            match chunk {
                Some(bytes) if bytes.has_remaining() => {
                    up_activity.touch();
                    if !up_limits.tcp_bytes_allowed(bytes.chunk().len() as u64) {
                        return Err(BridgeError::Io(
                            "client->upstream byte rate exceeded".to_owned(),
                        ));
                    }
                    upstream_send
                        .write_all(bytes.chunk())
                        .await
                        .map_err(|e| BridgeError::Io(format!("upstream WT write: {e}")))?;
                }
                Some(_) => {}
                None => {
                    upstream_send
                        .shutdown()
                        .await
                        .map_err(|e| BridgeError::Io(format!("upstream WT finish: {e}")))?;
                    return Ok::<(), BridgeError>(());
                }
            }
        }
    };
    let down_activity = activity.clone();
    let down_limits = limits;
    let upstream_to_downstream = async move {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = tokio::io::AsyncReadExt::read(&mut upstream_recv, &mut buffer)
                .await
                .map_err(|e| BridgeError::Io(format!("upstream WT read: {e}")))?;
            if read == 0 {
                std::future::poll_fn(|cx| downstream_send.poll_finish(cx))
                    .await
                    .map_err(|e| BridgeError::Io(format!("downstream WT finish: {e:?}")))?;
                return Ok::<(), BridgeError>(());
            }
            down_activity.touch();
            if !down_limits.tcp_bytes_allowed(read as u64) {
                return Err(BridgeError::Io(
                    "upstream->client byte rate exceeded".to_owned(),
                ));
            }
            let mut chunk = Bytes::copy_from_slice(&buffer[..read]);
            while chunk.has_remaining() {
                let wrote = std::future::poll_fn(|cx| downstream_send.poll_send(cx, &mut chunk))
                    .await
                    .map_err(|e| BridgeError::Io(format!("downstream WT send: {e:?}")))?;
                if wrote == 0 {
                    return Err(BridgeError::Io("downstream WT send returned 0".to_owned()));
                }
            }
        }
    };

    tokio::select! {
        _ = upstream.cancel.cancelled() => Ok(()),
        _ = idle_expired(&activity, idle) => {
            Err(BridgeError::Io("WT proxy stream idle timeout".to_owned()))
        }
        result = async {
            let (a, b) = tokio::join!(downstream_to_upstream, upstream_to_downstream);
            a?;
            b
        } => result,
    }
}

async fn send_wt_uni_reply(
    session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    mut frame: Bytes,
) {
    let mut stream = match session.open_uni(session.session_id()).await {
        Ok(stream) => stream,
        Err(error) => {
            debug!(error = ?error, "wisp: WT proxy uni reply open failed");
            return;
        }
    };
    while frame.has_remaining() {
        match std::future::poll_fn(|cx| stream.poll_send(cx, &mut frame)).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
    let _ = std::future::poll_fn(|cx| stream.poll_finish(cx)).await;
}

fn public_proxy_error(error: &WtProxyError) -> String {
    match error {
        WtProxyError::InvalidUrl(_) => "invalid upstream URL",
        WtProxyError::Destination(_) => "upstream destination rejected",
        WtProxyError::SessionLimit => "upstream session limit reached",
        WtProxyError::Timeout => "upstream connection timed out",
        WtProxyError::Tls(_) | WtProxyError::NoTrustRoots | WtProxyError::Connect(_) => {
            "upstream connection failed"
        }
        WtProxyError::SessionIdsExhausted => "upstream session ids exhausted",
    }
    .to_owned()
}

fn clamp_close_reason(reason: &str) -> String {
    const MAX_REASON_BYTES: usize = 1024;
    if reason.len() <= MAX_REASON_BYTES {
        return reason.to_owned();
    }
    let mut end = MAX_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

#[derive(Debug, Error)]
enum BridgeError {
    #[error("io: {0}")]
    Io(String),
    #[error("proxy: {0}")]
    Proxy(String),
    #[error("bad stream header: {0}")]
    BadHeader(String),
}

/// Side-effect surface for the post-handshake control bidi.
struct BridgeSink {
    flows: Arc<UdpFlowRegistry>,
    udp_connector: Arc<wisp_proxy::UdpConnector>,
    datagram_tx: mpsc::Sender<DatagramEgress>,
    control_writer: mpsc::Sender<Bytes>,
    options: Arc<wisp_config::WispServerOptions>,
    limits: SessionLimits,
    flow_shutdown: CancellationToken,
    wt_proxies: Option<Arc<WtProxyRegistry>>,
    downstream_session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    proxy_controller: Option<Arc<ProxyController>>,
    proxy_control_negotiated: bool,
    udp_slots: Option<Arc<Semaphore>>,
    /// Signalled once the reply to the latest UDP_OPEN has been queued.
    udp_reply_tail: Option<oneshot::Receiver<()>>,
    /// Tasks the session waits for before releasing its connection slot.
    tasks: TaskTracker,
    /// The session's IP tunnels, when IP_TUNNEL was negotiated.
    tunnels: Option<Arc<TunnelFlows>>,
}

/// One UDP_OPEN's place in the reply order. UDP_OPENED carries no request id,
/// so a client can only match replies to its requests by order: every
/// UDP_OPEN gets exactly one reply (UDP_OPENED, or UDP_CLOSE with a reason),
/// queued after the reply to the UDP_OPEN before it, however long each bind
/// takes.
struct UdpReplyTurn {
    after: Option<oneshot::Receiver<()>>,
    done: oneshot::Sender<()>,
}

impl UdpReplyTurn {
    async fn reply(self, control_writer: &mpsc::Sender<Bytes>, frame: Bytes) {
        if let Some(after) = self.after {
            // An error means the earlier turn was dropped without replying,
            // which also frees this one.
            let _ = after.await;
        }
        let _ = control_writer.send(frame).await;
        let _ = self.done.send(());
    }
}

impl BridgeSink {
    fn next_udp_reply_turn(&mut self) -> UdpReplyTurn {
        let (done, next) = oneshot::channel();
        UdpReplyTurn {
            after: self.udp_reply_tail.replace(next),
            done,
        }
    }

    /// Refuse a UDP_OPEN with a UDP_CLOSE for a fresh flow id, in reply order.
    fn refuse_udp_open(&mut self, reason: u8) {
        let flow_id = self.flows.alloc_id();
        let turn = self.next_udp_reply_turn();
        let control_writer = self.control_writer.clone();
        self.tasks.spawn(async move {
            turn.reply(
                &control_writer,
                wisp_wire::encode_udp_close_frame(flow_id, reason),
            )
            .await;
        });
    }
}

#[async_trait::async_trait]
impl ControlSink for BridgeSink {
    async fn on_control_text(&mut self, text: String) {
        if !self.proxy_control_negotiated {
            debug!("wisp: CONTROL text ignored (proxy control not negotiated)");
            return;
        }
        let Some(controller) = self.proxy_controller.clone() else {
            debug!("wisp: CONTROL text ignored (no proxy controller)");
            return;
        };
        if text.len() as u64 > self.options.max_text_frame_bytes {
            warn!("wisp: CONTROL text exceeds max_text_frame_bytes");
            return;
        }
        let reply_tx = self.control_writer.clone();
        let cancel = self.flow_shutdown.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                res = handle_proxy_control_text(&controller, &text) => {
                    if let Some(reply) = res {
                        let _ = reply_tx.send(encode_control_frame(&reply)).await;
                    }
                }
            }
        });
    }
    async fn on_udp_open(&mut self, frame: UdpOpenFrame) {
        // UDP opens spend the stream-open budget, as a stream open does,
        // rather than the control-message budget: running out refuses this
        // flow and leaves the session up.
        if !self.limits.stream_open_allowed() {
            debug!(host = ?frame.hostname, "wisp: UDP_OPEN rejected: stream-open rate limit");
            self.refuse_udp_open(CLOSE_THROTTLED);
            return;
        }
        if !self.limits.dns_allowed(&frame.hostname) {
            debug!(host = ?frame.hostname, "wisp: UDP_OPEN rejected: DNS rate limit");
            self.refuse_udp_open(CLOSE_THROTTLED);
            return;
        }
        let flow_permit = match self.udp_slots.as_ref() {
            Some(slots) => match slots.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    debug!(host = ?frame.hostname, "wisp: UDP_OPEN rejected: concurrent flow cap");
                    self.refuse_udp_open(CLOSE_THROTTLED);
                    return;
                }
            },
            None => None,
        };
        let flow_cap = self.options.stream_limit_total;
        if flow_cap != 0 && self.flows.len() as u64 >= flow_cap {
            debug!(
                host = ?frame.hostname,
                port = frame.port,
                cap = flow_cap,
                "wisp: UDP_OPEN rejected: concurrent flow cap"
            );
            self.refuse_udp_open(CLOSE_THROTTLED);
            return;
        }
        let flow_id = self.flows.alloc_id();
        debug!(
            flow_id = flow_id,
            host = ?frame.hostname,
            port = frame.port,
            "wisp: UDP_OPEN"
        );
        let turn = self.next_udp_reply_turn();
        let connector = self.udp_connector.clone();
        let datagram_tx = self.datagram_tx.clone();
        let flows = self.flows.clone();
        let control_writer = self.control_writer.clone();
        let limits = self.limits.clone();
        let flow_shutdown = self.flow_shutdown.clone();
        let idle = idle_limit(self.options.stream_idle_timeout_ms, 60_000);
        self.tasks.spawn(async move {
            open_udp_flow(
                flow_id,
                frame,
                connector,
                datagram_tx,
                flows,
                control_writer,
                limits,
                idle,
                flow_shutdown,
                flow_permit,
                turn,
            )
            .await;
        });
    }
    async fn on_udp_close(&mut self, frame: UdpClose) {
        debug!(
            flow_id = frame.flow_id,
            reason = frame.reason,
            "wisp: UDP_CLOSE"
        );
        self.flows.close(frame.flow_id);
    }
    async fn on_wt_proxy_open(&mut self, url: String) {
        let Some(registry) = self.wt_proxies.clone() else {
            return;
        };
        let downstream = self.downstream_session.clone();
        let datagram_tx = self.datagram_tx.clone();
        let limits = self.limits.clone();
        let session_cancel = self.flow_shutdown.clone();
        let pump_tasks = self.tasks.clone();
        self.tasks.spawn(async move {
            let opened = tokio::select! {
                _ = session_cancel.cancelled() => return,
                result = registry.open(&url) => result,
            };
            match opened {
                Ok(upstream) => {
                    debug!(
                        session_id = upstream.id,
                        host = ?upstream.session.request().url.host_str().unwrap_or("unknown"),
                        "wisp: upstream WebTransport session opened"
                    );
                    send_wt_uni_reply(
                        downstream.clone(),
                        wisp_wire::encode_wt_proxy_opened_frame(upstream.id),
                    )
                    .await;
                    pump_upstream_session(
                        registry,
                        upstream,
                        downstream,
                        datagram_tx,
                        limits,
                        pump_tasks,
                    );
                }
                Err(error) => {
                    debug!(error = %error, "wisp: upstream WebTransport open failed");
                    send_wt_uni_reply(
                        downstream,
                        wisp_wire::encode_wt_proxy_close_frame(
                            0,
                            0x03,
                            &public_proxy_error(&error),
                        ),
                    )
                    .await;
                }
            }
        });
    }
    async fn on_wt_proxy_close(&mut self, frame: WtProxyClose) {
        if let Some(registry) = &self.wt_proxies {
            registry.remove(frame.session_id, frame.code, frame.reason.as_bytes());
        }
    }
    async fn on_tunnel_open(&mut self, frame: TunnelFrame) {
        if let Some(flows) = &self.tunnels {
            flows.on_open(frame).await;
        }
    }
    async fn on_tunnel_close(&mut self, frame: TunnelClose) {
        if let Some(flows) = &self.tunnels {
            flows.on_close(frame);
        }
    }
    async fn on_tunnel_capsules(&mut self, frame: TunnelFrame) {
        if let Some(flows) = &self.tunnels {
            flows.on_capsules(frame).await;
        }
    }
}

/// Pops one QUIC datagram, parses its class- and kind-prefixed header, and
/// routes it by kind and flow id. A client that keeps exceeding the datagram
/// rate, or sends datagrams it did not negotiate or cannot frame, has the
/// whole session ended through `session_cancel`: leaving the session up with
/// its datagram path stopped would only strand its UDP flows.
async fn datagram_demux_loop(
    mut reader: h3_datagram::datagram_handler::DatagramReader<
        wisp_quic_msquic::adapter::MsQuicDatagramReceiver,
    >,
    flows: Arc<UdpFlowRegistry>,
    wt_proxies: Option<Arc<WtProxyRegistry>>,
    tunnels: Option<Arc<TunnelFlows>>,
    limits: SessionLimits,
    udp_negotiated: bool,
    max_datagram_bytes: u32,
    session_cancel: CancellationToken,
) {
    loop {
        let buf = match reader.read_datagram().await {
            Ok(datagram) => datagram.into_payload(),
            Err(e) => {
                debug!(error = ?e, "wisp: datagram receive ended");
                return;
            }
        };
        if buf.len() > max_datagram_bytes as usize {
            debug!(
                bytes = buf.len(),
                "wisp: oversized inbound WT datagram dropped"
            );
            continue;
        }
        // A tunnel carries a whole network stack's traffic and is metered by
        // the tunnel engine's own packet and byte limits instead.
        let tunnel_datagram = buf.get(1) == Some(&datagram_kind::IP) && tunnels.is_some();
        if !tunnel_datagram {
            match limits.datagram_decision(buf.len() as u64) {
                DatagramDecision::Allow => {}
                DatagramDecision::Drop => continue,
                DatagramDecision::Close => {
                    debug!("wisp: datagram rate exceeded; ending session");
                    session_cancel.cancel();
                    return;
                }
            }
        }
        match wisp_wire::parse_datagram(&buf) {
            Ok(d) => match d.kind {
                datagram_kind::UDP => {
                    if !udp_negotiated {
                        debug!("wisp: UDP datagram received without negotiated extension");
                        session_cancel.cancel();
                        return;
                    }
                    match flows.route(d.flow_id, d.payload) {
                        crate::udp_flow::RouteOutcome::Queued
                        | crate::udp_flow::RouteOutcome::Unknown
                        | crate::udp_flow::RouteOutcome::Closed => {}
                        crate::udp_flow::RouteOutcome::Full => {
                            debug!(flow = d.flow_id, "wisp: UDP flow queue full");
                        }
                    }
                }
                datagram_kind::WT_PROXY => {
                    let Some(registry) = &wt_proxies else {
                        debug!("wisp: WT_PROXY datagram received without negotiated extension");
                        session_cancel.cancel();
                        return;
                    };
                    let Some(upstream) = registry.get(d.flow_id) else {
                        continue;
                    };
                    if d.payload.len() > upstream.session.max_datagram_size() {
                        debug!(
                            session_id = d.flow_id,
                            "wisp: oversized WT_PROXY datagram dropped"
                        );
                        continue;
                    }
                    if let Err(error) = upstream.session.send_datagram(d.payload) {
                        debug!(session_id = d.flow_id, error = %error, "wisp: upstream WT datagram dropped");
                    }
                }
                datagram_kind::IP => {
                    let Some(tunnels) = &tunnels else {
                        debug!("wisp: IP datagram received without negotiated extension");
                        session_cancel.cancel();
                        return;
                    };
                    tunnels.on_datagram(d.flow_id, &d.payload);
                }
                other => {
                    debug!(kind = other, "wisp: unknown datagram kind dropped");
                }
            },
            Err(e) => {
                debug!(error = %e, "wisp: malformed datagram; ending session");
                session_cancel.cancel();
                return;
            }
        }
    }
}

/// Bring a UDP flow online: bind upstream, spawn recv pump, register tx side
/// so the demux task can shovel client datagrams upstream. Replies to the
/// UDP_OPEN, in request order, with UDP_OPENED once the upstream is ready or
/// UDP_CLOSE if it cannot be reached.
async fn open_udp_flow(
    flow_id: u32,
    frame: UdpOpenFrame,
    connector: Arc<wisp_proxy::UdpConnector>,
    datagram_tx: mpsc::Sender<DatagramEgress>,
    flows: Arc<UdpFlowRegistry>,
    control_writer: mpsc::Sender<Bytes>,
    limits: SessionLimits,
    idle: Option<Duration>,
    session_cancel: CancellationToken,
    flow_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    turn: UdpReplyTurn,
) {
    let sock = tokio::select! {
        _ = session_cancel.cancelled() => return,
        result = connector.bind(&frame.hostname, frame.port) => {
            match result {
                Ok(sock) => sock,
                Err(e) => {
                    debug!(error = %e, host = ?frame.hostname, port = frame.port, "wisp: UDP bind failed");
                    let reason = if matches!(
                        e,
                        wisp_proxy::ProxyError::HostBlocked(_)
                            | wisp_proxy::ProxyError::PortBlocked(_)
                            | wisp_proxy::ProxyError::DomainNotWhitelisted(_)
                            | wisp_proxy::ProxyError::LoopbackBlocked(_)
                            | wisp_proxy::ProxyError::PrivateBlocked(_)
                    ) {
                        CLOSE_HOST_BLOCKED
                    } else {
                        CLOSE_NETWORK_ERROR
                    };
                    turn.reply(
                        &control_writer,
                        wisp_wire::encode_udp_close_frame(flow_id, reason),
                    )
                    .await;
                    return;
                }
            }
        }
    };
    let cancel = session_cancel.child_token();
    let (upstream_tx, mut upstream_rx) = mpsc::channel::<Bytes>(UDP_FLOW_QUEUE_CAPACITY);
    flows.insert(
        flow_id,
        UdpFlowHandle {
            upstream_tx,
            cancel: cancel.clone(),
        },
    );

    turn.reply(&control_writer, wisp_wire::encode_udp_opened_frame(flow_id))
        .await;

    let sock = Arc::new(sock);
    // Traffic either way keeps the flow open.
    let activity = Activity::new();

    let sock_send = sock.clone();
    let cancel_send = cancel.clone();
    let send_activity = activity.clone();
    let mut pumps = JoinSet::new();
    pumps.spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_send.cancelled() => return,
                maybe = upstream_rx.recv() => {
                    let Some(payload) = maybe else { return };
                    send_activity.touch();
                    if let Err(e) = sock_send.send(&payload).await {
                        debug!(error = %e, "wisp: UDP upstream send failed");
                        return;
                    }
                }
            }
        }
    });

    let sock_recv = sock.clone();
    let cancel_recv = cancel.clone();
    let datagram_tx_recv = datagram_tx.clone();
    let recv_limits = limits;
    let recv_activity = activity.clone();
    pumps.spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            tokio::select! {
                _ = cancel_recv.cancelled() => return,
                res = sock_recv.recv(&mut buf) => {
                    let n = match res {
                        Ok(n) => n,
                        Err(e) => {
                            debug!(error = %e, "wisp: UDP upstream recv failed");
                            return;
                        }
                    };
                    recv_activity.touch();
                    match recv_limits.datagram_decision(n as u64) {
                        DatagramDecision::Allow => {}
                        DatagramDecision::Drop => {
                            debug!(flow_id, bytes = n, "wisp: upstream->client datagram dropped: rate limit");
                            continue;
                        }
                        DatagramDecision::Close => {
                            debug!(flow_id, "wisp: upstream->client datagram rate sustained-exceeded; closing flow");
                            return;
                        }
                    }
                    let dgram = wisp_wire::encode_datagram(
                        datagram_class::NORMAL,
                        datagram_kind::UDP,
                        flow_id,
                        &buf[..n],
                    );
                    match datagram_tx_recv.try_send(DatagramEgress::new(dgram)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            debug!(flow_id, "wisp: WT datagram egress queue full");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        }
    });

    pumps.spawn(async move {
        idle_expired(&activity, idle).await;
        debug!(flow_id, "wisp: UDP flow idle, closing");
    });

    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = pumps.join_next() => {}
    }
    cancel.cancel();
    pumps.abort_all();
    while pumps.join_next().await.is_some() {}
    if !session_cancel.is_cancelled() {
        let _ = control_writer
            .send(wisp_wire::encode_udp_close_frame(flow_id, 0x00))
            .await;
    }
    flows.remove(flow_id);
    drop(flow_permit);
}

#[derive(Debug, Error)]
enum HandlerError {
    #[error("h3 build: {0}")]
    H3Build(String),
    #[error("wt accept: {0}")]
    WtAccept(String),
    #[error("control accept: {0}")]
    ControlAccept(String),
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("control: {0}")]
    Control(String),
}

/// Wraps the first bidi stream of a WT session as the wisp-wt control bidi.
struct WtControlIo<C, B>
where
    C: h3::quic::Connection<B>,
    B: Buf,
{
    bidi: h3_webtransport::stream::BidiStream<C::BidiStream, B>,
    rx_buf: BytesMut,
}

impl<C, B> WtControlIo<C, B>
where
    C: h3::quic::Connection<B>,
    B: Buf,
{
    fn new(bidi: h3_webtransport::stream::BidiStream<C::BidiStream, B>) -> Self {
        Self {
            bidi,
            rx_buf: BytesMut::with_capacity(4096),
        }
    }

    fn into_inner(
        self,
    ) -> (
        h3_webtransport::stream::BidiStream<C::BidiStream, B>,
        BytesMut,
    ) {
        (self.bidi, self.rx_buf)
    }
}

#[async_trait::async_trait]
impl<C> ControlIo for WtControlIo<C, Bytes>
where
    C: h3::quic::Connection<Bytes> + Send,
    C::BidiStream: h3::quic::SendStreamUnframed<Bytes> + Send,
{
    async fn read_frame(&mut self) -> Result<Bytes, ControlIoError> {
        loop {
            if self.rx_buf.len() >= 4 {
                let len = u32::from_le_bytes([
                    self.rx_buf[0],
                    self.rx_buf[1],
                    self.rx_buf[2],
                    self.rx_buf[3],
                ]) as usize;
                if len > MAX_CONTROL_FRAME_BYTES {
                    return Err(ControlIoError::Io(format!(
                        "control frame length {len} exceeds cap {MAX_CONTROL_FRAME_BYTES}"
                    )));
                }
                if self.rx_buf.len() >= 4 + len {
                    let _ = self.rx_buf.split_to(4);
                    let body = self.rx_buf.split_to(len).freeze();
                    return Ok(body);
                }
            }
            let chunk = std::future::poll_fn(|cx| self.bidi.poll_data(cx))
                .await
                .map_err(|e| ControlIoError::Io(format!("{e:?}")))?;
            match chunk {
                Some(buf) => self.rx_buf.extend_from_slice(buf.chunk()),
                None => return Err(ControlIoError::Closed),
            }
        }
    }

    async fn write_frame(&mut self, frame: Bytes) -> Result<(), ControlIoError> {
        let mut remaining = frame;
        while remaining.has_remaining() {
            let n = std::future::poll_fn(|cx| self.bidi.poll_send(cx, &mut remaining))
                .await
                .map_err(|e| ControlIoError::Io(format!("{e:?}")))?;
            if n == 0 {
                return Err(ControlIoError::Io("zero-byte write".into()));
            }
        }
        Ok(())
    }
}

type WtBidiRecv = <h3_webtransport::stream::BidiStream<
    <MsQuicConnection as h3::quic::OpenStreams<Bytes>>::BidiStream,
    Bytes,
> as h3::quic::BidiStream<Bytes>>::RecvStream;
type WtBidiSend = <h3_webtransport::stream::BidiStream<
    <MsQuicConnection as h3::quic::OpenStreams<Bytes>>::BidiStream,
    Bytes,
> as h3::quic::BidiStream<Bytes>>::SendStream;

struct WtControlReader<C, B>
where
    C: h3::quic::Connection<B>,
    B: Buf,
{
    recv: WtBidiRecv,
    rx_buf: BytesMut,
    _phantom: std::marker::PhantomData<(C, B)>,
}

impl WtControlReader<MsQuicConnection, Bytes> {
    fn new(recv: WtBidiRecv, rx_buf: BytesMut) -> Self {
        Self {
            recv,
            rx_buf,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl ControlIo for WtControlReader<MsQuicConnection, Bytes> {
    async fn read_frame(&mut self) -> Result<Bytes, ControlIoError> {
        loop {
            if self.rx_buf.len() >= 4 {
                let len = u32::from_le_bytes([
                    self.rx_buf[0],
                    self.rx_buf[1],
                    self.rx_buf[2],
                    self.rx_buf[3],
                ]) as usize;
                if len > MAX_CONTROL_FRAME_BYTES {
                    return Err(ControlIoError::Io(format!(
                        "control frame length {len} exceeds cap {MAX_CONTROL_FRAME_BYTES}"
                    )));
                }
                if self.rx_buf.len() >= 4 + len {
                    let _ = self.rx_buf.split_to(4);
                    return Ok(self.rx_buf.split_to(len).freeze());
                }
            }
            let chunk = std::future::poll_fn(|cx| self.recv.poll_data(cx))
                .await
                .map_err(|e| ControlIoError::Io(format!("{e:?}")))?;
            match chunk {
                Some(b) => self.rx_buf.extend_from_slice(b.chunk()),
                None => return Err(ControlIoError::Closed),
            }
        }
    }

    async fn write_frame(&mut self, _frame: Bytes) -> Result<(), ControlIoError> {
        Err(ControlIoError::Io(
            "WtControlReader is read-only; writes are routed through BridgeSink".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn coalesced_chunks_survive_short_writes_in_order() {
        // A 7-byte pipe takes every write short, often partway into a chunk.
        let (mut writer, mut reader) = tokio::io::duplex(7);
        let mut expected = Vec::new();
        let mut chunks: Vec<Bytes> = (0..40u8)
            .map(|i| {
                let chunk: Vec<u8> = (0..(i % 11 + 1)).map(|j| i.wrapping_mul(31) ^ j).collect();
                expected.extend_from_slice(&chunk);
                Bytes::from(chunk)
            })
            .collect();
        let read = tokio::spawn(async move {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await.map(|_| got)
        });
        write_all_chunks(&mut writer, &mut chunks).await.unwrap();
        drop(writer);
        assert_eq!(read.await.unwrap().unwrap(), expected);
    }

    #[test]
    fn wt_stream_caps_release_slots_on_drop() {
        let options = WispServerOptions {
            stream_limit_total: 1,
            stream_limit_per_host: 1,
            ..WispServerOptions::default()
        };
        let caps = Arc::new(WtStreamCaps::new(&options));

        let guard = caps.try_acquire("example.com".to_owned()).unwrap();
        assert!(caps.try_acquire("other.example".to_owned()).is_none());
        drop(guard);
        assert!(caps.try_acquire("other.example".to_owned()).is_some());
    }

    #[test]
    fn idle_limit_treats_zero_as_disabled() {
        assert_eq!(idle_limit(None, 600_000), Some(Duration::from_secs(600)));
        assert_eq!(
            idle_limit(Some(2_000), 600_000),
            Some(Duration::from_secs(2))
        );
        assert_eq!(idle_limit(Some(0), 600_000), None);
    }

    #[tokio::test]
    async fn idle_timer_counts_activity_from_either_direction() {
        let activity = Activity::new();
        let idle = Some(Duration::from_millis(400));
        let expired = idle_expired(&activity, idle);
        tokio::pin!(expired);
        // Traffic every 100 ms, from whichever pump, keeps a 400 ms timer from
        // firing for well past 400 ms.
        for _ in 0..8 {
            tokio::select! {
                _ = &mut expired => panic!("an active stream must not idle out"),
                _ = tokio::time::sleep(Duration::from_millis(100)) => activity.touch(),
            }
        }
        tokio::time::timeout(Duration::from_secs(5), &mut expired)
            .await
            .expect("a quiet stream idles out");
    }

    #[tokio::test]
    async fn zero_idle_timeout_never_fires() {
        let activity = Activity::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), idle_expired(&activity, None))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn udp_open_replies_keep_request_order() {
        let (writer, mut replies) = mpsc::channel::<Bytes>(8);
        let mut tail: Option<oneshot::Receiver<()>> = None;
        let mut turn = || {
            let (done, next) = oneshot::channel();
            UdpReplyTurn {
                after: tail.replace(next),
                done,
            }
        };
        let (first, second, third) = (turn(), turn(), turn());
        // The later opens finish first; their replies still wait their turn.
        let late = tokio::spawn({
            let writer = writer.clone();
            async move {
                third.reply(&writer, Bytes::from_static(b"3")).await;
            }
        });
        let middle = tokio::spawn({
            let writer = writer.clone();
            async move {
                second.reply(&writer, Bytes::from_static(b"2")).await;
            }
        });
        tokio::task::yield_now().await;
        assert!(
            replies.try_recv().is_err(),
            "nothing before the first reply"
        );
        first.reply(&writer, Bytes::from_static(b"1")).await;
        late.await.unwrap();
        middle.await.unwrap();
        let order: Vec<Bytes> = std::iter::from_fn(|| replies.try_recv().ok()).collect();
        assert_eq!(order, [&b"1"[..], b"2", b"3"]);
    }

    #[tokio::test]
    async fn dropped_udp_reply_turn_frees_the_next() {
        let (writer, mut replies) = mpsc::channel::<Bytes>(8);
        let (done, next) = oneshot::channel();
        drop(done);
        let (later_done, _) = oneshot::channel();
        UdpReplyTurn {
            after: Some(next),
            done: later_done,
        }
        .reply(&writer, Bytes::from_static(b"after a cancelled open"))
        .await;
        assert_eq!(
            replies.try_recv().unwrap(),
            Bytes::from_static(b"after a cancelled open")
        );
    }

    #[test]
    fn wt_stream_caps_apply_per_host_limit() {
        let options = WispServerOptions {
            stream_limit_total: 3,
            stream_limit_per_host: 1,
            ..WispServerOptions::default()
        };
        let caps = Arc::new(WtStreamCaps::new(&options));

        let _first = caps.try_acquire("example.com".to_owned()).unwrap();
        assert!(caps.try_acquire("example.com".to_owned()).is_none());
        assert!(caps.try_acquire("other.example".to_owned()).is_some());
    }
}

//! Listener bind + h3 server boot.
//!
//! Wires the [`MsQuicEngine`] listener to an h3 server per accepted QUIC
//! connection. Each connection accepts exactly one WebTransport CONNECT to
//! the configured wisp-wt endpoint, runs [`PreUpgradePolicy`], accepts the
//! [`WebTransportSession`], runs [`negotiate_handshake`] on the first bidi
//! and then [`SessionDispatch`] on it.
//!
//! The actual TCP/UDP bridging hot path is handled by tasks spawned per
//! accepted bidi/uni/datagram from the WT session — see [`session_loop`].

#![allow(clippy::too_many_arguments)]

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{BidiStream as H3BidiStream, RecvStream as _, SendStreamUnframed as _};
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use http::Method;
use msquic::{Addr, BufferRef, Connection, Listener, ListenerEvent};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wisp_config::{normalize_endpoint, WispWtServerOptions};
use wisp_dos::DosGuard;
use wisp_proxy::TcpConnector;
use wisp_quic_msquic::adapter::MsQuicConnection;
use wisp_quic_msquic::engine::{EngineConfig, EngineError, MsQuicEngine};
use wisp_wire::{
    datagram_class, datagram_kind, try_parse_bidi_stream_header, BidiStreamKind, UdpClose,
    UdpOpenFrame, WtProxyClose,
};
use wisp_ws_h3::{serve_h3_websocket, H3WsContext};

use crate::control::{ControlOutcome, ControlSink, SessionDispatch};
use crate::handshake::{negotiate_handshake, ControlIo, ControlIoError, HandshakeError};
use crate::policy::PreUpgradePolicy;
use crate::session::SessionContext;

const ALPN_H3: &str = "h3";
/// Hard cap on a single wisp-wt control-bidi frame body. The 4-byte length
/// prefix is attacker-controlled (up to ~4 GiB); without this bound a client
/// could declare a huge frame and force `rx_buf` to grow unbounded (or drip
/// bytes forever), an unauthenticated memory-exhaustion / slowloris vector.
/// Mirrors `wisp_ws_h3::frame::MAX_FRAME_PAYLOAD`.
const MAX_CONTROL_FRAME_BYTES: usize = 16 * 1024 * 1024;
const SEC_PROTOCOL_HEADER: &str = ":protocol";
const WEBTRANSPORT_PROTOCOL: &str = "webtransport";
const WEBSOCKET_PROTOCOL: &str = "websocket";

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
/// listener and let in-flight sessions finish.
pub struct ServeHandle {
    _engine: Arc<MsQuicEngine>,
    listener: Listener,
    cancel: CancellationToken,
}

impl ServeHandle {
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn shutdown(self) {
        self.cancel.cancel();
        self.listener.stop();
    }
}

/// Bind the msquic listener and start dispatching sessions.
///
/// `ws_ctx`, when present, enables WS-over-H3 (RFC 9220) on the same
/// listener: requests with `:method = CONNECT` and `:protocol = websocket`
/// at the WS endpoint are dispatched to [`serve_h3_websocket`] instead of
/// the WT path. `None` keeps the listener WT-only.
pub async fn serve(
    options: Arc<WispWtServerOptions>,
    dos: Arc<DosGuard>,
    cancel: CancellationToken,
    ws_ctx: Option<Arc<H3WsContext>>,
) -> Result<ServeHandle, ServeError> {
    let cert_path = options.cert_path.clone().ok_or(ServeError::MissingTls)?;
    let key_path = options.key_path.clone().ok_or(ServeError::MissingTls)?;

    let engine_cfg = EngineConfig {
        registration_name: "wispd".to_owned(),
        alpns: vec![ALPN_H3.to_owned()],
        cert_path,
        key_path,
        bench_mode: false,
        ..EngineConfig::default()
    };
    let engine = Arc::new(MsQuicEngine::new(&engine_cfg)?);
    let configuration = engine.configuration.clone();

    let (conn_tx, conn_rx) = mpsc::unbounded_channel::<(MsQuicConnection, Option<SocketAddr>)>();

    let listener = engine.open_listener(move |_, ev| {
        if let ListenerEvent::NewConnection { info, connection } = ev {
            let peer = info.remote_address.as_socket();
            // SAFETY: msquic transferred ownership in the listener callback.
            // We own the handle from this point; MsQuicConnection holds it
            // inside an Arc<Connection> for the connection lifetime.
            let owned: Connection = unsafe { Connection::from_raw(connection.as_raw()) };
            if let Err(status) = owned.set_configuration(&configuration) {
                warn!(?status, "set_configuration failed; rejecting connection");
                drop(owned);
                return Ok(());
            }
            let ms_conn = MsQuicConnection::install(owned);
            if conn_tx.send((ms_conn, peer)).is_err() {
                debug!("conn_tx closed; dropping new connection");
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
    listener
        .start(&alpn_refs, Some(&Addr::from(local_addr)))
        .map_err(ServeError::Start)?;

    info!(addr = %local_addr, "wisp: listener bound");

    let acceptor_cancel = cancel.clone();
    tokio::spawn(connection_acceptor(
        conn_rx,
        options,
        dos,
        acceptor_cancel,
        ws_ctx,
    ));

    Ok(ServeHandle {
        _engine: engine,
        listener,
        cancel,
    })
}

async fn connection_acceptor(
    mut rx: mpsc::UnboundedReceiver<(MsQuicConnection, Option<SocketAddr>)>,
    options: Arc<WispWtServerOptions>,
    dos: Arc<DosGuard>,
    cancel: CancellationToken,
    ws_ctx: Option<Arc<H3WsContext>>,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("wisp: cancel received, exiting acceptor");
                return;
            }
            maybe = rx.recv() => {
                let Some((ms_conn, peer)) = maybe else {
                    info!("wisp: connection channel closed");
                    return;
                };
                let opts = options.clone();
                let dos = dos.clone();
                let ws_ctx = ws_ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(ms_conn, peer, opts, dos, ws_ctx).await {
                        debug!(error = %e, "wisp: connection handler exited with error");
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    mut ms_conn: MsQuicConnection,
    peer: Option<SocketAddr>,
    options: Arc<WispWtServerOptions>,
    dos: Arc<DosGuard>,
    ws_ctx: Option<Arc<H3WsContext>>,
) -> Result<(), HandlerError> {
    let endpoint = normalize_endpoint(&options.base.endpoint);
    // WS endpoint may diverge from WT endpoint (via [wisp_websocket].endpoint
    // override). H3WsContext::from_wisp_wt already baked that into
    // ctx.options.endpoint, so re-normalize from there.
    let ws_endpoint = ws_ctx
        .as_ref()
        .map(|ctx| normalize_endpoint(&ctx.options.endpoint));
    let max_sessions: u64 = options.base.max_connections;

    let dgram_rx = ms_conn
        .take_datagram_rx()
        .expect("datagram_rx already taken — MsQuicConnection used twice");
    let dgram_send = ms_conn.datagram_send_handle();

    let mut h3_conn: h3::server::Connection<MsQuicConnection, Bytes> = h3::server::builder()
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(max_sessions)
        .build(ms_conn)
        .await
        .map_err(|e| HandlerError::H3Build(format!("{e:?}")))?;

    let resolver = match h3_conn
        .accept()
        .await
        .map_err(|e| HandlerError::H3Accept(format!("{e:?}")))?
    {
        Some(r) => r,
        None => return Ok(()),
    };

    let (request, stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| HandlerError::H3Resolve(format!("{e:?}")))?;

    let path = request.uri().path().to_owned();
    let is_connect = request.method() == Method::CONNECT;
    let proto_header = request
        .headers()
        .get(SEC_PROTOCOL_HEADER)
        .and_then(|v| v.to_str().ok());
    let is_wt = proto_header
        .map(|s| s.eq_ignore_ascii_case(WEBTRANSPORT_PROTOCOL))
        .unwrap_or(false);
    let is_ws = proto_header
        .map(|s| s.eq_ignore_ascii_case(WEBSOCKET_PROTOCOL))
        .unwrap_or(false);

    let client_ip = peer
        .map(|sa| sa.ip().to_string())
        .unwrap_or_else(|| "0.0.0.0".to_owned());

    // RFC 9220 WS-over-H3: branch first so a WS request on the WS endpoint
    // doesn't fall through to the WT-only rejection below.
    if is_connect && is_ws {
        let Some(ctx) = ws_ctx.as_ref() else {
            debug!(%path, "wisp: WS-over-H3 request but ws_ctx not configured");
            return Ok(());
        };
        let Some(expected) = ws_endpoint.as_deref() else {
            debug!(%path, "wisp: ws_endpoint not configured");
            return Ok(());
        };
        let Some(view) = ctx.context_for_path(&path).await else {
            debug!(%path, expected, "wisp: WS path mismatch");
            return Ok(());
        };
        let policy = PreUpgradePolicy::new(view.options.clone(), dos.clone());
        if let Err(rej) = policy.check(request.headers(), &client_ip) {
            warn!(reason = rej.reason, "wisp: WS pre-upgrade rejected");
            return Ok(());
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
        info!(client_ip = %client_ip, "wisp: dispatching WS-over-H3");
        // Hold h3_conn on the stack across the WS pump so the H3 driver
        // keeps progressing the underlying QUIC connection. Once
        // serve_h3_websocket returns, the connection is done.
        let _h3_conn = h3_conn;
        return serve_h3_websocket(
            stream,
            client_ip,
            (**ctx).clone(),
            view,
            client_advertises_v2,
        )
        .await
        .map_err(|e| HandlerError::WsH3(e.to_string()));
    }

    if !is_connect || !is_wt || path != endpoint {
        debug!(method = %request.method(), %path, "rejecting non-wisp-wt request");
        return Ok(());
    }

    let policy = PreUpgradePolicy::new(Arc::new(options.base.clone()), dos.clone());
    let client_hash = match policy.check(request.headers(), &client_ip) {
        Ok(h) => h,
        Err(rej) => {
            warn!(reason = rej.reason, "wisp: pre-upgrade rejected");
            return Ok(());
        }
    };

    let session = WebTransportSession::accept(request, stream, h3_conn)
        .await
        .map_err(|e| HandlerError::WtAccept(format!("{e:?}")))?;
    info!(client_ip = %client_ip, "wisp: WebTransport session accepted");

    let mut ctx = SessionContext::new(client_ip, Arc::new(options.base.clone()), dos)
        .with_client_hash(client_hash);

    session_loop(session, &mut ctx, dgram_rx, dgram_send).await
}

async fn session_loop(
    session: WebTransportSession<MsQuicConnection, Bytes>,
    ctx: &mut SessionContext,
    dgram_rx: mpsc::UnboundedReceiver<Bytes>,
    dgram_send: wisp_quic_msquic::adapter::MsQuicDatagramSendHandle,
) -> Result<(), HandlerError> {
    let accepted = session
        .accept_bi()
        .await
        .map_err(|e| HandlerError::ControlAccept(format!("{e:?}")))?;
    let bidi = match accepted {
        Some(AcceptedBi::BidiStream(_, bidi)) => bidi,
        Some(AcceptedBi::Request(..)) => {
            return Err(HandlerError::ControlAccept(
                "first bidi was an HTTP request, not a WT bidi stream".into(),
            ))
        }
        None => return Ok(()),
    };

    let mut control_io: WtControlIo<MsQuicConnection, Bytes> = WtControlIo::new(bidi);
    if let Err(e) = negotiate_handshake(&mut control_io, ctx).await {
        return Err(HandlerError::Handshake(e));
    }

    info!(
        negotiated = ?ctx.negotiated.iter().collect::<Vec<_>>(),
        "wisp: handshake complete"
    );

    let (bidi, rx_buf) = control_io.into_inner();
    let (mut control_send, control_recv) = H3BidiStream::<Bytes>::split(bidi);
    let (control_writer_tx, mut control_writer_rx) = mpsc::unbounded_channel::<Bytes>();
    let writer_task = tokio::spawn(async move {
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
    let dgram_send = Arc::new(dgram_send);

    let session = Arc::new(session);
    let accept_session = session.clone();
    let accept_connector = tcp_connector.clone();
    let stream_logger = ctx.client_ip.clone();
    let accept_task = tokio::spawn(async move {
        accept_streams_loop(accept_session, accept_connector, stream_logger).await;
    });

    let demux_flows = udp_flows.clone();
    let demux_task = tokio::spawn(async move {
        datagram_demux_loop(dgram_rx, demux_flows).await;
    });

    let sink_options = ctx.options.clone();
    let mut sink = BridgeSink {
        flows: udp_flows.clone(),
        udp_connector,
        dgram_send: dgram_send.clone(),
        control_writer: control_writer_tx,
        options: sink_options,
    };

    let dispatch = SessionDispatch::new(ctx);
    let outcome = dispatch.run(&mut control_reader, &mut sink).await;

    udp_flows.shutdown_all();
    accept_task.abort();
    demux_task.abort();
    writer_task.abort();

    match outcome {
        ControlOutcome::PeerClose { reason } => {
            debug!(reason = reason, "wisp: peer CLOSE");
            Ok(())
        }
        ControlOutcome::PeerEof => Ok(()),
        ControlOutcome::Error(e) => Err(HandlerError::Control(e)),
    }
}

/// Hot loop: per-session, accept bidi streams and bridge to TCP/WT_PROXY_SUB.
async fn accept_streams_loop(
    session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    connector: Arc<TcpConnector>,
    client_ip: String,
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
            AcceptedBi::Request(..) => continue,
        };
        let connector = connector.clone();
        let client_ip = client_ip.clone();
        tokio::spawn(async move {
            if let Err(e) = bridge_one_stream(bidi, connector, &client_ip).await {
                debug!(client_ip = %client_ip, error = %e, "wisp: stream bridge ended");
            }
        });
    }
}

/// Reads the bidi header (priority + kind + tail) off the first bytes,
/// then either connects TCP and bidi-bridges (kind 0x01) or drops the stream
/// (WT_PROXY_SUB upstream bridging is the next milestone).
async fn bridge_one_stream(
    bidi: h3_webtransport::stream::BidiStream<
        <MsQuicConnection as h3::quic::OpenStreams<Bytes>>::BidiStream,
        Bytes,
    >,
    connector: Arc<TcpConnector>,
    client_ip: &str,
) -> Result<(), BridgeError> {
    let (mut send, mut recv) = H3BidiStream::<Bytes>::split(bidi);

    let mut rx_buf = BytesMut::with_capacity(1024);
    let (header, consumed) = loop {
        match try_parse_bidi_stream_header(&rx_buf)
            .map_err(|e| BridgeError::BadHeader(e.to_string()))?
        {
            Some((h, n)) => break (h, n),
            None => {
                let chunk = std::future::poll_fn(|cx| recv.poll_data(cx))
                    .await
                    .map_err(|e| BridgeError::Io(format!("wt recv (header): {e:?}")))?;
                match chunk {
                    Some(b) => rx_buf.extend_from_slice(b.chunk()),
                    None => return Ok(()),
                }
            }
        }
    };
    let _ = rx_buf.split_to(consumed);

    match header.kind {
        BidiStreamKind::Tcp { hostname, port } => {
            info!(
                client_ip = %client_ip,
                host = %hostname,
                port,
                priority = header.priority,
                "wisp: TCP bridge open"
            );
            let leftover = rx_buf.split().freeze();
            let tcp = connector
                .connect(&hostname, port)
                .await
                .map_err(|e| BridgeError::Proxy(e.to_string()))?;
            let (mut tcp_read, mut tcp_write) = tcp.into_split();

            if leftover.has_remaining() {
                tcp_write
                    .write_all(&leftover)
                    .await
                    .map_err(|e| BridgeError::Io(format!("tcp write (initial): {e}")))?;
            }

            let wt_to_tcp = async move {
                loop {
                    let chunk = std::future::poll_fn(|cx| recv.poll_data(cx))
                        .await
                        .map_err(|e| BridgeError::Io(format!("wt recv: {e:?}")))?;
                    match chunk {
                        Some(b) if b.has_remaining() => {
                            tcp_write
                                .write_all(b.chunk())
                                .await
                                .map_err(|e| BridgeError::Io(format!("tcp write: {e}")))?;
                        }
                        Some(_) => continue,
                        None => {
                            let _ = tcp_write.shutdown().await;
                            return Ok::<(), BridgeError>(());
                        }
                    }
                }
            };
            let tcp_to_wt = async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = tcp_read
                        .read(&mut buf)
                        .await
                        .map_err(|e| BridgeError::Io(format!("tcp read: {e}")))?;
                    if n == 0 {
                        return Ok::<(), BridgeError>(());
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

            let (a, b) = tokio::join!(wt_to_tcp, tcp_to_wt);
            a?;
            b?;
            Ok(())
        }
        BidiStreamKind::WtProxySub { session_id } => {
            debug!(session_id, "wisp: WT_PROXY_SUB stream (not yet bridged)");
            Ok(())
        }
    }
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
    dgram_send: Arc<wisp_quic_msquic::adapter::MsQuicDatagramSendHandle>,
    control_writer: mpsc::UnboundedSender<Bytes>,
    options: Arc<wisp_config::WispServerOptions>,
}

#[async_trait::async_trait]
impl ControlSink for BridgeSink {
    async fn on_control_text(&mut self, text: String) {
        debug!(text = %text, "wisp: CONTROL text frame");
    }
    async fn on_udp_open(&mut self, frame: UdpOpenFrame) {
        let flow_id = self.flows.alloc_id();
        debug!(
            flow_id = flow_id,
            host = %frame.hostname,
            port = frame.port,
            "wisp: UDP_OPEN"
        );
        let connector = self.udp_connector.clone();
        let dgram_send = self.dgram_send.clone();
        let flows = self.flows.clone();
        let control_writer = self.control_writer.clone();
        let max_age_ms = self.options.stream_idle_timeout_ms.unwrap_or(60_000);
        tokio::spawn(async move {
            open_udp_flow(
                flow_id,
                frame,
                connector,
                dgram_send,
                flows,
                control_writer,
                max_age_ms,
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
    async fn on_wt_proxy_open(&mut self, url: url::Url) {
        debug!(url = %url, "wisp: WT_PROXY_OPEN (upstream WT-proxy not yet wired)");
    }
    async fn on_wt_proxy_close(&mut self, frame: WtProxyClose) {
        debug!(
            session_id = frame.session_id,
            code = frame.code,
            reason = %frame.reason,
            "wisp: WT_PROXY_CLOSE"
        );
    }
}

// ---------------- UDP flow registry --------------------------------------

#[derive(Default)]
struct UdpFlowRegistry {
    flows: dashmap::DashMap<u32, UdpFlowHandle>,
    next_id: std::sync::atomic::AtomicU32,
}

struct UdpFlowHandle {
    upstream_tx: mpsc::UnboundedSender<Bytes>,
    cancel: tokio_util::sync::CancellationToken,
}

impl UdpFlowRegistry {
    fn alloc_id(&self) -> u32 {
        loop {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .wrapping_add(1);
            if id != 0 && !self.flows.contains_key(&id) {
                return id;
            }
        }
    }

    fn insert(&self, id: u32, handle: UdpFlowHandle) {
        self.flows.insert(id, handle);
    }

    fn route(&self, flow_id: u32, payload: Bytes) {
        if let Some(entry) = self.flows.get(&flow_id) {
            let _ = entry.upstream_tx.send(payload);
        }
    }

    fn close(&self, flow_id: u32) {
        if let Some((_, h)) = self.flows.remove(&flow_id) {
            h.cancel.cancel();
        }
    }

    fn shutdown_all(&self) {
        for entry in self.flows.iter() {
            entry.value().cancel.cancel();
        }
        self.flows.clear();
    }
}

/// Demux loop: pop one msquic datagram, parse the datagram header (always
/// class- and kind-prefixed), route by kind/flow_id.
async fn datagram_demux_loop(mut rx: mpsc::UnboundedReceiver<Bytes>, flows: Arc<UdpFlowRegistry>) {
    while let Some(buf) = rx.recv().await {
        match wisp_wire::parse_datagram(&buf) {
            Ok(d) => match d.kind {
                datagram_kind::UDP => {
                    flows.route(d.flow_id, d.payload);
                }
                datagram_kind::WT_PROXY => {
                    debug!(
                        flow = d.flow_id,
                        "wisp: WT_PROXY datagram (upstream pending)"
                    );
                }
                other => {
                    debug!(kind = other, "wisp: unknown datagram kind");
                }
            },
            Err(e) => {
                debug!(error = %e, "wisp: malformed datagram");
            }
        }
    }
}

/// Bring a UDP flow online: bind upstream, spawn recv pump, register tx side
/// so the demux task can shovel client datagrams upstream. Sends UDP_OPENED
/// back on the control bidi when the upstream is ready.
async fn open_udp_flow(
    flow_id: u32,
    frame: UdpOpenFrame,
    connector: Arc<wisp_proxy::UdpConnector>,
    dgram_send: Arc<wisp_quic_msquic::adapter::MsQuicDatagramSendHandle>,
    flows: Arc<UdpFlowRegistry>,
    control_writer: mpsc::UnboundedSender<Bytes>,
    max_age_ms: u64,
) {
    let sock = match connector.bind(&frame.hostname, frame.port).await {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, host = %frame.hostname, port = frame.port, "wisp: UDP bind failed");
            let _ = control_writer.send(wisp_wire::encode_udp_close_frame(flow_id, 0x03));
            return;
        }
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    let (upstream_tx, mut upstream_rx) = mpsc::unbounded_channel::<Bytes>();
    flows.insert(
        flow_id,
        UdpFlowHandle {
            upstream_tx,
            cancel: cancel.clone(),
        },
    );

    let _ = control_writer.send(wisp_wire::encode_udp_opened_frame(flow_id));

    let sock = Arc::new(sock);

    let sock_send = sock.clone();
    let cancel_send = cancel.clone();
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_send.cancelled() => return,
                maybe = upstream_rx.recv() => {
                    let Some(payload) = maybe else { return };
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
    let dgram_send_recv = dgram_send.clone();
    let max_age = std::time::Duration::from_millis(max_age_ms);
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            tokio::select! {
                _ = cancel_recv.cancelled() => return,
                _ = tokio::time::sleep(max_age) => {
                    debug!(flow_id, "wisp: UDP flow idle, closing");
                    return;
                }
                res = sock_recv.recv(&mut buf) => {
                    let n = match res {
                        Ok(n) => n,
                        Err(e) => {
                            debug!(error = %e, "wisp: UDP upstream recv failed");
                            return;
                        }
                    };
                    // Default class for upstream→client UDP is NORMAL.
                    // Heuristic upgrades (DNS = INTERACTIVE, etc.) can land
                    // on top later.
                    let dgram = wisp_wire::encode_datagram(
                        datagram_class::NORMAL,
                        datagram_kind::UDP,
                        flow_id,
                        &buf[..n],
                    );
                    if let Err(e) = dgram_send_recv.send(
                        dgram,
                        wisp_quic_msquic::adapter::DatagramClass::Normal,
                    ) {
                        debug!(error = ?e, "wisp: WT datagram send failed");
                        return;
                    }
                }
            }
        }
    });

    cancel.cancelled().await;
    let _ = send_task.await;
    let _ = recv_task.await;
    let _ = control_writer.send(wisp_wire::encode_udp_close_frame(flow_id, 0x00));
    flows.flows.remove(&flow_id);
}

#[derive(Debug, Error)]
enum HandlerError {
    #[error("h3 build: {0}")]
    H3Build(String),
    #[error("h3 accept: {0}")]
    H3Accept(String),
    #[error("h3 resolve: {0}")]
    H3Resolve(String),
    #[error("wt accept: {0}")]
    WtAccept(String),
    #[error("control accept: {0}")]
    ControlAccept(String),
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("control: {0}")]
    Control(String),
    #[error("ws-over-h3: {0}")]
    WsH3(String),
}

// ---------------- ControlIo over a WT bidi stream -----------------------

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

// ---------------- recv-only ControlIo over a split bidi --------------------

type WtBidiRecv = <h3_webtransport::stream::BidiStream<
    <MsQuicConnection as h3::quic::OpenStreams<Bytes>>::BidiStream,
    Bytes,
> as h3::quic::BidiStream<Bytes>>::RecvStream;

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

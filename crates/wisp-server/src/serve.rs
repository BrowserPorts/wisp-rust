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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use h3::quic::{
    BidiStream as H3BidiStream, RecvStream as _, SendStream as _, SendStreamUnframed as _,
};
use h3_webtransport::server::{AcceptedBi, WebTransportSession};
use http::Method;
use msquic::{Addr, BufferRef, Connection, Listener, ListenerEvent};
use parking_lot::Mutex;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wisp_config::{
    endpoint_matches, endpoint_path_token, normalize_endpoint, WispAuthRegistry, WispServerOptions,
    WispWtServerOptions, WISP_BASE_LIMIT_PROFILE,
};
use wisp_dos::{
    datagram_limit_decision, is_dns_resolution_allowed, is_tcp_stream_open_allowed,
    ConnectionDosGuard, ConnectionGuard, ConnectionLimiter, DatagramDecision, DosGuard,
    TcpByteLimiter,
};
use wisp_inspect::{inspect, InspectionDecision};
use wisp_iphash::IpHashBans;
use wisp_proxy::{HostPolicy, TcpConnector};
use wisp_quic_msquic::adapter::MsQuicConnection;
use wisp_quic_msquic::engine::{EngineConfig, EngineError, MsQuicEngine};
use wisp_wire::{
    datagram_class, datagram_kind, encode_control_frame, try_parse_bidi_stream_header,
    BidiStreamKind, Extension, ProxyControl, UdpClose, UdpOpenFrame, WebTransportProxy,
    WtProxyClose,
};
use wisp_wisp_server::{
    handle_proxy_control_text, ProxyController, ProxyControllerTemplate, ServerOptions,
};
use wisp_ws_h3::{serve_h3_websocket, H3WsContext};

use crate::control::{ControlOutcome, ControlSink, SessionDispatch};
use crate::handshake::{ControlIo, ControlIoError, HandshakeError};
use crate::policy::PreUpgradePolicy;
use crate::session::SessionContext;
use crate::udp_flow::{UdpFlowHandle, UdpFlowRegistry};
use crate::wt_proxy::{WtProxyError, WtProxyRegistry, WtProxySession};

const ALPN_H3: &str = "h3";
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

/// Optional extras for [`serve`]. Defaults keep the listener WT-only with no
/// proxy-control template.
#[derive(Clone, Default)]
pub struct ServeExtras {
    pub proxy_template: Option<Arc<ProxyControllerTemplate>>,
    /// Banned client IP hashes applied to WebTransport sessions. WS-over-H3
    /// uses the set on its [`H3WsContext`].
    pub ip_bans: Arc<IpHashBans>,
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
        peer_bidi_stream_count: if options.base.stream_limit_total == 0 {
            EngineConfig::default().peer_bidi_stream_count
        } else {
            options
                .base
                .stream_limit_total
                .saturating_add(1)
                .min(u64::from(u16::MAX)) as u16
        },
        idle_timeout_ms: options.base.idle_timeout_ms.unwrap_or(60_000).max(1),
        ..EngineConfig::default()
    };
    let engine = Arc::new(MsQuicEngine::new(&engine_cfg)?);
    let configuration = engine.configuration.clone();

    let raw_total_cap = if options.base.max_connections == 0 {
        RAW_CONNECTION_FALLBACK_CAP
    } else {
        options.base.max_connections
    };
    let raw_per_ip_cap = if options.base.max_connections_per_ip == 0 {
        RAW_CONNECTION_PER_IP_FALLBACK_CAP
    } else {
        options.base.max_connections_per_ip
    };
    let raw_limiter = Arc::new(ConnectionLimiter::new());
    let channel_capacity = usize::try_from(raw_total_cap)
        .unwrap_or(usize::MAX)
        .clamp(1, RAW_CONNECTION_FALLBACK_CAP as usize);
    let (conn_tx, conn_rx) =
        mpsc::channel::<(MsQuicConnection, Option<SocketAddr>, ConnectionGuard)>(channel_capacity);

    // The listener callback runs on an msquic worker thread with no Tokio
    // context, so hand it the runtime that `serve` was called on.
    let runtime = tokio::runtime::Handle::current();
    let listener = engine.open_listener(move |_, ev| {
        if let ListenerEvent::NewConnection { info, connection } = ev {
            let peer = info.remote_address.as_socket();
            // SAFETY: msquic transferred ownership in the listener callback.
            // We own the handle from this point; MsQuicConnection holds it
            // inside an Arc<Connection> for the connection lifetime.
            let owned: Connection = unsafe { Connection::from_raw(connection.as_raw()) };
            let client_ip = peer
                .map(|address| address.ip().to_string())
                .unwrap_or_else(|| "0.0.0.0".to_owned());
            let Some(raw_guard) =
                raw_limiter.try_acquire(&client_ip, raw_total_cap, raw_per_ip_cap)
            else {
                owned.shutdown(msquic::ConnectionShutdownFlags::SILENT, 0);
                return Ok(());
            };
            if let Err(status) = owned.set_configuration(&configuration) {
                warn!(?status, "set_configuration failed; rejecting connection");
                drop(owned);
                return Ok(());
            }
            let ms_conn = MsQuicConnection::install(owned, runtime.clone());
            if conn_tx.try_send((ms_conn, peer, raw_guard)).is_err() {
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
        connection_limiter,
        auth_registry,
        extras.proxy_template,
        extras.ip_bans,
    ));

    Ok(ServeHandle {
        _engine: engine,
        listener,
        cancel,
    })
}

async fn connection_acceptor(
    mut rx: mpsc::Receiver<(MsQuicConnection, Option<SocketAddr>, ConnectionGuard)>,
    options: Arc<WispWtServerOptions>,
    dos: Arc<DosGuard>,
    cancel: CancellationToken,
    ws_ctx: Option<Arc<H3WsContext>>,
    connection_limiter: Arc<ConnectionLimiter>,
    auth_registry: WispAuthRegistry,
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
    ip_bans: Arc<IpHashBans>,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("wisp: cancel received, exiting acceptor");
                return;
            }
            maybe = rx.recv() => {
                let Some((ms_conn, peer, raw_guard)) = maybe else {
                    info!("wisp: connection channel closed");
                    return;
                };
                let opts = options.clone();
                let dos = dos.clone();
                let ws_ctx = ws_ctx.clone();
                let connection_limiter = connection_limiter.clone();
                let auth_registry = auth_registry.clone();
                let proxy_template = proxy_template.clone();
                let ip_bans = ip_bans.clone();
                let connection_cancel = cancel.child_token();
                tokio::spawn(async move {
                    let result = tokio::select! {
                        _ = connection_cancel.cancelled() => return,
                        result = handle_connection(
                            ms_conn,
                            peer,
                            raw_guard,
                            opts,
                            dos,
                            ws_ctx,
                            connection_limiter,
                            auth_registry,
                            proxy_template,
                            ip_bans,
                        ) => result,
                    };
                    if let Err(e) = result {
                        debug!(error = %e, "wisp: connection handler ended");
                    }
                });
            }
        }
    }
}

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
    ip_bans: Arc<IpHashBans>,
) -> Result<(), HandlerError> {
    let endpoint = normalize_endpoint(&options.base.endpoint);
    let handshake_timeout =
        Duration::from_millis(options.base.handshake_timeout_ms.unwrap_or(10_000).max(1));
    let ws_endpoint = ws_ctx
        .as_ref()
        .map(|ctx| normalize_endpoint(&ctx.options.endpoint));
    let mut h3_conn: h3::server::Connection<MsQuicConnection, Bytes> = tokio::time::timeout(
        handshake_timeout,
        h3::server::builder()
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(1)
            .build(ms_conn),
    )
    .await
    .map_err(|_| HandlerError::H3Build("timed out".to_owned()))?
    .map_err(|e| HandlerError::H3Build(format!("{e:?}")))?;

    let resolver = match tokio::time::timeout(handshake_timeout, h3_conn.accept())
        .await
        .map_err(|_| HandlerError::H3Accept("timed out".to_owned()))?
        .map_err(|e| HandlerError::H3Accept(format!("{e:?}")))?
    {
        Some(r) => r,
        None => return Ok(()),
    };

    let (request, stream) = tokio::time::timeout(handshake_timeout, resolver.resolve_request())
        .await
        .map_err(|_| HandlerError::H3Resolve("timed out".to_owned()))?
        .map_err(|e| HandlerError::H3Resolve(format!("{e:?}")))?;

    let path = request.uri().path().to_owned();
    let is_connect = request.method() == Method::CONNECT;
    let protocol = request.extensions().get::<Protocol>();
    let is_wt = protocol == Some(&Protocol::WEB_TRANSPORT);
    let is_ws = protocol == Some(&Protocol::WEBSOCKET);

    let client_ip = peer
        .map(|sa| sa.ip().to_string())
        .unwrap_or_else(|| "0.0.0.0".to_owned());

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
            debug!(expected, "wisp: WS endpoint or authentication rejected");
            return Ok(());
        };
        let policy = PreUpgradePolicy::new(view.options.clone(), dos.clone())
            .with_ip_bans(ctx.ip_bans.clone());
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
        let _conn_guard = match ctx.connection_limiter.try_acquire(
            &client_ip,
            view.options.max_connections,
            view.options.max_connections_per_ip,
        ) {
            Some(guard) => guard,
            None => {
                warn!(client_ip = %client_ip, "wisp: rejecting WS-over-H3 concurrency cap");
                return Ok(());
            }
        };
        info!(client_ip = %client_ip, "wisp: dispatching WS-over-H3");
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

    if !is_connect
        || !is_wt
        || !(endpoint_matches(&path, &endpoint) || endpoint_path_token(&path, &endpoint).is_some())
    {
        debug!(method = %request.method(), %path, "rejecting non-wisp-wt request");
        return Ok(());
    }

    let effective_options = if let Some(token) = endpoint_path_token(&path, &endpoint) {
        if !options.base.auth.token_path {
            warn!("wisp: token paths are disabled");
            return Ok(());
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
            warn!("wisp: WebTransport authentication rejected");
            return Ok(());
        };
        Arc::new(resolved.options)
    } else {
        if options.base.auth.required {
            warn!("wisp: WebTransport authentication required");
            return Ok(());
        }
        auth_registry
            .profile(WISP_BASE_LIMIT_PROFILE)
            .map(Arc::new)
            .unwrap_or_else(|| Arc::new(options.base.clone()))
    };

    let policy =
        PreUpgradePolicy::new(effective_options.clone(), dos.clone()).with_ip_bans(ip_bans);
    let client_hash = match policy.check(request.headers(), &client_ip) {
        Ok(h) => h,
        Err(rej) => {
            warn!(reason = rej.reason, "wisp: pre-upgrade rejected");
            return Ok(());
        }
    };

    let _conn_guard = match connection_limiter.try_acquire(
        &client_ip,
        effective_options.max_connections,
        effective_options.max_connections_per_ip,
    ) {
        Some(g) => g,
        None => {
            warn!(client_ip = %client_ip, "wisp: rejecting: connection concurrency cap");
            return Ok(());
        }
    };

    let session = WebTransportSession::accept(request, stream, h3_conn)
        .await
        .map_err(|e| HandlerError::WtAccept(format!("{e:?}")))?;
    info!(client_ip = %client_ip, "wisp: WebTransport session accepted");

    let mut ctx =
        SessionContext::new(client_ip, effective_options, dos).with_client_hash(client_hash);

    session_loop(
        session,
        &mut ctx,
        options.webtransport_proxy_enabled,
        options.max_proxy_sessions_per_connection,
        options.max_proxy_substreams_per_session,
        options.max_datagram_bytes,
        options.proxy_control_enabled,
        proxy_template,
    )
    .await
}

async fn session_loop(
    session: WebTransportSession<MsQuicConnection, Bytes>,
    ctx: &mut SessionContext,
    wt_proxy_enabled: bool,
    max_proxy_sessions: u32,
    max_proxy_substreams: u32,
    max_datagram_bytes: u32,
    proxy_control_enabled: bool,
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
) -> Result<(), HandlerError> {
    let handshake_timeout =
        Duration::from_millis(ctx.options.handshake_timeout_ms.unwrap_or(10_000).max(1));
    let accepted = tokio::time::timeout(handshake_timeout, session.accept_bi())
        .await
        .map_err(|_| HandlerError::ControlAccept("timed out".to_owned()))?
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
            template.spawn(server_opts.proxy_control_limits(), None)
        })
    } else {
        None
    };
    if proxy_controller.is_some() {
        registry.register_raw(ProxyControl::ID, Bytes::from_static(br#"{"version":1}"#));
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

    info!(
        negotiated = ?ctx.negotiated.iter().collect::<Vec<_>>(),
        "wisp: handshake complete"
    );

    let (bidi, rx_buf) = control_io.into_inner();
    let (mut control_send, control_recv) = H3BidiStream::<Bytes>::split(bidi);
    let (control_writer_tx, mut control_writer_rx) = mpsc::channel::<Bytes>(64);
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
    let flow_shutdown = CancellationToken::new();
    let datagram_reader = session.datagram_reader();
    let mut datagram_sender = session.datagram_sender();
    let (datagram_tx, mut datagram_rx) =
        mpsc::channel::<DatagramEgress>(DATAGRAM_EGRESS_QUEUE_CAPACITY);
    let datagram_writer_task = tokio::spawn(async move {
        while let Some(queued) = datagram_rx.recv().await {
            if queued.frame.len() > max_datagram_bytes as usize {
                debug!(
                    bytes = queued.frame.len(),
                    "wisp: oversized WT datagram dropped"
                );
                continue;
            }
            let is_wt_proxy = queued.frame.get(1) == Some(&datagram_kind::WT_PROXY);
            if is_wt_proxy
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

    let session = Arc::new(session);
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
    let accept_session = session.clone();
    let accept_connector = tcp_connector.clone();
    let accept_wt_proxies = wt_proxies.clone();
    let accept_proxy = proxy_controller.clone();
    let stream_logger = ctx.client_ip.clone();
    let session_limits = SessionLimits::from_ctx(ctx);
    let accept_limits = session_limits.clone();
    let accept_task = tokio::spawn(async move {
        accept_streams_loop(
            accept_session,
            accept_connector,
            accept_wt_proxies,
            accept_proxy,
            stream_logger,
            accept_limits,
        )
        .await;
    });

    let demux_flows = udp_flows.clone();
    let demux_wt_proxies = wt_proxies.clone();
    let demux_limits = session_limits.clone();
    let udp_negotiated = ctx.has::<wisp_wire::Udp>();
    let demux_task = tokio::spawn(async move {
        datagram_demux_loop(
            datagram_reader,
            demux_flows,
            demux_wt_proxies,
            demux_limits,
            udp_negotiated,
            max_datagram_bytes,
        )
        .await;
    });

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
    };

    let dispatch = SessionDispatch::new(ctx);
    let outcome = dispatch.run(&mut control_reader, &mut sink).await;

    flow_shutdown.cancel();
    udp_flows.shutdown_all();
    if let Some(registry) = wt_proxies {
        registry.shutdown_all();
    }
    accept_task.abort();
    demux_task.abort();
    datagram_writer_task.abort();
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

/// Per-session DoS accounting threaded into the stream/datagram pump tasks so
/// the WT/QUIC path enforces the same per-IP / per-connection rate limits the
/// WS path does. Cloneable (all fields are `Arc`/`String`).
#[derive(Clone)]
struct SessionLimits {
    client_ip: String,
    options: Arc<WispServerOptions>,
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
            options: ctx.options.clone(),
            dos: ctx.dos.clone(),
            conn_dos: ctx.conn_dos.clone(),
            tcp_bytes,
            stream_caps: Arc::new(WtStreamCaps::new(&ctx.options)),
        }
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

/// Hot loop: per-session, accept bidi streams and bridge to TCP/WT_PROXY_SUB.
async fn accept_streams_loop(
    session: Arc<WebTransportSession<MsQuicConnection, Bytes>>,
    connector: Arc<TcpConnector>,
    wt_proxies: Option<Arc<WtProxyRegistry>>,
    proxy_controller: Option<Arc<ProxyController>>,
    client_ip: String,
    limits: SessionLimits,
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
        let limits = limits.clone();
        let wt_proxies = wt_proxies.clone();
        let proxy_controller = proxy_controller.clone();
        tokio::spawn(async move {
            if let Err(e) = bridge_one_stream(
                bidi,
                connector,
                wt_proxies,
                proxy_controller,
                &client_ip,
                &limits,
            )
            .await
            {
                debug!(client_ip = %client_ip, error = %e, "wisp: stream bridge ended");
            }
        });
    }
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
    client_ip: &str,
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
            if !limits.tcp_open_allowed(&hostname) {
                info!(
                    client_ip = %client_ip,
                    host = %hostname,
                    port,
                    "wisp: TCP bridge rejected (stream-open / dns rate limit)"
                );
                return Ok(());
            }
            info!(
                client_ip = %client_ip,
                host = %hostname,
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
                tokio::time::timeout(inspection_timeout, async {
                    loop {
                        let inspected_len = rx_buf.len().min(inspection_max);
                        match inspect(&rx_buf[..inspected_len], &limits.options) {
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
                .map_err(|_| BridgeError::Io("protocol inspection timed out".to_owned()))??;
            }
            let leftover = rx_buf.split().freeze();
            if !leftover.is_empty() && !limits.tcp_bytes_allowed(leftover.len() as u64) {
                return Err(BridgeError::Io(
                    "client->upstream byte rate exceeded".to_owned(),
                ));
            }
            let tcp = match proxy_controller.as_ref() {
                Some(controller) => {
                    let policy = HostPolicy::from_options(&limits.options);
                    controller
                        .connect_tcp(&hostname, port, limits.options.force_proxy, &policy)
                        .await
                        .map(|(stream, _)| stream)
                        .map_err(|e| BridgeError::Proxy(e.to_string()))?
                }
                None => {
                    if limits.options.force_proxy {
                        return Err(BridgeError::Proxy(
                            "force_proxy requires proxy control".to_owned(),
                        ));
                    }
                    connector
                        .connect(&hostname, port)
                        .await
                        .map_err(|e| BridgeError::Proxy(e.to_string()))?
                }
            };
            let (mut tcp_read, mut tcp_write) = tcp.into_split();

            if leftover.has_remaining() {
                tcp_write
                    .write_all(&leftover)
                    .await
                    .map_err(|e| BridgeError::Io(format!("tcp write (initial): {e}")))?;
            }

            let idle = Duration::from_millis(
                limits
                    .options
                    .stream_idle_timeout_ms
                    .unwrap_or(600_000)
                    .max(1),
            );
            let limits_up = limits.clone();
            let wt_to_tcp = async move {
                loop {
                    let chunk = match tokio::time::timeout(
                        idle,
                        std::future::poll_fn(|cx| recv.poll_data(cx)),
                    )
                    .await
                    {
                        Ok(r) => r.map_err(|e| BridgeError::Io(format!("wt recv: {e:?}")))?,
                        Err(_) => {
                            let _ = tcp_write.shutdown().await;
                            return Ok::<(), BridgeError>(());
                        }
                    };
                    match chunk {
                        Some(b) if b.has_remaining() => {
                            if !limits_up.tcp_bytes_allowed(b.chunk().len() as u64) {
                                return Err(BridgeError::Io(
                                    "client->upstream byte rate exceeded".into(),
                                ));
                            }
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
            let limits_down = limits.clone();
            let tcp_to_wt = async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match tokio::time::timeout(idle, tcp_read.read(&mut buf)).await {
                        Ok(r) => r.map_err(|e| BridgeError::Io(format!("tcp read: {e}")))?,
                        Err(_) => return Ok::<(), BridgeError>(()),
                    };
                    if n == 0 {
                        return Ok::<(), BridgeError>(());
                    }
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

            let (a, b) = tokio::join!(wt_to_tcp, tcp_to_wt);
            a?;
            b?;
            Ok(())
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

    let idle = Duration::from_millis(
        limits
            .options
            .stream_idle_timeout_ms
            .unwrap_or(600_000)
            .max(1),
    );
    let upstream_cancel = upstream.cancel.clone();
    let up_limits = limits.clone();
    let downstream_to_upstream = async move {
        loop {
            let chunk = tokio::time::timeout(
                idle,
                std::future::poll_fn(|cx| downstream_recv.poll_data(cx)),
            )
            .await
            .map_err(|_| BridgeError::Io("downstream WT stream idle timeout".to_owned()))?
            .map_err(|e| BridgeError::Io(format!("downstream WT receive: {e:?}")))?;
            match chunk {
                Some(bytes) if bytes.has_remaining() => {
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
    let down_limits = limits.clone();
    let upstream_to_downstream = async move {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = tokio::time::timeout(
                idle,
                tokio::io::AsyncReadExt::read(&mut upstream_recv, &mut buffer),
            )
            .await
            .map_err(|_| BridgeError::Io("upstream WT stream idle timeout".to_owned()))?
            .map_err(|e| BridgeError::Io(format!("upstream WT read: {e}")))?;
            if read == 0 {
                std::future::poll_fn(|cx| downstream_send.poll_finish(cx))
                    .await
                    .map_err(|e| BridgeError::Io(format!("downstream WT finish: {e:?}")))?;
                return Ok::<(), BridgeError>(());
            }
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
) {
    let datagram_upstream = upstream.clone();
    let datagram_limits = limits.clone();
    tokio::spawn(async move {
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
    tokio::spawn(async move {
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
            tokio::spawn(async move {
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
    tokio::spawn(async move {
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

    tokio::spawn(async move {
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
    let idle = Duration::from_millis(
        limits
            .options
            .stream_idle_timeout_ms
            .unwrap_or(600_000)
            .max(1),
    );
    let up_limits = limits.clone();
    let downstream_to_upstream = async move {
        loop {
            let chunk = tokio::time::timeout(
                idle,
                std::future::poll_fn(|cx| downstream_recv.poll_data(cx)),
            )
            .await
            .map_err(|_| BridgeError::Io("downstream WT stream idle timeout".to_owned()))?
            .map_err(|e| BridgeError::Io(format!("downstream WT receive: {e:?}")))?;
            match chunk {
                Some(bytes) if bytes.has_remaining() => {
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
    let down_limits = limits;
    let upstream_to_downstream = async move {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = tokio::time::timeout(
                idle,
                tokio::io::AsyncReadExt::read(&mut upstream_recv, &mut buffer),
            )
            .await
            .map_err(|_| BridgeError::Io("upstream WT stream idle timeout".to_owned()))?
            .map_err(|e| BridgeError::Io(format!("upstream WT read: {e}")))?;
            if read == 0 {
                std::future::poll_fn(|cx| downstream_send.poll_finish(cx))
                    .await
                    .map_err(|e| BridgeError::Io(format!("downstream WT finish: {e:?}")))?;
                return Ok::<(), BridgeError>(());
            }
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
        tokio::spawn(async move {
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
        if !self.limits.dns_allowed(&frame.hostname) {
            debug!(host = %frame.hostname, "wisp: UDP_OPEN rejected: DNS rate limit");
            return;
        }
        let flow_permit = match self.udp_slots.as_ref() {
            Some(slots) => match slots.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    debug!(host = %frame.hostname, "wisp: UDP_OPEN rejected: concurrent flow cap");
                    return;
                }
            },
            None => None,
        };
        let flow_cap = self.options.stream_limit_total;
        if flow_cap != 0 && self.flows.len() as u64 >= flow_cap {
            debug!(
                host = %frame.hostname,
                port = frame.port,
                cap = flow_cap,
                "wisp: UDP_OPEN rejected: concurrent flow cap"
            );
            return;
        }
        let flow_id = self.flows.alloc_id();
        debug!(
            flow_id = flow_id,
            host = %frame.hostname,
            port = frame.port,
            "wisp: UDP_OPEN"
        );
        let connector = self.udp_connector.clone();
        let datagram_tx = self.datagram_tx.clone();
        let flows = self.flows.clone();
        let control_writer = self.control_writer.clone();
        let limits = self.limits.clone();
        let flow_shutdown = self.flow_shutdown.clone();
        let max_age_ms = self.options.stream_idle_timeout_ms.unwrap_or(60_000);
        tokio::spawn(async move {
            open_udp_flow(
                flow_id,
                frame,
                connector,
                datagram_tx,
                flows,
                control_writer,
                limits,
                max_age_ms,
                flow_shutdown,
                flow_permit,
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
        tokio::spawn(async move {
            let opened = tokio::select! {
                _ = session_cancel.cancelled() => return,
                result = registry.open(&url) => result,
            };
            match opened {
                Ok(upstream) => {
                    info!(
                        session_id = upstream.id,
                        host = %upstream.session.request().url.host_str().unwrap_or("unknown"),
                        "wisp: upstream WebTransport session opened"
                    );
                    send_wt_uni_reply(
                        downstream.clone(),
                        wisp_wire::encode_wt_proxy_opened_frame(upstream.id),
                    )
                    .await;
                    pump_upstream_session(registry, upstream, downstream, datagram_tx, limits);
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
}

/// Pops one QUIC datagram, parses its class- and kind-prefixed header, and
/// routes it by kind and flow id.
async fn datagram_demux_loop(
    mut reader: h3_datagram::datagram_handler::DatagramReader<
        wisp_quic_msquic::adapter::MsQuicDatagramReceiver,
    >,
    flows: Arc<UdpFlowRegistry>,
    wt_proxies: Option<Arc<WtProxyRegistry>>,
    limits: SessionLimits,
    udp_negotiated: bool,
    max_datagram_bytes: u32,
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
        match limits.datagram_decision(buf.len() as u64) {
            DatagramDecision::Allow => {}
            DatagramDecision::Drop => continue,
            DatagramDecision::Close => {
                warn!("wisp: datagram rate exceeded; stopping demux");
                return;
            }
        }
        match wisp_wire::parse_datagram(&buf) {
            Ok(d) => match d.kind {
                datagram_kind::UDP => {
                    if !udp_negotiated {
                        warn!("wisp: UDP datagram received without negotiated extension");
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
                        warn!("wisp: WT_PROXY datagram received without negotiated extension");
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
                other => {
                    debug!(kind = other, "wisp: unknown datagram kind dropped");
                }
            },
            Err(e) => {
                warn!(error = %e, "wisp: malformed datagram");
                return;
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
    datagram_tx: mpsc::Sender<DatagramEgress>,
    flows: Arc<UdpFlowRegistry>,
    control_writer: mpsc::Sender<Bytes>,
    limits: SessionLimits,
    max_age_ms: u64,
    session_cancel: CancellationToken,
    flow_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    let sock = tokio::select! {
        _ = session_cancel.cancelled() => return,
        result = connector.bind(&frame.hostname, frame.port) => {
            match result {
                Ok(sock) => sock,
                Err(e) => {
                    debug!(error = %e, host = %frame.hostname, port = frame.port, "wisp: UDP bind failed");
                    let _ = control_writer
                        .send(wisp_wire::encode_udp_close_frame(flow_id, 0x03))
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

    let _ = control_writer
        .send(wisp_wire::encode_udp_opened_frame(flow_id))
        .await;

    let sock = Arc::new(sock);

    let sock_send = sock.clone();
    let cancel_send = cancel.clone();
    let mut pumps = JoinSet::new();
    pumps.spawn(async move {
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
    let datagram_tx_recv = datagram_tx.clone();
    let recv_limits = limits;
    let max_age = std::time::Duration::from_millis(max_age_ms);
    pumps.spawn(async move {
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

    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = pumps.join_next() => {}
    }
    cancel.cancel();
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

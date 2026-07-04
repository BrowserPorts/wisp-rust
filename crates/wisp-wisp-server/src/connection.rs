//! Per-connection Wisp driver. Each accepted WebSocket connection
//! (after the extended-CONNECT upgrade) becomes one [`serve_connection`]
//! call. The driver dispatches on the resolved Wisp version (v1 or v2) BEFORE
//! emitting any handshake bytes — v2 clients receive byte-identical wire
//! traces to the prior v2-only behavior, while v1 clients (e.g. wisp-js
//! without `Sec-WebSocket-Protocol: wisp-v2`) skip the v2 INFO exchange and
//! proceed directly to the v1 CONTINUE-first stream phase. Resolution is
//! controlled by `ServerOptions::wisp_version` (V1, V2, or Auto, where
//! Auto inspects `ServerContext::client_advertises_v2`).
//!
//! In v2 mode the driver:
//!
//! 1. Sends the server INFO packet (with negotiated extensions per
//!    [`ServerOptions`]).
//! 2. Awaits the client INFO and intersects extension sets.
//! 3. Sends CONTINUE(0, buffer_size).
//!
//! In v1 mode the driver sends CONTINUE(0, buffer_size) immediately and
//! treats negotiated extensions as empty (v1 has no extension mechanism).
//!
//! From there both versions share the same loop:
//! routes each subsequent packet — CONNECT opens a stream, DATA forwards
//! payload, CONTINUE updates client-side flow control (no-op server-side
//! for the simple model), CLOSE tears down a stream, INFO is a protocol
//! error after the initial handshake. Text-frame payloads on stream 0 are
//! routed to the proxy-control handler when
//! [`extension_id::STELLITE_PROXY_CONTROL`] is negotiated (v2 only).
//!
//! The TCP stream-open path runs [`wisp_inspect::inspect`] before
//! upstream bytes flow, mirroring the existing WT server.

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;
use wisp_config::{WispServerOptions, WispVersion};
use wisp_dos::{
    global_guard, is_dns_resolution_allowed, is_tcp_stream_open_allowed, ConnectionDosGuard,
    DosGuard,
};
use wisp_proxy::HostPolicy;
use wisp_wisp::{
    close_reason, encode_close, encode_continue, encode_info, extension_id,
    parse_extensions_capped, parse_packet, stream_type, ExtensionEntry, WispError, WispPacket,
    DEFAULT_MAX_EXTENSION_ENTRIES,
};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

const WISP_MAJOR_VERSION: u8 = 2;

use crate::proxy_control::{handle_proxy_control_text, ProxyControlLimits, ProxyController};
use crate::stream::{spawn_tcp_stream, StreamHandle, TcpStreamMsg};
use crate::udp::{spawn_udp_stream, UdpStreamMsg};

/// Tagged WS-frame envelope. The transport layer (H2 or H3 + tokio-websockets)
/// preserves the binary/text distinction so the server can route text frames
/// to STELLITE_PROXY_CONTROL while keeping binary on the Wisp v2 codec path.
#[derive(Debug, Clone)]
pub enum WispMessage {
    Binary(Bytes),
    Text(String),
}

impl WispMessage {
    pub fn binary(b: Bytes) -> Self {
        WispMessage::Binary(b)
    }
    pub fn text(s: String) -> Self {
        WispMessage::Text(s)
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("client transport closed")]
    ClientClosed,
    #[error("client transport error: {0}")]
    Transport(String),
    #[error("wisp protocol error: {0}")]
    Protocol(#[from] WispError),
    #[error("initial INFO packet missing or invalid")]
    BadHandshake,
    #[error("stream id collision: {0}")]
    StreamCollision(u32),
    #[error("wisp protocol violation: {0}")]
    ProtocolViolation(&'static str),
}

/// Per-connection server options. Mirrors the subset of
/// [`WispServerOptions`] that affects the WS conversation. There is no
/// MOTD field — MOTD is intentionally omitted from wisp-wt-rust as dead
/// weight from the bun reference; it will never be emitted or honored.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub buffer_size: u32,
    pub continue_threshold: u32,
    pub allow_udp_streams: bool,
    pub allow_tcp_streams: bool,
    pub proxy_control_enabled: bool,
    /// Cap on per-packet payload bytes (defends against gigantic frames).
    /// Matches `WispServerOptions::max_binary_frame_bytes`.
    pub max_binary_frame_bytes: u32,
    pub max_text_frame_bytes: u32,
    /// Audit-3 fix #63: hard cap on total concurrent streams (TCP+UDP)
    /// per WebSocket connection. 0 disables the cap.
    pub stream_limit_total: u32,
    /// Audit-3 fix #63: cap on concurrent streams per upstream host:port
    /// key. `None` (i.e. configured value < 0) disables the per-host cap.
    pub stream_limit_per_host: Option<u32>,
    /// Audit-3 fix #63: ceiling on stream-open events per minute per
    /// connection. 0 disables.
    pub max_tcp_stream_opens_per_connection_per_minute: u32,
    /// Audit-3 fix #67: ceiling on incoming text (proxy_control) frames
    /// parsed per minute per connection. Kicks in BEFORE
    /// `serde_json::from_str` so an attacker cannot force the parser at
    /// line speed. 0 disables.
    pub max_control_messages_per_connection_per_minute: u32,
    pub max_binary_packets_per_connection_per_minute: u32,
    pub max_concurrent_proxy_control_handlers: usize,
    pub proxy_control_ext_payload_max_bytes: usize,
    pub max_proxy_rules_per_connection: usize,
    pub max_proxy_control_reply_bytes: usize,
    pub max_proxy_rule_field_bytes: usize,
    pub proxy_control_upstream_ops_per_second: u32,
    pub proxy_control_upstream_burst: u32,
    pub proxy_control_mutation_ops_per_second: u32,
    pub proxy_control_mutation_burst: u32,
    pub wisp_version: WispVersion,
}

impl ServerOptions {
    /// Project the WS-relevant subset of [`WispServerOptions`] into the
    /// per-connection runtime view. `proxy_control_enabled` is passed in
    /// separately because [`WispServerOptions`] does not yet expose it
    /// (task #41 wires it through TOML).
    pub fn from_wisp(options: &WispServerOptions, proxy_control_enabled: bool) -> Self {
        Self {
            buffer_size: options.buffer_size.try_into().unwrap_or(u32::MAX),
            continue_threshold: options.continue_threshold.try_into().unwrap_or(u32::MAX),
            allow_udp_streams: options.allow_udp_streams,
            allow_tcp_streams: options.allow_tcp_streams,
            proxy_control_enabled,
            max_binary_frame_bytes: options
                .max_binary_frame_bytes
                .try_into()
                .unwrap_or(u32::MAX),
            max_text_frame_bytes: options.max_text_frame_bytes.try_into().unwrap_or(u32::MAX),
            stream_limit_total: options.stream_limit_total.try_into().unwrap_or(u32::MAX),
            stream_limit_per_host: if options.stream_limit_per_host < 0 {
                None
            } else {
                Some(u32::try_from(options.stream_limit_per_host).unwrap_or(u32::MAX))
            },
            max_tcp_stream_opens_per_connection_per_minute: options
                .max_tcp_stream_opens_per_connection_per_minute
                .try_into()
                .unwrap_or(u32::MAX),
            max_control_messages_per_connection_per_minute: options
                .max_control_messages_per_connection_per_minute
                .try_into()
                .unwrap_or(u32::MAX),
            max_binary_packets_per_connection_per_minute: options
                .max_binary_packets_per_connection_per_minute
                .try_into()
                .unwrap_or(u32::MAX),
            max_concurrent_proxy_control_handlers: usize::try_from(
                options.max_concurrent_proxy_control_handlers,
            )
            .unwrap_or(usize::MAX),
            proxy_control_ext_payload_max_bytes: usize::try_from(
                options.proxy_control_ext_payload_max_bytes,
            )
            .unwrap_or(usize::MAX),
            max_proxy_rules_per_connection: usize::try_from(options.max_proxy_rules_per_connection)
                .unwrap_or(usize::MAX),
            max_proxy_control_reply_bytes: usize::try_from(options.max_proxy_control_reply_bytes)
                .unwrap_or(usize::MAX),
            max_proxy_rule_field_bytes: usize::try_from(options.max_proxy_rule_field_bytes)
                .unwrap_or(usize::MAX),
            proxy_control_upstream_ops_per_second: options.proxy_control_upstream_ops_per_second,
            proxy_control_upstream_burst: options.proxy_control_upstream_burst,
            proxy_control_mutation_ops_per_second: options.proxy_control_mutation_ops_per_second,
            proxy_control_mutation_burst: options.proxy_control_mutation_burst,
            wisp_version: options.wisp_version,
        }
    }

    pub fn proxy_control_limits(&self) -> ProxyControlLimits {
        let defaults = ProxyControlLimits::default();
        ProxyControlLimits {
            max_rules: self.max_proxy_rules_per_connection,
            max_reply_bytes: self.max_proxy_control_reply_bytes,
            max_field_bytes: self.max_proxy_rule_field_bytes,
            upstream_ops_per_second: NonZeroU32::new(self.proxy_control_upstream_ops_per_second)
                .unwrap_or(defaults.upstream_ops_per_second),
            upstream_burst: NonZeroU32::new(self.proxy_control_upstream_burst)
                .unwrap_or(defaults.upstream_burst),
            mutation_ops_per_second: NonZeroU32::new(self.proxy_control_mutation_ops_per_second)
                .unwrap_or(defaults.mutation_ops_per_second),
            mutation_burst: NonZeroU32::new(self.proxy_control_mutation_burst)
                .unwrap_or(defaults.mutation_burst),
        }
    }
}

/// Shared per-connection state.
#[derive(Clone)]
pub struct ServerContext {
    pub client_ip: String,
    pub client_hash: Option<String>,
    pub options: Arc<WispServerOptions>,
    pub server_options: Arc<ServerOptions>,
    /// Per-process proxy controller. `None` when STELLITE_PROXY_CONTROL is
    /// not configured at the runtime layer; the negotiation falls back to
    /// "advertise but not active" and text frames are dropped.
    pub proxy_controller: Option<Arc<ProxyController>>,
    /// Whether the client advertised the `wisp-v2` Sec-WebSocket-Protocol
    /// subprotocol during the WebSocket upgrade. Used by the Auto wisp
    /// version resolver in `serve_connection` to pick the v1 vs v2 path
    /// before any handshake bytes are written. Transports that cannot
    /// observe the upgrade header (e.g. msquic WT-style streams that have
    /// no equivalent) should set this to `true` to preserve the v2 default.
    pub client_advertises_v2: bool,
    pub policy: Arc<HostPolicy>,
    pub dos_store: Arc<DosGuard>,
    pub conn_dos: Arc<ConnectionDosGuard>,
    /// Per-connection cancellation token. Cloned into every spawned stream /
    /// UDP-flow task so their blocking reads can wake on connection
    /// shutdown instead of waiting on a closed channel that the kernel
    /// never tells them about. `serve_connection` sets this to a fresh
    /// token before spawning anything and cancels it on exit.
    pub cancel: CancellationToken,
}

impl ServerContext {
    /// Build a context with a fresh CancellationToken. Adapters that don't
    /// have a parent token (the typical case — H2 / H3 dispatch builds a
    /// new ServerContext per upgrade) should call this rather than
    /// constructing the struct literal so the token is never accidentally
    /// shared across unrelated connections.
    pub fn new(
        client_ip: String,
        client_hash: Option<String>,
        options: Arc<WispServerOptions>,
        server_options: Arc<ServerOptions>,
        proxy_controller: Option<Arc<ProxyController>>,
        client_advertises_v2: bool,
    ) -> Self {
        let policy = Arc::new(HostPolicy::from_options(&options));
        Self {
            client_ip,
            client_hash,
            options,
            server_options,
            proxy_controller,
            client_advertises_v2,
            policy,
            dos_store: global_guard(),
            conn_dos: Arc::new(ConnectionDosGuard::new()),
            cancel: CancellationToken::new(),
        }
    }
}

/// Drive a single Wisp v2 conversation over a duplex message stream.
///
/// `messages` is an object-stream of [`bytes::Bytes`] — each item is one
/// WebSocket message (already de-framed by the underlying transport).
/// `outgoing` is a sink for server→client messages. Returning `Ok(())`
/// indicates a clean shutdown initiated by either side.
pub async fn serve_connection<TxErr, RxErr, Tx, Rx>(
    mut outgoing: Tx,
    mut incoming: Rx,
    ctx: ServerContext,
) -> Result<(), ServerError>
where
    Tx: Sink<WispMessage, Error = TxErr> + Unpin + Send + 'static,
    Rx: Stream<Item = Result<WispMessage, RxErr>> + Unpin + Send,
    TxErr: std::fmt::Display + Send + 'static,
    RxErr: std::fmt::Display + Send,
{
    // Audit fix #6: derive proxy_control activation from both the
    // deployer-level flag AND the actual controller wiring. A
    // misconfigured deployment (flag on, no providers registered) would
    // otherwise advertise the extension AND accept negotiation but then
    // silently drop every text frame — the client thinks it has
    // proxy_control but no implementation runs.
    let proxy_control_active =
        ctx.server_options.proxy_control_enabled && ctx.proxy_controller.is_some();

    let (egress_tx, mut egress_rx) = mpsc::channel::<WispMessage>(4096);

    let (control_egress_tx, mut control_egress_rx) = mpsc::channel::<String>(8);
    let control_concurrency = Arc::new(Semaphore::new(
        ctx.server_options
            .max_concurrent_proxy_control_handlers
            .max(1),
    ));

    let egress_writer_cancel = ctx.cancel.clone();
    let egress_writer = tokio::spawn(async move {
        let mut main_closed = false;
        let mut ctl_closed = false;
        let mut batch: Vec<WispMessage> = Vec::with_capacity(64);
        while !(main_closed && ctl_closed) {
            let first = tokio::select! {
                biased;
                _ = egress_writer_cancel.cancelled() => break,
                msg = egress_rx.recv(), if !main_closed => match msg {
                    Some(m) => Some(m),
                    None => { main_closed = true; continue; }
                },
                text = control_egress_rx.recv(), if !ctl_closed => match text {
                    Some(t) => Some(WispMessage::Text(t)),
                    None => { ctl_closed = true; continue; }
                },
            };
            let Some(m) = first else { continue };
            batch.push(m);
            while batch.len() < 64 {
                match egress_rx.try_recv() {
                    Ok(m) => batch.push(m),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        main_closed = true;
                        break;
                    }
                }
            }
            if batch.len() < 64 && !ctl_closed {
                while batch.len() < 64 {
                    match control_egress_rx.try_recv() {
                        Ok(t) => batch.push(WispMessage::Text(t)),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            ctl_closed = true;
                            break;
                        }
                    }
                }
            }
            for m in batch.drain(..) {
                if let Err(e) = outgoing.feed(m).await {
                    return Err(e.to_string());
                }
            }
            if let Err(e) = outgoing.flush().await {
                return Err(e.to_string());
            }
        }
        if let Err(e) = outgoing.close().await {
            return Err(e.to_string());
        }
        Ok::<(), String>(())
    });

    let resolved_version =
        resolve_wisp_version(ctx.server_options.wisp_version, ctx.client_advertises_v2);

    let negotiated = match resolved_version {
        ResolvedVersion::V2 => {
            let server_info = build_server_info(&ctx.server_options, proxy_control_active);
            if egress_tx
                .send(WispMessage::Binary(server_info))
                .await
                .is_err()
            {
                return Err(ServerError::ClientClosed);
            }

            let client_info = match incoming.next().await {
                Some(Ok(WispMessage::Binary(b))) => b,
                Some(Ok(WispMessage::Text(_))) => return Err(ServerError::BadHandshake),
                Some(Err(e)) => return Err(ServerError::Transport(e.to_string())),
                None => return Err(ServerError::ClientClosed),
            };
            if client_info.len() as u64 > ctx.server_options.max_binary_frame_bytes as u64 {
                return Err(ServerError::BadHandshake);
            }
            let parsed = parse_packet(client_info)?;
            let neg = match parsed {
                WispPacket::Info(info)
                    if info.stream_id == 0 && info.major == WISP_MAJOR_VERSION =>
                {
                    intersect_extensions(
                        &ctx.server_options,
                        proxy_control_active,
                        parse_extensions_capped(info.extensions, DEFAULT_MAX_EXTENSION_ENTRIES)?,
                    )
                }
                WispPacket::Info(_) => {
                    if egress_tx
                        .send(WispMessage::Binary(encode_close(
                            0,
                            close_reason::INVALID_INFO,
                        )))
                        .await
                        .is_err()
                    {
                        return Err(ServerError::ClientClosed);
                    }
                    return Err(ServerError::BadHandshake);
                }
                _ => return Err(ServerError::BadHandshake),
            };

            if egress_tx
                .send(WispMessage::Binary(encode_continue(
                    0,
                    ctx.server_options.buffer_size,
                )))
                .await
                .is_err()
            {
                return Err(ServerError::ClientClosed);
            }
            neg
        }
        ResolvedVersion::V1 => {
            tracing::debug!(
                client_ip = %ctx.client_ip,
                "wisp handshake resolved to v1 (no Sec-WebSocket-Protocol)"
            );
            if egress_tx
                .send(WispMessage::Binary(encode_continue(
                    0,
                    ctx.server_options.buffer_size,
                )))
                .await
                .is_err()
            {
                return Err(ServerError::ClientClosed);
            }
            NegotiatedExtensions::default()
        }
    };

    let mut streams: HashMap<u32, StreamHandle> = HashMap::new();
    let mut udp_streams: HashMap<u32, mpsc::Sender<UdpStreamMsg>> = HashMap::new();
    let mut caps = StreamCaps::new(&ctx.server_options);
    let (stream_done_tx, mut stream_done_rx) = mpsc::channel::<u32>(256);
    let control_msg_limiter: Option<DirectLimiter> = build_per_minute_limiter(
        ctx.server_options
            .max_control_messages_per_connection_per_minute,
    );
    let binary_packet_limiter: Option<DirectLimiter> = build_per_minute_limiter(
        ctx.server_options
            .max_binary_packets_per_connection_per_minute,
    );
    let mut serve_err: Option<ServerError> = None;

    loop {
        let msg = tokio::select! {
            recv = incoming.next() => match recv {
                Some(Ok(m)) => m,
                Some(Err(e)) => {
                    serve_err = Some(ServerError::Transport(e.to_string()));
                    break;
                }
                None => break,
            },
            done = stream_done_rx.recv() => {
                if let Some(stream_id) = done {
                    streams.remove(&stream_id);
                    udp_streams.remove(&stream_id);
                    caps.release(stream_id);
                }
                continue;
            }
        };
        match msg {
            WispMessage::Binary(frame) => {
                if frame.len() as u64 > ctx.server_options.max_binary_frame_bytes as u64 {
                    let _ = egress_tx
                        .send(WispMessage::Binary(encode_close(
                            0,
                            close_reason::CLIENT_ERROR,
                        )))
                        .await;
                    break;
                }
                if let Some(lim) = binary_packet_limiter.as_ref() {
                    if lim.check().is_err() {
                        tracing::warn!(
                            "wisp: closing connection: per-conn binary parse rate exceeded",
                        );
                        let _ = egress_tx
                            .send(WispMessage::Binary(encode_close(
                                0,
                                close_reason::CONN_THROTTLED,
                            )))
                            .await;
                        break;
                    }
                }
                let packet = match parse_packet(frame) {
                    Ok(p) => p,
                    Err(e) => {
                        serve_err = Some(e.into());
                        break;
                    }
                };
                if let Err(e) = handle_packet(
                    packet,
                    &mut streams,
                    &mut udp_streams,
                    &mut caps,
                    &ctx,
                    &negotiated,
                    &egress_tx,
                    &stream_done_tx,
                )
                .await
                {
                    let _ = egress_tx
                        .send(WispMessage::Binary(encode_close(
                            0,
                            close_reason::CLIENT_ERROR,
                        )))
                        .await;
                    serve_err = Some(e);
                    break;
                }
            }
            WispMessage::Text(text) => {
                if text.len() as u64 > ctx.server_options.max_text_frame_bytes as u64 {
                    let _ = egress_tx
                        .send(WispMessage::Binary(encode_close(
                            0,
                            close_reason::CLIENT_ERROR,
                        )))
                        .await;
                    break;
                }
                if !negotiated.proxy_control {
                    continue;
                }
                let Some(controller) = ctx.proxy_controller.as_ref() else {
                    continue;
                };
                if let Some(lim) = control_msg_limiter.as_ref() {
                    if lim.check().is_err() {
                        tracing::warn!(
                            "wisp: closing connection: per-conn proxy_control rate exceeded",
                        );
                        let _ = egress_tx
                            .send(WispMessage::Binary(encode_close(
                                0,
                                close_reason::CONN_THROTTLED,
                            )))
                            .await;
                        break;
                    }
                }
                let sem_permit = match control_concurrency.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::info!(
                            "wisp: dropping proxy_control text frame: in-flight cap reached",
                        );
                        if let Err(mpsc::error::TrySendError::Full(_)) = control_egress_tx.try_send(
                            "{\"type\":\"proxy_control_error\",\"ok\":false,\"error\":\"busy\"}"
                                .to_owned(),
                        ) {
                            tracing::info!(
                                "wisp: dropping proxy_control busy NACK: control egress saturated",
                            );
                        }
                        continue;
                    }
                };
                let controller = controller.clone();
                let cancel = ctx.cancel.clone();
                let ctl_tx = control_egress_tx.clone();
                tokio::spawn(async move {
                    let _permit = sem_permit;
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {}
                        res = handle_proxy_control_text(&controller, &text) => {
                            if let Some(reply) = res {
                                tokio::select! {
                                    biased;
                                    _ = cancel.cancelled() => {}
                                    _ = ctl_tx.send(reply) => {}
                                }
                            }
                        }
                    }
                });
            }
        }
    }
    drop(stream_done_tx);
    ctx.cancel.cancel();
    drop(egress_tx);
    drop(control_egress_tx);
    match egress_writer.await {
        Ok(Ok(())) => {}
        Ok(Err(sink_err)) => {
            if serve_err.is_none() {
                serve_err = Some(ServerError::Transport(sink_err));
            }
        }
        Err(_join_err) => {}
    }
    if let Some(e) = serve_err {
        return Err(e);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedVersion {
    V1,
    V2,
}

fn resolve_wisp_version(configured: WispVersion, client_advertises_v2: bool) -> ResolvedVersion {
    match configured {
        WispVersion::V1 => ResolvedVersion::V1,
        WispVersion::V2 => ResolvedVersion::V2,
        WispVersion::Auto => {
            if client_advertises_v2 {
                ResolvedVersion::V2
            } else {
                ResolvedVersion::V1
            }
        }
    }
}

/// Server INFO advertisement. `proxy_control_active` is the post-derivation
/// flag from `serve_connection` — it reflects "controller is wired AND
/// deployer opted in" so the advertised set never overstates what the
/// server can actually execute.
fn build_server_info(opts: &ServerOptions, proxy_control_active: bool) -> Bytes {
    let mut exts = Vec::with_capacity(2);
    if opts.allow_udp_streams {
        exts.push(ExtensionEntry {
            id: extension_id::UDP,
            payload: Bytes::new(),
        });
    }
    if proxy_control_active {
        exts.push(ExtensionEntry {
            id: extension_id::STELLITE_PROXY_CONTROL,
            payload: Bytes::from_static(PROXY_CONTROL_PAYLOAD),
        });
    }
    encode_info(2, 0, &exts)
}

/// Audit fix #6: pin the proxy_control extension payload to a single
/// version constant so both sides can detect skew without parsing magic.
/// The negotiator below checks the client's payload version against this
/// before flipping `negotiated.proxy_control`.
const PROXY_CONTROL_VERSION: u8 = 1;
const PROXY_CONTROL_PAYLOAD: &[u8] = br#"{"version":1}"#;

#[derive(Debug, Clone, Default)]
pub(crate) struct NegotiatedExtensions {
    pub udp: bool,
    pub proxy_control: bool,
}

fn intersect_extensions(
    opts: &ServerOptions,
    proxy_control_active: bool,
    client_exts: Vec<ExtensionEntry>,
) -> NegotiatedExtensions {
    let mut neg = NegotiatedExtensions::default();
    for ext in client_exts {
        match ext.id {
            extension_id::UDP if opts.allow_udp_streams => neg.udp = true,
            extension_id::STELLITE_PROXY_CONTROL if proxy_control_active => {
                // Audit fix #6: require the client's payload to advertise a
                // version we understand. Empty payloads are accepted as
                // version 1 for the legacy clients that pre-date the
                // version field; everything else must parse as JSON with a
                // numeric `version` we know.
                if proxy_control_payload_compatible(
                    &ext.payload,
                    opts.proxy_control_ext_payload_max_bytes,
                ) {
                    neg.proxy_control = true;
                }
            }
            _ => {}
        }
    }
    neg
}

fn proxy_control_payload_compatible(payload: &[u8], max_bytes: usize) -> bool {
    if payload.is_empty() {
        return true;
    }
    if payload.len() > max_bytes {
        return false;
    }
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    let Some(version) = val.get("version") else {
        return false;
    };
    let parsed = if let Some(n) = version.as_u64() {
        Some(n)
    } else if let Some(s) = version.as_str() {
        s.parse::<u64>().ok()
    } else if let Some(f) = version.as_f64() {
        if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= u64::MAX as f64 {
            Some(f as u64)
        } else {
            None
        }
    } else {
        None
    };
    matches!(parsed, Some(v) if v == PROXY_CONTROL_VERSION as u64)
}

#[cfg(test)]
mod proxy_control_compat_tests {
    use super::*;
    use serde_json::json;

    fn payload(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    const TEST_MAX: usize = 256;

    #[test]
    fn empty_payload_accepted_for_legacy_clients() {
        assert!(proxy_control_payload_compatible(&[], TEST_MAX));
    }

    #[test]
    fn numeric_version_matches() {
        assert!(proxy_control_payload_compatible(
            &payload(json!({"version": PROXY_CONTROL_VERSION})),
            TEST_MAX
        ));
    }

    #[test]
    fn string_version_matches() {
        assert!(proxy_control_payload_compatible(
            &payload(json!({"version": PROXY_CONTROL_VERSION.to_string()})),
            TEST_MAX
        ));
    }

    #[test]
    fn integer_float_version_matches() {
        assert!(proxy_control_payload_compatible(
            &payload(json!({"version": PROXY_CONTROL_VERSION as f64})),
            TEST_MAX
        ));
    }

    #[test]
    fn fractional_float_version_rejected() {
        assert!(!proxy_control_payload_compatible(
            &payload(json!({"version": 1.5})),
            TEST_MAX
        ));
    }

    #[test]
    fn unknown_version_rejected() {
        assert!(!proxy_control_payload_compatible(
            &payload(json!({"version": 9999})),
            TEST_MAX
        ));
    }

    #[test]
    fn oversized_payload_rejected_without_parsing() {
        let mut huge = String::from("{\"version\":1,\"pad\":\"");
        huge.push_str(&"x".repeat(TEST_MAX));
        huge.push_str("\"}");
        assert!(!proxy_control_payload_compatible(huge.as_bytes(), TEST_MAX));
    }

    #[test]
    fn non_json_payload_rejected() {
        assert!(!proxy_control_payload_compatible(b"not json", TEST_MAX));
    }

    #[test]
    fn missing_version_field_rejected() {
        assert!(!proxy_control_payload_compatible(
            &payload(json!({})),
            TEST_MAX
        ));
    }
}

/// Audit-3 fix #63: per-connection stream-cap accounting. Tracks total
/// concurrent streams, per-host:port counts, and the stream-open rate so
/// the CONNECT handler can reject without tearing the whole connection
/// down. None of this state crosses connections — a fresh `StreamCaps` is
/// built at the top of [`serve_connection`].
pub(crate) struct StreamCaps {
    total: u32,
    host_counts: HashMap<String, u32>,
    host_keys: HashMap<u32, String>,
    open_limiter: Option<DirectLimiter>,
    stream_limit_total: u32,
    stream_limit_per_host: Option<u32>,
}

impl StreamCaps {
    fn new(opts: &ServerOptions) -> Self {
        let open_limiter = if opts.max_tcp_stream_opens_per_connection_per_minute == 0 {
            None
        } else {
            let per_minute = NonZeroU32::new(opts.max_tcp_stream_opens_per_connection_per_minute)
                .expect("nonzero rate");
            let burst = NonZeroU32::new(opts.max_tcp_stream_opens_per_connection_per_minute.max(1))
                .expect("nonzero burst");
            let quota = Quota::with_period(std::time::Duration::from_secs(60))
                .expect("nonzero period")
                .allow_burst(burst);
            let _ = per_minute;
            Some(RateLimiter::direct(quota))
        };
        Self {
            total: 0,
            host_counts: HashMap::new(),
            host_keys: HashMap::new(),
            open_limiter,
            stream_limit_total: opts.stream_limit_total,
            stream_limit_per_host: opts.stream_limit_per_host,
        }
    }

    fn host_key(host: &str, port: u16) -> String {
        format!("{}:{port}", host.to_ascii_lowercase())
    }

    fn try_admit(&mut self, stream_id: u32, host: &str, port: u16) -> Result<(), AdmitDenied> {
        if self.stream_limit_total > 0 && self.total >= self.stream_limit_total {
            return Err(AdmitDenied::TotalCap);
        }
        let key = Self::host_key(host, port);
        if let Some(per_host) = self.stream_limit_per_host {
            let cur = self.host_counts.get(&key).copied().unwrap_or(0);
            if cur >= per_host {
                return Err(AdmitDenied::PerHostCap);
            }
        }
        if let Some(lim) = self.open_limiter.as_ref() {
            if lim.check().is_err() {
                return Err(AdmitDenied::RateLimit);
            }
        }
        self.total = self.total.saturating_add(1);
        *self.host_counts.entry(key.clone()).or_insert(0) += 1;
        self.host_keys.insert(stream_id, key);
        Ok(())
    }

    fn release(&mut self, stream_id: u32) {
        if let Some(key) = self.host_keys.remove(&stream_id) {
            self.total = self.total.saturating_sub(1);
            if let Some(c) = self.host_counts.get_mut(&key) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.host_counts.remove(&key);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AdmitDenied {
    TotalCap,
    PerHostCap,
    RateLimit,
}

#[cfg(test)]
mod stream_caps_tests {
    use super::*;

    fn opts(total: u32, per_host: Option<u32>, opens_per_min: u32) -> ServerOptions {
        ServerOptions {
            buffer_size: 65536,
            continue_threshold: 32768,
            allow_udp_streams: true,
            allow_tcp_streams: true,
            proxy_control_enabled: false,
            max_binary_frame_bytes: 65536,
            max_text_frame_bytes: 65536,
            stream_limit_total: total,
            stream_limit_per_host: per_host,
            max_tcp_stream_opens_per_connection_per_minute: opens_per_min,
            max_control_messages_per_connection_per_minute: 0,
            max_binary_packets_per_connection_per_minute: 0,
            max_concurrent_proxy_control_handlers: 16,
            proxy_control_ext_payload_max_bytes: 256,
            max_proxy_rules_per_connection: 256,
            max_proxy_control_reply_bytes: 64 * 1024,
            max_proxy_rule_field_bytes: 256,
            proxy_control_upstream_ops_per_second: 8,
            proxy_control_upstream_burst: 16,
            proxy_control_mutation_ops_per_second: 64,
            proxy_control_mutation_burst: 320,
            wisp_version: WispVersion::Auto,
        }
    }

    #[test]
    fn total_cap_blocks_after_limit() {
        let mut caps = StreamCaps::new(&opts(2, None, 0));
        assert!(caps.try_admit(1, "a", 80).is_ok());
        assert!(caps.try_admit(2, "b", 80).is_ok());
        assert!(matches!(
            caps.try_admit(3, "c", 80),
            Err(AdmitDenied::TotalCap)
        ));
        caps.release(1);
        assert!(caps.try_admit(3, "c", 80).is_ok());
    }

    #[test]
    fn per_host_cap_blocks_distinct_streams() {
        let mut caps = StreamCaps::new(&opts(100, Some(2), 0));
        assert!(caps.try_admit(1, "h", 80).is_ok());
        assert!(caps.try_admit(2, "h", 80).is_ok());
        assert!(matches!(
            caps.try_admit(3, "h", 80),
            Err(AdmitDenied::PerHostCap)
        ));
        assert!(caps.try_admit(4, "h", 81).is_ok());
        caps.release(1);
        assert!(caps.try_admit(3, "h", 80).is_ok());
    }

    #[test]
    fn per_host_cap_none_means_unlimited() {
        let mut caps = StreamCaps::new(&opts(1000, None, 0));
        for i in 0..50 {
            assert!(caps.try_admit(i, "h", 80).is_ok());
        }
    }

    #[test]
    fn open_rate_limit_blocks_burst() {
        let mut caps = StreamCaps::new(&opts(10_000, None, 5));
        for i in 0..5 {
            assert!(caps.try_admit(i, "h", 80).is_ok(), "i={i}");
        }
        assert!(matches!(
            caps.try_admit(99, "h", 80),
            Err(AdmitDenied::RateLimit)
        ));
    }

    #[test]
    fn release_decrements_host_count() {
        let mut caps = StreamCaps::new(&opts(100, Some(1), 0));
        assert!(caps.try_admit(1, "h", 80).is_ok());
        caps.release(1);
        assert!(caps.try_admit(2, "h", 80).is_ok());
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_packet(
    packet: WispPacket,
    streams: &mut HashMap<u32, StreamHandle>,
    udp_streams: &mut HashMap<u32, mpsc::Sender<UdpStreamMsg>>,
    caps: &mut StreamCaps,
    ctx: &ServerContext,
    negotiated: &NegotiatedExtensions,
    egress: &mpsc::Sender<WispMessage>,
    stream_done_tx: &mpsc::Sender<u32>,
) -> Result<(), ServerError> {
    match packet {
        WispPacket::Connect(conn) => {
            if conn.stream_id == 0 {
                return Err(ServerError::ProtocolViolation(
                    "stream_id 0 reserved for control channel",
                ));
            }
            if let Some(existing) = streams.get(&conn.stream_id) {
                if existing.tx.is_closed() {
                    streams.remove(&conn.stream_id);
                    caps.release(conn.stream_id);
                } else {
                    return Err(ServerError::StreamCollision(conn.stream_id));
                }
            }
            if let Some(existing) = udp_streams.get(&conn.stream_id) {
                if existing.is_closed() {
                    udp_streams.remove(&conn.stream_id);
                    caps.release(conn.stream_id);
                } else {
                    return Err(ServerError::StreamCollision(conn.stream_id));
                }
            }
            let needs_dns = conn.hostname.parse::<std::net::IpAddr>().is_err();
            let dns_allowed = !needs_dns
                || is_dns_resolution_allowed(
                    &ctx.client_ip,
                    &conn.hostname,
                    &ctx.options,
                    &ctx.dos_store,
                );
            if !dns_allowed {
                tracing::info!(
                    stream_id = conn.stream_id,
                    host = %conn.hostname,
                    "wisp connect rejected: dns resolution rate limit"
                );
                let _ = egress
                    .send(WispMessage::Binary(encode_close(
                        conn.stream_id,
                        close_reason::CONN_THROTTLED,
                    )))
                    .await;
                return Ok(());
            }
            match conn.stream_type {
                stream_type::TCP if ctx.server_options.allow_tcp_streams => {
                    if !is_tcp_stream_open_allowed(
                        &ctx.client_ip,
                        &ctx.conn_dos,
                        &ctx.options,
                        &ctx.dos_store,
                    ) {
                        tracing::info!(
                            stream_id = conn.stream_id,
                            host = %conn.hostname,
                            port = conn.port,
                            "wisp tcp connect rejected: stream-open rate limit"
                        );
                        let _ = egress
                            .send(WispMessage::Binary(encode_close(
                                conn.stream_id,
                                close_reason::CONN_THROTTLED,
                            )))
                            .await;
                        return Ok(());
                    }
                    if let Err(reason) = caps.try_admit(conn.stream_id, &conn.hostname, conn.port) {
                        tracing::info!(
                            stream_id = conn.stream_id,
                            host = %conn.hostname,
                            port = conn.port,
                            ?reason,
                            "wisp tcp connect rejected: stream cap"
                        );
                        let _ = egress
                            .send(WispMessage::Binary(encode_close(
                                conn.stream_id,
                                close_reason::CONN_THROTTLED,
                            )))
                            .await;
                        return Ok(());
                    }
                    let handle = spawn_tcp_stream(
                        conn.stream_id,
                        conn.hostname.clone(),
                        conn.port,
                        ctx.clone(),
                        egress.clone(),
                        stream_done_tx.clone(),
                    );
                    streams.insert(conn.stream_id, handle);
                }
                stream_type::UDP if negotiated.udp => {
                    if let Err(reason) = caps.try_admit(conn.stream_id, &conn.hostname, conn.port) {
                        tracing::info!(
                            stream_id = conn.stream_id,
                            host = %conn.hostname,
                            port = conn.port,
                            ?reason,
                            "wisp udp connect rejected: stream cap"
                        );
                        let _ = egress
                            .send(WispMessage::Binary(encode_close(
                                conn.stream_id,
                                close_reason::CONN_THROTTLED,
                            )))
                            .await;
                        return Ok(());
                    }
                    let tx = spawn_udp_stream(
                        conn.stream_id,
                        conn.hostname.clone(),
                        conn.port,
                        ctx.clone(),
                        egress.clone(),
                        stream_done_tx.clone(),
                    );
                    udp_streams.insert(conn.stream_id, tx);
                }
                _ => {
                    let _ = egress
                        .send(WispMessage::Binary(encode_close(
                            conn.stream_id,
                            close_reason::INVALID_INFO,
                        )))
                        .await;
                }
            }
        }
        WispPacket::Data(data) => {
            if data.stream_id == 0 {
                return Err(ServerError::ProtocolViolation(
                    "stream_id 0 reserved for control channel",
                ));
            }
            if let Some(handle) = streams.get(&data.stream_id) {
                let tx = handle.tx.clone();
                if tx.send(TcpStreamMsg::Data(data.payload)).await.is_err() {
                    streams.remove(&data.stream_id);
                    caps.release(data.stream_id);
                }
            } else if let Some(udp) = udp_streams.get(&data.stream_id) {
                let udp = udp.clone();
                if udp.send(UdpStreamMsg::Data(data.payload)).await.is_err() {
                    udp_streams.remove(&data.stream_id);
                    caps.release(data.stream_id);
                }
            }
        }
        WispPacket::Continue(_) => {}
        WispPacket::Close(close) => {
            if close.stream_id == 0 {
                return Err(ServerError::ProtocolViolation(
                    "stream_id 0 reserved for control channel",
                ));
            }
            if let Some(handle) = streams.remove(&close.stream_id) {
                let _ = handle.tx.try_send(TcpStreamMsg::Close(close.reason));
                caps.release(close.stream_id);
            } else if let Some(udp) = udp_streams.remove(&close.stream_id) {
                let _ = udp.try_send(UdpStreamMsg::Close);
                caps.release(close.stream_id);
            }
        }
        WispPacket::Info(_) => {
            return Err(ServerError::ProtocolViolation(
                "repeat INFO after handshake",
            ));
        }
    }
    Ok(())
}

fn build_per_minute_limiter(per_minute: u32) -> Option<DirectLimiter> {
    if per_minute == 0 {
        return None;
    }
    let burst = NonZeroU32::new(per_minute.max(1)).expect("nonzero burst");
    let quota = Quota::with_period(std::time::Duration::from_secs(60))
        .expect("nonzero period")
        .allow_burst(burst);
    Some(RateLimiter::direct(quota))
}

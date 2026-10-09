//! Per-connection Wisp driver. Each accepted WebSocket connection
//! (after the extended-CONNECT upgrade) becomes one [`serve_connection`]
//! call. The driver dispatches on the resolved Wisp version (v1 or v2) before
//! emitting any handshake bytes. A client that advertises
//! `Sec-WebSocket-Protocol: wisp-v2` takes the v2 path; a client that does
//! not skips the v2 INFO exchange and proceeds directly to the v1
//! CONTINUE-first stream phase. Resolution is controlled by
//! `ServerOptions::wisp_version` (V1, V2, or Auto, where Auto inspects
//! `ServerContext::client_advertises_v2`).
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
//! for the simple model), CLOSE tears down a stream, FIN finishes the
//! client's side of a TCP stream when [`extension_id::TCP_HALF_CLOSE`] is
//! negotiated, INFO is a protocol error after the initial handshake. Text-frame payloads on stream 0 are
//! routed to the proxy-control handler when
//! [`extension_id::WISP_PROXY_CONTROL`] is negotiated (v2 only).
//!
//! The TCP stream-open path runs [`wisp_inspect::inspect`] before
//! upstream bytes flow.

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
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use wisp_config::{WispServerOptions, WispVersion};
use wisp_dos::{
    is_dns_resolution_allowed, is_tcp_stream_open_allowed, ConnectionDosGuard, DosGuard,
    TcpByteLimiter,
};
use wisp_proxy::HostPolicy;
use wisp_wisp::{
    close_reason, encode_close, encode_continue, encode_fin, encode_info, extension_id,
    packet_type, parse_extensions_capped, parse_packet, stream_type, ExtensionEntry, WispError,
    WispPacket, DEFAULT_MAX_EXTENSION_ENTRIES,
};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

const WISP_MAJOR_VERSION: u8 = 2;

use crate::proxy_control::{
    handle_proxy_control_text, proxy_control_error_frame, ProxyControlLimits, ProxyController,
};
use crate::stream::{
    activate_writer, drop_slot, shutdown_upstream_write, spawn_tcp_connect, write_upstream,
    StreamTable, TcpEvent, TcpStreamSlot, TcpStreamState, WriteOutcome,
};
use crate::udp::{spawn_udp_stream, UdpStreamMsg};

/// Tagged WS-frame envelope. The transport layer (H2 or H3 + tokio-websockets)
/// preserves the binary/text distinction so the server can route text frames
/// to WISP_PROXY_CONTROL while keeping binary on the Wisp v2 codec path.
#[derive(Debug, Clone)]
pub enum WispMessage {
    Binary(Bytes),
    Text(String),
}

struct BudgetedMessage {
    message: WispMessage,
    permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(crate) struct EgressSender {
    tx: mpsc::Sender<BudgetedMessage>,
    flow_tx: mpsc::Sender<BudgetedMessage>,
    budget: Arc<Semaphore>,
}

impl EgressSender {
    fn new(
        tx: mpsc::Sender<BudgetedMessage>,
        flow_tx: mpsc::Sender<BudgetedMessage>,
        max_bytes: usize,
    ) -> Self {
        Self {
            tx,
            flow_tx,
            budget: Arc::new(Semaphore::new(max_bytes)),
        }
    }

    fn channel(&self, message: &WispMessage) -> &mpsc::Sender<BudgetedMessage> {
        match message {
            WispMessage::Binary(bytes) if bytes.first() == Some(&packet_type::CONTINUE) => {
                &self.flow_tx
            }
            _ => &self.tx,
        }
    }

    fn message_cost(message: &WispMessage) -> Option<u32> {
        let bytes = match message {
            WispMessage::Binary(bytes) => bytes.len(),
            WispMessage::Text(text) => text.len(),
        };
        u32::try_from(bytes.max(1)).ok()
    }

    pub(crate) async fn send(&self, message: WispMessage) -> Result<(), ()> {
        let permits = Self::message_cost(&message).ok_or(())?;
        let permit = self
            .budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| ())?;
        self.channel(&message)
            .send(BudgetedMessage { message, permit })
            .await
            .map_err(|_| ())
    }

    #[cfg(test)]
    fn try_send(&self, message: WispMessage) -> Result<(), ()> {
        let permits = Self::message_cost(&message).ok_or(())?;
        let permit = self
            .budget
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| ())?;
        self.channel(&message)
            .try_send(BudgetedMessage { message, permit })
            .map_err(|_| ())
    }
}

impl WispMessage {
    pub fn binary(b: Bytes) -> Self {
        WispMessage::Binary(b)
    }
    pub fn text(s: String) -> Self {
        WispMessage::Text(s)
    }
}

/// Transport-side failure. Distinct from protocol errors so callers match
/// [`ServerError::Transport`] instead of scraping a `String`.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct TransportError(Box<str>);

impl TransportError {
    pub fn new(err: impl std::fmt::Display) -> Self {
        Self(err.to_string().into_boxed_str())
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("client transport closed")]
    ClientClosed,
    #[error("client transport error: {0}")]
    Transport(#[source] TransportError),
    #[error("wisp protocol error: {0}")]
    Protocol(#[from] WispError),
    #[error("initial INFO packet missing or invalid")]
    BadHandshake,
    #[error("stream id collision: {0}")]
    StreamCollision(u32),
    #[error("wisp protocol violation: {0}")]
    ProtocolViolation(&'static str),
}

impl ServerError {
    fn transport(err: impl std::fmt::Display) -> Self {
        ServerError::Transport(TransportError::new(err))
    }
}

/// Per-connection server options. Projects the subset of
/// [`WispServerOptions`] that affects the WS conversation. There is
/// deliberately no MOTD field — it is never emitted or honored.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub buffer_size: u32,
    pub continue_threshold: u32,
    pub allow_udp_streams: bool,
    pub allow_tcp_streams: bool,
    pub proxy_control_enabled: bool,
    /// Cap on per-packet payload bytes (defends against gigantic frames).
    pub max_binary_frame_bytes: u32,
    pub max_text_frame_bytes: u32,
    pub handshake_timeout_ms: u64,
    /// Hard cap on total concurrent streams (TCP+UDP) per WebSocket
    /// connection. 0 disables the cap.
    pub stream_limit_total: u32,
    /// Cap on concurrent streams per upstream host:port key. `None`
    /// (configured value < 0) disables the per-host cap.
    pub stream_limit_per_host: Option<u32>,
    /// Ceiling on stream-open events per minute per connection. 0 disables.
    pub max_tcp_stream_opens_per_connection_per_minute: u32,
    /// Ceiling on incoming text (proxy_control) frames parsed per minute per
    /// connection. Enforced before `serde_json::from_str` so an attacker
    /// cannot force the parser at line speed. 0 disables.
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
    /// separately because [`WispServerOptions`] does not expose it.
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
            handshake_timeout_ms: options.handshake_timeout_ms.unwrap_or(10_000).max(1),
            stream_limit_total: options.stream_limit_total.try_into().unwrap_or(u32::MAX),
            stream_limit_per_host: if options.stream_limit_per_host < 0 {
                None
            } else {
                Some(u32::try_from(options.stream_limit_per_host).unwrap_or(u32::MAX))
            },
            max_tcp_stream_opens_per_connection_per_minute: per_minute_u32(
                options.max_tcp_stream_opens_per_connection_per_minute,
            ),
            max_control_messages_per_connection_per_minute: per_minute_u32(
                options.max_control_messages_per_connection_per_minute,
            ),
            max_binary_packets_per_connection_per_minute: per_minute_u32(
                options.max_binary_packets_per_connection_per_minute,
            ),
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
    /// Per-process proxy controller. `None` when WISP_PROXY_CONTROL is
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
    pub tcp_byte_limiter: Arc<TcpByteLimiter>,
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
        dos_store: Arc<DosGuard>,
    ) -> Self {
        let policy = Arc::new(HostPolicy::from_options(&options));
        let conn_dos = Arc::new(ConnectionDosGuard::new());
        let tcp_byte_limiter = Arc::new(TcpByteLimiter::new(
            &client_ip, &conn_dos, &options, &dos_store,
        ));
        Self {
            client_ip,
            client_hash,
            options,
            server_options,
            proxy_controller,
            client_advertises_v2,
            policy,
            dos_store,
            conn_dos,
            tcp_byte_limiter,
            cancel: CancellationToken::new(),
        }
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
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
    let proxy_control_active =
        ctx.server_options.proxy_control_enabled && ctx.proxy_controller.is_some();

    let (egress_raw_tx, mut egress_rx) = mpsc::channel::<BudgetedMessage>(4096);
    let (flow_egress_tx, mut flow_egress_rx) = mpsc::channel::<BudgetedMessage>(512);
    let egress_tx = EgressSender::new(
        egress_raw_tx,
        flow_egress_tx,
        usize::try_from(ctx.options.max_egress_queue_bytes).unwrap_or(u32::MAX as usize),
    );

    let (control_egress_tx, mut control_egress_rx) = mpsc::channel::<String>(8);
    let control_concurrency = Arc::new(Semaphore::new(
        ctx.server_options
            .max_concurrent_proxy_control_handlers
            .max(1),
    ));

    let egress_writer_cancel = ctx.cancel.clone();
    let egress_writer = tokio::spawn(async move {
        let mut main_closed = false;
        let mut flow_closed = false;
        let mut ctl_closed = false;
        let mut batch: Vec<(WispMessage, Option<OwnedSemaphorePermit>)> = Vec::with_capacity(64);
        let mut flushed_permits: Vec<OwnedSemaphorePermit> = Vec::with_capacity(64);
        while !(main_closed && flow_closed && ctl_closed) {
            let first = tokio::select! {
                biased;
                _ = egress_writer_cancel.cancelled() => break,
                msg = flow_egress_rx.recv(), if !flow_closed => match msg {
                    Some(m) => Some((m.message, Some(m.permit))),
                    None => { flow_closed = true; continue; }
                },
                msg = egress_rx.recv(), if !main_closed => match msg {
                    Some(m) => Some((m.message, Some(m.permit))),
                    None => { main_closed = true; continue; }
                },
                text = control_egress_rx.recv(), if !ctl_closed => match text {
                    Some(t) => Some((WispMessage::Text(t), None)),
                    None => { ctl_closed = true; continue; }
                },
            };
            let Some(m) = first else { continue };
            batch.push(m);
            while batch.len() < 64 {
                match flow_egress_rx.try_recv() {
                    Ok(m) => batch.push((m.message, Some(m.permit))),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        flow_closed = true;
                        break;
                    }
                }
            }
            while batch.len() < 64 {
                match egress_rx.try_recv() {
                    Ok(m) => batch.push((m.message, Some(m.permit))),
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
                        Ok(t) => batch.push((WispMessage::Text(t), None)),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            ctl_closed = true;
                            break;
                        }
                    }
                }
            }
            for (m, permit) in batch.drain(..) {
                if let Err(e) = outgoing.feed(m).await {
                    return Err(ServerError::transport(e));
                }
                if let Some(permit) = permit {
                    flushed_permits.push(permit);
                }
            }
            if let Err(e) = outgoing.flush().await {
                return Err(ServerError::transport(e));
            }
            flushed_permits.clear();
        }
        if let Err(e) = outgoing.close().await {
            return Err(ServerError::transport(e));
        }
        Ok::<(), ServerError>(())
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

            let handshake_timeout =
                std::time::Duration::from_millis(ctx.server_options.handshake_timeout_ms.max(1));
            let client_info = tokio::select! {
                _ = ctx.cancel.cancelled() => return Ok(()),
                result = tokio::time::timeout(handshake_timeout, incoming.next()) => match result {
                    Err(_) => return Err(ServerError::BadHandshake),
                    Ok(Some(Ok(WispMessage::Binary(b)))) => b,
                    Ok(Some(Ok(WispMessage::Text(_)))) => return Err(ServerError::BadHandshake),
                    Ok(Some(Err(e))) => return Err(ServerError::transport(e)),
                    Ok(None) => return Err(ServerError::ClientClosed),
                },
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

    let mut streams = StreamTable::new();
    let mut udp_streams: HashMap<u32, mpsc::Sender<UdpStreamMsg>> = HashMap::new();
    let mut caps = StreamCaps::new(&ctx.server_options);
    let (stream_done_tx, mut stream_done_rx) = mpsc::channel::<u32>(256);
    let (tcp_events_tx, mut tcp_events_rx) = mpsc::channel::<TcpEvent>(256);
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
            biased;
            _ = ctx.cancel.cancelled() => break,
            ev = tcp_events_rx.recv() => {
                match ev {
                    Some(TcpEvent::Ready { stream_id, write, reader }) => {
                        if let Some(slot) = streams.get_mut(stream_id) {
                            if let WriteOutcome::DropStream(reason) = activate_writer(
                                    slot,
                                    write,
                                    reader,
                                    stream_id,
                                    &ctx,
                                    &egress_tx,
                                    &tcp_events_tx,
                                ).await
                            {
                                if egress_tx
                                    .send(WispMessage::Binary(encode_close(stream_id, reason)))
                                    .await
                                    .is_err()
                                {
                                    serve_err = Some(ServerError::ClientClosed);
                                    break;
                                }
                                if let Some(slot) = streams.remove(stream_id) {
                                    drop_slot(slot);
                                }
                                caps.release(stream_id);
                            } else if (negotiated.stream_open_confirmation
                                && egress_tx
                                    .send(WispMessage::Binary(encode_continue(
                                        stream_id,
                                        ctx.server_options.buffer_size,
                                    )))
                                    .await
                                    .is_err())
                                || (slot.upstream_eof
                                    && finish_upstream_read(stream_id, &mut streams, &mut caps, &egress_tx)
                                        .await
                                        .is_err())
                            {
                                serve_err = Some(ServerError::ClientClosed);
                                break;
                            }
                        } else {
                            drop(write);
                            reader.abort();
                        }
                    }
                    Some(TcpEvent::Failed { stream_id })
                    | Some(TcpEvent::ReaderDone { stream_id })
                    | Some(TcpEvent::WriterDone { stream_id }) => {
                        if let Some(slot) = streams.remove(stream_id) {
                            drop_slot(slot);
                            caps.release(stream_id);
                        }
                    }
                    Some(TcpEvent::ReadEof { stream_id }) => {
                        let Some(slot) = streams.get_mut(stream_id) else {
                            continue;
                        };
                        slot.upstream_eof = true;
                        // A FIN must not overtake the stream's open confirmation.
                        if matches!(slot.state, TcpStreamState::Live { .. })
                            && finish_upstream_read(stream_id, &mut streams, &mut caps, &egress_tx)
                                .await
                                .is_err()
                        {
                            serve_err = Some(ServerError::ClientClosed);
                            break;
                        }
                    }
                    Some(TcpEvent::WriteShut { stream_id }) => {
                        let Some(slot) = streams.get_mut(stream_id) else {
                            continue;
                        };
                        slot.write_shut = true;
                        if release_finished(stream_id, &mut streams, &mut caps, &egress_tx)
                            .await
                            .is_err()
                        {
                            serve_err = Some(ServerError::ClientClosed);
                            break;
                        }
                    }
                    None => {}
                }
                continue;
            }
            done = stream_done_rx.recv() => {
                if let Some(stream_id) = done {
                    udp_streams.remove(&stream_id);
                    caps.release(stream_id);
                }
                continue;
            }
            recv = incoming.next() => match recv {
                Some(Ok(m)) => m,
                Some(Err(e)) => {
                    serve_err = Some(ServerError::transport(e));
                    break;
                }
                None => break,
            },
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
                if frame.len() >= 5 && frame[0] == packet_type::DATA {
                    let stream_id = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
                    if let Err(e) = handle_data(
                        stream_id,
                        frame.slice(5..),
                        &mut streams,
                        &mut udp_streams,
                        &mut caps,
                        &ctx,
                        &egress_tx,
                        &tcp_events_tx,
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
                    continue;
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
                    &tcp_events_tx,
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
                        if let Err(mpsc::error::TrySendError::Full(_)) =
                            control_egress_tx.try_send(proxy_control_error_frame("busy"))
                        {
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
    drop(tcp_events_tx);
    for (_, slot) in streams.drain() {
        drop_slot(slot);
    }
    ctx.cancel.cancel();
    drop(egress_tx);
    drop(control_egress_tx);
    match egress_writer.await {
        Ok(Ok(())) => {}
        Ok(Err(sink_err)) => {
            if serve_err.is_none() {
                serve_err = Some(sink_err);
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
    let mut exts = Vec::with_capacity(4);
    exts.push(ExtensionEntry {
        id: extension_id::STREAM_OPEN_CONFIRMATION,
        payload: Bytes::new(),
    });
    exts.push(ExtensionEntry {
        id: extension_id::TCP_HALF_CLOSE,
        payload: Bytes::new(),
    });
    if opts.allow_udp_streams {
        exts.push(ExtensionEntry {
            id: extension_id::UDP,
            payload: Bytes::new(),
        });
    }
    if proxy_control_active {
        exts.push(ExtensionEntry {
            id: extension_id::WISP_PROXY_CONTROL,
            payload: Bytes::from_static(PROXY_CONTROL_PAYLOAD),
        });
    }
    encode_info(2, 0, &exts)
}

/// Pins the proxy_control extension payload to a single version constant so
/// both sides can detect skew without parsing magic. The negotiator checks
/// the client's payload version against this before flipping
/// `negotiated.proxy_control`.
const PROXY_CONTROL_VERSION: u8 = 1;
const PROXY_CONTROL_PAYLOAD: &[u8] = br#"{"version":1}"#;

#[derive(Debug, Clone, Default)]
pub(crate) struct NegotiatedExtensions {
    pub udp: bool,
    pub proxy_control: bool,
    pub stream_open_confirmation: bool,
    pub tcp_half_close: bool,
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
            extension_id::STREAM_OPEN_CONFIRMATION => neg.stream_open_confirmation = true,
            extension_id::TCP_HALF_CLOSE if ext.payload.is_empty() => neg.tcp_half_close = true,
            extension_id::WISP_PROXY_CONTROL
                if proxy_control_active
                    && proxy_control_payload_compatible(
                        &ext.payload,
                        opts.proxy_control_ext_payload_max_bytes,
                    ) =>
            {
                neg.proxy_control = true;
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

/// Per-connection stream-cap accounting. Tracks total concurrent streams,
/// per-host:port counts, and the stream-open rate so the CONNECT handler can
/// reject without tearing the whole connection down. None of this state
/// crosses connections — a fresh `StreamCaps` is built at the top of
/// [`serve_connection`].
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
        let open_limiter =
            build_per_minute_limiter(opts.max_tcp_stream_opens_per_connection_per_minute);
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
            handshake_timeout_ms: 10_000,
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
async fn handle_data(
    stream_id: u32,
    payload: Bytes,
    streams: &mut StreamTable,
    udp_streams: &mut HashMap<u32, mpsc::Sender<UdpStreamMsg>>,
    caps: &mut StreamCaps,
    ctx: &ServerContext,
    egress: &EgressSender,
    tcp_events: &mpsc::Sender<TcpEvent>,
) -> Result<(), ServerError> {
    if stream_id == 0 {
        return Err(ServerError::ProtocolViolation(
            "stream_id 0 reserved for control channel",
        ));
    }
    if let Some(slot) = streams.get_mut(stream_id) {
        let outcome = if slot.client_fin {
            WriteOutcome::DropStream(close_reason::UNKNOWN)
        } else {
            write_upstream(slot, payload, stream_id, ctx, egress, tcp_events)
        };
        match outcome {
            WriteOutcome::DropStream(reason) => {
                egress
                    .send(WispMessage::Binary(encode_close(stream_id, reason)))
                    .await
                    .map_err(|()| ServerError::ClientClosed)?;
                if let Some(slot) = streams.remove(stream_id) {
                    drop_slot(slot);
                }
                caps.release(stream_id);
            }
            WriteOutcome::SendContinue => {
                if egress
                    .send(WispMessage::Binary(encode_continue(
                        stream_id,
                        ctx.server_options.buffer_size,
                    )))
                    .await
                    .is_err()
                {
                    return Err(ServerError::ClientClosed);
                }
            }
            WriteOutcome::Ok => {}
        }
    } else if let Some(udp) = udp_streams.get(&stream_id) {
        match udp.try_send(UdpStreamMsg::Data(payload)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                let tx = udp.clone();
                if tx.send(msg).await.is_err() {
                    udp_streams.remove(&stream_id);
                    caps.release(stream_id);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                udp_streams.remove(&stream_id);
                caps.release(stream_id);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_packet(
    packet: WispPacket,
    streams: &mut StreamTable,
    udp_streams: &mut HashMap<u32, mpsc::Sender<UdpStreamMsg>>,
    caps: &mut StreamCaps,
    ctx: &ServerContext,
    negotiated: &NegotiatedExtensions,
    egress: &EgressSender,
    stream_done_tx: &mpsc::Sender<u32>,
    tcp_events: &mpsc::Sender<TcpEvent>,
) -> Result<(), ServerError> {
    match packet {
        WispPacket::Connect(conn) => {
            if conn.stream_id == 0 {
                return Err(ServerError::ProtocolViolation(
                    "stream_id 0 reserved for control channel",
                ));
            }
            if streams.contains(conn.stream_id) {
                return Err(ServerError::StreamCollision(conn.stream_id));
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
                    streams.insert(conn.stream_id, TcpStreamSlot::connecting());
                    spawn_tcp_connect(
                        conn.stream_id,
                        conn.hostname.clone(),
                        conn.port,
                        negotiated.tcp_half_close,
                        ctx.clone(),
                        egress.clone(),
                        tcp_events.clone(),
                    );
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
            return handle_data(
                data.stream_id,
                data.payload,
                streams,
                udp_streams,
                caps,
                ctx,
                egress,
                tcp_events,
            )
            .await;
        }
        WispPacket::Continue(_) => {}
        WispPacket::Close(close) => {
            if close.stream_id == 0 {
                return Err(ServerError::ProtocolViolation(
                    "stream_id 0 reserved for control channel",
                ));
            }
            if let Some(slot) = streams.remove(close.stream_id) {
                drop_slot(slot);
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
        WispPacket::Fin(fin) => {
            if !negotiated.tcp_half_close {
                return Err(ServerError::ProtocolViolation(
                    "FIN without negotiated TCP half-close",
                ));
            }
            if fin.stream_id == 0 {
                return Err(ServerError::ProtocolViolation(
                    "stream_id 0 reserved for control channel",
                ));
            }
            if udp_streams.contains_key(&fin.stream_id) {
                return Err(ServerError::ProtocolViolation("FIN on a UDP stream"));
            }
            let Some(slot) = streams.get_mut(fin.stream_id) else {
                return Ok(());
            };
            let outcome = if slot.client_fin {
                WriteOutcome::DropStream(close_reason::UNKNOWN)
            } else {
                slot.client_fin = true;
                shutdown_upstream_write(slot).await
            };
            if let WriteOutcome::DropStream(reason) = outcome {
                return close_tcp_stream(fin.stream_id, reason, streams, caps, egress).await;
            }
            return release_finished(fin.stream_id, streams, caps, egress).await;
        }
    }
    Ok(())
}

async fn close_tcp_stream(
    stream_id: u32,
    reason: u8,
    streams: &mut StreamTable,
    caps: &mut StreamCaps,
    egress: &EgressSender,
) -> Result<(), ServerError> {
    egress
        .send(WispMessage::Binary(encode_close(stream_id, reason)))
        .await
        .map_err(|()| ServerError::ClientClosed)?;
    if let Some(slot) = streams.remove(stream_id) {
        drop_slot(slot);
    }
    caps.release(stream_id);
    Ok(())
}

/// Report an upstream EOF as FIN. Every DATA the reader produced is already
/// queued on the egress ahead of it.
async fn finish_upstream_read(
    stream_id: u32,
    streams: &mut StreamTable,
    caps: &mut StreamCaps,
    egress: &EgressSender,
) -> Result<(), ServerError> {
    egress
        .send(WispMessage::Binary(encode_fin(stream_id)))
        .await
        .map_err(|()| ServerError::ClientClosed)?;
    release_finished(stream_id, streams, caps, egress).await
}

/// Both directions sent FIN: the single CLOSE(0x02) ends the stream.
async fn release_finished(
    stream_id: u32,
    streams: &mut StreamTable,
    caps: &mut StreamCaps,
    egress: &EgressSender,
) -> Result<(), ServerError> {
    if streams
        .get_mut(stream_id)
        .is_some_and(|slot| slot.finished())
    {
        return close_tcp_stream(stream_id, close_reason::VOLUNTARY, streams, caps, egress).await;
    }
    Ok(())
}

/// Normalize a per-minute limit from the u64 config space into governor's u32
/// rate space. The `UNLIMITED` sentinel (`u64::MAX`, set via `-1` in TOML) and
/// `0` both mean "no limiter"; any other value is clamped into `u32`.
fn per_minute_u32(v: u64) -> u32 {
    if v == u64::MAX {
        return 0;
    }
    u32::try_from(v).unwrap_or(u32::MAX)
}

fn build_per_minute_limiter(per_minute: u32) -> Option<DirectLimiter> {
    if per_minute == 0 {
        return None;
    }
    let rate = NonZeroU32::new(per_minute).expect("nonzero rate");
    Some(RateLimiter::direct(Quota::per_minute(rate)))
}

#[cfg(test)]
mod serve_connection_tests {
    use super::*;
    use crate::ConnectError;
    use bytes::Bytes;
    use futures::{channel::mpsc as fmpsc, SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};
    use wisp_dos::{tcp_byte_limits_active, DosGuard, UNLIMITED};
    use wisp_proxy::HostPolicy;
    use wisp_wisp::{
        encode_connect, encode_data, encode_info, parse_extensions, parse_packet, stream_type,
        ClosePacket, ConnectPacket, FinPacket, WispPacket,
    };

    #[tokio::test]
    async fn egress_budget_tracks_bytes_until_receive() {
        let (raw_tx, mut raw_rx) = mpsc::channel(4);
        let (flow_tx, _flow_rx) = mpsc::channel(4);
        let tx = EgressSender::new(raw_tx, flow_tx, 4);
        assert!(tx
            .send(WispMessage::Binary(Bytes::from_static(b"1234")))
            .await
            .is_ok());
        assert!(tx
            .try_send(WispMessage::Binary(Bytes::from_static(b"5")))
            .is_err());
        drop(raw_rx.recv().await);
        assert!(tx
            .try_send(WispMessage::Binary(Bytes::from_static(b"5")))
            .is_ok());
    }

    fn loopback_test_options(echo_port: u16) -> Arc<WispServerOptions> {
        Arc::new(WispServerOptions {
            protocol_inspection: false,
            allow_loopback_ips: true,
            allow_private_ips: true,
            allow_direct_ip: true,
            port_whitelist: Some(vec![echo_port]),
            max_tcp_bytes_per_connection_per_second: UNLIMITED,
            max_tcp_bytes_per_ip_per_second: UNLIMITED,
            stream_idle_timeout_ms: Some(5_000),
            idle_timeout_ms: Some(2_000),
            connect_timeout_ms: Some(2_000),
            ..WispServerOptions::default()
        })
    }

    fn test_ctx(options: Arc<WispServerOptions>, advertises_v2: bool) -> ServerContext {
        let server_options = Arc::new(ServerOptions::from_wisp(&options, false));
        ServerContext::new(
            "127.0.0.1".to_owned(),
            None,
            options,
            server_options,
            None,
            advertises_v2,
            Arc::new(DosGuard::new()),
        )
    }

    async fn spawn_serve(
        ctx: ServerContext,
    ) -> (
        fmpsc::UnboundedSender<Result<WispMessage, std::io::Error>>,
        fmpsc::UnboundedReceiver<WispMessage>,
        tokio::task::JoinHandle<Result<(), ServerError>>,
    ) {
        let (in_tx, in_rx) = fmpsc::unbounded();
        let (out_tx, out_rx) = fmpsc::unbounded();
        let handle = tokio::spawn(async move { serve_connection(out_tx, in_rx, ctx).await });
        (in_tx, out_rx, handle)
    }

    async fn next_packet(rx: &mut fmpsc::UnboundedReceiver<WispMessage>) -> WispPacket {
        let msg = timeout(Duration::from_secs(2), rx.next())
            .await
            .expect("server packet timed out")
            .expect("server closed");
        match msg {
            WispMessage::Binary(b) => parse_packet(b).expect("valid wisp packet"),
            WispMessage::Text(t) => panic!("unexpected text frame {t}"),
        }
    }

    #[tokio::test]
    async fn v1_handshake_emits_continue_first() {
        let opts = loopback_test_options(6002);
        let ctx = test_ctx(opts, false);
        let (_in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => {
                assert_eq!(c.stream_id, 0);
                assert!(c.remaining > 0);
            }
            other => panic!("v1 must start with CONTINUE, got {other:?}"),
        }
        drop(_in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn v2_handshake_info_then_continue() {
        let opts = loopback_test_options(6002);
        let ctx = test_ctx(opts, true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Info(info) => {
                assert_eq!(info.stream_id, 0);
                assert_eq!(info.major, 2);
            }
            other => panic!("v2 must start with INFO, got {other:?}"),
        }
        in_tx
            .send(Ok(WispMessage::Binary(encode_info(2, 0, &[]))))
            .await
            .unwrap();
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("v2 must CONTINUE after INFO, got {other:?}"),
        }
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    async fn echo_listener() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (port, task)
    }

    #[tokio::test]
    async fn connect_data_echo_roundtrip() {
        let (port, echo) = echo_listener().await;
        let opts = loopback_test_options(port);
        assert!(
            !tcp_byte_limits_active(&opts),
            "unlimited sentinels must skip TCP byte metering"
        );
        let ctx = test_ctx(opts, false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;

        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }

        in_tx
            .send(Ok(WispMessage::Binary(encode_connect(&ConnectPacket {
                stream_id: 1,
                stream_type: stream_type::TCP,
                port,
                hostname: "127.0.0.1".to_owned(),
            }))))
            .await
            .unwrap();

        let payload = Bytes::from_static(b"wisp-echo-payload");
        in_tx
            .send(Ok(WispMessage::Binary(encode_data(1, &payload))))
            .await
            .unwrap();

        match next_packet(&mut out_rx).await {
            WispPacket::Data(d) => {
                assert_eq!(d.stream_id, 1);
                assert_eq!(&d.payload[..], &payload[..]);
            }
            other => panic!("expected echoed DATA, got {other:?}"),
        }

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        echo.abort();
    }

    #[tokio::test]
    async fn data_queued_during_connect_is_flushed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let opts = loopback_test_options(port);
        let ctx = test_ctx(opts, false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;

        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }

        in_tx
            .send(Ok(WispMessage::Binary(encode_connect(&ConnectPacket {
                stream_id: 1,
                stream_type: stream_type::TCP,
                port,
                hostname: "127.0.0.1".to_owned(),
            }))))
            .await
            .unwrap();

        let payload = Bytes::from_static(b"queued-before-tcp-ready");
        in_tx
            .send(Ok(WispMessage::Binary(encode_data(1, &payload))))
            .await
            .unwrap();

        match next_packet(&mut out_rx).await {
            WispPacket::Data(d) => {
                assert_eq!(d.stream_id, 1);
                assert_eq!(&d.payload[..], &payload[..]);
            }
            other => panic!("expected flushed DATA, got {other:?}"),
        }

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        echo.abort();
    }

    #[tokio::test]
    async fn full_initial_window_fits_bounded_stream_queue() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await
        });
        let opts = loopback_test_options(port);
        let ctx = test_ctx(opts, false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;

        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        in_tx
            .send(Ok(WispMessage::Binary(encode_connect(&ConnectPacket {
                stream_id: 1,
                stream_type: stream_type::TCP,
                port,
                hostname: "127.0.0.1".to_owned(),
            }))))
            .await
            .unwrap();

        let chunk = vec![b'x'; 50 * 1024];
        for _ in 0..256 {
            in_tx
                .send(Ok(WispMessage::Binary(encode_data(1, &chunk))))
                .await
                .unwrap();
        }

        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) if c.stream_id == 1 => {}
            WispPacket::Close(c) if c.stream_id == 1 => {
                panic!(
                    "initial credit window closed early with reason {}",
                    c.reason
                )
            }
            other => panic!("expected stream flow-control update, got {other:?}"),
        }

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        upstream.abort();
    }

    #[tokio::test]
    async fn mux_does_not_stall_other_streams_when_one_tcp_blocks() {
        let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let block_port = blocker.local_addr().unwrap().port();
        let block_task = tokio::spawn(async move {
            let (_sock, _) = blocker.accept().await.unwrap();
            std::future::pending::<()>().await
        });

        let (echo_port, echo) = echo_listener().await;
        let opts = Arc::new(WispServerOptions {
            protocol_inspection: false,
            allow_loopback_ips: true,
            allow_private_ips: true,
            allow_direct_ip: true,
            port_whitelist: Some(vec![echo_port, block_port]),
            max_tcp_bytes_per_connection_per_second: UNLIMITED,
            max_tcp_bytes_per_ip_per_second: UNLIMITED,
            stream_idle_timeout_ms: Some(5_000),
            idle_timeout_ms: Some(2_000),
            connect_timeout_ms: Some(2_000),
            ..WispServerOptions::default()
        });
        let ctx = test_ctx(opts, false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;

        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }

        in_tx
            .send(Ok(WispMessage::Binary(encode_connect(&ConnectPacket {
                stream_id: 1,
                stream_type: stream_type::TCP,
                port: block_port,
                hostname: "127.0.0.1".to_owned(),
            }))))
            .await
            .unwrap();

        let chunk = vec![b'x'; 32 * 1024];
        for _ in 0..256 {
            in_tx
                .send(Ok(WispMessage::Binary(encode_data(1, &chunk))))
                .await
                .unwrap();
        }

        in_tx
            .send(Ok(WispMessage::Binary(encode_connect(&ConnectPacket {
                stream_id: 2,
                stream_type: stream_type::TCP,
                port: echo_port,
                hostname: "127.0.0.1".to_owned(),
            }))))
            .await
            .unwrap();

        let payload = Bytes::from_static(b"other-stream-still-live");
        in_tx
            .send(Ok(WispMessage::Binary(encode_data(2, &payload))))
            .await
            .unwrap();
        loop {
            match next_packet(&mut out_rx).await {
                WispPacket::Data(d) if d.stream_id == 2 => {
                    assert_eq!(&d.payload[..], &payload[..]);
                    break;
                }
                WispPacket::Continue(c) if c.stream_id == 1 => {}
                WispPacket::Close(c) if c.stream_id == 1 => {}
                other => panic!("mux stalled: no echo on stream 2, got {other:?}"),
            }
        }

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        echo.abort();
        block_task.abort();
    }

    const HALF_CLOSE: &[u8] = &[
        extension_id::STREAM_OPEN_CONFIRMATION,
        extension_id::TCP_HALF_CLOSE,
    ];

    async fn send_packet(
        in_tx: &mut fmpsc::UnboundedSender<Result<WispMessage, std::io::Error>>,
        packet: Bytes,
    ) {
        in_tx.send(Ok(WispMessage::Binary(packet))).await.unwrap();
    }

    /// Runs the v2 handshake offering `ids` and returns the server's extensions.
    async fn v2_handshake(
        in_tx: &mut fmpsc::UnboundedSender<Result<WispMessage, std::io::Error>>,
        out_rx: &mut fmpsc::UnboundedReceiver<WispMessage>,
        ids: &[u8],
    ) -> Vec<ExtensionEntry> {
        let server = match next_packet(out_rx).await {
            WispPacket::Info(info) => parse_extensions(info.extensions).unwrap(),
            other => panic!("v2 must start with INFO, got {other:?}"),
        };
        let offered: Vec<ExtensionEntry> = ids
            .iter()
            .map(|&id| ExtensionEntry {
                id,
                payload: Bytes::new(),
            })
            .collect();
        send_packet(in_tx, encode_info(2, 0, &offered)).await;
        match next_packet(out_rx).await {
            WispPacket::Continue(c) if c.stream_id == 0 => {}
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        server
    }

    /// Opens a TCP stream to `listener` and waits for its open confirmation.
    async fn open_tcp(
        in_tx: &mut fmpsc::UnboundedSender<Result<WispMessage, std::io::Error>>,
        out_rx: &mut fmpsc::UnboundedReceiver<WispMessage>,
        listener: &TcpListener,
        stream_id: u32,
    ) -> tokio::net::TcpStream {
        send_packet(
            in_tx,
            encode_connect(&ConnectPacket {
                stream_id,
                stream_type: stream_type::TCP,
                port: listener.local_addr().unwrap().port(),
                hostname: "127.0.0.1".to_owned(),
            }),
        )
        .await;
        let (upstream, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("upstream accept timed out")
            .unwrap();
        match next_packet(out_rx).await {
            WispPacket::Continue(c) if c.stream_id == stream_id => {}
            other => panic!("expected open confirmation, got {other:?}"),
        }
        upstream
    }

    async fn expect_data(
        out_rx: &mut fmpsc::UnboundedReceiver<WispMessage>,
        stream_id: u32,
        expected: &[u8],
    ) {
        let mut got = Vec::new();
        while got.len() < expected.len() {
            match next_packet(out_rx).await {
                WispPacket::Data(d) if d.stream_id == stream_id => {
                    got.extend_from_slice(&d.payload)
                }
                other => panic!("expected DATA on stream {stream_id}, got {other:?}"),
            }
        }
        assert_eq!(got, expected);
    }

    async fn expect_quiet(out_rx: &mut fmpsc::UnboundedReceiver<WispMessage>) {
        if let Ok(Some(msg)) = timeout(Duration::from_millis(200), out_rx.next()).await {
            panic!("unexpected server message {msg:?}");
        }
    }

    /// A connection-level protocol error ends the connection; its CLOSE(0) is
    /// best effort because teardown cancels the egress writer.
    async fn expect_protocol_violation(
        mut out_rx: fmpsc::UnboundedReceiver<WispMessage>,
        handle: tokio::task::JoinHandle<Result<(), ServerError>>,
        stream_id: u32,
    ) {
        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("connection must end")
            .unwrap();
        assert!(matches!(result, Err(ServerError::ProtocolViolation(_))));
        while let Some(WispMessage::Binary(b)) = out_rx.next().await {
            match parse_packet(b).unwrap() {
                WispPacket::Continue(c) if c.stream_id == stream_id => {}
                other => assert_eq!(other, close(0, close_reason::CLIENT_ERROR)),
            }
        }
    }

    fn close(stream_id: u32, reason: u8) -> WispPacket {
        WispPacket::Close(ClosePacket { stream_id, reason })
    }

    fn fin(stream_id: u32) -> WispPacket {
        WispPacket::Fin(FinPacket { stream_id })
    }

    #[test]
    fn half_close_negotiates_only_with_empty_payload() {
        let opts = ServerOptions::from_wisp(&WispServerOptions::default(), false);
        let info = parse_packet(build_server_info(&opts, false)).unwrap();
        let WispPacket::Info(info) = info else {
            panic!("server INFO must be INFO");
        };
        assert!(parse_extensions(info.extensions)
            .unwrap()
            .contains(&ExtensionEntry {
                id: extension_id::TCP_HALF_CLOSE,
                payload: Bytes::new(),
            }));

        let offer = |payload: &'static [u8]| {
            vec![ExtensionEntry {
                id: extension_id::TCP_HALF_CLOSE,
                payload: Bytes::from_static(payload),
            }]
        };
        assert!(intersect_extensions(&opts, false, offer(b"")).tcp_half_close);
        assert!(!intersect_extensions(&opts, false, offer(b"\0")).tcp_half_close);
        assert!(!intersect_extensions(&opts, false, Vec::new()).tcp_half_close);
    }

    #[tokio::test]
    async fn client_fin_shuts_upstream_write_and_reading_continues() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctx = test_ctx(
            loopback_test_options(listener.local_addr().unwrap().port()),
            true,
        );
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, HALF_CLOSE).await;
        let mut upstream = open_tcp(&mut in_tx, &mut out_rx, &listener, 1).await;

        send_packet(&mut in_tx, encode_data(1, b"request")).await;
        send_packet(&mut in_tx, encode_fin(1)).await;
        let mut received = Vec::new();
        timeout(Duration::from_secs(2), upstream.read_to_end(&mut received))
            .await
            .expect("upstream never saw the FIN")
            .unwrap();
        assert_eq!(received, b"request");

        upstream.write_all(b"response-after-fin").await.unwrap();
        expect_data(&mut out_rx, 1, b"response-after-fin").await;
        expect_quiet(&mut out_rx).await;

        upstream.shutdown().await.unwrap();
        assert_eq!(next_packet(&mut out_rx).await, fin(1));
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::VOLUNTARY)
        );
        expect_quiet(&mut out_rx).await;

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn upstream_eof_sends_fin_and_client_keeps_writing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctx = test_ctx(
            loopback_test_options(listener.local_addr().unwrap().port()),
            true,
        );
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, HALF_CLOSE).await;
        let mut upstream = open_tcp(&mut in_tx, &mut out_rx, &listener, 1).await;

        upstream.write_all(b"goodbye").await.unwrap();
        upstream.shutdown().await.unwrap();
        expect_data(&mut out_rx, 1, b"goodbye").await;
        assert_eq!(next_packet(&mut out_rx).await, fin(1));
        expect_quiet(&mut out_rx).await;

        send_packet(&mut in_tx, encode_data(1, b"written-after-remote-fin")).await;
        let mut received = [0u8; 24];
        timeout(Duration::from_secs(2), upstream.read_exact(&mut received))
            .await
            .expect("upstream never got the late write")
            .unwrap();
        assert_eq!(&received, b"written-after-remote-fin");

        send_packet(&mut in_tx, encode_fin(1)).await;
        let mut rest = Vec::new();
        timeout(Duration::from_secs(2), upstream.read_to_end(&mut rest))
            .await
            .expect("upstream never saw the FIN")
            .unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::VOLUNTARY)
        );
        expect_quiet(&mut out_rx).await;

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn data_or_fin_after_client_fin_closes_the_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctx = test_ctx(
            loopback_test_options(listener.local_addr().unwrap().port()),
            true,
        );
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, HALF_CLOSE).await;

        let _first = open_tcp(&mut in_tx, &mut out_rx, &listener, 1).await;
        send_packet(&mut in_tx, encode_fin(1)).await;
        send_packet(&mut in_tx, encode_data(1, b"late")).await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::UNKNOWN)
        );

        let _second = open_tcp(&mut in_tx, &mut out_rx, &listener, 3).await;
        send_packet(&mut in_tx, encode_fin(3)).await;
        send_packet(&mut in_tx, encode_fin(3)).await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(3, close_reason::UNKNOWN)
        );
        expect_quiet(&mut out_rx).await;
        assert!(!handle.is_finished());

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn without_negotiation_eof_closes_and_fin_is_a_protocol_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctx = test_ctx(
            loopback_test_options(listener.local_addr().unwrap().port()),
            true,
        );
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        let server = v2_handshake(
            &mut in_tx,
            &mut out_rx,
            &[extension_id::STREAM_OPEN_CONFIRMATION],
        )
        .await;
        assert!(server.iter().any(|e| e.id == extension_id::TCP_HALF_CLOSE));

        let mut upstream = open_tcp(&mut in_tx, &mut out_rx, &listener, 1).await;
        upstream.write_all(b"last").await.unwrap();
        upstream.shutdown().await.unwrap();
        expect_data(&mut out_rx, 1, b"last").await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::VOLUNTARY)
        );

        let _second = open_tcp(&mut in_tx, &mut out_rx, &listener, 3).await;
        send_packet(&mut in_tx, encode_fin(3)).await;
        expect_protocol_violation(out_rx, handle, 3).await;
    }

    #[tokio::test]
    async fn fin_on_a_udp_stream_is_a_protocol_error() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ctx = test_ctx(
            loopback_test_options(socket.local_addr().unwrap().port()),
            true,
        );
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(
            &mut in_tx,
            &mut out_rx,
            &[extension_id::UDP, extension_id::TCP_HALF_CLOSE],
        )
        .await;
        send_packet(
            &mut in_tx,
            encode_connect(&ConnectPacket {
                stream_id: 1,
                stream_type: stream_type::UDP,
                port: socket.local_addr().unwrap().port(),
                hostname: "127.0.0.1".to_owned(),
            }),
        )
        .await;
        send_packet(&mut in_tx, encode_fin(1)).await;
        expect_protocol_violation(out_rx, handle, 1).await;
    }

    #[tokio::test]
    async fn fin_behind_a_full_write_queue_waits_and_takes_no_credit() {
        // The first chunk outgrows the socket buffers and blocks the writer,
        // and the rest fill its queue to capacity.
        const CHUNK: usize = 4 * 1024 * 1024;
        const CHUNKS: usize = 5;
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(16 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(1).unwrap();
        let mut opts = (*loopback_test_options(listener.local_addr().unwrap().port())).clone();
        opts.buffer_size = 8;
        opts.continue_threshold = CHUNKS as u64 + 1;
        opts.max_pending_packets_per_stream = CHUNKS as u64 - 1;
        opts.max_pending_bytes_per_stream = (CHUNK * CHUNKS) as u64;
        opts.max_binary_frame_bytes = (CHUNK * 2) as u64;
        let ctx = test_ctx(Arc::new(opts), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, HALF_CLOSE).await;
        let mut upstream = open_tcp(&mut in_tx, &mut out_rx, &listener, 1).await;

        let chunk = vec![b'x'; CHUNK];
        for _ in 0..CHUNKS {
            send_packet(&mut in_tx, encode_data(1, &chunk)).await;
        }
        send_packet(&mut in_tx, encode_fin(1)).await;
        expect_quiet(&mut out_rx).await;

        let mut received = Vec::new();
        timeout(Duration::from_secs(10), upstream.read_to_end(&mut received))
            .await
            .expect("upstream never saw the FIN")
            .unwrap();
        assert_eq!(received.len(), CHUNK * CHUNKS);

        upstream.shutdown().await.unwrap();
        assert_eq!(next_packet(&mut out_rx).await, fin(1));
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::VOLUNTARY)
        );
        expect_quiet(&mut out_rx).await;

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[test]
    fn connect_error_is_typed_not_string() {
        let err = ConnectError::NoAddresses("example.test".to_owned());
        assert!(matches!(err, ConnectError::NoAddresses(_)));
        let policy = HostPolicy::from_options(&WispServerOptions::default());
        let _ = policy;
    }
}

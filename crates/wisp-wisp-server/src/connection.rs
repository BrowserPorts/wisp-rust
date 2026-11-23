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
//! The TCP stream-open path classifies the client's first bytes with a
//! [`wisp_inspect::Inspector`] before any upstream bytes flow back.

use bytes::Bytes;
use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use wisp_config::{WispServerOptions, WispVersion};
use wisp_dos::{
    is_control_message_allowed, is_dns_resolution_allowed, is_tcp_stream_open_allowed,
    ConnectionDosGuard, DosGuard, TcpByteLimiter,
};
use wisp_proxy::{HostPolicy, NormalizedHost};
use wisp_wisp::{
    close_reason, encode_close, encode_continue, encode_fin, encode_info, extension_id,
    packet_type, parse_extensions_capped, parse_packet, stream_type, ExtensionEntry, WispError,
    WispPacket, DEFAULT_MAX_EXTENSION_ENTRIES,
};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

const WISP_MAJOR_VERSION: u8 = 2;

/// How long teardown waits for the egress writer to flush queued frames.
const EGRESS_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// `idle_timeout_ms` when it is unset. A connection always has an idle limit.
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 120_000;

use crate::budget::{BudgetCharge, Budgets};
use crate::proxy_control::{
    handle_proxy_control_text, proxy_control_error_frame, ProxyControlLimits, ProxyController,
};
use crate::stream::{
    activate_writer, drop_slot, flush_batch, shutdown_upstream_write, spawn_tcp_connect,
    write_upstream, StreamTable, TcpEvent, TcpStreamSlot, TcpStreamState, WriteOutcome,
};

/// `future` under a time limit, like [`tokio::time::timeout`], but the timer
/// is only made when the first poll does not finish. A write to a client that
/// is keeping up finishes at once, so the relay path builds no timer per frame.
async fn within<F: std::future::Future>(
    limit: std::time::Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::pin!(future);
    if let std::task::Poll::Ready(output) = futures::poll!(future.as_mut()) {
        return Ok(output);
    }
    tokio::time::timeout(limit, future).await
}

/// The connection's idle limit, `idle_timeout_ms`. Also bounds how long one
/// write to the client may take.
fn idle_limit(options: &WispServerOptions) -> std::time::Duration {
    std::time::Duration::from_millis(
        options
            .idle_timeout_ms
            .unwrap_or(DEFAULT_IDLE_TIMEOUT_MS)
            .max(1),
    )
}
use crate::udp::{spawn_udp_stream, UdpHandle, UdpStreamMsg};

/// UDP flows by wire stream ID.
type UdpStreams = HashMap<u32, UdpHandle>;

/// Per-connection limiter for repetitive rejection log lines. The first few
/// are logged as they happen, then only each power of two, each carrying the
/// running total, so a client that opens streams in a loop cannot flood the
/// log.
#[derive(Debug, Default)]
pub(crate) struct LogThrottle {
    count: AtomicU64,
}

impl LogThrottle {
    const LOG_FIRST: u64 = 8;

    /// Counts one rejection. `Some(total)` when it should be logged.
    pub(crate) fn admit(&self) -> Option<u64> {
        let total = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        (total <= Self::LOG_FIRST || total.is_power_of_two()).then_some(total)
    }
}

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
    permit: EgressPermit,
}

/// A queued frame's share of the connection's egress queue and, for DATA,
/// of the process byte budget. Released once the frame is flushed.
struct EgressPermit {
    _queue: OwnedSemaphorePermit,
    _process: Option<BudgetCharge>,
}

/// Runs when the egress writer ends, however it ends.
struct WriterExit {
    budget: Arc<Semaphore>,
    done: CancellationToken,
}

impl Drop for WriterExit {
    fn drop(&mut self) {
        self.budget.close();
        self.done.cancel();
    }
}

#[derive(Clone)]
pub(crate) struct EgressSender {
    tx: mpsc::Sender<BudgetedMessage>,
    flow_tx: mpsc::Sender<BudgetedMessage>,
    budget: Arc<Semaphore>,
    max_bytes: u32,
    process: Budgets,
}

impl EgressSender {
    fn new(
        tx: mpsc::Sender<BudgetedMessage>,
        flow_tx: mpsc::Sender<BudgetedMessage>,
        max_bytes: usize,
    ) -> Self {
        let max_bytes = max_bytes.clamp(1, Semaphore::MAX_PERMITS.min(u32::MAX as usize));
        Self {
            tx,
            flow_tx,
            budget: Arc::new(Semaphore::new(max_bytes)),
            max_bytes: max_bytes as u32,
            process: Budgets::process_only(),
        }
    }

    /// Upstream DATA counts against the process budget too; flow control and
    /// close frames are small and must never wait behind other connections.
    fn process_cost(message: &WispMessage) -> Option<usize> {
        match message {
            WispMessage::Binary(bytes) if bytes.first() == Some(&packet_type::DATA) => {
                Some(bytes.len())
            }
            _ => None,
        }
    }

    /// Resolves once the queue is not full and the process budget has room,
    /// so a reader waits here before it reads more from its upstream. Fails
    /// once the writer is gone.
    /// Whether [`Self::room`] would resolve at once: two atomic loads, so a
    /// reader with room skips building the wait.
    pub(crate) fn has_room(&self) -> bool {
        self.budget.available_permits() > 0 && self.process.has_room()
    }

    pub(crate) async fn room(&self) -> Result<(), ()> {
        if self.budget.available_permits() == 0 {
            drop(self.budget.acquire().await.map_err(|_| ())?);
        }
        self.process.room().await;
        Ok(())
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
        // A frame larger than the whole queue waits for the queue to empty
        // instead of waiting forever.
        let permits = Self::message_cost(&message).ok_or(())?.min(self.max_bytes);
        let queue = self
            .budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| ())?;
        let process = match Self::process_cost(&message) {
            Some(bytes) => {
                self.process.room().await;
                Some(self.process.charge(bytes))
            }
            None => None,
        };
        let permit = EgressPermit {
            _queue: queue,
            _process: process,
        };
        self.channel(&message)
            .send(BudgetedMessage { message, permit })
            .await
            .map_err(|_| ())
    }

    #[cfg(test)]
    fn try_send(&self, message: WispMessage) -> Result<(), ()> {
        let permits = Self::message_cost(&message).ok_or(())?.min(self.max_bytes);
        let queue = self
            .budget
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| ())?;
        let permit = EgressPermit {
            _queue: queue,
            _process: Self::process_cost(&message).map(|bytes| self.process.charge(bytes)),
        };
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
    /// Throttles the per-rejection log lines of this connection.
    pub(crate) reject_log: Arc<LogThrottle>,
    /// Upload bytes held for this connection's streams, against its own
    /// `max_ingress_bytes_per_connection` and the process budget.
    pub(crate) ingress: Budgets,
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
        let ingress = Budgets::for_connection(options.max_ingress_bytes_per_connection);
        let conn_dos = Arc::new(ConnectionDosGuard::new());
        let tcp_byte_limiter = Arc::new(TcpByteLimiter::new(
            &client_ip, &conn_dos, &options, &dos_store,
        ));
        if let Some(controller) = proxy_controller.as_ref() {
            controller.bind_client(&client_ip, None);
        }
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
            reject_log: Arc::new(LogThrottle::default()),
            ingress,
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

    let control_handlers = ctx
        .server_options
        .max_concurrent_proxy_control_handlers
        .max(1);
    // Room for the reply of every handler that can be in flight plus a few
    // busy NACKs, so a reply never waits on another and a NACK is not dropped.
    let (control_egress_tx, mut control_egress_rx) =
        mpsc::channel::<String>(control_handlers.saturating_add(8).min(4096));
    let control_concurrency = Arc::new(Semaphore::new(control_handlers));

    // Tells the writer to flush what is already queued and close. `ctx.cancel`
    // is not used for this: it fires first on teardown and would discard the
    // connection-level CLOSE the main loop just queued.
    let writer_stop = CancellationToken::new();
    let egress_writer_stop = writer_stop.clone();
    // Cancelled when the writer ends for any reason, so the main loop stops
    // serving a client it can no longer write to. Closing the queue budget
    // wakes every task waiting to queue a frame.
    let writer_done = CancellationToken::new();
    let egress_writer_done = writer_done.clone();
    let egress_budget = egress_tx.budget.clone();
    // A client that stops reading stalls each write; past the idle limit it
    // is dropped instead of pinning its queue and slot forever.
    let write_timeout = idle_limit(&ctx.options);
    let mut egress_writer = tokio::spawn(async move {
        let _exit = WriterExit {
            budget: egress_budget,
            done: egress_writer_done,
        };
        let mut main_closed = false;
        let mut flow_closed = false;
        let mut ctl_closed = false;
        let mut stopping = false;
        let mut batch: Vec<(WispMessage, Option<EgressPermit>)> = Vec::with_capacity(64);
        let mut flushed_permits: Vec<EgressPermit> = Vec::with_capacity(64);
        let stop = egress_writer_stop.cancelled();
        tokio::pin!(stop);
        while !(main_closed && flow_closed && ctl_closed) {
            // Control replies go first: they are tiny, and bulk data must not
            // starve them.
            let first = if stopping {
                if let Ok(t) = control_egress_rx.try_recv() {
                    Some((WispMessage::Text(t), None))
                } else if let Ok(m) = flow_egress_rx.try_recv() {
                    Some((m.message, Some(m.permit)))
                } else if let Ok(m) = egress_rx.try_recv() {
                    Some((m.message, Some(m.permit)))
                } else {
                    break;
                }
            } else {
                tokio::select! {
                    biased;
                    _ = &mut stop => { stopping = true; continue; }
                    text = control_egress_rx.recv(), if !ctl_closed => match text {
                        Some(t) => Some((WispMessage::Text(t), None)),
                        None => { ctl_closed = true; continue; }
                    },
                    msg = flow_egress_rx.recv(), if !flow_closed => match msg {
                        Some(m) => Some((m.message, Some(m.permit))),
                        None => { flow_closed = true; continue; }
                    },
                    msg = egress_rx.recv(), if !main_closed => match msg {
                        Some(m) => Some((m.message, Some(m.permit))),
                        None => { main_closed = true; continue; }
                    },
                }
            };
            let Some(m) = first else { continue };
            batch.push(m);
            if !ctl_closed {
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
            for (m, permit) in batch.drain(..) {
                match within(write_timeout, outgoing.feed(m)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(ServerError::transport(e)),
                    Err(_) => return Err(ServerError::transport("client write timed out")),
                }
                if let Some(permit) = permit {
                    flushed_permits.push(permit);
                }
            }
            match within(write_timeout, outgoing.flush()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(ServerError::transport(e)),
                Err(_) => return Err(ServerError::transport("client write timed out")),
            }
            flushed_permits.clear();
        }
        match tokio::time::timeout(write_timeout, outgoing.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(ServerError::transport(e)),
            Err(_) => return Err(ServerError::transport("client write timed out")),
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
    let mut udp_streams: UdpStreams = HashMap::new();
    let mut caps = StreamCaps::new(&ctx.server_options);
    let (stream_done_tx, mut stream_done_rx) = mpsc::channel::<(u32, u64)>(256);
    let (tcp_events_tx, mut tcp_events_rx) = mpsc::channel::<TcpEvent>(256);
    // Proxy control limits and rate budgets are shared across this client's
    // connections through the process-wide limiter, keyed by client IP.
    if let Some(controller) = ctx.proxy_controller.as_ref() {
        controller.bind_ip_budget(ctx.client_ip.clone(), ctx.dos_store.clone());
    }
    let binary_packet_limiter: Option<DirectLimiter> = build_per_minute_limiter(
        ctx.server_options
            .max_binary_packets_per_connection_per_minute,
    );
    let mut serve_err: Option<ServerError> = None;

    // A connection with no open stream that sends nothing for the idle limit
    // is closed. A v1 client has no handshake of its own, so its first frame
    // is due within the handshake timeout instead.
    let idle = idle_limit(&ctx.options);
    let mut heard_from_client = resolved_version == ResolvedVersion::V2;
    let mut last_inbound = tokio::time::Instant::now();
    let first_deadline = if heard_from_client {
        idle
    } else {
        std::time::Duration::from_millis(ctx.server_options.handshake_timeout_ms.max(1))
    };
    let idle_timer = tokio::time::sleep(first_deadline);
    tokio::pin!(idle_timer);
    // Uploads held for this connection's streams stop the client from being
    // read until the upstreams take some of them. One message is still read
    // and parked meanwhile, so a client that goes away is noticed.
    let mut parked: Option<WispMessage> = None;
    // Made once: a cancellation future per message would join and leave the
    // token's waiter list, under its lock, for every frame.
    let cancelled = ctx.cancel.cancelled();
    tokio::pin!(cancelled);
    let writer_gone = writer_done.cancelled();
    tokio::pin!(writer_gone);
    // DATA that arrives together is written to each upstream together: the
    // streams in `dirty` hold a batch, and are flushed before the loop waits
    // or handles anything but more DATA. `ready` is the next message when it
    // was already there to read, and `burst` bounds how many are taken that
    // way before the other branches get a turn.
    let mut dirty: Vec<u32> = Vec::new();
    let mut ready: Option<WispMessage> = None;
    let mut burst = 0_u32;

    loop {
        let ingress_open = ctx.ingress.has_room();
        if !ingress_open {
            if let Some(m) = ready.take() {
                parked = Some(m);
            }
        }
        let msg = if let Some(m) = ready.take() {
            m
        } else {
            burst = 0;
            if let Err(e) = flush_dirty(
                &mut dirty,
                &mut streams,
                &mut caps,
                &ctx,
                &egress_tx,
                &tcp_events_tx,
            )
            .await
            {
                serve_err = Some(e);
                break;
            }
            tokio::select! {
            biased;
            _ = &mut cancelled => break,
            // The writer's own error is collected at teardown.
            _ = &mut writer_gone => break,
            _ = &mut idle_timer => {
                let now = tokio::time::Instant::now();
                if !heard_from_client {
                    tracing::debug!(client_ip = %ctx.client_ip, "wisp: closing connection: no first frame");
                    break;
                }
                let quiet_until = last_inbound + idle;
                if now >= quiet_until && streams.is_empty() && udp_streams.is_empty() {
                    tracing::debug!(client_ip = %ctx.client_ip, "wisp: closing idle connection");
                    break;
                }
                // Quiet but with streams open: look again in a while.
                let next = if now < quiet_until {
                    quiet_until
                } else {
                    now + (idle / 4).max(std::time::Duration::from_millis(1))
                };
                idle_timer.as_mut().reset(next);
                continue;
            }
            ev = tcp_events_rx.recv() => {
                match ev {
                    Some(TcpEvent::Ready { stream_id, generation, write, reader, gate }) => {
                        if let Some(slot) = streams.get_gen_mut(stream_id, generation) {
                            let inspecting = slot.inspected(&ctx);
                            slot.set_gate(gate, inspecting);
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
                            } else if negotiated.stream_open_confirmation
                                && egress_tx
                                    .send(WispMessage::Binary(encode_continue(
                                        stream_id,
                                        ctx.server_options.buffer_size,
                                    )))
                                    .await
                                    .is_err()
                            {
                                serve_err = Some(ServerError::ClientClosed);
                                break;
                            } else {
                                // Upstream bytes may flow now: the open
                                // confirmation is ahead of them in the queue.
                                slot.confirm_open();
                                if slot.upstream_eof
                                    && finish_upstream_read(stream_id, &mut streams, &mut caps, &egress_tx)
                                        .await
                                        .is_err()
                                {
                                    serve_err = Some(ServerError::ClientClosed);
                                    break;
                                }
                            }
                        } else {
                            drop(write);
                            reader.abort();
                        }
                    }
                    Some(TcpEvent::Failed { stream_id, generation })
                    | Some(TcpEvent::ReaderDone { stream_id, generation })
                    | Some(TcpEvent::WriterDone { stream_id, generation }) => {
                        if let Some(slot) = streams.remove_gen(stream_id, generation) {
                            drop_slot(slot);
                            caps.release_gen(stream_id, generation);
                        }
                    }
                    Some(TcpEvent::InspectionTimeout { stream_id, generation }) => {
                        let pending = streams
                            .get_gen_mut(stream_id, generation)
                            .is_some_and(|slot| slot.inspection_pending());
                        if pending {
                            if let Some(rejections) = ctx.reject_log.admit() {
                                tracing::warn!(
                                    stream_id,
                                    rejections,
                                    "wisp tcp protocol inspection timed out"
                                );
                            }
                            if close_tcp_stream(
                                stream_id,
                                close_reason::TRANSFER_TIMEOUT,
                                &mut streams,
                                &mut caps,
                                &egress_tx,
                            )
                            .await
                            .is_err()
                            {
                                serve_err = Some(ServerError::ClientClosed);
                                break;
                            }
                        }
                    }
                    Some(TcpEvent::ReadEof { stream_id, generation }) => {
                        let Some(slot) = streams.get_gen_mut(stream_id, generation) else {
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
                    Some(TcpEvent::WriteShut { stream_id, generation }) => {
                        let Some(slot) = streams.get_gen_mut(stream_id, generation) else {
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
                if let Some((stream_id, generation)) = done {
                    // A flow that ended after its ID was reused must not
                    // remove the new flow.
                    if udp_streams
                        .get(&stream_id)
                        .is_some_and(|udp| udp.generation == generation)
                    {
                        udp_streams.remove(&stream_id);
                        caps.release_gen(stream_id, generation);
                    }
                }
                continue;
            }
            _ = std::future::ready(()), if ingress_open && parked.is_some() => {
                match parked.take() {
                    Some(m) => m,
                    None => continue,
                }
            }
            _ = ctx.ingress.room(), if !ingress_open => continue,
            recv = incoming.next(), if parked.is_none() => match recv {
                Some(Ok(m)) => {
                    heard_from_client = true;
                    last_inbound = tokio::time::Instant::now();
                    if !ingress_open {
                        parked = Some(m);
                        continue;
                    }
                    m
                }
                Some(Err(e)) => {
                    serve_err = Some(ServerError::transport(e));
                    break;
                }
                None => break,
            },
            }
        };
        let is_data = matches!(
            &msg,
            WispMessage::Binary(frame) if frame.len() >= 5 && frame[0] == packet_type::DATA
        );
        if !is_data {
            if let Err(e) = flush_dirty(
                &mut dirty,
                &mut streams,
                &mut caps,
                &ctx,
                &egress_tx,
                &tcp_events_tx,
            )
            .await
            {
                serve_err = Some(e);
                break;
            }
        }
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
                        Some(&mut dirty),
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
                    // Take the next message now if it is already here, so its
                    // DATA joins the same upstream write.
                    if burst < 64 && parked.is_none() {
                        burst += 1;
                        match incoming.next().now_or_never() {
                            Some(Some(Ok(m))) => {
                                last_inbound = tokio::time::Instant::now();
                                ready = Some(m);
                            }
                            Some(Some(Err(e))) => {
                                let _ = flush_dirty(
                                    &mut dirty,
                                    &mut streams,
                                    &mut caps,
                                    &ctx,
                                    &egress_tx,
                                    &tcp_events_tx,
                                )
                                .await;
                                serve_err = Some(ServerError::transport(e));
                                break;
                            }
                            Some(None) => {
                                let _ = flush_dirty(
                                    &mut dirty,
                                    &mut streams,
                                    &mut caps,
                                    &ctx,
                                    &egress_tx,
                                    &tcp_events_tx,
                                )
                                .await;
                                break;
                            }
                            None => {}
                        }
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
                // Both the per-connection and the per-IP control limits, as on
                // the WebTransport path.
                if !is_control_message_allowed(
                    &ctx.client_ip,
                    &ctx.conn_dos,
                    &ctx.options,
                    &ctx.dos_store,
                ) {
                    tracing::warn!("wisp: closing connection: proxy_control rate exceeded");
                    let _ = egress_tx
                        .send(WispMessage::Binary(encode_close(
                            0,
                            close_reason::CONN_THROTTLED,
                        )))
                        .await;
                    break;
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
    for (_, udp) in udp_streams.drain() {
        udp.abort();
    }
    ctx.cancel.cancel();
    drop(egress_tx);
    drop(control_egress_tx);
    // The writer flushes what is already queued, such as the CLOSE that
    // explains why the connection ended, then closes the sink. The wait is
    // short so a client that stopped reading cannot hold the teardown.
    writer_stop.cancel();
    match tokio::time::timeout(EGRESS_FLUSH_TIMEOUT, &mut egress_writer).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(sink_err))) => {
            if serve_err.is_none() {
                serve_err = Some(sink_err);
            }
        }
        Ok(Err(_join_err)) => {}
        Err(_elapsed) => egress_writer.abort(),
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
    /// Host key and generation of each admitted stream, by wire stream ID.
    host_keys: HashMap<u32, (String, u64)>,
    next_generation: u64,
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
            next_generation: 1,
            open_limiter,
            stream_limit_total: opts.stream_limit_total,
            stream_limit_per_host: opts.stream_limit_per_host,
        }
    }

    fn host_key(host: &str, port: u16) -> String {
        format!("{}:{port}", host.to_ascii_lowercase())
    }

    /// Admits a stream and returns its generation, which tells it apart from
    /// earlier streams that used the same wire ID.
    fn try_admit(&mut self, stream_id: u32, host: &str, port: u16) -> Result<u64, AdmitDenied> {
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
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.host_keys.insert(stream_id, (key, generation));
        Ok(generation)
    }

    /// Releases the stream currently holding `stream_id`.
    fn release(&mut self, stream_id: u32) {
        if let Some((key, _)) = self.host_keys.remove(&stream_id) {
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

impl StreamCaps {
    /// Releases `stream_id` only if it is still held by the stream that
    /// `generation` was issued to, so a late completion cannot free the cap of
    /// a newer stream that reused the ID.
    fn release_gen(&mut self, stream_id: u32, generation: u64) {
        if self
            .host_keys
            .get(&stream_id)
            .is_some_and(|(_, held)| *held == generation)
        {
            self.release(stream_id);
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
    fn stale_generation_cannot_release_a_reused_id() {
        let mut caps = StreamCaps::new(&opts(2, None, 0));
        let old = caps.try_admit(5, "a", 80).unwrap();
        caps.release(5);
        let new = caps.try_admit(5, "b", 80).unwrap();
        assert_ne!(old, new);
        caps.release_gen(5, old);
        assert_eq!(caps.total, 1, "the new stream keeps its cap");
        assert!(caps.try_admit(6, "c", 80).is_ok());
        assert!(matches!(
            caps.try_admit(7, "d", 80),
            Err(AdmitDenied::TotalCap)
        ));
        caps.release_gen(5, new);
        assert_eq!(caps.total, 1);
    }

    #[test]
    fn log_throttle_logs_the_first_few_then_powers_of_two() {
        let throttle = LogThrottle::default();
        let logged: Vec<u64> = (0..100).filter_map(|_| throttle.admit()).collect();
        assert_eq!(logged, vec![1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64]);
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
    udp_streams: &mut UdpStreams,
    caps: &mut StreamCaps,
    dirty: Option<&mut Vec<u32>>,
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
            write_upstream(
                slot,
                payload,
                stream_id,
                dirty.is_some(),
                ctx,
                egress,
                tcp_events,
            )
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
            WriteOutcome::SendContinue(credit) => {
                if egress
                    .send(WispMessage::Binary(encode_continue(stream_id, credit)))
                    .await
                    .is_err()
                {
                    return Err(ServerError::ClientClosed);
                }
            }
            WriteOutcome::Deferred { first } => {
                if let (true, Some(dirty)) = (first, dirty) {
                    dirty.push(stream_id);
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
    udp_streams: &mut UdpStreams,
    caps: &mut StreamCaps,
    ctx: &ServerContext,
    negotiated: &NegotiatedExtensions,
    egress: &EgressSender,
    stream_done_tx: &mpsc::Sender<(u32, u64)>,
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
            // Only a name that passes the destination policy costs a DNS
            // token, keyed by its normalized spelling. A refused host never
            // reaches the resolver; the dial task re-checks and reports it.
            let checked = if conn.stream_type == stream_type::UDP {
                ctx.policy.check_udp_host(&conn.hostname, conn.port)
            } else {
                ctx.policy.check_host(&conn.hostname, conn.port)
            };
            let dns_allowed = match &checked {
                Ok(NormalizedHost::Name(name)) => {
                    is_dns_resolution_allowed(&ctx.client_ip, name, &ctx.options, &ctx.dos_store)
                }
                _ => true,
            };
            if !dns_allowed {
                if let Some(rejections) = ctx.reject_log.admit() {
                    tracing::info!(
                        stream_id = conn.stream_id,
                        host = ?conn.hostname,
                        rejections,
                        "wisp connect rejected: dns resolution rate limit"
                    );
                }
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
                        if let Some(rejections) = ctx.reject_log.admit() {
                            tracing::info!(
                                stream_id = conn.stream_id,
                                host = ?conn.hostname,
                                port = conn.port,
                                rejections,
                                "wisp tcp connect rejected: stream-open rate limit"
                            );
                        }
                        let _ = egress
                            .send(WispMessage::Binary(encode_close(
                                conn.stream_id,
                                close_reason::CONN_THROTTLED,
                            )))
                            .await;
                        return Ok(());
                    }
                    let generation = match caps.try_admit(conn.stream_id, &conn.hostname, conn.port)
                    {
                        Ok(generation) => generation,
                        Err(reason) => {
                            if let Some(rejections) = ctx.reject_log.admit() {
                                tracing::info!(
                                    stream_id = conn.stream_id,
                                    host = ?conn.hostname,
                                    port = conn.port,
                                    ?reason,
                                    rejections,
                                    "wisp tcp connect rejected: stream cap"
                                );
                            }
                            let _ = egress
                                .send(WispMessage::Binary(encode_close(
                                    conn.stream_id,
                                    close_reason::CONN_THROTTLED,
                                )))
                                .await;
                            return Ok(());
                        }
                    };
                    let mut slot = TcpStreamSlot::connecting_for(generation, Some(&conn.hostname));
                    if let Ok(host) = &checked {
                        if ctx.policy.admitted_only_by_host_rule(host, conn.port) {
                            slot.skip_inspection();
                        }
                    }
                    slot.set_dial(spawn_tcp_connect(
                        conn.stream_id,
                        generation,
                        conn.hostname.clone(),
                        conn.port,
                        negotiated.tcp_half_close,
                        slot.activity(),
                        ctx.clone(),
                        egress.clone(),
                        tcp_events.clone(),
                    ));
                    streams.insert(conn.stream_id, slot);
                }
                stream_type::UDP if negotiated.udp => {
                    // UDP opens share the TCP stream-open budget, per
                    // connection and per client IP.
                    if !is_tcp_stream_open_allowed(
                        &ctx.client_ip,
                        &ctx.conn_dos,
                        &ctx.options,
                        &ctx.dos_store,
                    ) {
                        if let Some(rejections) = ctx.reject_log.admit() {
                            tracing::info!(
                                stream_id = conn.stream_id,
                                host = ?conn.hostname,
                                port = conn.port,
                                rejections,
                                "wisp udp connect rejected: stream-open rate limit"
                            );
                        }
                        let _ = egress
                            .send(WispMessage::Binary(encode_close(
                                conn.stream_id,
                                close_reason::CONN_THROTTLED,
                            )))
                            .await;
                        return Ok(());
                    }
                    let generation = match caps.try_admit(conn.stream_id, &conn.hostname, conn.port)
                    {
                        Ok(generation) => generation,
                        Err(reason) => {
                            if let Some(rejections) = ctx.reject_log.admit() {
                                tracing::info!(
                                    stream_id = conn.stream_id,
                                    host = ?conn.hostname,
                                    port = conn.port,
                                    ?reason,
                                    rejections,
                                    "wisp udp connect rejected: stream cap"
                                );
                            }
                            let _ = egress
                                .send(WispMessage::Binary(encode_close(
                                    conn.stream_id,
                                    close_reason::CONN_THROTTLED,
                                )))
                                .await;
                            return Ok(());
                        }
                    };
                    let udp = spawn_udp_stream(
                        conn.stream_id,
                        generation,
                        conn.hostname.clone(),
                        conn.port,
                        ctx.clone(),
                        egress.clone(),
                        stream_done_tx.clone(),
                    );
                    udp_streams.insert(conn.stream_id, udp);
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
                None,
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
                // Aborting also stops a flow that is still resolving its
                // destination, which a queued Close would not reach.
                let _ = udp.try_send(UdpStreamMsg::Close);
                udp.abort();
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

/// Writes every batch the DATA path collected to its upstream.
async fn flush_dirty(
    dirty: &mut Vec<u32>,
    streams: &mut StreamTable,
    caps: &mut StreamCaps,
    ctx: &ServerContext,
    egress: &EgressSender,
    tcp_events: &mpsc::Sender<TcpEvent>,
) -> Result<(), ServerError> {
    for stream_id in dirty.drain(..) {
        // A stream dropped since it joined the list has no batch to write.
        let Some(slot) = streams.get_mut(stream_id) else {
            continue;
        };
        match flush_batch(slot, stream_id, ctx, egress, tcp_events) {
            WriteOutcome::DropStream(reason) => {
                close_tcp_stream(stream_id, reason, streams, caps, egress).await?;
            }
            WriteOutcome::SendContinue(credit) => {
                egress
                    .send(WispMessage::Binary(encode_continue(stream_id, credit)))
                    .await
                    .map_err(|()| ServerError::ClientClosed)?;
            }
            WriteOutcome::Ok | WriteOutcome::Deferred { .. } => {}
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
/// rate space. The `UNLIMITED` sentinel (`u64::MAX`, set via `-1` in TOML)
/// becomes `0`, which here means "no limiter"; any other value is clamped into
/// `u32`. A configured `0` never reaches this for a rate limit, because
/// `validate()` refuses it (wisp-dos would read it as "deny all"); the one
/// documented zero is `max_binary_packets_per_connection_per_minute`, where
/// `0` means disabled.
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

        // The upstream takes nothing, so the stream earns no new credit, and
        // the full initial window must not close it either.
        expect_quiet(&mut out_rx).await;
        assert!(!handle.is_finished());

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

    fn queue(in_tx: &fmpsc::UnboundedSender<Result<WispMessage, std::io::Error>>, packet: Bytes) {
        in_tx
            .unbounded_send(Ok(WispMessage::Binary(packet)))
            .unwrap();
    }

    fn tcp_connect(stream_id: u32, hostname: &str, port: u16) -> Bytes {
        encode_connect(&ConnectPacket {
            stream_id,
            stream_type: stream_type::TCP,
            port,
            hostname: hostname.to_owned(),
        })
    }

    #[tokio::test]
    async fn connection_close_reason_is_delivered() {
        // The CLOSE used to lose a race with the writer's cancellation on
        // every run, so repeat it.
        for _ in 0..20 {
            let mut options = (*loopback_test_options(6002)).clone();
            options.max_binary_packets_per_connection_per_minute = 2;
            let ctx = test_ctx(Arc::new(options), false);
            let (in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
            match next_packet(&mut out_rx).await {
                WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
                other => panic!("expected handshake CONTINUE, got {other:?}"),
            }
            for _ in 0..3 {
                queue(&in_tx, encode_data(1, b"x"));
            }
            assert_eq!(
                next_packet(&mut out_rx).await,
                close(0, close_reason::CONN_THROTTLED)
            );
            let _ = timeout(Duration::from_secs(2), handle).await;
        }
    }

    #[tokio::test]
    async fn protocol_violation_close_reason_is_delivered() {
        let ctx = test_ctx(loopback_test_options(6002), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, &[]).await;
        send_packet(&mut in_tx, encode_data(0, b"x")).await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(0, close_reason::CLIENT_ERROR)
        );
        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("connection must end")
            .unwrap();
        assert!(matches!(result, Err(ServerError::ProtocolViolation(_))));
    }

    #[tokio::test]
    async fn reused_stream_id_never_reaches_the_old_destination() {
        let old = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_port = old.local_addr().unwrap().port();
        let (new_port, echo) = echo_listener().await;
        let mut options = (*loopback_test_options(new_port)).clone();
        options.port_whitelist = Some(vec![old_port, new_port]);
        let ctx = test_ctx(Arc::new(options), false);
        let (in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }

        // All queued before the server runs, so the first stream's dial has
        // not completed when its ID is reused.
        queue(&in_tx, tcp_connect(5, "127.0.0.1", old_port));
        queue(&in_tx, encode_data(5, b"for-old"));
        queue(&in_tx, encode_close(5, close_reason::VOLUNTARY));
        queue(&in_tx, tcp_connect(5, "127.0.0.1", new_port));
        queue(&in_tx, encode_data(5, b"for-new"));

        // Echo of exactly the new stream's payload: nothing of the old
        // stream's reached it.
        expect_data(&mut out_rx, 5, b"for-new").await;

        // The old destination may have received what the client sent while
        // its stream was open, but never what was sent to the new one.
        let mut seen = Vec::new();
        if let Ok(Ok((mut sock, _))) = timeout(Duration::from_millis(300), old.accept()).await {
            let mut buf = [0u8; 64];
            while let Ok(Ok(n)) = timeout(Duration::from_millis(300), sock.read(&mut buf)).await {
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
            }
        }
        assert!(
            !String::from_utf8_lossy(&seen).contains("for-new"),
            "old destination received {seen:?}"
        );

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        echo.abort();
    }

    #[tokio::test]
    async fn closing_a_connecting_stream_aborts_its_dial() {
        // The echo listener serves one connection. Were the first stream's
        // dial left running after CLOSE it would take that connection, and
        // the second stream's would never be answered. The cap of one also
        // has to be free again by the second CONNECT.
        let mut options = (*loopback_test_options(6002)).clone();
        options.stream_limit_total = 1;
        options.port_whitelist = None;
        let ctx = test_ctx(Arc::new(options), false);
        let (in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        let (port, echo) = echo_listener().await;
        queue(&in_tx, tcp_connect(1, "127.0.0.1", port));
        queue(&in_tx, encode_close(1, close_reason::VOLUNTARY));
        queue(&in_tx, tcp_connect(2, "127.0.0.1", port));
        queue(&in_tx, encode_data(2, b"second"));
        expect_data(&mut out_rx, 2, b"second").await;
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        echo.abort();
    }

    #[tokio::test]
    async fn reused_udp_stream_id_reaches_the_new_flow() {
        let old = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (old_port, new_port) = (
            old.local_addr().unwrap().port(),
            new.local_addr().unwrap().port(),
        );
        let mut options = (*loopback_test_options(new_port)).clone();
        options.port_whitelist = Some(vec![old_port, new_port]);
        let ctx = test_ctx(Arc::new(options), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, &[extension_id::UDP]).await;

        let udp_connect = |port| {
            encode_connect(&ConnectPacket {
                stream_id: 7,
                stream_type: stream_type::UDP,
                port,
                hostname: "127.0.0.1".to_owned(),
            })
        };
        queue(&in_tx, udp_connect(old_port));
        queue(&in_tx, encode_close(7, close_reason::VOLUNTARY));
        queue(&in_tx, udp_connect(new_port));
        queue(&in_tx, encode_data(7, b"udp-new"));

        let mut buf = [0u8; 32];
        let (n, _) = timeout(Duration::from_secs(2), new.recv_from(&mut buf))
            .await
            .expect("new flow got no datagram")
            .unwrap();
        assert_eq!(&buf[..n], b"udp-new");

        // The first flow ending must not have unregistered the new one.
        tokio::time::sleep(Duration::from_millis(100)).await;
        queue(&in_tx, encode_data(7, b"second"));
        let (n, _) = timeout(Duration::from_secs(2), new.recv_from(&mut buf))
            .await
            .expect("new flow was black-holed")
            .unwrap();
        assert_eq!(&buf[..n], b"second");
        assert!(
            timeout(Duration::from_millis(200), old.recv_from(&mut buf))
                .await
                .map_or(true, |got| got.is_err() || &buf[..4] != b"udp-"),
            "old flow received the new flow's datagram"
        );

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    fn udp_connect(stream_id: u32, hostname: &str, port: u16) -> Bytes {
        encode_connect(&ConnectPacket {
            stream_id,
            stream_type: stream_type::UDP,
            port,
            hostname: hostname.to_owned(),
        })
    }

    /// Runs one UDP open against a local socket and returns the first packet
    /// the server sends for that stream, plus whether a datagram arrived.
    async fn udp_open_outcome(
        edit: impl FnOnce(&mut WispServerOptions, u16),
    ) -> (WispPacket, bool) {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let mut options = (*loopback_test_options(port)).clone();
        edit(&mut options, port);
        let ctx = test_ctx(Arc::new(options), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, &[extension_id::UDP]).await;
        queue(&in_tx, udp_connect(7, "127.0.0.1", port));
        queue(&in_tx, encode_data(7, b"leak"));
        let first = next_packet(&mut out_rx).await;
        let mut buf = [0u8; 16];
        let arrived = timeout(Duration::from_millis(300), target.recv_from(&mut buf))
            .await
            .is_ok_and(|got| got.is_ok());
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        (first, arrived)
    }

    #[tokio::test]
    async fn udp_is_refused_where_tcp_must_be_proxied() {
        let (first, arrived) = udp_open_outcome(|o, _| o.force_proxy = true).await;
        assert_eq!(first, close(7, close_reason::HOST_BLOCKED));
        assert!(!arrived, "no datagram may leave from the server's address");
        let (first, arrived) = udp_open_outcome(|_, _| {}).await;
        assert!(matches!(first, WispPacket::Continue(_)), "got {first:?}");
        assert!(arrived);
    }

    #[tokio::test]
    async fn udp_port_whitelist_limits_udp_destinations() {
        let (first, arrived) =
            udp_open_outcome(|o, port| o.udp_port_whitelist = Some(vec![port.wrapping_add(1)]))
                .await;
        assert_eq!(first, close(7, close_reason::HOST_BLOCKED));
        assert!(!arrived);
        let (first, arrived) =
            udp_open_outcome(|o, port| o.udp_port_whitelist = Some(vec![port])).await;
        assert!(matches!(first, WispPacket::Continue(_)), "got {first:?}");
        assert!(arrived);
    }

    #[tokio::test]
    async fn udp_opens_are_rate_limited_like_tcp() {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let mut options = (*loopback_test_options(port)).clone();
        options.max_tcp_stream_opens_per_connection_per_minute = 1;
        let ctx = test_ctx(Arc::new(options), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, &[extension_id::UDP]).await;
        queue(&in_tx, udp_connect(7, "127.0.0.1", port));
        assert!(matches!(
            next_packet(&mut out_rx).await,
            WispPacket::Continue(_)
        ));
        queue(&in_tx, udp_connect(9, "127.0.0.1", port));
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(9, close_reason::CONN_THROTTLED)
        );
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn a_refused_host_costs_no_dns_token() {
        let mut options = (*loopback_test_options(443)).clone();
        options.port_whitelist = Some(vec![443]);
        options.domain_blacklist = Some(vec!["blocked.example".to_owned()]);
        options.max_dns_resolutions_per_ip_per_minute = 1;
        // Bounds the lookup of the allowed name well inside next_packet's wait.
        options.connect_timeout_ms = Some(500);
        let ctx = test_ctx(Arc::new(options), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, &[]).await;
        // Refused names, in any spelling, are closed as blocked and do not
        // spend the single DNS token.
        for (id, host) in [
            (3, "blocked.example"),
            (5, "BLOCKED.example."),
            (7, "16843009"),
        ] {
            queue(&in_tx, tcp_connect(id, host, 443));
            assert_eq!(
                next_packet(&mut out_rx).await,
                close(id, close_reason::HOST_BLOCKED)
            );
        }
        // The token is still there for an allowed name (`.invalid` never
        // resolves, so the stream then fails, but not as throttled).
        queue(&in_tx, tcp_connect(9, "nothing.invalid", 443));
        assert_ne!(
            next_packet(&mut out_rx).await,
            close(9, close_reason::CONN_THROTTLED)
        );
        queue(&in_tx, tcp_connect(11, "other.invalid", 443));
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(11, close_reason::CONN_THROTTLED)
        );
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    fn inspecting_options(port: u16, timeout_ms: u64) -> Arc<WispServerOptions> {
        let mut options = (*loopback_test_options(port)).clone();
        options.protocol_inspection = true;
        options.protocol_inspection_timeout_ms = Some(timeout_ms);
        Arc::new(options)
    }

    #[tokio::test]
    async fn server_first_output_is_held_until_the_client_is_classified() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-banner\r\n").await.unwrap();
            let mut request = vec![0u8; 256];
            let n = sock.read(&mut request).await.unwrap();
            request.truncate(n);
            request
        });
        let ctx = test_ctx(inspecting_options(port, 5_000), false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        send_packet(&mut in_tx, tcp_connect(1, "127.0.0.1", port)).await;
        // The banner is waiting on the socket, but nothing is forwarded while
        // the client has sent nothing to classify.
        expect_quiet(&mut out_rx).await;

        let request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        send_packet(&mut in_tx, encode_data(1, request)).await;
        expect_data(&mut out_rx, 1, b"SSH-2.0-banner\r\n").await;
        assert_eq!(upstream.await.unwrap(), request);

        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn host_rule_destination_speaks_first_through_inspection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"VT01-challenge").await.unwrap();
            let mut reply = vec![0u8; 64];
            let n = sock.read(&mut reply).await.unwrap();
            reply.truncate(n);
            reply
        });
        // Inspection is on and the port is outside port_whitelist; only an
        // address-range rule admits it, so it carries any protocol.
        let mut options = (*inspecting_options(port, 5_000)).clone();
        options.allow_direct_ip = false;
        options.port_whitelist = Some(vec![80, 443]);
        options.host_port_whitelist = Some(vec![wisp_config::HostPortRule {
            host: "127.0.0.0/8".to_owned(),
            port,
        }]);
        let ctx = test_ctx(Arc::new(options), false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        send_packet(&mut in_tx, tcp_connect(1, "127.0.0.1", port)).await;
        expect_data(&mut out_rx, 1, b"VT01-challenge").await;
        send_packet(&mut in_tx, encode_data(1, b"\x00\x01binary")).await;
        assert_eq!(upstream.await.unwrap(), b"\x00\x01binary");
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn open_confirmation_precedes_upstream_first_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"hello-first").await.unwrap();
            sock
        });
        let ctx = test_ctx(loopback_test_options(port), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, HALF_CLOSE).await;
        send_packet(&mut in_tx, tcp_connect(1, "127.0.0.1", port)).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) if c.stream_id == 1 => {}
            other => panic!("expected open confirmation first, got {other:?}"),
        }
        expect_data(&mut out_rx, 1, b"hello-first").await;
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
        let _ = upstream.await;
    }

    #[tokio::test]
    async fn silent_stream_hits_the_inspection_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ctx = test_ctx(inspecting_options(port, 200), false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        send_packet(&mut in_tx, tcp_connect(1, "127.0.0.1", port)).await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::TRANSFER_TIMEOUT)
        );
        // A dripping client is bounded the same way: bytes that never form a
        // request do not postpone the deadline.
        send_packet(&mut in_tx, tcp_connect(3, "127.0.0.1", port)).await;
        send_packet(&mut in_tx, encode_data(3, b"GET / HTTP/1.1\r\n")).await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(3, close_reason::TRANSFER_TIMEOUT)
        );
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn connect_method_is_blocked_on_a_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ctx = test_ctx(inspecting_options(port, 5_000), false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        send_packet(&mut in_tx, tcp_connect(1, "127.0.0.1", port)).await;
        send_packet(
            &mut in_tx,
            encode_data(
                1,
                b"CONNECT evil.example:22 HTTP/1.1\r\nHost: evil.example:22\r\n\r\n",
            ),
        )
        .await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::HOST_BLOCKED)
        );
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn host_header_must_name_the_connect_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // What each of the two connections sent before it ended.
        let upstream = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut request = vec![0u8; 256];
                let n = sock.read(&mut request).await.unwrap();
                request.truncate(n);
                received.push(request);
            }
            received
        });
        let ctx = test_ctx(inspecting_options(port, 5_000), false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        // Fronting: the stream was opened to localhost but speaks for another host.
        send_packet(&mut in_tx, tcp_connect(1, "localhost", port)).await;
        send_packet(
            &mut in_tx,
            encode_data(1, b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"),
        )
        .await;
        assert_eq!(
            next_packet(&mut out_rx).await,
            close(1, close_reason::HOST_BLOCKED)
        );

        let request = format!("GET / HTTP/1.1\r\nHost: LOCALHOST.:{port}\r\n\r\n");
        send_packet(&mut in_tx, tcp_connect(3, "localhost", port)).await;
        send_packet(&mut in_tx, encode_data(3, request.as_bytes())).await;
        let received = upstream.await.unwrap();
        assert!(received[0].is_empty(), "blocked stream leaked bytes");
        assert_eq!(received[1], request.as_bytes());
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn control_messages_are_limited_per_ip_across_connections() {
        let mut options = (*loopback_test_options(6002)).clone();
        options.max_control_messages_per_ip_per_minute = 2;
        options.max_control_messages_per_connection_per_minute = UNLIMITED;
        let options = Arc::new(options);
        let server_options = Arc::new(ServerOptions::from_wisp(&options, true));
        let template = crate::ProxyControllerTemplate::new(Vec::new());
        let dos = Arc::new(DosGuard::new());
        let connect = || {
            let ctx = ServerContext::new(
                "198.51.100.7".to_owned(),
                None,
                options.clone(),
                server_options.clone(),
                Some(template.spawn(server_options.proxy_control_limits(), None)),
                true,
                dos.clone(),
            );
            spawn_serve(ctx)
        };
        let list = || WispMessage::Text(r#"{"type":"proxy_list_providers"}"#.to_owned());

        let (mut first_tx, mut first_rx, first) = connect().await;
        v2_handshake(
            &mut first_tx,
            &mut first_rx,
            &[extension_id::WISP_PROXY_CONTROL],
        )
        .await;
        for _ in 0..2 {
            first_tx.send(Ok(list())).await.unwrap();
            match timeout(Duration::from_secs(2), first_rx.next()).await {
                Ok(Some(WispMessage::Text(reply))) => assert!(reply.contains("providers")),
                other => panic!("expected a control reply, got {other:?}"),
            }
        }

        // A second connection from the same IP finds the budget spent, though
        // its own per-connection limit is off.
        let (mut second_tx, mut second_rx, second) = connect().await;
        v2_handshake(
            &mut second_tx,
            &mut second_rx,
            &[extension_id::WISP_PROXY_CONTROL],
        )
        .await;
        second_tx.send(Ok(list())).await.unwrap();
        loop {
            let msg = timeout(Duration::from_secs(2), second_rx.next())
                .await
                .expect("second connection was never throttled")
                .expect("second connection closed without a reason");
            if let WispMessage::Binary(frame) = msg {
                assert_eq!(
                    parse_packet(frame).unwrap(),
                    close(0, close_reason::CONN_THROTTLED)
                );
                break;
            }
        }
        drop(first_tx);
        drop(second_tx);
        let _ = timeout(Duration::from_secs(2), first).await;
        let _ = timeout(Duration::from_secs(2), second).await;
    }

    /// Accepts every connection and never reads from it.
    async fn stalled_upstream() -> (u16, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(16 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(64).unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        (port, task)
    }

    #[tokio::test]
    async fn many_streams_stay_within_the_connection_upload_budget() {
        const BUDGET: usize = 512 * 1024;
        const CHUNK: usize = 32 * 1024;
        let (port, upstream) = stalled_upstream().await;
        let mut options = (*loopback_test_options(port)).clone();
        options.max_ingress_bytes_per_connection = BUDGET as u64;
        let ctx = test_ctx(Arc::new(options), false);
        let ingress = ctx.ingress.clone();
        let (in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }

        // Eight streams, each well inside its credit, together offer 16 MiB
        // to upstreams that take nothing past their socket buffers.
        let chunk = vec![b'x'; CHUNK];
        for stream_id in 1..=8 {
            queue(&in_tx, tcp_connect(stream_id, "127.0.0.1", port));
        }
        for _ in 0..64 {
            for stream_id in 1..=8 {
                queue(&in_tx, encode_data(stream_id, &chunk));
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let held = ingress.connection_used();
        assert!(held >= BUDGET / 2, "the budget was never reached: {held}");
        assert!(
            held < BUDGET + CHUNK,
            "held {held} bytes, past the {BUDGET} byte budget"
        );
        // Backpressure, not a close.
        expect_quiet(&mut out_rx).await;
        assert!(!handle.is_finished());

        upstream.abort();
        drop(in_tx);
        let _ = timeout(Duration::from_secs(5), handle).await;
        assert_eq!(ingress.connection_used(), 0, "teardown releases every byte");
    }

    #[tokio::test]
    async fn credit_compliant_client_is_paced_not_closed() {
        const CHUNK: usize = 8 * 1024;
        const PACKETS: usize = 512;
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(16 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(1).unwrap();
        let mut options = (*loopback_test_options(listener.local_addr().unwrap().port())).clone();
        options.buffer_size = 64;
        options.continue_threshold = 32;
        options.max_pending_packets_per_stream = 128;
        options.max_pending_bytes_per_stream = 128 * 1024;
        let ctx = test_ctx(Arc::new(options), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, HALF_CLOSE).await;
        let mut upstream = open_tcp(&mut in_tx, &mut out_rx, &listener, 1).await;
        // A slow upstream: small reads with a pause between them.
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut total = 0;
            loop {
                match upstream.read(&mut buf).await {
                    Ok(0) | Err(_) => break total,
                    Ok(n) => {
                        total += n;
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
        });

        // The client sends only while it holds credit, as the protocol asks.
        let chunk = vec![b'x'; CHUNK];
        let mut credit = 64u32;
        let mut sent = 0;
        let on_packet = |packet: WispPacket, credit: &mut u32| match packet {
            WispPacket::Continue(c) if c.stream_id == 1 => *credit = c.remaining,
            WispPacket::Close(c) => panic!("compliant client closed with reason {:#x}", c.reason),
            other => panic!("unexpected packet {other:?}"),
        };
        while sent < PACKETS {
            while let Ok(WispMessage::Binary(frame)) = out_rx.try_recv() {
                on_packet(parse_packet(frame).unwrap(), &mut credit);
            }
            if credit == 0 {
                let packet = timeout(Duration::from_secs(5), next_packet(&mut out_rx))
                    .await
                    .expect("credit never came back");
                on_packet(packet, &mut credit);
                continue;
            }
            send_packet(&mut in_tx, encode_data(1, &chunk)).await;
            credit -= 1;
            sent += 1;
        }
        send_packet(&mut in_tx, encode_fin(1)).await;
        let total = timeout(Duration::from_secs(10), reader)
            .await
            .expect("upstream never finished")
            .unwrap();
        assert_eq!(total, CHUNK * PACKETS);
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    /// Bytes `offset..offset + len` of a counting sequence that differs per
    /// stream, so a lost, repeated or reordered payload shows.
    fn counting_bytes(stream: usize, offset: usize, len: usize) -> Vec<u8> {
        (offset..offset + len)
            .map(|i| ((i + stream * 97) % 251) as u8)
            .collect()
    }

    #[tokio::test]
    async fn coalesced_bursts_reach_stalled_upstreams_whole_and_in_order() {
        // Each burst outgrows the socket buffers, so a batch is cut short,
        // often partway through a payload, and handed to a queued writer.
        const CHUNK: usize = 16 * 1024;
        const WINDOW: usize = 32;
        const TOTAL: usize = WINDOW * 4;
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(16 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(2).unwrap();
        let mut options = (*loopback_test_options(listener.local_addr().unwrap().port())).clone();
        options.buffer_size = WINDOW as u64;
        options.continue_threshold = (WINDOW / 2) as u64;
        options.max_pending_packets_per_stream = (WINDOW * 2) as u64;
        options.max_pending_bytes_per_stream = (CHUNK * WINDOW * 2) as u64;
        let ctx = test_ctx(Arc::new(options), true);
        let ingress = ctx.ingress.clone();
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, HALF_CLOSE).await;
        let upstreams = [
            open_tcp(&mut in_tx, &mut out_rx, &listener, 1).await,
            open_tcp(&mut in_tx, &mut out_rx, &listener, 2).await,
        ];
        // The upstreams take nothing at first, then read to the FIN.
        let readers = upstreams.map(|mut upstream| {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let mut received = Vec::new();
                upstream.read_to_end(&mut received).await.map(|_| received)
            })
        });

        // The client spends all its credit at once with the two streams
        // interleaved, so the server finds the payloads queued together.
        // The last burst ends with the FINs, which must not overtake it.
        let mut credit = [WINDOW as u32; 2];
        let mut sent = [0usize; 2];
        let on_packet = |packet: WispPacket, credit: &mut [u32; 2]| match packet {
            WispPacket::Continue(c) if c.stream_id == 1 || c.stream_id == 2 => {
                credit[c.stream_id as usize - 1] = c.remaining;
            }
            other => panic!("unexpected packet {other:?}"),
        };
        while sent != [TOTAL; 2] {
            while let Ok(WispMessage::Binary(frame)) = out_rx.try_recv() {
                on_packet(parse_packet(frame).unwrap(), &mut credit);
            }
            let burst = [0, 1].map(|s| (credit[s] as usize).min(TOTAL - sent[s]));
            if burst == [0, 0] {
                let packet = timeout(Duration::from_secs(5), next_packet(&mut out_rx))
                    .await
                    .expect("credit never came back");
                on_packet(packet, &mut credit);
                continue;
            }
            for k in 0..burst[0].max(burst[1]) {
                for s in 0..2 {
                    if k < burst[s] {
                        let payload = counting_bytes(s, sent[s] * CHUNK, CHUNK);
                        queue(&in_tx, encode_data(s as u32 + 1, &payload));
                        sent[s] += 1;
                        credit[s] -= 1;
                    }
                }
            }
        }
        queue(&in_tx, encode_fin(1));
        queue(&in_tx, encode_fin(2));

        for (s, reader) in readers.into_iter().enumerate() {
            let received = timeout(Duration::from_secs(10), reader)
                .await
                .expect("upstream never saw the FIN")
                .unwrap()
                .unwrap();
            let expected = counting_bytes(s, 0, TOTAL * CHUNK);
            assert_eq!(received.len(), expected.len(), "stream {} length", s + 1);
            let first_wrong = received.iter().zip(&expected).position(|(a, b)| a != b);
            assert_eq!(first_wrong, None, "stream {} bytes out of order", s + 1);
        }
        // Written payloads give back every byte they held.
        let released = timeout(Duration::from_secs(2), async {
            while ingress.connection_used() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            released.is_ok(),
            "{} bytes still held",
            ingress.connection_used()
        );
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn upload_to_a_quiet_upstream_is_not_cut() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut options = (*loopback_test_options(port)).clone();
        options.stream_idle_timeout_ms = Some(300);
        let ctx = test_ctx(Arc::new(options), false);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        send_packet(&mut in_tx, tcp_connect(1, "127.0.0.1", port)).await;
        let (mut upstream, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("upstream accept timed out")
            .unwrap();
        // The upstream only listens; the client keeps sending for four idle
        // windows.
        for _ in 0..12 {
            send_packet(&mut in_tx, encode_data(1, b"tick")).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(msg) = out_rx.try_recv() {
                panic!("upload was interrupted by {msg:?}");
            }
        }
        let mut received = vec![0u8; 48];
        timeout(Duration::from_secs(2), upstream.read_exact(&mut received))
            .await
            .expect("upstream missed the upload")
            .unwrap();
        assert_eq!(received, b"tick".repeat(12));
        drop(in_tx);
        let _ = timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn idle_connection_without_streams_closes() {
        let mut options = (*loopback_test_options(6002)).clone();
        options.idle_timeout_ms = Some(300);
        let ctx = test_ctx(Arc::new(options), true);
        let (mut in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        v2_handshake(&mut in_tx, &mut out_rx, &[]).await;
        let result = timeout(Duration::from_secs(2), handle)
            .await
            .expect("an idle connection was never closed")
            .unwrap();
        assert!(result.is_ok(), "{result:?}");
        drop(in_tx);
    }

    #[tokio::test]
    async fn v1_client_must_send_a_first_frame_in_time() {
        let mut options = (*loopback_test_options(6002)).clone();
        options.handshake_timeout_ms = Some(200);
        options.idle_timeout_ms = Some(60_000);
        let ctx = test_ctx(Arc::new(options), false);
        let (in_tx, mut out_rx, handle) = spawn_serve(ctx).await;
        match next_packet(&mut out_rx).await {
            WispPacket::Continue(c) => assert_eq!(c.stream_id, 0),
            other => panic!("expected handshake CONTINUE, got {other:?}"),
        }
        timeout(Duration::from_secs(2), handle)
            .await
            .expect("a silent v1 client was never closed")
            .unwrap()
            .unwrap();
        drop(in_tx);
    }

    /// A client transport that never accepts a frame, like a peer that has
    /// stopped reading with its window full.
    struct StalledSink;

    impl Sink<WispMessage> for StalledSink {
        type Error = std::io::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn start_send(
            self: std::pin::Pin<&mut Self>,
            _item: WispMessage,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn client_that_stops_reading_is_dropped() {
        let mut options = (*loopback_test_options(6002)).clone();
        options.idle_timeout_ms = Some(300);
        let ctx = test_ctx(Arc::new(options), false);
        let (in_tx, in_rx) = fmpsc::unbounded::<Result<WispMessage, std::io::Error>>();
        let handle = tokio::spawn(serve_connection(StalledSink, in_rx, ctx));
        let result = timeout(Duration::from_secs(3), handle)
            .await
            .expect("a client that never reads was never dropped")
            .unwrap();
        assert!(result.is_err(), "{result:?}");
        drop(in_tx);
    }

    #[test]
    fn connect_error_is_typed_not_string() {
        let err = ConnectError::NoAddresses("example.test".to_owned());
        assert!(matches!(err, ConnectError::NoAddresses(_)));
        let policy = HostPolicy::from_options(&WispServerOptions::default());
        let _ = policy;
    }
}

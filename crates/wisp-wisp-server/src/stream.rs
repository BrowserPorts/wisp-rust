//! Per-stream TCP bridge.
//!
//! CONNECT dials in a helper task. The mux never `write_all`s: if the TCP
//! write half is idle it `try_write`s (mrrowisp `Write` on the hit path).
//! `WouldBlock` moves the half to a writer task that drains a bounded
//! channel, then returns the half so the next packet can hit `try_write`
//! again. A reader task only pumps upstream → client. Pending DATA before
//! the dial finishes is flushed through the same path once the socket is
//! live, so order is preserved.
//!
//! With TCP Half-Close negotiated, a client FIN shuts down the upstream write
//! half once everything queued ahead of it is written: inline when the half is
//! idle, or by closing the writer's channel so the writer task drains it and
//! then shuts down. An upstream EOF stops the reader and is reported to the
//! mux, which sends the FIN and releases the stream once both sides are done.
//!
//! Upload credit follows the upstream: a payload the upstream has not taken
//! yet is held in a [`StreamFlow`], and CONTINUE is granted as the upstream
//! drains, so a client that honours its credit is paced rather than closed.
//! Held bytes count against the connection's and the process's byte budgets.

use bytes::{BufMut, Bytes, BytesMut};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashMap, VecDeque};
use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::timeout;
use tracing::warn;
use wisp_inspect::{BlockReason, InspectionDecision, Inspector};
use wisp_proxy::{HostPolicy, ProxyError};
use wisp_wisp::{
    close_reason, encode_close, encode_continue, write_data_header, PACKET_HEADER_LEN,
};

use crate::budget::{BudgetCharge, Budgets};
use crate::connection::{EgressSender, ServerContext, WispMessage};
use crate::proxy_control::ProxyConnectError;

const READ_CHUNK: usize = 128 * 1024;
const READ_BUFFER_POOL_CAPACITY: usize = 256;
const WRITE_BATCH_CAPACITY: usize = 64;
/// Upstream reads shorter than this are copied out of the pooled buffer, so
/// a frame waiting in the egress queue pins only its own length and not the
/// whole read buffer the egress budget does not see.
const COPY_READS_BELOW: usize = 16 * 1024;
pub(crate) const TCP_SOCKET_BUF: usize = 512 * 1024;

#[derive(Default)]
struct ReadBufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
}

impl ReadBufferPool {
    fn take(self: &Arc<Self>) -> PooledReadBuffer {
        let data = self
            .buffers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(PACKET_HEADER_LEN + READ_CHUNK));
        PooledReadBuffer {
            data,
            pool: self.clone(),
        }
    }

    fn put(&self, mut data: Vec<u8>) {
        data.clear();
        if data.capacity() < PACKET_HEADER_LEN + READ_CHUNK {
            return;
        }
        let mut buffers = self
            .buffers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if buffers.len() < READ_BUFFER_POOL_CAPACITY {
            buffers.push(data);
        }
    }
}

struct PooledReadBuffer {
    data: Vec<u8>,
    pool: Arc<ReadBufferPool>,
}

impl AsRef<[u8]> for PooledReadBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for PooledReadBuffer {
    fn drop(&mut self) {
        self.pool.put(std::mem::take(&mut self.data));
    }
}

fn read_buffer_pool() -> Arc<ReadBufferPool> {
    static POOL: OnceLock<Arc<ReadBufferPool>> = OnceLock::new();
    POOL.get_or_init(|| Arc::new(ReadBufferPool::default()))
        .clone()
}

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("dns lookup failed for {host}: {source}")]
    DnsLookup {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("no addresses resolved for {0}")]
    NoAddresses(String),
    #[error(transparent)]
    Policy(#[from] ProxyError),
    #[error("tcp connect failed: {0}")]
    Tcp(#[source] std::io::Error),
    #[error("force_proxy is enabled but no proxy controller is active")]
    ForceProxyWithoutController,
}

#[derive(Debug, Error)]
enum OpenFail {
    #[error(transparent)]
    Connect(ConnectError),
    #[error(transparent)]
    Proxy(ProxyConnectError),
}

/// Checks `host:port` against the policy, resolves a name through the shared
/// cached resolver (never the blocking system resolver) and checks every
/// address it returns.
pub(crate) async fn resolve_checked(
    host: &str,
    port: u16,
    policy: &HostPolicy,
) -> Result<Vec<SocketAddr>, ConnectError> {
    Ok(policy.resolve(host, port).await?)
}

/// Errors worth one more round of dials: the listener was not there yet or
/// dropped the handshake. A timeout already spent its budget and is final.
fn connect_error_is_retryable(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::Interrupted
    )
}

/// Orders addresses for dialing, alternating families and starting with the
/// preferred one. With staggered attempts a blackholed IPv6 route then costs
/// one stagger delay, not the whole dial budget.
fn interleave_families(addrs: &mut Vec<SocketAddr>, ipv6_first: bool) {
    let (mut first, mut second): (VecDeque<SocketAddr>, VecDeque<SocketAddr>) =
        addrs.drain(..).partition(|sa| sa.is_ipv6() == ipv6_first);
    while !first.is_empty() || !second.is_empty() {
        if let Some(sa) = first.pop_front() {
            addrs.push(sa);
        }
        if let Some(sa) = second.pop_front() {
            addrs.push(sa);
        }
    }
}

/// While one dial is pending, the next address starts after this long.
const DIAL_STAGGER: Duration = Duration::from_millis(250);
/// Addresses dialed for one stream at most.
const MAX_DIAL_ADDRS: usize = 8;
/// Pauses before each extra round, taken only when every attempt of the
/// previous round was refused or reset. Each address gets at most three SYNs.
const DIAL_RETRY_BACKOFF: [Duration; 2] = [Duration::from_millis(50), Duration::from_millis(200)];

pub(crate) async fn connect_checked_tcp(
    host: &str,
    port: u16,
    policy: &HostPolicy,
) -> Result<TcpStream, ConnectError> {
    let mut addrs = resolve_checked(host, port, policy).await?;
    interleave_families(
        &mut addrs,
        matches!(
            policy.dns.result_order,
            wisp_config::DnsResultOrder::Ipv6first
        ),
    );
    addrs.truncate(MAX_DIAL_ADDRS);
    let stream = dial_addrs(&addrs, policy.dns.timeout).await?;
    tune_tcp(&stream);
    Ok(stream)
}

/// Dials `addrs` with staggered starts (each attempt has its own timeout) and
/// returns the first connection. A round where every attempt was refused or
/// reset is retried after a short pause, up to [`DIAL_RETRY_BACKOFF`].
async fn dial_addrs(
    addrs: &[SocketAddr],
    per_attempt: Duration,
) -> Result<TcpStream, ConnectError> {
    let mut last = None;
    for backoff in std::iter::once(None).chain(DIAL_RETRY_BACKOFF.iter().map(Some)) {
        if let Some(delay) = backoff {
            tokio::time::sleep(*delay).await;
        }
        match dial_round(addrs, per_attempt).await {
            Ok(stream) => return Ok(stream),
            Err((error, retryable)) => {
                last = Some(error);
                if !retryable {
                    break;
                }
            }
        }
    }
    Err(ConnectError::Tcp(last.unwrap_or_else(|| {
        std::io::Error::other("no address connected")
    })))
}

async fn dial_one(addr: SocketAddr, per_attempt: Duration) -> std::io::Result<TcpStream> {
    match timeout(per_attempt, TcpStream::connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connect timed out",
        )),
    }
}

/// One pass over `addrs`. On failure, returns the last error and whether
/// every attempt failed in a retryable way.
async fn dial_round(
    addrs: &[SocketAddr],
    per_attempt: Duration,
) -> Result<TcpStream, (std::io::Error, bool)> {
    let mut attempts = FuturesUnordered::new();
    let mut next = 0;
    let mut last: Option<std::io::Error> = None;
    let mut retryable = true;
    loop {
        if attempts.is_empty() {
            let Some(addr) = addrs.get(next) else {
                break;
            };
            attempts.push(dial_one(*addr, per_attempt));
            next += 1;
        }
        tokio::select! {
            Some(result) = attempts.next() => match result {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    retryable &= connect_error_is_retryable(&error);
                    last = Some(error);
                }
            },
            _ = tokio::time::sleep(DIAL_STAGGER), if next < addrs.len() => {
                attempts.push(dial_one(addrs[next], per_attempt));
                next += 1;
            }
        }
    }
    match last {
        Some(error) => Err((error, retryable)),
        None => Err((std::io::Error::other("no address to dial"), false)),
    }
}

pub(crate) fn tune_tcp(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(TCP_SOCKET_BUF);
    let _ = sock.set_send_buffer_size(TCP_SOCKET_BUF);
}

/// A stream's tasks report back by wire stream ID plus the generation the mux
/// gave that stream when it opened. The client may reuse an ID right after
/// CLOSE, so an event whose generation no longer matches the slot belongs to
/// an earlier stream and is ignored.
pub(crate) enum TcpEvent {
    Ready {
        stream_id: u32,
        generation: u64,
        write: OwnedWriteHalf,
        reader: ReaderHandle,
        /// Opens the reader's gate; see [`UpstreamGate`].
        gate: oneshot::Sender<()>,
    },
    Failed {
        stream_id: u32,
        generation: u64,
    },
    ReaderDone {
        stream_id: u32,
        generation: u64,
    },
    WriterDone {
        stream_id: u32,
        generation: u64,
    },
    ReadEof {
        stream_id: u32,
        generation: u64,
    },
    WriteShut {
        stream_id: u32,
        generation: u64,
    },
    /// The protocol inspection deadline passed.
    InspectionTimeout {
        stream_id: u32,
        generation: u64,
    },
}

/// Aborts the reader task when dropped, so a reader whose slot is gone, or
/// whose `Ready` event never reached the mux, cannot keep forwarding upstream
/// bytes under a stream ID that may already belong to another stream.
pub(crate) struct ReaderHandle(JoinHandle<()>);

impl ReaderHandle {
    pub(crate) fn abort(&self) {
        self.0.abort();
    }
}

impl Drop for ReaderHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Holds the upstream reader back until the client has been told the stream
/// is open and, when protocol inspection is on, the client's first bytes have
/// been classified. Without it a server-first service streams to the client
/// before inspection has judged anything, and its first DATA can overtake the
/// open-confirmation CONTINUE.
pub(crate) struct UpstreamGate {
    tx: Option<oneshot::Sender<()>>,
    confirmed: bool,
    classified: bool,
}

impl UpstreamGate {
    fn release_if_ready(&mut self) {
        if self.confirmed && self.classified {
            if let Some(tx) = self.tx.take() {
                let _ = tx.send(());
            }
        }
    }
}

/// First client bytes held back while the protocol is classified. The timer
/// task is aborted when the state is dropped, whether the stream was
/// classified or torn down.
pub(crate) struct InspectionState {
    buf: BytesMut,
    inspector: Inspector,
    timer: Option<JoinHandle<()>>,
}

impl Drop for InspectionState {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.abort();
        }
    }
}

/// Last time a stream moved bytes in either direction. Client DATA, writes
/// to the upstream and reads from it all reset it, so the stream idle timer
/// does not cut an upload to an upstream that has nothing to say.
pub(crate) struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        })
    }

    pub(crate) fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn idle_for(&self, idle: Option<Duration>) -> bool {
        let Some(idle) = idle else {
            return false;
        };
        let elapsed = self.start.elapsed().as_millis() as u64;
        elapsed.saturating_sub(self.last_ms.load(Ordering::Relaxed)) >= idle.as_millis() as u64
    }
}

/// Upload credit for one stream. CONTINUE is granted as the upstream takes
/// the client's bytes rather than as they are queued: after
/// `continue_threshold` payloads have been written, the client is told how
/// many more the stream can hold. While the stream holds more than
/// `max_pending_bytes_per_stream` unwritten bytes no credit is granted.
pub(crate) struct StreamFlow {
    counters: Mutex<FlowCounters>,
    budgets: Budgets,
    buffer_size: u32,
    threshold: u32,
    soft_bytes: usize,
}

#[derive(Default)]
struct FlowCounters {
    held_packets: usize,
    held_bytes: usize,
    written_since_grant: u32,
}

impl StreamFlow {
    fn new(budgets: Budgets, buffer_size: u32, threshold: u32, soft_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            counters: Mutex::new(FlowCounters::default()),
            budgets,
            buffer_size,
            threshold: threshold.max(1),
            soft_bytes,
        })
    }

    fn for_ctx(ctx: &ServerContext) -> Arc<Self> {
        Self::new(
            ctx.ingress.clone(),
            ctx.server_options.buffer_size,
            ctx.server_options.continue_threshold,
            usize::try_from(ctx.options.max_pending_bytes_per_stream).unwrap_or(usize::MAX),
        )
    }

    fn counters(&self) -> MutexGuard<'_, FlowCounters> {
        self.counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Holds `bytes` of one payload until the returned guard is dropped.
    fn hold(self: &Arc<Self>, bytes: usize) -> HeldBytes {
        let mut counters = self.counters();
        counters.held_packets += 1;
        counters.held_bytes = counters.held_bytes.saturating_add(bytes);
        drop(counters);
        HeldBytes {
            flow: self.clone(),
            bytes,
            _charge: self.budgets.charge(bytes),
        }
    }

    fn held_packets(&self) -> usize {
        self.counters().held_packets
    }

    /// A payload went to the upstream without being held.
    fn note_written(&self) {
        let mut counters = self.counters();
        counters.written_since_grant = counters.written_since_grant.saturating_add(1);
    }

    /// Credit to grant now, if the upstream has taken enough since the last
    /// grant. The value is the room left in the client's window.
    fn take_grant(&self) -> Option<u32> {
        let mut counters = self.counters();
        if counters.written_since_grant < self.threshold || counters.held_bytes > self.soft_bytes {
            return None;
        }
        let room = (self.buffer_size as usize).saturating_sub(counters.held_packets);
        if room == 0 {
            return None;
        }
        counters.written_since_grant = 0;
        Some(u32::try_from(room).unwrap_or(u32::MAX))
    }
}

/// One payload's share of a [`StreamFlow`] and of the byte budgets. Dropping
/// it means the upstream took the payload, or the stream is gone.
pub(crate) struct HeldBytes {
    flow: Arc<StreamFlow>,
    bytes: usize,
    _charge: BudgetCharge,
}

impl Drop for HeldBytes {
    fn drop(&mut self) {
        let mut counters = self.flow.counters();
        counters.held_packets = counters.held_packets.saturating_sub(1);
        counters.held_bytes = counters.held_bytes.saturating_sub(self.bytes);
        counters.written_since_grant = counters.written_since_grant.saturating_add(1);
    }
}

/// A client payload the upstream has not taken yet.
pub(crate) struct QueuedWrite {
    data: Bytes,
    _held: HeldBytes,
}

pub(crate) struct QueuedWriter {
    tx: Option<mpsc::Sender<QueuedWrite>>,
    task: JoinHandle<()>,
}

pub(crate) enum TcpStreamState {
    Connecting {
        pending: Vec<QueuedWrite>,
    },
    Live {
        write: Option<OwnedWriteHalf>,
        queued: Option<QueuedWriter>,
        inspection: Option<InspectionState>,
        reader: ReaderHandle,
    },
}

pub(crate) struct TcpStreamSlot {
    pub state: TcpStreamState,
    /// Distinguishes this stream from earlier ones that used the same wire ID.
    pub generation: u64,
    /// Hostname the client asked for; the inspected SNI or Host must match it.
    host: Option<String>,
    /// The dial task, aborted with the slot so a stale dial cannot activate a
    /// later stream or hold a connection open after CLOSE.
    dial: Option<AbortHandle>,
    gate: Option<UpstreamGate>,
    /// Admitted only by a host and port rule, so its bytes are not inspected.
    uninspected: bool,
    activity: Arc<Activity>,
    /// Upload credit and held bytes, made with the first payload.
    flow: Option<Arc<StreamFlow>>,
    /// The client sent FIN; no more DATA is valid.
    pub client_fin: bool,
    /// The upstream write half has been shut down.
    pub write_shut: bool,
    /// The upstream read half hit EOF.
    pub upstream_eof: bool,
}

impl TcpStreamSlot {
    #[cfg(test)]
    pub(crate) fn connecting() -> Self {
        Self::connecting_for(0, None)
    }

    pub(crate) fn connecting_for(generation: u64, host: Option<&str>) -> Self {
        Self {
            state: TcpStreamState::Connecting {
                pending: Vec::new(),
            },
            generation,
            host: host.map(str::to_owned),
            dial: None,
            gate: None,
            uninspected: false,
            activity: Activity::new(),
            flow: None,
            client_fin: false,
            write_shut: false,
            upstream_eof: false,
        }
    }

    /// Both directions are finished and the stream can be released.
    pub(crate) fn finished(&self) -> bool {
        self.write_shut && self.upstream_eof
    }

    /// Leaves the stream out of protocol inspection (see
    /// `HostPolicy::admitted_only_by_host_rule`).
    pub(crate) fn skip_inspection(&mut self) {
        self.uninspected = true;
    }

    /// Whether the client's first bytes are inspected before upstream is read.
    pub(crate) fn inspected(&self, ctx: &ServerContext) -> bool {
        ctx.options.protocol_inspection && !self.uninspected
    }

    pub(crate) fn set_dial(&mut self, dial: AbortHandle) {
        self.dial = Some(dial);
    }

    /// The activity clock the stream's reader idles against.
    pub(crate) fn activity(&self) -> Arc<Activity> {
        self.activity.clone()
    }

    fn flow_for(&mut self, ctx: &ServerContext) -> Arc<StreamFlow> {
        self.flow
            .get_or_insert_with(|| StreamFlow::for_ctx(ctx))
            .clone()
    }

    /// Installs the gate the reader waits on. `inspecting` is whether the
    /// client's first bytes still have to be classified.
    pub(crate) fn set_gate(&mut self, tx: oneshot::Sender<()>, inspecting: bool) {
        self.gate = Some(UpstreamGate {
            tx: Some(tx),
            confirmed: false,
            classified: !inspecting,
        });
    }

    /// The client has been told the stream is open (or needs no telling).
    pub(crate) fn confirm_open(&mut self) {
        if let Some(gate) = self.gate.as_mut() {
            gate.confirmed = true;
            gate.release_if_ready();
        }
    }

    /// Protocol inspection is still waiting on the client's first bytes.
    pub(crate) fn inspection_pending(&self) -> bool {
        matches!(
            &self.state,
            TcpStreamState::Live {
                inspection: Some(_),
                ..
            }
        )
    }

    /// Holds DATA that arrived before the dial finished. Only the packet
    /// count is a hard cap, and a client that honours its credit stays under
    /// it; the bytes count against the byte budgets, which stop the client
    /// from being read rather than close the stream.
    fn queue_pending(
        &mut self,
        payload: Bytes,
        flow: &Arc<StreamFlow>,
        max_packets: usize,
    ) -> Result<(), u8> {
        let TcpStreamState::Connecting { pending } = &mut self.state else {
            return Ok(());
        };
        if flow.held_packets() >= max_packets {
            return Err(close_reason::CONN_THROTTLED);
        }
        let held = flow.hold(payload.len());
        pending.push(QueuedWrite {
            data: payload,
            _held: held,
        });
        Ok(())
    }
}

/// Seeded hash table for attacker-controlled stream identifiers.
pub(crate) struct StreamTable {
    items: HashMap<u32, TcpStreamSlot>,
}

impl StreamTable {
    pub(crate) fn new() -> Self {
        Self {
            items: HashMap::with_capacity(16),
        }
    }

    pub(crate) fn get_mut(&mut self, id: u32) -> Option<&mut TcpStreamSlot> {
        self.items.get_mut(&id)
    }

    /// The slot for `id`, only if it is still the stream `generation` opened.
    pub(crate) fn get_gen_mut(&mut self, id: u32, generation: u64) -> Option<&mut TcpStreamSlot> {
        self.items
            .get_mut(&id)
            .filter(|slot| slot.generation == generation)
    }

    pub(crate) fn contains(&self, id: u32) -> bool {
        self.items.contains_key(&id)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn insert(&mut self, id: u32, slot: TcpStreamSlot) {
        self.items.insert(id, slot);
    }

    pub(crate) fn remove(&mut self, id: u32) -> Option<TcpStreamSlot> {
        self.items.remove(&id)
    }

    /// Removes `id` only if it is still the stream `generation` opened.
    pub(crate) fn remove_gen(&mut self, id: u32, generation: u64) -> Option<TcpStreamSlot> {
        if self.get_gen_mut(id, generation).is_some() {
            self.items.remove(&id)
        } else {
            None
        }
    }

    pub(crate) fn drain(&mut self) -> impl Iterator<Item = (u32, TcpStreamSlot)> + '_ {
        self.items.drain()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_tcp_connect(
    stream_id: u32,
    generation: u64,
    hostname: String,
    port: u16,
    half_close: bool,
    activity: Arc<Activity>,
    ctx: ServerContext,
    egress: EgressSender,
    events: mpsc::Sender<TcpEvent>,
) -> AbortHandle {
    tokio::spawn(async move {
        if let Err(e) = ctx.policy.check(&hostname, port) {
            if let Some(rejections) = ctx.reject_log.admit() {
                warn!(stream_id, host = ?hostname, port, error = ?e.to_string(), rejections, "wisp tcp host policy reject");
            }
            wisp_reports::emit_report(
                wisp_reports::ReportErrorType::HostPolicyBlocked,
                wisp_reports::ReportInput {
                    context: Some(wisp_reports::ConnectionContext {
                        client_ip: Some(ctx.client_ip.clone()),
                        client_ip_hash: ctx.client_hash.clone(),
                        transport: Some(wisp_reports::Transport::Ws),
                        ..Default::default()
                    }),
                    hostname: Some(hostname.clone()),
                    port: Some(port),
                    stream_type: Some(wisp_reports::StreamType::Tcp),
                    wisp_close_code: Some(i32::from(close_reason::HOST_BLOCKED)),
                    ..Default::default()
                },
            );
            send_close(&egress, &ctx.cancel, stream_id, close_reason::HOST_BLOCKED).await;
            let _ = events
                .send(TcpEvent::Failed {
                    stream_id,
                    generation,
                })
                .await;
            return;
        }

        let connect_timeout =
            Duration::from_millis(ctx.options.connect_timeout_ms.unwrap_or(10_000).max(1));

        let connect_fut = async {
            if let Some(controller) = ctx.proxy_controller.as_ref() {
                controller
                    .connect_tcp(&hostname, port, ctx.options.force_proxy, &ctx.policy)
                    .await
                    .map(|(stream, _active)| stream)
                    .map_err(OpenFail::Proxy)
            } else if ctx.options.force_proxy {
                Err(OpenFail::Connect(ConnectError::ForceProxyWithoutController))
            } else {
                connect_checked_tcp(&hostname, port, &ctx.policy)
                    .await
                    .map_err(OpenFail::Connect)
            }
        };
        let upstream = match timeout(connect_timeout, connect_fut).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                if let Some(rejections) = ctx.reject_log.admit() {
                    warn!(stream_id, host = ?hostname, port, error = ?e.to_string(), rejections, "wisp tcp connect failed");
                }
                send_close(&egress, &ctx.cancel, stream_id, close_reason::CONN_REFUSED).await;
                let _ = events
                    .send(TcpEvent::Failed {
                        stream_id,
                        generation,
                    })
                    .await;
                return;
            }
            Err(_) => {
                send_close(&egress, &ctx.cancel, stream_id, close_reason::NO_RESPONSE).await;
                let _ = events
                    .send(TcpEvent::Failed {
                        stream_id,
                        generation,
                    })
                    .await;
                return;
            }
        };
        tune_tcp(&upstream);

        let (up_read, write) = upstream.into_split();
        let (gate_tx, gate_rx) = oneshot::channel();
        let reader = spawn_reader(
            stream_id,
            generation,
            up_read,
            half_close,
            gate_rx,
            activity,
            ctx,
            egress,
            events.clone(),
        );
        let _ = events
            .send(TcpEvent::Ready {
                stream_id,
                generation,
                write,
                reader,
                gate: gate_tx,
            })
            .await;
    })
    .abort_handle()
}

#[allow(clippy::too_many_arguments)]
fn spawn_reader(
    stream_id: u32,
    generation: u64,
    mut up_read: tokio::net::tcp::OwnedReadHalf,
    half_close: bool,
    gate: oneshot::Receiver<()>,
    activity: Arc<Activity>,
    ctx: ServerContext,
    egress: EgressSender,
    events: mpsc::Sender<TcpEvent>,
) -> ReaderHandle {
    let meter_tcp = ctx.tcp_byte_limiter.is_active();
    let idle = ctx
        .options
        .stream_idle_timeout_ms
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis);
    ReaderHandle(tokio::spawn(async move {
        // Nothing is read from upstream until the mux opens the gate. A gate
        // dropped unopened means the stream was torn down first.
        tokio::select! {
            _ = ctx.cancel.cancelled() => return,
            opened = gate => if opened.is_err() {
                return;
            },
        }
        activity.touch();
        let pool = read_buffer_pool();
        let mut eof = false;
        'read_loop: loop {
            // Nothing more is read from the upstream while the client's
            // egress queue, or the process budget, is full.
            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => break,
                room = egress.room() => if room.is_err() {
                    break;
                },
            }
            let mut buf = pool.take();
            if buf.data.capacity() < PACKET_HEADER_LEN + READ_CHUNK {
                buf.data
                    .reserve(PACKET_HEADER_LEN + READ_CHUNK - buf.data.capacity());
            }
            buf.data.resize(PACKET_HEADER_LEN, 0);
            tokio::select! {
                _ = ctx.cancel.cancelled() => break,
                _ = idle_wait(idle) => {
                    if activity.idle_for(idle) {
                        send_close(&egress, &ctx.cancel, stream_id, close_reason::TRANSFER_TIMEOUT).await;
                        break;
                    }
                }
                res = up_read.read_buf(&mut buf.data) => match res {
                    Ok(0) if half_close => {
                        eof = true;
                        break;
                    }
                    Ok(0) => {
                        send_close(&egress, &ctx.cancel, stream_id, close_reason::VOLUNTARY).await;
                        break;
                    }
                    Ok(mut n) => {
                        let mut peer_closed = false;
                        while buf.data.len() < PACKET_HEADER_LEN + READ_CHUNK {
                            let remaining = PACKET_HEADER_LEN + READ_CHUNK - buf.data.len();
                            let read_result = {
                                let mut limited = (&mut buf.data).limit(remaining);
                                up_read.try_read_buf(&mut limited)
                            };
                            match read_result {
                                Ok(0) => {
                                    peer_closed = true;
                                    break;
                                }
                                Ok(read) => n += read,
                                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                    break;
                                }
                                Err(error) => {
                                    warn!(stream_id, %error, "wisp tcp upstream read error");
                                    send_close(&egress, &ctx.cancel, stream_id, close_reason::NETWORK_ERROR).await;
                                    break 'read_loop;
                                }
                            }
                        }
                        activity.touch();
                        if meter_tcp
                            && !ctx.tcp_byte_limiter.is_allowed(n as u64)
                        {
                            warn!(stream_id, "wisp tcp upstream->client byte rate exceeded, closing stream");
                            send_close(&egress, &ctx.cancel, stream_id, close_reason::CONN_THROTTLED).await;
                            break;
                        }
                        write_data_header(stream_id, &mut buf.data);
                        let frame = if n < COPY_READS_BELOW {
                            let frame = Bytes::copy_from_slice(&buf.data);
                            drop(buf);
                            frame
                        } else {
                            Bytes::from_owner(buf)
                        };
                        let send_res = tokio::select! {
                            biased;
                            _ = ctx.cancel.cancelled() => break,
                            r = egress.send(WispMessage::Binary(frame)) => r,
                        };
                        if send_res.is_err() {
                            break;
                        }
                        if peer_closed && half_close {
                            eof = true;
                            break;
                        }
                        if peer_closed {
                            send_close(&egress, &ctx.cancel, stream_id, close_reason::VOLUNTARY).await;
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(stream_id, error = %e, "wisp tcp upstream read error");
                        send_close(&egress, &ctx.cancel, stream_id, close_reason::NETWORK_ERROR).await;
                        break;
                    }
                }
            }
        }
        // The stream stays open for writing, so its idle timeout still runs.
        if eof
            && events
                .send(TcpEvent::ReadEof {
                    stream_id,
                    generation,
                })
                .await
                .is_ok()
        {
            loop {
                tokio::select! {
                    _ = ctx.cancel.cancelled() => break,
                    _ = idle_wait(idle) => {
                        if activity.idle_for(idle) {
                            send_close(&egress, &ctx.cancel, stream_id, close_reason::TRANSFER_TIMEOUT).await;
                            break;
                        }
                    }
                }
            }
        }
        let _ = events
            .send(TcpEvent::ReaderDone {
                stream_id,
                generation,
            })
            .await;
    }))
}

pub(crate) enum WriteOutcome {
    Ok,
    /// Grant the client this much CONTINUE credit for the stream.
    SendContinue(u32),
    DropStream(u8),
}

/// Hard cap on the payloads one stream holds unwritten. A client that honours
/// its credit holds at most two windows (one granted, one still in flight).
fn write_queue_cap(ctx: &ServerContext) -> usize {
    let pending = usize::try_from(ctx.options.max_pending_packets_per_stream).unwrap_or(128);
    pending.clamp(1, 4096)
}

enum NbWrite {
    Done,
    Wrote(usize),
    Failed,
}

fn try_write_nonblock(write: &mut OwnedWriteHalf, buf: &[u8]) -> NbWrite {
    let mut written = 0;
    while written < buf.len() {
        match write.try_write(&buf[written..]) {
            Ok(0) => return NbWrite::Failed,
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return if written == 0 {
                    NbWrite::Wrote(0)
                } else {
                    NbWrite::Wrote(written)
                };
            }
            Err(_) => return NbWrite::Failed,
        }
    }
    NbWrite::Done
}

fn apply_inspection(
    state: &mut InspectionState,
    payload: Bytes,
    inspection_max: usize,
    ctx: &ServerContext,
    stream_id: u32,
) -> Result<Option<Bytes>, u8> {
    let ibuf = &mut state.buf;
    let remaining = inspection_max.saturating_sub(ibuf.len());
    let take = remaining.min(payload.len());
    ibuf.extend_from_slice(&payload[..take]);
    match state.inspector.feed(ibuf.as_ref(), &ctx.options) {
        InspectionDecision::Allow(_) => {
            let mut out = ibuf.split();
            if take < payload.len() {
                out.extend_from_slice(&payload[take..]);
            }
            Ok(Some(out.freeze()))
        }
        InspectionDecision::NeedMore => {
            if ibuf.len() >= inspection_max {
                return Err(close_reason::HOST_BLOCKED);
            }
            Ok(None)
        }
        InspectionDecision::Block { reason } => {
            if let Some(rejections) = ctx.reject_log.admit() {
                warn!(
                    stream_id,
                    ?reason,
                    rejections,
                    "wisp tcp protocol inspection blocked stream"
                );
            }
            Err(match reason {
                BlockReason::ProtocolNotAllowed
                | BlockReason::HostMismatch
                | BlockReason::H2cDisallowed
                | BlockReason::TlsWithoutAlpnDisallowed
                | BlockReason::QuicInitialDisallowed => close_reason::HOST_BLOCKED,
                BlockReason::BufferExhausted => close_reason::CLIENT_ERROR,
            })
        }
    }
}

fn grant_outcome(flow: &StreamFlow) -> WriteOutcome {
    flow.take_grant()
        .map_or(WriteOutcome::Ok, WriteOutcome::SendContinue)
}

/// The upstream took a payload: release what it held, or count it if it was
/// never held.
fn taken(flow: &StreamFlow, held: Option<HeldBytes>) {
    match held {
        Some(held) => drop(held),
        None => flow.note_written(),
    }
}

/// Mux-thread DATA path. Never awaits TCP: Connecting queues; Live
/// `try_write`s when the socket is idle and only enqueues on WouldBlock.
pub(crate) fn write_upstream(
    slot: &mut TcpStreamSlot,
    payload: Bytes,
    stream_id: u32,
    ctx: &ServerContext,
    egress: &EgressSender,
    events: &mpsc::Sender<TcpEvent>,
) -> WriteOutcome {
    slot.activity.touch();
    if matches!(slot.state, TcpStreamState::Connecting { .. }) {
        let flow = slot.flow_for(ctx);
        if let Err(reason) = slot.queue_pending(payload, &flow, write_queue_cap(ctx)) {
            return WriteOutcome::DropStream(reason);
        }
        return WriteOutcome::Ok;
    }
    write_live(slot, payload, None, stream_id, ctx, egress, events)
}

/// Writes one payload to a live stream. `held` is set when the payload was
/// already held while the stream was connecting.
fn write_live(
    slot: &mut TcpStreamSlot,
    payload: Bytes,
    held: Option<HeldBytes>,
    stream_id: u32,
    ctx: &ServerContext,
    egress: &EgressSender,
    events: &mpsc::Sender<TcpEvent>,
) -> WriteOutcome {
    if ctx.tcp_byte_limiter.is_active() && !ctx.tcp_byte_limiter.is_allowed(payload.len() as u64) {
        warn!(
            stream_id,
            "wisp tcp client->upstream byte rate exceeded, closing stream"
        );
        return WriteOutcome::DropStream(close_reason::CONN_THROTTLED);
    }

    let generation = slot.generation;
    let flow = slot.flow_for(ctx);
    let activity = slot.activity.clone();
    let TcpStreamState::Live {
        write,
        queued,
        inspection,
        ..
    } = &mut slot.state
    else {
        return WriteOutcome::Ok;
    };

    let payload = if let Some(state) = inspection.as_mut() {
        let inspection_max =
            usize::try_from(ctx.options.protocol_inspection_max_bytes).unwrap_or(usize::MAX);
        match apply_inspection(state, payload, inspection_max, ctx, stream_id) {
            Ok(Some(payload)) => {
                *inspection = None;
                if let Some(gate) = slot.gate.as_mut() {
                    gate.classified = true;
                    gate.release_if_ready();
                }
                payload
            }
            Ok(None) => {
                // The inspection buffer, capped at protocol_inspection_max_bytes,
                // took the bytes.
                taken(&flow, held);
                return grant_outcome(&flow);
            }
            Err(reason) => return WriteOutcome::DropStream(reason),
        }
    } else {
        payload
    };

    if let Some(write_half) = write.as_mut() {
        match try_write_nonblock(write_half, &payload) {
            NbWrite::Done => {
                taken(&flow, held);
                return grant_outcome(&flow);
            }
            NbWrite::Wrote(n) => {
                let rest = payload.slice(n..);
                let held = held.unwrap_or_else(|| flow.hold(rest.len()));
                let write_half = write.take().expect("write half present");
                *queued = Some(spawn_writer(
                    stream_id,
                    generation,
                    write_half,
                    QueuedWrite {
                        data: rest,
                        _held: held,
                    },
                    flow,
                    activity,
                    ctx.clone(),
                    egress.clone(),
                    events.clone(),
                    write_queue_cap(ctx),
                ));
                return WriteOutcome::Ok;
            }
            NbWrite::Failed => {
                return WriteOutcome::DropStream(close_reason::NETWORK_ERROR);
            }
        }
    }

    let Some(writer) = queued.as_ref() else {
        return WriteOutcome::DropStream(close_reason::NETWORK_ERROR);
    };
    let Some(tx) = writer.tx.as_ref() else {
        return WriteOutcome::DropStream(close_reason::NETWORK_ERROR);
    };
    let held = match held {
        Some(held) => held,
        None => {
            // Past two windows the client is ignoring its credit.
            if flow.held_packets() >= write_queue_cap(ctx) {
                return WriteOutcome::DropStream(close_reason::CONN_THROTTLED);
            }
            flow.hold(payload.len())
        }
    };
    match tx.try_send(QueuedWrite {
        data: payload,
        _held: held,
    }) {
        Ok(()) => WriteOutcome::Ok,
        Err(mpsc::error::TrySendError::Full(_)) => {
            WriteOutcome::DropStream(close_reason::CONN_THROTTLED)
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            WriteOutcome::DropStream(close_reason::NETWORK_ERROR)
        }
    }
}

/// Keep the write half in mux-owned state. A queued writer is allocated only
/// after the socket first reports backpressure.
pub(crate) async fn activate_writer(
    slot: &mut TcpStreamSlot,
    write: OwnedWriteHalf,
    reader: ReaderHandle,
    stream_id: u32,
    ctx: &ServerContext,
    egress: &EgressSender,
    events: &mpsc::Sender<TcpEvent>,
) -> WriteOutcome {
    let pending = match &mut slot.state {
        TcpStreamState::Connecting { pending, .. } => std::mem::take(pending),
        TcpStreamState::Live { .. } => {
            drop(write);
            reader.abort();
            return WriteOutcome::Ok;
        }
    };
    slot.state = TcpStreamState::Live {
        write: Some(write),
        queued: None,
        inspection: slot.inspected(ctx).then(|| InspectionState {
            buf: BytesMut::new(),
            inspector: Inspector::new(slot.host.as_deref()),
            timer: Some(spawn_inspection_timer(
                stream_id,
                slot.generation,
                ctx,
                events,
            )),
        }),
        reader,
    };
    for queued in pending {
        let QueuedWrite { data, _held: held } = queued;
        match write_live(slot, data, Some(held), stream_id, ctx, egress, events) {
            WriteOutcome::DropStream(reason) => return WriteOutcome::DropStream(reason),
            WriteOutcome::SendContinue(credit) => {
                if egress
                    .send(WispMessage::Binary(encode_continue(stream_id, credit)))
                    .await
                    .is_err()
                {
                    return WriteOutcome::DropStream(close_reason::NETWORK_ERROR);
                }
            }
            WriteOutcome::Ok => {}
        }
    }
    if slot.client_fin {
        return shutdown_upstream_write(slot).await;
    }
    WriteOutcome::Ok
}

/// Client FIN path. An idle write half is shut down here; a queued writer
/// loses its sender, so it shuts the half down after writing what it holds.
/// A connecting stream is shut down by [`activate_writer`] after its pending
/// DATA.
pub(crate) async fn shutdown_upstream_write(slot: &mut TcpStreamSlot) -> WriteOutcome {
    let TcpStreamState::Live {
        write,
        queued,
        inspection,
        ..
    } = &mut slot.state
    else {
        return WriteOutcome::Ok;
    };
    if inspection
        .as_ref()
        .is_some_and(|state| !state.buf.is_empty())
    {
        return WriteOutcome::DropStream(close_reason::HOST_BLOCKED);
    }
    if let Some(mut write_half) = write.take() {
        if write_half.shutdown().await.is_err() {
            return WriteOutcome::DropStream(close_reason::NETWORK_ERROR);
        }
        slot.write_shut = true;
        return WriteOutcome::Ok;
    }
    match queued.as_mut() {
        Some(writer) => {
            writer.tx = None;
            WriteOutcome::Ok
        }
        None => WriteOutcome::DropStream(close_reason::NETWORK_ERROR),
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_writer(
    stream_id: u32,
    generation: u64,
    mut write: OwnedWriteHalf,
    first: QueuedWrite,
    flow: Arc<StreamFlow>,
    activity: Arc<Activity>,
    ctx: ServerContext,
    egress: EgressSender,
    events: mpsc::Sender<TcpEvent>,
    queue_capacity: usize,
) -> QueuedWriter {
    let (tx, mut rx) = mpsc::channel::<QueuedWrite>(queue_capacity.max(1));
    let task = tokio::spawn(async move {
        let run = async {
            let mut batch = VecDeque::with_capacity(WRITE_BATCH_CAPACITY);
            batch.push_back(first);
            loop {
                while batch.len() < WRITE_BATCH_CAPACITY {
                    match rx.try_recv() {
                        Ok(queued) => batch.push_back(queued),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                write_batch_cancel(&mut write, &mut batch, &activity, &ctx.cancel)
                    .await
                    .map_err(|()| close_reason::NETWORK_ERROR)?;
                // Credit follows what the upstream has taken.
                if let Some(credit) = flow.take_grant() {
                    let sent = tokio::select! {
                        biased;
                        _ = ctx.cancel.cancelled() => return Ok(false),
                        r = egress.send(WispMessage::Binary(encode_continue(stream_id, credit))) => r,
                    };
                    if sent.is_err() {
                        return Ok(false);
                    }
                }
                let queued = tokio::select! {
                    biased;
                    _ = ctx.cancel.cancelled() => return Ok(false),
                    queued = rx.recv() => queued,
                };
                let Some(queued) = queued else {
                    break;
                };
                batch.push_back(queued);
            }
            // A closed channel is the client's FIN, queued behind its DATA.
            write
                .shutdown()
                .await
                .map_err(|_| close_reason::NETWORK_ERROR)?;
            Ok(true)
        };

        match run.await {
            Ok(true) => {
                let _ = events
                    .send(TcpEvent::WriteShut {
                        stream_id,
                        generation,
                    })
                    .await;
            }
            Ok(false) => {
                let _ = events
                    .send(TcpEvent::WriterDone {
                        stream_id,
                        generation,
                    })
                    .await;
            }
            Err(reason) => {
                send_close(&egress, &ctx.cancel, stream_id, reason).await;
                let _ = events
                    .send(TcpEvent::WriterDone {
                        stream_id,
                        generation,
                    })
                    .await;
            }
        }
    });
    QueuedWriter { tx: Some(tx), task }
}

/// Starts the clock on a stream's protocol inspection. Like WebTransport, an
/// unset `protocol_inspection_timeout_ms` means the 10 s default, never no limit.
fn spawn_inspection_timer(
    stream_id: u32,
    generation: u64,
    ctx: &ServerContext,
    events: &mpsc::Sender<TcpEvent>,
) -> JoinHandle<()> {
    let limit = Duration::from_millis(
        ctx.options
            .protocol_inspection_timeout_ms
            .unwrap_or(10_000)
            .max(1),
    );
    let events = events.clone();
    tokio::spawn(async move {
        tokio::time::sleep(limit).await;
        let _ = events
            .send(TcpEvent::InspectionTimeout {
                stream_id,
                generation,
            })
            .await;
    })
}

/// Tears down every task a slot owns. Dropping the slot aborts the reader
/// and the inspection timer; the dial and the writer are aborted here.
pub(crate) fn drop_slot(mut slot: TcpStreamSlot) {
    if let Some(dial) = slot.dial.take() {
        dial.abort();
    }
    if let TcpStreamState::Live { queued, reader, .. } = &slot.state {
        if let Some(writer) = queued {
            writer.task.abort();
        }
        reader.abort();
    }
}

fn advance_write_batch(batch: &mut VecDeque<QueuedWrite>, mut written: usize) {
    while written > 0 {
        let Some(front) = batch.front_mut() else {
            return;
        };
        if written < front.data.len() {
            front.data = front.data.slice(written..);
            return;
        }
        written -= front.data.len();
        batch.pop_front();
    }
}

async fn write_batch_cancel(
    write: &mut OwnedWriteHalf,
    batch: &mut VecDeque<QueuedWrite>,
    activity: &Activity,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<(), ()> {
    while !batch.is_empty() {
        let slice_count = batch.len().min(WRITE_BATCH_CAPACITY);
        let slices: [IoSlice<'_>; WRITE_BATCH_CAPACITY] = std::array::from_fn(|index| {
            batch
                .get(index)
                .map_or_else(|| IoSlice::new(&[]), |queued| IoSlice::new(&queued.data))
        });
        let slices = &slices[..slice_count];
        match write.try_write_vectored(slices) {
            Ok(0) => return Err(()),
            Ok(n) => {
                activity.touch();
                advance_write_batch(batch, n);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let written = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Err(()),
                    r = write.write_vectored(slices) => r.map_err(|_| ()),
                }?;
                if written == 0 {
                    return Err(());
                }
                activity.touch();
                advance_write_batch(batch, written);
            }
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

pub(crate) async fn send_close(
    egress: &EgressSender,
    cancel: &tokio_util::sync::CancellationToken,
    stream_id: u32,
    reason: u8,
) {
    let _ = tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(()),
        r = egress.send(WispMessage::Binary(encode_close(stream_id, reason))) => r.map_err(|_| ()),
    };
}

async fn idle_wait(idle: Option<Duration>) {
    match idle {
        Some(d) => tokio::time::sleep(d / 2).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_config::WispServerOptions;
    use wisp_dos::UNLIMITED;
    use wisp_wisp::{encode_data, parse_packet, WispPacket};

    #[test]
    fn in_place_header_roundtrips_like_encode_data() {
        let payload = b"relay-payload";
        let mut buf = BytesMut::with_capacity(PACKET_HEADER_LEN + payload.len());
        buf.resize(PACKET_HEADER_LEN, 0);
        buf.extend_from_slice(payload);
        write_data_header(42, &mut buf);
        match parse_packet(buf.freeze()).unwrap() {
            WispPacket::Data(d) => {
                assert_eq!(d.stream_id, 42);
                assert_eq!(&d.payload[..], payload);
            }
            other => panic!("got {other:?}"),
        }
        assert_eq!(
            encode_data(42, payload),
            encode_data_via_header(42, payload)
        );
    }

    fn encode_data_via_header(stream_id: u32, payload: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(PACKET_HEADER_LEN + payload.len());
        buf.resize(PACKET_HEADER_LEN, 0);
        buf.extend_from_slice(payload);
        write_data_header(stream_id, &mut buf);
        buf.freeze()
    }

    #[test]
    fn unlimited_tcp_limits_are_inactive() {
        let opts = WispServerOptions {
            max_tcp_bytes_per_connection_per_second: UNLIMITED,
            max_tcp_bytes_per_ip_per_second: UNLIMITED,
            ..WispServerOptions::default()
        };
        assert!(!wisp_dos::tcp_byte_limits_active(&opts));
    }

    #[test]
    fn finite_tcp_limit_is_active() {
        let opts = WispServerOptions {
            max_tcp_bytes_per_connection_per_second: 1024,
            max_tcp_bytes_per_ip_per_second: UNLIMITED,
            ..WispServerOptions::default()
        };
        assert!(wisp_dos::tcp_byte_limits_active(&opts));
    }

    #[test]
    fn stream_table_handles_sparse_ids() {
        let mut t = StreamTable::new();
        t.insert(1, TcpStreamSlot::connecting());
        t.insert(2, TcpStreamSlot::connecting());
        assert!(t.get_mut(2).is_some());
        assert!(t.get_mut(2).is_some());
        assert!(t.contains(1));
        t.remove(1);
        assert!(!t.contains(1));
        assert!(t.get_mut(2).is_some());
    }

    fn test_flow(buffer_size: u32, threshold: u32, soft_bytes: usize) -> Arc<StreamFlow> {
        StreamFlow::new(
            Budgets::for_connection(1 << 20),
            buffer_size,
            threshold,
            soft_bytes,
        )
    }

    #[test]
    fn credit_is_granted_as_the_upstream_takes_payloads() {
        let flow = test_flow(8, 4, 1 << 20);
        let held: Vec<HeldBytes> = (0..6).map(|_| flow.hold(10)).collect();
        assert_eq!(flow.take_grant(), None, "nothing written yet");
        let mut held = held.into_iter();
        for _ in 0..3 {
            drop(held.next());
        }
        assert_eq!(flow.take_grant(), None, "three of four written");
        flow.note_written();
        // Four written, three still held: the window has five slots left.
        assert_eq!(flow.take_grant(), Some(5));
        assert_eq!(flow.take_grant(), None, "the count restarts after a grant");
    }

    #[test]
    fn credit_waits_while_the_stream_holds_too_many_bytes() {
        let flow = test_flow(8, 1, 100);
        let big = flow.hold(150);
        flow.note_written();
        assert_eq!(flow.take_grant(), None, "150 held bytes exceed 100");
        drop(big);
        assert_eq!(flow.take_grant(), Some(8));
    }

    #[test]
    fn held_bytes_count_against_the_connection_budget() {
        let budgets = Budgets::for_connection(100);
        let flow = StreamFlow::new(budgets.clone(), 8, 4, 1 << 20);
        let first = flow.hold(60);
        let second = flow.hold(60);
        assert_eq!(budgets.connection_used(), 120);
        assert!(!budgets.has_room());
        drop(first);
        drop(second);
        assert_eq!(budgets.connection_used(), 0);
    }

    #[test]
    fn connect_addrs_try_ipv4_before_ipv6() {
        let v6 = SocketAddr::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], 443));
        let v4 = SocketAddr::from(([1, 2, 3, 4], 443));
        let v6_later = SocketAddr::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0, 2], 443));
        let v4_later = SocketAddr::from(([1, 2, 3, 5], 443));
        let mut addrs = vec![v6, v4, v6_later];
        interleave_families(&mut addrs, false);
        assert_eq!(addrs, vec![v4, v6, v6_later]);
        let mut addrs = vec![v6, v4, v6_later, v4_later];
        interleave_families(&mut addrs, false);
        assert_eq!(addrs, vec![v4, v6, v4_later, v6_later]);
        let mut addrs = vec![v4, v4_later, v6];
        interleave_families(&mut addrs, true);
        assert_eq!(addrs, vec![v6, v4, v4_later]);
    }

    #[tokio::test]
    async fn blackholed_first_address_does_not_starve_the_next() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        // TEST-NET-1 is not routed, so this attempt hangs until its timeout.
        let dead = SocketAddr::from(([192, 0, 2, 1], live.port()));
        let started = Instant::now();
        let stream = dial_addrs(&[dead, live], Duration::from_secs(5))
            .await
            .expect("the second address connects");
        assert_eq!(stream.peer_addr().unwrap(), live);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the second attempt starts after the stagger, not after the first times out"
        );
    }

    #[tokio::test]
    async fn refused_dials_are_retried_a_bounded_number_of_times() {
        use tokio::net::TcpListener;
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let started = Instant::now();
        let err = dial_addrs(&[addr], Duration::from_secs(1))
            .await
            .expect_err("nothing listens");
        assert!(
            matches!(err, ConnectError::Tcp(e) if e.kind() == std::io::ErrorKind::ConnectionRefused)
        );
        // Three rounds with 50 ms and 200 ms pauses, not eight with backoff.
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn resolve_checked_rejects_numeric_aliases_and_blocked_addresses() {
        let policy = HostPolicy::from_options(&WispServerOptions {
            allow_direct_ip: false,
            ..WispServerOptions::default()
        });
        for host in ["16843009", "0x01010101", "1.1.1", "0177.0.0.1"] {
            assert!(
                matches!(
                    resolve_checked(host, 443, &policy).await,
                    Err(ConnectError::Policy(ProxyError::InvalidHost))
                ),
                "{host}"
            );
        }
        let policy = HostPolicy::from_options(&WispServerOptions {
            allow_direct_ip: true,
            ip_blacklist: Some(vec!["203.0.113.0/24".to_owned()]),
            ..WispServerOptions::default()
        });
        assert!(matches!(
            resolve_checked("203.0.113.9", 443, &policy).await,
            Err(ConnectError::Policy(ProxyError::HostBlocked(_)))
        ));
    }

    #[test]
    fn connecting_queue_has_packet_cap_but_no_byte_cap() {
        let mut slot = TcpStreamSlot::connecting();
        let flow = test_flow(8, 4, 4);
        assert!(slot
            .queue_pending(Bytes::from_static(b"larger than the soft cap"), &flow, 2)
            .is_ok());
        assert!(slot
            .queue_pending(Bytes::from_static(b"2"), &flow, 2)
            .is_ok());
        assert!(slot
            .queue_pending(Bytes::from_static(b"3"), &flow, 2)
            .is_err());
    }

    #[tokio::test]
    async fn resolve_checked_rejects_loopback_when_disallowed() {
        let policy = HostPolicy::from_options(&WispServerOptions {
            allow_loopback_ips: false,
            allow_private_ips: false,
            allow_direct_ip: true,
            port_whitelist: None,
            ..WispServerOptions::default()
        });
        let err = resolve_checked("127.0.0.1", 9, &policy)
            .await
            .expect_err("loopback must be rejected");
        assert!(
            matches!(err, ConnectError::Policy(ProxyError::LoopbackBlocked(_))),
            "expected typed policy error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn connect_retries_until_listener_accepts() {
        use tokio::net::TcpListener;
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let policy = HostPolicy::from_options(&WispServerOptions {
            allow_loopback_ips: true,
            allow_private_ips: true,
            allow_direct_ip: true,
            port_whitelist: None,
            ..WispServerOptions::default()
        });
        let listener = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let bound = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            let (sock, _) = bound.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(sock);
        });
        let stream = connect_checked_tcp("127.0.0.1", port, &policy)
            .await
            .expect("connect_checked_tcp must retry past ConnectionRefused");
        drop(stream);
        let _ = listener.await;
    }

    #[tokio::test]
    async fn connect_checked_tcp_rejects_blocked_port() {
        let policy = HostPolicy::from_options(&WispServerOptions {
            allow_loopback_ips: true,
            allow_private_ips: true,
            allow_direct_ip: true,
            port_whitelist: Some(vec![80, 443]),
            ..WispServerOptions::default()
        });
        // The dial path checks the whole policy, port included, not only the
        // resolved addresses.
        assert!(matches!(
            resolve_checked("127.0.0.1", 9, &policy).await,
            Err(ConnectError::Policy(ProxyError::PortBlocked(9)))
        ));
        let addrs = resolve_checked("127.0.0.1", 443, &policy)
            .await
            .expect("loopback allowed");
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }

    #[test]
    fn stream_table_ignores_a_stale_generation() {
        let mut t = StreamTable::new();
        t.insert(5, TcpStreamSlot::connecting_for(1, None));
        assert!(t.remove(5).is_some());
        t.insert(5, TcpStreamSlot::connecting_for(2, None));
        assert!(t.get_gen_mut(5, 1).is_none());
        assert!(t.remove_gen(5, 1).is_none());
        assert!(t.contains(5), "the reused ID still holds the new stream");
        assert!(t.get_gen_mut(5, 2).is_some());
        assert!(t.remove_gen(5, 2).is_some());
        assert!(!t.contains(5));
    }

    #[test]
    fn upstream_gate_opens_only_after_confirmation_and_classification() {
        let mut slot = TcpStreamSlot::connecting();
        let (tx, mut rx) = oneshot::channel();
        slot.set_gate(tx, true);
        slot.confirm_open();
        assert!(rx.try_recv().is_err(), "unclassified stream stays gated");
        let gate = slot.gate.as_mut().unwrap();
        gate.classified = true;
        gate.release_if_ready();
        assert!(rx.try_recv().is_ok());

        let mut slot = TcpStreamSlot::connecting();
        let (tx, mut rx) = oneshot::channel();
        slot.set_gate(tx, false);
        assert!(rx.try_recv().is_err(), "unconfirmed stream stays gated");
        slot.confirm_open();
        assert!(rx.try_recv().is_ok());
    }
}

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

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::warn;
use wisp_config::WispServerOptions;
use wisp_inspect::{inspect, BlockReason, InspectionDecision};
use wisp_proxy::{HostPolicy, ProxyError};
use wisp_wisp::{
    close_reason, encode_close, encode_continue, write_data_header, PACKET_HEADER_LEN,
};

use crate::connection::{EgressSender, ServerContext, WispMessage};
use crate::proxy_control::ProxyConnectError;

const READ_CHUNK: usize = 128 * 1024;
const READ_BUFFER_POOL_CAPACITY: usize = 256;
const WRITE_BATCH_CAPACITY: usize = 64;
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

pub(crate) async fn resolve_checked(
    host: &str,
    port: u16,
    policy: &HostPolicy,
) -> Result<Vec<SocketAddr>, ConnectError> {
    let addrs: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|source| ConnectError::DnsLookup {
            host: host.to_owned(),
            source,
        })?
        .collect();
    if addrs.is_empty() {
        return Err(ConnectError::NoAddresses(host.to_owned()));
    }
    for sa in &addrs {
        policy.check_ip(sa.ip())?;
    }
    Ok(addrs)
}

fn connect_error_is_retryable(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::AddrInUse
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

/// A blackholed IPv6 route never returns, and the dial budget is one timeout
/// for the whole attempt. Trying IPv4 first reaches a working A record instead
/// of spending that budget on the AAAA answer.
fn prefer_ipv4(addrs: &mut [SocketAddr]) {
    addrs.sort_by_key(|sa| sa.is_ipv6());
}

pub(crate) async fn connect_checked_tcp(
    host: &str,
    port: u16,
    policy: &HostPolicy,
) -> Result<TcpStream, ConnectError> {
    let mut addrs = resolve_checked(host, port, policy).await?;
    prefer_ipv4(&mut addrs);
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..8u32 {
        for sa in &addrs {
            match TcpStream::connect(*sa).await {
                Ok(s) => {
                    tune_tcp(&s);
                    return Ok(s);
                }
                Err(e) => {
                    let retry = connect_error_is_retryable(&e);
                    last = Some(e);
                    if !retry {
                        continue;
                    }
                }
            }
        }
        if attempt + 1 < 8 {
            tokio::time::sleep(Duration::from_millis(1 << attempt.min(4))).await;
        }
    }
    Err(ConnectError::Tcp(last.unwrap_or_else(|| {
        std::io::Error::other("no address connected")
    })))
}

pub(crate) fn tune_tcp(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(TCP_SOCKET_BUF);
    let _ = sock.set_send_buffer_size(TCP_SOCKET_BUF);
}

pub(crate) enum TcpEvent {
    Ready {
        stream_id: u32,
        write: OwnedWriteHalf,
        reader: JoinHandle<()>,
    },
    Failed {
        stream_id: u32,
    },
    ReaderDone {
        stream_id: u32,
    },
    WriterDone {
        stream_id: u32,
    },
    ReadEof {
        stream_id: u32,
    },
    WriteShut {
        stream_id: u32,
    },
}

struct QueuedWrite {
    data: Bytes,
    _permit: OwnedSemaphorePermit,
}

pub(crate) struct QueuedWriter {
    tx: Option<mpsc::Sender<QueuedWrite>>,
    byte_budget: Arc<Semaphore>,
    task: JoinHandle<()>,
}

pub(crate) enum TcpStreamState {
    Connecting {
        pending: Vec<Bytes>,
        pending_bytes: usize,
    },
    Live {
        write: Option<OwnedWriteHalf>,
        queued: Option<QueuedWriter>,
        inspection_buf: Option<BytesMut>,
        reader: JoinHandle<()>,
    },
}

pub(crate) struct TcpStreamSlot {
    pub state: TcpStreamState,
    packets_since_continue: u32,
    /// The client sent FIN; no more DATA is valid.
    pub client_fin: bool,
    /// The upstream write half has been shut down.
    pub write_shut: bool,
    /// The upstream read half hit EOF.
    pub upstream_eof: bool,
}

impl TcpStreamSlot {
    pub(crate) fn connecting() -> Self {
        Self {
            state: TcpStreamState::Connecting {
                pending: Vec::new(),
                pending_bytes: 0,
            },
            packets_since_continue: 0,
            client_fin: false,
            write_shut: false,
            upstream_eof: false,
        }
    }

    /// Both directions are finished and the stream can be released.
    pub(crate) fn finished(&self) -> bool {
        self.write_shut && self.upstream_eof
    }

    pub(crate) fn queue_pending(
        &mut self,
        payload: Bytes,
        max_packets: usize,
        max_bytes: usize,
    ) -> Result<(), u8> {
        let TcpStreamState::Connecting {
            pending,
            pending_bytes,
        } = &mut self.state
        else {
            return Ok(());
        };
        let add = payload.len();
        if pending.len() >= max_packets || pending_bytes.saturating_add(add) > max_bytes {
            return Err(close_reason::CONN_THROTTLED);
        }
        pending.push(payload);
        *pending_bytes += add;
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

    pub(crate) fn contains(&self, id: u32) -> bool {
        self.items.contains_key(&id)
    }

    pub(crate) fn insert(&mut self, id: u32, slot: TcpStreamSlot) {
        self.items.insert(id, slot);
    }

    pub(crate) fn remove(&mut self, id: u32) -> Option<TcpStreamSlot> {
        self.items.remove(&id)
    }

    pub(crate) fn drain(&mut self) -> impl Iterator<Item = (u32, TcpStreamSlot)> + '_ {
        self.items.drain()
    }
}

pub(crate) fn spawn_tcp_connect(
    stream_id: u32,
    hostname: String,
    port: u16,
    half_close: bool,
    ctx: ServerContext,
    egress: EgressSender,
    events: mpsc::Sender<TcpEvent>,
) {
    tokio::spawn(async move {
        if let Err(e) = ctx.policy.check(&hostname, port) {
            warn!(stream_id, %hostname, port, error = %e, "wisp tcp host policy reject");
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
            let _ = events.send(TcpEvent::Failed { stream_id }).await;
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
                warn!(stream_id, %hostname, port, error = %e, "wisp tcp connect failed");
                send_close(&egress, &ctx.cancel, stream_id, close_reason::CONN_REFUSED).await;
                let _ = events.send(TcpEvent::Failed { stream_id }).await;
                return;
            }
            Err(_) => {
                send_close(&egress, &ctx.cancel, stream_id, close_reason::NO_RESPONSE).await;
                let _ = events.send(TcpEvent::Failed { stream_id }).await;
                return;
            }
        };
        tune_tcp(&upstream);

        let (up_read, write) = upstream.into_split();
        let reader = spawn_reader(stream_id, up_read, half_close, ctx, egress, events.clone());
        let _ = events
            .send(TcpEvent::Ready {
                stream_id,
                write,
                reader,
            })
            .await;
    });
}

fn spawn_reader(
    stream_id: u32,
    mut up_read: tokio::net::tcp::OwnedReadHalf,
    half_close: bool,
    ctx: ServerContext,
    egress: EgressSender,
    events: mpsc::Sender<TcpEvent>,
) -> JoinHandle<()> {
    let meter_tcp = ctx.tcp_byte_limiter.is_active();
    let idle = ctx
        .options
        .stream_idle_timeout_ms
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis);
    let start = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));
    tokio::spawn(async move {
        let pool = read_buffer_pool();
        let mut eof = false;
        'read_loop: loop {
            let mut buf = pool.take();
            if buf.data.capacity() < PACKET_HEADER_LEN + READ_CHUNK {
                buf.data
                    .reserve(PACKET_HEADER_LEN + READ_CHUNK - buf.data.capacity());
            }
            buf.data.resize(PACKET_HEADER_LEN, 0);
            tokio::select! {
                _ = ctx.cancel.cancelled() => break,
                _ = idle_wait(idle) => {
                    if idle_exceeded(&last_activity, start, idle) {
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
                        touch(&last_activity, start);
                        if meter_tcp
                            && !ctx.tcp_byte_limiter.is_allowed(n as u64)
                        {
                            warn!(stream_id, "wisp tcp upstream->client byte rate exceeded, closing stream");
                            send_close(&egress, &ctx.cancel, stream_id, close_reason::CONN_THROTTLED).await;
                            break;
                        }
                        write_data_header(stream_id, &mut buf.data);
                        let frame = Bytes::from_owner(buf);
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
        if eof && events.send(TcpEvent::ReadEof { stream_id }).await.is_ok() {
            loop {
                tokio::select! {
                    _ = ctx.cancel.cancelled() => break,
                    _ = idle_wait(idle) => {
                        if idle_exceeded(&last_activity, start, idle) {
                            send_close(&egress, &ctx.cancel, stream_id, close_reason::TRANSFER_TIMEOUT).await;
                            break;
                        }
                    }
                }
            }
        }
        let _ = events.send(TcpEvent::ReaderDone { stream_id }).await;
    })
}

pub(crate) enum WriteOutcome {
    Ok,
    SendContinue,
    DropStream(u8),
}

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
    ibuf: &mut BytesMut,
    payload: Bytes,
    inspection_max: usize,
    options: &WispServerOptions,
    stream_id: u32,
) -> Result<Option<Bytes>, u8> {
    let remaining = inspection_max.saturating_sub(ibuf.len());
    let take = remaining.min(payload.len());
    ibuf.extend_from_slice(&payload[..take]);
    match inspect(ibuf.as_ref(), options) {
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
            warn!(
                stream_id,
                ?reason,
                "wisp tcp protocol inspection blocked stream"
            );
            Err(match reason {
                BlockReason::ProtocolNotAllowed
                | BlockReason::H2cDisallowed
                | BlockReason::TlsWithoutAlpnDisallowed
                | BlockReason::QuicInitialDisallowed => close_reason::HOST_BLOCKED,
                BlockReason::BufferExhausted => close_reason::CLIENT_ERROR,
            })
        }
    }
}

fn accepted_packet(counter: &mut u32, threshold: u32) -> WriteOutcome {
    *counter = counter.saturating_add(1);
    if *counter >= threshold {
        *counter = 0;
        WriteOutcome::SendContinue
    } else {
        WriteOutcome::Ok
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
    if matches!(slot.state, TcpStreamState::Connecting { .. }) {
        let max_packets = write_queue_cap(ctx);
        let max_pending =
            usize::try_from(ctx.options.max_pending_bytes_per_stream).unwrap_or(usize::MAX);
        if let Err(reason) = slot.queue_pending(payload, max_packets, max_pending) {
            return WriteOutcome::DropStream(reason);
        }
        return WriteOutcome::Ok;
    }

    if ctx.tcp_byte_limiter.is_active() && !ctx.tcp_byte_limiter.is_allowed(payload.len() as u64) {
        warn!(
            stream_id,
            "wisp tcp client->upstream byte rate exceeded, closing stream"
        );
        return WriteOutcome::DropStream(close_reason::CONN_THROTTLED);
    }

    let TcpStreamState::Live {
        write,
        queued,
        inspection_buf,
        ..
    } = &mut slot.state
    else {
        return WriteOutcome::Ok;
    };

    let payload = if let Some(buffer) = inspection_buf.as_mut() {
        let inspection_max =
            usize::try_from(ctx.options.protocol_inspection_max_bytes).unwrap_or(usize::MAX);
        match apply_inspection(buffer, payload, inspection_max, &ctx.options, stream_id) {
            Ok(Some(payload)) => {
                *inspection_buf = None;
                payload
            }
            Ok(None) => {
                return accepted_packet(
                    &mut slot.packets_since_continue,
                    ctx.server_options.continue_threshold,
                );
            }
            Err(reason) => return WriteOutcome::DropStream(reason),
        }
    } else {
        payload
    };

    if let Some(write_half) = write.as_mut() {
        match try_write_nonblock(write_half, &payload) {
            NbWrite::Done => {
                return accepted_packet(
                    &mut slot.packets_since_continue,
                    ctx.server_options.continue_threshold,
                );
            }
            NbWrite::Wrote(n) => {
                let rest = payload.slice(n..);
                let write_half = write.take().expect("write half present");
                let Some(writer) = spawn_writer(
                    stream_id,
                    write_half,
                    rest,
                    ctx.clone(),
                    egress.clone(),
                    events.clone(),
                    write_queue_cap(ctx),
                ) else {
                    return WriteOutcome::DropStream(close_reason::NETWORK_ERROR);
                };
                *queued = Some(writer);
                return accepted_packet(
                    &mut slot.packets_since_continue,
                    ctx.server_options.continue_threshold,
                );
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
    let permit_count = u32::try_from(payload.len().max(1)).unwrap_or(u32::MAX);
    let Ok(permit) = writer
        .byte_budget
        .clone()
        .try_acquire_many_owned(permit_count)
    else {
        return WriteOutcome::DropStream(close_reason::CONN_THROTTLED);
    };
    match tx.try_send(QueuedWrite {
        data: payload,
        _permit: permit,
    }) {
        Ok(()) => accepted_packet(
            &mut slot.packets_since_continue,
            ctx.server_options.continue_threshold,
        ),
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
    reader: JoinHandle<()>,
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
        inspection_buf: ctx.options.protocol_inspection.then(BytesMut::new),
        reader,
    };
    for payload in pending {
        match write_upstream(slot, payload, stream_id, ctx, egress, events) {
            WriteOutcome::DropStream(reason) => return WriteOutcome::DropStream(reason),
            WriteOutcome::SendContinue => {
                if egress
                    .send(WispMessage::Binary(encode_continue(
                        stream_id,
                        ctx.server_options.buffer_size,
                    )))
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
        inspection_buf,
        ..
    } = &mut slot.state
    else {
        return WriteOutcome::Ok;
    };
    if inspection_buf
        .as_ref()
        .is_some_and(|buffer| !buffer.is_empty())
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

fn spawn_writer(
    stream_id: u32,
    mut write: OwnedWriteHalf,
    first: Bytes,
    ctx: ServerContext,
    egress: EgressSender,
    events: mpsc::Sender<TcpEvent>,
    queue_capacity: usize,
) -> Option<QueuedWriter> {
    let byte_capacity = usize::try_from(ctx.options.max_pending_bytes_per_stream)
        .unwrap_or(usize::MAX)
        .min(u32::MAX as usize);
    let byte_budget = Arc::new(Semaphore::new(byte_capacity));
    let first_permits = u32::try_from(first.len().max(1)).ok()?;
    let permit = byte_budget
        .clone()
        .try_acquire_many_owned(first_permits)
        .ok()?;
    let (tx, mut rx) = mpsc::channel::<QueuedWrite>(queue_capacity);
    let task = tokio::spawn(async move {
        let run = async {
            let mut batch = VecDeque::with_capacity(WRITE_BATCH_CAPACITY);
            batch.push_back(QueuedWrite {
                data: first,
                _permit: permit,
            });
            loop {
                while batch.len() < WRITE_BATCH_CAPACITY {
                    match rx.try_recv() {
                        Ok(queued) => batch.push_back(queued),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                write_batch_cancel(&mut write, &mut batch, &ctx.cancel)
                    .await
                    .map_err(|()| close_reason::NETWORK_ERROR)?;
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
                let _ = events.send(TcpEvent::WriteShut { stream_id }).await;
            }
            Ok(false) => {
                let _ = events.send(TcpEvent::WriterDone { stream_id }).await;
            }
            Err(reason) => {
                send_close(&egress, &ctx.cancel, stream_id, reason).await;
                let _ = events.send(TcpEvent::WriterDone { stream_id }).await;
            }
        }
    });
    Some(QueuedWriter {
        tx: Some(tx),
        byte_budget,
        task,
    })
}

pub(crate) fn drop_slot(slot: TcpStreamSlot) {
    if let TcpStreamState::Live { queued, reader, .. } = slot.state {
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
            Ok(n) => advance_write_batch(batch, n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let written = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Err(()),
                    r = write.write_vectored(slices) => r.map_err(|_| ()),
                }?;
                if written == 0 {
                    return Err(());
                }
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

fn touch(last: &AtomicU64, start: Instant) {
    last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
}

fn idle_exceeded(last: &AtomicU64, start: Instant, idle: Option<Duration>) -> bool {
    let Some(idle) = idle else {
        return false;
    };
    let elapsed = start.elapsed().as_millis() as u64;
    elapsed.saturating_sub(last.load(Ordering::Relaxed)) >= idle.as_millis() as u64
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

    #[test]
    fn continue_threshold_counts_packets() {
        let mut packets = 0;
        for _ in 0..3 {
            assert!(matches!(accepted_packet(&mut packets, 4), WriteOutcome::Ok));
        }
        assert!(matches!(
            accepted_packet(&mut packets, 4),
            WriteOutcome::SendContinue
        ));
        assert_eq!(packets, 0);
    }

    #[test]
    fn connecting_queue_has_independent_byte_cap() {
        let mut slot = TcpStreamSlot::connecting();
        assert!(slot
            .queue_pending(Bytes::from_static(b"1234"), 2, 4)
            .is_ok());
        assert!(slot.queue_pending(Bytes::from_static(b"5"), 2, 4).is_err());
    }

    #[test]
    fn connect_addrs_try_ipv4_before_ipv6() {
        let v6 = SocketAddr::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], 443));
        let v4 = SocketAddr::from(([1, 2, 3, 4], 443));
        let v6_later = SocketAddr::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0, 2], 443));
        let mut addrs = vec![v6, v4, v6_later];
        prefer_ipv4(&mut addrs);
        assert_eq!(addrs[0], v4);
        assert!(addrs[1].is_ipv6());
        assert!(addrs[2].is_ipv6());
        assert_eq!(addrs[1], v6);
        assert_eq!(addrs[2], v6_later);
    }

    #[test]
    fn connecting_queue_has_packet_cap() {
        let mut slot = TcpStreamSlot::connecting();
        assert!(slot.queue_pending(Bytes::from_static(b"1"), 1, 4).is_ok());
        assert!(slot.queue_pending(Bytes::from_static(b"2"), 1, 4).is_err());
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
        let addrs = resolve_checked("127.0.0.1", 9, &policy)
            .await
            .expect("loopback allowed");
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }
}

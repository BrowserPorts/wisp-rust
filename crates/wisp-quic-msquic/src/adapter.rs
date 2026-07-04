//! Concrete msquic↔async adapter feeding `h3::quic::Connection<Bytes>`.
//!
//! ## Strategy
//!
//! msquic delivers callbacks on internal worker threads. We turn that into an
//! async surface by:
//!
//! 1. Per-stream registry: a [`DashMap`] keyed by `HQUIC` (the msquic stream
//!    handle, treated as opaque). Each entry owns the channel halves that
//!    fan `QUIC_STREAM_EVENT_RECEIVE` payloads into an async reader and
//!    forwards async writes to `MsQuic->StreamSend`.
//! 2. Per-connection mpsc pair: one channel for inbound bidi streams, one
//!    for inbound uni streams. h3 polls them separately
//!    (`poll_accept_bidi` vs `poll_accept_recv`), so we keep them split at
//!    the source.
//! 3. A datagram channel: connection callbacks for `DATAGRAM_RECEIVED` push
//!    into a [`tokio::sync::mpsc::UnboundedSender`]; the
//!    `RecvDatagramHandler` impl pops.
//!
//! ## h3 integration
//!
//! [`MsQuicConnection`] implements `h3::quic::Connection<Bytes>` plus
//! `h3-datagram`'s `DatagramConnectionExt<Bytes>` so it can drive
//! `h3-webtransport::server::WebTransportSession`.

#![allow(clippy::module_name_repetitions)]

use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use h3::error::Code;
use h3::quic::{
    self, BidiStream as H3BidiStream, ConnectionErrorIncoming, OpenStreams as H3OpenStreams,
    RecvStream as H3RecvStream, SendStream as H3SendStream,
    SendStreamUnframed as H3SendStreamUnframed, StreamErrorIncoming, StreamId, WriteBuf,
};
use h3_datagram::quic_traits::{
    DatagramConnectionExt, RecvDatagram, SendDatagram, SendDatagramErrorIncoming,
};
use msquic::{
    Connection, ConnectionEvent, ConnectionShutdownFlags, SendFlags, Stream, StreamEvent,
    StreamOpenFlags, StreamShutdownFlags,
};
use parking_lot::RwLock;
use std::{
    ffi::c_void,
    sync::Arc,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::sync::{mpsc, Notify};

/// Per-stream priority hint. msquic accepts 0..=0xFFFF; 0x7FFF is the
/// product default. wisp-wt extension 0x04 maps a 1-byte client hint
/// onto this 16-bit space and we forward the hint via
/// `MsQuic->SetParam(Stream, QUIC_PARAM_STREAM_PRIORITY, ...)`.
pub const DEFAULT_PRIORITY: u16 = 0x7FFF;
/// Control bidi sits at the top of the priority space so its frames
/// (INFO/READY/CLOSE/CONTROL) preempt bulk traffic.
pub const CONTROL_PRIORITY: u16 = 0xFFFF;
/// Server→client one-shot uni streams (extension 0x08 SERVER_UNI_RESPONSES)
/// sit slightly above the data default so a single small reply (e.g.
/// WT_PROXY_OPENED) doesn't queue behind a long TCP relay.
pub const UNI_RESPONSE_PRIORITY: u16 = DEFAULT_PRIORITY.saturating_add(0x100);

/// Datagram priority class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramClass {
    Bulk = 0,
    Normal = 1,
    Interactive = 2,
}

impl DatagramClass {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Bulk,
            2 => Self::Interactive,
            _ => Self::Normal,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Carrier mode for the per-flow UDP extension (0x09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCarrier {
    Datagram,
    UniStream,
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("msquic: {0}")]
    MsQuic(#[source] msquic::Status),
    #[error("stream closed")]
    Closed,
    #[error("datagram send rejected (peer disabled, payload too large, or queue full)")]
    DatagramRejected,
    #[error("connection going away")]
    ConnectionShutdown,
}

// ---------------- inbound channels (callback → async readers) -------------

#[derive(Clone)]
pub(crate) struct StreamChans {
    pub recv_tx: mpsc::UnboundedSender<Result<Bytes, StreamErrorIncoming>>,
    pub fin_notify: Arc<Notify>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NewStreamKind {
    Bidi,
    Uni,
}

pub(crate) struct NewStreamEvent {
    pub stream: Arc<Stream>,
    pub stream_id: u64,
    pub recv_rx: mpsc::UnboundedReceiver<Result<Bytes, StreamErrorIncoming>>,
    pub send_tx: mpsc::UnboundedSender<SendItem>,
}

pub(crate) struct SendItem {
    pub bytes: Bytes,
    pub fin: bool,
}

// ---------------- shared connection state ---------------------------------

pub(crate) struct ConnectionState {
    /// Keyed by the msquic-assigned QUIC stream id (monotonic and never reused
    /// within a connection). Keying by the raw `HQUIC` pointer risked an
    /// ABA/handle-reuse mixup: a freed stream's address could be reused by a
    /// new stream while a stale callback for the old one was still in flight.
    streams: DashMap<u64, StreamChans>,
    new_bidi_tx: mpsc::UnboundedSender<NewStreamEvent>,
    new_uni_tx: mpsc::UnboundedSender<NewStreamEvent>,
    datagram_tx: mpsc::UnboundedSender<Bytes>,
    /// Set true the first time the callback observes a connection-shutdown
    /// event. Used to short-circuit further sends and emit
    /// `ConnectionErrorIncoming` to h3.
    closed: RwLock<Option<ConnectionErrorIncoming>>,
}

impl ConnectionState {
    fn close(&self, err: ConnectionErrorIncoming) {
        {
            let mut guard = self.closed.write();
            if guard.is_none() {
                *guard = Some(err.clone());
            }
        }
        for entry in self.streams.iter() {
            let chans = entry.value().clone();
            let _ = chans
                .recv_tx
                .send(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: err.clone(),
                }));
        }
        self.streams.clear();
    }

    fn closed_err(&self) -> Option<ConnectionErrorIncoming> {
        self.closed.read().clone()
    }
}

// ---------------- the connection wrapper ---------------------------------

/// Owning handle held by the server task for the lifetime of a session.
///
/// Wraps a freshly-accepted msquic connection and its callback fan-out.
/// Implements `h3::quic::Connection<Bytes>` and
/// `h3-datagram`'s `DatagramConnectionExt<Bytes>` so it can drive
/// `h3-webtransport::server::WebTransportSession`.
pub struct MsQuicConnection {
    connection: Arc<Connection>,
    state: Arc<ConnectionState>,
    new_bidi_rx: mpsc::UnboundedReceiver<NewStreamEvent>,
    new_uni_rx: mpsc::UnboundedReceiver<NewStreamEvent>,
    /// The receiver for raw msquic datagrams. h3-datagram's recv path is
    /// stubbed (see `recv_datagram_handler`), so the wisp-wt UDP bridge owns
    /// this channel directly via `take_datagram_rx`.
    datagram_rx: Option<mpsc::UnboundedReceiver<Bytes>>,
    /// Last advertised max datagram length from msquic.
    pub max_datagram_size: Arc<RwLock<u16>>,
    /// Set once msquic emits `DatagramStateChanged { send_enabled: true }`.
    pub datagram_send_enabled: Arc<RwLock<bool>>,
}

impl MsQuicConnection {
    /// Wrap a freshly-accepted msquic connection. Installs the dispatcher
    /// callback that fans events into the per-stream registry.
    pub fn install(connection: Connection) -> Self {
        let (new_bidi_tx, new_bidi_rx) = mpsc::unbounded_channel();
        let (new_uni_tx, new_uni_rx) = mpsc::unbounded_channel();
        let (datagram_tx, datagram_rx) = mpsc::unbounded_channel();
        let max_datagram_size = Arc::new(RwLock::new(0u16));
        let datagram_send_enabled = Arc::new(RwLock::new(false));
        let state = Arc::new(ConnectionState {
            streams: DashMap::new(),
            new_bidi_tx,
            new_uni_tx,
            datagram_tx,
            closed: RwLock::new(None),
        });
        let connection = Arc::new(connection);
        let cb_state = state.clone();
        let cb_conn = connection.clone();
        let cb_max = max_datagram_size.clone();
        let cb_enabled = datagram_send_enabled.clone();
        connection.set_callback_handler(move |_conn_ref, event| {
            // Never let a panic unwind across msquic's extern "C" trampoline.
            // Under panic=abort (release) a panic aborts anyway; in debug/test
            // builds this converts a would-be process-wide crash into a
            // swallowed per-connection error.
            let hook = std::panic::AssertUnwindSafe(|| {
                on_connection_event(&cb_state, &cb_conn, &cb_max, &cb_enabled, event);
            });
            if std::panic::catch_unwind(hook).is_err() {
                tracing::error!("panic in msquic connection callback (swallowed)");
            }
            Ok(())
        });
        Self {
            connection,
            state,
            new_bidi_rx,
            new_uni_rx,
            datagram_rx: Some(datagram_rx),
            max_datagram_size,
            datagram_send_enabled,
        }
    }

    /// Hand the raw msquic datagram receiver out so the wisp-wt UDP bridge can
    /// consume datagrams directly. Returns `None` after the first call. Safe
    /// to call before `MsQuicConnection` is moved into h3 because the channel
    /// is fed from the connection callback, not from h3.
    pub fn take_datagram_rx(&mut self) -> Option<mpsc::UnboundedReceiver<Bytes>> {
        self.datagram_rx.take()
    }

    /// Side-channel handle for sending raw datagrams that bypasses h3's
    /// datagram extension. Cloneable so per-flow tasks can each own one.
    pub fn datagram_send_handle(&self) -> MsQuicDatagramSendHandle {
        MsQuicDatagramSendHandle {
            connection: self.connection.clone(),
            enabled: self.datagram_send_enabled.clone(),
            max_size: self.max_datagram_size.clone(),
        }
    }

    /// Send a datagram with priority class. Class `Interactive` adds
    /// `QUIC_SEND_FLAG_DGRAM_PRIORITY` so msquic reorders it ahead of bulk
    /// in the egress queue.
    pub fn send_datagram_classed(
        &self,
        payload: Bytes,
        class: DatagramClass,
    ) -> Result<(), AdapterError> {
        send_datagram_inner(
            &self.connection,
            &self.datagram_send_enabled,
            &self.max_datagram_size,
            payload,
            class,
        )
    }

    /// Initiate a graceful connection shutdown with the supplied error code.
    pub fn close_with_code(&self, error_code: u64) {
        self.connection
            .shutdown(ConnectionShutdownFlags::NONE, error_code);
    }
}

fn send_datagram_inner(
    connection: &Arc<Connection>,
    enabled: &RwLock<bool>,
    max_size: &RwLock<u16>,
    payload: Bytes,
    class: DatagramClass,
) -> Result<(), AdapterError> {
    if !*enabled.read() {
        return Err(AdapterError::DatagramRejected);
    }
    let max = *max_size.read();
    if max != 0 && payload.len() > max as usize {
        return Err(AdapterError::DatagramRejected);
    }
    let mut flags = SendFlags::NONE;
    if matches!(class, DatagramClass::Interactive) {
        flags |= SendFlags::DGRAM_PRIORITY;
    }
    let leaked: *const Bytes = Box::into_raw(Box::new(payload.clone()));
    let buf = msquic::BufferRef::from(payload.as_ref());
    let bufs = [buf];
    let res = unsafe { connection.datagram_send(&bufs, flags, leaked as *const c_void) };
    if let Err(e) = res {
        // SAFETY: matches the Box::into_raw above; we own the alloc.
        unsafe { drop(Box::from_raw(leaked as *mut Bytes)) };
        return Err(AdapterError::MsQuic(e));
    }
    Ok(())
}

// ---------------- callback handlers --------------------------------------

fn on_connection_event(
    state: &Arc<ConnectionState>,
    _connection: &Arc<Connection>,
    max_size: &RwLock<u16>,
    enabled: &RwLock<bool>,
    event: ConnectionEvent<'_>,
) {
    match event {
        ConnectionEvent::PeerStreamStarted { stream, flags } => {
            // SAFETY: msquic transferred ownership in the callback per the
            // PEER_STREAM_STARTED contract; from_raw matches the doc.
            let owned = unsafe { Stream::from_raw(stream.as_raw()) };
            let owned = Arc::new(owned);
            let kind = if flags.contains(StreamOpenFlags::UNIDIRECTIONAL) {
                NewStreamKind::Uni
            } else {
                NewStreamKind::Bidi
            };
            let stream_id = owned.get_stream_id().unwrap_or(u64::MAX);
            let evt = install_stream(state.clone(), owned, kind, stream_id);
            let tx = match kind {
                NewStreamKind::Bidi => &state.new_bidi_tx,
                NewStreamKind::Uni => &state.new_uni_tx,
            };
            let _ = tx.send(evt);
        }
        ConnectionEvent::DatagramReceived { buffer, .. } => {
            let mut buf = BytesMut::with_capacity(buffer.as_bytes().len());
            buf.extend_from_slice(buffer.as_bytes());
            let _ = state.datagram_tx.send(buf.freeze());
        }
        ConnectionEvent::DatagramStateChanged {
            send_enabled,
            max_send_length,
        } => {
            *enabled.write() = send_enabled;
            *max_size.write() = max_send_length;
        }
        ConnectionEvent::DatagramSendStateChanged {
            client_context,
            state,
        } => {
            // msquic hands back the per-send client context on every state
            // transition; the boxed payload clone from `send_datagram_inner`
            // must be freed exactly once, when the send reaches a terminal
            // state. Freeing on a non-final state (Sent / LostSuspect) would
            // free the buffer msquic still references — use-after-free.
            use msquic::DatagramSendState::{
                Acknowledged, AcknowledgedSpurious, Canceled, LostDiscarded,
            };
            let is_final = matches!(
                state,
                Acknowledged | AcknowledgedSpurious | LostDiscarded | Canceled
            );
            if is_final && !client_context.is_null() {
                // SAFETY: pointer came from Box::into_raw in send_datagram_inner.
                unsafe { drop(Box::from_raw(client_context as *mut Bytes)) };
            }
        }
        ConnectionEvent::ShutdownInitiatedByPeer { error_code } => {
            state.close(ConnectionErrorIncoming::ApplicationClose { error_code });
        }
        ConnectionEvent::ShutdownInitiatedByTransport { status, .. } => {
            let code = status.try_as_status_code().ok();
            let timeout = matches!(
                code,
                Some(msquic::StatusCode::QUIC_STATUS_CONNECTION_TIMEOUT)
                    | Some(msquic::StatusCode::QUIC_STATUS_CONNECTION_IDLE)
            );
            let err = if timeout {
                ConnectionErrorIncoming::Timeout
            } else {
                ConnectionErrorIncoming::InternalError(format!("transport shutdown: {status}"))
            };
            state.close(err);
        }
        ConnectionEvent::ShutdownComplete { .. } => {
            if state.closed.read().is_none() {
                state.close(ConnectionErrorIncoming::ApplicationClose { error_code: 0 });
            }
        }
        _ => {}
    }
}

fn install_stream(
    state: Arc<ConnectionState>,
    stream: Arc<Stream>,
    _kind: NewStreamKind,
    stream_id: u64,
) -> NewStreamEvent {
    let (recv_tx, recv_rx) = mpsc::unbounded_channel();
    let (send_tx, mut send_rx) = mpsc::unbounded_channel::<SendItem>();
    let fin_notify = Arc::new(Notify::new());
    let chans = StreamChans {
        recv_tx,
        fin_notify: fin_notify.clone(),
    };
    state.streams.insert(stream_id, chans);

    let cb_state = state.clone();
    stream.set_callback_handler(move |_, ev| {
        // See the connection callback: never unwind across the FFI boundary.
        let hook = std::panic::AssertUnwindSafe(|| {
            on_stream_event(&cb_state, stream_id, ev);
        });
        if std::panic::catch_unwind(hook).is_err() {
            tracing::error!(stream_id, "panic in msquic stream callback (swallowed)");
        }
        Ok(())
    });

    // Spawn the send pump so async writes get drained into MsQuic->StreamSend.
    let send_stream = stream.clone();
    tokio::spawn(async move {
        while let Some(item) = send_rx.recv().await {
            let mut flags = SendFlags::NONE;
            if item.fin {
                flags |= SendFlags::FIN;
            }
            let leaked: *const Bytes = Box::into_raw(Box::new(item.bytes.clone()));
            let buf = msquic::BufferRef::from(item.bytes.as_ref());
            let bufs = [buf];
            // SAFETY: bufs references the leaked Bytes; both live until
            // the SendComplete callback frees the box.
            let res = unsafe { send_stream.send(&bufs, flags, leaked as *const c_void) };
            if res.is_err() {
                // SAFETY: matches the Box::into_raw above.
                unsafe { drop(Box::from_raw(leaked as *mut Bytes)) };
                break;
            }
        }
    });

    NewStreamEvent {
        stream,
        stream_id,
        recv_rx,
        send_tx,
    }
}

fn on_stream_event(state: &ConnectionState, key: u64, event: StreamEvent<'_>) {
    let entry = state.streams.get(&key).map(|e| e.value().clone());
    let Some(chans) = entry else { return };
    match event {
        StreamEvent::Receive {
            buffers,
            total_buffer_length,
            ..
        } => {
            let mut buf = BytesMut::with_capacity(*total_buffer_length as usize);
            for b in buffers {
                buf.extend_from_slice(b.as_bytes());
            }
            let _ = chans.recv_tx.send(Ok(buf.freeze()));
        }
        StreamEvent::SendComplete { client_context, .. } => {
            if !client_context.is_null() {
                // SAFETY: pointer came from Box::into_raw above.
                unsafe { drop(Box::from_raw(client_context as *mut Bytes)) };
            }
        }
        StreamEvent::PeerSendShutdown => {
            // Peer FIN on the recv direction only. Signal end-of-stream with an
            // empty chunk (MsQuicRecvStream::poll_data maps empty -> None/EOF).
            // We must NOT remove the registry entry here: our own send side may
            // still be flushing, and dropping the entry would make every later
            // SendComplete leak its boxed payload (the early-return guard skips
            // the free). Terminal cleanup happens on ShutdownComplete.
            let _ = chans.recv_tx.send(Ok(Bytes::new()));
        }
        StreamEvent::PeerSendAborted { error_code } => {
            let _ = chans
                .recv_tx
                .send(Err(StreamErrorIncoming::StreamTerminated { error_code }));
        }
        StreamEvent::SendShutdownComplete { .. } => {
            chans.fin_notify.notify_waiters();
        }
        StreamEvent::ShutdownComplete { .. } => {
            state.streams.remove(&key);
        }
        _ => {}
    }
}

/// QUIC_PARAM_STREAM_PRIORITY — exposed as a safe wrapper over the unsafe FFI.
fn set_stream_priority(stream: &Stream, priority: u16) -> Result<(), AdapterError> {
    // SAFETY: handle is owned by the Arc<Stream> for the duration of this
    // call; pointer + length describe a local stack value with stable address.
    unsafe {
        msquic::Api::set_param(
            stream.as_raw(),
            msquic::PARAM_STREAM_PRIORITY,
            std::mem::size_of::<u16>() as u32,
            &priority as *const u16 as *const c_void,
        )
    }
    .map_err(AdapterError::MsQuic)
}

// ---------------- h3 SendStream / RecvStream / BidiStream ----------------

pub struct MsQuicSendStream {
    send_tx: mpsc::UnboundedSender<SendItem>,
    stream: Arc<Stream>,
    stream_id: StreamId,
    finished: bool,
}

pub struct MsQuicRecvStream {
    recv_rx: mpsc::UnboundedReceiver<Result<Bytes, StreamErrorIncoming>>,
    stream: Arc<Stream>,
    stream_id: StreamId,
}

pub struct MsQuicBidiStream {
    pub send: MsQuicSendStream,
    pub recv: MsQuicRecvStream,
}

impl MsQuicSendStream {
    pub fn set_priority(&self, priority: u16) -> Result<(), AdapterError> {
        set_stream_priority(&self.stream, priority)
    }
}

impl MsQuicRecvStream {
    pub fn set_priority(&self, priority: u16) -> Result<(), AdapterError> {
        set_stream_priority(&self.stream, priority)
    }
}

impl H3SendStream<Bytes> for MsQuicSendStream {
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        // The send pump backs onto an unbounded mpsc — it never applies
        // backpressure at this layer. Per-flow shaping is enforced upstream
        // (rate limiters in wisp-server) and downstream by msquic.
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        let mut wb = data.into();
        // WriteBuf<B> is a Buf chain that may or may not start with a frame
        // header. Drain into a single Bytes and forward.
        let mut acc = BytesMut::with_capacity(wb.remaining());
        while wb.has_remaining() {
            let chunk = wb.chunk();
            acc.extend_from_slice(chunk);
            let n = chunk.len();
            wb.advance(n);
        }
        if acc.is_empty() {
            return Ok(());
        }
        self.send_tx
            .send(SendItem {
                bytes: acc.freeze(),
                fin: false,
            })
            .map_err(|_| StreamErrorIncoming::Unknown(Box::new(AdapterError::Closed)))
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if !self.finished {
            self.finished = true;
            let _ = self.send_tx.send(SendItem {
                bytes: Bytes::new(),
                fin: true,
            });
        }
        // We don't currently block on FIN ack — msquic handles it asynchronously
        // and h3 doesn't strictly require FIN-acked completion.
        Poll::Ready(Ok(()))
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .shutdown(StreamShutdownFlags::ABORT_SEND, reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.stream_id
    }
}

impl H3RecvStream for MsQuicRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        match self.recv_rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(None)),
            Poll::Ready(Some(Ok(b))) if b.is_empty() => Poll::Ready(Ok(None)),
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Ok(Some(b))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        let _ = self
            .stream
            .shutdown(StreamShutdownFlags::ABORT_RECEIVE, error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.stream_id
    }
}

// BidiStream needs to satisfy SendStream + RecvStream + the split() helper.

impl H3SendStream<Bytes> for MsQuicBidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }
    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }
    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl H3RecvStream for MsQuicBidiStream {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }
    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }
    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl H3BidiStream<Bytes> for MsQuicBidiStream {
    type SendStream = MsQuicSendStream;
    type RecvStream = MsQuicRecvStream;
    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

// Unframed write path for WebTransport raw stream data. h3-webtransport's
// `BidiStream::poll_send` delegates here; without it, we'd have to wrap
// every WT-stream byte in an HTTP/3 DATA frame which is incorrect on WT.
impl H3SendStreamUnframed<Bytes> for MsQuicSendStream {
    fn poll_send<D: Buf>(
        &mut self,
        _cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        if !buf.has_remaining() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.remaining();
        let mut acc = BytesMut::with_capacity(n);
        while buf.has_remaining() {
            let chunk = buf.chunk();
            acc.extend_from_slice(chunk);
            let len = chunk.len();
            buf.advance(len);
        }
        self.send_tx
            .send(SendItem {
                bytes: acc.freeze(),
                fin: false,
            })
            .map_err(|_| StreamErrorIncoming::Unknown(Box::new(AdapterError::Closed)))?;
        Poll::Ready(Ok(n))
    }
}

impl H3SendStreamUnframed<Bytes> for MsQuicBidiStream {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

// ---------------- h3 OpenStreams + Connection ----------------------------

/// Cloneable opener that h3 hands out via `Connection::opener()`.
#[derive(Clone)]
pub struct MsQuicOpener {
    connection: Arc<Connection>,
    state: Arc<ConnectionState>,
}

impl MsQuicOpener {
    fn open_stream(&mut self, uni: bool) -> Result<NewStreamEvent, StreamErrorIncoming> {
        if let Some(err) = self.state.closed_err() {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: err,
            });
        }
        let flags = if uni {
            StreamOpenFlags::UNIDIRECTIONAL
        } else {
            StreamOpenFlags::NONE
        };
        let stream = Stream::open(&self.connection, flags, |_, _| Ok(()))
            .map_err(|e| stream_unknown(AdapterError::MsQuic(e)))?;
        stream
            .start(msquic::StreamStartFlags::IMMEDIATE)
            .map_err(|e| stream_unknown(AdapterError::MsQuic(e)))?;
        let stream = Arc::new(stream);
        let stream_id = stream.get_stream_id().unwrap_or(u64::MAX);
        let kind = if uni {
            NewStreamKind::Uni
        } else {
            NewStreamKind::Bidi
        };
        Ok(install_stream(self.state.clone(), stream, kind, stream_id))
    }
}

fn stream_unknown(err: AdapterError) -> StreamErrorIncoming {
    StreamErrorIncoming::Unknown(Box::new(err))
}

fn evt_to_send_stream(evt: NewStreamEvent) -> MsQuicSendStream {
    let stream_id =
        StreamId::try_from(evt.stream_id).unwrap_or_else(|_| StreamId::try_from(0u64).unwrap());
    MsQuicSendStream {
        send_tx: evt.send_tx,
        stream: evt.stream,
        stream_id,
        finished: false,
    }
}

fn evt_to_recv_stream(evt: NewStreamEvent) -> MsQuicRecvStream {
    let stream_id =
        StreamId::try_from(evt.stream_id).unwrap_or_else(|_| StreamId::try_from(0u64).unwrap());
    MsQuicRecvStream {
        recv_rx: evt.recv_rx,
        stream: evt.stream,
        stream_id,
    }
}

fn evt_to_bidi(evt: NewStreamEvent) -> MsQuicBidiStream {
    let stream_id =
        StreamId::try_from(evt.stream_id).unwrap_or_else(|_| StreamId::try_from(0u64).unwrap());
    let send = MsQuicSendStream {
        send_tx: evt.send_tx,
        stream: evt.stream.clone(),
        stream_id,
        finished: false,
    };
    let recv = MsQuicRecvStream {
        recv_rx: evt.recv_rx,
        stream: evt.stream,
        stream_id,
    };
    MsQuicBidiStream { send, recv }
}

impl H3OpenStreams<Bytes> for MsQuicOpener {
    type BidiStream = MsQuicBidiStream;
    type SendStream = MsQuicSendStream;

    fn poll_open_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.open_stream(false) {
            Ok(evt) => Poll::Ready(Ok(evt_to_bidi(evt))),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_open_send(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match self.open_stream(true) {
            Ok(evt) => Poll::Ready(Ok(evt_to_send_stream(evt))),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn close(&mut self, code: Code, _reason: &[u8]) {
        self.connection
            .shutdown(ConnectionShutdownFlags::NONE, code.value());
    }
}

impl H3OpenStreams<Bytes> for MsQuicConnection {
    type BidiStream = MsQuicBidiStream;
    type SendStream = MsQuicSendStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let mut opener = MsQuicOpener {
            connection: self.connection.clone(),
            state: self.state.clone(),
        };
        opener.poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let mut opener = MsQuicOpener {
            connection: self.connection.clone(),
            state: self.state.clone(),
        };
        opener.poll_open_send(cx)
    }

    fn close(&mut self, code: Code, _reason: &[u8]) {
        self.connection
            .shutdown(ConnectionShutdownFlags::NONE, code.value());
    }
}

impl quic::Connection<Bytes> for MsQuicConnection {
    type RecvStream = MsQuicRecvStream;
    type OpenStreams = MsQuicOpener;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        match self.new_uni_rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(evt)) => Poll::Ready(Ok(evt_to_recv_stream(evt))),
            Poll::Ready(None) => {
                let err = self
                    .state
                    .closed_err()
                    .unwrap_or_else(|| ConnectionErrorIncoming::ApplicationClose { error_code: 0 });
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        match self.new_bidi_rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(evt)) => Poll::Ready(Ok(evt_to_bidi(evt))),
            Poll::Ready(None) => {
                let err = self
                    .state
                    .closed_err()
                    .unwrap_or_else(|| ConnectionErrorIncoming::ApplicationClose { error_code: 0 });
                Poll::Ready(Err(err))
            }
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        MsQuicOpener {
            connection: self.connection.clone(),
            state: self.state.clone(),
        }
    }
}

// ---------------- h3-datagram glue --------------------------------------

/// Side-channel datagram sender that bypasses the h3-datagram crate. The
/// wisp-wt UDP bridge owns one of these per session and clones it into per-
/// flow tasks; sends are non-blocking and class-aware (Interactive uses
/// `QUIC_SEND_FLAG_DGRAM_PRIORITY`).
#[derive(Clone)]
pub struct MsQuicDatagramSendHandle {
    connection: Arc<Connection>,
    enabled: Arc<RwLock<bool>>,
    max_size: Arc<RwLock<u16>>,
}

impl MsQuicDatagramSendHandle {
    pub fn send(&self, payload: Bytes, class: DatagramClass) -> Result<(), AdapterError> {
        send_datagram_inner(
            &self.connection,
            &self.enabled,
            &self.max_size,
            payload,
            class,
        )
    }

    pub fn max_datagram_size(&self) -> u16 {
        *self.max_size.read()
    }

    pub fn send_enabled(&self) -> bool {
        *self.enabled.read()
    }
}

#[derive(Clone)]
pub struct MsQuicDatagramSender {
    connection: Arc<Connection>,
    enabled: Arc<RwLock<bool>>,
    max_size: Arc<RwLock<u16>>,
}

pub struct MsQuicDatagramReceiver {
    rx: mpsc::UnboundedReceiver<Bytes>,
    closed: Arc<RwLock<Option<ConnectionErrorIncoming>>>,
}

impl SendDatagram<Bytes> for MsQuicDatagramSender {
    fn send_datagram<T: Into<h3_datagram::datagram::EncodedDatagram<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), SendDatagramErrorIncoming> {
        if !*self.enabled.read() {
            return Err(SendDatagramErrorIncoming::NotAvailable);
        }
        let mut encoded = data.into();
        let mut acc = BytesMut::with_capacity(encoded.remaining());
        while encoded.has_remaining() {
            let chunk = encoded.chunk();
            acc.extend_from_slice(chunk);
            let n = chunk.len();
            encoded.advance(n);
        }
        let payload = acc.freeze();
        let max = *self.max_size.read();
        if max != 0 && payload.len() > max as usize {
            return Err(SendDatagramErrorIncoming::TooLarge);
        }
        send_datagram_inner(
            &self.connection,
            &self.enabled,
            &self.max_size,
            payload,
            DatagramClass::Normal,
        )
        .map_err(|e| match e {
            AdapterError::DatagramRejected => SendDatagramErrorIncoming::NotAvailable,
            AdapterError::ConnectionShutdown => SendDatagramErrorIncoming::ConnectionError(
                ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
            ),
            AdapterError::Closed => SendDatagramErrorIncoming::NotAvailable,
            AdapterError::MsQuic(s) => SendDatagramErrorIncoming::ConnectionError(
                ConnectionErrorIncoming::InternalError(format!("msquic datagram_send: {s}")),
            ),
        })
    }
}

impl RecvDatagram for MsQuicDatagramReceiver {
    type Buffer = Bytes;
    fn poll_incoming_datagram(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Buffer, ConnectionErrorIncoming>> {
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(b)) => Poll::Ready(Ok(b)),
            Poll::Ready(None) => {
                let err =
                    self.closed.read().clone().unwrap_or_else(|| {
                        ConnectionErrorIncoming::ApplicationClose { error_code: 0 }
                    });
                Poll::Ready(Err(err))
            }
        }
    }
}

impl DatagramConnectionExt<Bytes> for MsQuicConnection {
    type SendDatagramHandler = MsQuicDatagramSender;
    type RecvDatagramHandler = MsQuicDatagramReceiver;

    fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
        MsQuicDatagramSender {
            connection: self.connection.clone(),
            enabled: self.datagram_send_enabled.clone(),
            max_size: self.max_datagram_size.clone(),
        }
    }

    fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
        // h3 only constructs one receiver per connection; the receiver
        // takes ownership of the datagram channel by stealing it.
        // We can't actually move it out of `&self`, so return a fresh
        // empty channel and emit a closed error if h3 polls. In practice,
        // the server task uses the connection's receiver directly via
        // the `WebTransportSession::accept_datagram` path which is wired
        // through h3-webtransport — so this stub is reachable only if the
        // user calls the bare h3-datagram API. For Wispmark that path
        // isn't exercised; full support is a follow-up.
        let (_tx, rx) = mpsc::unbounded_channel();
        MsQuicDatagramReceiver {
            rx,
            closed: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_class_round_trips() {
        assert_eq!(DatagramClass::from_byte(0), DatagramClass::Bulk);
        assert_eq!(DatagramClass::from_byte(1), DatagramClass::Normal);
        assert_eq!(DatagramClass::from_byte(2), DatagramClass::Interactive);
        assert_eq!(DatagramClass::from_byte(99), DatagramClass::Normal);
        assert_eq!(DatagramClass::Interactive.to_byte(), 2);
    }

    #[test]
    fn priority_constants_are_ordered() {
        const _: () = assert!(CONTROL_PRIORITY > UNI_RESPONSE_PRIORITY);
        const _: () = assert!(UNI_RESPONSE_PRIORITY > DEFAULT_PRIORITY);
    }

    #[test]
    fn udp_carrier_variants() {
        assert_ne!(UdpCarrier::Datagram, UdpCarrier::UniStream);
    }
}

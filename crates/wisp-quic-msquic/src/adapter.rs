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
//! 3. A bounded datagram channel: connection callbacks for
//!    `DATAGRAM_RECEIVED` use non-blocking admission and the
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
use futures::task::AtomicWaker;
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
    Configuration, Connection, ConnectionEvent, ConnectionShutdownFlags, Registration, SendFlags,
    Status, StatusCode, Stream, StreamEvent, StreamOpenFlags, StreamShutdownFlags,
};
use parking_lot::{Mutex, RwLock};
use std::{
    ffi::c_void,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::{CancellationToken, PollSender};

const DATAGRAM_RECEIVE_QUEUE_CAPACITY: usize = 256;
const NEW_STREAM_QUEUE_CAPACITY: usize = 256;
const STREAM_RECEIVE_QUEUE_CAPACITY: usize = 4;
const STREAM_SEND_QUEUE_CAPACITY: usize = 8;

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
    #[error("stream id lookup failed")]
    StreamIdUnavailable,
    #[error("send_data called before the previous frame was accepted by poll_ready")]
    NotReady,
}

#[derive(Clone)]
pub(crate) struct StreamChans {
    pub recv_tx: mpsc::Sender<RecvItem>,
    pub fin_state: Arc<FinState>,
    pub send_complete: Arc<Notify>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NewStreamKind {
    Bidi,
    Uni,
}

pub(crate) struct NewStreamEvent {
    pub stream: Arc<Stream>,
    pub stream_id: u64,
    pub recv_rx: mpsc::Receiver<RecvItem>,
    pub send_tx: mpsc::Sender<SendItem>,
    pub fin_state: Arc<FinState>,
}

pub(crate) struct RecvItem {
    result: Result<Bytes, StreamErrorIncoming>,
    complete_len: Option<u64>,
}

pub(crate) struct SendItem {
    pub bytes: Bytes,
    pub fin: bool,
}

pub(crate) struct FinState {
    complete: AtomicBool,
    waker: AtomicWaker,
}

impl FinState {
    fn new() -> Self {
        Self {
            complete: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        }
    }

    fn mark_complete(&self) {
        self.complete.store(true, Ordering::Release);
        self.waker.wake();
    }
}

fn submit_stream_send(stream: &Stream, item: &SendItem) -> Result<(), Status> {
    let mut flags = SendFlags::NONE;
    if item.fin {
        flags |= SendFlags::FIN;
    }
    let leaked: *const Bytes = Box::into_raw(Box::new(item.bytes.clone()));
    let buf = msquic::BufferRef::from(item.bytes.as_ref());
    let bufs = [buf];
    // SAFETY: the buffer references the boxed Bytes, which is released by
    let result = unsafe { stream.send(&bufs, flags, leaked.cast()) };
    if result.is_err() {
        // SAFETY: matches the Box::into_raw above.
        unsafe { drop(Box::from_raw(leaked as *mut Bytes)) };
    }
    result
}

pub(crate) struct ConnectionState {
    /// Keyed by the msquic-assigned QUIC stream id (monotonic and never reused
    /// within a connection). Keying by the raw `HQUIC` pointer risked an
    /// ABA/handle-reuse mixup: a freed stream's address could be reused by a
    /// new stream while a stale callback for the old one was still in flight.
    streams: DashMap<u64, StreamChans>,
    new_bidi_tx: mpsc::Sender<NewStreamEvent>,
    new_uni_tx: mpsc::Sender<NewStreamEvent>,
    datagram_tx: mpsc::Sender<Bytes>,
    /// Set true the first time the callback observes a connection-shutdown
    /// event. Used to short-circuit further sends and emit
    /// `ConnectionErrorIncoming` to h3.
    closed: Arc<RwLock<Option<ConnectionErrorIncoming>>>,
    datagram_cancel: CancellationToken,
    connected: AtomicBool,
    connected_notify: Notify,
    /// Runtime that owns this connection's async side. msquic delivers events
    /// on its own worker threads, which have no Tokio context, so anything the
    /// callbacks need to spawn goes through this handle.
    runtime: tokio::runtime::Handle,
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
            let _ = chans.recv_tx.try_send(RecvItem {
                result: Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: err.clone(),
                }),
                complete_len: None,
            });
            chans.send_complete.notify_one();
            chans.fin_state.mark_complete();
        }
        self.datagram_cancel.cancel();
        self.connected_notify.notify_one();
    }

    fn closed_err(&self) -> Option<ConnectionErrorIncoming> {
        self.closed.read().clone()
    }
}

/// Owning handle held by the server task for the lifetime of a session.
///
/// Wraps a freshly-accepted msquic connection and its callback fan-out.
/// Implements `h3::quic::Connection<Bytes>` and
/// `h3-datagram`'s `DatagramConnectionExt<Bytes>` so it can drive
/// `h3-webtransport::server::WebTransportSession`.
pub struct MsQuicConnection {
    connection: Arc<Connection>,
    state: Arc<ConnectionState>,
    new_bidi_rx: mpsc::Receiver<NewStreamEvent>,
    new_uni_rx: mpsc::Receiver<NewStreamEvent>,
    datagram_rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
    /// Last advertised max datagram length from msquic.
    pub max_datagram_size: Arc<RwLock<u16>>,
    /// Set once msquic emits `DatagramStateChanged { send_enabled: true }`.
    pub datagram_send_enabled: Arc<RwLock<bool>>,
}

impl MsQuicConnection {
    /// Wrap a freshly-accepted msquic connection. Installs the dispatcher
    /// callback that fans events into the per-stream registry.
    ///
    /// `runtime` is the Tokio runtime the connection's tasks run on. Callers in
    /// an msquic callback have no ambient runtime, so it is passed in rather
    /// than looked up.
    pub fn install(connection: Connection, runtime: tokio::runtime::Handle) -> Self {
        let (new_bidi_tx, new_bidi_rx) = mpsc::channel(NEW_STREAM_QUEUE_CAPACITY);
        let (new_uni_tx, new_uni_rx) = mpsc::channel(NEW_STREAM_QUEUE_CAPACITY);
        let (datagram_tx, datagram_rx) = mpsc::channel(DATAGRAM_RECEIVE_QUEUE_CAPACITY);
        let max_datagram_size = Arc::new(RwLock::new(0u16));
        let datagram_send_enabled = Arc::new(RwLock::new(false));
        let state = Arc::new(ConnectionState {
            streams: DashMap::new(),
            new_bidi_tx,
            new_uni_tx,
            datagram_tx,
            closed: Arc::new(RwLock::new(None)),
            datagram_cancel: CancellationToken::new(),
            connected: AtomicBool::new(false),
            connected_notify: Notify::new(),
            runtime,
        });
        let connection = Arc::new(connection);
        let cb_state = state.clone();
        let cb_conn = connection.clone();
        let cb_max = max_datagram_size.clone();
        let cb_enabled = datagram_send_enabled.clone();
        connection.set_callback_handler(move |_conn_ref, event| {
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
            datagram_rx: Mutex::new(Some(datagram_rx)),
            max_datagram_size,
            datagram_send_enabled,
        }
    }

    /// Open an outbound connection to an already policy-checked address while
    /// retaining `server_name` for TLS SNI and certificate validation.
    pub async fn connect(
        registration: &Registration,
        configuration: &Configuration,
        server_name: &str,
        remote_addr: SocketAddr,
    ) -> Result<Self, AdapterError> {
        let connection =
            Connection::open(registration, |_, _| Ok(())).map_err(AdapterError::MsQuic)?;
        let remote = msquic::Addr::from(remote_addr);
        // SAFETY: `remote` has the FFI-compatible `Addr` layout and remains
        unsafe {
            msquic::Api::set_param(
                connection.as_raw(),
                msquic::ffi::QUIC_PARAM_CONN_REMOTE_ADDRESS,
                std::mem::size_of::<msquic::Addr>() as u32,
                std::ptr::from_ref(&remote).cast(),
            )
        }
        .map_err(AdapterError::MsQuic)?;

        let connected = Self::install(connection, tokio::runtime::Handle::current());
        connected
            .connection
            .start(configuration, server_name, remote_addr.port())
            .map_err(AdapterError::MsQuic)?;
        wait_for_connected(&connected.state).await?;
        Ok(connected)
    }

    /// Initiate a graceful connection shutdown with the supplied error code.
    pub fn close_with_code(&self, error_code: u64) {
        self.connection
            .shutdown(ConnectionShutdownFlags::NONE, error_code);
    }
}

async fn wait_for_connected(state: &ConnectionState) -> Result<(), AdapterError> {
    loop {
        if state.connected.load(Ordering::Acquire) {
            return Ok(());
        }
        if state.closed_err().is_some() {
            return Err(AdapterError::ConnectionShutdown);
        }
        state.connected_notify.notified().await;
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

fn on_connection_event(
    state: &Arc<ConnectionState>,
    _connection: &Arc<Connection>,
    max_size: &RwLock<u16>,
    enabled: &RwLock<bool>,
    event: ConnectionEvent<'_>,
) {
    match event {
        ConnectionEvent::Connected { .. } => {
            state.connected.store(true, Ordering::Release);
            state.connected_notify.notify_one();
        }
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
            let Ok(stream_id) = owned.get_stream_id() else {
                tracing::warn!("dropping peer stream with unresolvable id");
                return;
            };
            let evt = install_stream(state.clone(), owned, kind, stream_id);
            let tx = match kind {
                NewStreamKind::Bidi => &state.new_bidi_tx,
                NewStreamKind::Uni => &state.new_uni_tx,
            };
            if let Err(error) = tx.try_send(evt) {
                let rejected = error.into_inner();
                let _ = rejected.stream.shutdown(StreamShutdownFlags::ABORT, 0);
                state.streams.remove(&stream_id);
            }
        }
        ConnectionEvent::DatagramReceived { buffer, .. } => {
            let mut buf = BytesMut::with_capacity(buffer.as_bytes().len());
            buf.extend_from_slice(buffer.as_bytes());
            let _ = state.datagram_tx.try_send(buf.freeze());
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
        ConnectionEvent::ShutdownComplete { .. } if state.closed.read().is_none() => {
            state.close(ConnectionErrorIncoming::ApplicationClose { error_code: 0 });
            state.streams.clear();
        }
        ConnectionEvent::ShutdownComplete { .. } => {
            state.streams.clear();
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
    let (recv_tx, recv_rx) = mpsc::channel(STREAM_RECEIVE_QUEUE_CAPACITY);
    let (send_tx, mut send_rx) = mpsc::channel::<SendItem>(STREAM_SEND_QUEUE_CAPACITY);
    let fin_state = Arc::new(FinState::new());
    let send_complete = Arc::new(Notify::new());
    let chans = StreamChans {
        recv_tx,
        fin_state: fin_state.clone(),
        send_complete: send_complete.clone(),
    };
    state.streams.insert(stream_id, chans);

    let cb_state = state.clone();
    stream.set_callback_handler(move |_, ev| {
        let hook = std::panic::AssertUnwindSafe(|| on_stream_event(&cb_state, stream_id, ev));
        match std::panic::catch_unwind(hook) {
            Ok(result) => result,
            Err(_) => {
                tracing::error!(stream_id, "panic in msquic stream callback");
                Err(Status::new(StatusCode::QUIC_STATUS_INTERNAL_ERROR))
            }
        }
    });

    let send_stream = stream.clone();
    // Reached from msquic's worker thread for peer streams, so spawn through
    // the connection's runtime handle instead of the ambient context.
    state.runtime.spawn(async move {
        while let Some(item) = send_rx.recv().await {
            let completed = send_complete.notified();
            if submit_stream_send(&send_stream, &item).is_err() {
                break;
            }
            completed.await;
        }
    });

    NewStreamEvent {
        stream,
        stream_id,
        recv_rx,
        send_tx,
        fin_state,
    }
}

fn on_stream_event(
    state: &ConnectionState,
    key: u64,
    event: StreamEvent<'_>,
) -> Result<(), Status> {
    if let StreamEvent::SendComplete { client_context, .. } = event {
        if !client_context.is_null() {
            // SAFETY: pointer came from Box::into_raw in the send worker.
            unsafe { drop(Box::from_raw(client_context as *mut Bytes)) };
        }
        if let Some(chans) = state.streams.get(&key) {
            chans.send_complete.notify_one();
        }
        return Ok(());
    }
    let entry = state.streams.get(&key).map(|e| e.value().clone());
    let Some(chans) = entry else { return Ok(()) };
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
            chans
                .recv_tx
                .try_send(RecvItem {
                    result: Ok(buf.freeze()),
                    complete_len: Some(*total_buffer_length),
                })
                .map_err(|_| Status::new(StatusCode::QUIC_STATUS_OUT_OF_MEMORY))?;
            return Err(Status::new(StatusCode::QUIC_STATUS_PENDING));
        }
        StreamEvent::PeerSendShutdown => {
            let _ = chans.recv_tx.try_send(RecvItem {
                result: Ok(Bytes::new()),
                complete_len: None,
            });
        }
        StreamEvent::PeerSendAborted { error_code } => {
            let _ = chans.recv_tx.try_send(RecvItem {
                result: Err(StreamErrorIncoming::StreamTerminated { error_code }),
                complete_len: None,
            });
        }
        StreamEvent::SendShutdownComplete { .. } => {
            chans.fin_state.mark_complete();
        }
        StreamEvent::ShutdownComplete { .. } => {
            state.streams.remove(&key);
        }
        _ => {}
    }
    Ok(())
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

pub struct MsQuicSendStream {
    send_tx: PollSender<SendItem>,
    /// Frame accepted by `send_data` and not yet handed to the send worker.
    /// h3 calls `send_data` first and drives it out with `poll_ready`, so the
    /// frame waits here until the worker queue has room.
    pending: Option<SendItem>,
    stream: Arc<Stream>,
    stream_id: StreamId,
    fin_sent: bool,
    fin_state: Arc<FinState>,
}

pub struct MsQuicRecvStream {
    recv_rx: mpsc::Receiver<RecvItem>,
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

impl MsQuicSendStream {
    /// Move the frame buffered by `send_data` into the worker queue, waiting for
    /// room. Ready once nothing is buffered, which keeps queue order intact for
    /// whatever is sent next.
    fn poll_flush_pending(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        if self.pending.is_none() {
            return Poll::Ready(Ok(()));
        }
        match self.send_tx.poll_reserve(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(stream_unknown(AdapterError::Closed))),
            Poll::Ready(Ok(())) => {}
        }
        let Some(item) = self.pending.take() else {
            return Poll::Ready(Ok(()));
        };
        Poll::Ready(
            self.send_tx
                .send_item(item)
                .map_err(|_| stream_unknown(AdapterError::Closed)),
        )
    }
}

impl H3SendStream<Bytes> for MsQuicSendStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.poll_flush_pending(cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if self.pending.is_some() {
            // h3 must wait for `poll_ready` between frames; refusing here keeps
            // a misuse from reordering or dropping data.
            return Err(stream_unknown(AdapterError::NotReady));
        }
        let mut wb = data.into();
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
        self.pending = Some(SendItem {
            bytes: acc.freeze(),
            fin: false,
        });
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if !self.fin_sent {
            match self.poll_flush_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            match self.send_tx.poll_reserve(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(stream_unknown(AdapterError::Closed)))
                }
                Poll::Ready(Ok(())) => {}
            }
            self.send_tx
                .send_item(SendItem {
                    bytes: Bytes::new(),
                    fin: true,
                })
                .map_err(|_| stream_unknown(AdapterError::Closed))?;
            self.fin_sent = true;
        }
        if self.fin_state.complete.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        self.fin_state.waker.register(cx.waker());
        if self.fin_state.complete.load(Ordering::Acquire) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn reset(&mut self, reset_code: u64) {
        self.pending = None;
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
            Poll::Ready(Some(item)) => {
                if let Some(len) = item.complete_len {
                    self.stream.receive_complete(len);
                }
                match item.result {
                    Ok(b) if b.is_empty() => Poll::Ready(Ok(None)),
                    Ok(b) => Poll::Ready(Ok(Some(b))),
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
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

/// Unframed write path for WebTransport raw stream data, so WT-stream bytes
/// are not wrapped in an HTTP/3 DATA frame.
impl H3SendStreamUnframed<Bytes> for MsQuicSendStream {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        if !buf.has_remaining() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        match self.send_tx.poll_reserve(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(stream_unknown(AdapterError::Closed))),
            Poll::Ready(Ok(())) => {}
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
            .send_item(SendItem {
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
        let Ok(stream_id) = stream.get_stream_id() else {
            return Err(stream_unknown(AdapterError::StreamIdUnavailable));
        };
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

fn evt_to_send_stream(evt: NewStreamEvent) -> Result<MsQuicSendStream, AdapterError> {
    let stream_id =
        StreamId::try_from(evt.stream_id).map_err(|_| AdapterError::StreamIdUnavailable)?;
    Ok(MsQuicSendStream {
        send_tx: PollSender::new(evt.send_tx),
        pending: None,
        stream: evt.stream,
        stream_id,
        fin_sent: false,
        fin_state: evt.fin_state,
    })
}

fn evt_to_recv_stream(evt: NewStreamEvent) -> Result<MsQuicRecvStream, AdapterError> {
    let stream_id =
        StreamId::try_from(evt.stream_id).map_err(|_| AdapterError::StreamIdUnavailable)?;
    Ok(MsQuicRecvStream {
        recv_rx: evt.recv_rx,
        stream: evt.stream,
        stream_id,
    })
}

fn evt_to_bidi(evt: NewStreamEvent) -> Result<MsQuicBidiStream, AdapterError> {
    let stream_id =
        StreamId::try_from(evt.stream_id).map_err(|_| AdapterError::StreamIdUnavailable)?;
    let send = MsQuicSendStream {
        send_tx: PollSender::new(evt.send_tx),
        pending: None,
        stream: evt.stream.clone(),
        stream_id,
        fin_sent: false,
        fin_state: evt.fin_state,
    };
    let recv = MsQuicRecvStream {
        recv_rx: evt.recv_rx,
        stream: evt.stream,
        stream_id,
    };
    Ok(MsQuicBidiStream { send, recv })
}

impl H3OpenStreams<Bytes> for MsQuicOpener {
    type BidiStream = MsQuicBidiStream;
    type SendStream = MsQuicSendStream;

    fn poll_open_bidi(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.open_stream(false) {
            Ok(evt) => Poll::Ready(evt_to_bidi(evt).map_err(stream_unknown)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_open_send(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match self.open_stream(true) {
            Ok(evt) => Poll::Ready(evt_to_send_stream(evt).map_err(stream_unknown)),
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
            Poll::Ready(Some(evt)) => Poll::Ready(
                evt_to_recv_stream(evt)
                    .map_err(|error| ConnectionErrorIncoming::InternalError(error.to_string())),
            ),
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
            Poll::Ready(Some(evt)) => Poll::Ready(
                evt_to_bidi(evt)
                    .map_err(|error| ConnectionErrorIncoming::InternalError(error.to_string())),
            ),
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

#[derive(Clone)]
pub struct MsQuicDatagramSender {
    connection: Arc<Connection>,
    enabled: Arc<RwLock<bool>>,
    max_size: Arc<RwLock<u16>>,
}

pub struct MsQuicDatagramReceiver {
    rx: mpsc::Receiver<Bytes>,
    closed: Arc<RwLock<Option<ConnectionErrorIncoming>>>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
}

fn encoded_datagram_class(payload: &[u8]) -> DatagramClass {
    let Some(first) = payload.first() else {
        return DatagramClass::Normal;
    };
    let quarter_stream_id_len = 1usize << (first >> 6);
    payload
        .get(quarter_stream_id_len)
        .copied()
        .map(DatagramClass::from_byte)
        .unwrap_or(DatagramClass::Normal)
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
        let class = encoded_datagram_class(&payload);
        send_datagram_inner(
            &self.connection,
            &self.enabled,
            &self.max_size,
            payload,
            class,
        )
        .map_err(|e| match e {
            AdapterError::DatagramRejected => SendDatagramErrorIncoming::NotAvailable,
            AdapterError::ConnectionShutdown => SendDatagramErrorIncoming::ConnectionError(
                ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
            ),
            AdapterError::Closed | AdapterError::StreamIdUnavailable | AdapterError::NotReady => {
                SendDatagramErrorIncoming::NotAvailable
            }
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
        if self.cancelled.as_mut().poll(cx).is_ready() {
            let err = self
                .closed
                .read()
                .clone()
                .unwrap_or(ConnectionErrorIncoming::ApplicationClose { error_code: 0 });
            return Poll::Ready(Err(err));
        }
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
        let rx = self.datagram_rx.lock().take().unwrap_or_else(|| {
            let (_tx, rx) = mpsc::channel(1);
            rx
        });
        MsQuicDatagramReceiver {
            rx,
            closed: self.state.closed.clone(),
            cancelled: Box::pin(self.state.datagram_cancel.clone().cancelled_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection_state() -> Arc<ConnectionState> {
        let (new_bidi_tx, _new_bidi_rx) = mpsc::channel(1);
        let (new_uni_tx, _new_uni_rx) = mpsc::channel(1);
        let (datagram_tx, _datagram_rx) = mpsc::channel(1);
        Arc::new(ConnectionState {
            streams: DashMap::new(),
            new_bidi_tx,
            new_uni_tx,
            datagram_tx,
            closed: Arc::new(RwLock::new(None)),
            datagram_cancel: CancellationToken::new(),
            connected: AtomicBool::new(false),
            connected_notify: Notify::new(),
            runtime: tokio::runtime::Handle::current(),
        })
    }

    #[test]
    fn datagram_class_round_trips() {
        assert_eq!(DatagramClass::from_byte(0), DatagramClass::Bulk);
        assert_eq!(DatagramClass::from_byte(1), DatagramClass::Normal);
        assert_eq!(DatagramClass::from_byte(2), DatagramClass::Interactive);
        assert_eq!(DatagramClass::from_byte(99), DatagramClass::Normal);
        assert_eq!(DatagramClass::Interactive.to_byte(), 2);
    }

    #[test]
    fn encoded_datagram_class_skips_quarter_stream_id() {
        assert_eq!(
            encoded_datagram_class(&[0x00, 0x02, 0xaa]),
            DatagramClass::Interactive
        );
        assert_eq!(
            encoded_datagram_class(&[0x40, 0x01, 0x00, 0xaa]),
            DatagramClass::Bulk
        );
        assert_eq!(encoded_datagram_class(&[]), DatagramClass::Normal);
        assert_eq!(encoded_datagram_class(&[0xc0]), DatagramClass::Normal);
    }

    #[tokio::test]
    async fn datagram_receiver_delivers_callback_payload() {
        let (tx, rx) = mpsc::channel(1);
        let closed = Arc::new(RwLock::new(None));
        let cancel = CancellationToken::new();
        let mut receiver = MsQuicDatagramReceiver {
            rx,
            closed,
            cancelled: Box::pin(cancel.cancelled_owned()),
        };
        tx.send(Bytes::from_static(b"datagram")).await.unwrap();
        let payload = std::future::poll_fn(|cx| receiver.poll_incoming_datagram(cx))
            .await
            .unwrap();
        assert_eq!(payload.as_ref(), b"datagram");
    }

    #[tokio::test]
    async fn datagram_receiver_wakes_on_connection_shutdown() {
        let (_tx, rx) = mpsc::channel(1);
        let closed = Arc::new(RwLock::new(Some(
            ConnectionErrorIncoming::ApplicationClose { error_code: 77 },
        )));
        let cancel = CancellationToken::new();
        let mut receiver = MsQuicDatagramReceiver {
            rx,
            closed,
            cancelled: Box::pin(cancel.clone().cancelled_owned()),
        };
        cancel.cancel();
        let err = std::future::poll_fn(|cx| receiver.poll_incoming_datagram(cx))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ConnectionErrorIncoming::ApplicationClose { error_code: 77 }
        ));
    }

    #[tokio::test]
    async fn outbound_connect_waiter_observes_connected_event() {
        let state = connection_state();
        let waiter = tokio::spawn({
            let state = state.clone();
            async move { wait_for_connected(&state).await }
        });
        state.connected.store(true, Ordering::Release);
        state.connected_notify.notify_one();
        waiter.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn outbound_connect_waiter_observes_shutdown() {
        let state = connection_state();
        let waiter = tokio::spawn({
            let state = state.clone();
            async move { wait_for_connected(&state).await }
        });
        state.close(ConnectionErrorIncoming::ApplicationClose { error_code: 9 });
        let err = waiter.await.unwrap().unwrap_err();
        assert!(matches!(err, AdapterError::ConnectionShutdown));
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

    #[test]
    fn stream_id_unavailable_maps_to_unknown_error() {
        let err = stream_unknown(AdapterError::StreamIdUnavailable);
        match err {
            StreamErrorIncoming::Unknown(inner) => {
                assert_eq!(inner.to_string(), "stream id lookup failed");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }
}

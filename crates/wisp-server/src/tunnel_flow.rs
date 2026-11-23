//! IP tunnels on the wisp-wt binding (extension 0xF3).
//!
//! Control rides the control bidi: `TUNNEL_OPEN` from the client, answered by
//! `TUNNEL_OPENED` with the open confirmation or by `TUNNEL_CLOSE`;
//! `TUNNEL_CAPSULES` for later control; `TUNNEL_CLOSE` from either side.
//! Packets ride datagrams of kind `IP` when both sides set DATAGRAMS and the
//! OPEN asks for them:
//!
//! ```text
//! [class:u8][kind=0x02:u8][tunnel_id:u32][frag][packet or piece]
//! ```
//!
//! with the `wisp-ip` fragment header, since a 1500-byte packet does not fit
//! one of Chrome's datagrams. Otherwise they ride one uni stream per tunnel
//! and direction: prelude `[tunnel_id:u32]`, then `[length:u16][packet]`.
//!
//! [`TunnelFlows`] holds a session's tunnels. It writes through
//! [`TunnelOutput`] and the control writer, so the session loop supplies the
//! QUIC side and tests supply channels.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::debug;
use wisp_config::WispServerOptions;
use wisp_ip::capsule::{error_code, want};
use wisp_ip::frag::{self, FragHeader, Reassembled, Reassembler};
use wisp_ip::info::flags;
use wisp_ip::{close_reason, encode_capsules, parse_capsules, Capsule, Negotiated};
use wisp_proxy::HostPolicy;
use wisp_tun::{credential_may_open, OpenRequest, Opened, Tunnel, TunnelHandle, TunnelService};
use wisp_wire::{
    datagram_class, datagram_kind, encode_tunnel_close_frame, encode_tunnel_frame, frame_type,
    TunnelClose, TunnelFrame,
};

/// Bytes of one wisp-wt datagram the server sends, header included. Chrome
/// 154's WebTransport client uses 1250-byte QUIC packets, which leave about
/// 1200 bytes for a datagram (EXTENSION.md section 6.3).
pub const TUNNEL_DATAGRAM_BYTES: usize = 1200;

/// `[class][kind][tunnel_id]` in front of every tunnel datagram.
const DATAGRAM_HEADER: usize = 6;

/// Packets a tunnel's uni stream may have queued towards the client.
pub const TUNNEL_UNI_QUEUE: usize = 256;

/// Packets at most this long ride the interactive datagram class (TCP
/// acknowledgements, DNS).
const INTERACTIVE_MAX: usize = 128;

/// Where a session's tunnel packets go towards the client.
pub trait TunnelOutput: Send + Sync + 'static {
    /// Queues one datagram; `false` when it was dropped.
    fn datagram(&self, frame: Bytes) -> bool;
    /// A writer for the uni stream that carries `tunnel_id`'s packets to the
    /// client. Each item is one encoded chunk; the writer sends the prelude.
    fn uni(&self, tunnel_id: u32) -> mpsc::Sender<Bytes>;
}

/// The connection-level facts a tunnel open needs.
#[derive(Clone)]
pub struct TunnelSession {
    pub client_ip: String,
    pub principal: Option<String>,
    pub options: Arc<WispServerOptions>,
    pub policy: Arc<HostPolicy>,
    /// Largest datagram the server accepts, header included.
    pub max_datagram_bytes: usize,
}

enum Entry {
    Opening {
        generation: u64,
        cancel: CancellationToken,
    },
    Open {
        generation: u64,
        handle: TunnelHandle,
        datagrams: bool,
        reassembler: Arc<Mutex<Reassembler>>,
        close: CancellationToken,
        detach: CancellationToken,
    },
}

impl Entry {
    fn generation(&self) -> u64 {
        match self {
            Entry::Opening { generation, .. } | Entry::Open { generation, .. } => *generation,
        }
    }
}

/// A wisp-wt session's tunnels, by tunnel id.
pub struct TunnelFlows {
    service: Arc<TunnelService>,
    negotiated: Negotiated,
    session: TunnelSession,
    control: mpsc::Sender<Bytes>,
    output: Arc<dyn TunnelOutput>,
    entries: Mutex<HashMap<u32, Entry>>,
    next_generation: AtomicU64,
    tasks: TaskTracker,
    epoch: Instant,
}

impl TunnelFlows {
    pub fn new(
        service: Arc<TunnelService>,
        negotiated: Negotiated,
        session: TunnelSession,
        control: mpsc::Sender<Bytes>,
        output: Arc<dyn TunnelOutput>,
        tasks: TaskTracker,
    ) -> Arc<Self> {
        Arc::new(Self {
            service,
            negotiated,
            session,
            control,
            output,
            entries: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            tasks,
            epoch: Instant::now(),
        })
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// What the server accepts in one datagram after `[class][kind][id]`,
    /// for the LINK capsule.
    fn max_datagram_payload(&self) -> u16 {
        u16::try_from(
            self.session
                .max_datagram_bytes
                .saturating_sub(DATAGRAM_HEADER),
        )
        .unwrap_or(u16::MAX)
    }

    /// Room for the fragment header and data in one datagram the server
    /// sends.
    fn datagram_room(&self) -> usize {
        TUNNEL_DATAGRAM_BYTES.min(self.session.max_datagram_bytes) - DATAGRAM_HEADER
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    async fn send_control(&self, frame: Bytes) {
        let _ = self.control.send(frame).await;
    }

    async fn refuse(&self, tunnel_id: u32, error: Option<Capsule>, reason: u8) {
        if let Some(capsule) = error {
            self.send_control(encode_tunnel_frame(
                frame_type::TUNNEL_CAPSULES,
                tunnel_id,
                &encode_capsules(&[capsule]),
            ))
            .await;
        }
        self.send_control(encode_tunnel_close_frame(tunnel_id, reason))
            .await;
    }

    /// `TUNNEL_OPEN` from the client.
    pub async fn on_open(self: &Arc<Self>, frame: TunnelFrame) {
        let tunnel_id = frame.tunnel_id;
        if self.entries.lock().contains_key(&tunnel_id) {
            debug!(tunnel_id, "wisp: TUNNEL_OPEN for a tunnel id in use");
            self.close_tunnel(tunnel_id, close_reason::INVALID_INFO)
                .await;
            return;
        }
        let capsules = match parse_capsules(&frame.capsules) {
            Ok(list) => list,
            Err(e) => {
                debug!(tunnel_id, error = %e, "wisp: TUNNEL_OPEN with bad capsules");
                self.refuse(tunnel_id, None, close_reason::INVALID_INFO)
                    .await;
                return;
            }
        };
        let Some(Capsule::Open { want: wanted }) = capsules.first().cloned() else {
            self.refuse(tunnel_id, None, close_reason::INVALID_INFO)
                .await;
            return;
        };
        if !credential_may_open(&self.session.options) {
            self.refuse(tunnel_id, None, close_reason::BLOCKED).await;
            return;
        }
        if self.len() >= usize::from(self.negotiated.max_tunnels) {
            let error = Capsule::Error {
                code: error_code::TOO_MANY_TUNNELS,
                message: "too many tunnels on this session".to_owned(),
            };
            self.refuse(tunnel_id, Some(error), close_reason::THROTTLED)
                .await;
            return;
        }
        let datagrams = wanted & want::DATAGRAMS != 0 && self.negotiated.has(flags::DATAGRAMS);
        let request = OpenRequest {
            want: wanted,
            resume: capsules.iter().find_map(|c| match c {
                Capsule::Resume { token } => Some(*token),
                _ => None,
            }),
            principal: self.session.principal.clone(),
            client_ip: self.session.client_ip.clone(),
            policy: self.session.policy.clone(),
            negotiated: self.negotiated,
            max_datagram_payload: if datagrams {
                self.max_datagram_payload()
            } else {
                0
            },
        };
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        self.entries.lock().insert(
            tunnel_id,
            Entry::Opening {
                generation,
                cancel: cancel.clone(),
            },
        );
        let flows = self.clone();
        self.tasks.spawn(async move {
            let result = tokio::select! {
                _ = cancel.cancelled() => return,
                result = flows.service.open(request) => result,
            };
            match result {
                Ok(opened) => flows.opened(tunnel_id, generation, opened, datagrams).await,
                Err(error) => {
                    let current = {
                        let mut entries = flows.entries.lock();
                        let current = entries
                            .get(&tunnel_id)
                            .is_some_and(|e| e.generation() == generation);
                        if current {
                            entries.remove(&tunnel_id);
                        }
                        current
                    };
                    if current {
                        debug!(tunnel_id, error = %error, "wisp: tunnel open refused");
                        flows
                            .refuse(tunnel_id, error.error_capsule(), error.close_reason())
                            .await;
                    }
                }
            }
        });
    }

    async fn opened(
        self: &Arc<Self>,
        tunnel_id: u32,
        generation: u64,
        opened: Opened,
        datagrams: bool,
    ) {
        let Opened {
            tunnel,
            confirmation,
            resumed,
        } = opened;
        let close = CancellationToken::new();
        let detach = CancellationToken::new();
        let reassembler = Arc::new(Mutex::new(Reassembler::new(usize::from(
            self.negotiated.max_packet,
        ))));
        {
            let mut entries = self.entries.lock();
            let current = matches!(
                entries.get(&tunnel_id),
                Some(Entry::Opening { generation: g, .. }) if *g == generation
            );
            if !current {
                drop(entries);
                tunnel.close();
                return;
            }
            entries.insert(
                tunnel_id,
                Entry::Open {
                    generation,
                    handle: tunnel.handle(),
                    datagrams,
                    reassembler,
                    close: close.clone(),
                    detach: detach.clone(),
                },
            );
        }
        debug!(
            tunnel_id,
            tunnel = tunnel.id(),
            resumed,
            datagrams,
            "wisp: tunnel open"
        );
        // The confirmation goes out before any packet of the tunnel.
        self.send_control(encode_tunnel_frame(
            frame_type::TUNNEL_OPENED,
            tunnel_id,
            &encode_capsules(&confirmation),
        ))
        .await;
        let sink = if datagrams {
            Sink::Datagrams {
                room: self.datagram_room(),
                fragments: self.negotiated.has(flags::FRAGMENTS),
                pkt_id: 0,
            }
        } else {
            Sink::Uni(self.output.uni(tunnel_id))
        };
        let flows = self.clone();
        self.tasks
            .spawn(flows.pump(tunnel, tunnel_id, generation, sink, close, detach));
    }

    async fn pump(
        self: Arc<Self>,
        mut tunnel: Tunnel,
        tunnel_id: u32,
        generation: u64,
        mut sink: Sink,
        close: CancellationToken,
        detach: CancellationToken,
    ) {
        let stolen = tunnel.stolen();
        tokio::pin!(stolen);
        loop {
            tokio::select! {
                biased;
                _ = close.cancelled() => {
                    tunnel.close();
                    return;
                }
                _ = detach.cancelled() => {
                    tunnel.detach();
                    return;
                }
                _ = &mut stolen => {
                    debug!(tunnel_id, "wisp: tunnel resumed on another session");
                    tunnel.detach();
                    if self.remove_if(tunnel_id, generation) {
                        self.send_control(encode_tunnel_close_frame(tunnel_id, close_reason::VOLUNTARY)).await;
                    }
                    return;
                }
                packet = tunnel.recv() => match packet {
                    Some(packet) => sink.deliver(self.output.as_ref(), tunnel_id, &packet),
                    None => {
                        tunnel.close();
                        if self.remove_if(tunnel_id, generation) {
                            self.send_control(encode_tunnel_close_frame(tunnel_id, close_reason::NETWORK_ERROR)).await;
                        }
                        return;
                    }
                },
            }
        }
    }

    fn remove_if(&self, tunnel_id: u32, generation: u64) -> bool {
        let mut entries = self.entries.lock();
        if entries
            .get(&tunnel_id)
            .is_some_and(|e| e.generation() == generation)
        {
            entries.remove(&tunnel_id);
            true
        } else {
            false
        }
    }

    /// Ends `tunnel_id` from the server's side.
    async fn close_tunnel(&self, tunnel_id: u32, reason: u8) {
        self.forget(tunnel_id);
        self.send_control(encode_tunnel_close_frame(tunnel_id, reason))
            .await;
    }

    fn forget(&self, tunnel_id: u32) {
        match self.entries.lock().remove(&tunnel_id) {
            Some(Entry::Opening { cancel, .. }) => cancel.cancel(),
            Some(Entry::Open { close, .. }) => close.cancel(),
            None => {}
        }
    }

    /// `TUNNEL_CLOSE` from the client.
    pub fn on_close(&self, frame: TunnelClose) {
        debug!(
            tunnel_id = frame.tunnel_id,
            reason = frame.reason,
            "wisp: TUNNEL_CLOSE"
        );
        self.forget(frame.tunnel_id);
    }

    /// `TUNNEL_CAPSULES` from the client: nothing a client sends later
    /// changes a version 1 tunnel, but a bad capsule or a second OPEN ends it.
    pub async fn on_capsules(&self, frame: TunnelFrame) {
        if !self.entries.lock().contains_key(&frame.tunnel_id) {
            return;
        }
        let bad = match parse_capsules(&frame.capsules) {
            Err(_) => true,
            Ok(list) => list.iter().any(|c| matches!(c, Capsule::Open { .. })),
        };
        if bad {
            self.close_tunnel(frame.tunnel_id, close_reason::INVALID_INFO)
                .await;
        }
    }

    /// A datagram of kind `IP` (after `[class][kind][tunnel_id]`).
    pub fn on_datagram(&self, tunnel_id: u32, payload: &[u8]) {
        let (handle, reassembler) = match self.entries.lock().get(&tunnel_id) {
            Some(Entry::Open {
                handle,
                datagrams: true,
                reassembler,
                ..
            }) => (handle.clone(), reassembler.clone()),
            _ => return,
        };
        let Ok((header, data)) = FragHeader::parse(payload) else {
            return;
        };
        let packet = match header {
            FragHeader::Whole => Bytes::copy_from_slice(data),
            FragHeader::Piece { .. } => {
                match reassembler.lock().push(self.now_ms(), header, data) {
                    Reassembled::Packet(p) => Bytes::from(p),
                    Reassembled::Pending | Reassembled::Discarded(_) => return,
                }
            }
        };
        handle.forward(packet);
    }

    /// Whether the client's uni stream for `tunnel_id` should be read: an
    /// open tunnel that does not use datagrams.
    pub fn accepts_uni(&self, tunnel_id: u32) -> Option<TunnelHandle> {
        match self.entries.lock().get(&tunnel_id) {
            Some(Entry::Open {
                handle,
                datagrams: false,
                ..
            }) => Some(handle.clone()),
            _ => None,
        }
    }

    /// The session is ending: open tunnels wait for a resume.
    pub fn shutdown(&self) {
        for (_, entry) in self.entries.lock().drain() {
            match entry {
                Entry::Opening { cancel, .. } => cancel.cancel(),
                Entry::Open { detach, .. } => detach.cancel(),
            }
        }
    }
}

enum Sink {
    Datagrams {
        room: usize,
        fragments: bool,
        pkt_id: u16,
    },
    Uni(mpsc::Sender<Bytes>),
}

impl Sink {
    fn deliver(&mut self, output: &dyn TunnelOutput, tunnel_id: u32, packet: &[u8]) {
        match self {
            Sink::Datagrams {
                room,
                fragments,
                pkt_id,
            } => {
                let class = if packet.len() <= INTERACTIVE_MAX {
                    datagram_class::INTERACTIVE
                } else {
                    datagram_class::NORMAL
                };
                let Ok(pieces) = frag::split(packet.len(), *room, *pkt_id) else {
                    return;
                };
                if pieces.len() > 1 {
                    if !*fragments {
                        debug!(
                            tunnel_id,
                            bytes = packet.len(),
                            "wisp: packet too large for one datagram"
                        );
                        return;
                    }
                    *pkt_id = pkt_id.wrapping_add(1);
                }
                for (header, range) in pieces {
                    let mut frame = BytesMut::with_capacity(DATAGRAM_HEADER + 3 + range.len());
                    frame.put_u8(class);
                    frame.put_u8(datagram_kind::IP);
                    frame.put_u32_le(tunnel_id);
                    let mut h = Vec::with_capacity(3);
                    header.encode(&mut h);
                    frame.extend_from_slice(&h);
                    frame.extend_from_slice(&packet[range]);
                    if !output.datagram(frame.freeze()) {
                        return;
                    }
                }
            }
            Sink::Uni(tx) => {
                let mut chunk = BytesMut::with_capacity(2 + packet.len());
                chunk.put_u16_le(packet.len() as u16);
                chunk.extend_from_slice(packet);
                let _ = tx.try_send(chunk.freeze());
            }
        }
    }
}

/// Reads a client's tunnel uni stream: the 4-byte prelude, then chunks.
#[derive(Default)]
pub struct UniDecoder {
    buf: BytesMut,
    tunnel_id: Option<u32>,
}

impl UniDecoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The tunnel id, once the prelude is in.
    pub fn tunnel_id(&mut self) -> Option<u32> {
        if self.tunnel_id.is_none() && self.buf.len() >= 4 {
            let p = self.buf.split_to(4);
            self.tunnel_id = Some(u32::from_le_bytes([p[0], p[1], p[2], p[3]]));
        }
        self.tunnel_id
    }

    /// The next whole packet, if the buffer holds one.
    pub fn next_packet(&mut self) -> Option<Bytes> {
        self.tunnel_id()?;
        if self.buf.len() < 2 {
            return None;
        }
        let len = usize::from(u16::from_le_bytes([self.buf[0], self.buf[1]]));
        if self.buf.len() < 2 + len {
            return None;
        }
        let _ = self.buf.split_to(2);
        Some(self.buf.split_to(len).freeze())
    }

    /// Bytes held waiting for the rest of a chunk.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests;

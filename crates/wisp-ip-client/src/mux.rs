//! Tunnels on one Wisp connection, on either binding.
//!
//! A [`Mux`] speaks the client's half of the connection: the handshake that
//! negotiates `IP_TUNNEL`, the open of each tunnel and its confirmation, later
//! control, packets, and closes.
//!
//! - **WebSocket** (Wisp v2, section 6.1). The server sends INFO first; the
//!   client answers with its own 0xF3 entry and waits for CONTINUE on stream
//!   0. A tunnel lives on a stream id: `TUNNEL` packets carry capsules, each
//!   `DATA` is one IP packet, `CLOSE` ends it. The client must offer
//!   `Sec-WebSocket-Protocol: wisp-v2`, or wisp-rust's `Auto` mode speaks v1,
//!   which has no extensions.
//! - **WebTransport** (wisp-wt, section 6.2). The client sends INFO first on
//!   the control bidi; the server answers INFO and READY. Tunnels use the
//!   frames `TUNNEL_OPEN`, `TUNNEL_OPENED`, `TUNNEL_CLOSE` and
//!   `TUNNEL_CAPSULES`. Packets ride datagrams of kind `IP` with the fragment
//!   header (section 6.3), split to the session's live datagram limit, or one
//!   uni stream per direction when the session or the relay has no
//!   datagrams. The client's uni stream is opened as soon as the tunnel is
//!   confirmed, with its 4-byte prelude written alone, because the h3
//!   revision wisp-rust pins parses a uni stream's session id only once more
//!   bytes follow its header (LS-5 finding 1): the first packet then
//!   unblocks the stream instead of waiting behind it. Packets of the first
//!   [`UNI_PRELUDE_GAP_MS`] wait, so that the transport cannot coalesce
//!   the first one with the prelude into the receive the bug stalls.
//!
//! The mux does no I/O. The carrier passes in what it receives and sends
//! what [`Mux::poll_transmit`] yields; [`Mux::poll_event`] reports what
//! happened to the connection and its tunnels.

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use wisp_ip::capsule::want;
use wisp_ip::frag::{self, FragHeader, Reassembled, Reassembler, REASSEMBLY_TIMEOUT_MS};
use wisp_ip::info::{flags, ClientInfo, InfoError, Negotiated, ServerInfo};
use wisp_ip::{
    close_reason, encode_capsules, parse_capsules, Capsule, LinkParams, ResumeToken, EXTENSION_ID,
    VERSION,
};
use wisp_wire::{datagram_class, datagram_kind, frame_type};

use crate::{DATAGRAM_HEADER, INTERACTIVE_MAX};

/// Longest wisp-wt control frame the client accepts. Version 1 frames are a
/// few hundred bytes; this only stops a broken peer from growing the buffer.
pub const MAX_CONTROL_FRAME: usize = 1 << 20;

/// Bytes an incoming uni stream may hold before a chunk completes: one
/// largest chunk and its length.
const MAX_UNI_BUFFER: usize = 2 + u16::MAX as usize;

/// How long a new outgoing uni stream holds its packets after the prelude.
/// A packet written right behind the prelude can leave in the same QUIC
/// packet, and the relay's h3 then holds the header, the prelude and that
/// packet until more bytes arrive (seen as a 10 s stall under load).
pub const UNI_PRELUDE_GAP_MS: u64 = 50;

/// Packets a uni stream holds during the gap; more are dropped.
const MAX_UNI_HELD: usize = 64;

/// The connection a mux runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// Wisp v2 over a WebSocket: one binary message per Wisp packet.
    WebSocket,
    /// wisp-wt over a WebTransport session. `max_datagram_size` is the
    /// session's live limit for one datagram (`maxDatagramSize` in a
    /// browser); 0 or `datagrams: false` means packets ride uni streams.
    WebTransport {
        datagrams: bool,
        max_datagram_size: usize,
    },
}

impl Carrier {
    pub fn is_webtransport(&self) -> bool {
        matches!(self, Carrier::WebTransport { .. })
    }
}

/// What the carrier is to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transmit {
    /// One binary WebSocket message (one Wisp v2 packet).
    Ws(Vec<u8>),
    /// Bytes for the wisp-wt control bidi: whole frames, back to back.
    WtControl(Vec<u8>),
    /// One WebTransport datagram.
    WtDatagram(Vec<u8>),
    /// Open the uni stream that carries `tunnel_id`'s packets to the relay
    /// and write `prelude` on it as a write of its own, before any chunk.
    WtUniOpen { tunnel_id: u32, prelude: [u8; 4] },
    /// One `[length:u16][packet]` chunk for `tunnel_id`'s uni stream.
    WtUniChunk { tunnel_id: u32, chunk: Vec<u8> },
    /// Finish `tunnel_id`'s uni stream.
    WtUniFinish { tunnel_id: u32 },
    /// End the connection.
    Close,
}

/// Why the relay cannot carry tunnels on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// The server answered as Wisp v1 (no INFO, so no extensions). The
    /// WebSocket did not offer, or the server did not take, `wisp-v2`.
    WispV1,
    /// The server's INFO has no 0xF3 entry: a relay without the extension.
    NoExtension,
    /// The server's 0xF3 entry does not carry the magic or valid limits.
    BadEntry(InfoError),
    /// The server's version range does not contain version 1.
    Version { min: u8, max: u8 },
    /// Neither IPv4 nor IPv6 is offered and wanted on both sides.
    NoFamily,
}

/// What happened on the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxEvent {
    /// The handshake finished with the extension negotiated.
    Ready(Negotiated),
    /// The handshake finished without it. The mux has asked to close.
    Unsupported(Unsupported),
    /// The tunnel's open confirmation: every capsule of it, in order.
    Opened { id: u32, capsules: Vec<Capsule> },
    /// Later control from the relay (a new `ADDRESS_ASSIGN`, a rotated
    /// `RESUME_TOKEN`, ...).
    Control { id: u32, capsules: Vec<Capsule> },
    /// One IP packet for the machine.
    Packet { id: u32, packet: Vec<u8> },
    /// The tunnel is gone: refused, or closed by either side. `error` is the
    /// `ERROR` capsule that preceded the close, if any.
    Closed {
        id: u32,
        reason: u8,
        error: Option<(u16, String)>,
    },
    /// The relay ended the whole connection, or broke the protocol. The mux
    /// has asked to close.
    ConnectionFailed(String),
}

/// What the client asks the relay for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wants {
    pub ipv4: bool,
    pub ipv6: bool,
    pub resume: bool,
    pub icmp_echo: bool,
}

impl Default for Wants {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            resume: true,
            icmp_echo: true,
        }
    }
}

impl Wants {
    fn flags(&self, carrier: Carrier) -> u16 {
        let mut f = 0;
        if self.ipv4 {
            f |= flags::IPV4;
        }
        if self.ipv6 {
            f |= flags::IPV6;
        }
        if self.resume {
            f |= flags::RESUME;
        }
        if self.icmp_echo {
            f |= flags::ICMP_ECHO;
        }
        if let Carrier::WebTransport {
            datagrams: true, ..
        } = carrier
        {
            f |= flags::DATAGRAMS | flags::FRAGMENTS;
        }
        f
    }
}

/// Counters for tests and diagnostics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MuxStats {
    pub packets_out: u64,
    pub packets_in: u64,
    pub datagrams_out: u64,
    /// Packets sent as more than one datagram.
    pub split_out: u64,
    /// Packets received in pieces and put back together.
    pub reassembled_in: u64,
    /// Packets not sent: too large for the tunnel, or no room to split.
    pub dropped_out: u64,
    /// Pieces or packets thrown away on receipt.
    pub dropped_in: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    WsAwaitInfo,
    WsAwaitContinue,
    WtAwaitInfo,
    WtAwaitReady,
    Ready,
    /// Unsupported or failed: everything further is ignored.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelState {
    Opening,
    Open,
}

struct MuxTunnel {
    state: TunnelState,
    /// Whether the open asked for datagrams.
    want_datagrams: bool,
    /// Packets ride datagrams (else uni streams on WT; DATA on WS).
    datagrams: bool,
    max_packet: usize,
    max_datagram_payload: usize,
    pkt_id: u16,
    reassembler: Reassembler,
    uni_open: bool,
    /// Until when the uni stream holds its packets (see [`UNI_PRELUDE_GAP_MS`]).
    uni_hold_until: Option<u64>,
    uni_held: VecDeque<Vec<u8>>,
    /// An `ERROR` capsule waiting for the CLOSE it explains.
    error: Option<(u16, String)>,
}

struct UniIn {
    buf: Vec<u8>,
    tunnel_id: Option<u32>,
    /// A stream for no tunnel of ours: read and thrown away.
    ignored: bool,
}

/// One Wisp connection's tunnels. See the module documentation.
pub struct Mux {
    wants: Wants,
    carrier: Option<Carrier>,
    phase: Phase,
    client_flags: u16,
    server: Option<ServerInfo>,
    negotiated: Option<Negotiated>,
    tunnels: BTreeMap<u32, MuxTunnel>,
    next_id: u32,
    control: Vec<u8>,
    uni_in: BTreeMap<u64, UniIn>,
    max_datagram_size: usize,
    reassembly_check: Option<u64>,
    /// The time of the latest call that carried one.
    now_ms: u64,
    transmits: VecDeque<Transmit>,
    events: VecDeque<MuxEvent>,
    stats: MuxStats,
}

impl Mux {
    pub fn new(wants: Wants) -> Self {
        Self {
            wants,
            carrier: None,
            phase: Phase::Idle,
            client_flags: 0,
            server: None,
            negotiated: None,
            tunnels: BTreeMap::new(),
            next_id: 1,
            control: Vec::new(),
            uni_in: BTreeMap::new(),
            max_datagram_size: 0,
            reassembly_check: None,
            now_ms: 0,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            stats: MuxStats::default(),
        }
    }

    pub fn stats(&self) -> MuxStats {
        self.stats
    }

    pub fn carrier(&self) -> Option<Carrier> {
        self.carrier
    }

    pub fn negotiated(&self) -> Option<Negotiated> {
        self.negotiated
    }

    /// Whether the handshake is done and tunnels can be opened.
    pub fn is_ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<MuxEvent> {
        self.events.pop_front()
    }

    /// Datagram room for the fragment header and data of one packet of
    /// `id`: the live datagram limit and the relay's limit, less the
    /// `[class][kind][tunnel_id]` header.
    pub fn datagram_room(&self, id: u32) -> Option<usize> {
        let t = self.tunnels.get(&id)?;
        if !t.datagrams {
            return None;
        }
        let limit = self
            .max_datagram_size
            .min(DATAGRAM_HEADER + t.max_datagram_payload);
        Some(limit.saturating_sub(DATAGRAM_HEADER))
    }

    /// The carrier is connected. On WebTransport the client speaks first.
    pub fn connected(&mut self, carrier: Carrier) {
        self.reset();
        self.carrier = Some(carrier);
        self.client_flags = self.wants.flags(carrier);
        match carrier {
            Carrier::WebSocket => self.phase = Phase::WsAwaitInfo,
            Carrier::WebTransport {
                max_datagram_size, ..
            } => {
                self.max_datagram_size = max_datagram_size;
                let entry = wisp_wire::ExtensionEntry {
                    id: EXTENSION_ID,
                    payload: Bytes::from(self.client_entry().encode()),
                };
                self.transmits.push_back(Transmit::WtControl(
                    wisp_wire::encode_info_frame(&[entry]).to_vec(),
                ));
                self.phase = Phase::WtAwaitInfo;
            }
        }
    }

    /// The carrier is gone. Every tunnel and buffer is forgotten; the
    /// caller decides what to resume.
    pub fn disconnected(&mut self) {
        self.reset();
    }

    fn reset(&mut self) {
        self.carrier = None;
        self.phase = Phase::Idle;
        self.server = None;
        self.negotiated = None;
        self.tunnels.clear();
        self.control.clear();
        self.uni_in.clear();
        self.reassembly_check = None;
        self.transmits.clear();
        self.next_id = 1;
    }

    /// The session's live datagram limit changed.
    pub fn set_max_datagram_size(&mut self, size: usize) {
        self.max_datagram_size = size;
    }

    fn client_entry(&self) -> ClientInfo {
        ClientInfo {
            version: VERSION,
            flags: self.client_flags,
        }
    }

    fn fail(&mut self, why: String) {
        self.phase = Phase::Done;
        self.tunnels.clear();
        self.events.push_back(MuxEvent::ConnectionFailed(why));
        self.transmits.push_back(Transmit::Close);
    }

    fn unsupported(&mut self, why: Unsupported) {
        self.phase = Phase::Done;
        self.events.push_back(MuxEvent::Unsupported(why));
        self.transmits.push_back(Transmit::Close);
    }

    /// Checks the server's entry against what the client offers and
    /// records the agreement.
    fn agree(&mut self, entry: Option<&[u8]>) -> Result<Negotiated, Unsupported> {
        let payload = entry.ok_or(Unsupported::NoExtension)?;
        let server = ServerInfo::parse(payload).map_err(Unsupported::BadEntry)?;
        if VERSION < server.ver_min || VERSION > server.ver_max {
            return Err(Unsupported::Version {
                min: server.ver_min,
                max: server.ver_max,
            });
        }
        let neg = Negotiated {
            version: VERSION,
            flags: self.client_flags & server.flags & flags::KNOWN,
            max_tunnels: server.max_tunnels,
            link_mtu: server.link_mtu,
            max_packet: server.max_packet,
        };
        if !neg.has(flags::IPV4) && !neg.has(flags::IPV6) {
            return Err(Unsupported::NoFamily);
        }
        self.server = Some(server);
        Ok(neg)
    }

    // ---- WebSocket binding -------------------------------------------------

    /// One binary WebSocket message from the relay.
    pub fn ws_message(&mut self, now_ms: u64, message: &[u8]) {
        self.now_ms = now_ms;
        if self.carrier != Some(Carrier::WebSocket) || self.phase == Phase::Done {
            return;
        }
        let packet = match wisp_wisp::parse_packet(Bytes::copy_from_slice(message)) {
            Ok(p) => p,
            Err(e) => {
                self.fail(format!("bad Wisp packet from the relay: {e}"));
                return;
            }
        };
        use wisp_wisp::WispPacket as P;
        match (self.phase, packet) {
            (Phase::WsAwaitInfo, P::Info(info)) => {
                let entries = match wisp_wisp::parse_extensions(info.extensions) {
                    Ok(e) => e,
                    Err(e) => {
                        self.fail(format!("bad INFO from the relay: {e}"));
                        return;
                    }
                };
                let ours = entries
                    .iter()
                    .find(|e| e.id == EXTENSION_ID)
                    .map(|e| e.payload.as_ref());
                match self.agree(ours) {
                    Ok(neg) => {
                        let entry = wisp_wisp::ExtensionEntry {
                            id: EXTENSION_ID,
                            payload: Bytes::from(self.client_entry().encode()),
                        };
                        self.transmits.push_back(Transmit::Ws(
                            wisp_wisp::encode_info(2, 0, &[entry]).to_vec(),
                        ));
                        self.negotiated = Some(neg);
                        self.phase = Phase::WsAwaitContinue;
                    }
                    Err(why) => {
                        // Answer the INFO so the server's handshake completes
                        // cleanly, then leave.
                        self.transmits
                            .push_back(Transmit::Ws(wisp_wisp::encode_info(2, 0, &[]).to_vec()));
                        self.unsupported(why);
                    }
                }
            }
            (Phase::WsAwaitInfo, P::Continue(c)) if c.stream_id == 0 => {
                self.unsupported(Unsupported::WispV1);
            }
            (Phase::WsAwaitContinue, P::Continue(c)) if c.stream_id == 0 => {
                self.phase = Phase::Ready;
                let neg = self.negotiated.expect("set with the INFO answer");
                self.events.push_back(MuxEvent::Ready(neg));
            }
            (_, P::Close(c)) if c.stream_id == 0 => {
                self.fail(format!(
                    "the relay closed the connection (reason {:#04x})",
                    c.reason
                ));
            }
            (Phase::Ready, P::Tunnel(t)) => self.on_tunnel_capsules(t.stream_id, &t.capsules, true),
            (Phase::Ready, P::Data(d)) => {
                let open = self
                    .tunnels
                    .get(&d.stream_id)
                    .is_some_and(|t| t.state == TunnelState::Open);
                if open {
                    self.deliver(d.stream_id, d.payload.to_vec());
                } else {
                    self.stats.dropped_in += 1;
                }
            }
            (Phase::Ready, P::Close(c)) => self.on_tunnel_close(c.stream_id, c.reason),
            (Phase::Ready, P::Continue(_)) => {
                // A tunnel draws no CONTINUE (section 6.1); nothing else of
                // ours has credit. Ignored.
            }
            (phase, other) => {
                self.fail(format!(
                    "unexpected Wisp packet {:?} in phase {phase:?}",
                    packet_name(&other)
                ));
            }
        }
    }

    // ---- WebTransport binding ----------------------------------------------

    /// Bytes read from the wisp-wt control bidi.
    pub fn wt_control(&mut self, now_ms: u64, bytes: &[u8]) {
        self.now_ms = now_ms;
        if !matches!(self.carrier, Some(Carrier::WebTransport { .. })) || self.phase == Phase::Done
        {
            return;
        }
        self.control.extend_from_slice(bytes);
        loop {
            if self.control.len() < 4 {
                return;
            }
            let len = u32::from_le_bytes([
                self.control[0],
                self.control[1],
                self.control[2],
                self.control[3],
            ]) as usize;
            if len == 0 || len > MAX_CONTROL_FRAME {
                self.fail(format!("control frame of {len} bytes"));
                return;
            }
            if self.control.len() < 4 + len {
                return;
            }
            let body: Vec<u8> = self.control.drain(..4 + len).skip(4).collect();
            self.on_wt_frame(now_ms, body[0], &body[1..]);
            if self.phase == Phase::Done {
                return;
            }
        }
    }

    fn on_wt_frame(&mut self, _now_ms: u64, ty: u8, payload: &[u8]) {
        match (self.phase, ty) {
            (Phase::WtAwaitInfo, frame_type::INFO) => {
                let entries = match wisp_wire::parse_extensions(payload) {
                    Ok(e) => e,
                    Err(e) => {
                        self.fail(format!("bad INFO from the relay: {e}"));
                        return;
                    }
                };
                let ours = entries
                    .iter()
                    .find(|e| e.id == EXTENSION_ID)
                    .map(|e| e.payload.to_vec());
                match self.agree(ours.as_deref()) {
                    Ok(neg) => {
                        self.negotiated = Some(neg);
                        self.phase = Phase::WtAwaitReady;
                    }
                    Err(why) => self.unsupported(why),
                }
            }
            (Phase::WtAwaitReady, frame_type::READY) => {
                self.phase = Phase::Ready;
                let neg = self.negotiated.expect("set with the INFO");
                self.events.push_back(MuxEvent::Ready(neg));
            }
            (_, frame_type::CLOSE) => {
                let reason = payload.first().copied().unwrap_or(0);
                self.fail(format!(
                    "the relay closed the session (reason {reason:#04x})"
                ));
            }
            (Phase::Ready, frame_type::TUNNEL_OPENED)
            | (Phase::Ready, frame_type::TUNNEL_CAPSULES) => {
                match wisp_wire::parse_tunnel_payload(payload) {
                    Ok(frame) => {
                        if ty == frame_type::TUNNEL_OPENED
                            && self
                                .tunnels
                                .get(&frame.tunnel_id)
                                .is_some_and(|t| t.state != TunnelState::Opening)
                        {
                            self.close_tunnel(frame.tunnel_id, close_reason::INVALID_INFO);
                            return;
                        }
                        let confirmation = ty == frame_type::TUNNEL_OPENED;
                        self.on_tunnel_capsules_wt(frame.tunnel_id, &frame.capsules, confirmation);
                    }
                    Err(e) => self.fail(format!("bad tunnel frame: {e}")),
                }
            }
            (Phase::Ready, frame_type::TUNNEL_CLOSE) => {
                match wisp_wire::parse_tunnel_close_payload(payload) {
                    Ok(c) => self.on_tunnel_close(c.tunnel_id, c.reason),
                    Err(e) => self.fail(format!("bad TUNNEL_CLOSE: {e}")),
                }
            }
            (Phase::Ready, frame_type::TUNNEL_OPEN) => {
                self.fail("the relay sent TUNNEL_OPEN".to_owned());
            }
            (Phase::Ready, _) => {
                // CONTROL text and frames of extensions this client never
                // negotiates: nothing for tunnels.
            }
            (phase, ty) => self.fail(format!("control frame {ty:#04x} in phase {phase:?}")),
        }
    }

    /// One WebTransport datagram.
    pub fn wt_datagram(&mut self, now_ms: u64, datagram: &[u8]) {
        if self.phase != Phase::Ready || datagram.len() < DATAGRAM_HEADER {
            return;
        }
        if datagram[1] != datagram_kind::IP {
            return;
        }
        let id = u32::from_le_bytes([datagram[2], datagram[3], datagram[4], datagram[5]]);
        let Some(t) = self.tunnels.get_mut(&id) else {
            self.stats.dropped_in += 1;
            return;
        };
        if t.state != TunnelState::Open || !t.datagrams {
            self.stats.dropped_in += 1;
            return;
        }
        let Ok((header, data)) = FragHeader::parse(&datagram[DATAGRAM_HEADER..]) else {
            self.stats.dropped_in += 1;
            return;
        };
        let pieced = matches!(header, FragHeader::Piece { .. });
        match t.reassembler.push(now_ms, header, data) {
            Reassembled::Packet(p) => {
                if pieced {
                    self.stats.reassembled_in += 1;
                }
                self.deliver(id, p);
            }
            Reassembled::Pending => {
                self.reassembly_check
                    .get_or_insert(now_ms + REASSEMBLY_TIMEOUT_MS);
            }
            Reassembled::Discarded(_) => self.stats.dropped_in += 1,
        }
    }

    /// Bytes read from an incoming uni stream; `stream` is any handle the
    /// carrier uses to tell its streams apart.
    pub fn wt_uni(&mut self, stream: u64, bytes: &[u8]) {
        if self.phase != Phase::Ready {
            return;
        }
        let entry = self.uni_in.entry(stream).or_insert_with(|| UniIn {
            buf: Vec::new(),
            tunnel_id: None,
            ignored: false,
        });
        if entry.ignored {
            return;
        }
        entry.buf.extend_from_slice(bytes);
        let mut packets = Vec::new();
        let mut ignore = false;
        loop {
            let Some(id) = entry.tunnel_id.or_else(|| {
                (entry.buf.len() >= 4).then(|| {
                    let id = u32::from_le_bytes([
                        entry.buf[0],
                        entry.buf[1],
                        entry.buf[2],
                        entry.buf[3],
                    ]);
                    entry.buf.drain(..4);
                    id
                })
            }) else {
                break;
            };
            entry.tunnel_id = Some(id);
            let accepts = self
                .tunnels
                .get(&id)
                .is_some_and(|t| t.state == TunnelState::Open && !t.datagrams);
            if !accepts {
                // A WT-proxy reply or a stream for a tunnel we no longer
                // have (LS-5 finding 2): not ours to read.
                ignore = true;
                break;
            }
            if entry.buf.len() < 2 {
                break;
            }
            let len = usize::from(u16::from_le_bytes([entry.buf[0], entry.buf[1]]));
            if entry.buf.len() < 2 + len {
                break;
            }
            let packet = entry.buf[2..2 + len].to_vec();
            entry.buf.drain(..2 + len);
            packets.push((id, packet));
        }
        if ignore || entry.buf.len() > MAX_UNI_BUFFER {
            entry.ignored = true;
            entry.buf = Vec::new();
        }
        for (id, packet) in packets {
            self.deliver(id, packet);
        }
    }

    /// An incoming uni stream ended.
    pub fn wt_uni_end(&mut self, stream: u64) {
        self.uni_in.remove(&stream);
    }

    // ---- Tunnels -----------------------------------------------------------

    /// Opens a tunnel and returns its id. `None` before the handshake is
    /// done or when the relay's tunnel limit is reached.
    pub fn open(
        &mut self,
        want_v4: bool,
        want_v6: bool,
        resume: Option<ResumeToken>,
    ) -> Option<u32> {
        if self.phase != Phase::Ready {
            return None;
        }
        let neg = self.negotiated?;
        if self.tunnels.len() >= usize::from(neg.max_tunnels) {
            return None;
        }
        let mut w = 0u16;
        if want_v4 && neg.has(flags::IPV4) {
            w |= want::IPV4;
        }
        if want_v6 && neg.has(flags::IPV6) {
            w |= want::IPV6;
        }
        if w == 0 {
            return None;
        }
        let datagrams = matches!(
            self.carrier,
            Some(Carrier::WebTransport {
                datagrams: true,
                ..
            })
        ) && neg.has(flags::DATAGRAMS)
            && self.max_datagram_size > DATAGRAM_HEADER;
        if datagrams {
            w |= want::DATAGRAMS;
        }
        let id = self.allocate_id();
        let mut capsules = vec![Capsule::Open { want: w }];
        if let Some(token) = resume.filter(|_| neg.has(flags::RESUME)) {
            capsules.push(Capsule::Resume { token });
        }
        let body = encode_capsules(&capsules);
        let tx = match self.carrier {
            Some(Carrier::WebSocket) => Transmit::Ws(wisp_wisp::encode_tunnel(id, &body).to_vec()),
            _ => Transmit::WtControl(
                wisp_wire::encode_tunnel_frame(frame_type::TUNNEL_OPEN, id, &body).to_vec(),
            ),
        };
        self.transmits.push_back(tx);
        self.tunnels.insert(
            id,
            MuxTunnel {
                state: TunnelState::Opening,
                want_datagrams: datagrams,
                datagrams: false,
                max_packet: usize::from(neg.max_packet),
                max_datagram_payload: 0,
                pkt_id: 0,
                reassembler: Reassembler::new(usize::from(neg.max_packet)),
                uni_open: false,
                uni_hold_until: None,
                uni_held: VecDeque::new(),
                error: None,
            },
        );
        Some(id)
    }

    fn allocate_id(&mut self) -> u32 {
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.checked_add(1).unwrap_or(1);
            if id != 0 && !self.tunnels.contains_key(&id) {
                return id;
            }
        }
    }

    /// Closes a tunnel from the client's side.
    pub fn close(&mut self, id: u32, reason: u8) {
        if self.tunnels.contains_key(&id) {
            self.close_tunnel(id, reason);
        }
    }

    fn close_tunnel(&mut self, id: u32, reason: u8) {
        let Some(t) = self.tunnels.remove(&id) else {
            return;
        };
        match self.carrier {
            Some(Carrier::WebSocket) => self
                .transmits
                .push_back(Transmit::Ws(wisp_wisp::encode_close(id, reason).to_vec())),
            Some(Carrier::WebTransport { .. }) => {
                if t.uni_open {
                    self.transmits
                        .push_back(Transmit::WtUniFinish { tunnel_id: id });
                }
                self.transmits.push_back(Transmit::WtControl(
                    wisp_wire::encode_tunnel_close_frame(id, reason).to_vec(),
                ));
            }
            None => {}
        }
        self.events.push_back(MuxEvent::Closed {
            id,
            reason,
            error: None,
        });
    }

    fn on_tunnel_close(&mut self, id: u32, reason: u8) {
        let Some(t) = self.tunnels.remove(&id) else {
            return;
        };
        if t.uni_open {
            self.transmits
                .push_back(Transmit::WtUniFinish { tunnel_id: id });
        }
        self.events.push_back(MuxEvent::Closed {
            id,
            reason,
            error: t.error,
        });
    }

    fn on_tunnel_capsules_wt(&mut self, id: u32, body: &[u8], confirmation: bool) {
        let state = self.tunnels.get(&id).map(|t| t.state);
        match (state, confirmation) {
            (Some(TunnelState::Opening), true) => self.on_tunnel_capsules(id, body, true),
            // TUNNEL_CAPSULES while opening carries the ERROR of a refusal.
            (Some(TunnelState::Opening), false) => self.on_refusal_capsules(id, body),
            (Some(TunnelState::Open), false) => self.on_tunnel_capsules(id, body, false),
            _ => {}
        }
    }

    /// `TUNNEL` (WS) or `TUNNEL_OPENED`/`TUNNEL_CAPSULES` (WT) capsules for
    /// `id`. On WS, `may_confirm` is true and the tunnel's state decides.
    fn on_tunnel_capsules(&mut self, id: u32, body: &[u8], may_confirm: bool) {
        let Some(state) = self.tunnels.get(&id).map(|t| t.state) else {
            return;
        };
        let capsules = match parse_capsules(body) {
            Ok(c) => c,
            Err(_) => {
                self.close_tunnel(id, close_reason::INVALID_INFO);
                return;
            }
        };
        if capsules.iter().any(|c| {
            matches!(
                c,
                Capsule::Open { .. } | Capsule::AddressRequest(_) | Capsule::Resume { .. }
            )
        }) {
            self.close_tunnel(id, close_reason::INVALID_INFO);
            return;
        }
        if state == TunnelState::Opening && may_confirm {
            let link = capsules.iter().find_map(|c| match c {
                Capsule::Link(l) => Some(*l),
                _ => None,
            });
            let has_addresses = capsules
                .iter()
                .any(|c| matches!(c, Capsule::AddressAssign(_)));
            let has_routes = capsules
                .iter()
                .any(|c| matches!(c, Capsule::RouteAdvertisement(_)));
            match link {
                Some(link) if has_addresses && has_routes => {
                    self.confirm(id, link);
                    self.events.push_back(MuxEvent::Opened { id, capsules });
                }
                _ if capsules.iter().all(|c| matches!(c, Capsule::Error { .. })) => {
                    self.on_refusal_capsules(id, body);
                }
                _ => self.close_tunnel(id, close_reason::INVALID_INFO),
            }
            return;
        }
        if state == TunnelState::Open {
            self.events.push_back(MuxEvent::Control { id, capsules });
        }
    }

    fn on_refusal_capsules(&mut self, id: u32, body: &[u8]) {
        let Ok(capsules) = parse_capsules(body) else {
            self.close_tunnel(id, close_reason::INVALID_INFO);
            return;
        };
        if let Some(t) = self.tunnels.get_mut(&id) {
            for c in capsules {
                if let Capsule::Error { code, message } = c {
                    t.error = Some((code, message));
                }
            }
        }
    }

    fn confirm(&mut self, id: u32, link: LinkParams) {
        let is_wt = self.carrier.is_some_and(|c| c.is_webtransport());
        let neg_max = self
            .negotiated
            .map(|n| n.max_packet)
            .unwrap_or(link.max_packet);
        let Some(t) = self.tunnels.get_mut(&id) else {
            return;
        };
        t.state = TunnelState::Open;
        t.max_packet = usize::from(neg_max.min(link.max_packet));
        t.reassembler = Reassembler::new(t.max_packet);
        t.max_datagram_payload = usize::from(link.max_datagram_payload);
        t.datagrams = is_wt && t.want_datagrams && link.max_datagram_payload > 0;
        if is_wt && !t.datagrams {
            t.uni_open = true;
            t.uni_hold_until = Some(self.now_ms + UNI_PRELUDE_GAP_MS);
            self.transmits.push_back(Transmit::WtUniOpen {
                tunnel_id: id,
                prelude: id.to_le_bytes(),
            });
        }
    }

    fn deliver(&mut self, id: u32, packet: Vec<u8>) {
        self.stats.packets_in += 1;
        self.events.push_back(MuxEvent::Packet { id, packet });
    }

    /// Sends one IP packet on `id`. Returns `false` when it was dropped:
    /// the tunnel is not open, the packet is larger than the tunnel takes,
    /// or it needs pieces the relay does not accept.
    pub fn send_packet(&mut self, now_ms: u64, id: u32, packet: &[u8]) -> bool {
        self.now_ms = now_ms;
        let room = self.datagram_room(id);
        let fragments = self.negotiated.is_some_and(|n| n.has(flags::FRAGMENTS));
        let carrier = self.carrier;
        let Some(t) = self.tunnels.get_mut(&id) else {
            return false;
        };
        if t.state != TunnelState::Open || packet.is_empty() || packet.len() > t.max_packet {
            self.stats.dropped_out += 1;
            return false;
        }
        match carrier {
            Some(Carrier::WebSocket) => {
                self.transmits
                    .push_back(Transmit::Ws(wisp_wisp::encode_data(id, packet).to_vec()));
            }
            Some(Carrier::WebTransport { .. }) if t.datagrams => {
                let room = room.unwrap_or(0);
                let Ok(pieces) = frag::split(packet.len(), room, t.pkt_id) else {
                    self.stats.dropped_out += 1;
                    return false;
                };
                if pieces.len() > 1 {
                    if !fragments {
                        self.stats.dropped_out += 1;
                        return false;
                    }
                    t.pkt_id = t.pkt_id.wrapping_add(1);
                    self.stats.split_out += 1;
                }
                let class = if packet.len() <= INTERACTIVE_MAX {
                    datagram_class::INTERACTIVE
                } else {
                    datagram_class::NORMAL
                };
                for (header, range) in pieces {
                    let mut d = Vec::with_capacity(DATAGRAM_HEADER + 3 + range.len());
                    d.push(class);
                    d.push(datagram_kind::IP);
                    d.extend_from_slice(&id.to_le_bytes());
                    header.encode(&mut d);
                    d.extend_from_slice(&packet[range]);
                    self.stats.datagrams_out += 1;
                    self.transmits.push_back(Transmit::WtDatagram(d));
                }
            }
            Some(Carrier::WebTransport { .. }) => {
                let mut chunk = Vec::with_capacity(2 + packet.len());
                chunk.extend_from_slice(&(packet.len() as u16).to_le_bytes());
                chunk.extend_from_slice(packet);
                match t.uni_hold_until {
                    Some(until) if now_ms < until => {
                        if t.uni_held.len() >= MAX_UNI_HELD {
                            self.stats.dropped_out += 1;
                            return false;
                        }
                        t.uni_held.push_back(chunk);
                    }
                    Some(_) => {
                        t.uni_hold_until = None;
                        for held in t.uni_held.drain(..) {
                            self.transmits.push_back(Transmit::WtUniChunk {
                                tunnel_id: id,
                                chunk: held,
                            });
                        }
                        self.transmits.push_back(Transmit::WtUniChunk {
                            tunnel_id: id,
                            chunk,
                        });
                    }
                    None => self.transmits.push_back(Transmit::WtUniChunk {
                        tunnel_id: id,
                        chunk,
                    }),
                }
            }
            None => return false,
        }
        self.stats.packets_out += 1;
        true
    }

    /// The earliest time [`Self::handle_timeout`] has work.
    pub fn poll_timeout(&self) -> Option<u64> {
        let held = self
            .tunnels
            .values()
            .filter(|t| !t.uni_held.is_empty())
            .filter_map(|t| t.uni_hold_until)
            .min();
        [self.reassembly_check, held].into_iter().flatten().min()
    }

    /// Sends the packets a new uni stream held, and drops incomplete
    /// packets that waited too long for their last piece.
    pub fn handle_timeout(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        for (id, t) in self.tunnels.iter_mut() {
            if t.uni_hold_until.is_some_and(|until| now_ms >= until) {
                t.uni_hold_until = None;
                for chunk in t.uni_held.drain(..) {
                    self.transmits.push_back(Transmit::WtUniChunk {
                        tunnel_id: *id,
                        chunk,
                    });
                }
            }
        }
        let Some(at) = self.reassembly_check else {
            return;
        };
        if now_ms < at {
            return;
        }
        let mut pending = false;
        for t in self.tunnels.values_mut() {
            let before = t.reassembler.dropped();
            t.reassembler.expire(now_ms);
            self.stats.dropped_in += t.reassembler.dropped() - before;
            pending |= t.reassembler.pending() > 0;
        }
        self.reassembly_check = pending.then_some(now_ms + REASSEMBLY_TIMEOUT_MS);
    }
}

fn packet_name(p: &wisp_wisp::WispPacket) -> &'static str {
    use wisp_wisp::WispPacket as P;
    match p {
        P::Connect(_) => "CONNECT",
        P::Data(_) => "DATA",
        P::Continue(_) => "CONTINUE",
        P::Close(_) => "CLOSE",
        P::Info(_) => "INFO",
        P::Fin(_) => "FIN",
        P::Tunnel(_) => "TUNNEL",
    }
}

#[cfg(test)]
mod tests;

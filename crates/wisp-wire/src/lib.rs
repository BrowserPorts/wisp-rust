//! wisp-wt frame and stream encoders.
//!
//! Four negotiable extensions ([`extension::UDP`],
//! [`extension::WEBTRANSPORT_PROXY`], [`extension::WISP_PROXY_CONTROL`],
//! [`extension::IP_TUNNEL`]) gate wisp-specific routing features. Everything else (stream priority,
//! datagram priority class, server→client uni responses, per-flow UDP uni
//! streams) is baked into the base protocol unconditionally — every
//! spec-compliant WebTransport server can do them, so there is nothing to
//! negotiate.
//!
//! All multi-byte integers are little-endian.
//!
//! ### Frame layout
//!
//! ```text
//! [bodyLen:u32 LE][type:u8][payload:bodyLen-1 bytes]
//! ```
//!
//! ### INFO payload
//!
//! ```text
//! [extensions: ([id:u8][len:u32 LE][payload])* ]
//! ```
//!
//! ### Datagrams (always class- and kind-prefixed)
//!
//! ```text
//! [class:u8][kind:u8][flowId:u32 LE][payload]
//! ```
//!
//! `class` is one of [`datagram_class`] (`BULK = 0`, `NORMAL = 1`,
//! `INTERACTIVE = 2`); class 2 maps to `QUIC_SEND_FLAG_DGRAM_PRIORITY`.
//! `kind` is one of [`datagram_kind`] (`UDP = 0x00`, `WT_PROXY = 0x01`,
//! `IP = 0x02`). For `IP` the flow id is a tunnel id and the payload starts
//! with the tunnel fragment header (`wisp-ip`'s `frag` module).
//!
//! ### IP tunnels
//!
//! With [`extension::IP_TUNNEL`] negotiated, tunnels are controlled with
//! [`frame_type::TUNNEL_OPEN`], [`frame_type::TUNNEL_OPENED`],
//! [`frame_type::TUNNEL_CLOSE`] and [`frame_type::TUNNEL_CAPSULES`], each
//! `[tunnelId:u32 LE]` followed by capsules (or, for `TUNNEL_CLOSE`, a reason
//! byte). Packets ride `IP` datagrams, or, when datagrams are not negotiated,
//! one uni stream per tunnel and direction with the same prelude and chunk
//! layout as a per-flow UDP uni stream.
//!
//! ### Bidi stream header (always priority-prefixed)
//!
//! ```text
//! [priority:i32 LE][kind:u8] kind-specific tail
//! ```
//!
//! Priority drives `QUIC_PARAM_STREAM_PRIORITY` directly. Kind is one of
//! [`stream_kind`]:
//!
//! - `TCP = 0x01`: `[port:u16 LE][hostLen:u16 LE][hostname]`.
//! - `WT_PROXY_SUB = 0x02`: `[sessionId:u32 LE]`.
//!
//! ### Per-flow UDP uni stream (server↔client, always available)
//!
//! ```text
//! prelude:        [flowId:u32 LE]
//! repeating chunk: [len:u16 LE][payload:len bytes]
//! ```
//!
//! One uni stream per UDP flow, in each direction. Chunks ride the same
//! QUIC stream's flow-control window — a chatty UDP flow gets bounded
//! independently of the connection-wide datagram queue.

#![forbid(unsafe_code)]

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

/// Stream priority used for the control bidi. Driven into msquic's
/// `QUIC_PARAM_STREAM_PRIORITY` so control frames preempt bulk data.
pub const WISP_WT_CONTROL_SEND_ORDER: i32 = i32::MAX;
/// Default for data-bearing TCP bridges.
pub const WISP_WT_DEFAULT_DATA_SEND_ORDER: i32 = 0;

pub const WISP_WT_PROXY_UPSTREAM_DATAGRAM_MAX_AGE_MS: u32 = 1_000;
pub const WISP_WT_PROXY_UPSTREAM_DATAGRAM_HIGH_WATER_MARK: u32 = 256;

/// Frame type bytes carried in the first byte of the frame body.
pub mod frame_type {
    pub const INFO: u8 = 0x01;
    pub const READY: u8 = 0x02;
    pub const CLOSE: u8 = 0x03;
    pub const CONTROL: u8 = 0x04;
    pub const UDP_OPEN: u8 = 0x05;
    pub const UDP_OPENED: u8 = 0x06;
    pub const UDP_CLOSE: u8 = 0x07;
    pub const WT_PROXY_OPEN: u8 = 0x08;
    pub const WT_PROXY_OPENED: u8 = 0x09;
    pub const WT_PROXY_CLOSE: u8 = 0x0a;
    /// C→S `[tunnelId:u32][capsules]`, the client picks an id not in use.
    pub const TUNNEL_OPEN: u8 = 0x0b;
    /// S→C `[tunnelId:u32][capsules]`, the open confirmation.
    pub const TUNNEL_OPENED: u8 = 0x0c;
    /// Either way `[tunnelId:u32][reason:u8]`, reasons as Wisp CLOSE.
    pub const TUNNEL_CLOSE: u8 = 0x0d;
    /// Either way `[tunnelId:u32][capsules]`, later control.
    pub const TUNNEL_CAPSULES: u8 = 0x0e;
}

/// Bidi stream kind discriminator, immediately following the priority prefix.
pub mod stream_kind {
    pub const TCP: u8 = 0x01;
    pub const WT_PROXY_SUB: u8 = 0x02;
}

/// Datagram kind discriminator, the byte after the priority class.
pub mod datagram_kind {
    pub const UDP: u8 = 0x00;
    pub const WT_PROXY: u8 = 0x01;
    /// An IP packet, or a piece of one, of the tunnel named by the flow id.
    pub const IP: u8 = 0x02;
}

/// Three-class datagram priority. `INTERACTIVE` maps to
/// `QUIC_SEND_FLAG_DGRAM_PRIORITY` so latency-sensitive flows preempt bulk in
/// msquic's egress queue.
pub mod datagram_class {
    pub const BULK: u8 = 0;
    pub const NORMAL: u8 = 1;
    pub const INTERACTIVE: u8 = 2;
}

/// Raw numeric ids for the negotiable extensions. Prefer the typed
/// [`Extension`] impls (e.g. [`Udp`], [`WebTransportProxy`],
/// [`ProxyControl`]) for new code — these constants exist so that
/// frame-dispatch code that matches on a raw byte stays readable.
pub mod extension {
    pub const UDP: u8 = 0x01;
    pub const WEBTRANSPORT_PROXY: u8 = 0x02;
    pub const WISP_PROXY_CONTROL: u8 = 0x03;
    pub const IP_TUNNEL: u8 = 0xf3;
}

/// A negotiable wisp-wt extension.
///
/// Each extension is a zero-sized type with two associated constants. The
/// server registers them in an [`ExtensionRegistry`] which produces the
/// `Vec<ExtensionEntry>` advertised in its INFO frame. Code that needs to
/// gate behavior on whether an extension is live calls
/// `SessionContext::has::<E>()` instead of comparing raw u8s.
///
/// To add a new extension:
///
/// ```ignore
/// pub struct MyFeature;
/// impl Extension for MyFeature {
///     const ID: u8 = 0x04;
///     const NAME: &'static str = "MY_FEATURE";
///     // optional: override server_payload() if the extension carries data
/// }
/// // then in the server setup: registry.register::<MyFeature>();
/// ```
pub trait Extension {
    /// Numeric extension id carried in INFO.
    const ID: u8;
    /// Human-readable name, used in logs and diagnostics.
    const NAME: &'static str;
    /// Payload the server advertises in its INFO frame for this extension.
    /// Defaults to empty — most negotiable extensions are presence-only.
    fn server_payload() -> Bytes {
        Bytes::new()
    }
}

/// 0x01 — UDP packet relay. When negotiated, the client may send `UDP_OPEN` /
/// `UDP_CLOSE` control frames and route UDP packets over WT datagrams (or, in
/// per-flow uni mode, dedicated uni streams).
pub struct Udp;
impl Extension for Udp {
    const ID: u8 = extension::UDP;
    const NAME: &'static str = "UDP";
}

/// 0x02 — Upstream WebTransport proxy. When negotiated, the server bridges
/// `WT_PROXY_OPEN` to an upstream WT session and forwards client-opened sub
/// streams onto it.
pub struct WebTransportProxy;
impl Extension for WebTransportProxy {
    const ID: u8 = extension::WEBTRANSPORT_PROXY;
    const NAME: &'static str = "WEBTRANSPORT_PROXY";
}

/// 0x03 — Wisp control channel for proxy-side coordination
/// outside of the wisp-wt frame catalog.
pub struct ProxyControl;
impl Extension for ProxyControl {
    const ID: u8 = extension::WISP_PROXY_CONTROL;
    const NAME: &'static str = "WISP_PROXY_CONTROL";
}

/// 0xF3 — IP packets in tunnels. The INFO payload is not empty: it carries
/// the magic `WIPT`, the version range, flags and limits, built from the
/// server's tunnel configuration, so the server registers it with
/// [`ExtensionRegistry::register_raw`]. The client's entry must carry the
/// magic and a version in range, or the extension stays off.
pub struct IpTunnel;
impl Extension for IpTunnel {
    const ID: u8 = extension::IP_TUNNEL;
    const NAME: &'static str = "IP_TUNNEL";
}

/// Server-side builder for the extension set advertised in INFO. Add typed
/// extensions with [`register`](Self::register); read back the advertised
/// `ExtensionEntry`s with [`entries`](Self::entries) and the raw id set with
/// [`ids`](Self::ids).
#[derive(Debug, Default, Clone)]
pub struct ExtensionRegistry {
    entries: Vec<ExtensionEntry>,
    ids: std::collections::HashSet<u8>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an extension by its type. Idempotent — re-registering the
    /// same `E::ID` replaces the previous entry rather than duplicating it.
    pub fn register<E: Extension>(&mut self) -> &mut Self {
        self.register_raw(E::ID, E::server_payload())
    }

    /// Lower-level escape hatch for extensions whose id/payload is computed
    /// at runtime (e.g. forwarded from a parent server).
    pub fn register_raw(&mut self, id: u8, payload: Bytes) -> &mut Self {
        self.entries.retain(|e| e.id != id);
        self.entries.push(ExtensionEntry { id, payload });
        self.ids.insert(id);
        self
    }

    pub fn entries(&self) -> &[ExtensionEntry] {
        &self.entries
    }

    pub fn ids(&self) -> &std::collections::HashSet<u8> {
        &self.ids
    }

    pub fn contains<E: Extension>(&self) -> bool {
        self.ids.contains(&E::ID)
    }

    /// Intersection of this registry's ids with a peer-supplied id set.
    /// Used by the handshake to compute the negotiated set.
    pub fn intersect_ids(
        &self,
        other: &std::collections::HashSet<u8>,
    ) -> std::collections::HashSet<u8> {
        self.ids.intersection(other).copied().collect()
    }
}

/// Errors surfaced by the codec.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("wisp-wt frame too short")]
    FrameTooShort,
    #[error("wisp-wt CLOSE too short")]
    CloseTooShort,
    #[error("wisp-wt UDP_OPEN too short")]
    UdpOpenTooShort,
    #[error("wisp-wt UDP_OPEN host too short")]
    UdpOpenHostTooShort,
    #[error("wisp-wt UDP_OPENED too short")]
    UdpOpenedTooShort,
    #[error("wisp-wt UDP_CLOSE too short")]
    UdpCloseTooShort,
    #[error("wisp-wt WT_PROXY_OPEN too short")]
    WtProxyOpenTooShort,
    #[error("wisp-wt WT_PROXY_OPEN url too short")]
    WtProxyOpenUrlTooShort,
    #[error("wisp-wt WT_PROXY_OPEN url not utf-8")]
    WtProxyOpenUrlNotUtf8,
    #[error("wisp-wt WT_PROXY_OPENED too short")]
    WtProxyOpenedTooShort,
    #[error("wisp-wt WT_PROXY_CLOSE too short")]
    WtProxyCloseTooShort,
    #[error("wisp-wt WT_PROXY_CLOSE reason too short")]
    WtProxyCloseReasonTooShort,
    #[error("wisp-wt WT_PROXY_CLOSE reason not utf-8")]
    WtProxyCloseReasonNotUtf8,
    #[error("wisp-wt TCP stream header too short")]
    TcpHeaderTooShort,
    #[error("wisp-wt WT_PROXY_SUB stream header too short")]
    WtProxySubHeaderTooShort,
    #[error("wisp-wt unknown stream kind: {0:#04x}")]
    UnknownStreamKind(u8),
    #[error("wisp-wt UDP uni prelude too short")]
    UdpUniPreludeTooShort,
    #[error("wisp-wt UDP uni chunk too short")]
    UdpUniChunkTooShort,
    #[error("wisp-wt datagram too short")]
    DatagramTooShort,
    #[error("wisp-wt host name not utf-8")]
    HostnameNotUtf8,
    #[error("wisp-wt control payload not utf-8")]
    ControlNotUtf8,
    #[error("wisp-wt extension entry too short")]
    ExtensionTooShort,
    #[error("wisp-wt extension payload too short")]
    ExtensionPayloadTooShort,
    #[error("wisp-wt tunnel frame too short")]
    TunnelFrameTooShort,
    #[error("wisp-wt TUNNEL_CLOSE too short")]
    TunnelCloseTooShort,
}

pub type Result<T> = std::result::Result<T, WireError>;

/// Generic frame body (after stripping the 4-byte length prefix).
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: u8,
    pub payload: Bytes,
}

#[derive(Debug, Clone)]
pub struct InfoFrame {
    /// Raw extension bytes; pass to [`parse_extensions`] when needed.
    pub extensions: Bytes,
}

#[derive(Debug, Clone)]
pub struct ExtensionEntry {
    pub id: u8,
    pub payload: Bytes,
}

#[derive(Debug, Clone)]
pub struct UdpOpenFrame {
    pub port: u16,
    pub hostname: String,
}

#[derive(Debug, Clone, Copy)]
pub struct UdpClose {
    pub flow_id: u32,
    pub reason: u8,
}

/// A `TUNNEL_OPEN`, `TUNNEL_OPENED` or `TUNNEL_CAPSULES` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelFrame {
    pub tunnel_id: u32,
    /// Encoded capsules, parsed by `wisp-ip`.
    pub capsules: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelClose {
    pub tunnel_id: u32,
    pub reason: u8,
}

#[derive(Debug, Clone)]
pub struct WtProxyClose {
    pub session_id: u32,
    pub code: u32,
    pub reason: String,
}

/// Parsed bidi stream header. Includes the priority that should be set on the
/// underlying QUIC stream via `QUIC_PARAM_STREAM_PRIORITY`.
#[derive(Debug, Clone)]
pub struct BidiStreamHeader {
    pub priority: i32,
    pub kind: BidiStreamKind,
}

#[derive(Debug, Clone)]
pub enum BidiStreamKind {
    Tcp { port: u16, hostname: String },
    WtProxySub { session_id: u32 },
}

/// Class- and kind-prefixed datagram.
#[derive(Debug, Clone)]
pub struct Datagram {
    pub class: u8,
    pub kind: u8,
    pub flow_id: u32,
    pub payload: Bytes,
}

pub fn encode_frame(frame_type: u8, payload: &[u8]) -> Bytes {
    let body_len = 1 + payload.len();
    let mut out = BytesMut::with_capacity(4 + body_len);
    out.put_u32_le(body_len as u32);
    out.put_u8(frame_type);
    out.extend_from_slice(payload);
    out.freeze()
}

pub fn decode_frame_body(body: &[u8]) -> Result<Frame> {
    if body.is_empty() {
        return Err(WireError::FrameTooShort);
    }
    Ok(Frame {
        frame_type: body[0],
        payload: Bytes::copy_from_slice(&body[1..]),
    })
}

pub fn encode_extensions(entries: &[ExtensionEntry]) -> Bytes {
    let total: usize = entries.iter().map(|e| 5 + e.payload.len()).sum();
    let mut out = BytesMut::with_capacity(total);
    for e in entries {
        out.put_u8(e.id);
        out.put_u32_le(e.payload.len() as u32);
        out.extend_from_slice(&e.payload);
    }
    out.freeze()
}

pub fn parse_extensions(buf: &[u8]) -> Result<Vec<ExtensionEntry>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        if offset + 5 > buf.len() {
            return Err(WireError::ExtensionTooShort);
        }
        let id = buf[offset];
        let length = u32::from_le_bytes([
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
        ]) as usize;
        let start = offset + 5;
        let end = start
            .checked_add(length)
            .ok_or(WireError::ExtensionPayloadTooShort)?;
        if end > buf.len() {
            return Err(WireError::ExtensionPayloadTooShort);
        }
        out.push(ExtensionEntry {
            id,
            payload: Bytes::copy_from_slice(&buf[start..end]),
        });
        offset = end;
    }
    Ok(out)
}

pub fn extension_set(entries: &[ExtensionEntry]) -> std::collections::HashSet<u8> {
    entries.iter().map(|e| e.id).collect()
}

pub fn encode_info_frame(extensions: &[ExtensionEntry]) -> Bytes {
    let ext = encode_extensions(extensions);
    encode_frame(frame_type::INFO, &ext)
}

pub fn parse_info_payload(payload: &[u8]) -> Result<InfoFrame> {
    Ok(InfoFrame {
        extensions: Bytes::copy_from_slice(payload),
    })
}

pub fn encode_ready_frame() -> Bytes {
    encode_frame(frame_type::READY, &[])
}

pub fn encode_close_frame(reason: u8) -> Bytes {
    encode_frame(frame_type::CLOSE, &[reason])
}

pub fn parse_close_payload(payload: &[u8]) -> Result<u8> {
    if payload.is_empty() {
        return Err(WireError::CloseTooShort);
    }
    Ok(payload[0])
}

pub fn encode_control_frame(text: &str) -> Bytes {
    encode_frame(frame_type::CONTROL, text.as_bytes())
}

pub fn parse_control_payload(payload: &[u8]) -> Result<String> {
    std::str::from_utf8(payload)
        .map(|s| s.to_owned())
        .map_err(|_| WireError::ControlNotUtf8)
}

pub fn encode_udp_open_frame(hostname: &str, port: u16) -> Bytes {
    let host = hostname.as_bytes();
    let mut payload = BytesMut::with_capacity(4 + host.len());
    payload.put_u16_le(port);
    payload.put_u16_le(host.len() as u16);
    payload.extend_from_slice(host);
    encode_frame(frame_type::UDP_OPEN, &payload)
}

pub fn parse_udp_open_payload(payload: &[u8]) -> Result<UdpOpenFrame> {
    if payload.len() < 4 {
        return Err(WireError::UdpOpenTooShort);
    }
    let port = u16::from_le_bytes([payload[0], payload[1]]);
    let host_len = u16::from_le_bytes([payload[2], payload[3]]) as usize;
    let start: usize = 4;
    let end = start
        .checked_add(host_len)
        .ok_or(WireError::UdpOpenHostTooShort)?;
    if end > payload.len() {
        return Err(WireError::UdpOpenHostTooShort);
    }
    let hostname = std::str::from_utf8(&payload[start..end])
        .map_err(|_| WireError::HostnameNotUtf8)?
        .to_owned();
    Ok(UdpOpenFrame { port, hostname })
}

pub fn encode_udp_opened_frame(flow_id: u32) -> Bytes {
    let mut payload = BytesMut::with_capacity(4);
    payload.put_u32_le(flow_id);
    encode_frame(frame_type::UDP_OPENED, &payload)
}

pub fn parse_udp_opened_payload(payload: &[u8]) -> Result<u32> {
    if payload.len() < 4 {
        return Err(WireError::UdpOpenedTooShort);
    }
    Ok(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

pub fn encode_udp_close_frame(flow_id: u32, reason: u8) -> Bytes {
    let mut payload = BytesMut::with_capacity(5);
    payload.put_u32_le(flow_id);
    payload.put_u8(reason);
    encode_frame(frame_type::UDP_CLOSE, &payload)
}

pub fn parse_udp_close_payload(payload: &[u8]) -> Result<UdpClose> {
    if payload.len() < 5 {
        return Err(WireError::UdpCloseTooShort);
    }
    Ok(UdpClose {
        flow_id: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
        reason: payload[4],
    })
}

pub fn encode_wt_proxy_open_frame(url: &str) -> Bytes {
    let bytes = url.as_bytes();
    let mut payload = BytesMut::with_capacity(2 + bytes.len());
    payload.put_u16_le(bytes.len() as u16);
    payload.extend_from_slice(bytes);
    encode_frame(frame_type::WT_PROXY_OPEN, &payload)
}

pub fn parse_wt_proxy_open_payload(payload: &[u8]) -> Result<String> {
    if payload.len() < 2 {
        return Err(WireError::WtProxyOpenTooShort);
    }
    let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    let end = 2usize
        .checked_add(len)
        .ok_or(WireError::WtProxyOpenUrlTooShort)?;
    if end > payload.len() {
        return Err(WireError::WtProxyOpenUrlTooShort);
    }
    std::str::from_utf8(&payload[2..end])
        .map(|s| s.to_owned())
        .map_err(|_| WireError::WtProxyOpenUrlNotUtf8)
}

pub fn encode_wt_proxy_opened_frame(session_id: u32) -> Bytes {
    let mut payload = BytesMut::with_capacity(4);
    payload.put_u32_le(session_id);
    encode_frame(frame_type::WT_PROXY_OPENED, &payload)
}

pub fn parse_wt_proxy_opened_payload(payload: &[u8]) -> Result<u32> {
    if payload.len() < 4 {
        return Err(WireError::WtProxyOpenedTooShort);
    }
    Ok(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

pub fn encode_wt_proxy_close_frame(session_id: u32, code: u32, reason: &str) -> Bytes {
    let r = reason.as_bytes();
    let mut payload = BytesMut::with_capacity(10 + r.len());
    payload.put_u32_le(session_id);
    payload.put_u32_le(code);
    payload.put_u16_le(r.len() as u16);
    payload.extend_from_slice(r);
    encode_frame(frame_type::WT_PROXY_CLOSE, &payload)
}

pub fn parse_wt_proxy_close_payload(payload: &[u8]) -> Result<WtProxyClose> {
    if payload.len() < 10 {
        return Err(WireError::WtProxyCloseTooShort);
    }
    let session_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let code = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let len = u16::from_le_bytes([payload[8], payload[9]]) as usize;
    let end = 10usize
        .checked_add(len)
        .ok_or(WireError::WtProxyCloseReasonTooShort)?;
    if end > payload.len() {
        return Err(WireError::WtProxyCloseReasonTooShort);
    }
    let reason = std::str::from_utf8(&payload[10..end])
        .map_err(|_| WireError::WtProxyCloseReasonNotUtf8)?
        .to_owned();
    Ok(WtProxyClose {
        session_id,
        code,
        reason,
    })
}

/// Encode `TUNNEL_OPEN`, `TUNNEL_OPENED` or `TUNNEL_CAPSULES`.
pub fn encode_tunnel_frame(frame_type: u8, tunnel_id: u32, capsules: &[u8]) -> Bytes {
    let mut payload = BytesMut::with_capacity(4 + capsules.len());
    payload.put_u32_le(tunnel_id);
    payload.extend_from_slice(capsules);
    encode_frame(frame_type, &payload)
}

pub fn parse_tunnel_payload(payload: &[u8]) -> Result<TunnelFrame> {
    if payload.len() < 4 {
        return Err(WireError::TunnelFrameTooShort);
    }
    Ok(TunnelFrame {
        tunnel_id: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
        capsules: Bytes::copy_from_slice(&payload[4..]),
    })
}

pub fn encode_tunnel_close_frame(tunnel_id: u32, reason: u8) -> Bytes {
    let mut payload = BytesMut::with_capacity(5);
    payload.put_u32_le(tunnel_id);
    payload.put_u8(reason);
    encode_frame(frame_type::TUNNEL_CLOSE, &payload)
}

pub fn parse_tunnel_close_payload(payload: &[u8]) -> Result<TunnelClose> {
    if payload.len() < 5 {
        return Err(WireError::TunnelCloseTooShort);
    }
    Ok(TunnelClose {
        tunnel_id: u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
        reason: payload[4],
    })
}

/// Encode the priority-prefixed TCP bidi header.
pub fn encode_tcp_stream_header(hostname: &str, port: u16, priority: i32) -> Bytes {
    let host = hostname.as_bytes();
    let mut buf = BytesMut::with_capacity(9 + host.len());
    buf.put_i32_le(priority);
    buf.put_u8(stream_kind::TCP);
    buf.put_u16_le(port);
    buf.put_u16_le(host.len() as u16);
    buf.extend_from_slice(host);
    buf.freeze()
}

/// Encode the priority-prefixed WT_PROXY_SUB bidi header.
pub fn encode_wt_proxy_sub_stream_header(session_id: u32, priority: i32) -> Bytes {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_i32_le(priority);
    buf.put_u8(stream_kind::WT_PROXY_SUB);
    buf.put_u32_le(session_id);
    buf.freeze()
}

/// Try to parse a bidi stream header (priority + kind + kind-specific tail).
/// Returns `Ok(None)` on a short read; the caller should buffer more bytes.
pub fn try_parse_bidi_stream_header(buf: &[u8]) -> Result<Option<(BidiStreamHeader, usize)>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let priority = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let kind = buf[4];
    match kind {
        stream_kind::TCP => {
            if buf.len() < 9 {
                return Ok(None);
            }
            let port = u16::from_le_bytes([buf[5], buf[6]]);
            let host_len = u16::from_le_bytes([buf[7], buf[8]]) as usize;
            let header_end = 9usize.saturating_add(host_len);
            if buf.len() < header_end {
                return Ok(None);
            }
            let hostname = std::str::from_utf8(&buf[9..header_end])
                .map_err(|_| WireError::HostnameNotUtf8)?
                .to_owned();
            Ok(Some((
                BidiStreamHeader {
                    priority,
                    kind: BidiStreamKind::Tcp { port, hostname },
                },
                header_end,
            )))
        }
        stream_kind::WT_PROXY_SUB => {
            if buf.len() < 9 {
                return Ok(None);
            }
            let session_id = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
            Ok(Some((
                BidiStreamHeader {
                    priority,
                    kind: BidiStreamKind::WtProxySub { session_id },
                },
                9,
            )))
        }
        other => Err(WireError::UnknownStreamKind(other)),
    }
}

/// Encode a class- and kind-prefixed datagram.
pub fn encode_datagram(class: u8, kind: u8, flow_id: u32, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(6 + payload.len());
    out.put_u8(class);
    out.put_u8(kind);
    out.put_u32_le(flow_id);
    out.extend_from_slice(payload);
    out.freeze()
}

pub fn parse_datagram(raw: &[u8]) -> Result<Datagram> {
    if raw.len() < 6 {
        return Err(WireError::DatagramTooShort);
    }
    Ok(Datagram {
        class: raw[0],
        kind: raw[1],
        flow_id: u32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]),
        payload: Bytes::copy_from_slice(&raw[6..]),
    })
}

/// 4-byte prelude that opens a per-flow UDP uni stream.
pub fn encode_udp_flow_uni_prelude(flow_id: u32) -> Bytes {
    let mut out = BytesMut::with_capacity(4);
    out.put_u32_le(flow_id);
    out.freeze()
}

pub fn parse_udp_flow_uni_prelude(buf: &[u8]) -> Result<u32> {
    if buf.len() < 4 {
        return Err(WireError::UdpUniPreludeTooShort);
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// `[len:u16 LE][payload]` chunk.
pub fn encode_udp_flow_uni_chunk(payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(2 + payload.len());
    out.put_u16_le(payload.len() as u16);
    out.extend_from_slice(payload);
    out.freeze()
}

/// Try to consume one chunk from the front of `buf`. Returns
/// `Ok(Some((payload, bytes_consumed)))` on a complete chunk, `Ok(None)` on
/// a short read.
pub fn try_parse_udp_flow_uni_chunk(buf: &[u8]) -> Result<Option<(Bytes, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let end = 2usize.saturating_add(len);
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some((Bytes::copy_from_slice(&buf[2..end]), end)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    }

    #[test]
    fn frame_roundtrip() {
        let f = encode_frame(frame_type::READY, &[]);
        assert_eq!(hex(&f), "0100000002");
        let parsed = decode_frame_body(&f[4..]).unwrap();
        assert_eq!(parsed.frame_type, frame_type::READY);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn close_roundtrip() {
        let f = encode_close_frame(0x42);
        assert_eq!(hex(&f), "020000000342");
        let parsed = decode_frame_body(&f[4..]).unwrap();
        assert_eq!(parsed.frame_type, frame_type::CLOSE);
        assert_eq!(parse_close_payload(&parsed.payload).unwrap(), 0x42);
    }

    #[test]
    fn info_roundtrip_no_extensions() {
        let frame = encode_info_frame(&[]);
        let parsed = decode_frame_body(&frame[4..]).unwrap();
        let info = parse_info_payload(&parsed.payload).unwrap();
        assert!(info.extensions.is_empty());
    }

    #[test]
    fn info_roundtrip_with_extensions() {
        let entries = vec![
            ExtensionEntry {
                id: extension::UDP,
                payload: Bytes::new(),
            },
            ExtensionEntry {
                id: extension::WEBTRANSPORT_PROXY,
                payload: Bytes::from_static(&[0xde, 0xad]),
            },
            ExtensionEntry {
                id: extension::WISP_PROXY_CONTROL,
                payload: Bytes::new(),
            },
        ];
        let frame = encode_info_frame(&entries);
        let parsed = decode_frame_body(&frame[4..]).unwrap();
        let info = parse_info_payload(&parsed.payload).unwrap();
        let parsed_ext = parse_extensions(&info.extensions).unwrap();
        assert_eq!(parsed_ext.len(), 3);
        assert_eq!(parsed_ext[0].id, extension::UDP);
        assert!(parsed_ext[0].payload.is_empty());
        assert_eq!(parsed_ext[1].id, extension::WEBTRANSPORT_PROXY);
        assert_eq!(parsed_ext[1].payload.as_ref(), &[0xde, 0xad]);
        assert_eq!(parsed_ext[2].id, extension::WISP_PROXY_CONTROL);
        let set = extension_set(&parsed_ext);
        assert!(set.contains(&extension::UDP));
        assert!(set.contains(&extension::WEBTRANSPORT_PROXY));
        assert!(set.contains(&extension::WISP_PROXY_CONTROL));
    }

    #[test]
    fn udp_open_roundtrip() {
        let f = encode_udp_open_frame("example.com", 53);
        let parsed = decode_frame_body(&f[4..]).unwrap();
        let open = parse_udp_open_payload(&parsed.payload).unwrap();
        assert_eq!(open.port, 53);
        assert_eq!(open.hostname, "example.com");
    }

    #[test]
    fn udp_close_roundtrip() {
        let f = encode_udp_close_frame(0x1234_5678, 0x07);
        let parsed = decode_frame_body(&f[4..]).unwrap();
        let close = parse_udp_close_payload(&parsed.payload).unwrap();
        assert_eq!(close.flow_id, 0x1234_5678);
        assert_eq!(close.reason, 0x07);
    }

    #[test]
    fn wt_proxy_open_roundtrip() {
        let f = encode_wt_proxy_open_frame("https://upstream.example/wisp-wt");
        let parsed = decode_frame_body(&f[4..]).unwrap();
        let url = parse_wt_proxy_open_payload(&parsed.payload).unwrap();
        assert_eq!(url, "https://upstream.example/wisp-wt");
    }

    #[test]
    fn wt_proxy_open_rejects_truncated_and_non_utf8_urls() {
        assert!(matches!(
            parse_wt_proxy_open_payload(&[4, 0, b'h']),
            Err(WireError::WtProxyOpenUrlTooShort)
        ));
        assert!(matches!(
            parse_wt_proxy_open_payload(&[1, 0, 0xff]),
            Err(WireError::WtProxyOpenUrlNotUtf8)
        ));
    }

    #[test]
    fn wt_proxy_opened_roundtrip() {
        let f = encode_wt_proxy_opened_frame(0xcafe_d00d);
        let parsed = decode_frame_body(&f[4..]).unwrap();
        let id = parse_wt_proxy_opened_payload(&parsed.payload).unwrap();
        assert_eq!(id, 0xcafe_d00d);
    }

    #[test]
    fn wt_proxy_close_roundtrip() {
        let f = encode_wt_proxy_close_frame(0xfeed_face, 0x4242, "bye");
        let parsed = decode_frame_body(&f[4..]).unwrap();
        let close = parse_wt_proxy_close_payload(&parsed.payload).unwrap();
        assert_eq!(close.session_id, 0xfeed_face);
        assert_eq!(close.code, 0x4242);
        assert_eq!(close.reason, "bye");
    }

    #[test]
    fn datagram_roundtrip_udp() {
        let d = encode_datagram(
            datagram_class::INTERACTIVE,
            datagram_kind::UDP,
            0xdead_beef,
            b"abc",
        );
        assert_eq!(hex(&d), "0200efbeadde616263");
        let parsed = parse_datagram(&d).unwrap();
        assert_eq!(parsed.class, datagram_class::INTERACTIVE);
        assert_eq!(parsed.kind, datagram_kind::UDP);
        assert_eq!(parsed.flow_id, 0xdead_beef);
        assert_eq!(parsed.payload.as_ref(), b"abc");
    }

    #[test]
    fn datagram_roundtrip_wt_proxy() {
        let d = encode_datagram(
            datagram_class::NORMAL,
            datagram_kind::WT_PROXY,
            0x0000_0001,
            b"x",
        );
        let parsed = parse_datagram(&d).unwrap();
        assert_eq!(parsed.class, datagram_class::NORMAL);
        assert_eq!(parsed.kind, datagram_kind::WT_PROXY);
        assert_eq!(parsed.flow_id, 1);
    }

    #[test]
    fn datagram_rejects_every_truncated_header() {
        for len in 0..6 {
            assert!(matches!(
                parse_datagram(&[0; 6][..len]),
                Err(WireError::DatagramTooShort)
            ));
        }
    }

    #[test]
    fn tcp_header_roundtrip() {
        let h = encode_tcp_stream_header("example.com", 443, 0x1000);
        let (parsed, consumed) = try_parse_bidi_stream_header(&h).unwrap().unwrap();
        assert_eq!(parsed.priority, 0x1000);
        match parsed.kind {
            BidiStreamKind::Tcp { port, hostname } => {
                assert_eq!(port, 443);
                assert_eq!(hostname, "example.com");
            }
            _ => panic!("expected TCP"),
        }
        assert_eq!(consumed, h.len());
    }

    #[test]
    fn wt_proxy_sub_header_roundtrip() {
        let h = encode_wt_proxy_sub_stream_header(0xaabbccdd, 0x7fff);
        let (parsed, consumed) = try_parse_bidi_stream_header(&h).unwrap().unwrap();
        assert_eq!(parsed.priority, 0x7fff);
        match parsed.kind {
            BidiStreamKind::WtProxySub { session_id } => {
                assert_eq!(session_id, 0xaabbccdd);
            }
            _ => panic!("expected WT_PROXY_SUB"),
        }
        assert_eq!(consumed, h.len());
    }

    #[test]
    fn bidi_header_short_returns_none() {
        let buf = [0u8; 4];
        assert!(try_parse_bidi_stream_header(&buf).unwrap().is_none());
    }

    #[test]
    fn wt_proxy_sub_header_waits_for_complete_session_id() {
        let header = encode_wt_proxy_sub_stream_header(7, 0);
        for len in 5..header.len() {
            assert!(try_parse_bidi_stream_header(&header[..len])
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn bidi_header_unknown_kind_errors() {
        let mut buf = BytesMut::new();
        buf.put_i32_le(0);
        buf.put_u8(0xff);
        let err = try_parse_bidi_stream_header(&buf).unwrap_err();
        assert!(matches!(err, WireError::UnknownStreamKind(0xff)));
    }

    #[test]
    fn udp_uni_prelude_and_chunk() {
        let prelude = encode_udp_flow_uni_prelude(0xcafebabe);
        assert_eq!(parse_udp_flow_uni_prelude(&prelude).unwrap(), 0xcafebabe);
        let chunk = encode_udp_flow_uni_chunk(b"hello");
        let (payload, consumed) = try_parse_udp_flow_uni_chunk(&chunk).unwrap().unwrap();
        assert_eq!(payload.as_ref(), b"hello");
        assert_eq!(consumed, chunk.len());
    }

    #[test]
    fn udp_uni_chunk_short_returns_none() {
        let chunk = encode_udp_flow_uni_chunk(b"hello");
        assert!(try_parse_udp_flow_uni_chunk(&chunk[..3]).unwrap().is_none());
    }

    #[test]
    fn extensions_short_errors() {
        let buf = [0x01u8, 0x05, 0x00, 0x00, 0x00];
        let err = parse_extensions(&buf).unwrap_err();
        assert!(matches!(err, WireError::ExtensionPayloadTooShort));
    }

    #[test]
    fn tunnel_frames_roundtrip() {
        let capsules = [0x01, 0x00, 0x02, 0x00, 0x01, 0x00];
        let f = encode_tunnel_frame(frame_type::TUNNEL_OPEN, 0x0102_0304, &capsules);
        assert_eq!(hex(&f), "0b0000000b04030201010002000100");
        let parsed = decode_frame_body(&f[4..]).unwrap();
        assert_eq!(parsed.frame_type, frame_type::TUNNEL_OPEN);
        let open = parse_tunnel_payload(&parsed.payload).unwrap();
        assert_eq!(open.tunnel_id, 0x0102_0304);
        assert_eq!(open.capsules.as_ref(), &capsules);

        for ty in [frame_type::TUNNEL_OPENED, frame_type::TUNNEL_CAPSULES] {
            let f = encode_tunnel_frame(ty, 9, &[]);
            let parsed = decode_frame_body(&f[4..]).unwrap();
            assert_eq!(parsed.frame_type, ty);
            let body = parse_tunnel_payload(&parsed.payload).unwrap();
            assert_eq!(body.tunnel_id, 9);
            assert!(body.capsules.is_empty());
        }

        let f = encode_tunnel_close_frame(9, 0x41);
        assert_eq!(hex(&f), "060000000d0900000041");
        let parsed = decode_frame_body(&f[4..]).unwrap();
        assert_eq!(
            parse_tunnel_close_payload(&parsed.payload).unwrap(),
            TunnelClose {
                tunnel_id: 9,
                reason: 0x41
            }
        );
    }

    #[test]
    fn tunnel_frames_reject_short_payloads() {
        assert!(matches!(
            parse_tunnel_payload(&[1, 2, 3]),
            Err(WireError::TunnelFrameTooShort)
        ));
        assert!(matches!(
            parse_tunnel_close_payload(&[1, 2, 3, 4]),
            Err(WireError::TunnelCloseTooShort)
        ));
    }

    #[test]
    fn ip_datagram_roundtrip() {
        let d = encode_datagram(
            datagram_class::INTERACTIVE,
            datagram_kind::IP,
            7,
            &[0x00, 0x45],
        );
        assert_eq!(hex(&d), "0202070000000045");
        let parsed = parse_datagram(&d).unwrap();
        assert_eq!(parsed.kind, datagram_kind::IP);
        assert_eq!(parsed.flow_id, 7);
        assert_eq!(parsed.payload.as_ref(), &[0x00, 0x45]);
    }

    #[test]
    fn ip_tunnel_registers_with_its_payload() {
        let mut reg = ExtensionRegistry::new();
        reg.register::<Udp>()
            .register_raw(IpTunnel::ID, Bytes::from_static(b"WIPT"));
        assert!(reg.contains::<IpTunnel>());
        assert_eq!(IpTunnel::ID, 0xf3);
        let entry = reg.entries().iter().find(|e| e.id == IpTunnel::ID).unwrap();
        assert_eq!(entry.payload.as_ref(), b"WIPT");
    }

    #[test]
    fn extension_registry_register_and_intersect() {
        let mut reg = ExtensionRegistry::new();
        reg.register::<Udp>()
            .register::<WebTransportProxy>()
            .register::<ProxyControl>();
        assert!(reg.contains::<Udp>());
        assert!(reg.contains::<WebTransportProxy>());
        assert!(reg.contains::<ProxyControl>());
        assert_eq!(reg.entries().len(), 3);

        let mut client_ids = std::collections::HashSet::new();
        client_ids.insert(Udp::ID);
        client_ids.insert(ProxyControl::ID);
        let negotiated = reg.intersect_ids(&client_ids);
        assert!(negotiated.contains(&Udp::ID));
        assert!(!negotiated.contains(&WebTransportProxy::ID));
        assert!(negotiated.contains(&ProxyControl::ID));
    }

    #[test]
    fn extension_registry_register_is_idempotent() {
        let mut reg = ExtensionRegistry::new();
        reg.register::<Udp>().register::<Udp>();
        assert_eq!(reg.entries().len(), 1);
        assert_eq!(reg.entries()[0].id, Udp::ID);
    }
}

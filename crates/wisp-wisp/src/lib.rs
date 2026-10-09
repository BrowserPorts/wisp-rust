//! Wisp v2 wire codec.
//!
//! Packets are `[type:u8][stream_id:u32 LE][payload]`. All multi-byte
//! integers are little-endian.
//!
//! Packet types: CONNECT (0x01), DATA (0x02), CONTINUE (0x03), CLOSE (0x04),
//! INFO (0x05), and FIN (0xF2) from the TCP Half-Close extension. Stream
//! types: TCP (0x01), UDP (0x02). Extensions are `[id:u8][len:u32 LE][payload]`
//! and live inside INFO payloads.

#![forbid(unsafe_code)]

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WispError {
    #[error("wisp packet too short")]
    PacketTooShort,
    #[error("wisp CONNECT payload too short")]
    ConnectTooShort,
    #[error("wisp CONTINUE payload too short")]
    ContinueTooShort,
    #[error("wisp CLOSE payload too short")]
    CloseTooShort,
    #[error("wisp INFO payload too short")]
    InfoTooShort,
    #[error("wisp FIN payload must be empty")]
    FinPayloadNotEmpty,
    #[error("unknown wisp packet type: {0:#x}")]
    UnknownPacketType(u8),
    #[error("wisp extension too short")]
    ExtensionTooShort,
    #[error("wisp extension payload truncated")]
    ExtensionPayloadTruncated,
    #[error("wisp hostname is not valid UTF-8")]
    InvalidHostnameUtf8,
    #[error("too many extension entries (cap {0})")]
    ExtensionEntryCap(usize),
    #[error("hostname exceeds {0} bytes")]
    HostnameTooLong(usize),
}

/// Default cap on extension-list entries. The wisp v2 spec doesn't bound
/// this so a malicious client could send a multi-megabyte INFO with
/// millions of entries; cap at 64 — the protocol uses ~4 today and a
/// theoretical 256 is the per-byte ID space ceiling.
pub const DEFAULT_MAX_EXTENSION_ENTRIES: usize = 64;

/// Default hostname byte cap inside CONNECT. RFC 1035 limits a DNS name
/// to 255 octets; we mirror that as the parse-time fail-closed bound.
pub const DEFAULT_MAX_HOST_BYTES: usize = 255;

pub type Result<T> = std::result::Result<T, WispError>;

/// Wisp packet type bytes.
pub mod packet_type {
    pub const CONNECT: u8 = 0x01;
    pub const DATA: u8 = 0x02;
    pub const CONTINUE: u8 = 0x03;
    pub const CLOSE: u8 = 0x04;
    pub const INFO: u8 = 0x05;
    /// Valid only when [`extension_id::TCP_HALF_CLOSE`] is negotiated.
    pub const FIN: u8 = 0xf2;
}

/// Wisp stream type bytes inside a CONNECT payload.
pub mod stream_type {
    pub const TCP: u8 = 0x01;
    pub const UDP: u8 = 0x02;
}

/// Wisp close reason codes. The `0x45 PROXY_ROTATED` reason is a
/// Wisp-specific extension on top of the spec.
pub mod close_reason {
    pub const UNKNOWN: u8 = 0x01;
    pub const VOLUNTARY: u8 = 0x02;
    pub const NETWORK_ERROR: u8 = 0x03;
    pub const INCOMPATIBLE_EXTENSIONS: u8 = 0x04;
    pub const INVALID_INFO: u8 = 0x41;
    pub const UNREACHABLE_HOST: u8 = 0x42;
    pub const NO_RESPONSE: u8 = 0x43;
    pub const CONN_REFUSED: u8 = 0x44;
    pub const PROXY_ROTATED: u8 = 0x45;
    pub const TRANSFER_TIMEOUT: u8 = 0x47;
    pub const HOST_BLOCKED: u8 = 0x48;
    pub const CONN_THROTTLED: u8 = 0x49;
    pub const CLIENT_ERROR: u8 = 0x81;
    pub const AUTH_BAD_PASSWORD: u8 = 0xc0;
    pub const AUTH_BAD_SIGNATURE: u8 = 0xc1;
    pub const AUTH_MISSING_CREDENTIALS: u8 = 0xc2;
}

/// Wisp v2 extension IDs. Aligned with `wisp-wire::extension::*` so the
/// same numeric ids mean the same thing across the WT and WS transports.
/// Auth and MOTD extensions are intentionally omitted as dead weight.
/// Extension `0x02` (WEBTRANSPORT_PROXY) is WT-only and unused in the WS
/// transport. STREAM_OPEN_CONFIRMATION lets a client wait for the upstream
/// connect before treating a stream as open: when negotiated, the server
/// sends a per-stream CONTINUE as soon as the TCP connect succeeds.
/// TCP_HALF_CLOSE carries a per-direction FIN in packet type 0xF2 so one side
/// can finish writing while the other keeps sending.
pub mod extension_id {
    pub const UDP: u8 = 0x01;
    pub const WISP_PROXY_CONTROL: u8 = 0x03;
    pub const STREAM_OPEN_CONFIRMATION: u8 = 0x05;
    pub const TCP_HALF_CLOSE: u8 = 0xf2;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectPacket {
    pub stream_id: u32,
    pub stream_type: u8,
    pub port: u16,
    pub hostname: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    pub stream_id: u32,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuePacket {
    pub stream_id: u32,
    pub remaining: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosePacket {
    pub stream_id: u32,
    pub reason: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoPacket {
    pub stream_id: u32,
    pub major: u8,
    pub minor: u8,
    pub extensions: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinPacket {
    pub stream_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WispPacket {
    Connect(ConnectPacket),
    Data(DataPacket),
    Continue(ContinuePacket),
    Close(ClosePacket),
    Info(InfoPacket),
    Fin(FinPacket),
}

impl WispPacket {
    pub fn stream_id(&self) -> u32 {
        match self {
            WispPacket::Connect(p) => p.stream_id,
            WispPacket::Data(p) => p.stream_id,
            WispPacket::Continue(p) => p.stream_id,
            WispPacket::Close(p) => p.stream_id,
            WispPacket::Info(p) => p.stream_id,
            WispPacket::Fin(p) => p.stream_id,
        }
    }
}

pub fn parse_packet(buf: Bytes) -> Result<WispPacket> {
    if buf.len() < 5 {
        return Err(WispError::PacketTooShort);
    }
    let mut head = &buf[..5];
    let packet_type = head.get_u8();
    let stream_id = head.get_u32_le();
    let payload = buf.slice(5..);
    match packet_type {
        packet_type::CONNECT => parse_connect(stream_id, payload).map(WispPacket::Connect),
        packet_type::DATA => Ok(WispPacket::Data(DataPacket { stream_id, payload })),
        packet_type::CONTINUE => parse_continue(stream_id, payload).map(WispPacket::Continue),
        packet_type::CLOSE => parse_close(stream_id, payload).map(WispPacket::Close),
        packet_type::INFO => parse_info(stream_id, payload).map(WispPacket::Info),
        packet_type::FIN if payload.is_empty() => Ok(WispPacket::Fin(FinPacket { stream_id })),
        packet_type::FIN => Err(WispError::FinPayloadNotEmpty),
        other => Err(WispError::UnknownPacketType(other)),
    }
}

fn parse_connect(stream_id: u32, payload: Bytes) -> Result<ConnectPacket> {
    parse_connect_capped(stream_id, payload, DEFAULT_MAX_HOST_BYTES)
}

/// Same as [`parse_connect`] with an explicit hostname-byte cap. The
/// connection-level handler calls this with the configured value; the
/// crate-wide [`parse_packet`] uses [`DEFAULT_MAX_HOST_BYTES`].
pub fn parse_connect_capped(
    stream_id: u32,
    payload: Bytes,
    max_host_bytes: usize,
) -> Result<ConnectPacket> {
    if payload.len() < 3 {
        return Err(WispError::ConnectTooShort);
    }
    let mut head = &payload[..3];
    let stream_type = head.get_u8();
    let port = head.get_u16_le();
    let hostname_bytes = payload.slice(3..);
    if hostname_bytes.len() > max_host_bytes {
        return Err(WispError::HostnameTooLong(max_host_bytes));
    }
    let hostname = std::str::from_utf8(&hostname_bytes)
        .map_err(|_| WispError::InvalidHostnameUtf8)?
        .to_owned();
    Ok(ConnectPacket {
        stream_id,
        stream_type,
        port,
        hostname,
    })
}

fn parse_continue(stream_id: u32, payload: Bytes) -> Result<ContinuePacket> {
    if payload.len() < 4 {
        return Err(WispError::ContinueTooShort);
    }
    let mut head = &payload[..4];
    Ok(ContinuePacket {
        stream_id,
        remaining: head.get_u32_le(),
    })
}

fn parse_close(stream_id: u32, payload: Bytes) -> Result<ClosePacket> {
    if payload.is_empty() {
        return Err(WispError::CloseTooShort);
    }
    Ok(ClosePacket {
        stream_id,
        reason: payload[0],
    })
}

fn parse_info(stream_id: u32, payload: Bytes) -> Result<InfoPacket> {
    if payload.len() < 2 {
        return Err(WispError::InfoTooShort);
    }
    let major = payload[0];
    let minor = payload[1];
    let extensions = payload.slice(2..);
    Ok(InfoPacket {
        stream_id,
        major,
        minor,
        extensions,
    })
}

pub fn encode_connect(packet: &ConnectPacket) -> Bytes {
    let host_bytes = packet.hostname.as_bytes();
    let mut buf = BytesMut::with_capacity(8 + host_bytes.len());
    buf.put_u8(packet_type::CONNECT);
    buf.put_u32_le(packet.stream_id);
    buf.put_u8(packet.stream_type);
    buf.put_u16_le(packet.port);
    buf.extend_from_slice(host_bytes);
    buf.freeze()
}

/// Size of the Wisp packet header (`type:u8` + `stream_id:u32 LE`).
pub const PACKET_HEADER_LEN: usize = 5;

/// Write a DATA header into the first [`PACKET_HEADER_LEN`] bytes of `buf`.
/// The remainder of `buf` is the payload and is left untouched — used by the
/// TCP/UDP pumps so a read buffer can become a frame without copying payload.
pub fn write_data_header(stream_id: u32, buf: &mut [u8]) {
    debug_assert!(buf.len() >= PACKET_HEADER_LEN);
    buf[0] = packet_type::DATA;
    buf[1..5].copy_from_slice(&stream_id.to_le_bytes());
}

pub fn encode_data(stream_id: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(PACKET_HEADER_LEN + payload.len());
    buf.resize(PACKET_HEADER_LEN, 0);
    buf.extend_from_slice(payload);
    write_data_header(stream_id, &mut buf);
    buf.freeze()
}

pub fn encode_data_owned(stream_id: u32, payload: Bytes) -> Bytes {
    encode_data(stream_id, &payload)
}

pub fn encode_continue(stream_id: u32, remaining: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u8(packet_type::CONTINUE);
    buf.put_u32_le(stream_id);
    buf.put_u32_le(remaining);
    buf.freeze()
}

pub fn encode_close(stream_id: u32, reason: u8) -> Bytes {
    let mut buf = BytesMut::with_capacity(6);
    buf.put_u8(packet_type::CLOSE);
    buf.put_u32_le(stream_id);
    buf.put_u8(reason);
    buf.freeze()
}

pub fn encode_fin(stream_id: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(PACKET_HEADER_LEN);
    buf.put_u8(packet_type::FIN);
    buf.put_u32_le(stream_id);
    buf.freeze()
}

pub fn encode_info(major: u8, minor: u8, extensions: &[ExtensionEntry]) -> Bytes {
    let ext_bytes = encode_extensions(extensions);
    let mut buf = BytesMut::with_capacity(7 + ext_bytes.len());
    buf.put_u8(packet_type::INFO);
    buf.put_u32_le(0);
    buf.put_u8(major);
    buf.put_u8(minor);
    buf.extend_from_slice(&ext_bytes);
    buf.freeze()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionEntry {
    pub id: u8,
    pub payload: Bytes,
}

pub fn encode_extensions(extensions: &[ExtensionEntry]) -> Bytes {
    let total: usize = extensions.iter().map(|e| 5 + e.payload.len()).sum();
    let mut buf = BytesMut::with_capacity(total);
    for ext in extensions {
        buf.put_u8(ext.id);
        buf.put_u32_le(ext.payload.len() as u32);
        buf.extend_from_slice(&ext.payload);
    }
    buf.freeze()
}

pub fn parse_extensions(buf: Bytes) -> Result<Vec<ExtensionEntry>> {
    parse_extensions_capped(buf, DEFAULT_MAX_EXTENSION_ENTRIES)
}

/// Cap-aware variant. Returns [`WispError::ExtensionEntryCap`] once the
/// number of decoded entries would exceed `max_entries`. Used by the
/// connection-level INFO parser so a malicious client can't force the
/// server to allocate an unbounded `Vec<ExtensionEntry>`.
pub fn parse_extensions_capped(buf: Bytes, max_entries: usize) -> Result<Vec<ExtensionEntry>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if out.len() >= max_entries {
            return Err(WispError::ExtensionEntryCap(max_entries));
        }
        if offset + 5 > buf.len() {
            return Err(WispError::ExtensionTooShort);
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
            .ok_or(WispError::ExtensionPayloadTruncated)?;
        if end > buf.len() {
            return Err(WispError::ExtensionPayloadTruncated);
        }
        out.push(ExtensionEntry {
            id,
            payload: buf.slice(start..end),
        });
        offset = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_connect_tcp() {
        let pkt = ConnectPacket {
            stream_id: 7,
            stream_type: stream_type::TCP,
            port: 443,
            hostname: "example.com".to_owned(),
        };
        let bytes = encode_connect(&pkt);
        let parsed = parse_packet(bytes).unwrap();
        assert_eq!(WispPacket::Connect(pkt), parsed);
    }

    #[test]
    fn roundtrip_data() {
        let payload: &[u8] = b"hello";
        let bytes = encode_data(99, payload);
        match parse_packet(bytes).unwrap() {
            WispPacket::Data(d) => {
                assert_eq!(d.stream_id, 99);
                assert_eq!(&d.payload[..], payload);
            }
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn write_data_header_matches_encode_data() {
        let payload = b"in-place";
        let encoded = encode_data(7, payload);
        let mut buf = BytesMut::with_capacity(PACKET_HEADER_LEN + payload.len());
        buf.resize(PACKET_HEADER_LEN, 0);
        buf.extend_from_slice(payload);
        write_data_header(7, &mut buf);
        assert_eq!(encoded, buf.freeze());
    }

    #[test]
    fn roundtrip_continue() {
        let bytes = encode_continue(0, 65_536);
        let parsed = parse_packet(bytes).unwrap();
        assert_eq!(
            WispPacket::Continue(ContinuePacket {
                stream_id: 0,
                remaining: 65_536,
            }),
            parsed,
        );
    }

    #[test]
    fn roundtrip_close() {
        let bytes = encode_close(42, close_reason::PROXY_ROTATED);
        let parsed = parse_packet(bytes).unwrap();
        assert_eq!(
            WispPacket::Close(ClosePacket {
                stream_id: 42,
                reason: close_reason::PROXY_ROTATED,
            }),
            parsed,
        );
    }

    #[test]
    fn roundtrip_fin() {
        let bytes = encode_fin(9);
        assert_eq!(&bytes[..], &[0xf2, 9, 0, 0, 0]);
        assert_eq!(
            parse_packet(bytes).unwrap(),
            WispPacket::Fin(FinPacket { stream_id: 9 }),
        );
    }

    #[test]
    fn fin_with_payload_rejects() {
        let mut buf = BytesMut::new();
        buf.put_u8(packet_type::FIN);
        buf.put_u32_le(9);
        buf.put_u8(0);
        assert_eq!(
            parse_packet(buf.freeze()).unwrap_err(),
            WispError::FinPayloadNotEmpty,
        );
    }

    #[test]
    fn roundtrip_info_with_extensions() {
        let exts = vec![
            ExtensionEntry {
                id: extension_id::UDP,
                payload: Bytes::new(),
            },
            ExtensionEntry {
                id: extension_id::WISP_PROXY_CONTROL,
                payload: Bytes::from_static(br#"{"version":1}"#),
            },
        ];
        let bytes = encode_info(2, 1, &exts);
        let parsed = parse_packet(bytes).unwrap();
        match parsed {
            WispPacket::Info(info) => {
                assert_eq!(info.major, 2);
                assert_eq!(info.minor, 1);
                let parsed_exts = parse_extensions(info.extensions).unwrap();
                assert_eq!(parsed_exts, exts);
            }
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn truncated_packet_rejects() {
        assert_eq!(
            parse_packet(Bytes::from_static(&[0x01, 0x00, 0x00])).unwrap_err(),
            WispError::PacketTooShort,
        );
    }

    #[test]
    fn unknown_packet_type_rejects() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xff);
        buf.put_u32_le(0);
        assert_eq!(
            parse_packet(buf.freeze()).unwrap_err(),
            WispError::UnknownPacketType(0xff),
        );
    }

    #[test]
    fn truncated_extension_rejects() {
        let buf = Bytes::from_static(&[0x01, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            parse_extensions(buf).unwrap_err(),
            WispError::ExtensionPayloadTruncated,
        );
    }
}

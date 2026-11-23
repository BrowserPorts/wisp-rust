//! IP header validation and the fields a relay keys its flows by.
//!
//! [`inspect`] checks that a buffer is exactly one IPv4 or IPv6 packet with
//! sane header lengths before anything else looks at it, then reports its
//! addresses, upper-layer protocol, ports or ICMP type, and for an ICMP error
//! the addresses and ports of the packet it quotes.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP protocol and IPv6 next-header numbers used here.
pub mod proto {
    pub const HOP_BY_HOP: u8 = 0;
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT: u8 = 59;
    pub const DEST_OPTS: u8 = 60;
}

/// TCP flag bits.
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;
}

/// IPv6 extension headers walked before giving up.
const MAX_EXTENSION_HEADERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    Empty,
    /// The version nibble is neither 4 nor 6.
    Version(u8),
    /// Shorter than the fixed header.
    TooShort,
    /// IPv4 IHL below 5 or past the end of the packet.
    HeaderLength,
    /// The length field disagrees with the buffer's length.
    TotalLength,
    /// IPv4 header checksum mismatch.
    Checksum,
    /// IPv6 extension headers truncated or too many of them.
    ExtensionHeaders,
    /// The transport header is shorter than its protocol's minimum.
    Transport,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::Empty => f.write_str("empty packet"),
            PacketError::Version(v) => write!(f, "IP version {v}"),
            PacketError::TooShort => f.write_str("packet shorter than its IP header"),
            PacketError::HeaderLength => f.write_str("bad IPv4 header length"),
            PacketError::TotalLength => f.write_str("IP length field disagrees with the packet"),
            PacketError::Checksum => f.write_str("bad IPv4 header checksum"),
            PacketError::ExtensionHeaders => f.write_str("bad IPv6 extension headers"),
            PacketError::Transport => f.write_str("transport header truncated"),
        }
    }
}

impl core::error::Error for PacketError {}

/// Where a packet sits in an IP-level fragment train.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fragment {
    /// Not fragmented.
    None,
    /// The first fragment: it carries the transport header.
    First,
    /// A later fragment: no transport header.
    Later,
}

/// Addresses and ports of the packet an ICMP error quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quoted {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    /// Ports of a quoted TCP or UDP packet, or the echo identifier of a
    /// quoted echo, in both fields.
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Upper-layer protocol, after any IPv6 extension headers.
    pub protocol: u8,
    /// TTL or hop limit.
    pub ttl: u8,
    /// Offset of the upper-layer header.
    pub transport_offset: usize,
    pub fragment: Fragment,
    /// TCP and UDP ports; for ICMP echo the identifier in both. 0 otherwise.
    pub src_port: u16,
    pub dst_port: u16,
    /// ICMP or ICMPv6 type and code; 0 otherwise.
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// TCP flags; 0 otherwise.
    pub tcp_flags: u8,
    /// The quoted packet of an ICMP error, when it is long enough to read.
    pub quoted: Option<Quoted>,
}

impl PacketInfo {
    pub fn is_ipv4(&self) -> bool {
        self.src.is_ipv4()
    }

    pub fn is_icmp(&self) -> bool {
        self.protocol == proto::ICMP || self.protocol == proto::ICMPV6
    }

    /// An ICMP echo request.
    pub fn is_echo_request(&self) -> bool {
        (self.protocol == proto::ICMP && self.icmp_type == 8)
            || (self.protocol == proto::ICMPV6 && self.icmp_type == 128)
    }

    /// An ICMP echo reply.
    pub fn is_echo_reply(&self) -> bool {
        (self.protocol == proto::ICMP && self.icmp_type == 0)
            || (self.protocol == proto::ICMPV6 && self.icmp_type == 129)
    }

    /// An ICMP error message (destination unreachable, time exceeded, ...).
    pub fn is_icmp_error(&self) -> bool {
        match self.protocol {
            proto::ICMP => matches!(self.icmp_type, 3 | 4 | 5 | 11 | 12),
            proto::ICMPV6 => self.icmp_type < 128,
            _ => false,
        }
    }
}

/// Validates `packet` as one complete IPv4 or IPv6 packet and reads its
/// flow fields. Padding after the packet is rejected: one tunnel message is
/// exactly one packet.
pub fn inspect(packet: &[u8]) -> Result<PacketInfo, PacketError> {
    let first = *packet.first().ok_or(PacketError::Empty)?;
    match first >> 4 {
        4 => inspect_v4(packet),
        6 => inspect_v6(packet),
        v => Err(PacketError::Version(v)),
    }
}

fn inspect_v4(p: &[u8]) -> Result<PacketInfo, PacketError> {
    if p.len() < 20 {
        return Err(PacketError::TooShort);
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    if ihl < 20 || ihl > p.len() {
        return Err(PacketError::HeaderLength);
    }
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    if total != p.len() {
        return Err(PacketError::TotalLength);
    }
    if internet_checksum(&p[..ihl], 0) != 0 {
        return Err(PacketError::Checksum);
    }
    let flags_frag = u16::from_be_bytes([p[6], p[7]]);
    let more = flags_frag & 0x2000 != 0;
    let offset = flags_frag & 0x1fff;
    let fragment = match (offset, more) {
        (0, false) => Fragment::None,
        (0, true) => Fragment::First,
        _ => Fragment::Later,
    };
    let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
    finish(p, src, dst, p[9], p[8], ihl, fragment)
}

fn inspect_v6(p: &[u8]) -> Result<PacketInfo, PacketError> {
    if p.len() < 40 {
        return Err(PacketError::TooShort);
    }
    let payload = usize::from(u16::from_be_bytes([p[4], p[5]]));
    if payload + 40 != p.len() {
        return Err(PacketError::TotalLength);
    }
    let src = IpAddr::V6(v6_at(p, 8));
    let dst = IpAddr::V6(v6_at(p, 24));
    let (next, offset, fragment) = walk_v6_extensions(p, p[6], 40)?;
    finish(p, src, dst, next, p[7], offset, fragment)
}

/// Skips hop-by-hop, routing, fragment and destination-options headers.
fn walk_v6_extensions(
    p: &[u8],
    mut next: u8,
    mut offset: usize,
) -> Result<(u8, usize, Fragment), PacketError> {
    let mut fragment = Fragment::None;
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next {
            proto::HOP_BY_HOP | proto::ROUTING | proto::DEST_OPTS => {
                if p.len() < offset + 8 {
                    return Err(PacketError::ExtensionHeaders);
                }
                let len = (usize::from(p[offset + 1]) + 1) * 8;
                if p.len() < offset + len {
                    return Err(PacketError::ExtensionHeaders);
                }
                next = p[offset];
                offset += len;
            }
            proto::FRAGMENT => {
                if p.len() < offset + 8 {
                    return Err(PacketError::ExtensionHeaders);
                }
                let frag = u16::from_be_bytes([p[offset + 2], p[offset + 3]]);
                fragment = if frag >> 3 != 0 {
                    Fragment::Later
                } else {
                    Fragment::First
                };
                next = p[offset];
                offset += 8;
            }
            _ => return Ok((next, offset, fragment)),
        }
    }
    Err(PacketError::ExtensionHeaders)
}

fn v6_at(p: &[u8], at: usize) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&p[at..at + 16]);
    Ipv6Addr::from(o)
}

fn finish(
    p: &[u8],
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    ttl: u8,
    offset: usize,
    fragment: Fragment,
) -> Result<PacketInfo, PacketError> {
    let mut info = PacketInfo {
        src,
        dst,
        protocol,
        ttl,
        transport_offset: offset,
        fragment,
        src_port: 0,
        dst_port: 0,
        icmp_type: 0,
        icmp_code: 0,
        tcp_flags: 0,
        quoted: None,
    };
    if fragment == Fragment::Later {
        return Ok(info);
    }
    let t = &p[offset..];
    match protocol {
        proto::TCP => {
            if t.len() < 20 {
                return Err(PacketError::Transport);
            }
            info.src_port = u16::from_be_bytes([t[0], t[1]]);
            info.dst_port = u16::from_be_bytes([t[2], t[3]]);
            info.tcp_flags = t[13];
        }
        proto::UDP => {
            if t.len() < 8 {
                return Err(PacketError::Transport);
            }
            info.src_port = u16::from_be_bytes([t[0], t[1]]);
            info.dst_port = u16::from_be_bytes([t[2], t[3]]);
        }
        proto::ICMP | proto::ICMPV6 => {
            if t.len() < 8 {
                return Err(PacketError::Transport);
            }
            info.icmp_type = t[0];
            info.icmp_code = t[1];
            if info.is_echo_request() || info.is_echo_reply() {
                let id = u16::from_be_bytes([t[4], t[5]]);
                info.src_port = id;
                info.dst_port = id;
            } else if info.is_icmp_error() {
                info.quoted = quoted(&t[8..]);
            }
        }
        _ => {}
    }
    Ok(info)
}

/// Reads the head of the packet an ICMP error quotes. Quotes are often cut
/// short, so only the IP header and the first 8 bytes after it are needed.
fn quoted(q: &[u8]) -> Option<Quoted> {
    let first = *q.first()?;
    let (src, dst, mut next, offset) = match first >> 4 {
        4 => {
            if q.len() < 20 {
                return None;
            }
            let ihl = usize::from(first & 0x0f) * 4;
            if ihl < 20 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(q[12], q[13], q[14], q[15])),
                IpAddr::V4(Ipv4Addr::new(q[16], q[17], q[18], q[19])),
                q[9],
                ihl,
            )
        }
        6 => {
            if q.len() < 40 {
                return None;
            }
            (IpAddr::V6(v6_at(q, 8)), IpAddr::V6(v6_at(q, 24)), q[6], 40)
        }
        _ => return None,
    };
    let mut offset = offset;
    if src.is_ipv6() {
        let (n, o, _) = walk_v6_extensions(q, next, offset).ok()?;
        next = n;
        offset = o;
    }
    let t = q.get(offset..)?;
    let (src_port, dst_port) = match next {
        proto::TCP | proto::UDP if t.len() >= 4 => (
            u16::from_be_bytes([t[0], t[1]]),
            u16::from_be_bytes([t[2], t[3]]),
        ),
        proto::ICMP | proto::ICMPV6 if t.len() >= 6 => {
            let id = u16::from_be_bytes([t[4], t[5]]);
            (id, id)
        }
        _ => (0, 0),
    };
    Some(Quoted {
        src,
        dst,
        protocol: next,
        src_port,
        dst_port,
    })
}

/// The Internet checksum (RFC 1071) of `data`, starting from a partial sum
/// such as a pseudo-header's. A buffer that carries a correct checksum sums
/// to 0.
pub fn internet_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = u64::from(initial);
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u64::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u64::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Partial sum of the TCP, UDP or ICMPv6 pseudo-header, to pass as
/// `initial` to [`internet_checksum`] over the upper-layer message.
pub fn pseudo_header_sum(src: IpAddr, dst: IpAddr, protocol: u8, len: usize) -> u32 {
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        for c in bytes.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
    };
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            add(&s.octets());
            add(&d.octets());
            sum += u32::from(protocol);
            sum += len as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            add(&s.octets());
            add(&d.octets());
            sum += (len as u32) >> 16;
            sum += (len as u32) & 0xffff;
            sum += u32::from(protocol);
        }
        _ => {}
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A minimal IPv4 packet with a correct header checksum.
    pub(crate) fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = Vec::with_capacity(total);
        p.extend_from_slice(&[
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            1,
            0,
            0,
            64,
            protocol,
            0,
            0,
        ]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        let c = internet_checksum(&p, 0);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn ipv6(src: &str, dst: &str, next: u8, payload: &[u8]) -> Vec<u8> {
        let src: Ipv6Addr = src.parse().unwrap();
        let dst: Ipv6Addr = dst.parse().unwrap();
        let mut p = Vec::new();
        p.extend_from_slice(&[0x60, 0, 0, 0]);
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.push(next);
        p.push(64);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    fn udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&[0, 8, 0, 0]);
        u
    }

    #[test]
    fn ipv4_udp_fields() {
        let p = ipv4([192, 168, 1, 100], [8, 8, 8, 8], proto::UDP, &udp(5353, 53));
        let info = inspect(&p).unwrap();
        assert_eq!(info.src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(info.dst, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(info.protocol, proto::UDP);
        assert_eq!((info.src_port, info.dst_port), (5353, 53));
        assert_eq!(info.ttl, 64);
        assert_eq!(info.fragment, Fragment::None);
    }

    #[test]
    fn ipv4_rejects_bad_headers() {
        let good = ipv4([10, 0, 0, 1], [1, 1, 1, 1], proto::UDP, &udp(1, 2));
        assert_eq!(inspect(&[]), Err(PacketError::Empty));
        assert_eq!(inspect(&good[..19]), Err(PacketError::TooShort));
        let mut padded = good.clone();
        padded.push(0);
        assert_eq!(inspect(&padded), Err(PacketError::TotalLength));
        let mut bad_sum = good.clone();
        bad_sum[11] ^= 1;
        assert_eq!(inspect(&bad_sum), Err(PacketError::Checksum));
        let mut bad_ihl = good.clone();
        bad_ihl[0] = 0x44;
        assert_eq!(inspect(&bad_ihl), Err(PacketError::HeaderLength));
        let mut bad_version = good;
        bad_version[0] = 0x55;
        assert_eq!(inspect(&bad_version), Err(PacketError::Version(5)));
        let short_tcp = ipv4([10, 0, 0, 1], [1, 1, 1, 1], proto::TCP, &[0; 10]);
        assert_eq!(inspect(&short_tcp), Err(PacketError::Transport));
    }

    #[test]
    fn ipv6_walks_extension_headers() {
        // Hop-by-hop (8 bytes, next = fragment), fragment (offset 0, M=1, next = UDP).
        let mut payload = Vec::new();
        payload.extend_from_slice(&[proto::FRAGMENT, 0, 1, 4, 0, 0, 0, 0]);
        payload.extend_from_slice(&[proto::UDP, 0, 0, 1, 0, 0, 0, 7]);
        payload.extend_from_slice(&udp(4000, 443));
        let p = ipv6("2001:db8::1", "2606:4700::1", proto::HOP_BY_HOP, &payload);
        let info = inspect(&p).unwrap();
        assert_eq!(info.protocol, proto::UDP);
        assert_eq!(info.fragment, Fragment::First);
        assert_eq!((info.src_port, info.dst_port), (4000, 443));
        assert_eq!(info.transport_offset, 56);
    }

    #[test]
    fn ipv6_rejects_bad_lengths() {
        let p = ipv6("::1", "::2", proto::UDP, &udp(1, 2));
        assert_eq!(inspect(&p[..39]), Err(PacketError::TooShort));
        let mut padded = p.clone();
        padded.push(0);
        assert_eq!(inspect(&padded), Err(PacketError::TotalLength));
        let cut = ipv6("::1", "::2", proto::HOP_BY_HOP, &[proto::UDP, 4, 0, 0]);
        assert_eq!(inspect(&cut), Err(PacketError::ExtensionHeaders));
    }

    #[test]
    fn icmp_echo_and_errors() {
        let echo = ipv4(
            [192, 168, 1, 100],
            [1, 1, 1, 1],
            proto::ICMP,
            &[8, 0, 0, 0, 0x12, 0x34, 0, 1],
        );
        let info = inspect(&echo).unwrap();
        assert!(info.is_echo_request());
        assert_eq!(info.src_port, 0x1234);

        let inner = ipv4([192, 168, 1, 100], [9, 9, 9, 9], proto::UDP, &udp(1234, 53));
        let mut icmp = Vec::from([3u8, 3, 0, 0, 0, 0, 0, 0]);
        icmp.extend_from_slice(&inner[..28]);
        let err = ipv4([192, 168, 1, 100], [9, 9, 9, 9], proto::ICMP, &icmp);
        let info = inspect(&err).unwrap();
        assert!(info.is_icmp_error());
        let q = info.quoted.unwrap();
        assert_eq!(q.protocol, proto::UDP);
        assert_eq!((q.src_port, q.dst_port), (1234, 53));
        assert_eq!(q.dst, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
    }

    #[test]
    fn later_ipv4_fragments_have_no_ports() {
        let mut p = ipv4([10, 0, 0, 1], [1, 1, 1, 1], proto::UDP, &[1, 2, 3]);
        p[6] = 0x00;
        p[7] = 0x10;
        p[10] = 0;
        p[11] = 0;
        let c = internet_checksum(&p[..20], 0);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let info = inspect(&p).unwrap();
        assert_eq!(info.fragment, Fragment::Later);
        assert_eq!(info.src_port, 0);
    }

    #[test]
    fn checksum_matches_rfc1071_example() {
        // RFC 1071 section 3: 00 01 f2 03 f4 f5 f6 f7 sums to ddf2.
        assert_eq!(
            internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7], 0),
            !0xddf2
        );
    }
}

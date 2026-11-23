//! Tunnel control capsules: `[type:u16][length:u16][value: length bytes]`,
//! processed in order within one message.
//!
//! A receiver ignores a capsule it does not know whose type has bit 15 set;
//! an unknown type with bit 15 clear is an error, on which the receiver closes
//! the tunnel with reason 0x41.
//!
//! Addresses travel as `[family:u8 (4 or 6)][prefix_len:u8][4 or 16 bytes]`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Capsule type numbers of version 1.
pub mod capsule_type {
    /// C→S `[want:u16]`, first in the message that opens a tunnel.
    pub const OPEN: u16 = 0x0001;
    /// C→S addresses or prefixes the client would like.
    pub const ADDRESS_REQUEST: u16 = 0x0002;
    /// S→C the complete current address set, with lifetimes.
    pub const ADDRESS_ASSIGN: u16 = 0x0003;
    /// S→C the complete set of routes the server forwards.
    pub const ROUTE_ADVERTISEMENT: u16 = 0x0004;
    /// S→C `[link_mtu:u16][max_packet:u16][max_datagram_payload:u16]`.
    pub const LINK: u16 = 0x0005;
    /// S→C resolvers reachable through the tunnel and a search list.
    pub const DNS_CONFIG: u16 = 0x0006;
    /// S→C `[grace_s:u32][token: 32 bytes]`.
    pub const RESUME_TOKEN: u16 = 0x0007;
    /// C→S `[token: 32 bytes]`, only together with `OPEN`.
    pub const RESUME: u16 = 0x0008;
    /// S→C `[code:u16][message: UTF-8]`, informative.
    pub const ERROR: u16 = 0x0009;
}

/// Bit that marks a capsule type a receiver may ignore when it does not
/// know it.
pub const OPTIONAL_TYPE_BIT: u16 = 0x8000;

/// Capsules accepted in one message. Version 1 never needs more than nine.
pub const MAX_CAPSULES: usize = 32;

/// Bits of the `OPEN` capsule's `want` field.
pub mod want {
    pub const IPV4: u16 = 1 << 0;
    pub const IPV6: u16 = 1 << 1;
    /// WebTransport binding: carry this tunnel's packets in datagrams.
    pub const DATAGRAMS: u16 = 1 << 2;
}

/// `ERROR` capsule codes (section 9).
pub mod error_code {
    pub const NO_ADDRESS: u16 = 0x0001;
    pub const FAMILY_NOT_OFFERED: u16 = 0x0002;
    pub const TOO_MANY_TUNNELS: u16 = 0x0003;
    pub const RESUME_REJECTED: u16 = 0x0004;
    pub const PACKET_LIMITS: u16 = 0x0005;
}

/// Lifetime value meaning "forever".
pub const FOREVER: u32 = u32::MAX;

/// Length of a resume token.
pub const TOKEN_LEN: usize = 32;

/// A bearer secret that lets a client resume its tunnel.
pub type ResumeToken = [u8; TOKEN_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    /// The buffer ends inside a capsule header or value.
    Truncated,
    /// An unknown capsule type with bit 15 clear.
    UnknownCritical(u16),
    /// A known capsule whose value does not have the layout of its type.
    Malformed(u16),
    /// More than [`MAX_CAPSULES`] capsules in one message.
    TooMany,
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapsuleError::Truncated => f.write_str("capsule truncated"),
            CapsuleError::UnknownCritical(t) => write!(f, "unknown capsule type {t:#06x}"),
            CapsuleError::Malformed(t) => write!(f, "malformed capsule of type {t:#06x}"),
            CapsuleError::TooMany => f.write_str("too many capsules in one message"),
        }
    }
}

impl core::error::Error for CapsuleError {}

/// An address and prefix length, `prefix_len` bounded by the family's width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    /// `None` when `len` is wider than the address.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        (len <= max_prefix(addr)).then_some(Self { addr, len })
    }

    /// A single address (/32 or /128).
    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            len: max_prefix(addr),
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn len(&self) -> u8 {
        self.len
    }

    /// `true` for a prefix of length 0 (`0.0.0.0/0`, `::/0`).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// The address with the host bits cleared.
    pub fn network(&self) -> IpAddr {
        mask(self.addr, self.len)
    }

    /// Whether `ip` lies inside this prefix (same family, same leading bits).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(self.addr, self.len) == mask(ip, self.len)
            }
            _ => false,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self.addr {
            IpAddr::V4(v4) => {
                out.push(4);
                out.push(self.len);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(6);
                out.push(self.len);
                out.extend_from_slice(&v6.octets());
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Option<Self> {
        let family = r.u8()?;
        let len = r.u8()?;
        let addr = r.addr(family)?;
        Self::new(addr, len)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        32
    } else {
        128
    }
}

fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len.min(32)))
            };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len.min(128)))
            };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

/// One entry of `ADDRESS_ASSIGN`. A prefix shorter than the address width is
/// on-link: the client may use any address in it and treats the rest as its
/// LAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddress {
    pub prefix: Prefix,
    pub valid_lft: u32,
    pub preferred_lft: u32,
}

/// One entry of `ROUTE_ADVERTISEMENT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEntry {
    pub dest: Prefix,
    pub gateway: IpAddr,
    pub metric: u32,
}

/// The `LINK` capsule. `max_datagram_payload` is 0 on the WebSocket binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkParams {
    pub link_mtu: u16,
    pub max_packet: u16,
    pub max_datagram_payload: u16,
}

/// The `DNS_CONFIG` capsule: resolvers reachable through the tunnel and a
/// search list of names separated by one space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub servers: Vec<IpAddr>,
    pub search: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    Open { want: u16 },
    AddressRequest(Vec<Prefix>),
    AddressAssign(Vec<AssignedAddress>),
    RouteAdvertisement(Vec<RouteEntry>),
    Link(LinkParams),
    DnsConfig(DnsConfig),
    ResumeToken { grace_s: u32, token: ResumeToken },
    Resume { token: ResumeToken },
    Error { code: u16, message: String },
}

impl Capsule {
    pub fn capsule_type(&self) -> u16 {
        match self {
            Capsule::Open { .. } => capsule_type::OPEN,
            Capsule::AddressRequest(_) => capsule_type::ADDRESS_REQUEST,
            Capsule::AddressAssign(_) => capsule_type::ADDRESS_ASSIGN,
            Capsule::RouteAdvertisement(_) => capsule_type::ROUTE_ADVERTISEMENT,
            Capsule::Link(_) => capsule_type::LINK,
            Capsule::DnsConfig(_) => capsule_type::DNS_CONFIG,
            Capsule::ResumeToken { .. } => capsule_type::RESUME_TOKEN,
            Capsule::Resume { .. } => capsule_type::RESUME,
            Capsule::Error { .. } => capsule_type::ERROR,
        }
    }

    /// Appends this capsule. A list longer than 255 entries is cut at 255
    /// and a value longer than 65535 bytes is cut to fit: neither can come
    /// from a validated configuration.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut value = Vec::new();
        match self {
            Capsule::Open { want } => value.extend_from_slice(&want.to_le_bytes()),
            Capsule::AddressRequest(prefixes) => {
                let n = prefixes.len().min(255);
                value.push(n as u8);
                for p in &prefixes[..n] {
                    p.encode(&mut value);
                }
            }
            Capsule::AddressAssign(addrs) => {
                let n = addrs.len().min(255);
                value.push(n as u8);
                for a in &addrs[..n] {
                    a.prefix.encode(&mut value);
                    value.extend_from_slice(&a.valid_lft.to_le_bytes());
                    value.extend_from_slice(&a.preferred_lft.to_le_bytes());
                }
            }
            Capsule::RouteAdvertisement(routes) => {
                let n = routes.len().min(255);
                value.push(n as u8);
                for r in &routes[..n] {
                    r.dest.encode(&mut value);
                    push_addr(&mut value, r.gateway);
                    value.extend_from_slice(&r.metric.to_le_bytes());
                }
            }
            Capsule::Link(link) => {
                value.extend_from_slice(&link.link_mtu.to_le_bytes());
                value.extend_from_slice(&link.max_packet.to_le_bytes());
                value.extend_from_slice(&link.max_datagram_payload.to_le_bytes());
            }
            Capsule::DnsConfig(dns) => {
                let n = dns.servers.len().min(255);
                value.push(n as u8);
                for s in &dns.servers[..n] {
                    value.push(if s.is_ipv4() { 4 } else { 6 });
                    push_addr(&mut value, *s);
                }
                let search = truncate_utf8(&dns.search, usize::from(u16::MAX) - value.len() - 2);
                value.extend_from_slice(&(search.len() as u16).to_le_bytes());
                value.extend_from_slice(search.as_bytes());
            }
            Capsule::ResumeToken { grace_s, token } => {
                value.extend_from_slice(&grace_s.to_le_bytes());
                value.extend_from_slice(token);
            }
            Capsule::Resume { token } => value.extend_from_slice(token),
            Capsule::Error { code, message } => {
                value.extend_from_slice(&code.to_le_bytes());
                value.extend_from_slice(
                    truncate_utf8(message, usize::from(u16::MAX) - 2).as_bytes(),
                );
            }
        }
        value.truncate(usize::from(u16::MAX));
        out.extend_from_slice(&self.capsule_type().to_le_bytes());
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(&value);
    }

    fn decode(ty: u16, value: &[u8]) -> Result<Option<Self>, CapsuleError> {
        let mut r = Reader::new(value);
        let bad = CapsuleError::Malformed(ty);
        let capsule = match ty {
            capsule_type::OPEN => Capsule::Open {
                want: r.u16().ok_or(bad.clone())?,
            },
            capsule_type::ADDRESS_REQUEST => {
                let n = r.u8().ok_or(bad.clone())?;
                let mut out = Vec::with_capacity(usize::from(n));
                for _ in 0..n {
                    out.push(Prefix::decode(&mut r).ok_or(bad.clone())?);
                }
                Capsule::AddressRequest(out)
            }
            capsule_type::ADDRESS_ASSIGN => {
                let n = r.u8().ok_or(bad.clone())?;
                let mut out = Vec::with_capacity(usize::from(n));
                for _ in 0..n {
                    let prefix = Prefix::decode(&mut r).ok_or(bad.clone())?;
                    let valid_lft = r.u32().ok_or(bad.clone())?;
                    let preferred_lft = r.u32().ok_or(bad.clone())?;
                    out.push(AssignedAddress {
                        prefix,
                        valid_lft,
                        preferred_lft,
                    });
                }
                Capsule::AddressAssign(out)
            }
            capsule_type::ROUTE_ADVERTISEMENT => {
                let n = r.u8().ok_or(bad.clone())?;
                let mut out = Vec::with_capacity(usize::from(n));
                for _ in 0..n {
                    let dest = Prefix::decode(&mut r).ok_or(bad.clone())?;
                    let family = if dest.is_ipv4() { 4 } else { 6 };
                    let gateway = r.addr(family).ok_or(bad.clone())?;
                    let metric = r.u32().ok_or(bad.clone())?;
                    out.push(RouteEntry {
                        dest,
                        gateway,
                        metric,
                    });
                }
                Capsule::RouteAdvertisement(out)
            }
            capsule_type::LINK => Capsule::Link(LinkParams {
                link_mtu: r.u16().ok_or(bad.clone())?,
                max_packet: r.u16().ok_or(bad.clone())?,
                max_datagram_payload: r.u16().ok_or(bad.clone())?,
            }),
            capsule_type::DNS_CONFIG => {
                let n = r.u8().ok_or(bad.clone())?;
                let mut servers = Vec::with_capacity(usize::from(n));
                for _ in 0..n {
                    let family = r.u8().ok_or(bad.clone())?;
                    servers.push(r.addr(family).ok_or(bad.clone())?);
                }
                let len = r.u16().ok_or(bad.clone())?;
                let raw = r.take(usize::from(len)).ok_or(bad.clone())?;
                let search = core::str::from_utf8(raw).map_err(|_| bad.clone())?;
                Capsule::DnsConfig(DnsConfig {
                    servers,
                    search: String::from(search),
                })
            }
            capsule_type::RESUME_TOKEN => Capsule::ResumeToken {
                grace_s: r.u32().ok_or(bad.clone())?,
                token: r.token().ok_or(bad.clone())?,
            },
            capsule_type::RESUME => Capsule::Resume {
                token: r.token().ok_or(bad.clone())?,
            },
            capsule_type::ERROR => {
                let code = r.u16().ok_or(bad.clone())?;
                let message = core::str::from_utf8(r.rest()).map_err(|_| bad.clone())?;
                Capsule::Error {
                    code,
                    message: String::from(message),
                }
            }
            other if other & OPTIONAL_TYPE_BIT != 0 => return Ok(None),
            other => return Err(CapsuleError::UnknownCritical(other)),
        };
        if !r.is_empty() {
            return Err(bad);
        }
        Ok(Some(capsule))
    }
}

fn push_addr(out: &mut Vec<u8>, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Parses every capsule of a message, in order. Unknown optional capsules
/// are skipped; anything else unknown or malformed fails the whole message.
pub fn parse_capsules(buf: &[u8]) -> Result<Vec<Capsule>, CapsuleError> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut seen = 0usize;
    while offset < buf.len() {
        seen += 1;
        if seen > MAX_CAPSULES {
            return Err(CapsuleError::TooMany);
        }
        if buf.len() - offset < 4 {
            return Err(CapsuleError::Truncated);
        }
        let ty = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let len = usize::from(u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]));
        let start = offset + 4;
        let end = start + len;
        if end > buf.len() {
            return Err(CapsuleError::Truncated);
        }
        if let Some(capsule) = Capsule::decode(ty, &buf[start..end])? {
            out.push(capsule);
        }
        offset = end;
    }
    Ok(out)
}

/// Encodes capsules back to back.
pub fn encode_capsules(capsules: &[Capsule]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in capsules {
        c.encode(&mut out);
    }
    out
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Some(head)
    }

    fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buf)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn token(&mut self) -> Option<ResumeToken> {
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(self.take(TOKEN_LEN)?);
        Some(token)
    }

    fn addr(&mut self, family: u8) -> Option<IpAddr> {
        match family {
            4 => {
                let b = self.take(4)?;
                Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            }
            6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(self.take(16)?);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn open_matches_the_spec_example() {
        // EXTENSION.md 6.1, open on stream 7 asking for IPv4 and IPv6:
        // F3 07 00 00 00 | 01 00 02 00 03 00
        let bytes = encode_capsules(&[Capsule::Open { want: 0x0003 }]);
        assert_eq!(bytes, [0x01, 0x00, 0x02, 0x00, 0x03, 0x00]);
        assert_eq!(
            parse_capsules(&bytes).unwrap(),
            vec![Capsule::Open { want: 3 }]
        );
    }

    #[test]
    fn answer_matches_the_spec_example() {
        let capsules = vec![
            Capsule::AddressAssign(vec![AssignedAddress {
                prefix: Prefix::new(v4(192, 168, 1, 100), 24).unwrap(),
                valid_lft: FOREVER,
                preferred_lft: FOREVER,
            }]),
            Capsule::RouteAdvertisement(vec![RouteEntry {
                dest: Prefix::new(v4(0, 0, 0, 0), 0).unwrap(),
                gateway: v4(192, 168, 1, 1),
                metric: 100,
            }]),
            Capsule::Link(LinkParams {
                link_mtu: 1500,
                max_packet: 1500,
                max_datagram_payload: 0,
            }),
        ];
        let bytes = encode_capsules(&capsules);
        // EXTENSION.md 6.1, the answer: 192.168.1.100/24, default route via
        // 192.168.1.1 metric 100, MTU 1500.
        let expected: &[u8] = &[
            0x03, 0x00, 0x0f, 0x00, 0x01, 0x04, 0x18, 0xc0, 0xa8, 0x01, 0x64, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, //
            0x04, 0x00, 0x0f, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01,
            0x01, 0x64, 0x00, 0x00, 0x00, //
            0x05, 0x00, 0x06, 0x00, 0xdc, 0x05, 0xdc, 0x05, 0x00, 0x00,
        ];
        assert_eq!(bytes, expected);
        assert_eq!(parse_capsules(&bytes).unwrap(), capsules);
    }

    #[test]
    fn every_capsule_round_trips() {
        let v6: IpAddr = "2001:db8:1:2::100".parse().unwrap();
        let capsules = vec![
            Capsule::Open { want: 7 },
            Capsule::AddressRequest(vec![
                Prefix::new(v4(192, 168, 1, 100), 32).unwrap(),
                Prefix::new(v6, 64).unwrap(),
            ]),
            Capsule::AddressAssign(vec![AssignedAddress {
                prefix: Prefix::new(v6, 64).unwrap(),
                valid_lft: 3600,
                preferred_lft: 1800,
            }]),
            Capsule::RouteAdvertisement(vec![RouteEntry {
                dest: Prefix::new("::".parse().unwrap(), 0).unwrap(),
                gateway: "fe80::1".parse().unwrap(),
                metric: 1024,
            }]),
            Capsule::DnsConfig(DnsConfig {
                servers: vec![v4(192, 168, 1, 1), "2001:4860:4860::8888".parse().unwrap()],
                search: String::from("lan example.com"),
            }),
            Capsule::ResumeToken {
                grace_s: 30,
                token: [7; TOKEN_LEN],
            },
            Capsule::Resume {
                token: [9; TOKEN_LEN],
            },
            Capsule::Error {
                code: error_code::RESUME_REJECTED,
                message: String::from("token expired"),
            },
        ];
        let bytes = encode_capsules(&capsules);
        assert_eq!(parse_capsules(&bytes).unwrap(), capsules);
    }

    #[test]
    fn unknown_optional_capsules_are_skipped() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x8123u16.to_le_bytes());
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        Capsule::Open { want: 1 }.encode(&mut bytes);
        assert_eq!(
            parse_capsules(&bytes).unwrap(),
            vec![Capsule::Open { want: 1 }]
        );
    }

    #[test]
    fn unknown_critical_capsules_fail_the_message() {
        let mut bytes = Vec::new();
        Capsule::Open { want: 1 }.encode(&mut bytes);
        bytes.extend_from_slice(&0x0123u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            parse_capsules(&bytes),
            Err(CapsuleError::UnknownCritical(0x0123))
        );
    }

    #[test]
    fn malformed_and_truncated_capsules_fail() {
        // OPEN with a one-byte value.
        assert_eq!(
            parse_capsules(&[0x01, 0x00, 0x01, 0x00, 0x03]),
            Err(CapsuleError::Malformed(capsule_type::OPEN))
        );
        // OPEN with a trailing byte.
        assert_eq!(
            parse_capsules(&[0x01, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00]),
            Err(CapsuleError::Malformed(capsule_type::OPEN))
        );
        // Header cut short.
        assert_eq!(
            parse_capsules(&[0x01, 0x00, 0x02]),
            Err(CapsuleError::Truncated)
        );
        // Value longer than the buffer.
        assert_eq!(
            parse_capsules(&[0x01, 0x00, 0x09, 0x00, 0x03, 0x00]),
            Err(CapsuleError::Truncated)
        );
        // Family 5 and an IPv4 prefix of /33.
        assert_eq!(
            parse_capsules(&[0x02, 0x00, 0x07, 0x00, 0x01, 0x05, 0x18, 1, 2, 3, 4]),
            Err(CapsuleError::Malformed(capsule_type::ADDRESS_REQUEST))
        );
        assert_eq!(
            parse_capsules(&[0x02, 0x00, 0x07, 0x00, 0x01, 0x04, 33, 1, 2, 3, 4]),
            Err(CapsuleError::Malformed(capsule_type::ADDRESS_REQUEST))
        );
        // ERROR whose message is not UTF-8.
        assert_eq!(
            parse_capsules(&[0x09, 0x00, 0x03, 0x00, 0x01, 0x00, 0xff]),
            Err(CapsuleError::Malformed(capsule_type::ERROR))
        );
    }

    #[test]
    fn message_capsule_count_is_bounded() {
        let mut bytes = Vec::new();
        for _ in 0..=MAX_CAPSULES {
            bytes.extend_from_slice(&0x8001u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }
        assert_eq!(parse_capsules(&bytes), Err(CapsuleError::TooMany));
    }

    #[test]
    fn prefix_contains_its_addresses_only() {
        let lan = Prefix::new(v4(192, 168, 1, 100), 24).unwrap();
        assert!(lan.contains(v4(192, 168, 1, 7)));
        assert!(!lan.contains(v4(192, 168, 2, 7)));
        assert!(!lan.contains("::1".parse().unwrap()));
        assert_eq!(lan.network(), v4(192, 168, 1, 0));
        let all = Prefix::new(v4(0, 0, 0, 0), 0).unwrap();
        assert!(all.contains(v4(8, 8, 8, 8)));
        let v6 = Prefix::new("2001:db8:1:2::".parse().unwrap(), 64).unwrap();
        assert!(v6.contains("2001:db8:1:2:aaaa::1".parse().unwrap()));
        assert!(!v6.contains("2001:db8:1:3::1".parse().unwrap()));
        assert!(Prefix::new(v4(1, 2, 3, 4), 33).is_none());
    }
}

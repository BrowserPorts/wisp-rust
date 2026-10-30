//! Ethernet II frames, ARP and the ICMPv6 neighbour-discovery messages the
//! virtual router reads and writes. Only what a router on a one-host link
//! needs: no VLANs, no IPv6 extension headers in NDP, no ARP for anything
//! but IPv4 over Ethernet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wisp_ip::packet::{internet_checksum, pseudo_header_sum};

pub type Mac = [u8; 6];

pub const BROADCAST: Mac = [0xff; 6];

pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86dd;
}

/// Destination, source and type.
pub const HEADER_LEN: usize = 14;

/// Shortest frame on the wire without its frame check sequence. Shorter
/// frames are padded, as an Ethernet interface pads them.
pub const MIN_FRAME_LEN: usize = 60;

pub mod icmpv6 {
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
    pub const MLD_QUERY: u8 = 130;
    pub const MLD_REPORT: u8 = 131;
    pub const MLD_DONE: u8 = 132;
    pub const ROUTER_SOLICITATION: u8 = 133;
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
    pub const REDIRECT: u8 = 137;
    pub const MLDV2_REPORT: u8 = 143;
}

/// Neighbour-discovery option types (RFC 4861, RFC 8106).
pub mod nd_option {
    pub const SOURCE_LINK_ADDR: u8 = 1;
    pub const TARGET_LINK_ADDR: u8 = 2;
    pub const PREFIX_INFO: u8 = 3;
    pub const MTU: u8 = 5;
    pub const RDNSS: u8 = 25;
}

/// All-nodes multicast, where unsolicited router advertisements go.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

pub fn is_multicast(mac: &Mac) -> bool {
    mac[0] & 1 == 1
}

/// The Ethernet address an IPv6 multicast address maps to (RFC 2464).
pub fn ipv6_multicast_mac(addr: Ipv6Addr) -> Mac {
    let o = addr.octets();
    [0x33, 0x33, o[12], o[13], o[14], o[15]]
}

pub struct Frame<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_frame(frame: &[u8]) -> Option<Frame<'_>> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    Some(Frame {
        dst,
        src,
        ethertype: u16::from_be_bytes([frame[12], frame[13]]),
        payload: &frame[HEADER_LEN..],
    })
}

pub fn build_frame(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((HEADER_LEN + payload.len()).max(MIN_FRAME_LEN));
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    if f.len() < MIN_FRAME_LEN {
        f.resize(MIN_FRAME_LEN, 0);
    }
    f
}

// ---- ARP --------------------------------------------------------------------

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4Addr,
    pub target_mac: Mac,
    pub target_ip: Ipv4Addr,
}

/// An ARP message for IPv4 over Ethernet; anything else is `None`.
pub fn parse_arp(p: &[u8]) -> Option<Arp> {
    if p.len() < 28 || p[0..2] != [0, 1] || p[2..4] != [0x08, 0x00] || p[4] != 6 || p[5] != 4 {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    let mut target_mac = [0u8; 6];
    sender_mac.copy_from_slice(&p[8..14]);
    target_mac.copy_from_slice(&p[18..24]);
    Some(Arp {
        op: u16::from_be_bytes([p[6], p[7]]),
        sender_mac,
        sender_ip: Ipv4Addr::new(p[14], p[15], p[16], p[17]),
        target_mac,
        target_ip: Ipv4Addr::new(p[24], p[25], p[26], p[27]),
    })
}

pub fn build_arp(a: &Arp) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
    p.extend_from_slice(&a.op.to_be_bytes());
    p.extend_from_slice(&a.sender_mac);
    p.extend_from_slice(&a.sender_ip.octets());
    p.extend_from_slice(&a.target_mac);
    p.extend_from_slice(&a.target_ip.octets());
    p
}

// ---- IP headers ------------------------------------------------------------

/// The IP version nibble, and the packet cut to the length its header
/// gives (frames may carry padding). `None` when the header is cut short or
/// claims more bytes than the frame holds.
pub fn ip_packet(ethertype: u16, payload: &[u8]) -> Option<&[u8]> {
    match ethertype {
        ethertype::IPV4 => {
            if payload.len() < 20 || payload[0] >> 4 != 4 {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            let ihl = usize::from(payload[0] & 0x0f) * 4;
            if ihl < 20 || total < ihl || total > payload.len() {
                return None;
            }
            Some(&payload[..total])
        }
        ethertype::IPV6 => {
            if payload.len() < 40 || payload[0] >> 4 != 6 {
                return None;
            }
            let total = 40 + usize::from(u16::from_be_bytes([payload[4], payload[5]]));
            if total > payload.len() {
                return None;
            }
            Some(&payload[..total])
        }
        _ => None,
    }
}

pub fn ipv4_dst(p: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(p[16], p[17], p[18], p[19])
}

pub fn ipv6_src(p: &[u8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&p[8..24]);
    Ipv6Addr::from(o)
}

pub fn ipv6_dst(p: &[u8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&p[24..40]);
    Ipv6Addr::from(o)
}

pub fn is_ipv6_link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// An ICMPv6 message wrapped in an IPv6 header with hop limit 255 (as
/// neighbour discovery requires), checksum filled in.
pub fn build_icmpv6(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8, mut msg: Vec<u8>) -> Vec<u8> {
    msg[2] = 0;
    msg[3] = 0;
    let sum = internet_checksum(
        &msg,
        pseudo_header_sum(IpAddr::V6(src), IpAddr::V6(dst), 58, msg.len()),
    );
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut p = Vec::with_capacity(40 + msg.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    p.push(58);
    p.push(hop_limit);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&msg);
    p
}

/// An ICMPv6 message directly after the IPv6 header: its type, code, hop
/// limit and body (from the type byte on). `None` for anything else.
pub struct Icmpv6<'a> {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub hop_limit: u8,
    pub ty: u8,
    pub code: u8,
    pub msg: &'a [u8],
}

pub fn parse_icmpv6(packet: &[u8]) -> Option<Icmpv6<'_>> {
    if packet.len() < 44 || packet[6] != 58 {
        return None;
    }
    let msg = &packet[40..];
    let sum = internet_checksum(
        msg,
        pseudo_header_sum(
            IpAddr::V6(ipv6_src(packet)),
            IpAddr::V6(ipv6_dst(packet)),
            58,
            msg.len(),
        ),
    );
    if sum != 0 {
        return None;
    }
    Some(Icmpv6 {
        src: ipv6_src(packet),
        dst: ipv6_dst(packet),
        hop_limit: packet[7],
        ty: msg[0],
        code: msg[1],
        msg,
    })
}

/// The options of a neighbour-discovery message, starting at `offset` of
/// the ICMPv6 message: `(type, body without the type and length bytes)`.
/// `None` for an option of length 0 or one that runs past the end.
pub fn nd_options(msg: &[u8], offset: usize) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut i = offset;
    while i < msg.len() {
        if msg.len() - i < 2 {
            return None;
        }
        let len = usize::from(msg[i + 1]) * 8;
        if len == 0 || i + len > msg.len() {
            return None;
        }
        out.push((msg[i], &msg[i + 2..i + len]));
        i += len;
    }
    Some(out)
}

/// The link-layer address option (`SOURCE_LINK_ADDR` or `TARGET_LINK_ADDR`).
pub fn link_addr_option(ty: u8, mac: Mac) -> [u8; 8] {
    [ty, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]
}

/// A neighbour solicitation's target.
pub fn ns_target(msg: &[u8]) -> Option<Ipv6Addr> {
    if msg.len() < 24 {
        return None;
    }
    let mut o = [0u8; 16];
    o.copy_from_slice(&msg[8..24]);
    Some(Ipv6Addr::from(o))
}

/// Neighbour advertisement flags.
pub mod na_flags {
    pub const ROUTER: u32 = 0x8000_0000;
    pub const SOLICITED: u32 = 0x4000_0000;
    pub const OVERRIDE: u32 = 0x2000_0000;
}

pub fn build_na(target: Ipv6Addr, flags: u32, mac: Mac) -> Vec<u8> {
    let mut m = Vec::with_capacity(32);
    m.extend_from_slice(&[icmpv6::NEIGHBOR_ADVERTISEMENT, 0, 0, 0]);
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&target.octets());
    m.extend_from_slice(&link_addr_option(nd_option::TARGET_LINK_ADDR, mac));
    m
}

/// What a router advertisement says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    pub cur_hop_limit: u8,
    pub router_lifetime_s: u16,
    pub source_mac: Mac,
    pub mtu: Option<u32>,
    /// `(prefix, length, autonomous, valid_s, preferred_s)`; on-link always.
    pub prefix: Option<(Ipv6Addr, u8, bool, u32, u32)>,
    pub rdnss: Vec<Ipv6Addr>,
    pub rdnss_lifetime_s: u32,
}

pub fn build_ra(ra: &Advertisement) -> Vec<u8> {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(&[icmpv6::ROUTER_ADVERTISEMENT, 0, 0, 0]);
    m.push(ra.cur_hop_limit);
    m.push(0); // M and O clear: addresses by SLAAC, no DHCPv6.
    m.extend_from_slice(&ra.router_lifetime_s.to_be_bytes());
    m.extend_from_slice(&0u32.to_be_bytes()); // reachable time: unspecified
    m.extend_from_slice(&0u32.to_be_bytes()); // retransmit timer: unspecified
    m.extend_from_slice(&link_addr_option(
        nd_option::SOURCE_LINK_ADDR,
        ra.source_mac,
    ));
    if let Some(mtu) = ra.mtu {
        m.extend_from_slice(&[nd_option::MTU, 1, 0, 0]);
        m.extend_from_slice(&mtu.to_be_bytes());
    }
    if let Some((prefix, len, autonomous, valid, preferred)) = ra.prefix {
        m.extend_from_slice(&[nd_option::PREFIX_INFO, 4, len]);
        m.push(if autonomous { 0xc0 } else { 0x80 }); // L, and A for SLAAC
        m.extend_from_slice(&valid.to_be_bytes());
        m.extend_from_slice(&preferred.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        m.extend_from_slice(&prefix.octets());
    }
    if !ra.rdnss.is_empty() {
        m.extend_from_slice(&[nd_option::RDNSS, (1 + 2 * ra.rdnss.len()) as u8, 0, 0]);
        m.extend_from_slice(&ra.rdnss_lifetime_s.to_be_bytes());
        for a in &ra.rdnss {
            m.extend_from_slice(&a.octets());
        }
    }
    m
}

/// Parses a router advertisement's body (tests read what the router sent).
pub fn parse_ra(msg: &[u8]) -> Option<Advertisement> {
    if msg.len() < 16 || msg[0] != icmpv6::ROUTER_ADVERTISEMENT {
        return None;
    }
    let mut ra = Advertisement {
        cur_hop_limit: msg[4],
        router_lifetime_s: u16::from_be_bytes([msg[6], msg[7]]),
        source_mac: [0; 6],
        mtu: None,
        prefix: None,
        rdnss: Vec::new(),
        rdnss_lifetime_s: 0,
    };
    for (ty, body) in nd_options(msg, 16)? {
        match ty {
            nd_option::SOURCE_LINK_ADDR if body.len() >= 6 => {
                ra.source_mac.copy_from_slice(&body[..6]);
            }
            nd_option::MTU if body.len() >= 6 => {
                ra.mtu = Some(u32::from_be_bytes([body[2], body[3], body[4], body[5]]));
            }
            nd_option::PREFIX_INFO if body.len() >= 30 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&body[14..30]);
                ra.prefix = Some((
                    Ipv6Addr::from(o),
                    body[0],
                    body[1] & 0x40 != 0,
                    u32::from_be_bytes([body[2], body[3], body[4], body[5]]),
                    u32::from_be_bytes([body[6], body[7], body[8], body[9]]),
                ));
            }
            nd_option::RDNSS if body.len() >= 6 => {
                ra.rdnss_lifetime_s = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
                for chunk in body[6..].chunks_exact(16) {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(chunk);
                    ra.rdnss.push(Ipv6Addr::from(o));
                }
            }
            _ => {}
        }
    }
    Some(ra)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_padded_to_the_ethernet_minimum() {
        let f = build_frame(BROADCAST, [2, 0, 0, 0, 0, 1], ethertype::ARP, &[1, 2, 3]);
        assert_eq!(f.len(), MIN_FRAME_LEN);
        let parsed = parse_frame(&f).unwrap();
        assert_eq!(parsed.ethertype, ethertype::ARP);
        assert_eq!(&parsed.payload[..3], &[1, 2, 3]);
    }

    #[test]
    fn arp_round_trips() {
        let a = Arp {
            op: ARP_REQUEST,
            sender_mac: [2, 0, 0, 0, 0, 0x64],
            sender_ip: Ipv4Addr::new(192, 168, 1, 100),
            target_mac: [0; 6],
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
        };
        assert_eq!(parse_arp(&build_arp(&a)), Some(a));
        assert_eq!(parse_arp(&[0u8; 27]), None);
    }

    #[test]
    fn ip_packets_lose_their_padding() {
        let mut p = vec![0x45, 0, 0, 28];
        p.resize(28, 0);
        p.extend_from_slice(&[0; 18]);
        assert_eq!(ip_packet(ethertype::IPV4, &p).unwrap().len(), 28);
        let mut short = p.clone();
        short[3] = 200;
        assert!(ip_packet(ethertype::IPV4, &short).is_none());
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v6.resize(48, 0);
        v6.extend_from_slice(&[0; 4]);
        assert_eq!(ip_packet(ethertype::IPV6, &v6).unwrap().len(), 48);
    }

    #[test]
    fn icmpv6_checksums_verify() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let p = build_icmpv6(
            src,
            ALL_NODES,
            255,
            build_na(src, na_flags::ROUTER, [2, 0, 0, 0, 0, 1]),
        );
        let m = parse_icmpv6(&p).expect("checksum verifies");
        assert_eq!(m.ty, icmpv6::NEIGHBOR_ADVERTISEMENT);
        assert_eq!(m.hop_limit, 255);
        let mut bad = p.clone();
        bad[50] ^= 1;
        assert!(parse_icmpv6(&bad).is_none());
    }

    #[test]
    fn router_advertisements_round_trip() {
        let ra = Advertisement {
            cur_hop_limit: 64,
            router_lifetime_s: 1800,
            source_mac: [2, 0, 0, 0, 0, 1],
            mtu: Some(1500),
            prefix: Some((
                "2001:db8:42::".parse().unwrap(),
                64,
                true,
                u32::MAX,
                u32::MAX,
            )),
            rdnss: vec!["2001:db8::53".parse().unwrap()],
            rdnss_lifetime_s: 1800,
        };
        assert_eq!(parse_ra(&build_ra(&ra)), Some(ra));
    }

    #[test]
    fn multicast_addresses_map_to_33_33() {
        assert_eq!(ipv6_multicast_mac(ALL_NODES), [0x33, 0x33, 0, 0, 0, 1]);
        assert!(is_multicast(&[0x33, 0x33, 0, 0, 0, 1]));
        assert!(!is_multicast(&[0x02, 0, 0, 0, 0, 1]));
    }
}

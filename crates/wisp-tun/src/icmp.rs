//! Answers to packets the relay refuses, built as the LAN's router would
//! send them: ICMP destination unreachable (administratively prohibited, or
//! for IPv6 also "source address failed ingress policy"), or a TCP reset that
//! appears to come from the destination.
//!
//! No answer is built for an ICMP error, a fragment after the first, or a
//! packet without a unicast source (RFC 1122 3.2.2, RFC 4443 2.4 (e)).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wisp_ip::packet::{
    internet_checksum, proto, pseudo_header_sum, tcp_flags, Fragment, PacketInfo,
};

/// ICMP code 13: communication administratively prohibited.
pub const V4_ADMIN_PROHIBITED: u8 = 13;
/// ICMPv6 destination unreachable code 1: administratively prohibited.
pub const V6_ADMIN_PROHIBITED: u8 = 1;
/// ICMPv6 destination unreachable code 5: source address failed
/// ingress/egress policy (RFC 9484 7.2).
pub const V6_SOURCE_FAILED: u8 = 5;

/// Bytes of the offending packet quoted in an ICMPv4 error (RFC 1812 4.3.2.3:
/// the reply stays within 576 bytes).
const V4_QUOTE: usize = 576 - 28;
/// Bytes quoted in an ICMPv6 error (the reply stays within 1280 bytes).
const V6_QUOTE: usize = 1280 - 48;

const TTL: u8 = 64;

fn answerable(info: &PacketInfo) -> bool {
    if info.is_icmp_error() || info.fragment == Fragment::Later {
        return false;
    }
    match info.src {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast()),
    }
}

/// Destination unreachable with `code`, from `from`, quoting `packet`.
pub fn unreachable(packet: &[u8], info: &PacketInfo, from: IpAddr, code: u8) -> Option<Vec<u8>> {
    if !answerable(info) {
        return None;
    }
    match (from, info.src) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let quote = &packet[..packet.len().min(V4_QUOTE)];
            let mut icmp = Vec::with_capacity(8 + quote.len());
            icmp.extend_from_slice(&[3, code, 0, 0, 0, 0, 0, 0]);
            icmp.extend_from_slice(quote);
            let sum = internet_checksum(&icmp, 0);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            Some(ipv4(from, to, proto::ICMP, &icmp))
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            let quote = &packet[..packet.len().min(V6_QUOTE)];
            let mut icmp = Vec::with_capacity(8 + quote.len());
            icmp.extend_from_slice(&[1, code, 0, 0, 0, 0, 0, 0]);
            icmp.extend_from_slice(quote);
            let sum = internet_checksum(
                &icmp,
                pseudo_header_sum(from.into(), to.into(), proto::ICMPV6, icmp.len()),
            );
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            Some(ipv6(from, to, proto::ICMPV6, &icmp))
        }
        _ => None,
    }
}

/// A TCP reset for a refused TCP packet, from its destination (RFC 9293
/// 3.10.7.1: a segment that does not belong to a connection).
pub fn tcp_reset(packet: &[u8], info: &PacketInfo) -> Option<Vec<u8>> {
    if info.protocol != proto::TCP || !answerable(info) || info.tcp_flags & tcp_flags::RST != 0 {
        return None;
    }
    let t = packet.get(info.transport_offset..)?;
    if t.len() < 20 {
        return None;
    }
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
    let data_offset = usize::from(t[12] >> 4) * 4;
    let payload = t.len().saturating_sub(data_offset) as u32;
    let mut seg_len = payload;
    if info.tcp_flags & tcp_flags::SYN != 0 {
        seg_len += 1;
    }
    if info.tcp_flags & tcp_flags::FIN != 0 {
        seg_len += 1;
    }
    let (rst_seq, rst_ack, flags) = if info.tcp_flags & tcp_flags::ACK != 0 {
        (ack, 0, tcp_flags::RST)
    } else {
        (
            0,
            seq.wrapping_add(seg_len),
            tcp_flags::RST | tcp_flags::ACK,
        )
    };
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&info.dst_port.to_be_bytes());
    tcp.extend_from_slice(&info.src_port.to_be_bytes());
    tcp.extend_from_slice(&rst_seq.to_be_bytes());
    tcp.extend_from_slice(&rst_ack.to_be_bytes());
    tcp.extend_from_slice(&[5 << 4, flags, 0, 0, 0, 0, 0, 0]);
    let sum = internet_checksum(
        &tcp,
        pseudo_header_sum(info.dst, info.src, proto::TCP, tcp.len()),
    );
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    match (info.dst, info.src) {
        (IpAddr::V4(from), IpAddr::V4(to)) => Some(ipv4(from, to, proto::TCP, &tcp)),
        (IpAddr::V6(from), IpAddr::V6(to)) => Some(ipv6(from, to, proto::TCP, &tcp)),
        _ => None,
    }
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x40, 0, TTL, protocol, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let sum = internet_checksum(&p, 0);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.push(next);
    p.push(TTL);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// An IPv4 packet with a correct header checksum; for tests here and in the
/// transports.
pub fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    ipv4(src, dst, protocol, payload)
}

/// An IPv6 packet; for tests here and in the transports.
pub fn build_ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    ipv6(src, dst, next, payload)
}

/// A UDP datagram inside an IP packet, checksum filled.
pub fn build_udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, data: &[u8]) -> Vec<u8> {
    let len = 8 + data.len();
    let mut udp = Vec::with_capacity(len);
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&(len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(data);
    let mut sum = internet_checksum(&udp, pseudo_header_sum(src, dst, proto::UDP, len));
    if sum == 0 {
        sum = 0xffff;
    }
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ipv4(s, d, proto::UDP, &udp),
        (IpAddr::V6(s), IpAddr::V6(d)) => ipv6(s, d, proto::UDP, &udp),
        _ => Vec::new(),
    }
}

/// A TCP segment without options or data, checksum filled.
pub fn build_tcp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, seq: u32, flags: u8) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    let sum = internet_checksum(&tcp, pseudo_header_sum(src, dst, proto::TCP, tcp.len()));
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ipv4(s, d, proto::TCP, &tcp),
        (IpAddr::V6(s), IpAddr::V6(d)) => ipv6(s, d, proto::TCP, &tcp),
        _ => Vec::new(),
    }
}

/// An ICMP or ICMPv6 echo request.
pub fn build_echo(src: IpAddr, dst: IpAddr, id: u16, seq: u16) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut icmp = vec![8, 0, 0, 0];
            icmp.extend_from_slice(&id.to_be_bytes());
            icmp.extend_from_slice(&seq.to_be_bytes());
            icmp.extend_from_slice(b"wisp-tun");
            let sum = internet_checksum(&icmp, 0);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            ipv4(s, d, proto::ICMP, &icmp)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut icmp = vec![128, 0, 0, 0];
            icmp.extend_from_slice(&id.to_be_bytes());
            icmp.extend_from_slice(&seq.to_be_bytes());
            icmp.extend_from_slice(b"wisp-tun");
            let sum = internet_checksum(
                &icmp,
                pseudo_header_sum(src, dst, proto::ICMPV6, icmp.len()),
            );
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            ipv6(s, d, proto::ICMPV6, &icmp)
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_ip::inspect;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn admin_prohibited_quotes_the_packet_and_checks_out() {
        let p = build_udp(v4("192.168.1.100"), 4000, v4("10.0.0.1"), 53, b"q");
        let info = inspect(&p).unwrap();
        let reply = unreachable(&p, &info, v4("192.168.1.1"), V4_ADMIN_PROHIBITED).unwrap();
        let r = inspect(&reply).unwrap();
        assert_eq!(r.src, v4("192.168.1.1"));
        assert_eq!(r.dst, v4("192.168.1.100"));
        assert_eq!((r.icmp_type, r.icmp_code), (3, 13));
        assert_eq!(internet_checksum(&reply[20..], 0), 0);
        let q = r.quoted.unwrap();
        assert_eq!((q.src_port, q.dst_port), (4000, 53));
    }

    #[test]
    fn icmpv6_unreachable_checks_out() {
        let src: IpAddr = "2001:db8:1::100".parse().unwrap();
        let dst: IpAddr = "fd00::1".parse().unwrap();
        let p = build_udp(src, 4000, dst, 53, b"q");
        let info = inspect(&p).unwrap();
        let gw: IpAddr = "2001:db8:1::1".parse().unwrap();
        let reply = unreachable(&p, &info, gw, V6_SOURCE_FAILED).unwrap();
        let r = inspect(&reply).unwrap();
        assert_eq!(
            (r.protocol, r.icmp_type, r.icmp_code),
            (proto::ICMPV6, 1, 5)
        );
        let sum = internet_checksum(
            &reply[40..],
            pseudo_header_sum(gw, src, proto::ICMPV6, reply.len() - 40),
        );
        assert_eq!(sum, 0);
    }

    #[test]
    fn no_answer_to_an_icmp_error() {
        let p = build_udp(v4("192.168.1.100"), 4000, v4("10.0.0.1"), 53, b"q");
        let info = inspect(&p).unwrap();
        let err = unreachable(&p, &info, v4("192.168.1.1"), 13).unwrap();
        let err_info = inspect(&err).unwrap();
        assert!(unreachable(&err, &err_info, v4("192.168.1.1"), 13).is_none());
    }

    #[test]
    fn reset_answers_a_syn() {
        let syn = build_tcp(
            v4("192.168.1.100"),
            40000,
            v4("10.0.0.1"),
            22,
            1000,
            tcp_flags::SYN,
        );
        let info = inspect(&syn).unwrap();
        let rst = tcp_reset(&syn, &info).unwrap();
        let r = inspect(&rst).unwrap();
        assert_eq!(r.src, v4("10.0.0.1"));
        assert_eq!((r.src_port, r.dst_port), (22, 40000));
        assert_eq!(r.tcp_flags, tcp_flags::RST | tcp_flags::ACK);
        assert_eq!(&rst[28..32], &1001u32.to_be_bytes());
        let sum = internet_checksum(
            &rst[20..],
            pseudo_header_sum(r.src, r.dst, proto::TCP, rst.len() - 20),
        );
        assert_eq!(sum, 0);
        assert!(tcp_reset(&rst, &r).is_none(), "never a reset for a reset");
    }
}

//! Pieces of a relay and of a machine for the unit tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use wisp_ip::capsule::FOREVER;
use wisp_ip::info::{flags, ServerInfo};
use wisp_ip::packet::{internet_checksum, pseudo_header_sum};
use wisp_ip::{
    encode_capsules, AssignedAddress, Capsule, DnsConfig, LinkParams, Prefix, RouteEntry,
    EXTENSION_ID,
};

use crate::ether::{self, build_frame, ethertype, Mac};

pub const HOST_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
pub const GATEWAY_MAC: Mac = [0x02, 0x57, 0x49, 0x50, 0x54, 0x01];
pub const CLIENT4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
pub const GATEWAY4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const REMOTE4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

pub fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// The relay's INFO entry: everything version 1 has, MTU 1500.
pub fn server_entry() -> Vec<u8> {
    ServerInfo::v1(flags::KNOWN, 1, 1500, 1500).encode()
}

/// The server's Wisp v2 INFO packet carrying `entry` (or no 0xF3 entry).
pub fn ws_server_info(entry: Option<Vec<u8>>) -> Vec<u8> {
    let mut exts = vec![wisp_wisp::ExtensionEntry {
        id: wisp_wisp::extension_id::STREAM_OPEN_CONFIRMATION,
        payload: Bytes::new(),
    }];
    if let Some(e) = entry {
        exts.push(wisp_wisp::ExtensionEntry {
            id: EXTENSION_ID,
            payload: Bytes::from(e),
        });
    }
    wisp_wisp::encode_info(2, 0, &exts).to_vec()
}

/// wisp-wt INFO then READY, as the server writes them.
pub fn wt_server_info_ready(entry: Vec<u8>) -> Vec<u8> {
    let mut out = wisp_wire::encode_info_frame(&[wisp_wire::ExtensionEntry {
        id: EXTENSION_ID,
        payload: Bytes::from(entry),
    }])
    .to_vec();
    out.extend_from_slice(&wisp_wire::encode_ready_frame());
    out
}

/// What LS-5's relay confirms: the home LAN, the default route via .1,
/// MTU 1500, two resolvers, and a resume token when `grace_s` > 0.
pub fn confirmation(v6: bool, max_datagram_payload: u16, grace_s: u32, token: u8) -> Vec<Capsule> {
    let mut addresses = vec![AssignedAddress {
        prefix: Prefix::new(IpAddr::V4(CLIENT4), 24).unwrap(),
        valid_lft: FOREVER,
        preferred_lft: FOREVER,
    }];
    let mut routes = vec![RouteEntry {
        dest: Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap(),
        gateway: IpAddr::V4(GATEWAY4),
        metric: 100,
    }];
    if v6 {
        addresses.push(AssignedAddress {
            prefix: Prefix::new(IpAddr::V6(self::v6("2001:db8:42:7::100")), 64).unwrap(),
            valid_lft: FOREVER,
            preferred_lft: FOREVER,
        });
        routes.push(RouteEntry {
            dest: Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap(),
            gateway: IpAddr::V6(self::v6("fe80::1")),
            metric: 100,
        });
    }
    let mut out = vec![
        Capsule::AddressAssign(addresses),
        Capsule::RouteAdvertisement(routes),
        Capsule::Link(LinkParams {
            link_mtu: 1500,
            max_packet: 1500,
            max_datagram_payload,
        }),
        Capsule::DnsConfig(DnsConfig {
            servers: vec![
                "1.1.1.1".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ],
            search: String::new(),
        }),
    ];
    if grace_s > 0 {
        out.push(Capsule::ResumeToken {
            grace_s,
            token: [token; 32],
        });
    }
    out
}

pub fn ws_tunnel(stream: u32, capsules: &[Capsule]) -> Vec<u8> {
    wisp_wisp::encode_tunnel(stream, &encode_capsules(capsules)).to_vec()
}

pub fn wt_tunnel(ty: u8, id: u32, capsules: &[Capsule]) -> Vec<u8> {
    wisp_wire::encode_tunnel_frame(ty, id, &encode_capsules(capsules)).to_vec()
}

/// An IPv4 UDP packet with `len` bytes of payload.
pub fn udp4(src: Ipv4Addr, dst: Ipv4Addr, len: usize) -> Vec<u8> {
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let mut udp = Vec::with_capacity(8 + len);
    udp.extend_from_slice(&40000u16.to_be_bytes());
    udp.extend_from_slice(&7u16.to_be_bytes());
    udp.extend_from_slice(&((8 + len) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&payload);
    let sum = internet_checksum(
        &udp,
        pseudo_header_sum(IpAddr::V4(src), IpAddr::V4(dst), 17, udp.len()),
    );
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    let total = 20 + udp.len();
    let mut p = vec![0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 17, 0, 0];
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let sum = internet_checksum(&p, 0);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p.extend_from_slice(&udp);
    p
}

/// An IPv6 UDP packet with `len` bytes of payload.
pub fn udp6(src: Ipv6Addr, dst: Ipv6Addr, len: usize) -> Vec<u8> {
    let mut udp = vec![0x9c, 0x40, 0, 7, 0, 0, 0, 0];
    udp[4..6].copy_from_slice(&((8 + len) as u16).to_be_bytes());
    udp.extend((0..len).map(|i| i as u8));
    let sum = internet_checksum(
        &udp,
        pseudo_header_sum(IpAddr::V6(src), IpAddr::V6(dst), 17, udp.len()),
    );
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    p.extend_from_slice(&[17, 64]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&udp);
    p
}

/// A frame from the machine to the gateway.
pub fn to_gateway(packet: &[u8]) -> Vec<u8> {
    let ty = if packet[0] >> 4 == 4 {
        ethertype::IPV4
    } else {
        ethertype::IPV6
    };
    build_frame(GATEWAY_MAC, HOST_MAC, ty, packet)
}

pub fn arp_request(target: Ipv4Addr) -> Vec<u8> {
    build_frame(
        ether::BROADCAST,
        HOST_MAC,
        ethertype::ARP,
        &ether::build_arp(&ether::Arp {
            op: ether::ARP_REQUEST,
            sender_mac: HOST_MAC,
            sender_ip: CLIENT4,
            target_mac: [0; 6],
            target_ip: target,
        }),
    )
}

/// A neighbour solicitation from `src` for `target`, to its
/// solicited-node multicast group.
pub fn neighbour_solicitation(src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let t = target.octets();
    let group = Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(t[13]),
        u16::from_be_bytes([t[14], t[15]]),
    );
    let mut m = vec![ether::icmpv6::NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&target.octets());
    if !src.is_unspecified() {
        m.extend_from_slice(&ether::link_addr_option(
            ether::nd_option::SOURCE_LINK_ADDR,
            HOST_MAC,
        ));
    }
    build_frame(
        ether::ipv6_multicast_mac(group),
        HOST_MAC,
        ethertype::IPV6,
        &ether::build_icmpv6(src, group, 255, m),
    )
}

pub fn router_solicitation() -> Vec<u8> {
    let all_routers = v6("ff02::2");
    let mut m = vec![ether::icmpv6::ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&ether::link_addr_option(
        ether::nd_option::SOURCE_LINK_ADDR,
        HOST_MAC,
    ));
    build_frame(
        ether::ipv6_multicast_mac(all_routers),
        HOST_MAC,
        ethertype::IPV6,
        &ether::build_icmpv6(v6("fe80::5054:ff:fe12:3456"), all_routers, 255, m),
    )
}

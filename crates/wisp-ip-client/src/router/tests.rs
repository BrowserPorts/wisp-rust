use super::*;
use crate::ether::{parse_ra, ARP_REPLY};
use crate::testutil::*;

fn router(v6: bool) -> Router {
    let mut r = Router::new(RouterConfig {
        host_mac: None,
        ..RouterConfig::default()
    });
    let caps = confirmation(v6, 0, 0, 0);
    r.configure(&LinkConfig::from_capsules(&caps).unwrap(), 0);
    r
}

fn reply(r: FromWire) -> Vec<u8> {
    match r {
        FromWire::Reply(f) => f,
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// The ICMPv6 message inside a frame the router sent.
fn icmpv6_of(frame: &[u8]) -> (Ipv6Addr, Ipv6Addr, Vec<u8>) {
    let f = parse_frame(frame).unwrap();
    assert_eq!(f.ethertype, ethertype::IPV6);
    let p = ether::ip_packet(f.ethertype, f.payload).unwrap();
    let m = parse_icmpv6(p).expect("valid checksum");
    assert_eq!(m.hop_limit, 255);
    (m.src, m.dst, m.msg.to_vec())
}

#[test]
fn arp_is_answered_for_the_gateway_only() {
    let mut r = router(false);
    let f = reply(r.from_wire(&arp_request(GATEWAY4), 0));
    let frame = parse_frame(&f).unwrap();
    assert_eq!((frame.dst, frame.src), (HOST_MAC, GATEWAY_MAC));
    let a = parse_arp(frame.payload).unwrap();
    assert_eq!(a.op, ARP_REPLY);
    assert_eq!((a.sender_mac, a.sender_ip), (GATEWAY_MAC, GATEWAY4));
    assert_eq!((a.target_mac, a.target_ip), (HOST_MAC, CLIENT4));
    assert_eq!(f.len(), 60, "padded as an Ethernet interface pads");

    // Another host on the LAN does not exist; a probe for the machine's
    // own address (sender 0.0.0.0) goes unanswered too.
    assert_eq!(
        r.from_wire(&arp_request(Ipv4Addr::new(192, 168, 1, 7)), 0),
        FromWire::Drop(DropReason::Arp)
    );
    let probe = build_frame(
        BROADCAST,
        HOST_MAC,
        ethertype::ARP,
        &build_arp(&Arp {
            op: ARP_REQUEST,
            sender_mac: HOST_MAC,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: [0; 6],
            target_ip: CLIENT4,
        }),
    );
    assert_eq!(r.from_wire(&probe, 0), FromWire::Drop(DropReason::Arp));
    assert_eq!(r.host_mac(), Some(HOST_MAC), "learnt from the first frame");
}

#[test]
fn unicast_ip_for_the_gateway_is_forwarded_without_padding() {
    let mut r = router(false);
    let p = udp4(CLIENT4, REMOTE4, 4);
    let mut f = to_gateway(&p);
    f.extend_from_slice(&[0; 8]);
    assert_eq!(r.from_wire(&f, 0), FromWire::Forward(p.clone()));

    for dst in [
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(192, 168, 1, 255),
        Ipv4Addr::new(224, 0, 0, 251),
        Ipv4Addr::new(169, 254, 1, 1),
    ] {
        assert_eq!(
            r.from_wire(&to_gateway(&udp4(CLIENT4, dst, 4)), 0),
            FromWire::Drop(DropReason::LinkLocal),
            "{dst}"
        );
    }
    let mut elsewhere = to_gateway(&p);
    elsewhere[0..6].copy_from_slice(&[0x52, 0x54, 0, 9, 9, 9]);
    assert_eq!(
        r.from_wire(&elsewhere, 0),
        FromWire::Drop(DropReason::NotForGateway)
    );
    // The gateway's own address goes to the relay, which answers echo.
    assert!(matches!(
        r.from_wire(&to_gateway(&udp4(CLIENT4, GATEWAY4, 4)), 0),
        FromWire::Forward(_)
    ));
}

#[test]
fn packets_from_the_tunnel_are_framed_for_the_machine() {
    let mut r = Router::new(RouterConfig {
        host_mac: Some(HOST_MAC),
        ..RouterConfig::default()
    });
    let p = udp4(REMOTE4, CLIENT4, 100);
    let f = r.to_wire(&p).unwrap();
    let frame = parse_frame(&f).unwrap();
    assert_eq!(
        (frame.dst, frame.src, frame.ethertype),
        (HOST_MAC, GATEWAY_MAC, ethertype::IPV4)
    );
    assert_eq!(frame.payload, p.as_slice());
    let p6 = udp6(v6("2606:4700::1"), v6("2001:db8:42:7::100"), 10);
    assert_eq!(
        parse_frame(&r.to_wire(&p6).unwrap()).unwrap().ethertype,
        ethertype::IPV6
    );
    assert!(r.to_wire(&[0x10, 0, 0]).is_none());
}

#[test]
fn a_routed_prefix_is_advertised_for_slaac() {
    let mut r = router(true);
    assert!(r.advertises_ipv6());
    let f = r.poll_frame().expect("an advertisement at once");
    let frame = parse_frame(&f).unwrap();
    assert_eq!(frame.dst, [0x33, 0x33, 0, 0, 0, 1]);
    assert_eq!(frame.src, GATEWAY_MAC);
    let (src, dst, msg) = icmpv6_of(&f);
    assert_eq!(src, DEFAULT_GATEWAY_LINK_LOCAL);
    assert_eq!(dst, ALL_NODES);
    let ra = parse_ra(&msg).unwrap();
    assert_eq!(ra.cur_hop_limit, 64);
    assert_eq!(ra.router_lifetime_s, 1800);
    assert_eq!(ra.source_mac, GATEWAY_MAC);
    assert_eq!(ra.mtu, Some(1500));
    assert_eq!(
        ra.prefix,
        Some((v6("2001:db8:42:7::"), 64, true, u32::MAX, u32::MAX))
    );
    assert_eq!(ra.rdnss, [v6("2606:4700:4700::1111")]);
    assert!(r.poll_frame().is_none());

    // Unsolicited ones follow at the interval.
    assert_eq!(r.poll_timeout(), Some(200_000));
    r.handle_timeout(200_000);
    assert!(r.poll_frame().is_some());
    assert_eq!(r.poll_timeout(), Some(400_000));
}

#[test]
fn solicitations_are_answered_no_more_than_every_three_seconds() {
    let mut r = router(true);
    r.poll_frame();
    assert_eq!(
        r.from_wire(&router_solicitation(), 1_000),
        FromWire::Drop(DropReason::NeighbourDiscovery)
    );
    let f = reply(r.from_wire(&router_solicitation(), 3_000));
    let (_, _, msg) = icmpv6_of(&f);
    assert!(parse_ra(&msg).is_some());
    assert_eq!(r.stats().router_advertisements, 2);
}

#[test]
fn without_a_routed_prefix_the_router_is_silent() {
    let mut r = router(false);
    assert!(!r.advertises_ipv6());
    assert!(r.poll_frame().is_none());
    assert_eq!(
        r.from_wire(&router_solicitation(), 10_000),
        FromWire::Drop(DropReason::NeighbourDiscovery)
    );
    assert_eq!(
        r.from_wire(
            &neighbour_solicitation(v6("fe80::5054:ff:fe12:3456"), v6("fe80::1")),
            0
        ),
        FromWire::Drop(DropReason::NeighbourDiscovery)
    );
    let p = udp6(v6("2001:db8::5"), v6("2606:4700::1"), 4);
    assert_eq!(
        r.from_wire(&to_gateway(&p), 0),
        FromWire::Drop(DropReason::Unconfigured)
    );
}

#[test]
fn neighbour_solicitations_for_the_gateway_are_answered() {
    let mut r = router(true);
    let host_ll = v6("fe80::5054:ff:fe12:3456");
    let f = reply(r.from_wire(&neighbour_solicitation(host_ll, v6("fe80::1")), 0));
    assert_eq!(parse_frame(&f).unwrap().dst, HOST_MAC);
    let (src, dst, msg) = icmpv6_of(&f);
    assert_eq!((src, dst), (v6("fe80::1"), host_ll));
    assert_eq!(msg[0], icmpv6::NEIGHBOR_ADVERTISEMENT);
    let flags = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    assert_eq!(
        flags,
        na_flags::ROUTER | na_flags::SOLICITED | na_flags::OVERRIDE
    );
    assert_eq!(ns_target(&msg), Some(v6("fe80::1")));
    assert_eq!(&msg[24..32], &[2, 1, 0x02, 0x57, 0x49, 0x50, 0x54, 0x01]);

    // Duplicate address detection (source ::) and other targets: silence.
    assert_eq!(
        r.from_wire(
            &neighbour_solicitation(Ipv6Addr::UNSPECIFIED, v6("fe80::1")),
            0
        ),
        FromWire::Drop(DropReason::NeighbourDiscovery)
    );
    assert_eq!(
        r.from_wire(&neighbour_solicitation(host_ll, v6("2001:db8:42:7::99")), 0),
        FromWire::Drop(DropReason::NeighbourDiscovery)
    );
}

#[test]
fn ipv6_traffic_crosses_only_when_global() {
    let mut r = router(true);
    r.poll_frame();
    let ours = v6("2001:db8:42:7:5054:ff:fe12:3456");
    let p = udp6(ours, v6("2606:4700::1"), 20);
    assert_eq!(r.from_wire(&to_gateway(&p), 0), FromWire::Forward(p));
    let ll = udp6(v6("fe80::5054:ff:fe12:3456"), v6("2606:4700::1"), 20);
    assert_eq!(
        r.from_wire(&to_gateway(&ll), 0),
        FromWire::Drop(DropReason::LinkLocal)
    );
    let mcast = udp6(ours, v6("ff02::fb"), 20);
    let mut f = to_gateway(&mcast);
    f[0..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 0xfb]);
    assert_eq!(r.from_wire(&f, 0), FromWire::Drop(DropReason::LinkLocal));
}

#[test]
fn deconfiguring_withdraws_the_default_route() {
    let mut r = router(true);
    r.poll_frame();
    r.deconfigure(5_000);
    let (_, _, msg) = icmpv6_of(&r.poll_frame().unwrap());
    let ra = parse_ra(&msg).unwrap();
    assert_eq!(ra.router_lifetime_s, 0);
    assert_eq!(ra.prefix.unwrap().4, 0, "preferred lifetime 0");
    assert!(!r.advertises_ipv6());
    assert_eq!(r.poll_timeout(), None);
    assert_eq!(
        r.from_wire(&arp_request(GATEWAY4), 0),
        FromWire::Drop(DropReason::Unconfigured)
    );
}

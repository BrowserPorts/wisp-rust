use super::*;
use crate::icmp::{build_echo, build_tcp, build_udp};
use crate::memory::{MemoryBackend, MemoryNetwork};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;
use wisp_config::{IpTunnelOptions, WispServerOptions};
use wisp_ip::info::ServerInfo;
use wisp_ip::packet::tcp_flags;

const CLIENT: &str = "192.168.1.100";
const PUBLIC: &str = "93.184.216.34";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn service(
    edit: impl FnOnce(&mut IpTunnelOptions),
) -> (
    Arc<TunnelService>,
    Arc<MemoryBackend>,
    UnboundedReceiver<MemoryNetwork>,
) {
    let mut o = IpTunnelOptions {
        enabled: true,
        ..IpTunnelOptions::default()
    };
    edit(&mut o);
    let cfg = TunnelConfig::from_options(&o, &WispServerOptions::default()).unwrap();
    let (backend, networks) = MemoryBackend::new();
    let svc = TunnelService::new(cfg, backend.clone(), Arc::new(DosGuard::new()));
    (svc, backend, networks)
}

fn negotiated(svc: &TunnelService) -> Negotiated {
    let info: ServerInfo = svc.config().server_info(crate::Binding::WebSocket);
    Negotiated {
        version: 1,
        flags: info.flags,
        max_tunnels: info.max_tunnels,
        link_mtu: info.link_mtu,
        max_packet: info.max_packet,
    }
}

fn request(svc: &TunnelService, want: u16) -> OpenRequest {
    OpenRequest {
        want,
        resume: None,
        principal: Some("token-a".to_owned()),
        client_ip: "203.0.113.9".to_owned(),
        policy: Arc::new(HostPolicy::from_options(&WispServerOptions::default())),
        negotiated: negotiated(svc),
        max_datagram_payload: 0,
    }
}

fn token_of(confirmation: &[Capsule]) -> ResumeToken {
    confirmation
        .iter()
        .find_map(|c| match c {
            Capsule::ResumeToken { token, .. } => Some(*token),
            _ => None,
        })
        .expect("a resume token")
}

async fn next(net: &mut MemoryNetwork) -> Bytes {
    timeout(Duration::from_secs(2), net.from_tunnel.recv())
        .await
        .expect("network packet timed out")
        .expect("network closed")
}

async fn to_client(t: &mut Tunnel) -> Option<Bytes> {
    timeout(Duration::from_millis(200), t.recv())
        .await
        .ok()
        .flatten()
}

fn syn(dst: &str, port: u16) -> Bytes {
    Bytes::from(build_tcp(
        ip(CLIENT),
        40000,
        ip(dst),
        port,
        1,
        tcp_flags::SYN,
    ))
}

#[tokio::test]
async fn open_hands_out_the_reference_lan() {
    let (svc, _b, mut nets) = service(|_| {});
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    assert!(!opened.resumed);
    let c = &opened.confirmation;
    assert_eq!(
        c[0],
        Capsule::AddressAssign(vec![AssignedAddress {
            prefix: Prefix::new(ip(CLIENT), 24).unwrap(),
            valid_lft: FOREVER,
            preferred_lft: FOREVER,
        }])
    );
    assert_eq!(
        c[1],
        Capsule::RouteAdvertisement(vec![RouteEntry {
            dest: Prefix::new(ip("0.0.0.0"), 0).unwrap(),
            gateway: ip("192.168.1.1"),
            metric: 100,
        }])
    );
    assert_eq!(
        c[2],
        Capsule::Link(LinkParams {
            link_mtu: 1500,
            max_packet: 1500,
            max_datagram_payload: 0,
        })
    );
    assert!(matches!(c[3], Capsule::ResumeToken { grace_s: 30, .. }));
    let net = nets.recv().await.unwrap();
    assert_eq!(net.plan.gateway4, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(svc.live_tunnels(), 1);
    opened.tunnel.close();
    net.torn_down().await;
    assert_eq!(svc.live_tunnels(), 0);
}

#[tokio::test]
async fn allowed_flow_goes_out_and_its_replies_come_back() {
    let (svc, _b, mut nets) = service(|_| {});
    let mut t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let mut net = nets.recv().await.unwrap();
    let h = t.handle();
    assert_eq!(h.forward(syn(PUBLIC, 443)), Outcome::Forwarded);
    assert_eq!(next(&mut net).await, syn(PUBLIC, 443));
    let synack = build_tcp(
        ip(PUBLIC),
        443,
        ip(CLIENT),
        40000,
        9,
        tcp_flags::SYN | tcp_flags::ACK,
    );
    net.to_tunnel
        .send(Bytes::from(synack.clone()))
        .await
        .unwrap();
    assert_eq!(to_client(&mut t).await.unwrap(), synack);
}

#[tokio::test]
async fn unsolicited_inbound_never_reaches_the_client() {
    let (svc, _b, mut nets) = service(|_| {});
    let mut t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let net = nets.recv().await.unwrap();
    let probe = build_tcp(ip(PUBLIC), 443, ip(CLIENT), 22, 1, tcp_flags::SYN);
    net.to_tunnel.send(Bytes::from(probe)).await.unwrap();
    let ping = build_echo(ip(PUBLIC), ip(CLIENT), 7, 1);
    net.to_tunnel.send(Bytes::from(ping)).await.unwrap();
    assert!(to_client(&mut t).await.is_none());
}

#[tokio::test]
async fn spoofed_source_is_dropped() {
    let (svc, _b, mut nets) = service(|_| {});
    let mut t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let mut net = nets.recv().await.unwrap();
    let h = t.handle();
    for src in ["10.9.9.9", "192.168.1.1", "192.168.1.0", "192.168.1.255"] {
        let p = build_tcp(ip(src), 40000, ip(PUBLIC), 443, 1, tcp_flags::SYN);
        assert_eq!(
            h.forward(Bytes::from(p)),
            Outcome::Dropped(DropReason::Spoofed),
            "{src}"
        );
    }
    // Any other address of the on-link /24 is the client's to use.
    let p = build_tcp(ip("192.168.1.7"), 40000, ip(PUBLIC), 443, 1, tcp_flags::SYN);
    assert_eq!(h.forward(Bytes::from(p)), Outcome::Forwarded);
    next(&mut net).await;
    assert!(to_client(&mut t).await.is_none());
}

#[tokio::test]
async fn private_loopback_and_metadata_destinations_are_rejected() {
    let (svc, _b, mut nets) = service(|_| {});
    let mut t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let mut net = nets.recv().await.unwrap();
    let h = t.handle();
    for dst in ["10.0.0.1", "127.0.0.1", "172.16.5.5", "192.168.1.1"] {
        assert_eq!(h.forward(syn(dst, 443)), Outcome::Refused, "{dst}");
        let answer = to_client(&mut t).await.expect("an ICMP answer");
        let info = inspect(&answer).unwrap();
        assert_eq!(info.src, ip("192.168.1.1"));
        assert_eq!(
            (info.protocol, info.icmp_type, info.icmp_code),
            (proto::ICMP, 3, 13)
        );
        assert_eq!(info.quoted.unwrap().dst, ip(dst));
    }
    // Link-local (the metadata address among them) is never forwarded.
    assert_eq!(
        h.forward(syn("169.254.169.254", 80)),
        Outcome::Dropped(DropReason::NotForwarded)
    );
    // A port outside the policy is refused too.
    assert_eq!(h.forward(syn(PUBLIC, 25)), Outcome::Refused);
    assert!(to_client(&mut t).await.is_some());
    assert!(
        net.from_tunnel.try_recv().is_err(),
        "nothing reached the network"
    );
}

#[tokio::test]
async fn reject_with_reset_and_drop() {
    let (svc, _b, mut nets) = service(|o| o.reject_with = wisp_config::TunnelReject::Reset);
    let mut t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let _net = nets.recv().await.unwrap();
    assert_eq!(t.handle().forward(syn("10.0.0.1", 443)), Outcome::Refused);
    let rst = inspect(&to_client(&mut t).await.unwrap()).unwrap();
    assert_eq!(rst.protocol, proto::TCP);
    assert_eq!(rst.tcp_flags, tcp_flags::RST | tcp_flags::ACK);

    let (svc, _b, mut nets) = service(|o| o.reject_with = wisp_config::TunnelReject::Drop);
    let mut t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let _net = nets.recv().await.unwrap();
    assert_eq!(t.handle().forward(syn("10.0.0.1", 443)), Outcome::Refused);
    assert!(to_client(&mut t).await.is_none());
}

#[tokio::test]
async fn flow_cap_and_flow_rate() {
    let (svc, _b, mut nets) = service(|o| {
        o.max_flows_per_tunnel = 2;
    });
    let t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let _net = nets.recv().await.unwrap();
    let h = t.handle();
    let udp = |port: u16| Bytes::from(build_udp(ip(CLIENT), port, ip(PUBLIC), 443, b"x"));
    assert_eq!(h.forward(udp(1)), Outcome::Forwarded);
    assert_eq!(h.forward(udp(2)), Outcome::Forwarded);
    assert_eq!(h.forward(udp(3)), Outcome::Dropped(DropReason::FlowLimit));
    // Known flows keep flowing.
    assert_eq!(h.forward(udp(1)), Outcome::Forwarded);

    let (svc, _b, mut nets) = service(|o| {
        o.max_new_flows_per_tunnel_per_minute = 2;
    });
    let t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let _net = nets.recv().await.unwrap();
    let h = t.handle();
    assert_eq!(h.forward(udp(1)), Outcome::Forwarded);
    assert_eq!(h.forward(udp(2)), Outcome::Forwarded);
    assert_eq!(h.forward(udp(3)), Outcome::Dropped(DropReason::FlowRate));
}

#[tokio::test]
async fn packet_rate_is_bounded() {
    let (svc, _b, mut nets) = service(|o| o.max_packets_per_tunnel_per_second = 3);
    let t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let _net = nets.recv().await.unwrap();
    let h = t.handle();
    for _ in 0..3 {
        assert_eq!(h.forward(syn(PUBLIC, 443)), Outcome::Forwarded);
    }
    assert_eq!(
        h.forward(syn(PUBLIC, 443)),
        Outcome::Dropped(DropReason::RateLimited)
    );
}

#[tokio::test]
async fn malformed_and_oversized_packets_are_dropped() {
    let (svc, _b, mut nets) = service(|_| {});
    let t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let _net = nets.recv().await.unwrap();
    let h = t.handle();
    assert_eq!(
        h.forward(Bytes::from_static(&[0x45, 0, 0])),
        Outcome::Dropped(DropReason::Malformed)
    );
    assert_eq!(
        h.forward(Bytes::from(vec![0x45; 1501])),
        Outcome::Dropped(DropReason::TooLarge)
    );
    assert_eq!(
        h.forward(Bytes::from(crate::icmp::build_ipv4(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            47,
            &[0; 8]
        ))),
        Outcome::Dropped(DropReason::NotForwarded)
    );
}

#[tokio::test]
async fn echo_and_the_gateway() {
    let (svc, _b, mut nets) = service(|_| {});
    let mut t = svc.open(request(&svc, want::IPV4)).await.unwrap().tunnel;
    let mut net = nets.recv().await.unwrap();
    let h = t.handle();
    let ping = Bytes::from(build_echo(ip(CLIENT), ip("1.1.1.1"), 9, 1));
    assert_eq!(h.forward(ping.clone()), Outcome::Forwarded);
    assert_eq!(next(&mut net).await, ping);
    // The kernel's own Time Exceeded, sent from the gateway, reaches the
    // client even without a flow of its own.
    let mut exceeded = vec![11u8, 0, 0, 0, 0, 0, 0, 0];
    exceeded.extend_from_slice(&ping[..28]);
    let sum = wisp_ip::packet::internet_checksum(&exceeded, 0);
    exceeded[2..4].copy_from_slice(&sum.to_be_bytes());
    let from_gw = crate::icmp::build_ipv4(
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 1, 100),
        proto::ICMP,
        &exceeded,
    );
    net.to_tunnel
        .send(Bytes::from(from_gw.clone()))
        .await
        .unwrap();
    assert_eq!(to_client(&mut t).await.unwrap(), from_gw);
}

#[tokio::test]
async fn resume_within_grace_keeps_network_and_flows() {
    let (svc, _b, mut nets) = service(|_| {});
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    let token = token_of(&opened.confirmation);
    let mut net = nets.recv().await.unwrap();
    let h = opened.tunnel.handle();
    assert_eq!(h.forward(syn(PUBLIC, 443)), Outcome::Forwarded);
    next(&mut net).await;
    drop(h);
    opened.tunnel.detach();

    let mut req = request(&svc, want::IPV4);
    req.resume = Some(token);
    req.client_ip = "198.51.100.77".to_owned();
    let resumed = svc.open(req).await.unwrap();
    assert!(resumed.resumed);
    let new_token = token_of(&resumed.confirmation);
    assert_ne!(new_token, token, "a fresh token");
    assert!(!net.is_torn_down());
    assert!(nets.try_recv().is_err(), "no new network");
    let mut t = resumed.tunnel;
    let synack = build_tcp(
        ip(PUBLIC),
        443,
        ip(CLIENT),
        40000,
        9,
        tcp_flags::SYN | tcp_flags::ACK,
    );
    net.to_tunnel
        .send(Bytes::from(synack.clone()))
        .await
        .unwrap();
    assert_eq!(
        to_client(&mut t).await.unwrap(),
        synack,
        "the flow survived"
    );

    // The old token was single-use.
    let mut again = request(&svc, want::IPV4);
    again.resume = Some(token);
    let fresh = svc.open(again).await.unwrap();
    assert!(!fresh.resumed);
    assert!(fresh.confirmation.iter().any(|c| matches!(
        c,
        Capsule::Error {
            code: error_code::RESUME_REJECTED,
            ..
        }
    )));
}

#[tokio::test(start_paused = true)]
async fn resume_past_grace_gets_a_new_tunnel() {
    let (svc, _b, mut nets) = service(|o| o.resume_grace_s = 5);
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    let token = token_of(&opened.confirmation);
    let net = nets.recv().await.unwrap();
    opened.tunnel.detach();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!net.is_torn_down(), "still inside the grace period");
    tokio::time::sleep(Duration::from_secs(2)).await;
    net.torn_down().await;
    assert_eq!(svc.live_tunnels(), 0);

    let mut req = request(&svc, want::IPV4);
    req.resume = Some(token);
    let fresh = svc.open(req).await.unwrap();
    assert!(!fresh.resumed);
    assert!(nets.recv().await.is_some(), "a new network");
}

#[tokio::test]
async fn resume_takes_a_tunnel_its_old_connection_still_holds() {
    let (svc, _b, mut nets) = service(|_| {});
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    let token = token_of(&opened.confirmation);
    let _net = nets.recv().await.unwrap();
    let old = opened.tunnel;
    // The old connection's pump: lets go once stolen.
    let holder = tokio::spawn(async move {
        old.stolen().await;
        old.detach();
    });
    let mut req = request(&svc, want::IPV4);
    req.resume = Some(token);
    let resumed = svc.open(req).await.unwrap();
    assert!(resumed.resumed);
    holder.await.unwrap();
}

#[tokio::test]
async fn resume_is_bound_to_the_principal() {
    let (svc, _b, mut nets) = service(|_| {});
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    let token = token_of(&opened.confirmation);
    let net = nets.recv().await.unwrap();
    opened.tunnel.detach();
    let mut req = request(&svc, want::IPV4);
    req.resume = Some(token);
    req.principal = Some("token-b".to_owned());
    let other = svc.open(req).await.unwrap();
    assert!(!other.resumed);
    assert!(!net.is_torn_down(), "the owner can still resume");
}

#[tokio::test]
async fn closed_tunnel_cannot_be_resumed() {
    let (svc, _b, mut nets) = service(|_| {});
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    let token = token_of(&opened.confirmation);
    let net = nets.recv().await.unwrap();
    opened.tunnel.close();
    net.torn_down().await;
    let mut req = request(&svc, want::IPV4);
    req.resume = Some(token);
    let fresh = svc.open(req).await.unwrap();
    assert!(!fresh.resumed);
    assert_eq!(svc.store.len(), 1, "only the new tunnel's token");
}

#[tokio::test]
async fn a_dropped_tunnel_leaves_no_resume_token() {
    let (svc, _b, mut nets) = service(|_| {});
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    let token = token_of(&opened.confirmation);
    let net = nets.recv().await.unwrap();
    assert_eq!(svc.store.len(), 1);
    drop(opened);
    net.torn_down().await;
    assert_eq!(svc.store.len(), 0);
    let mut req = request(&svc, want::IPV4);
    req.resume = Some(token);
    let fresh = timeout(Duration::from_millis(500), svc.open(req))
        .await
        .expect("no wait for a holder that is gone")
        .unwrap();
    assert!(!fresh.resumed);
}

#[tokio::test(start_paused = true)]
async fn an_expired_parked_tunnel_drops_cleanly() {
    let (svc, _b, mut nets) = service(|o| o.resume_grace_s = 1);
    let opened = svc.open(request(&svc, want::IPV4)).await.unwrap();
    let net = nets.recv().await.unwrap();
    opened.tunnel.detach();
    assert_eq!(svc.store.len(), 1);
    tokio::time::sleep(Duration::from_secs(2)).await;
    net.torn_down().await;
    assert_eq!(svc.store.len(), 0);
    assert_eq!(svc.live_tunnels(), 0);
}

#[tokio::test]
async fn refusals() {
    let (svc, backend, _nets) = service(|o| o.max_tunnels_total = 1);
    assert_eq!(
        svc.open(request(&svc, want::IPV6)).await.err(),
        Some(OpenError::FamilyNotOffered)
    );
    let first = svc.open(request(&svc, want::IPV4)).await.unwrap();
    assert_eq!(
        svc.open(request(&svc, want::IPV4)).await.err(),
        Some(OpenError::TooMany)
    );
    first.tunnel.close();
    backend.fail_next("no netns");
    assert!(matches!(
        svc.open(request(&svc, want::IPV4)).await.err(),
        Some(OpenError::Network(_))
    ));
    assert_eq!(svc.live_tunnels(), 0, "a failed open holds nothing");

    let mut req = request(&svc, want::IPV4);
    req.policy = Arc::new(HostPolicy::from_options(&WispServerOptions {
        domain_whitelist: Some(vec!["example.com".to_owned()]),
        ..WispServerOptions::default()
    }));
    assert_eq!(svc.open(req).await.err(), Some(OpenError::Blocked));
}

#[tokio::test]
async fn ipv6_tunnels_get_a_routed_prefix() {
    let (svc, _b, mut nets) = service(|o| o.ipv6_prefix = Some("2001:db8:42::/48".to_owned()));
    let opened = svc
        .open(request(&svc, want::IPV4 | want::IPV6))
        .await
        .unwrap();
    let net = nets.recv().await.unwrap();
    assert_eq!(net.plan.ipv6, Some(("2001:db8:42::".parse().unwrap(), 64)));
    let Capsule::AddressAssign(addrs) = &opened.confirmation[0] else {
        panic!("ADDRESS_ASSIGN first");
    };
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[1].prefix.addr(), ip("2001:db8:42::100"));
    let second = svc.open(request(&svc, want::IPV6)).await.unwrap();
    let net2 = nets.recv().await.unwrap();
    assert_eq!(
        net2.plan.ipv6,
        Some(("2001:db8:42:1::".parse().unwrap(), 64))
    );

    // Spoofed IPv6 sources are answered with code 5.
    let mut t = second.tunnel;
    let h = t.handle();
    let p = build_udp(ip("2001:db8:42::5"), 1, ip("2606:4700::1111"), 443, b"x");
    assert_eq!(
        h.forward(Bytes::from(p)),
        Outcome::Dropped(DropReason::Spoofed)
    );
    let answer = inspect(&to_client(&mut t).await.unwrap()).unwrap();
    assert_eq!((answer.icmp_type, answer.icmp_code), (1, 5));
    // IPv4 was not assigned to this tunnel.
    assert_eq!(
        h.forward(syn(PUBLIC, 443)),
        Outcome::Dropped(DropReason::Spoofed)
    );
}

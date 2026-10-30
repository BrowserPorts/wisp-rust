//! The namespace backend against a real kernel. Linux only, and they need
//! `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`, so they are ignored by default:
//!
//! ```text
//! cargo test -p wisp-tun --test netns --no-run
//! sudo target/debug/deps/netns-<hash> --ignored --test-threads=1
//! ```
//!
//! Each test builds a stand-in internet: a namespace `wtest-inet` behind a
//! veth from the relay's namespace, holding 192.88.99.2 (an address the
//! destination policy treats as public), with a UDP echo server on port 7.
//! Tunnel namespaces are named `wtest-<id>`.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::time::timeout;
use wisp_config::{IpTunnelOptions, WispServerOptions};
use wisp_dos::DosGuard;
use wisp_ip::capsule::want;
use wisp_ip::packet::{proto, tcp_flags};
use wisp_ip::{inspect, Capsule, Negotiated};
use wisp_proxy::HostPolicy;
use wisp_tun::icmp::{build_echo, build_tcp, build_udp};
use wisp_tun::netns::NetnsBackend;
use wisp_tun::{
    Backend, Binding, Device, DropReason, NetworkPlan, OpenRequest, Outcome, Tunnel, TunnelConfig,
    TunnelService,
};

const INET_NS: &str = "wtest-inet";
const INET: Ipv4Addr = Ipv4Addr::new(192, 88, 99, 2);
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

fn sh(args: &[&str]) {
    let status = Command::new(args[0])
        .args(&args[1..])
        .status()
        .expect("spawn");
    assert!(status.success(), "{args:?} failed");
}

fn sh_quiet(args: &[&str]) {
    let _ = Command::new(args[0])
        .args(&args[1..])
        .stderr(std::process::Stdio::null())
        .status();
}

/// The stand-in internet, removed on drop.
struct Inet {
    received: Arc<AtomicUsize>,
}

impl Inet {
    fn up() -> Self {
        sh_quiet(&["ip", "netns", "del", INET_NS]);
        sh(&["ip", "netns", "add", INET_NS]);
        sh(&[
            "ip", "link", "add", "wtest0", "type", "veth", "peer", "name", "eth0", "netns", INET_NS,
        ]);
        sh(&["ip", "addr", "add", "192.88.99.1/24", "dev", "wtest0"]);
        sh(&["ip", "link", "set", "wtest0", "up"]);
        sh(&[
            "ip",
            "-n",
            INET_NS,
            "addr",
            "add",
            "192.88.99.2/24",
            "dev",
            "eth0",
        ]);
        sh(&["ip", "-n", INET_NS, "link", "set", "eth0", "up"]);
        sh(&["ip", "-n", INET_NS, "link", "set", "lo", "up"]);
        sh(&[
            "ip",
            "-n",
            INET_NS,
            "route",
            "add",
            "default",
            "via",
            "192.88.99.1",
        ]);
        let received = Arc::new(AtomicUsize::new(0));
        let counter = received.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            enter_netns(INET_NS);
            let sock = UdpSocket::bind("0.0.0.0:7").expect("bind echo");
            ready_tx.send(()).unwrap();
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = sock.send_to(&buf[..n], from);
            }
        });
        ready_rx.recv().unwrap();
        Self { received }
    }

    /// Sends one UDP datagram from the internet side to `dst`.
    fn send_from_inet(dst: Ipv4Addr, port: u16) {
        std::thread::spawn(move || {
            enter_netns(INET_NS);
            let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
            let _ = sock.send_to(b"unsolicited", (dst, port));
        })
        .join()
        .unwrap();
    }
}

impl Drop for Inet {
    fn drop(&mut self) {
        sh_quiet(&["ip", "netns", "del", INET_NS]);
        sh_quiet(&["ip", "link", "del", "wtest0"]);
    }
}

fn enter_netns(name: &str) {
    let f = std::fs::File::open(format!("/run/netns/{name}")).expect("netns file");
    // SAFETY: setns on an open namespace descriptor affects only this thread.
    let rc = unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns {name}");
}

fn netns_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/run/netns/{name}")).exists()
}

fn options(edit: impl FnOnce(&mut IpTunnelOptions)) -> IpTunnelOptions {
    let mut o = IpTunnelOptions {
        enabled: true,
        netns_prefix: "wtest".to_owned(),
        ..IpTunnelOptions::default()
    };
    edit(&mut o);
    o
}

fn base() -> WispServerOptions {
    WispServerOptions {
        port_whitelist: Some(vec![7, 443]),
        ..WispServerOptions::default()
    }
}

async fn service(
    edit: impl FnOnce(&mut IpTunnelOptions),
) -> (Arc<TunnelService>, Arc<NetnsBackend>) {
    let cfg = TunnelConfig::from_options(&options(edit), &base()).unwrap();
    let backend = NetnsBackend::start(Arc::new(cfg.clone()))
        .await
        .expect("backend");
    let svc = TunnelService::new(cfg, backend.clone(), Arc::new(DosGuard::new()));
    (svc, backend)
}

fn request(svc: &TunnelService) -> OpenRequest {
    let info = svc.config().server_info(Binding::WebSocket);
    OpenRequest {
        want: want::IPV4,
        resume: None,
        principal: None,
        client_ip: "203.0.113.50".to_owned(),
        policy: Arc::new(HostPolicy::from_options(&base())),
        negotiated: Negotiated {
            version: 1,
            flags: info.flags,
            max_tunnels: info.max_tunnels,
            link_mtu: info.link_mtu,
            max_packet: info.max_packet,
        },
        max_datagram_payload: 0,
    }
}

fn udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Bytes {
    Bytes::from(build_udp(src.into(), sport, dst.into(), dport, data))
}

async fn recv(t: &mut Tunnel, wait_ms: u64) -> Option<Bytes> {
    timeout(Duration::from_millis(wait_ms), t.recv())
        .await
        .ok()
        .flatten()
}

async fn device_recv(d: &mut Device, wait_ms: u64) -> Option<Bytes> {
    timeout(Duration::from_millis(wait_ms), d.from_network.recv())
        .await
        .ok()
        .flatten()
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn udp_round_trip_through_a_home_router() {
    let inet = Inet::up();
    let (svc, backend) = service(|_| {}).await;
    let mut t = svc.open(request(&svc)).await.unwrap().tunnel;
    assert!(netns_exists(&format!("wtest-{}", t.id())));
    let h = t.handle();
    assert_eq!(
        h.forward(udp(CLIENT, 40000, INET, 7, b"hello")),
        Outcome::Forwarded
    );
    let reply = recv(&mut t, 3000).await.expect("echo reply");
    let info = inspect(&reply).unwrap();
    assert_eq!(info.src, IpAddr::V4(INET));
    assert_eq!(info.dst, IpAddr::V4(CLIENT));
    assert_eq!((info.src_port, info.dst_port), (7, 40000));
    // Two routers on the way back: the relay and the tunnel's namespace.
    assert_eq!(info.ttl, 62);
    assert_eq!(&reply[28..], b"hello");
    assert_eq!(inet.received.load(Ordering::SeqCst), 1);
    t.close();
    drop(h);
    tokio::time::sleep(Duration::from_millis(500)).await;
    settle().await;
    backend.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn ttl_expiry_and_the_gateway_answer_like_a_router() {
    let _inet = Inet::up();
    let (svc, backend) = service(|_| {}).await;
    let mut t = svc.open(request(&svc)).await.unwrap().tunnel;
    let h = t.handle();
    let mut p = build_udp(CLIENT.into(), 40001, INET.into(), 7, b"ttl");
    p[8] = 1;
    p[10] = 0;
    p[11] = 0;
    let sum = wisp_ip::packet::internet_checksum(&p[..20], 0);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(h.forward(Bytes::from(p)), Outcome::Forwarded);
    let exceeded = inspect(&recv(&mut t, 3000).await.expect("time exceeded")).unwrap();
    assert_eq!(exceeded.src, IpAddr::V4(GATEWAY));
    assert_eq!((exceeded.icmp_type, exceeded.icmp_code), (11, 0));

    let ping = Bytes::from(build_echo(CLIENT.into(), GATEWAY.into(), 77, 1));
    assert_eq!(h.forward(ping), Outcome::Forwarded);
    let pong = inspect(&recv(&mut t, 3000).await.expect("echo reply")).unwrap();
    assert!(pong.is_echo_reply());
    assert_eq!(pong.src, IpAddr::V4(GATEWAY));
    t.close();
    drop(h);
    settle().await;
    backend.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn spoofed_source_is_dropped_by_both_layers() {
    let inet = Inet::up();
    let (svc, backend) = service(|_| {}).await;
    let t = svc.open(request(&svc)).await.unwrap().tunnel;
    let h = t.handle();
    let spoofed = udp(Ipv4Addr::new(10, 9, 9, 9), 40000, INET, 7, b"spoof");
    assert_eq!(
        h.forward(spoofed.clone()),
        Outcome::Dropped(DropReason::Spoofed)
    );

    // The kernel's backstop, with the per-flow layer bypassed.
    let cfg = svc.config().clone();
    let mut dev = backend.create(plan(&cfg, 9001, 64)).await.unwrap();
    dev.to_network.send(spoofed).await.unwrap();
    dev.to_network
        .send(udp(GATEWAY, 40000, INET, 7, b"gateway"))
        .await
        .unwrap();
    assert!(device_recv(&mut dev, 1000).await.is_none());
    assert_eq!(
        inet.received.load(Ordering::SeqCst),
        0,
        "nothing left the tunnel"
    );
    t.close();
    drop(h);
    drop(dev);
    settle().await;
    backend.stop().await.unwrap();
}

fn plan(cfg: &TunnelConfig, id: u64, max_flows: u32) -> NetworkPlan {
    NetworkPlan {
        id,
        lan: (Ipv4Addr::new(192, 168, 1, 0), 24),
        gateway4: cfg.gateway4,
        client4: cfg.client4,
        ipv6: None,
        link_mtu: cfg.link_mtu,
        max_packet: cfg.max_packet,
        max_flows,
        dns_servers: cfg.dns_servers.clone(),
    }
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn private_loopback_and_metadata_destinations_are_rejected() {
    let _inet = Inet::up();
    let (svc, backend) = service(|_| {}).await;
    let mut t = svc.open(request(&svc)).await.unwrap().tunnel;
    let h = t.handle();
    for dst in [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(192, 88, 99, 1),
    ] {
        let syn = build_tcp(CLIENT.into(), 40000, dst.into(), 443, 1, tcp_flags::SYN);
        assert_eq!(h.forward(Bytes::from(syn)), Outcome::Refused, "{dst}");
        let answer = inspect(&recv(&mut t, 1000).await.expect("reject")).unwrap();
        assert_eq!((answer.icmp_type, answer.icmp_code), (3, 13), "{dst}");
    }
    let meta = build_tcp(
        CLIENT.into(),
        40000,
        Ipv4Addr::new(169, 254, 169, 254).into(),
        80,
        1,
        tcp_flags::SYN,
    );
    assert_eq!(
        h.forward(Bytes::from(meta.clone())),
        Outcome::Dropped(DropReason::NotForwarded)
    );

    // Bypassing the per-flow layer, the namespace's own rules reject with
    // ICMP administratively prohibited, metadata and the relay's transit
    // addresses included.
    let cfg = svc.config().clone();
    let mut dev = backend.create(plan(&cfg, 9002, 64)).await.unwrap();
    for dst in [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(10, 231, 0, 1),
    ] {
        let syn = build_tcp(CLIENT.into(), 40002, dst.into(), 443, 1, tcp_flags::SYN);
        dev.to_network.send(Bytes::from(syn)).await.unwrap();
        let answer = inspect(&device_recv(&mut dev, 2000).await.expect("kernel reject")).unwrap();
        assert_eq!(answer.protocol, proto::ICMP, "{dst}");
        assert_eq!((answer.icmp_type, answer.icmp_code), (3, 13), "{dst}");
    }
    t.close();
    drop(h);
    drop(dev);
    settle().await;
    backend.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn no_inbound_connections() {
    let inet = Inet::up();
    let (svc, backend) = service(|_| {}).await;
    let mut t = svc.open(request(&svc)).await.unwrap().tunnel;
    let h = t.handle();
    // The relay's side of this tunnel's transit /30 is .1, the namespace .2.
    Inet::send_from_inet(Ipv4Addr::new(10, 231, 0, 2), 40000);
    Inet::send_from_inet(Ipv4Addr::new(10, 231, 0, 2), 22);
    assert!(
        recv(&mut t, 1000).await.is_none(),
        "unsolicited packets stay out"
    );
    // A flow the client starts gets its replies.
    assert_eq!(
        h.forward(udp(CLIENT, 40003, INET, 7, b"out")),
        Outcome::Forwarded
    );
    assert!(recv(&mut t, 3000).await.is_some());
    assert_eq!(inet.received.load(Ordering::SeqCst), 1);
    t.close();
    drop(h);
    settle().await;
    backend.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn tunnels_cannot_reach_each_other() {
    let _inet = Inet::up();
    let (svc, backend) = service(|o| o.max_tunnels_total = 4).await;
    let cfg = svc.config().clone();
    let mut a = backend.create(plan(&cfg, 9101, 64)).await.unwrap();
    let mut b = backend.create(plan(&cfg, 9102, 64)).await.unwrap();
    // B's namespace side of its transit /30 (slot 1): 10.231.0.6.
    let syn = build_tcp(
        CLIENT.into(),
        40004,
        Ipv4Addr::new(10, 231, 0, 6).into(),
        443,
        1,
        tcp_flags::SYN,
    );
    a.to_network.send(Bytes::from(syn)).await.unwrap();
    let answer = inspect(&device_recv(&mut a, 2000).await.expect("reject")).unwrap();
    assert_eq!((answer.icmp_type, answer.icmp_code), (3, 13));
    assert!(device_recv(&mut b, 500).await.is_none());
    drop(a);
    drop(b);
    settle().await;
    backend.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn conntrack_cap_bounds_live_flows() {
    let inet = Inet::up();
    let (svc, backend) = service(|_| {}).await;
    let cfg = svc.config().clone();
    let mut dev = backend.create(plan(&cfg, 9201, 3)).await.unwrap();
    for port in 41000..41003 {
        dev.to_network
            .send(udp(CLIENT, port, INET, 7, b"flow"))
            .await
            .unwrap();
        assert!(device_recv(&mut dev, 2000).await.is_some(), "flow {port}");
    }
    dev.to_network
        .send(udp(CLIENT, 41003, INET, 7, b"one too many"))
        .await
        .unwrap();
    assert!(device_recv(&mut dev, 1000).await.is_none());
    assert_eq!(inet.received.load(Ordering::SeqCst), 3);
    // An existing flow still works.
    dev.to_network
        .send(udp(CLIENT, 41000, INET, 7, b"again"))
        .await
        .unwrap();
    assert!(device_recv(&mut dev, 2000).await.is_some());
    drop(dev);
    settle().await;
    backend.stop().await.unwrap();
}

fn token_of(confirmation: &[Capsule]) -> wisp_ip::ResumeToken {
    confirmation
        .iter()
        .find_map(|c| match c {
            Capsule::ResumeToken { token, .. } => Some(*token),
            _ => None,
        })
        .expect("token")
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn resume_within_and_past_the_grace_period() {
    let inet = Inet::up();
    let (svc, backend) = service(|o| o.resume_grace_s = 2).await;
    let opened = svc.open(request(&svc)).await.unwrap();
    let token = token_of(&opened.confirmation);
    let ns = format!("wtest-{}", opened.tunnel.id());
    let h = opened.tunnel.handle();
    assert_eq!(
        h.forward(udp(CLIENT, 42000, INET, 7, b"before")),
        Outcome::Forwarded
    );
    let mut t = opened.tunnel;
    assert!(recv(&mut t, 3000).await.is_some());
    drop(h);
    t.detach();

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(netns_exists(&ns), "the network waits for the client");
    let mut req = request(&svc);
    req.resume = Some(token);
    let resumed = svc.open(req).await.unwrap();
    assert!(resumed.resumed);
    let token = token_of(&resumed.confirmation);
    let mut t = resumed.tunnel;
    let h = t.handle();
    assert_eq!(
        h.forward(udp(CLIENT, 42000, INET, 7, b"after")),
        Outcome::Forwarded
    );
    let reply = recv(&mut t, 3000).await.expect("the flow continues");
    assert_eq!(&reply[28..], b"after");
    assert_eq!(inet.received.load(Ordering::SeqCst), 2);
    drop(h);
    t.detach();

    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert!(
        !netns_exists(&ns),
        "past the grace period the network is gone"
    );
    let mut req = request(&svc);
    req.resume = Some(token);
    let fresh = svc.open(req).await.unwrap();
    assert!(!fresh.resumed);
    assert_ne!(fresh.tunnel.id(), t_id(&ns));
    fresh.tunnel.close();
    tokio::time::sleep(Duration::from_millis(300)).await;
    settle().await;
    backend.stop().await.unwrap();
}

/// Lets spawned teardowns finish before the test's runtime goes away.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

fn t_id(ns: &str) -> u64 {
    ns.rsplit('-').next().unwrap().parse().unwrap()
}

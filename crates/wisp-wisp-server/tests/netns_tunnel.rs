//! Wisp over WebSocket with the real tunnel network: `serve_connection`
//! driving the Linux namespace backend. Ignored by default; it needs Linux,
//! `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`:
//!
//! ```text
//! cargo test -p wisp-wisp-server --test netns_tunnel --no-run
//! sudo target/debug/deps/netns_tunnel-<hash> --ignored --test-threads=1
//! ```
//!
//! A stand-in internet namespace `wtws-inet` holds 192.88.99.2 with a UDP
//! echo server on port 7; tunnel namespaces are named `wtws-<id>`.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::{channel::mpsc, SinkExt, StreamExt};
use tokio::time::timeout;
use wisp_config::{IpTunnelOptions, WispServerOptions};
use wisp_dos::DosGuard;
use wisp_ip::capsule::want;
use wisp_ip::{encode_capsules, inspect, parse_capsules, Capsule, ClientInfo};
use wisp_tun::icmp::build_udp;
use wisp_tun::netns::NetnsBackend;
use wisp_tun::{TunnelConfig, TunnelService};
use wisp_wisp::{
    close_reason, encode_close, encode_data, encode_info, encode_tunnel, extension_id,
    parse_packet, ExtensionEntry, WispPacket,
};
use wisp_wisp_server::{serve_connection, ServerContext, ServerOptions, WispMessage};

const INET_NS: &str = "wtws-inet";
const INET: Ipv4Addr = Ipv4Addr::new(192, 88, 99, 2);
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);

fn sh(args: &[&str]) {
    let ok = Command::new(args[0])
        .args(&args[1..])
        .status()
        .expect("spawn")
        .success();
    assert!(ok, "{args:?} failed");
}

fn sh_quiet(args: &[&str]) {
    let _ = Command::new(args[0])
        .args(&args[1..])
        .stderr(std::process::Stdio::null())
        .status();
}

fn enter_netns(name: &str) {
    let f = std::fs::File::open(format!("/run/netns/{name}")).expect("netns file");
    // SAFETY: setns on an open namespace descriptor affects only this thread.
    assert_eq!(unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) }, 0);
}

struct Inet;

impl Inet {
    fn up() -> Self {
        sh_quiet(&["ip", "netns", "del", INET_NS]);
        sh(&["ip", "netns", "add", INET_NS]);
        sh(&[
            "ip", "link", "add", "wtws0", "type", "veth", "peer", "name", "eth0", "netns", INET_NS,
        ]);
        sh(&["ip", "addr", "add", "192.88.99.1/24", "dev", "wtws0"]);
        sh(&["ip", "link", "set", "wtws0", "up"]);
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
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            enter_netns(INET_NS);
            let sock = UdpSocket::bind("0.0.0.0:7").expect("bind echo");
            ready_tx.send(()).unwrap();
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&buf[..n], from);
            }
        });
        ready_rx.recv().unwrap();
        Inet
    }
}

impl Drop for Inet {
    fn drop(&mut self) {
        sh_quiet(&["ip", "netns", "del", INET_NS]);
        sh_quiet(&["ip", "link", "del", "wtws0"]);
    }
}

async fn next(rx: &mut mpsc::UnboundedReceiver<WispMessage>) -> WispPacket {
    match timeout(Duration::from_secs(3), rx.next())
        .await
        .expect("server packet timed out")
        .expect("server closed")
    {
        WispMessage::Binary(b) => parse_packet(b).unwrap(),
        WispMessage::Text(t) => panic!("text frame {t}"),
    }
}

#[tokio::test]
#[ignore = "needs Linux, CAP_NET_ADMIN and CAP_SYS_ADMIN"]
async fn wisp_over_websocket_through_a_real_tunnel_network() {
    let _inet = Inet::up();
    let base = WispServerOptions {
        port_whitelist: Some(vec![7]),
        idle_timeout_ms: Some(10_000),
        ..WispServerOptions::default()
    };
    let tunnel_options = IpTunnelOptions {
        enabled: true,
        netns_prefix: "wtws".to_owned(),
        ..IpTunnelOptions::default()
    };
    let cfg = TunnelConfig::from_options(&tunnel_options, &base).unwrap();
    let backend = NetnsBackend::start(Arc::new(cfg.clone()))
        .await
        .expect("namespace backend");
    let dos = Arc::new(DosGuard::new());
    let tunnels = TunnelService::new(cfg, backend.clone(), dos.clone());

    let options = Arc::new(base);
    let server_options = Arc::new(ServerOptions::from_wisp(&options, false));
    let ctx = ServerContext::new(
        "203.0.113.20".to_owned(),
        None,
        options,
        server_options,
        None,
        true,
        dos,
    )
    .with_tunnels(Some(tunnels));
    let (mut in_tx, in_rx) = mpsc::unbounded::<Result<WispMessage, std::io::Error>>();
    let (out_tx, mut out_rx) = mpsc::unbounded();
    let server = tokio::spawn(async move { serve_connection(out_tx, in_rx, ctx).await });

    // Handshake offering IP_TUNNEL.
    assert!(matches!(next(&mut out_rx).await, WispPacket::Info(_)));
    let offer = ExtensionEntry {
        id: extension_id::IP_TUNNEL,
        payload: Bytes::from(
            ClientInfo {
                version: 1,
                flags: 0x3f,
            }
            .encode(),
        ),
    };
    let send = |p: Bytes| Ok(WispMessage::Binary(p));
    in_tx.send(send(encode_info(2, 0, &[offer]))).await.unwrap();
    assert!(matches!(next(&mut out_rx).await, WispPacket::Continue(_)));

    // Open the tunnel on stream 9.
    let open = encode_capsules(&[Capsule::Open { want: want::IPV4 }]);
    in_tx.send(send(encode_tunnel(9, &open))).await.unwrap();
    let WispPacket::Tunnel(confirmation) = next(&mut out_rx).await else {
        panic!("expected the open confirmation");
    };
    let capsules = parse_capsules(&confirmation.capsules).unwrap();
    assert!(
        matches!(&capsules[0], Capsule::AddressAssign(a) if a[0].prefix.addr() == IpAddr::V4(CLIENT))
    );

    // A UDP packet to the echo server and its answer, routed by the kernel.
    let packet = build_udp(CLIENT.into(), 40000, INET.into(), 7, b"through the kernel");
    in_tx.send(send(encode_data(9, &packet))).await.unwrap();
    let WispPacket::Data(reply) = next(&mut out_rx).await else {
        panic!("expected the echo as DATA");
    };
    assert_eq!(reply.stream_id, 9);
    let info = inspect(&reply.payload).unwrap();
    assert_eq!(info.src, IpAddr::V4(INET));
    assert_eq!(info.ttl, 62);
    assert_eq!(&reply.payload[28..], b"through the kernel");

    // A private destination is refused like a firewall would.
    let private = build_udp(
        CLIENT.into(),
        40001,
        Ipv4Addr::new(10, 0, 0, 1).into(),
        7,
        b"x",
    );
    in_tx.send(send(encode_data(9, &private))).await.unwrap();
    let WispPacket::Data(refusal) = next(&mut out_rx).await else {
        panic!("expected the ICMP answer as DATA");
    };
    let info = inspect(&refusal.payload).unwrap();
    assert_eq!((info.icmp_type, info.icmp_code), (3, 13));

    // CLOSE tears the namespace down.
    in_tx
        .send(send(encode_close(9, close_reason::VOLUNTARY)))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(!std::path::Path::new("/run/netns/wtws-1").exists());
    drop(in_tx);
    let _ = timeout(Duration::from_secs(3), server).await;
    backend.stop().await.unwrap();
}

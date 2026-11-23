//! The uplink against the relay's own WebSocket connection loop
//! (`wisp_wisp_server::serve_connection`) and tunnel engine, with the
//! engine's in-memory backend standing in for the tunnel's network. Covers
//! the handshake, the open confirmation, the virtual router's ARP answer,
//! packets both ways, resume after a dropped connection, and the rejected
//! token of a relay that restarted (ERROR 0x0004 inside the confirmation).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;
use wisp_config::{IpTunnelOptions, WispServerOptions};
use wisp_dos::DosGuard;
use wisp_ip_client::ether::{self, ethertype};
use wisp_ip_client::{Carrier, Event, Output, Transmit, Uplink, UplinkConfig};
use wisp_tun::icmp::build_udp;
use wisp_tun::memory::{MemoryBackend, MemoryNetwork};
use wisp_tun::{TunnelConfig, TunnelService};
use wisp_wisp_server::{serve_connection, ServerContext, ServerOptions, WispMessage};

const HOST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const STEP: Duration = Duration::from_secs(5);

struct Relay {
    service: Arc<TunnelService>,
    nets: tokio::sync::mpsc::UnboundedReceiver<MemoryNetwork>,
}

fn relay() -> Relay {
    let o = IpTunnelOptions {
        enabled: true,
        resume_grace_s: 30,
        ..IpTunnelOptions::default()
    };
    let cfg = TunnelConfig::from_options(&o, &WispServerOptions::default()).unwrap();
    let (backend, nets) = MemoryBackend::new();
    Relay {
        service: TunnelService::new(cfg, backend, Arc::new(DosGuard::new())),
        nets,
    }
}

struct Conn {
    to_server: Option<mpsc::UnboundedSender<Result<WispMessage, std::io::Error>>>,
    from_server: mpsc::UnboundedReceiver<WispMessage>,
    task: tokio::task::JoinHandle<()>,
}

fn connect(service: &Arc<TunnelService>) -> Conn {
    let options = Arc::new(WispServerOptions {
        idle_timeout_ms: Some(60_000),
        ..WispServerOptions::default()
    });
    let server_options = Arc::new(ServerOptions::from_wisp(&options, false));
    let ctx = ServerContext::new(
        "203.0.113.20".to_owned(),
        None,
        options,
        server_options,
        None,
        true,
        Arc::new(DosGuard::new()),
    )
    .with_tunnels(Some(service.clone()));
    let (to_server, in_rx) = mpsc::unbounded();
    let (out_tx, from_server) = mpsc::unbounded();
    let task = tokio::spawn(async move {
        let _ = serve_connection(out_tx, in_rx, ctx).await;
    });
    Conn {
        to_server: Some(to_server),
        from_server,
        task,
    }
}

/// Moves the uplink's carrier output to the server and returns its wire
/// frames and events.
async fn flush(u: &mut Uplink, c: &mut Conn) -> (Vec<Vec<u8>>, Vec<Event>) {
    let mut wire = Vec::new();
    let mut events = Vec::new();
    while let Some(o) = u.poll_output() {
        match o {
            Output::Carrier(Transmit::Ws(b)) => {
                if let Some(tx) = c.to_server.as_mut() {
                    tx.send(Ok(WispMessage::Binary(Bytes::from(b))))
                        .await
                        .unwrap();
                }
            }
            Output::Carrier(Transmit::Close) => c.to_server = None,
            Output::Carrier(other) => panic!("no WebTransport output on WebSocket: {other:?}"),
            Output::Wire(f) => wire.push(f),
            Output::Event(e) => events.push(e),
        }
    }
    (wire, events)
}

/// Feeds server messages to the uplink until `done` holds for what came
/// out, and returns everything that came out.
async fn run_until(
    u: &mut Uplink,
    c: &mut Conn,
    now: u64,
    done: impl Fn(&[Vec<u8>], &[Event]) -> bool,
) -> (Vec<Vec<u8>>, Vec<Event>) {
    let (mut wire, mut events) = flush(u, c).await;
    while !done(&wire, &events) {
        let msg = timeout(STEP, c.from_server.next())
            .await
            .expect("the relay answers in time")
            .expect("the relay keeps the connection");
        let WispMessage::Binary(b) = msg else {
            panic!("text from the relay");
        };
        u.ws_message(now, &b);
        let (w, e) = flush(u, c).await;
        wire.extend(w);
        events.extend(e);
    }
    (wire, events)
}

fn link_up(events: &[Event]) -> Option<(bool, bool)> {
    events.iter().find_map(|e| match e {
        Event::LinkUp {
            resumed,
            flows_lost,
            ..
        } => Some((*resumed, *flows_lost)),
        _ => None,
    })
}

fn uplink() -> Uplink {
    let mut cfg = UplinkConfig::default();
    cfg.wants.ipv6 = false;
    cfg.router.host_mac = Some(HOST_MAC);
    Uplink::new(cfg)
}

fn frame_to_gateway(u: &Uplink, packet: &[u8]) -> Vec<u8> {
    ether::build_frame(u.router().gateway_mac(), HOST_MAC, ethertype::IPV4, packet)
}

async fn drop_connection(u: &mut Uplink, mut c: Conn, now: u64) -> Vec<Event> {
    c.to_server = None;
    timeout(STEP, c.task)
        .await
        .expect("the relay ends")
        .unwrap();
    u.disconnected(now);
    std::iter::from_fn(|| u.poll_output())
        .filter_map(|o| match o {
            Output::Event(e) => Some(e),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn the_uplink_opens_a_tunnel_and_carries_packets() {
    let mut r = relay();
    let mut u = uplink();
    let mut c = connect(&r.service);
    u.connected(0, Carrier::WebSocket);
    let (_, events) = run_until(&mut u, &mut c, 0, |_, e| link_up(e).is_some()).await;
    assert_eq!(link_up(&events), Some((false, false)));
    let cfg = u.config().unwrap().clone();
    assert_eq!(cfg.ipv4().unwrap().prefix.addr(), IpAddr::V4(CLIENT));
    assert_eq!(cfg.gateway4(), Some(GATEWAY));
    assert_eq!(cfg.link.link_mtu, 1500);
    let mut net = r.nets.recv().await.expect("the relay built a network");

    // ARP for the gateway is answered on the link; nothing crosses.
    let arp = ether::build_frame(
        ether::BROADCAST,
        HOST_MAC,
        ethertype::ARP,
        &ether::build_arp(&ether::Arp {
            op: ether::ARP_REQUEST,
            sender_mac: HOST_MAC,
            sender_ip: CLIENT,
            target_mac: [0; 6],
            target_ip: GATEWAY,
        }),
    );
    u.wire_frame(1, &arp);
    let (wire, _) = flush(&mut u, &mut c).await;
    assert_eq!(wire.len(), 1);
    assert!(net.from_tunnel.try_recv().is_err());

    // A UDP packet from the machine reaches the tunnel's network unchanged.
    let out = build_udp(CLIENT.into(), 40000, REMOTE.into(), 443, &[7u8; 1000]);
    u.wire_frame(2, &frame_to_gateway(&u, &out));
    flush(&mut u, &mut c).await;
    let got = timeout(STEP, net.from_tunnel.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.as_ref(), out.as_slice());

    // The answer comes back as a frame for the machine.
    let back = build_udp(REMOTE.into(), 443, CLIENT.into(), 40000, &[9u8; 1400]);
    net.to_tunnel.send(Bytes::from(back.clone())).await.unwrap();
    let (wire, _) = run_until(&mut u, &mut c, 3, |w, _| !w.is_empty()).await;
    let f = ether::parse_frame(&wire[0]).unwrap();
    assert_eq!(f.dst, HOST_MAC);
    assert_eq!(f.payload, back.as_slice());
    assert_eq!(u.stats().mux.packets_in, 1);
}

#[tokio::test]
async fn a_dropped_connection_resumes_the_same_tunnel() {
    let mut r = relay();
    let mut u = uplink();
    let mut c = connect(&r.service);
    u.connected(0, Carrier::WebSocket);
    run_until(&mut u, &mut c, 0, |_, e| link_up(e).is_some()).await;
    let net = r.nets.recv().await.unwrap();
    // A flow, so the relay's inbound filter lets its answers in.
    let out = build_udp(CLIENT.into(), 40001, REMOTE.into(), 443, b"before");
    u.wire_frame(1, &frame_to_gateway(&u, &out));
    flush(&mut u, &mut c).await;

    let events = drop_connection(&mut u, c, 1_000).await;
    assert!(matches!(
        &events[..],
        [Event::Detached {
            resume_until_ms: 31_000
        }]
    ));

    let mut c = connect(&r.service);
    u.connected(2_000, Carrier::WebSocket);
    let (_, events) = run_until(&mut u, &mut c, 2_000, |_, e| link_up(e).is_some()).await;
    assert_eq!(
        link_up(&events),
        Some((true, false)),
        "resumed, flows alive"
    );
    assert!(
        r.nets.try_recv().is_err(),
        "the relay kept the tunnel's network"
    );
    // The flow's answer, sent by the network the tunnel kept, arrives on the
    // new connection.
    let back = build_udp(REMOTE.into(), 443, CLIENT.into(), 40001, b"after");
    net.to_tunnel.send(Bytes::from(back.clone())).await.unwrap();
    let (wire, _) = run_until(&mut u, &mut c, 3_000, |w, _| !w.is_empty()).await;
    // Short frames carry Ethernet padding after the packet.
    let payload = ether::parse_frame(&wire[0]).unwrap().payload;
    assert_eq!(&payload[..back.len()], back.as_slice());
}

#[tokio::test]
async fn a_restarted_relay_rejects_the_token_and_the_flows_are_lost() {
    let r = relay();
    let mut u = uplink();
    let mut c = connect(&r.service);
    u.connected(0, Carrier::WebSocket);
    run_until(&mut u, &mut c, 0, |_, e| link_up(e).is_some()).await;
    drop_connection(&mut u, c, 1_000).await;

    // A new relay process: it knows no token.
    let mut restarted = relay();
    let mut c = connect(&restarted.service);
    u.connected(2_000, Carrier::WebSocket);
    let (_, events) = run_until(&mut u, &mut c, 2_000, |_, e| link_up(e).is_some()).await;
    assert_eq!(link_up(&events), Some((false, true)), "a new tunnel");
    assert!(restarted.nets.try_recv().is_ok(), "built a new network");
    assert_eq!(
        u.config().unwrap().ipv4().unwrap().prefix.addr(),
        IpAddr::V4(CLIENT),
        "the same addresses, which is why ERROR 0x0004 matters"
    );
}

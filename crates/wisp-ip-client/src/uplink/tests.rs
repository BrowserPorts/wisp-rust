use super::*;
use crate::ether::parse_frame;
use crate::testutil::*;
use bytes::Bytes;
use wisp_ip::parse_capsules;
use wisp_wisp::{parse_packet, WispPacket};

fn uplink(resume: bool) -> Uplink {
    Uplink::new(UplinkConfig {
        wants: Wants {
            ipv4: true,
            ipv6: true,
            resume,
            icmp_echo: true,
        },
        router: RouterConfig {
            host_mac: Some(HOST_MAC),
            ..RouterConfig::default()
        },
        open_timeout_ms: 15_000,
    })
}

#[derive(Default)]
struct Drained {
    ws: Vec<WispPacket>,
    wire: Vec<Vec<u8>>,
    events: Vec<Event>,
    close: bool,
}

fn drain(u: &mut Uplink) -> Drained {
    let mut d = Drained::default();
    while let Some(o) = u.poll_output() {
        match o {
            Output::Carrier(Transmit::Ws(b)) => d.ws.push(parse_packet(Bytes::from(b)).unwrap()),
            Output::Carrier(Transmit::Close) => d.close = true,
            Output::Carrier(other) => panic!("unexpected {other:?}"),
            Output::Wire(f) => d.wire.push(f),
            Output::Event(e) => d.events.push(e),
        }
    }
    d
}

/// Connects over WebSocket and returns the stream id the uplink opened and
/// the capsules of its OPEN.
fn connect(u: &mut Uplink, now: u64) -> (u32, Vec<Capsule>) {
    u.connected(now, Carrier::WebSocket);
    u.ws_message(now, &ws_server_info(Some(server_entry())));
    u.ws_message(now, &wisp_wisp::encode_continue(0, 128));
    let d = drain(u);
    let WispPacket::Tunnel(open) = d.ws.last().unwrap().clone() else {
        panic!("the uplink opens a tunnel once the handshake is done");
    };
    (open.stream_id, parse_capsules(&open.capsules).unwrap())
}

fn link_up(d: &Drained) -> (bool, bool, LinkConfig) {
    d.events
        .iter()
        .find_map(|e| match e {
            Event::LinkUp {
                config,
                resumed,
                flows_lost,
            } => Some((*resumed, *flows_lost, config.clone())),
            _ => None,
        })
        .expect("LinkUp")
}

#[test]
fn a_tunnel_carries_the_machines_frames() {
    let mut u = uplink(true);
    let (id, open) = connect(&mut u, 0);
    assert_eq!(
        open,
        [Capsule::Open { want: 3 }],
        "no token on a first open"
    );
    u.ws_message(10, &ws_tunnel(id, &confirmation(false, 0, 30, 1)));
    let d = drain(&mut u);
    let (resumed, lost, cfg) = link_up(&d);
    assert!(!resumed && !lost);
    assert_eq!(cfg.gateway4(), Some(GATEWAY4));
    assert!(d.wire.is_empty(), "no router advertisement without IPv6");
    assert!(u.is_up());

    // ARP for the gateway is the router's; the packet goes to the relay.
    u.wire_frame(20, &arp_request(GATEWAY4));
    assert_eq!(drain(&mut u).wire.len(), 1);
    let p = udp4(CLIENT4, REMOTE4, 64);
    u.wire_frame(21, &to_gateway(&p));
    let d = drain(&mut u);
    assert!(
        matches!(&d.ws[..], [WispPacket::Data(data)] if data.stream_id == id && data.payload == p)
    );

    // And the answer reaches the wire as a frame for the machine.
    let back = udp4(REMOTE4, CLIENT4, 64);
    u.ws_message(22, &wisp_wisp::encode_data(id, &back));
    let d = drain(&mut u);
    let f = parse_frame(&d.wire[0]).unwrap();
    assert_eq!((f.dst, f.src), (HOST_MAC, GATEWAY_MAC));
    assert_eq!(&f.payload[..back.len()], back.as_slice());
}

#[test]
fn an_ipv6_tunnel_starts_router_advertisements() {
    let mut u = uplink(true);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &ws_tunnel(id, &confirmation(true, 0, 30, 1)));
    let d = drain(&mut u);
    assert_eq!(d.wire.len(), 1, "one router advertisement");
    assert!(u.router().advertises_ipv6());
}

#[test]
fn a_dropped_carrier_resumes_within_the_grace_period() {
    let mut u = uplink(true);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 30, 1)));
    drain(&mut u);

    u.disconnected(1_000);
    let d = drain(&mut u);
    assert_eq!(
        d.events,
        [Event::Detached {
            resume_until_ms: 31_000
        }]
    );
    assert!(u.config().is_some(), "the machine keeps its addresses");
    // A cable pulled for a moment: frames meanwhile are dropped.
    u.wire_frame(2_000, &to_gateway(&udp4(CLIENT4, REMOTE4, 10)));
    assert_eq!(u.stats().dropped_not_up, 1);
    assert_eq!(u.poll_timeout(), Some(31_000));

    let (id2, open) = connect(&mut u, 5_000);
    assert_eq!(
        open,
        [
            Capsule::Open { want: 3 },
            Capsule::Resume { token: [1; 32] }
        ]
    );
    u.ws_message(5_010, &ws_tunnel(id2, &confirmation(false, 0, 30, 2)));
    let (resumed, lost, _) = link_up(&drain(&mut u));
    assert!(resumed && !lost);

    // The rotated token is the one the next resume uses.
    u.disconnected(6_000);
    drain(&mut u);
    let (_, open) = connect(&mut u, 6_500);
    assert_eq!(open[1], Capsule::Resume { token: [2; 32] });
}

#[test]
fn a_rejected_token_means_the_flows_are_gone() {
    let mut u = uplink(true);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 30, 1)));
    drain(&mut u);
    u.disconnected(1_000);
    drain(&mut u);
    let (id2, open) = connect(&mut u, 2_000);
    assert_eq!(open.len(), 2);
    // The relay restarted and does not know the token: a new tunnel, with
    // the same addresses, and ERROR 0x0004 inside the confirmation.
    let mut caps = confirmation(false, 0, 30, 5);
    caps.push(Capsule::Error {
        code: error_code::RESUME_REJECTED,
        message: "resume token rejected; this is a new tunnel".to_owned(),
    });
    u.ws_message(2_010, &ws_tunnel(id2, &caps));
    let (resumed, lost, cfg) = link_up(&drain(&mut u));
    assert!(!resumed && lost);
    assert_eq!(
        cfg.ipv4().unwrap().prefix.addr(),
        std::net::IpAddr::V4(CLIENT4)
    );
}

#[test]
fn past_the_grace_period_the_token_is_not_sent() {
    let mut u = uplink(true);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 30, 1)));
    drain(&mut u);
    u.disconnected(1_000);
    drain(&mut u);
    u.handle_timeout(31_000);
    let d = drain(&mut u);
    assert_eq!(
        d.events,
        [Event::LinkDown {
            reason: LinkDownReason::ResumeExpired
        }]
    );
    assert!(u.config().is_none());
    let (id2, open) = connect(&mut u, 40_000);
    assert_eq!(open, [Capsule::Open { want: 3 }]);
    u.ws_message(40_000, &ws_tunnel(id2, &confirmation(false, 0, 30, 3)));
    let (resumed, lost, _) = link_up(&drain(&mut u));
    assert!(!resumed && lost);
}

#[test]
fn without_a_token_a_dropped_carrier_ends_the_link() {
    let mut u = uplink(false);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 0, 0)));
    drain(&mut u);
    u.disconnected(1_000);
    assert_eq!(
        drain(&mut u).events,
        [Event::LinkDown {
            reason: LinkDownReason::CarrierLost
        }]
    );
}

#[test]
fn a_refused_open_is_reported() {
    let mut u = uplink(true);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &wisp_wisp::encode_close(id, close_reason::BLOCKED));
    assert_eq!(
        drain(&mut u).events,
        [Event::LinkDown {
            reason: LinkDownReason::Refused {
                reason: close_reason::BLOCKED,
                error: None
            }
        }]
    );
}

#[test]
fn a_slow_confirmation_times_out_once() {
    let mut u = uplink(true);
    connect(&mut u, 0);
    assert_eq!(u.poll_timeout(), Some(15_000));
    u.handle_timeout(15_000);
    let d = drain(&mut u);
    assert_eq!(d.events, [Event::OpenTimedOut]);
    assert!(d.close);
    u.handle_timeout(16_000);
    assert!(drain(&mut u).events.is_empty());
    u.disconnected(16_500);
    assert!(drain(&mut u).events.is_empty());
}

#[test]
fn later_control_changes_the_configuration() {
    let mut u = uplink(true);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 30, 1)));
    drain(&mut u);
    let new = wisp_ip::AssignedAddress {
        prefix: wisp_ip::Prefix::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 101)),
            24,
        )
        .unwrap(),
        valid_lft: 600,
        preferred_lft: 300,
    };
    u.ws_message(1, &ws_tunnel(id, &[Capsule::AddressAssign(vec![new])]));
    let d = drain(&mut u);
    assert!(matches!(&d.events[..], [Event::LinkChanged { config }] if config.addresses == [new]));
    // The same again changes nothing.
    u.ws_message(2, &ws_tunnel(id, &[Capsule::AddressAssign(vec![new])]));
    assert!(drain(&mut u).events.is_empty());
}

#[test]
fn a_voluntary_close_ends_tunnel_and_carrier() {
    let mut u = uplink(true);
    let (id, _) = connect(&mut u, 0);
    u.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 30, 1)));
    drain(&mut u);
    u.close(5);
    let d = drain(&mut u);
    assert!(
        matches!(&d.ws[..], [WispPacket::Close(c)] if c.stream_id == id && c.reason == close_reason::VOLUNTARY)
    );
    assert!(d.close);
    assert!(matches!(
        &d.events[..],
        [Event::LinkDown {
            reason: LinkDownReason::Closed { .. }
        }]
    ));
    // The carrier's disconnect afterwards does not try to resume.
    u.disconnected(6);
    assert!(drain(&mut u).events.is_empty());
}

use super::*;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;
use wisp_config::IpTunnelOptions;
use wisp_dos::DosGuard;
use wisp_ip::capsule::LinkParams;
use wisp_tun::icmp::build_udp;
use wisp_tun::memory::{MemoryBackend, MemoryNetwork};
use wisp_tun::{Binding, TunnelConfig};
use wisp_wire::{decode_frame_body, parse_tunnel_close_payload, parse_tunnel_payload};

const CLIENT: &str = "192.168.1.100";
const PUBLIC: &str = "93.184.216.34";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[derive(Default)]
struct Recorder {
    datagrams: Mutex<Vec<Bytes>>,
    unis: Mutex<HashMap<u32, mpsc::Receiver<Bytes>>>,
}

struct Output(Arc<Recorder>);

impl TunnelOutput for Output {
    fn datagram(&self, frame: Bytes) -> bool {
        self.0.datagrams.lock().push(frame);
        true
    }
    fn uni(&self, tunnel_id: u32) -> mpsc::Sender<Bytes> {
        let (tx, rx) = mpsc::channel(TUNNEL_UNI_QUEUE);
        self.0.unis.lock().insert(tunnel_id, rx);
        tx
    }
}

struct Harness {
    flows: Arc<TunnelFlows>,
    control: mpsc::Receiver<Bytes>,
    recorder: Arc<Recorder>,
    nets: mpsc::UnboundedReceiver<MemoryNetwork>,
    service: Arc<TunnelService>,
}

fn harness(edit: impl FnOnce(&mut IpTunnelOptions), options: WispServerOptions) -> Harness {
    let mut o = IpTunnelOptions {
        enabled: true,
        ..IpTunnelOptions::default()
    };
    edit(&mut o);
    let cfg = TunnelConfig::from_options(&o, &WispServerOptions::default()).unwrap();
    let info = cfg.server_info(Binding::WebTransport);
    let (backend, nets) = MemoryBackend::new();
    let service = TunnelService::new(cfg, backend, Arc::new(DosGuard::new()));
    let (control_tx, control) = mpsc::channel(64);
    let recorder = Arc::new(Recorder::default());
    let options = Arc::new(options);
    let flows = TunnelFlows::new(
        service.clone(),
        Negotiated {
            version: 1,
            flags: info.flags,
            max_tunnels: info.max_tunnels,
            link_mtu: info.link_mtu,
            max_packet: info.max_packet,
        },
        TunnelSession {
            client_ip: "203.0.113.4".to_owned(),
            principal: None,
            policy: Arc::new(HostPolicy::from_options(&options)),
            options,
            max_datagram_bytes: 65_535,
        },
        control_tx,
        Arc::new(Output(recorder.clone())),
        TaskTracker::new(),
    );
    Harness {
        flows,
        control,
        recorder,
        nets,
        service,
    }
}

fn open_frame(tunnel_id: u32, wanted: u16) -> TunnelFrame {
    TunnelFrame {
        tunnel_id,
        capsules: Bytes::from(encode_capsules(&[Capsule::Open { want: wanted }])),
    }
}

/// The next control frame: its type and body.
async fn control(h: &mut Harness) -> (u8, Bytes) {
    let frame = timeout(Duration::from_secs(2), h.control.recv())
        .await
        .expect("control frame timed out")
        .expect("control closed");
    let body = decode_frame_body(&frame[4..]).unwrap();
    (body.frame_type, body.payload)
}

async fn expect_opened(h: &mut Harness, tunnel_id: u32) -> Vec<Capsule> {
    let (ty, payload) = control(h).await;
    assert_eq!(ty, frame_type::TUNNEL_OPENED);
    let opened = parse_tunnel_payload(&payload).unwrap();
    assert_eq!(opened.tunnel_id, tunnel_id);
    parse_capsules(&opened.capsules).unwrap()
}

async fn expect_close(h: &mut Harness, tunnel_id: u32, reason: u8) {
    let (ty, payload) = control(h).await;
    assert_eq!(ty, frame_type::TUNNEL_CLOSE);
    let close = parse_tunnel_close_payload(&payload).unwrap();
    assert_eq!((close.tunnel_id, close.reason), (tunnel_id, reason));
}

fn link(capsules: &[Capsule]) -> LinkParams {
    capsules
        .iter()
        .find_map(|c| match c {
            Capsule::Link(l) => Some(*l),
            _ => None,
        })
        .expect("LINK")
}

async fn from_tunnel(net: &mut MemoryNetwork) -> Bytes {
    timeout(Duration::from_secs(2), net.from_tunnel.recv())
        .await
        .expect("network packet timed out")
        .unwrap()
}

fn public_options() -> WispServerOptions {
    WispServerOptions {
        port_whitelist: Some(vec![443]),
        ..WispServerOptions::default()
    }
}

#[tokio::test]
async fn datagram_tunnel_carries_whole_and_split_packets() {
    let mut h = harness(|_| {}, public_options());
    h.flows
        .on_open(open_frame(7, want::IPV4 | want::DATAGRAMS))
        .await;
    let capsules = expect_opened(&mut h, 7).await;
    assert_eq!(link(&capsules).max_datagram_payload, 65_529);
    let mut net = h.nets.recv().await.unwrap();

    // A small packet in one datagram.
    let small = build_udp(ip(CLIENT), 4000, ip(PUBLIC), 443, b"q");
    h.flows
        .on_datagram(7, &[&[frag::WHOLE][..], &small[..]].concat());
    assert_eq!(&from_tunnel(&mut net).await[..], &small[..]);

    // A 1500-byte packet in two pieces, last piece first.
    let big = build_udp(ip(CLIENT), 4000, ip(PUBLIC), 443, &[7u8; 1472]);
    assert_eq!(big.len(), 1500);
    let pieces = frag::split(big.len(), 1194, 0x0102).unwrap();
    assert_eq!(pieces.len(), 2);
    for (header, range) in pieces.into_iter().rev() {
        let mut d = Vec::new();
        header.encode(&mut d);
        d.extend_from_slice(&big[range]);
        h.flows.on_datagram(7, &d);
    }
    assert_eq!(&from_tunnel(&mut net).await[..], &big[..]);

    // Replies: a small one rides the interactive class whole, a 1500-byte
    // one is split to fit Chrome's datagrams.
    let reply = build_udp(ip(PUBLIC), 443, ip(CLIENT), 4000, b"r");
    net.to_tunnel
        .send(Bytes::from(reply.clone()))
        .await
        .unwrap();
    let big_reply = build_udp(ip(PUBLIC), 443, ip(CLIENT), 4000, &[9u8; 1472]);
    net.to_tunnel
        .send(Bytes::from(big_reply.clone()))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while h.recorder.datagrams.lock().len() < 3 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let datagrams = h.recorder.datagrams.lock().clone();
    assert_eq!(datagrams.len(), 3);
    assert_eq!(
        &datagrams[0][..7],
        &[
            datagram_class::INTERACTIVE,
            datagram_kind::IP,
            7,
            0,
            0,
            0,
            frag::WHOLE
        ]
    );
    assert_eq!(&datagrams[0][7..], &reply[..]);
    let mut r = Reassembler::new(1500);
    let mut out = None;
    for d in &datagrams[1..] {
        assert!(d.len() <= TUNNEL_DATAGRAM_BYTES);
        assert_eq!(
            &d[..6],
            &[datagram_class::NORMAL, datagram_kind::IP, 7, 0, 0, 0]
        );
        let (header, data) = FragHeader::parse(&d[6..]).unwrap();
        if let Reassembled::Packet(p) = r.push(0, header, data) {
            out = Some(p);
        }
    }
    assert_eq!(out.unwrap(), big_reply);
}

#[tokio::test]
async fn uni_stream_tunnel_without_datagrams() {
    let mut h = harness(|_| {}, public_options());
    h.flows.on_open(open_frame(3, want::IPV4)).await;
    let capsules = expect_opened(&mut h, 3).await;
    assert_eq!(link(&capsules).max_datagram_payload, 0);
    let mut net = h.nets.recv().await.unwrap();

    // Datagrams are not this tunnel's.
    let packet = build_udp(ip(CLIENT), 4001, ip(PUBLIC), 443, b"uni");
    h.flows
        .on_datagram(3, &[&[frag::WHOLE][..], &packet[..]].concat());
    assert!(net.from_tunnel.try_recv().is_err());

    // The client's uni stream, cut at awkward places.
    let mut stream = Vec::new();
    stream.extend_from_slice(&3u32.to_le_bytes());
    stream.extend_from_slice(&(packet.len() as u16).to_le_bytes());
    stream.extend_from_slice(&packet);
    let mut decoder = UniDecoder::default();
    decoder.push(&stream[..3]);
    assert!(decoder.tunnel_id().is_none());
    decoder.push(&stream[3..9]);
    assert_eq!(decoder.tunnel_id(), Some(3));
    assert!(decoder.next_packet().is_none());
    decoder.push(&stream[9..]);
    let handle = h.flows.accepts_uni(3).expect("a uni tunnel");
    assert!(h.flows.accepts_uni(4).is_none());
    handle.forward(decoder.next_packet().unwrap());
    assert_eq!(decoder.buffered(), 0);
    assert_eq!(&from_tunnel(&mut net).await[..], &packet[..]);

    // Replies come back on the server's uni stream as chunks.
    let reply = build_udp(ip(PUBLIC), 443, ip(CLIENT), 4001, b"back");
    net.to_tunnel
        .send(Bytes::from(reply.clone()))
        .await
        .unwrap();
    let mut rx = h.recorder.unis.lock().remove(&3).expect("a uni stream");
    let chunk = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&chunk[..2], &(reply.len() as u16).to_le_bytes());
    assert_eq!(&chunk[2..], &reply[..]);
    assert!(h.recorder.datagrams.lock().is_empty());
}

#[tokio::test]
async fn close_and_later_control() {
    let mut h = harness(|o| o.max_tunnels_per_connection = 4, public_options());
    h.flows
        .on_open(open_frame(1, want::IPV4 | want::DATAGRAMS))
        .await;
    expect_opened(&mut h, 1).await;
    let net = h.nets.recv().await.unwrap();
    h.flows.on_close(TunnelClose {
        tunnel_id: 1,
        reason: close_reason::VOLUNTARY,
    });
    timeout(Duration::from_secs(2), net.torn_down())
        .await
        .expect("TUNNEL_CLOSE tears the network down");
    assert!(h.flows.is_empty());

    h.flows
        .on_open(open_frame(2, want::IPV4 | want::DATAGRAMS))
        .await;
    expect_opened(&mut h, 2).await;
    let _net = h.nets.recv().await.unwrap();
    // Harmless later control is ignored; a second OPEN ends the tunnel.
    h.flows
        .on_capsules(TunnelFrame {
            tunnel_id: 2,
            capsules: Bytes::new(),
        })
        .await;
    h.flows.on_capsules(open_frame(2, want::IPV4)).await;
    expect_close(&mut h, 2, close_reason::INVALID_INFO).await;
    assert!(h.flows.is_empty());
}

#[tokio::test]
async fn refused_opens() {
    let mut h = harness(|_| {}, public_options());
    // Not an OPEN first.
    h.flows
        .on_open(TunnelFrame {
            tunnel_id: 1,
            capsules: Bytes::from(encode_capsules(&[Capsule::Resume { token: [0; 32] }])),
        })
        .await;
    expect_close(&mut h, 1, close_reason::INVALID_INFO).await;
    // An unknown critical capsule.
    h.flows
        .on_open(TunnelFrame {
            tunnel_id: 2,
            capsules: Bytes::from_static(&[
                0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x77, 0x00, 0x00, 0x00,
            ]),
        })
        .await;
    expect_close(&mut h, 2, close_reason::INVALID_INFO).await;
    // One tunnel per session.
    h.flows.on_open(open_frame(3, want::IPV4)).await;
    expect_opened(&mut h, 3).await;
    h.flows.on_open(open_frame(4, want::IPV4)).await;
    let (ty, payload) = control(&mut h).await;
    assert_eq!(ty, frame_type::TUNNEL_CAPSULES);
    let error = parse_tunnel_payload(&payload).unwrap();
    assert!(matches!(
        parse_capsules(&error.capsules).unwrap()[..],
        [Capsule::Error {
            code: error_code::TOO_MANY_TUNNELS,
            ..
        }]
    ));
    expect_close(&mut h, 4, close_reason::THROTTLED).await;

    // A credential that may not open tunnels.
    let mut blocked = public_options();
    blocked.allow_ip_tunnel = false;
    let mut h = harness(|_| {}, blocked);
    h.flows.on_open(open_frame(1, want::IPV4)).await;
    expect_close(&mut h, 1, close_reason::BLOCKED).await;
    assert!(h.nets.try_recv().is_err());
}

#[tokio::test]
async fn session_end_leaves_tunnels_to_resume() {
    let mut h = harness(|_| {}, public_options());
    h.flows
        .on_open(open_frame(5, want::IPV4 | want::DATAGRAMS))
        .await;
    expect_opened(&mut h, 5).await;
    let net = h.nets.recv().await.unwrap();
    h.flows.shutdown();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!net.is_torn_down(), "parked for the resume grace period");
    assert_eq!(h.service.live_tunnels(), 1);
}

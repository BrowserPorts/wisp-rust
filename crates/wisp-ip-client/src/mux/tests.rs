use super::*;
use crate::testutil::*;
use wisp_ip::capsule::error_code;
use wisp_ip::frag::Reassembler;
use wisp_wisp::{parse_packet, WispPacket};

fn transmits(m: &mut Mux) -> Vec<Transmit> {
    std::iter::from_fn(|| m.poll_transmit()).collect()
}

fn events(m: &mut Mux) -> Vec<MuxEvent> {
    std::iter::from_fn(|| m.poll_event()).collect()
}

fn ws(t: &Transmit) -> WispPacket {
    match t {
        Transmit::Ws(b) => parse_packet(Bytes::copy_from_slice(b)).unwrap(),
        other => panic!("expected a WebSocket message, got {other:?}"),
    }
}

/// A WebSocket mux through the handshake.
fn ws_ready() -> Mux {
    let mut m = Mux::new(Wants::default());
    m.connected(Carrier::WebSocket);
    assert!(transmits(&mut m).is_empty(), "the server speaks first");
    m.ws_message(0, &ws_server_info(Some(server_entry())));
    let t = transmits(&mut m);
    assert_eq!(t.len(), 1);
    let WispPacket::Info(info) = ws(&t[0]) else {
        panic!("the client answers INFO");
    };
    assert_eq!((info.major, info.minor), (2, 0));
    let entries = wisp_wisp::parse_extensions(info.extensions).unwrap();
    assert_eq!(entries.len(), 1);
    let entry = ClientInfo::parse(&entries[0].payload).unwrap();
    assert_eq!(entry.version, 1);
    assert_eq!(
        entry.flags,
        flags::IPV4 | flags::IPV6 | flags::RESUME | flags::ICMP_ECHO,
        "no datagram flags on WebSocket"
    );
    assert!(!m.is_ready());
    m.ws_message(0, &wisp_wisp::encode_continue(0, 128));
    assert!(m.is_ready());
    let ev = events(&mut m);
    assert!(
        matches!(&ev[..], [MuxEvent::Ready(n)] if n.has(flags::RESUME) && !n.has(flags::DATAGRAMS))
    );
    m
}

fn wt_ready(datagrams: bool, max_datagram_size: usize) -> Mux {
    let mut m = Mux::new(Wants::default());
    m.connected(Carrier::WebTransport {
        datagrams,
        max_datagram_size,
    });
    let t = transmits(&mut m);
    let Transmit::WtControl(info) = &t[0] else {
        panic!("the client speaks first on WebTransport");
    };
    assert_eq!(info[4], wisp_wire::frame_type::INFO);
    let entries = wisp_wire::parse_extensions(&info[5..]).unwrap();
    let entry = ClientInfo::parse(&entries[0].payload).unwrap();
    assert_eq!(
        entry.flags & (flags::DATAGRAMS | flags::FRAGMENTS) != 0,
        datagrams
    );
    // INFO and READY arrive a byte at a time.
    for b in wt_server_info_ready(server_entry()) {
        m.wt_control(0, &[b]);
    }
    assert!(m.is_ready());
    assert!(matches!(&events(&mut m)[..], [MuxEvent::Ready(_)]));
    m
}

#[test]
fn websocket_handshake_open_and_packets() {
    let mut m = ws_ready();
    let id = m.open(true, true, None).unwrap();
    let t = transmits(&mut m);
    let WispPacket::Tunnel(open) = ws(&t[0]) else {
        panic!("TUNNEL with OPEN");
    };
    assert_eq!(open.stream_id, id);
    assert_eq!(
        parse_capsules(&open.capsules).unwrap(),
        [Capsule::Open {
            want: want::IPV4 | want::IPV6
        }]
    );
    // DATA before the confirmation is not the relay's to send: dropped.
    m.ws_message(0, &wisp_wisp::encode_data(id, &udp4(REMOTE4, CLIENT4, 10)));
    assert!(events(&mut m).is_empty());
    assert!(
        !m.send_packet(0, id, &udp4(CLIENT4, REMOTE4, 10)),
        "not open yet"
    );

    m.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 30, 7)));
    let ev = events(&mut m);
    assert!(
        matches!(&ev[..], [MuxEvent::Opened { id: i, capsules }] if *i == id && capsules.len() == 5)
    );

    let out = udp4(CLIENT4, REMOTE4, 1452);
    assert!(m.send_packet(0, id, &out));
    let WispPacket::Data(d) = ws(&transmits(&mut m)[0]) else {
        panic!("DATA");
    };
    assert_eq!((d.stream_id, d.payload.as_ref()), (id, out.as_slice()));

    let back = udp4(REMOTE4, CLIENT4, 1452);
    m.ws_message(0, &wisp_wisp::encode_data(id, &back));
    assert_eq!(
        events(&mut m),
        [MuxEvent::Packet {
            id,
            packet: back.clone()
        }]
    );
    // A tunnel draws no CONTINUE, and one sent anyway changes nothing.
    m.ws_message(0, &wisp_wisp::encode_continue(id, 5));
    assert!(events(&mut m).is_empty() && transmits(&mut m).is_empty());
    assert!(
        !m.send_packet(0, id, &[0x45; 1501]),
        "larger than max_packet"
    );
}

#[test]
fn a_wisp_v1_server_is_unsupported() {
    let mut m = Mux::new(Wants::default());
    m.connected(Carrier::WebSocket);
    m.ws_message(0, &wisp_wisp::encode_continue(0, 128));
    assert_eq!(events(&mut m), [MuxEvent::Unsupported(Unsupported::WispV1)]);
    assert_eq!(transmits(&mut m), [Transmit::Close]);
}

#[test]
fn a_relay_without_the_extension_is_unsupported() {
    let mut m = Mux::new(Wants::default());
    m.connected(Carrier::WebSocket);
    m.ws_message(0, &ws_server_info(None));
    let t = transmits(&mut m);
    assert!(matches!(ws(&t[0]), WispPacket::Info(i) if i.extensions.is_empty()));
    assert_eq!(t[1], Transmit::Close);
    assert_eq!(
        events(&mut m),
        [MuxEvent::Unsupported(Unsupported::NoExtension)]
    );
}

#[test]
fn a_wrong_magic_or_version_is_unsupported() {
    let mut bad = server_entry();
    bad[0] = b'X';
    let mut m = Mux::new(Wants::default());
    m.connected(Carrier::WebSocket);
    m.ws_message(0, &ws_server_info(Some(bad)));
    assert_eq!(
        events(&mut m),
        [MuxEvent::Unsupported(Unsupported::BadEntry(
            InfoError::BadMagic
        ))]
    );

    let mut v2 = ServerInfo::v1(flags::KNOWN, 1, 1500, 1500);
    v2.ver_min = 2;
    v2.ver_max = 3;
    let mut m = Mux::new(Wants::default());
    m.connected(Carrier::WebSocket);
    m.ws_message(0, &ws_server_info(Some(v2.encode())));
    assert_eq!(
        events(&mut m),
        [MuxEvent::Unsupported(Unsupported::Version {
            min: 2,
            max: 3
        })]
    );
}

#[test]
fn a_refusal_carries_its_error() {
    let mut m = ws_ready();
    let id = m.open(true, false, None).unwrap();
    transmits(&mut m);
    m.ws_message(
        0,
        &ws_tunnel(
            id,
            &[Capsule::Error {
                code: error_code::TOO_MANY_TUNNELS,
                message: "too many".to_owned(),
            }],
        ),
    );
    assert!(events(&mut m).is_empty());
    m.ws_message(0, &wisp_wisp::encode_close(id, close_reason::THROTTLED));
    assert_eq!(
        events(&mut m),
        [MuxEvent::Closed {
            id,
            reason: close_reason::THROTTLED,
            error: Some((error_code::TOO_MANY_TUNNELS, "too many".to_owned())),
        }]
    );
}

#[test]
fn a_resume_token_rides_the_open() {
    let mut m = ws_ready();
    let id = m.open(true, false, Some([9; 32])).unwrap();
    let WispPacket::Tunnel(open) = ws(&transmits(&mut m)[0]) else {
        panic!()
    };
    assert_eq!(
        parse_capsules(&open.capsules).unwrap(),
        [
            Capsule::Open { want: want::IPV4 },
            Capsule::Resume { token: [9; 32] }
        ]
    );
    // ERROR 0x0004 inside the confirmation is informative (LS-5 finding 3).
    let mut caps = confirmation(false, 0, 30, 1);
    caps.push(Capsule::Error {
        code: error_code::RESUME_REJECTED,
        message: "resume token rejected; this is a new tunnel".to_owned(),
    });
    m.ws_message(0, &ws_tunnel(id, &caps));
    assert!(
        matches!(&events(&mut m)[..], [MuxEvent::Opened { capsules, .. }] if capsules.len() == 6)
    );
}

#[test]
fn bad_later_control_closes_the_tunnel() {
    let mut m = ws_ready();
    let id = m.open(true, false, None).unwrap();
    m.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 0, 0)));
    transmits(&mut m);
    events(&mut m);
    // An unknown capsule with bit 15 set is skipped.
    let mut body = vec![0x34, 0x92, 2, 0, 1, 2];
    m.ws_message(0, &wisp_wisp::encode_tunnel(id, &body));
    assert_eq!(
        events(&mut m),
        [MuxEvent::Control {
            id,
            capsules: vec![]
        }]
    );
    // One with bit 15 clear ends the tunnel with 0x41.
    body[1] = 0x12;
    m.ws_message(0, &wisp_wisp::encode_tunnel(id, &body));
    let t = transmits(&mut m);
    assert!(
        matches!(ws(&t[0]), WispPacket::Close(c) if c.stream_id == id && c.reason == close_reason::INVALID_INFO)
    );
    assert!(matches!(
        &events(&mut m)[..],
        [MuxEvent::Closed { reason: 0x41, .. }]
    ));
}

#[test]
fn webtransport_splits_to_the_live_datagram_limit() {
    // Chrome 154's maxDatagramSize: a fixed 1024.
    let mut m = wt_ready(true, 1024);
    let id = m.open(true, true, None).unwrap();
    let t = transmits(&mut m);
    let Transmit::WtControl(open) = &t[0] else {
        panic!()
    };
    assert_eq!(open[4], wisp_wire::frame_type::TUNNEL_OPEN);
    let frame = wisp_wire::parse_tunnel_payload(&open[5..]).unwrap();
    assert_eq!(frame.tunnel_id, id);
    assert_eq!(
        parse_capsules(&frame.capsules).unwrap(),
        [Capsule::Open {
            want: want::IPV4 | want::IPV6 | want::DATAGRAMS
        }]
    );
    // The relay takes 1194 bytes after the header (1200-byte datagrams).
    m.wt_control(
        0,
        &wt_tunnel(
            wisp_wire::frame_type::TUNNEL_OPENED,
            id,
            &confirmation(true, 1194, 30, 1),
        ),
    );
    assert!(matches!(&events(&mut m)[..], [MuxEvent::Opened { .. }]));
    assert_eq!(m.datagram_room(id), Some(1018));

    let mut server = Reassembler::new(1500);
    let mut check = |m: &mut Mux, packet: &[u8], limit: usize, pieces: usize| {
        assert!(m.send_packet(0, id, packet));
        let ds: Vec<Vec<u8>> = transmits(m)
            .into_iter()
            .map(|t| match t {
                Transmit::WtDatagram(d) => d,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(ds.len(), pieces);
        let mut whole = None;
        for d in &ds {
            assert!(d.len() <= limit, "{} > {limit}", d.len());
            assert_eq!(d[1], datagram_kind::IP);
            assert_eq!(u32::from_le_bytes([d[2], d[3], d[4], d[5]]), id);
            let (h, rest) = FragHeader::parse(&d[6..]).unwrap();
            if let Reassembled::Packet(p) = server.push(0, h, rest) {
                whole = Some(p);
            }
        }
        assert_eq!(whole.as_deref(), Some(packet));
        ds[0][0]
    };
    // LD2: a 1500-byte packet goes as two pieces.
    let full = udp4(CLIENT4, REMOTE4, 1472);
    assert_eq!(check(&mut m, &full, 1024, 2), datagram_class::NORMAL);
    // A TCP acknowledgement-sized packet rides the interactive class.
    assert_eq!(
        check(&mut m, &udp4(CLIENT4, REMOTE4, 12), 1024, 1),
        datagram_class::INTERACTIVE
    );
    // The limit is read at run time: a session that allows 1200 still
    // needs two, one that allows 600 needs three.
    m.set_max_datagram_size(1200);
    check(&mut m, &full, 1200, 2);
    m.set_max_datagram_size(600);
    check(&mut m, &full, 600, 3);
    // 1006 bytes fit one 1024-byte datagram whole: 6 + 1 + 1006 < 1024.
    m.set_max_datagram_size(1024);
    check(&mut m, &udp4(CLIENT4, REMOTE4, 1006 - 28), 1024, 1);
    assert_eq!(m.stats().split_out, 3);

    // Pieces from the relay, out of order, are put back together.
    let back = udp4(REMOTE4, CLIENT4, 1472);
    let pieces = frag::split(back.len(), 1194, 77).unwrap();
    for (h, r) in pieces.into_iter().rev() {
        let mut d = vec![datagram_class::NORMAL, datagram_kind::IP];
        d.extend_from_slice(&id.to_le_bytes());
        h.encode(&mut d);
        d.extend_from_slice(&back[r]);
        m.wt_datagram(5, &d);
    }
    assert_eq!(events(&mut m), [MuxEvent::Packet { id, packet: back }]);
    assert_eq!(m.stats().reassembled_in, 1);
}

#[test]
fn an_incomplete_packet_is_dropped_after_a_second() {
    let mut m = wt_ready(true, 1024);
    let id = m.open(true, false, None).unwrap();
    m.wt_control(
        0,
        &wt_tunnel(
            wisp_wire::frame_type::TUNNEL_OPENED,
            id,
            &confirmation(false, 1194, 0, 0),
        ),
    );
    events(&mut m);
    let back = udp4(REMOTE4, CLIENT4, 1472);
    let (h, r) = frag::split(back.len(), 1018, 1).unwrap().remove(0);
    let mut d = vec![1, datagram_kind::IP];
    d.extend_from_slice(&id.to_le_bytes());
    h.encode(&mut d);
    d.extend_from_slice(&back[r]);
    m.wt_datagram(100, &d);
    assert_eq!(m.poll_timeout(), Some(1100));
    m.handle_timeout(1100);
    assert_eq!(m.stats().dropped_in, 1);
    assert_eq!(m.poll_timeout(), None);
}

#[test]
fn without_datagrams_packets_ride_uni_streams_with_the_prelude_alone() {
    let mut m = wt_ready(false, 0);
    let id = m.open(true, false, None).unwrap();
    let t = transmits(&mut m);
    let Transmit::WtControl(open) = &t[0] else {
        panic!()
    };
    let frame = wisp_wire::parse_tunnel_payload(&open[5..]).unwrap();
    assert_eq!(
        parse_capsules(&frame.capsules).unwrap(),
        [Capsule::Open { want: want::IPV4 }]
    );
    m.wt_control(
        0,
        &wt_tunnel(
            wisp_wire::frame_type::TUNNEL_OPENED,
            id,
            &confirmation(false, 0, 0, 0),
        ),
    );
    assert!(matches!(&events(&mut m)[..], [MuxEvent::Opened { .. }]));
    // The stream opens at the confirmation, before any packet, with the
    // 4-byte prelude as a write of its own (LS-5 finding 1).
    assert_eq!(
        transmits(&mut m),
        [Transmit::WtUniOpen {
            tunnel_id: id,
            prelude: id.to_le_bytes()
        }]
    );
    // Packets right behind the prelude wait out the gap, so they cannot
    // share its QUIC packet.
    let p = udp4(CLIENT4, REMOTE4, 1472);
    assert!(m.send_packet(10, id, &p));
    assert!(transmits(&mut m).is_empty());
    assert_eq!(m.poll_timeout(), Some(UNI_PRELUDE_GAP_MS));
    m.handle_timeout(UNI_PRELUDE_GAP_MS);
    let Transmit::WtUniChunk { tunnel_id, chunk } = &transmits(&mut m)[0] else {
        panic!()
    };
    assert_eq!(*tunnel_id, id);
    assert_eq!(u16::from_le_bytes([chunk[0], chunk[1]]) as usize, p.len());
    assert_eq!(&chunk[2..], p.as_slice());
    // After the gap packets go at once.
    assert!(m.send_packet(UNI_PRELUDE_GAP_MS + 1, id, &p));
    assert!(matches!(
        &transmits(&mut m)[..],
        [Transmit::WtUniChunk { .. }]
    ));

    // The relay's stream: prelude, then chunks, cut anywhere.
    let back = udp4(REMOTE4, CLIENT4, 300);
    let mut stream = id.to_le_bytes().to_vec();
    for _ in 0..2 {
        stream.extend_from_slice(&(back.len() as u16).to_le_bytes());
        stream.extend_from_slice(&back);
    }
    for piece in stream.chunks(7) {
        m.wt_uni(42, piece);
    }
    let ev = events(&mut m);
    assert_eq!(ev.len(), 2);
    assert!(ev
        .iter()
        .all(|e| matches!(e, MuxEvent::Packet { packet, .. } if *packet == back)));

    // A stream that names no tunnel of ours is not read.
    m.wt_uni(43, &99u32.to_le_bytes());
    m.wt_uni(43, &[4, 0, 1, 2, 3, 4]);
    assert!(events(&mut m).is_empty());

    // Closing finishes the stream and sends TUNNEL_CLOSE.
    m.close(id, close_reason::VOLUNTARY);
    let t = transmits(&mut m);
    assert_eq!(t[0], Transmit::WtUniFinish { tunnel_id: id });
    let Transmit::WtControl(close) = &t[1] else {
        panic!()
    };
    assert_eq!(close[4], wisp_wire::frame_type::TUNNEL_CLOSE);
}

#[test]
fn a_session_close_frame_fails_the_connection() {
    let mut m = wt_ready(true, 1024);
    m.wt_control(0, &wisp_wire::encode_close_frame(0x02));
    assert!(matches!(
        &events(&mut m)[..],
        [MuxEvent::ConnectionFailed(_)]
    ));
    assert_eq!(transmits(&mut m), [Transmit::Close]);
}

#[test]
fn reconnecting_starts_from_nothing() {
    let mut m = ws_ready();
    let id = m.open(true, false, None).unwrap();
    m.ws_message(0, &ws_tunnel(id, &confirmation(false, 0, 0, 0)));
    m.disconnected();
    assert!(!m.is_ready());
    assert!(!m.send_packet(0, id, &udp4(CLIENT4, REMOTE4, 10)));
    assert!(m.open(true, false, None).is_none());
}

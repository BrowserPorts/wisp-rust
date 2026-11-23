//! IP tunnels on wisp-wt over real QUIC: the msquic listener and session
//! loop against a `web-transport-quinn` client, with the tunnel engine's
//! in-memory backend standing in for the tunnel's network. Covers the
//! extension's INFO entry, the four tunnel frames, `IP` datagrams with
//! fragments, and the uni-stream carriage.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wisp_config::{IpTunnelOptions, WispAuthRegistry, WispServerOptions, WispWtServerOptions};
use wisp_dos::{ConnectionLimiter, DosGuard};
use wisp_ip::capsule::want;
use wisp_ip::frag::{FragHeader, Reassembled, Reassembler, WHOLE};
use wisp_ip::{encode_capsules, parse_capsules, Capsule, ClientInfo, ServerInfo};
use wisp_iphash::IpHashBans;
use wisp_server::{serve, ServeExtras, ServeHandle};
use wisp_tun::icmp::build_udp;
use wisp_tun::memory::{MemoryBackend, MemoryNetwork};
use wisp_tun::{TunnelConfig, TunnelService};
use wisp_wire::{
    datagram_class, datagram_kind, decode_frame_body, encode_datagram, encode_info_frame,
    encode_tunnel_frame, frame_type, parse_extensions, parse_tunnel_payload, Extension,
    ExtensionEntry, IpTunnel,
};

const WT_PATH: &str = "/wisp-wt";
const STEP: Duration = Duration::from_secs(10);
const CLIENT: &str = "192.168.1.100";
const PUBLIC: &str = "93.184.216.34";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

struct Harness {
    _dir: tempfile::TempDir,
    handle: Option<ServeHandle>,
    addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    nets: mpsc::UnboundedReceiver<MemoryNetwork>,
}

impl Harness {
    async fn start() -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let dir = tempfile::tempdir().expect("temp dir");
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("self-signed certificate");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write cert");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let mut options = WispWtServerOptions {
            enabled: true,
            host: "127.0.0.1".to_owned(),
            port,
            cert_path: Some(cert_path.to_string_lossy().into_owned()),
            key_path: Some(key_path.to_string_lossy().into_owned()),
            ..WispWtServerOptions::default()
        };
        options.base.endpoint = WT_PATH.to_owned();
        options.base.block_blank_origins = false;
        options.base.auth.required = false;
        options.base.port_whitelist = Some(vec![443]);
        options.ip_tunnel = IpTunnelOptions {
            enabled: true,
            ..IpTunnelOptions::default()
        };
        let cfg = TunnelConfig::from_options(&options.ip_tunnel, &WispServerOptions::default())
            .expect("tunnel config");
        let (backend, nets) = MemoryBackend::new();
        let dos = Arc::new(DosGuard::new());
        let tunnels = TunnelService::new(cfg, backend, dos.clone());
        let handle = serve(
            Arc::new(options),
            dos,
            CancellationToken::new(),
            None,
            Arc::new(ConnectionLimiter::new()),
            WispAuthRegistry::default(),
            ServeExtras {
                proxy_template: None,
                ip_bans: Arc::new(IpHashBans::new()),
                tunnels: Some(tunnels),
            },
        )
        .await
        .expect("serve binds the loopback listener");
        Self {
            _dir: dir,
            handle: Some(handle),
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            cert: cert.der().clone(),
            nets,
        }
    }

    async fn session(&self) -> (quinn::Endpoint, web_transport_quinn::Session) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.clone()).expect("trust the test cert");
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        let connection = timeout(
            STEP,
            endpoint
                .connect(self.addr, "localhost")
                .expect("connect starts"),
        )
        .await
        .expect("QUIC handshake finishes")
        .expect("QUIC connection");
        let url = format!("https://localhost:{}{WT_PATH}", self.addr.port())
            .parse::<url::Url>()
            .unwrap();
        let session = timeout(STEP, web_transport_quinn::Session::connect(connection, url))
            .await
            .expect("the WT CONNECT is answered")
            .expect("the WT session is admitted");
        (endpoint, session)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

async fn read_exact(recv: &mut web_transport_quinn::RecvStream, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    timeout(STEP, recv.read_exact(&mut out))
        .await
        .expect("bytes arrive in time")
        .expect("stream delivers the bytes");
    out
}

/// One control frame: its type and payload.
async fn read_frame(recv: &mut web_transport_quinn::RecvStream) -> (u8, Bytes) {
    let len = u32::from_le_bytes(read_exact(recv, 4).await.try_into().unwrap()) as usize;
    let body = decode_frame_body(&read_exact(recv, len).await).expect("control frame");
    (body.frame_type, body.payload)
}

/// Runs the wisp-wt handshake offering IP_TUNNEL and returns the control
/// stream with the server's tunnel entry.
async fn handshake(
    session: &web_transport_quinn::Session,
) -> (
    web_transport_quinn::SendStream,
    web_transport_quinn::RecvStream,
    ServerInfo,
) {
    let (mut send, mut recv) = timeout(STEP, session.open_bi())
        .await
        .expect("open control")
        .expect("control bidi");
    let info = encode_info_frame(&[ExtensionEntry {
        id: IpTunnel::ID,
        payload: Bytes::from(
            ClientInfo {
                version: 1,
                flags: 0x3f,
            }
            .encode(),
        ),
    }]);
    send.write_all(&info).await.expect("send client INFO");
    let (ty, payload) = read_frame(&mut recv).await;
    assert_eq!(ty, frame_type::INFO);
    let server = parse_extensions(&payload)
        .unwrap()
        .into_iter()
        .find(|e| e.id == IpTunnel::ID)
        .expect("the server offers IP_TUNNEL");
    let server = ServerInfo::parse(&server.payload).expect("a WIPT entry");
    assert_eq!(read_frame(&mut recv).await.0, frame_type::READY);
    (send, recv, server)
}

async fn open_tunnel(
    send: &mut web_transport_quinn::SendStream,
    recv: &mut web_transport_quinn::RecvStream,
    tunnel_id: u32,
    wanted: u16,
) -> Vec<Capsule> {
    let open = encode_tunnel_frame(
        frame_type::TUNNEL_OPEN,
        tunnel_id,
        &encode_capsules(&[Capsule::Open { want: wanted }]),
    );
    send.write_all(&open).await.expect("send TUNNEL_OPEN");
    let (ty, payload) = read_frame(recv).await;
    assert_eq!(ty, frame_type::TUNNEL_OPENED);
    let opened = parse_tunnel_payload(&payload).unwrap();
    assert_eq!(opened.tunnel_id, tunnel_id);
    parse_capsules(&opened.capsules).unwrap()
}

async fn from_tunnel(net: &mut MemoryNetwork) -> Bytes {
    timeout(STEP, net.from_tunnel.recv())
        .await
        .expect("a packet reaches the tunnel's network")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_packets_ride_datagrams_with_fragments() {
    let mut harness = Harness::start().await;
    let (endpoint, session) = harness.session().await;
    let (mut send, mut recv, server) = handshake(&session).await;
    assert!(server.flags & wisp_ip::info::flags::DATAGRAMS != 0);
    let confirmation = open_tunnel(&mut send, &mut recv, 7, want::IPV4 | want::DATAGRAMS).await;
    assert!(confirmation
        .iter()
        .any(|c| matches!(c, Capsule::Link(l) if l.max_datagram_payload > 0)));
    let mut net = timeout(STEP, harness.nets.recv()).await.unwrap().unwrap();

    let packet = build_udp(ip(CLIENT), 4000, ip(PUBLIC), 443, b"over a datagram");
    let mut payload = vec![WHOLE];
    payload.extend_from_slice(&packet);
    session
        .send_datagram(encode_datagram(
            datagram_class::NORMAL,
            datagram_kind::IP,
            7,
            &payload,
        ))
        .expect("send IP datagram");
    assert_eq!(&from_tunnel(&mut net).await[..], &packet[..]);

    // A 1500-byte reply arrives in pieces that each fit Chrome's datagrams.
    let reply = build_udp(ip(PUBLIC), 443, ip(CLIENT), 4000, &[5u8; 1472]);
    net.to_tunnel
        .send(Bytes::from(reply.clone()))
        .await
        .unwrap();
    let mut reassembler = Reassembler::new(1500);
    let whole = loop {
        let d = timeout(STEP, session.read_datagram())
            .await
            .expect("a datagram arrives")
            .expect("datagram");
        assert!(d.len() <= 1200, "{} bytes", d.len());
        assert_eq!(d[1], datagram_kind::IP);
        assert_eq!(&d[2..6], &7u32.to_le_bytes());
        let (header, data) = FragHeader::parse(&d[6..]).unwrap();
        assert!(matches!(header, FragHeader::Piece { count: 2, .. }));
        if let Reassembled::Packet(p) = reassembler.push(0, header, data) {
            break p;
        }
    };
    assert_eq!(whole, reply);

    // TUNNEL_CLOSE from the client ends it.
    send.write_all(&wisp_wire::encode_tunnel_close_frame(7, 0x02))
        .await
        .unwrap();
    timeout(STEP, net.torn_down())
        .await
        .expect("the tunnel's network is torn down");
    session.close(0, b"done");
    drop(endpoint);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_packets_ride_uni_streams_without_datagrams() {
    let mut harness = Harness::start().await;
    let (endpoint, session) = harness.session().await;
    let (mut send, mut recv, _server) = handshake(&session).await;
    let confirmation = open_tunnel(&mut send, &mut recv, 3, want::IPV4).await;
    assert!(confirmation
        .iter()
        .any(|c| matches!(c, Capsule::Link(l) if l.max_datagram_payload == 0)));
    let mut net = timeout(STEP, harness.nets.recv()).await.unwrap().unwrap();

    let packet = build_udp(ip(CLIENT), 4001, ip(PUBLIC), 443, b"over a uni stream");
    let mut uni = timeout(STEP, session.open_uni())
        .await
        .unwrap()
        .expect("open uni");
    // The client opens its uni stream with the prelude alone and sends
    // packets after it. The pinned h3 parses a WebTransport uni stream's
    // session id only once more data arrives after the bytes holding it, so a
    // first packet sent together with the stream header would wait for the
    // next one.
    uni.write_all(&3u32.to_le_bytes())
        .await
        .expect("write prelude");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut chunk = (packet.len() as u16).to_le_bytes().to_vec();
    chunk.extend_from_slice(&packet);
    uni.write_all(&chunk).await.expect("write packet");
    assert_eq!(&from_tunnel(&mut net).await[..], &packet[..]);

    let reply = build_udp(ip(PUBLIC), 443, ip(CLIENT), 4001, &[6u8; 1472]);
    net.to_tunnel
        .send(Bytes::from(reply.clone()))
        .await
        .unwrap();
    let mut down = timeout(STEP, session.accept_uni())
        .await
        .expect("the server opens a uni stream")
        .expect("uni");
    assert_eq!(read_exact(&mut down, 4).await, 3u32.to_le_bytes());
    let len = u16::from_le_bytes(read_exact(&mut down, 2).await.try_into().unwrap());
    assert_eq!(usize::from(len), reply.len());
    assert_eq!(read_exact(&mut down, reply.len()).await, reply);
    session.close(0, b"done");
    drop(endpoint);
}

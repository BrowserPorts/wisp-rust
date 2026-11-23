//! The uplink client (`wisp-ip-client`) against the relay's WebTransport
//! binding over real QUIC: the msquic listener and session loop, a
//! `web-transport-quinn` session as the browser's WebTransport, and the
//! tunnel engine's in-memory backend as the tunnel's network. The client
//! sizes its datagrams to Chrome 154's `maxDatagramSize` of 1024, so a
//! 1500-byte packet goes as two pieces, and puts the relay's pieces back
//! together. Without datagrams it opens its uni stream with the prelude
//! alone at the confirmation (LS-5 finding 1).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wisp_config::{IpTunnelOptions, WispAuthRegistry, WispServerOptions, WispWtServerOptions};
use wisp_dos::{ConnectionLimiter, DosGuard};
use wisp_ip_client::ether::{self, ethertype};
use wisp_ip_client::{Carrier, Event, Output, Transmit, Uplink, UplinkConfig};
use wisp_iphash::IpHashBans;
use wisp_server::{serve, ServeExtras, ServeHandle};
use wisp_tun::icmp::build_udp;
use wisp_tun::memory::{MemoryBackend, MemoryNetwork};
use wisp_tun::{TunnelConfig, TunnelService};

const WT_PATH: &str = "/wisp-wt";
const STEP: Duration = Duration::from_secs(10);
const HOST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const PUBLIC: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
/// Chrome 154's `WebTransportDatagramDuplexStream.maxDatagramSize`.
const CHROME_MAX_DATAGRAM: usize = 1024;

struct Harness {
    _dir: tempfile::TempDir,
    handle: Option<ServeHandle>,
    addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    nets: mpsc::UnboundedReceiver<MemoryNetwork>,
}

impl Harness {
    async fn start() -> Self {
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

enum Inbound {
    Control(Vec<u8>),
    Datagram(Bytes),
    Uni(u64, Vec<u8>),
}

/// The browser's side: a WebTransport session that hands what it receives
/// to the uplink and sends what the uplink asks for.
struct Browser {
    session: web_transport_quinn::Session,
    control: web_transport_quinn::SendStream,
    inbound: mpsc::UnboundedReceiver<Inbound>,
    uni_out: HashMap<u32, web_transport_quinn::SendStream>,
    uplink: Uplink,
    epoch: Instant,
    wire: Vec<Vec<u8>>,
    events: Vec<Event>,
    datagram_sizes: Vec<usize>,
    uni_opens: Vec<u32>,
}

impl Browser {
    async fn connect(session: web_transport_quinn::Session, datagrams: bool) -> Self {
        let (control, mut recv) = timeout(STEP, session.open_bi())
            .await
            .expect("open control")
            .expect("control bidi");
        let (tx, inbound) = mpsc::unbounded_channel();
        let ctl_tx = tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok(Some(n)) = recv.read(&mut buf).await {
                if ctl_tx.send(Inbound::Control(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        });
        let dg = session.clone();
        let dg_tx = tx.clone();
        tokio::spawn(async move {
            while let Ok(d) = dg.read_datagram().await {
                if dg_tx.send(Inbound::Datagram(d)).is_err() {
                    break;
                }
            }
        });
        let unis = session.clone();
        tokio::spawn(async move {
            let mut next = 1u64;
            while let Ok(mut s) = unis.accept_uni().await {
                let id = next;
                next += 1;
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(Some(n)) = s.read(&mut buf).await {
                        if tx.send(Inbound::Uni(id, buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let mut cfg = UplinkConfig::default();
        cfg.wants.ipv6 = false;
        cfg.router.host_mac = Some(HOST_MAC);
        let mut b = Self {
            session,
            control,
            inbound,
            uni_out: HashMap::new(),
            uplink: Uplink::new(cfg),
            epoch: Instant::now(),
            wire: Vec::new(),
            events: Vec::new(),
            datagram_sizes: Vec::new(),
            uni_opens: Vec::new(),
        };
        let now = b.now();
        b.uplink.connected(
            now,
            Carrier::WebTransport {
                datagrams,
                max_datagram_size: if datagrams { CHROME_MAX_DATAGRAM } else { 0 },
            },
        );
        b.flush().await;
        b
    }

    fn now(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    async fn flush(&mut self) {
        while let Some(o) = self.uplink.poll_output() {
            match o {
                Output::Carrier(Transmit::WtControl(b)) => {
                    self.control.write_all(&b).await.expect("control write")
                }
                Output::Carrier(Transmit::WtDatagram(d)) => {
                    assert!(d.len() <= CHROME_MAX_DATAGRAM, "{} bytes", d.len());
                    self.datagram_sizes.push(d.len());
                    self.session
                        .send_datagram(Bytes::from(d))
                        .expect("send datagram");
                }
                Output::Carrier(Transmit::WtUniOpen { tunnel_id, prelude }) => {
                    let mut s = timeout(STEP, self.session.open_uni())
                        .await
                        .unwrap()
                        .expect("open uni");
                    s.write_all(&prelude).await.expect("prelude");
                    self.uni_opens.push(tunnel_id);
                    self.uni_out.insert(tunnel_id, s);
                }
                Output::Carrier(Transmit::WtUniChunk { tunnel_id, chunk }) => {
                    let s = self.uni_out.get_mut(&tunnel_id).expect("opened first");
                    s.write_all(&chunk).await.expect("chunk");
                }
                Output::Carrier(Transmit::WtUniFinish { tunnel_id }) => {
                    if let Some(mut s) = self.uni_out.remove(&tunnel_id) {
                        let _ = s.finish();
                    }
                }
                Output::Carrier(Transmit::Close) => self.session.close(0, b"done"),
                Output::Carrier(Transmit::Ws(_)) => panic!("WebSocket output on WebTransport"),
                Output::Wire(f) => self.wire.push(f),
                Output::Event(e) => self.events.push(e),
            }
        }
    }

    async fn run_until(&mut self, done: impl Fn(&Self) -> bool) {
        self.flush().await;
        while !done(self) {
            let msg = timeout(STEP, self.inbound.recv())
                .await
                .expect("the relay answers in time")
                .expect("the session is up");
            let now = self.now();
            match msg {
                Inbound::Control(b) => self.uplink.wt_control(now, &b),
                Inbound::Datagram(d) => self.uplink.wt_datagram(now, &d),
                Inbound::Uni(s, b) => self.uplink.wt_uni(now, s, &b),
            }
            self.flush().await;
        }
    }

    async fn frame(&mut self, packet: &[u8]) {
        let f = ether::build_frame(
            self.uplink.router().gateway_mac(),
            HOST_MAC,
            ethertype::IPV4,
            packet,
        );
        let now = self.now();
        self.uplink.wire_frame(now, &f);
        self.flush().await;
        // Timers due soon (a new uni stream's gap after its prelude) run
        // as the uplink Worker's would.
        while let Some(at) = self.uplink.poll_timeout() {
            let now = self.now();
            if at > now + 1_000 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(at.saturating_sub(now))).await;
            let now = self.now();
            self.uplink.handle_timeout(now);
            self.flush().await;
        }
    }
}

fn is_up(b: &Browser) -> bool {
    b.events.iter().any(|e| matches!(e, Event::LinkUp { .. }))
}

async fn from_tunnel(net: &mut MemoryNetwork) -> Bytes {
    timeout(STEP, net.from_tunnel.recv())
        .await
        .expect("a packet reaches the tunnel's network")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_uplink_splits_to_chromes_datagram_limit_and_reassembles() {
    let mut harness = Harness::start().await;
    let (endpoint, session) = harness.session().await;
    let mut b = Browser::connect(session, true).await;
    b.run_until(is_up).await;
    let cfg = b.uplink.config().unwrap().clone();
    assert!(cfg.link.max_datagram_payload > 0, "datagrams were granted");
    assert_eq!(
        b.uplink.mux().datagram_room(b.uplink.tunnel_id().unwrap()),
        Some(1018)
    );
    let mut net = timeout(STEP, harness.nets.recv()).await.unwrap().unwrap();

    // A full-size packet from the machine: two datagrams of at most 1024
    // bytes, put back together by the relay.
    let out = build_udp(CLIENT.into(), 4000, PUBLIC.into(), 443, &[3u8; 1472]);
    assert_eq!(out.len(), 1500);
    b.frame(&out).await;
    assert_eq!(b.datagram_sizes, [1024, 1500 - 1015 + 9]);
    assert_eq!(&from_tunnel(&mut net).await[..], &out[..]);

    // A small one rides one datagram.
    let small = build_udp(CLIENT.into(), 4000, PUBLIC.into(), 443, b"ack-sized");
    b.frame(&small).await;
    assert_eq!(&from_tunnel(&mut net).await[..], &small[..]);

    // The relay's full-size answer arrives in pieces and reaches the wire
    // whole.
    let reply = build_udp(PUBLIC.into(), 443, CLIENT.into(), 4000, &[5u8; 1472]);
    net.to_tunnel
        .send(Bytes::from(reply.clone()))
        .await
        .unwrap();
    b.run_until(|b| !b.wire.is_empty()).await;
    let f = ether::parse_frame(&b.wire[0]).unwrap();
    assert_eq!(f.dst, HOST_MAC);
    assert_eq!(f.payload, &reply[..]);
    assert_eq!(b.uplink.stats().mux.reassembled_in, 1);

    // Closing from the client tears the tunnel's network down.
    let now = b.now();
    b.uplink.close(now);
    b.flush().await;
    timeout(STEP, net.torn_down())
        .await
        .expect("the tunnel's network is torn down");
    drop(endpoint);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_datagrams_the_uplink_uses_uni_streams() {
    let mut harness = Harness::start().await;
    let (endpoint, session) = harness.session().await;
    let mut b = Browser::connect(session, false).await;
    b.run_until(is_up).await;
    let id = b.uplink.tunnel_id().unwrap();
    // The stream was opened at the confirmation, before any packet.
    assert_eq!(b.uni_opens, [id]);
    let mut net = timeout(STEP, harness.nets.recv()).await.unwrap().unwrap();

    // The first packet is not held back behind the stream header.
    let out = build_udp(CLIENT.into(), 4001, PUBLIC.into(), 443, &[4u8; 1472]);
    b.frame(&out).await;
    assert_eq!(&from_tunnel(&mut net).await[..], &out[..]);

    let reply = build_udp(PUBLIC.into(), 443, CLIENT.into(), 4001, &[6u8; 1200]);
    net.to_tunnel
        .send(Bytes::from(reply.clone()))
        .await
        .unwrap();
    b.run_until(|b| !b.wire.is_empty()).await;
    assert_eq!(ether::parse_frame(&b.wire[0]).unwrap().payload, &reply[..]);
    assert!(b.datagram_sizes.is_empty());
    drop(endpoint);
}

//! Live IP-hash bans over real QUIC.
//!
//! `ip_bans.rs` drives the policy without a connection. These tests start
//! [`wisp_server::serve`] on a loopback UDP port with a self-signed
//! certificate and connect with quinn, an independent QUIC stack: h3 drives
//! WS-over-H3, and `web-transport-quinn`, the client the proxy itself uses for
//! upstream sessions, drives WebTransport. The msquic listener, the h3 server
//! and both session paths therefore run for real. Each test checks that an
//! unbanned client is served end to end (Wisp data through to a local TCP echo
//! server), that a banned client is refused with a `WISP_IP_HASH_BANNED`
//! report, and that clearing the ban admits the next session again.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::ext::Protocol;
use http::{header, Method, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wisp_config::{WispAuthRegistry, WispWtServerOptions};
use wisp_dos::{ConnectionLimiter, DosGuard};
use wisp_iphash::{hash_client_ip, IpHashBans};
use wisp_reports::{set_report_hook, Report, ReportErrorType};
use wisp_server::{serve, H3WsContext, ServeExtras, ServeHandle};
use wisp_wire::{
    decode_frame_body, encode_info_frame, encode_tcp_stream_header, frame_type, Extension,
    ExtensionEntry, Udp,
};
use wisp_wisp::{encode_connect, encode_data, parse_packet, ConnectPacket, WispPacket};

const WS_PATH: &str = "/wisp-ws";
const WT_PATH: &str = "/wisp-wt";
const STEP: Duration = Duration::from_secs(10);

/// The report hook is process-wide, so the tests take turns.
static SERIAL: Mutex<()> = Mutex::const_new(());

struct Harness {
    _dir: tempfile::TempDir,
    handle: Option<ServeHandle>,
    addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    bans: Arc<IpHashBans>,
    echo_port: u16,
    reports: mpsc::UnboundedReceiver<Report>,
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind a probe socket")
        .local_addr()
        .expect("probe address")
        .port()
}

/// A TCP server that echoes every byte back, standing in for the destination
/// a Wisp client asks the proxy to reach.
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = listener.local_addr().expect("echo address").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
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

        let echo_port = spawn_echo().await;
        let port = free_udp_port();

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
        options.base.allow_direct_ip = true;
        options.base.allow_loopback_ips = true;
        options.base.port_whitelist = None;
        options.base.protocol_inspection = false;
        options.websocket.enabled = true;
        options.websocket.endpoint = Some(WS_PATH.to_owned());
        let options = Arc::new(options);

        // One ban set shared by both transports, the way the runtime wires it.
        let bans = Arc::new(IpHashBans::new());
        let dos = Arc::new(DosGuard::new());
        let limiter = Arc::new(ConnectionLimiter::new());
        let cancel = CancellationToken::new();
        let ws_ctx = H3WsContext::from_wisp_wt_with_template_and_auth(
            &options,
            None,
            WispAuthRegistry::default(),
            dos.clone(),
            limiter.clone(),
        )
        .with_ip_bans(bans.clone())
        .with_shutdown_token(cancel.clone());
        let handle = serve(
            options,
            dos,
            cancel,
            Some(Arc::new(ws_ctx)),
            limiter,
            WispAuthRegistry::default(),
            ServeExtras {
                proxy_template: None,
                ip_bans: bans.clone(),
            },
        )
        .await
        .expect("serve binds the loopback listener");

        let (tx, reports) = mpsc::unbounded_channel();
        set_report_hook(Some(Arc::new(move |report: &Report| {
            if report.error_type == ReportErrorType::IpHashBanned {
                let _ = tx.send(report.clone());
            }
        })));

        Self {
            _dir: dir,
            handle: Some(handle),
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            cert: cert.der().clone(),
            bans,
            echo_port,
            reports,
        }
    }

    fn loopback_hash() -> String {
        hash_client_ip(Some("127.0.0.1"), None).expect("loopback hashes")
    }

    fn ban(&self) {
        self.bans.replace([Self::loopback_hash()]);
    }

    fn unban(&self) {
        self.bans.replace(Vec::<String>::new());
    }

    /// A fresh QUIC connection from its own client socket, so every session is
    /// a new connection the server has to admit or refuse.
    async fn connect(&self) -> (quinn::Endpoint, quinn::Connection) {
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
        .expect("QUIC handshake succeeds");
        (endpoint, connection)
    }

    async fn expect_ban_report(&mut self) {
        let report = timeout(STEP, self.reports.recv())
            .await
            .expect("a ban report arrives")
            .expect("report channel open");
        assert_eq!(report.report_code, "WISP_IP_HASH_BANNED");
        assert_eq!(
            report.ip_hash.as_deref(),
            Some(Self::loopback_hash().as_str())
        );
    }

    fn assert_no_ban_report(&mut self) {
        assert!(
            self.reports.try_recv().is_err(),
            "an admitted session must not emit a ban report"
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        set_report_hook(None);
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

// WS-over-H3 client ---------------------------------------------------------

type H3Client = (
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    tokio::task::JoinHandle<()>,
);

async fn h3_client(connection: quinn::Connection) -> H3Client {
    let (mut driver, send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .expect("h3 client builds");
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    (send_request, driver)
}

fn extended_connect(path: &str, protocol: Protocol) -> Request<()> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost{path}"))
        .header(header::ORIGIN, "https://app.example")
        .extension(protocol)
        .body(())
        .expect("request")
}

/// RFC 6455 client frame: FIN set, masked, single fragment.
fn ws_client_frame(opcode: u8, payload: &[u8]) -> Bytes {
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut out = BytesMut::new();
    out.put_u8(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.put_u8(0x80 | n as u8),
        n if n <= u16::MAX as usize => {
            out.put_u8(0x80 | 126);
            out.put_u16(n as u16);
        }
        n => {
            out.put_u8(0x80 | 127);
            out.put_u64(n as u64);
        }
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out.freeze()
}

/// Incremental decoder for the unmasked frames the server sends.
#[derive(Default)]
struct ServerFrames(BytesMut);

impl ServerFrames {
    fn next(&mut self) -> Option<(u8, Bytes)> {
        let buf = &self.0;
        if buf.len() < 2 {
            return None;
        }
        let opcode = buf[0] & 0x0f;
        let (len, header) = match buf[1] & 0x7f {
            126 if buf.len() >= 4 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
            127 if buf.len() >= 10 => (
                u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize,
                10,
            ),
            126 | 127 => return None,
            n => (n as usize, 2),
        };
        if buf.len() < header + len {
            return None;
        }
        self.0.advance(header);
        Some((opcode, self.0.split_to(len).freeze()))
    }
}

/// Read server frames until a Wisp binary packet arrives.
async fn next_wisp_packet(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    frames: &mut ServerFrames,
) -> WispPacket {
    loop {
        while let Some((opcode, payload)) = frames.next() {
            if opcode == 0x2 {
                return parse_packet(payload).expect("well-formed Wisp packet");
            }
        }
        let chunk = timeout(STEP, stream.recv_data())
            .await
            .expect("server data arrives")
            .expect("stream open")
            .expect("server keeps the stream open");
        frames.0.extend_from_slice(chunk.chunk());
    }
}

enum Outcome {
    Served,
    Refused,
}

/// Open a WS-over-H3 session, and when it is admitted push `hello` through a
/// Wisp TCP stream to the echo server and read it back.
async fn ws_session(harness: &Harness) -> Outcome {
    let (endpoint, connection) = harness.connect().await;
    let (mut send_request, driver) = h3_client(connection.clone()).await;
    let mut stream = timeout(
        STEP,
        send_request.send_request(extended_connect(WS_PATH, Protocol::WEBSOCKET)),
    )
    .await
    .expect("request goes out")
    .expect("request stream opens");

    let response = match timeout(STEP, stream.recv_response()).await {
        Ok(Ok(response)) => response,
        // Closing the stream or the connection without a response is a refusal.
        Ok(Err(_)) => return finish_h3(endpoint, connection, driver, Outcome::Refused),
        Err(_) => panic!("neither a response nor a close arrived for the WS CONNECT"),
    };
    if response.status() != StatusCode::OK {
        return finish_h3(endpoint, connection, driver, Outcome::Refused);
    }

    let mut frames = ServerFrames::default();
    match next_wisp_packet(&mut stream, &mut frames).await {
        WispPacket::Continue(packet) => assert_eq!(packet.stream_id, 0),
        other => panic!("expected the initial CONTINUE, got {other:?}"),
    }
    let connect = ConnectPacket {
        stream_id: 1,
        stream_type: 1,
        port: harness.echo_port,
        hostname: "127.0.0.1".to_owned(),
    };
    stream
        .send_data(ws_client_frame(0x2, &encode_connect(&connect)))
        .await
        .expect("send CONNECT");
    stream
        .send_data(ws_client_frame(0x2, &encode_data(1, b"hello over ws")))
        .await
        .expect("send DATA");
    let mut echoed = Vec::new();
    while echoed.len() < b"hello over ws".len() {
        match next_wisp_packet(&mut stream, &mut frames).await {
            WispPacket::Data(data) if data.stream_id == 1 => {
                echoed.extend_from_slice(&data.payload)
            }
            WispPacket::Continue(_) => {}
            other => panic!("unexpected packet while waiting for the echo: {other:?}"),
        }
    }
    assert_eq!(echoed, b"hello over ws");
    let _ = stream
        .send_data(ws_client_frame(0x8, &1000u16.to_be_bytes()))
        .await;
    let _ = stream.finish().await;
    finish_h3(endpoint, connection, driver, Outcome::Served)
}

fn finish_h3(
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    driver: tokio::task::JoinHandle<()>,
    outcome: Outcome,
) -> Outcome {
    driver.abort();
    finish(endpoint, connection, outcome)
}

fn finish(endpoint: quinn::Endpoint, connection: quinn::Connection, outcome: Outcome) -> Outcome {
    connection.close(0u32.into(), b"done");
    drop(endpoint);
    outcome
}

// WebTransport client -------------------------------------------------------

async fn read_exact(recv: &mut web_transport_quinn::RecvStream, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    timeout(STEP, recv.read_exact(&mut out))
        .await
        .expect("bytes arrive in time")
        .expect("stream delivers the bytes");
    out
}

/// Read one length-prefixed wisp-wt control frame and return its type.
async fn read_control_frame(recv: &mut web_transport_quinn::RecvStream) -> u8 {
    let len = u32::from_le_bytes(read_exact(recv, 4).await.try_into().unwrap()) as usize;
    let body = read_exact(recv, len).await;
    decode_frame_body(&body).expect("control frame").frame_type
}

/// Open a WebTransport session with `web-transport-quinn`, the same client
/// the proxy uses for upstream sessions. When it is admitted, run the wisp-wt
/// control handshake and push `hello over wt` through a TCP stream to the echo
/// server.
async fn wt_session(harness: &Harness) -> Outcome {
    let (endpoint, connection) = harness.connect().await;
    let url = format!("https://localhost:{}{WT_PATH}", harness.addr.port())
        .parse::<url::Url>()
        .expect("session url");
    let session = match timeout(
        STEP,
        web_transport_quinn::Session::connect(connection.clone(), url),
    )
    .await
    {
        Ok(Ok(session)) => session,
        // A reset CONNECT stream or a non-200 status is a refusal.
        Ok(Err(_)) => return finish(endpoint, connection, Outcome::Refused),
        Err(_) => panic!("neither a session nor an error arrived for the WT CONNECT"),
    };

    // The first bidi is the wisp-wt control stream: INFO in, INFO and READY out.
    let (mut control_send, mut control_recv) = timeout(STEP, session.open_bi())
        .await
        .expect("open control")
        .expect("control bidi");
    let info = encode_info_frame(&[ExtensionEntry {
        id: Udp::ID,
        payload: Bytes::new(),
    }]);
    control_send
        .write_all(&info)
        .await
        .expect("send client INFO");
    assert_eq!(
        read_control_frame(&mut control_recv).await,
        frame_type::INFO
    );
    assert_eq!(
        read_control_frame(&mut control_recv).await,
        frame_type::READY
    );

    // A TCP stream to the echo server: header then raw bytes both ways.
    let (mut tcp_send, mut tcp_recv) = timeout(STEP, session.open_bi())
        .await
        .expect("open tcp")
        .expect("tcp bidi");
    let mut first = encode_tcp_stream_header("127.0.0.1", harness.echo_port, 0).to_vec();
    first.extend_from_slice(b"hello over wt");
    tcp_send
        .write_all(&first)
        .await
        .expect("send TCP header and data");
    let echoed = read_exact(&mut tcp_recv, b"hello over wt".len()).await;
    assert_eq!(echoed, b"hello over wt");

    let _ = tcp_send.finish();
    let _ = control_send.finish();
    session.close(0, b"done");
    finish(endpoint, connection, Outcome::Served)
}

// Tests ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_over_h3_serves_refuses_banned_client_and_serves_again_after_clearing() {
    let _turn = SERIAL.lock().await;
    let mut harness = Harness::start().await;

    assert!(matches!(ws_session(&harness).await, Outcome::Served));
    harness.assert_no_ban_report();

    harness.ban();
    assert!(matches!(ws_session(&harness).await, Outcome::Refused));
    harness.expect_ban_report().await;

    harness.unban();
    assert!(matches!(ws_session(&harness).await, Outcome::Served));
    harness.assert_no_ban_report();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_serves_refuses_banned_client_and_serves_again_after_clearing() {
    let _turn = SERIAL.lock().await;
    let mut harness = Harness::start().await;

    assert!(matches!(wt_session(&harness).await, Outcome::Served));
    harness.assert_no_ban_report();

    harness.ban();
    assert!(matches!(wt_session(&harness).await, Outcome::Refused));
    harness.expect_ban_report().await;

    harness.unban();
    assert!(matches!(wt_session(&harness).await, Outcome::Served));
    harness.assert_no_ban_report();
}

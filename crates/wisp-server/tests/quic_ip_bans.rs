//! Live IP-hash bans over real QUIC.
//!
//! `ip_bans.rs` drives the policy without a connection. These tests start
//! [`wisp_server::serve`] on a loopback UDP port with a self-signed
//! certificate and connect with quinn, an independent QUIC stack: h3 drives
//! WS-over-H3, and `web-transport-quinn`, the client the proxy itself uses for
//! upstream sessions, drives WebTransport. The msquic listener, the h3 server
//! and both session paths therefore run for real. WS-over-H3 also runs from an
//! msquic client built on [`MsQuicConnection::connect`], so the adapter's
//! outbound path carries a real h3 session too. Each test checks that an
//! unbanned client is served end to end (Wisp data through to a local TCP echo
//! server), that a banned client is refused with a `WISP_IP_HASH_BANNED`
//! report, and that clearing the ban admits the next session again. A banned
//! address is refused at the QUIC level, before its handshake, so the refusal
//! shows up as a failed connection.
//!
//! The same harness also covers the QUIC hardening that only a live
//! connection exercises: an oversized request header block, several
//! WS-over-H3 sessions on one connection, a TCP bridge finishing its stream at
//! upstream EOF, and destination policy on WebTransport TCP streams.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
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
use wisp_iphash::{hash_client_ip_keyed, IpHashBans};
use wisp_quic_msquic::adapter::MsQuicConnection;
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
        Self::start_with(|_| {}).await
    }

    /// Start with the defaults below, then let `configure` adjust them.
    async fn start_with(configure: impl FnOnce(&mut WispWtServerOptions)) -> Self {
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
        configure(&mut options);
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
        hash_client_ip_keyed(Some("127.0.0.1")).expect("loopback hashes")
    }

    fn ban(&self) {
        self.bans.replace([Self::loopback_hash()]);
    }

    fn unban(&self) {
        self.bans.replace(Vec::<String>::new());
    }

    /// A fresh QUIC connection from its own client socket, so every session is
    /// a new connection the server has to admit or refuse. `None` when the
    /// server refused the connection.
    async fn connect(&self) -> Option<(quinn::Endpoint, quinn::Connection)> {
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
        .ok()?;
        Some((endpoint, connection))
    }

    /// Like [`Harness::connect`], for a client that must be admitted.
    async fn connect_admitted(&self) -> (quinn::Endpoint, quinn::Connection) {
        self.connect()
            .await
            .expect("the server admits the QUIC connection")
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
async fn next_wisp_packet<S: h3::quic::BidiStream<Bytes>>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
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
    let Some((endpoint, connection)) = harness.connect().await else {
        return Outcome::Refused;
    };
    let (mut send_request, driver) = h3_client(connection.clone()).await;
    let mut stream = timeout(
        STEP,
        send_request.send_request(extended_connect(WS_PATH, Protocol::WEBSOCKET)),
    )
    .await
    .expect("request goes out")
    .expect("request stream opens");
    let outcome = ws_exchange(harness, &mut stream).await;
    finish_h3(endpoint, connection, driver, outcome)
}

/// Read the WS CONNECT response and, when it is admitted, run the Wisp echo
/// over the request stream. Shared by the quinn and msquic clients.
async fn ws_exchange<S: h3::quic::BidiStream<Bytes>>(
    harness: &Harness,
    stream: &mut h3::client::RequestStream<S, Bytes>,
) -> Outcome {
    let response = match timeout(STEP, stream.recv_response()).await {
        Ok(Ok(response)) => response,
        // Closing the stream or the connection without a response is a refusal.
        Ok(Err(_)) => return Outcome::Refused,
        Err(_) => panic!("neither a response nor a close arrived for the WS CONNECT"),
    };
    if response.status() != StatusCode::OK {
        return Outcome::Refused;
    }

    let mut frames = ServerFrames::default();
    match next_wisp_packet(stream, &mut frames).await {
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
        match next_wisp_packet(stream, &mut frames).await {
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
    Outcome::Served
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

// msquic WS-over-H3 client --------------------------------------------------

/// Client-side msquic handles. Field order is load-bearing, as in
/// `MsQuicEngine`: the configuration closes before the registration.
struct MsQuicClient {
    configuration: msquic::Configuration,
    registration: msquic::Registration,
}

impl MsQuicClient {
    fn new() -> Self {
        let registration = msquic::Registration::new(
            &msquic::RegistrationConfig::new().set_app_name("wisp-test-client".to_owned()),
        )
        .expect("client registration opens");
        // h3 needs room for the server's control and QPACK uni streams, and
        // h3-datagram expects datagrams to be negotiated.
        let settings = msquic::Settings::new()
            .set_PeerBidiStreamCount(16)
            .set_PeerUnidiStreamCount(16)
            .set_DatagramReceiveEnabled()
            .set_IdleTimeoutMs(STEP.as_millis() as u64);
        let alpn = [msquic::BufferRef::from("h3")];
        let configuration = msquic::Configuration::open(&registration, &alpn, Some(&settings))
            .expect("client configuration opens");
        configuration
            .load_credential(
                &msquic::CredentialConfig::new_client().set_credential_flags(
                    msquic::CredentialFlags::CLIENT
                        | msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION,
                ),
            )
            .expect("client credentials load");
        Self {
            configuration,
            registration,
        }
    }

    /// Close the handles off the runtime. `RegistrationClose` blocks until every
    /// connection opened under it is closed, so a connection the adapter leaks
    /// shows up here as a hang.
    async fn close(self) {
        timeout(STEP, tokio::task::spawn_blocking(move || drop(self)))
            .await
            .expect("every client connection closes, letting the registration close")
            .expect("close task");
    }
}

/// Open a WS-over-H3 session from an msquic client through
/// [`MsQuicConnection::connect`], the adapter's outbound path.
async fn msquic_ws_session(harness: &Harness, client: &MsQuicClient) -> Outcome {
    let connected = timeout(
        STEP,
        MsQuicConnection::connect(
            &client.registration,
            &client.configuration,
            "localhost",
            harness.addr,
        ),
    )
    .await
    .expect("msquic handshake finishes");
    // A refused connection never completes its handshake.
    let Ok(connection) = connected else {
        return Outcome::Refused;
    };
    let (mut driver, mut send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(connection)
        .await
        .expect("h3 client builds over msquic");
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let mut stream = timeout(
        STEP,
        send_request.send_request(extended_connect(WS_PATH, Protocol::WEBSOCKET)),
    )
    .await
    .expect("request goes out")
    .expect("request stream opens");
    let outcome = ws_exchange(harness, &mut stream).await;

    // Dropping the last request sender closes the connection with
    // H3_NO_ERROR, which in turn lets the driver finish.
    drop(stream);
    drop(send_request);
    timeout(STEP, driver)
        .await
        .expect("the h3 driver finishes once the connection closes")
        .expect("driver task");
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
    let Some((endpoint, connection)) = harness.connect().await else {
        return Outcome::Refused;
    };
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_over_h3_from_msquic_serves_refuses_banned_client_and_serves_again_after_clearing() {
    let _turn = SERIAL.lock().await;
    let mut harness = Harness::start().await;
    let client = MsQuicClient::new();

    assert!(matches!(
        msquic_ws_session(&harness, &client).await,
        Outcome::Served
    ));
    harness.assert_no_ban_report();

    harness.ban();
    assert!(matches!(
        msquic_ws_session(&harness, &client).await,
        Outcome::Refused
    ));
    harness.expect_ban_report().await;

    harness.unban();
    assert!(matches!(
        msquic_ws_session(&harness, &client).await,
        Outcome::Served
    ));
    harness.assert_no_ban_report();

    client.close().await;
}

// QUIC hardening ------------------------------------------------------------

/// QUIC variable-length integer (RFC 9000 section 16).
fn varint(value: u64) -> Vec<u8> {
    match value {
        0..=0x3f => vec![value as u8],
        0x40..=0x3fff => (value as u16 | 0x4000).to_be_bytes().to_vec(),
        0x4000..=0x3fff_ffff => (value as u32 | 0x8000_0000).to_be_bytes().to_vec(),
        _ => (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec(),
    }
}

/// An admitted WebTransport session that has finished the wisp-wt control
/// handshake. The control stream halves are kept so the session stays open.
struct WtClient {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    session: web_transport_quinn::Session,
    _control: (
        web_transport_quinn::SendStream,
        web_transport_quinn::RecvStream,
    ),
}

impl WtClient {
    async fn connect(harness: &Harness) -> Self {
        let (endpoint, connection) = harness.connect_admitted().await;
        let url = format!("https://localhost:{}{WT_PATH}", harness.addr.port())
            .parse::<url::Url>()
            .expect("session url");
        let session = timeout(
            STEP,
            web_transport_quinn::Session::connect(connection.clone(), url),
        )
        .await
        .expect("the WT CONNECT is answered")
        .expect("the WT session is admitted");
        let (mut control_send, mut control_recv) = timeout(STEP, session.open_bi())
            .await
            .expect("open control")
            .expect("control bidi");
        control_send
            .write_all(&encode_info_frame(&[]))
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
        Self {
            endpoint,
            connection,
            session,
            _control: (control_send, control_recv),
        }
    }

    /// Open a TCP stream to `port` on loopback, send `payload`, and read what
    /// comes back until the server ends the stream. `Err` when it was reset.
    async fn tcp_round_trip(
        &self,
        port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, web_transport_quinn::ReadToEndError> {
        let (mut send, mut recv) = timeout(STEP, self.session.open_bi())
            .await
            .expect("open tcp")
            .expect("tcp bidi");
        let mut first = encode_tcp_stream_header("127.0.0.1", port, 0).to_vec();
        first.extend_from_slice(payload);
        send.write_all(&first)
            .await
            .expect("send TCP header and data");
        // The client's send side stays open: the stream must end because the
        // server ended it.
        let read = timeout(STEP, recv.read_to_end(64 * 1024))
            .await
            .expect("the server ends the stream");
        drop(send);
        read
    }

    fn close(self) {
        self.session.close(0, b"done");
        finish(self.endpoint, self.connection, Outcome::Served);
    }
}

/// A TCP server that reads one chunk, answers `reply`, and closes.
async fn spawn_one_shot(reply: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind one-shot");
    let port = listener.local_addr().expect("one-shot address").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(reply).await;
            let _ = socket.shutdown().await;
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_request_header_block_is_refused_without_a_panic() {
    let _turn = SERIAL.lock().await;
    let harness = Harness::start().await;

    // A panic in a server task would only end that task here, where tests
    // unwind, but it aborts the production process. Count them.
    let panics = Arc::new(AtomicUsize::new(0));
    let previous_hook = std::panic::take_hook();
    let counted = panics.clone();
    std::panic::set_hook(Box::new(move |info| {
        counted.fetch_add(1, Ordering::SeqCst);
        eprintln!("panic: {info}");
    }));

    let (endpoint, connection) = harness.connect_admitted().await;
    let (mut send, mut recv) = timeout(STEP, connection.open_bi())
        .await
        .expect("open request stream")
        .expect("request stream");
    // QPACK prefix (no dynamic table) and then 30 000 copies of the static
    // `:method: GET` field line. Building an `http::HeaderMap` for more than
    // about 24 577 fields panics; the field-section limit refuses the block
    // long before that.
    let mut block = vec![0x00, 0x00];
    block.resize(2 + 30_000, 0xd1);
    let mut frame = vec![0x01];
    frame.extend_from_slice(&varint(block.len() as u64));
    frame.extend_from_slice(&block);
    send.write_all(&frame).await.expect("send HEADERS");
    let _ = send.finish();
    // The server answers 431 or resets the stream; either way it ends.
    let _ = timeout(STEP, recv.read_to_end(64 * 1024)).await;

    std::panic::set_hook(previous_hook);
    assert_eq!(
        panics.load(Ordering::SeqCst),
        0,
        "an oversized header block must not panic the server"
    );
    finish(endpoint, connection, Outcome::Served);
    assert!(matches!(ws_session(&harness).await, Outcome::Served));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_over_h3_serves_concurrent_sessions_on_one_connection() {
    let _turn = SERIAL.lock().await;
    let harness = Harness::start().await;
    let (endpoint, connection) = harness.connect_admitted().await;
    let (mut send_request, driver) = h3_client(connection.clone()).await;

    // Both CONNECTs are open before either session is used.
    let mut first = timeout(
        STEP,
        send_request.send_request(extended_connect(WS_PATH, Protocol::WEBSOCKET)),
    )
    .await
    .expect("first request goes out")
    .expect("first request stream opens");
    let mut second = timeout(
        STEP,
        send_request.send_request(extended_connect(WS_PATH, Protocol::WEBSOCKET)),
    )
    .await
    .expect("second request goes out")
    .expect("second request stream opens");
    assert!(matches!(
        ws_exchange(&harness, &mut second).await,
        Outcome::Served
    ));
    assert!(matches!(
        ws_exchange(&harness, &mut first).await,
        Outcome::Served
    ));
    finish_h3(endpoint, connection, driver, Outcome::Served);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_tcp_stream_finishes_when_the_upstream_closes() {
    let _turn = SERIAL.lock().await;
    let harness = Harness::start().await;
    let port = spawn_one_shot(b"bye").await;
    let client = WtClient::connect(&harness).await;

    let reply = client
        .tcp_round_trip(port, b"hi")
        .await
        .expect("a clean finish, not a reset");
    assert_eq!(reply, b"bye");
    client.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_tcp_streams_follow_destination_policy() {
    let _turn = SERIAL.lock().await;

    // A port outside the whitelist is refused before anything is dialed.
    let harness = Harness::start_with(|options| {
        options.base.port_whitelist = Some(vec![1]);
    })
    .await;
    let client = WtClient::connect(&harness).await;
    assert!(client
        .tcp_round_trip(harness.echo_port, b"blocked")
        .await
        .is_err());
    client.close();
    drop(harness);

    // So is every TCP stream when TCP streams are turned off.
    let harness = Harness::start_with(|options| {
        options.base.allow_tcp_streams = false;
    })
    .await;
    let client = WtClient::connect(&harness).await;
    assert!(client
        .tcp_round_trip(harness.echo_port, b"blocked")
        .await
        .is_err());
    client.close();
    drop(harness);

    // The default policy of this harness still bridges the same stream.
    let harness = Harness::start().await;
    let client = WtClient::connect(&harness).await;
    let port = spawn_one_shot(b"ok").await;
    assert_eq!(client.tcp_round_trip(port, b"hi").await.unwrap(), b"ok");
    client.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_handle_closes_from_a_blocking_thread() {
    let _turn = SERIAL.lock().await;
    let mut harness = Harness::start().await;
    assert!(matches!(ws_session(&harness).await, Outcome::Served));
    let handle = harness.handle.take().expect("serve handle");
    timeout(
        STEP,
        tokio::task::spawn_blocking(move || handle.close_blocking()),
    )
    .await
    .expect("msquic releases every handle")
    .expect("close task");
    drop(harness);

    // A new listener in the same process serves again. It takes a new port:
    // msquic in this build does not receive on a port reopened in-process,
    // with or without these changes.
    let harness = Harness::start().await;
    assert!(matches!(ws_session(&harness).await, Outcome::Served));
}

#[tokio::test(flavor = "current_thread")]
async fn serve_handle_drop_on_a_current_thread_runtime_does_not_hang() {
    let _turn = SERIAL.lock().await;
    let harness = Harness::start().await;
    // A live connection is what teardown has to wait for, and the tasks that
    // release it run on this thread.
    let (endpoint, connection) = harness.connect_admitted().await;
    drop(harness);
    finish(endpoint, connection, Outcome::Served);
}

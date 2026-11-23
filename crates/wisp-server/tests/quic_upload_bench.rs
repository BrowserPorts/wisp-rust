//! Upload throughput of WebTransport TCP streams through [`wisp_server::serve`],
//! for comparing builds. Ignored by default; run it in release:
//!
//! ```sh
//! cargo test --release -p wisp-server --test quic_upload_bench -- --ignored --nocapture
//! ```
//!
//! Each of `WT_BENCH_STREAMS` (10) streams writes `WT_BENCH_WRITE` (512) byte
//! chunks as fast as QUIC flow control allows to a local TCP sink, and the
//! bytes the sink receives over `WT_BENCH_SECS` (5) seconds, after one second
//! of warm-up, are reported. The client is quinn with `web-transport-quinn`,
//! as in `quic_ip_bans.rs`; on a loaded machine, differences under about 20 %
//! are noise.
//!
//! Client and server share the process, and QUIC packet I/O dominates: in a
//! November 2026 profile, UDP sends and receives took about 75 % of the CPU
//! and the bridge's upstream TCP writes about 18 %. msquic hands the bridge
//! one receive at a time, so a write carries about 2 KB, and merging the
//! receives already waiting (about 9 % of them) into vectored writes changed
//! neither throughput nor CPU per byte, so the bridge writes each receive as
//! it comes.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wisp_config::{WispAuthRegistry, WispWtServerOptions};
use wisp_dos::{ConnectionLimiter, DosGuard, UNLIMITED};
use wisp_iphash::IpHashBans;
use wisp_server::{serve, ServeExtras};
use wisp_wire::{decode_frame_body, encode_info_frame, encode_tcp_stream_header, frame_type};

const WT_PATH: &str = "/wisp-wt";
const STEP: Duration = Duration::from_secs(10);

fn env_or(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A TCP server that reads and discards everything, counting the bytes.
async fn spawn_sink(received: Arc<AtomicU64>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
    let port = listener.local_addr().expect("sink address").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let received = received.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    received.fetch_add(n as u64, Ordering::Relaxed);
                }
            });
        }
    });
    port
}

async fn read_control_frame(recv: &mut web_transport_quinn::RecvStream) -> u8 {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.expect("frame length");
    let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
    recv.read_exact(&mut body).await.expect("frame body");
    decode_frame_body(&body).expect("control frame").frame_type
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark; run with --ignored --nocapture"]
async fn webtransport_upload_throughput() {
    let streams = env_or("WT_BENCH_STREAMS", 10);
    let write = env_or("WT_BENCH_WRITE", 512);
    let secs = env_or("WT_BENCH_SECS", 5) as u64;

    let dir = tempfile::tempdir().expect("temp dir");
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

    let received = Arc::new(AtomicU64::new(0));
    let sink_port = spawn_sink(received.clone()).await;
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("free UDP port")
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
    options.base.allow_direct_ip = true;
    options.base.allow_loopback_ips = true;
    options.base.port_whitelist = None;
    options.base.protocol_inspection = false;
    options.base.max_tcp_bytes_per_connection_per_second = UNLIMITED;
    options.base.max_tcp_bytes_per_ip_per_second = UNLIMITED;
    let handle = serve(
        Arc::new(options),
        Arc::new(DosGuard::new()),
        CancellationToken::new(),
        None,
        Arc::new(ConnectionLimiter::new()),
        WispAuthRegistry::default(),
        ServeExtras {
            proxy_template: None,
            ip_bans: Arc::new(IpHashBans::new()),
            tunnels: None,
        },
    )
    .await
    .expect("serve binds");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).expect("trust the test cert");
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let connection = timeout(STEP, endpoint.connect(addr, "localhost").expect("connect"))
        .await
        .expect("handshake in time")
        .expect("handshake");
    let url = format!("https://localhost:{port}{WT_PATH}")
        .parse::<url::Url>()
        .expect("url");
    let session = timeout(
        STEP,
        web_transport_quinn::Session::connect(connection.clone(), url),
    )
    .await
    .expect("CONNECT answered")
    .expect("session admitted");
    let (mut control_send, mut control_recv) = session.open_bi().await.expect("control bidi");
    control_send
        .write_all(&encode_info_frame(&[]))
        .await
        .expect("client INFO");
    assert_eq!(
        read_control_frame(&mut control_recv).await,
        frame_type::INFO
    );
    assert_eq!(
        read_control_frame(&mut control_recv).await,
        frame_type::READY
    );

    let stop = CancellationToken::new();
    let mut writers = Vec::new();
    for _ in 0..streams {
        let (mut send, recv) = session.open_bi().await.expect("tcp bidi");
        send.write_all(&encode_tcp_stream_header("127.0.0.1", sink_port, 0))
            .await
            .expect("stream header");
        let stop = stop.clone();
        writers.push(tokio::spawn(async move {
            let _recv = recv;
            let chunk = vec![0x5au8; write];
            while !stop.is_cancelled() {
                if send.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        }));
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = received.load(Ordering::Relaxed);
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(secs)).await;
    let bytes = received.load(Ordering::Relaxed) - before;
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "wt upload s={streams} w={write}: {:.1} MiB/s",
        bytes as f64 / elapsed / 1_048_576.0
    );
    assert!(bytes > 0, "no bytes reached the sink");

    stop.cancel();
    for writer in writers {
        writer.abort();
    }
    session.close(0, b"done");
    connection.close(0u32.into(), b"done");
    drop(endpoint);
    handle.shutdown();
}

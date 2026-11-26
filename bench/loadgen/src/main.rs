//! Wisp v1 load generator with its own TCP echo server, for measuring wispd
//! without the external wispmark harness.
//!
//! ```text
//! wisp-loadgen <mode> <ws_port> <echo_port> <conns> <streams> <payload> <secs>
//! ```
//!
//! It starts an echo server on `echo_port`, opens `conns` WebSocket
//! connections to `ws://127.0.0.1:<ws_port>/`, and on each runs `streams`
//! streams to the echo server. After one second of warm-up it measures for
//! `secs` seconds and prints one result line. The server must allow loopback
//! destinations and `echo_port`, as `configs/wispd.test.toml` does.
//!
//! Modes:
//! - `bulk`: each stream uploads `payload`-byte packets as fast as its credit
//!   allows. Reports echoed bytes per second.
//! - `rr`: each stream sends one `payload`-byte request and waits for it to
//!   come back before the next. Reports round trips per second and latency.
//! - `churn`: as `rr`, but every round trip uses a new stream. The echo
//!   server closes its end after echoing one payload, so wispd's upstream
//!   socket is closed by its peer and leaves no TIME_WAIT behind. When the
//!   client closed each stream instead, wispd closed first and every stream
//!   parked an ephemeral port in TIME_WAIT; at a few thousand streams a second
//!   that ran out of ports ("Can't assign requested address").
//! - `churn-client-close`: as `churn`, but the client closes each stream once
//!   its echo is back, as a browser closing a finished request does. wispd
//!   then closes its upstream socket first, so every stream holds an
//!   ephemeral port in TIME_WAIT for twice the MSL. This mode measures how
//!   long the port range lasts; `bench/port-range.sh` widens it.
use bytes::{BufMut, BytesMut};
use futures::{FutureExt, SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_websockets::{ClientBuilder, Message, WebSocketStream};

static BYTES: AtomicU64 = AtomicU64::new(0);
static OPS: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);

const PACKET_DATA: u8 = 0x02;
const PACKET_CONTINUE: u8 = 0x03;
const PACKET_CLOSE: u8 = 0x04;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Bulk,
    RoundTrip,
    Churn,
    ChurnClientClose,
}

impl Mode {
    fn churns(self) -> bool {
        matches!(self, Mode::Churn | Mode::ChurnClientClose)
    }
}

fn connect(id: u32, port: u16) -> Message {
    let mut b = BytesMut::with_capacity(32);
    b.put_u8(0x01);
    b.put_u32_le(id);
    b.put_u8(0x01); // TCP
    b.put_u16_le(port);
    b.extend_from_slice(b"127.0.0.1");
    Message::binary(b.freeze())
}

fn data(id: u32, payload: &[u8]) -> Message {
    let mut b = BytesMut::with_capacity(5 + payload.len());
    b.put_u8(PACKET_DATA);
    b.put_u32_le(id);
    b.extend_from_slice(payload);
    Message::binary(b.freeze())
}

/// Packet type and stream id.
fn head(p: &[u8]) -> (u8, u32) {
    (p[0], u32::from_le_bytes([p[1], p[2], p[3], p[4]]))
}

fn close(id: u32) -> Message {
    let mut b = BytesMut::with_capacity(6);
    b.put_u8(PACKET_CLOSE);
    b.put_u32_le(id);
    b.put_u8(0x02); // voluntary
    Message::binary(b.freeze())
}

fn continue_credit(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[5], p[6], p[7], p[8]])
}

/// Echoes every connection. With `close_after`, a connection is closed once
/// that many bytes have been echoed.
async fn echo(listener: TcpListener, close_after: Option<usize>) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            continue;
        };
        let _ = s.set_nodelay(true);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 256 * 1024];
            let mut echoed = 0;
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        echoed += n;
                        if close_after.is_some_and(|limit| echoed >= limit) {
                            let _ = s.shutdown().await;
                            break;
                        }
                    }
                }
            }
        });
    }
}

async fn ws(port: u16) -> WebSocketStream<TcpStream> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to wispd");
    tcp.set_nodelay(true).unwrap();
    let uri: http::Uri = format!("ws://127.0.0.1:{port}/").parse().unwrap();
    let (ws, _) = ClientBuilder::from_uri(uri)
        .connect_on(tcp)
        .await
        .expect("WebSocket handshake");
    ws
}

async fn bulk(port: u16, echo_port: u16, streams: u32, payload: usize) {
    let (mut tx, mut rx) = ws(port).await.split();
    let credit: Arc<Vec<AtomicU32>> = Arc::new((0..=streams).map(|_| AtomicU32::new(0)).collect());
    let notify = Arc::new(Notify::new());
    let (reader_credit, reader_notify) = (credit.clone(), notify.clone());
    tokio::spawn(async move {
        while let Some(Ok(m)) = rx.next().await {
            if !m.is_binary() {
                continue;
            }
            let p = m.as_payload();
            match head(p) {
                (PACKET_DATA, _) => {
                    BYTES.fetch_add((p.len() - 5) as u64, Relaxed);
                }
                (PACKET_CONTINUE, 0) => {
                    let n = continue_credit(p);
                    for c in reader_credit.iter() {
                        c.store(n, Relaxed);
                    }
                    reader_notify.notify_one();
                }
                (PACKET_CONTINUE, id) => {
                    reader_credit[id as usize].store(continue_credit(p), Relaxed);
                    reader_notify.notify_one();
                }
                (PACKET_CLOSE, _) => {
                    ERRORS.fetch_add(1, Relaxed);
                }
                _ => {}
            }
        }
    });
    notify.notified().await;
    for id in 1..=streams {
        tx.feed(connect(id, echo_port)).await.unwrap();
    }
    let body = vec![0x5au8; payload];
    loop {
        let mut sent = false;
        for id in 1..=streams {
            let c = &credit[id as usize];
            if c.load(Relaxed) > 0 {
                c.fetch_sub(1, Relaxed);
                if tx.feed(data(id, &body)).await.is_err() {
                    return;
                }
                sent = true;
            }
        }
        if tx.flush().await.is_err() {
            return;
        }
        if !sent {
            notify.notified().await;
        }
    }
}

struct RoundTrip {
    received: usize,
    started: Instant,
    credit: u32,
    waiting_for_credit: bool,
}

async fn round_trips(
    port: u16,
    echo_port: u16,
    streams: u32,
    payload: usize,
    mode: Mode,
    latencies: Arc<Mutex<Vec<u32>>>,
) {
    let mut w = ws(port).await;
    let body = vec![0x5au8; payload];
    let mut live: HashMap<u32, RoundTrip> = HashMap::new();
    let mut next_id = 1u32;
    let mut local: Vec<u32> = Vec::with_capacity(1 << 16);
    let mut window = 0u32;
    let mut out: Vec<Message> = Vec::new();
    let mut open = |live: &mut HashMap<u32, RoundTrip>, out: &mut Vec<Message>, window: u32| {
        let id = next_id;
        next_id += 1;
        out.push(connect(id, echo_port));
        out.push(data(id, &body));
        live.insert(
            id,
            RoundTrip {
                received: 0,
                started: Instant::now(),
                credit: window - 1,
                waiting_for_credit: false,
            },
        );
    };
    loop {
        let Some(Ok(m)) = w.next().await else { break };
        let mut current = Some(m);
        // Handle everything already received, then flush once.
        while let Some(m) = current.take() {
            if m.is_binary() {
                let p = m.as_payload();
                match head(p) {
                    (PACKET_CONTINUE, 0) => {
                        window = continue_credit(p);
                        for _ in 0..streams {
                            open(&mut live, &mut out, window);
                        }
                    }
                    (PACKET_CONTINUE, id) => {
                        if let Some(s) = live.get_mut(&id) {
                            s.credit = continue_credit(p);
                            if s.waiting_for_credit {
                                s.waiting_for_credit = false;
                                s.credit -= 1;
                                s.started = Instant::now();
                                out.push(data(id, &body));
                            }
                        }
                    }
                    (PACKET_DATA, id) => {
                        let mut finished = false;
                        if let Some(s) = live.get_mut(&id) {
                            s.received += p.len() - 5;
                            if s.received >= payload {
                                s.received = 0;
                                local.push(s.started.elapsed().as_micros() as u32);
                                OPS.fetch_add(1, Relaxed);
                                BYTES.fetch_add(payload as u64, Relaxed);
                                if mode.churns() {
                                    finished = true;
                                } else if s.credit > 0 {
                                    s.credit -= 1;
                                    s.started = Instant::now();
                                    out.push(data(id, &body));
                                } else {
                                    s.waiting_for_credit = true;
                                }
                            }
                        }
                        if finished {
                            // In `churn` the echo server closes the stream,
                            // and its CLOSE arrives after it is forgotten.
                            live.remove(&id);
                            if mode == Mode::ChurnClientClose {
                                out.push(close(id));
                            }
                            open(&mut live, &mut out, window);
                        }
                    }
                    (PACKET_CLOSE, id) => {
                        // Only a stream still waiting on its echo was cut.
                        if live.remove(&id).is_some() {
                            ERRORS.fetch_add(1, Relaxed);
                            if mode.churns() {
                                open(&mut live, &mut out, window);
                            }
                        }
                    }
                    _ => {}
                }
            }
            current = match w.next().now_or_never() {
                Some(Some(Ok(m))) => Some(m),
                _ => None,
            };
        }
        for m in out.drain(..) {
            if w.feed(m).await.is_err() {
                return;
            }
        }
        if w.flush().await.is_err() {
            return;
        }
        if local.len() >= 4096 {
            latencies.lock().unwrap().append(&mut local);
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: wisp-loadgen <bulk|rr|churn|churn-client-close> <ws_port> <echo_port> <conns> <streams> <payload> <secs>"
    );
    std::process::exit(2);
}

fn arg<T: std::str::FromStr>(args: &[String], index: usize) -> T {
    args.get(index)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| usage())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = match args.get(1).map(String::as_str) {
        Some("bulk") => Mode::Bulk,
        Some("rr") => Mode::RoundTrip,
        Some("churn") => Mode::Churn,
        Some("churn-client-close") => Mode::ChurnClientClose,
        _ => usage(),
    };
    let port: u16 = arg(&args, 2);
    let echo_port: u16 = arg(&args, 3);
    let conns: u32 = arg(&args, 4);
    let streams: u32 = arg(&args, 5);
    let payload: usize = arg(&args, 6);
    let secs: u64 = arg(&args, 7);
    if payload == 0 {
        usage();
    }

    let listener = TcpListener::bind(("127.0.0.1", echo_port))
        .await
        .expect("bind the echo port");
    let close_after = (mode == Mode::Churn).then_some(payload);
    tokio::spawn(echo(listener, close_after));

    let latencies = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..conns {
        let latencies = latencies.clone();
        match mode {
            Mode::Bulk => drop(tokio::spawn(bulk(port, echo_port, streams, payload))),
            Mode::RoundTrip | Mode::Churn | Mode::ChurnClientClose => drop(tokio::spawn(
                round_trips(port, echo_port, streams, payload, mode, latencies),
            )),
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await; // warm-up
    latencies.lock().unwrap().clear();
    let (bytes0, ops0, errors0) = (BYTES.load(Relaxed), OPS.load(Relaxed), ERRORS.load(Relaxed));
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(secs)).await;
    let elapsed = started.elapsed().as_secs_f64();
    let bytes = BYTES.load(Relaxed) - bytes0;
    let ops = OPS.load(Relaxed) - ops0;
    let errors = ERRORS.load(Relaxed) - errors0;
    let mut sorted = std::mem::take(&mut *latencies.lock().unwrap());
    sorted.sort_unstable();
    let percentile = |p: f64| {
        if sorted.is_empty() {
            0
        } else {
            sorted[((sorted.len() - 1) as f64 * p) as usize]
        }
    };
    let name = args[1].as_str();
    println!(
        "{name} c={conns} s={streams} p={payload}: {:.1} MiB/s {:.0} ops/s p50={}us p99={}us errors={errors}",
        bytes as f64 / elapsed / 1_048_576.0,
        ops as f64 / elapsed,
        percentile(0.5),
        percentile(0.99),
    );
    std::process::exit(0);
}

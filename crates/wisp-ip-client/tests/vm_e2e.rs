//! End to end on Linux: a real `wispd` with IP tunnels, a machine whose
//! kernel is a network namespace behind a TAP device, and this crate's
//! [`Uplink`] between the two, over Wisp v2 on a WebSocket.
//!
//! The machine namespace stands in for the netkernel: it is a Linux 6.12
//! network stack with an Ethernet `eth0`, configured only through the
//! manager's netlink messages, and the TAP device's frames are what the
//! wire device's frame ring carries. A stand-in internet namespace
//! (`ls6-inet`, 192.88.99.2) holds a web server, a TCP echo and a UDP echo;
//! wispd's per-tunnel namespace routes to it with NAT.
//!
//! Ignored by default. It needs root (namespaces, TAP, wispd's tunnel
//! engine) and a wispd built with the `ws` feature:
//!
//! ```text
//! cargo test -p wisp-ip-client --test vm_e2e --no-run
//! sudo WISPD_BIN=/path/to/wispd target/debug/deps/vm_e2e-<hash> \
//!     --ignored --test-threads=1 --nocapture
//! ```

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use tokio_websockets::{ClientBuilder, Message};
use wisp_ip_client::manager::{ConfigPlan, InterfaceSpec, LinkConfig, MachineManager};
use wisp_ip_client::netlink::parse_ack;
use wisp_ip_client::{Carrier, Event, Output, Transmit, Uplink, UplinkConfig};

const INET_NS: &str = "ls6-inet";
const MACHINE_NS: &str = "ls6-m";
const TUNNEL_PREFIX: &str = "ls6t";
const SERVER: Ipv4Addr = Ipv4Addr::new(192, 88, 99, 2);
const WS_PORT: u16 = 6101;
const HOST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x4c, 0x53, 0x36];
const HTTP_BODY: usize = 256 * 1024;

// ---- shell and namespaces -----------------------------------------------------

fn sh(args: &[&str]) {
    let ok = Command::new(args[0])
        .args(&args[1..])
        .status()
        .expect("spawn")
        .success();
    assert!(ok, "{args:?} failed");
}

fn sh_quiet(args: &[&str]) {
    let _ = Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn output(args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .expect("spawn");
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

fn log(step: &str) {
    println!("[vm_e2e {:>8.3}] {step}", epoch().elapsed().as_secs_f64());
}

fn epoch() -> Instant {
    use std::sync::OnceLock;
    static T: OnceLock<Instant> = OnceLock::new();
    *T.get_or_init(Instant::now)
}

fn enter_netns(name: &str) {
    let f = std::fs::File::open(format!("/run/netns/{name}")).expect("netns file");
    // SAFETY: setns on an open namespace descriptor changes only this thread.
    assert_eq!(unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) }, 0);
}

/// Runs `f` on a fresh thread inside namespace `ns`.
fn in_ns<T: Send + 'static>(ns: &'static str, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(move || {
        enter_netns(ns);
        f()
    })
    .join()
    .expect("namespace thread")
}

fn http_body() -> Vec<u8> {
    (0..HTTP_BODY).map(|i| (i * 7 % 251) as u8).collect()
}

/// The stand-in internet: 192.88.99.2 and 3fff:99::2 behind a veth, with
/// three dual-stack servers. 3fff::/20 is the IPv6 documentation prefix of
/// RFC 9637, which the relay's policy, unlike 2001:db8::/32, treats as
/// global; nothing here routes it outside the VM.
struct Inet;

impl Inet {
    fn up() -> Self {
        sh_quiet(&["ip", "netns", "del", INET_NS]);
        sh_quiet(&["ip", "link", "del", "ls6i0"]);
        sh(&["ip", "netns", "add", INET_NS]);
        sh(&[
            "ip", "link", "add", "ls6i0", "type", "veth", "peer", "name", "eth0", "netns", INET_NS,
        ]);
        sh(&["ip", "addr", "add", "192.88.99.1/24", "dev", "ls6i0"]);
        sh(&["ip", "link", "set", "ls6i0", "up"]);
        sh(&[
            "ip",
            "-6",
            "addr",
            "add",
            "3fff:99::1/64",
            "dev",
            "ls6i0",
            "nodad",
        ]);
        sh(&[
            "ip",
            "-n",
            INET_NS,
            "-6",
            "addr",
            "add",
            "3fff:99::2/64",
            "dev",
            "eth0",
            "nodad",
        ]);
        sh(&[
            "ip",
            "-n",
            INET_NS,
            "addr",
            "add",
            "192.88.99.2/24",
            "dev",
            "eth0",
        ]);
        sh(&["ip", "-n", INET_NS, "link", "set", "eth0", "up"]);
        sh(&["ip", "-n", INET_NS, "link", "set", "lo", "up"]);
        sh(&[
            "ip",
            "-n",
            INET_NS,
            "route",
            "add",
            "default",
            "via",
            "192.88.99.1",
        ]);
        sh(&[
            "ip",
            "-n",
            INET_NS,
            "-6",
            "route",
            "add",
            "default",
            "via",
            "3fff:99::1",
        ]);
        let (tx, rx) = std::sync::mpsc::channel();
        for which in 0..3 {
            let tx = tx.clone();
            std::thread::spawn(move || {
                enter_netns(INET_NS);
                match which {
                    0 => {
                        let l = TcpListener::bind("[::]:8080").expect("bind http");
                        tx.send(()).unwrap();
                        for mut s in l.incoming().flatten() {
                            std::thread::spawn(move || {
                                let mut req = Vec::new();
                                let mut buf = [0u8; 1024];
                                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                                    match s.read(&mut buf) {
                                        Ok(0) | Err(_) => return,
                                        Ok(n) => req.extend_from_slice(&buf[..n]),
                                    }
                                }
                                let body = http_body();
                                let head = format!(
                                    "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                                    body.len()
                                );
                                let _ = s.write_all(head.as_bytes());
                                let _ = s.write_all(&body);
                            });
                        }
                    }
                    1 => {
                        let l = TcpListener::bind("[::]:8081").expect("bind echo");
                        tx.send(()).unwrap();
                        for mut s in l.incoming().flatten() {
                            std::thread::spawn(move || {
                                let mut buf = [0u8; 4096];
                                while let Ok(n) = s.read(&mut buf) {
                                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                                        return;
                                    }
                                }
                            });
                        }
                    }
                    _ => {
                        let u = UdpSocket::bind("[::]:7").expect("bind udp echo");
                        tx.send(()).unwrap();
                        let mut buf = [0u8; 2048];
                        while let Ok((n, from)) = u.recv_from(&mut buf) {
                            let _ = u.send_to(&buf[..n], from);
                        }
                    }
                }
            });
        }
        for _ in 0..3 {
            rx.recv().unwrap();
        }
        Inet
    }
}

impl Drop for Inet {
    fn drop(&mut self) {
        sh_quiet(&["ip", "netns", "del", INET_NS]);
        sh_quiet(&["ip", "link", "del", "ls6i0"]);
    }
}

/// What a wispd that exits on a signal leaves behind: it parks its tunnels
/// for resume and exits without removing their namespaces (the next start
/// removes stale ones). Removed before and after the test.
struct Leftovers;

impl Leftovers {
    fn sweep() {
        for line in output(&["ip", "netns", "list"]).lines() {
            if let Some(name) = line.split_whitespace().next() {
                if name.starts_with(TUNNEL_PREFIX) {
                    sh_quiet(&["ip", "netns", "del", name]);
                }
            }
        }
        for line in output(&["ip", "-br", "link"]).lines() {
            if let Some(name) = line.split_whitespace().next() {
                let name = name.split('@').next().unwrap_or(name);
                if name.starts_with("wtv") {
                    sh_quiet(&["ip", "link", "del", name]);
                }
            }
        }
        sh_quiet(&["nft", "delete", "table", "inet", "wisp_tun"]);
    }
}

impl Drop for Leftovers {
    fn drop(&mut self) {
        Leftovers::sweep();
    }
}

// ---- the machine ------------------------------------------------------------

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

/// The machine: a namespace whose `eth0` is a TAP device this process holds.
struct Machine {
    tap: OwnedFd,
    ifindex: u32,
}

impl Machine {
    fn up() -> Self {
        sh_quiet(&["ip", "netns", "del", MACHINE_NS]);
        sh(&["ip", "netns", "add", MACHINE_NS]);
        sh(&["ip", "-n", MACHINE_NS, "link", "set", "lo", "up"]);
        let (fd, ifindex) = in_ns(MACHINE_NS, || {
            // SAFETY: plain open/ioctl on /dev/net/tun with a correctly
            // sized, NUL-terminated ifreq; the descriptor is owned below.
            unsafe {
                let fd = libc::open(
                    c"/dev/net/tun".as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                );
                assert!(fd >= 0, "open /dev/net/tun");
                let mut ifr = [0u8; 40];
                ifr[..4].copy_from_slice(b"eth0");
                ifr[16..18].copy_from_slice(&(IFF_TAP | IFF_NO_PI).to_ne_bytes());
                assert_eq!(libc::ioctl(fd, TUNSETIFF, ifr.as_mut_ptr()), 0, "TUNSETIFF");
                let index = libc::if_nametoindex(c"eth0".as_ptr());
                assert!(index > 0);
                (fd, index)
            }
        });
        // SAFETY: `fd` was just opened and is owned by nothing else.
        let tap = unsafe { OwnedFd::from_raw_fd(fd) };
        Machine { tap, ifindex }
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        sh_quiet(&["ip", "netns", "del", MACHINE_NS]);
    }
}

/// The machine manager on the machine namespace: the plan's netlink
/// messages go to its kernel exactly as encoded, on a NETLINK_ROUTE socket.
struct NamespaceManager {
    iface: InterfaceSpec,
    current: Option<LinkConfig>,
    seq: u32,
    log: Vec<String>,
}

impl MachineManager for NamespaceManager {
    type Error = String;

    fn interface(&self) -> &InterfaceSpec {
        &self.iface
    }

    fn current(&self) -> Option<&LinkConfig> {
        self.current.as_ref()
    }

    fn set_current(&mut self, config: Option<LinkConfig>) {
        self.current = config;
    }

    fn execute(&mut self, plan: &ConfigPlan) -> Result<(), String> {
        let ops: Vec<(String, Vec<u8>, u32)> = plan
            .netlink
            .iter()
            .map(|op| {
                self.seq += 1;
                (op.to_string(), op.encode(self.seq), self.seq)
            })
            .collect();
        let sysctl = plan.sysctl.clone();
        let results = in_ns(MACHINE_NS, move || {
            let mut out = Vec::new();
            // SAFETY: a netlink socket used with correctly sized buffers.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                )
            };
            assert!(fd >= 0, "netlink socket");
            for (line, msg, seq) in ops {
                let sent = unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) };
                assert_eq!(sent as usize, msg.len(), "send {line}");
                let mut buf = vec![0u8; 8192];
                let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
                assert!(n > 0, "recv ack for {line}");
                let ack = parse_ack(&buf[..n as usize], seq);
                out.push((line, ack));
            }
            unsafe { libc::close(fd) };
            for w in sysctl {
                let r = std::fs::write(
                    format!("/proc/sys/net/{}", w.path),
                    format!("{}\n", w.value),
                );
                out.push((
                    format!("sysctl net.{}={}", w.path.replace('/', "."), w.value),
                    Some(r.map_err(|e| e.raw_os_error().unwrap_or(-1))),
                ));
            }
            out
        });
        for (line, ack) in results {
            self.log.push(format!("{line} -> {ack:?}"));
            match ack {
                Some(Ok(())) => {}
                other => return Err(format!("{line}: {other:?}")),
            }
        }
        if let Some(r) = &plan.resolver {
            self.log
                .push(format!("resolv.conf:\n{}", r.resolv_conf().trim_end()));
        }
        Ok(())
    }
}

// ---- wispd --------------------------------------------------------------------

struct Wispd {
    child: Child,
}

impl Wispd {
    fn start(bin: &PathBuf, dir: &std::path::Path, run: u32, ipv6: bool) -> Self {
        let ipv6_prefix = if ipv6 {
            "ipv6_prefix    = \"3fff:42::/48\"\n"
        } else {
            ""
        };
        let config = dir.join("wispd.toml");
        std::fs::write(
            &config,
            format!(
                r#"[wisp.server]
endpoint = "/"

[wisp.origin]
block_blank_origins = false

[wisp.auth]
required = false

[wisp.destination]
port_whitelist = [7, 8080, 8081]

[wisp.timeouts]
idle_timeout_ms = 120000
stream_idle_timeout_ms = 120000

[wisp_websocket]
enabled      = true
ingress_mode = "direct_plain"
host         = "127.0.0.1"
port         = {WS_PORT}

[ip_tunnel]
enabled        = true
netns_prefix   = "{TUNNEL_PREFIX}"
resume_grace_s = 20
reject_with    = "icmp"
icmp_echo      = true
dns_servers    = ["192.88.99.2"]
dns_search     = ["ls6.test"]
{ipv6_prefix}"#
            ),
        )
        .unwrap();
        let log = std::fs::File::create(dir.join(format!("wispd-{run}.log"))).unwrap();
        let child = Command::new(bin)
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "info,wisp_tun=debug,wisp_wisp_server=debug")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("start wispd");
        let until = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(("127.0.0.1", WS_PORT)).is_err() {
            assert!(Instant::now() < until, "wispd did not listen");
            std::thread::sleep(Duration::from_millis(100));
        }
        Wispd { child }
    }
}

impl Drop for Wispd {
    fn drop(&mut self) {
        // SAFETY: a signal to our own child.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let until = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- the uplink driver ----------------------------------------------------------

enum Cmd {
    /// Drop the WebSocket, wait, connect again.
    Reconnect { after: Duration },
    /// Close the tunnel and stop.
    Stop(oneshot::Sender<Vec<String>>),
}

type Ws =
    tokio_websockets::WebSocketStream<tokio_websockets::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect() -> Ws {
    let uri = format!("ws://127.0.0.1:{WS_PORT}/");
    let (ws, resp) = ClientBuilder::new()
        .uri(&uri)
        .unwrap()
        .add_header(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("wisp-v2"),
        )
        .unwrap()
        .connect()
        .await
        .expect("WebSocket to wispd");
    assert_eq!(
        resp.headers()
            .get(http::header::SEC_WEBSOCKET_PROTOCOL)
            .map(|v| v.as_bytes()),
        Some(&b"wisp-v2"[..]),
        "wispd speaks Wisp v2"
    );
    ws
}

fn write_frame(fd: RawFd, frame: &[u8]) {
    // SAFETY: writing a buffer to the TAP descriptor.
    let n = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
    if n < 0 {
        // EAGAIN: the machine's receive queue is full; the frame is lost.
    }
}

/// Runs the uplink: WebSocket on one side, the TAP device on the other,
/// the manager on every configuration change.
async fn drive(
    ipv6: bool,
    tap: OwnedFd,
    mut manager: NamespaceManager,
    events: mpsc::UnboundedSender<Event>,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
) {
    let tap = AsyncFd::new(tap).expect("TAP into the reactor");
    let start = Instant::now();
    let now = move || start.elapsed().as_millis() as u64;
    let mut cfg = UplinkConfig::default();
    cfg.wants.ipv6 = ipv6;
    cfg.router.host_mac = Some(HOST_MAC);
    let mut uplink = Uplink::new(cfg);
    let mut ws = Some(ws_connect().await);
    uplink.connected(now(), Carrier::WebSocket);
    let mut reconnect_at: Option<Instant> = None;
    let mut buf = vec![0u8; 65536];
    loop {
        // Carry out everything the uplink asked for.
        while let Some(o) = uplink.poll_output() {
            match o {
                Output::Carrier(Transmit::Ws(b)) => {
                    if let Some(w) = ws.as_mut() {
                        if w.send(Message::binary(b)).await.is_err() {
                            ws = None;
                            uplink.disconnected(now());
                        }
                    }
                }
                Output::Carrier(Transmit::Close) => {
                    if let Some(mut w) = ws.take() {
                        let _ = w.close().await;
                    }
                }
                Output::Carrier(other) => panic!("WebTransport output on WebSocket: {other:?}"),
                Output::Wire(f) => write_frame(tap.as_raw_fd(), &f),
                Output::Event(e) => {
                    match &e {
                        Event::LinkUp { config, .. } | Event::LinkChanged { config } => {
                            manager
                                .configure(config)
                                .expect("the machine takes its config");
                        }
                        Event::LinkDown { .. } => {
                            manager.deconfigure().expect("the machine drops its config");
                        }
                        _ => {}
                    }
                    let _ = events.send(e);
                }
            }
        }
        let deadline = uplink.poll_timeout();
        let sleep_ms = deadline.map(|d| d.saturating_sub(now())).unwrap_or(60_000);
        let reconnect_in = reconnect_at.map(|t| t.saturating_duration_since(Instant::now()));
        tokio::select! {
            msg = async { ws.as_mut().unwrap().next().await }, if ws.is_some() => match msg {
                Some(Ok(m)) if m.is_binary() => uplink.ws_message(now(), m.as_payload()),
                Some(Ok(m)) if m.is_close() => {
                    ws = None;
                    uplink.disconnected(now());
                }
                Some(Ok(_)) => {}
                _ => {
                    ws = None;
                    uplink.disconnected(now());
                }
            },
            ready = tap.readable() => {
                let mut guard = ready.expect("TAP readable");
                loop {
                    // SAFETY: reading into our own buffer from the TAP fd.
                    let n = unsafe { libc::read(tap.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                    if n <= 0 {
                        guard.clear_ready();
                        break;
                    }
                    uplink.wire_frame(now(), &buf[..n as usize]);
                }
            }
            cmd = cmds.recv() => match cmd {
                Some(Cmd::Reconnect { after }) => {
                    if let Some(mut w) = ws.take() {
                        // The carrier drops without a tunnel CLOSE: a
                        // network change, not a goodbye.
                        let _ = w.close().await;
                    }
                    uplink.disconnected(now());
                    reconnect_at = Some(Instant::now() + after);
                }
                Some(Cmd::Stop(done)) => {
                    uplink.close(now());
                    while let Some(o) = uplink.poll_output() {
                        match o {
                            Output::Carrier(Transmit::Ws(b)) => {
                                if let Some(w) = ws.as_mut() {
                                    let _ = w.send(Message::binary(b)).await;
                                }
                            }
                            Output::Event(Event::LinkDown { .. }) => {
                                manager.deconfigure().expect("deconfigure");
                            }
                            // The router's last advertisement, withdrawing
                            // the IPv6 default route.
                            Output::Wire(f) => write_frame(tap.as_raw_fd(), &f),
                            _ => {}
                        }
                    }
                    if let Some(mut w) = ws.take() {
                        let _ = w.close().await;
                    }
                    let _ = done.send(std::mem::take(&mut manager.log));
                    return;
                }
                None => return,
            },
            _ = tokio::time::sleep(reconnect_in.unwrap_or(Duration::from_secs(3600))), if reconnect_at.is_some() => {
                reconnect_at = None;
                ws = Some(ws_connect().await);
                uplink.connected(now(), Carrier::WebSocket);
            }
            _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {
                uplink.handle_timeout(now());
            }
        }
    }
}

async fn wait_event(
    events: &mut mpsc::UnboundedReceiver<Event>,
    what: &str,
    pick: impl Fn(&Event) -> bool,
) -> Event {
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let e = tokio::time::timeout_at(until, events.recv())
            .await
            .unwrap_or_else(|_| panic!("no {what} in 30 s"))
            .expect("driver running");
        log(&format!("event: {e:?}"));
        if pick(&e) {
            return e;
        }
    }
}

// ---- traffic from the machine ---------------------------------------------------

fn http_get() -> (usize, Duration) {
    http_get_from(IpAddr::V4(SERVER))
}

fn http_get_from(server: IpAddr) -> (usize, Duration) {
    in_ns(MACHINE_NS, move || {
        let t = Instant::now();
        let mut s =
            TcpStream::connect_timeout(&SocketAddr::new(server, 8080), Duration::from_secs(10))
                .expect("connect to the web server through the tunnel");
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(b"GET / HTTP/1.0\r\nHost: 192.88.99.2\r\n\r\n")
            .unwrap();
        let mut all = Vec::new();
        s.read_to_end(&mut all).unwrap();
        let split = all
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("headers")
            + 4;
        assert!(all.starts_with(b"HTTP/1.0 200 OK"));
        assert!(all[split..] == http_body()[..], "the body arrives intact");
        (all.len() - split, t.elapsed())
    })
}

fn udp_exchange() -> Vec<usize> {
    udp_exchange_with(IpAddr::V4(SERVER))
}

/// UDP echoes of 64 and 512 bytes and of the largest payload one
/// 1500-byte packet holds.
fn udp_exchange_with(server: IpAddr) -> Vec<usize> {
    in_ns(MACHINE_NS, move || {
        let u = UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .unwrap();
        u.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut sizes = Vec::new();
        let full = if server.is_ipv4() { 1472 } else { 1452 };
        for len in [64usize, 512, full] {
            let msg: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            u.send_to(&msg, SocketAddr::new(server, 7)).unwrap();
            let mut buf = [0u8; 2048];
            let (n, from) = u.recv_from(&mut buf).expect("the echo comes back");
            assert_eq!(from, SocketAddr::new(server, 7));
            assert_eq!(&buf[..n], &msg[..]);
            sizes.push(n);
        }
        sizes
    })
}

// ---- the test -------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and WISPD_BIN"]
async fn tcp_and_udp_through_ip_tunnel_with_resume() {
    epoch();
    let bin = PathBuf::from(std::env::var("WISPD_BIN").expect("WISPD_BIN"));
    let dir =
        PathBuf::from(std::env::var("LS6_E2E_DIR").unwrap_or_else(|_| "/tmp/ls6-e2e".to_owned()));
    std::fs::create_dir_all(&dir).unwrap();
    Leftovers::sweep();
    let _leftovers = Leftovers;
    let _inet = Inet::up();
    let machine = Machine::up();
    let mut wispd = Some(Wispd::start(&bin, &dir, 1, false));
    log("inet, machine and wispd up");

    let manager = NamespaceManager {
        iface: InterfaceSpec {
            name: "eth0".to_owned(),
            ifindex: machine.ifindex,
            mac: HOST_MAC,
        },
        current: None,
        seq: 0,
        log: Vec::new(),
    };
    let (ev_tx, mut events) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let tap = machine.tap.try_clone().unwrap();
    let driver = tokio::spawn(drive(false, tap, manager, ev_tx, cmd_rx));

    // 1. The tunnel opens and the manager configures eth0.
    let up = wait_event(&mut events, "LinkUp", |e| matches!(e, Event::LinkUp { .. })).await;
    assert!(matches!(
        up,
        Event::LinkUp {
            resumed: false,
            flows_lost: false,
            ..
        }
    ));
    let addr = output(&["ip", "-n", MACHINE_NS, "-4", "addr", "show", "dev", "eth0"]);
    let route = output(&["ip", "-n", MACHINE_NS, "-4", "route"]);
    let link = output(&["ip", "-n", MACHINE_NS, "link", "show", "dev", "eth0"]);
    println!("{addr}{route}{link}");
    assert!(addr.contains("inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"));
    assert!(
        route.contains("default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100")
    );
    assert!(link.contains("mtu 1500") && link.contains("52:54:00:4c:53:36"));
    let tunnels = output(&["ip", "netns", "list"]);
    let tunnel_ns: Vec<&str> = tunnels
        .lines()
        .filter(|l| l.starts_with(TUNNEL_PREFIX))
        .collect();
    assert_eq!(
        tunnel_ns.len(),
        1,
        "one network for the one tunnel: {tunnels}"
    );
    let first_tunnel = tunnel_ns[0].split_whitespace().next().unwrap().to_owned();
    log(&format!(
        "eth0 configured over netlink; tunnel namespace {first_tunnel}"
    ));

    // 2. UDP: three sizes, the largest a full 1500-byte packet.
    let sizes = udp_exchange();
    log(&format!("UDP echo through the tunnel: {sizes:?} bytes"));

    // 3. ICMP, and the TTL a host behind a home router sees (two routers).
    let ping = output(&[
        "ip",
        "netns",
        "exec",
        MACHINE_NS,
        "ping",
        "-c",
        "2",
        "-W",
        "3",
        "192.88.99.2",
    ]);
    println!("{ping}");
    assert!(
        ping.contains("ttl=62"),
        "echo replies come through two routers"
    );

    // 4. TCP: a 256 KiB download, then the same with curl.
    let (n, took) = http_get();
    log(&format!(
        "HTTP GET through the tunnel: {n} bytes in {took:?}"
    ));
    let curl = output(&[
        "ip",
        "netns",
        "exec",
        MACHINE_NS,
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{size_download}",
        "http://192.88.99.2:8080/",
    ]);
    log(&format!("curl from the machine: {curl}"));
    assert_eq!(curl.trim(), format!("200 {HTTP_BODY}"));

    // Without a routed prefix the router stays silent: the machine has its
    // link-local address only and no IPv6 default route, as on an IPv4-only
    // network.
    let v6addr = output(&[
        "ip", "-n", MACHINE_NS, "-6", "addr", "show", "dev", "eth0", "scope", "global",
    ]);
    let v6route = output(&["ip", "-n", MACHINE_NS, "-6", "route", "show", "default"]);
    assert!(
        v6addr.trim().is_empty() && v6route.trim().is_empty(),
        "{v6addr}{v6route}"
    );
    log("IPv4-only tunnel: no router advertisement, no global IPv6 address");

    // 5. A private destination is refused by the relay like a firewall:
    //    ICMP administratively prohibited, so connect fails at once.
    let refused = in_ns(MACHINE_NS, || {
        let t = Instant::now();
        let r = TcpStream::connect_timeout(
            &SocketAddr::from(([10, 0, 0, 1], 8080)),
            Duration::from_secs(10),
        );
        (r.map(|_| ()).map_err(|e| e.raw_os_error()), t.elapsed())
    });
    log(&format!("connect to 10.0.0.1:8080: {refused:?}"));
    assert_eq!(refused.0, Err(Some(libc::EHOSTUNREACH)));

    // 6. Resume (LD13): a TCP connection survives the carrier dropping for 2 s.
    let (tx, rx) = std::sync::mpsc::channel::<&'static [u8]>();
    let (back_tx, back_rx) = std::sync::mpsc::channel::<std::io::Result<Vec<u8>>>();
    let echo = std::thread::spawn(move || {
        enter_netns(MACHINE_NS);
        let mut s =
            TcpStream::connect_timeout(&SocketAddr::from((SERVER, 8081)), Duration::from_secs(10))
                .unwrap();
        s.set_read_timeout(Some(Duration::from_secs(25))).unwrap();
        while let Ok(msg) = rx.recv() {
            if msg.is_empty() {
                let _ = s.shutdown(Shutdown::Both);
                return;
            }
            let r = s.write_all(msg).and_then(|_| {
                let mut buf = vec![0u8; msg.len()];
                s.read_exact(&mut buf).map(|_| buf)
            });
            back_tx.send(r).unwrap();
        }
    });
    tx.send(b"hello\n").unwrap();
    assert_eq!(back_rx.recv().unwrap().unwrap(), b"hello\n");
    log("TCP echo connection open; dropping the WebSocket for 2 s");
    cmd_tx
        .send(Cmd::Reconnect {
            after: Duration::from_secs(2),
        })
        .unwrap();
    wait_event(&mut events, "Detached", |e| {
        matches!(e, Event::Detached { .. })
    })
    .await;
    // Sent into the gap: the uplink drops it, the machine's TCP retransmits.
    tx.send(b"world\n").unwrap();
    let resumed = wait_event(&mut events, "LinkUp", |e| matches!(e, Event::LinkUp { .. })).await;
    assert!(
        matches!(
            resumed,
            Event::LinkUp {
                resumed: true,
                flows_lost: false,
                ..
            }
        ),
        "{resumed:?}"
    );
    let t = Instant::now();
    assert_eq!(back_rx.recv().unwrap().unwrap(), b"world\n");
    log(&format!(
        "resumed; the bytes sent into the gap arrived {:?} after the resume",
        t.elapsed()
    ));
    let tunnels = output(&["ip", "netns", "list"]);
    assert!(
        tunnels.contains(&first_tunnel),
        "the same tunnel network: {tunnels}"
    );

    // 7. The relay restarts: the token is unknown to the new process, so it
    //    opens a new tunnel with ERROR 0x0004 in the confirmation and the
    //    uplink reports the flows as lost. What happens to the old TCP
    //    connection is the relay's NAT state, recorded, not asserted: the
    //    new process numbers its first tunnel 1 again, and the host's
    //    conntrack entries outlive the old process.
    drop(wispd.take());
    wispd = Some(Wispd::start(&bin, &dir, 2, false));
    log("wispd restarted");
    cmd_tx
        .send(Cmd::Reconnect {
            after: Duration::from_millis(200),
        })
        .unwrap();
    let fresh = wait_event(&mut events, "LinkUp", |e| matches!(e, Event::LinkUp { .. })).await;
    assert!(
        matches!(
            fresh,
            Event::LinkUp {
                resumed: false,
                flows_lost: true,
                ..
            }
        ),
        "{fresh:?}"
    );
    tx.send(b"again\n").unwrap();
    let old = back_rx.recv().unwrap();
    log(&format!(
        "the old TCP connection after the restart: {:?}",
        old.as_ref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .map_err(|e| e.kind())
    ));
    tx.send(b"").unwrap();
    echo.join().unwrap();
    // New connections work on the new tunnel.
    let (n, _) = http_get();
    assert_eq!(n, HTTP_BODY);
    log("a new TCP connection works on the new tunnel");

    // 8. Stop: the tunnel closes and the manager removes its configuration.
    let (done_tx, done_rx) = oneshot::channel();
    cmd_tx.send(Cmd::Stop(done_tx)).unwrap();
    let manager_log = done_rx.await.unwrap();
    driver.await.unwrap();
    println!("manager log:\n{}", manager_log.join("\n"));
    let addr = output(&["ip", "-n", MACHINE_NS, "-4", "addr", "show", "dev", "eth0"]);
    assert!(!addr.contains("192.168.1.100"), "{addr}");
    std::thread::sleep(Duration::from_millis(500));
    drop(wispd.take());
    let left = output(&["ip", "netns", "list"]);
    assert!(
        !left.lines().any(|l| l.starts_with(TUNNEL_PREFIX)),
        "no tunnel namespace left: {left}"
    );
    log("done");
}

/// IPv6 when the relay routes a prefix to the tunnel (decision LD3b): the
/// virtual router advertises the tunnel's /64, the machine's own kernel
/// forms its address by SLAAC and takes its default route from the
/// advertisement, and IPv6 traffic crosses without NAT66 next to IPv4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root and WISPD_BIN"]
async fn ipv6_by_slaac_through_a_routed_prefix() {
    epoch();
    let bin = PathBuf::from(std::env::var("WISPD_BIN").expect("WISPD_BIN"));
    let dir =
        PathBuf::from(std::env::var("LS6_E2E_DIR").unwrap_or_else(|_| "/tmp/ls6-e2e".to_owned()));
    std::fs::create_dir_all(&dir).unwrap();
    Leftovers::sweep();
    let _leftovers = Leftovers;
    let _inet = Inet::up();
    let machine = Machine::up();
    let wispd = Wispd::start(&bin, &dir, 3, true);
    log("dual-stack: inet, machine and wispd (ipv6_prefix 3fff:42::/48) up");
    let manager = NamespaceManager {
        iface: InterfaceSpec {
            name: "eth0".to_owned(),
            ifindex: machine.ifindex,
            mac: HOST_MAC,
        },
        current: None,
        seq: 0,
        log: Vec::new(),
    };
    let (ev_tx, mut events) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let tap = machine.tap.try_clone().unwrap();
    let driver = tokio::spawn(drive(true, tap, manager, ev_tx, cmd_rx));
    let up = wait_event(&mut events, "LinkUp", |e| matches!(e, Event::LinkUp { .. })).await;
    let Event::LinkUp { config, .. } = up else {
        unreachable!()
    };
    let v6 = config.ipv6().expect("an IPv6 address in the confirmation");
    assert_eq!(v6.prefix.len(), 64);
    let IpAddr::V6(assigned) = v6.prefix.addr() else {
        unreachable!()
    };
    let seg = assigned.segments();
    let prefix = Ipv6Addr::new(seg[0], seg[1], seg[2], seg[3], 0, 0, 0, 0);
    // EUI-64 from 52:54:00:4c:53:36, the address the kernel forms by SLAAC.
    let slaac = Ipv6Addr::new(
        seg[0], seg[1], seg[2], seg[3], 0x5054, 0x00ff, 0xfe4c, 0x5336,
    );
    log(&format!(
        "routed /64 {prefix}/64; expecting SLAAC address {slaac}"
    ));

    // Wait for the router advertisement's work: the address past DAD and
    // the default route via fe80::1.
    let until = Instant::now() + Duration::from_secs(15);
    let (addr, route) = loop {
        let addr = output(&[
            "ip", "-n", MACHINE_NS, "-6", "addr", "show", "dev", "eth0", "scope", "global",
        ]);
        let route = output(&["ip", "-n", MACHINE_NS, "-6", "route", "show", "default"]);
        if addr.contains(&slaac.to_string())
            && !addr.contains("tentative")
            && route.contains("fe80::1")
        {
            break (addr, route);
        }
        assert!(
            Instant::now() < until,
            "no SLAAC address in time:\n{addr}{route}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    println!("{addr}{route}");
    assert!(route.contains("default via fe80::1 dev eth0 proto ra"));
    assert!(
        addr.contains("scope global dynamic mngtmpaddr") || addr.contains("scope global dynamic")
    );
    let accept_ra = in_ns(MACHINE_NS, || {
        std::fs::read_to_string("/proc/sys/net/ipv6/conf/eth0/accept_ra").unwrap()
    });
    assert_eq!(accept_ra.trim(), "1");
    log("SLAAC address and default route from the virtual router's advertisement");

    let server6 = IpAddr::V6("3fff:99::2".parse().unwrap());
    let sizes = udp_exchange_with(server6);
    log(&format!(
        "UDP over IPv6 through the tunnel: {sizes:?} bytes"
    ));
    let ping = output(&[
        "ip",
        "netns",
        "exec",
        MACHINE_NS,
        "ping",
        "-6",
        "-c",
        "2",
        "-W",
        "3",
        "3fff:99::2",
    ]);
    println!("{ping}");
    assert!(ping.contains("ttl=62"), "hop limit through two routers");
    let (n, took) = http_get_from(server6);
    log(&format!("HTTP over IPv6: {n} bytes in {took:?}"));
    let curl = output(&[
        "ip",
        "netns",
        "exec",
        MACHINE_NS,
        "curl",
        "-6",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{size_download}",
        "http://[3fff:99::2]:8080/",
    ]);
    assert_eq!(curl.trim(), format!("200 {HTTP_BODY}"));
    // The server sees the machine's own address: no NAT66.
    let seen = in_ns(INET_NS, || {
        output(&["ss", "-6", "-tn", "state", "time-wait"])
    });
    log(&format!(
        "the server's sockets: {}",
        seen.trim().replace('\n', " | ")
    ));
    // And IPv4 still works beside it.
    assert_eq!(udp_exchange().len(), 3);

    let (done_tx, done_rx) = oneshot::channel();
    cmd_tx.send(Cmd::Stop(done_tx)).unwrap();
    let manager_log = done_rx.await.unwrap();
    driver.await.unwrap();
    println!("manager log:\n{}", manager_log.join("\n"));
    // The last advertisement withdrew the default route.
    std::thread::sleep(Duration::from_millis(300));
    let route = output(&["ip", "-n", MACHINE_NS, "-6", "route", "show", "default"]);
    log(&format!(
        "IPv6 default route after the close: {:?}",
        route.trim()
    ));
    assert!(route.trim().is_empty());
    drop(wispd);
    log("done");
}

/// Not a check of its own: brings up the stand-in internet and wispd and
/// keeps them for `LS6_SERVE_SECS` seconds (default 120) for a client
/// outside the VM, such as the carrier package's `relay.e2e.test.ts` under
/// bun through Lima's forward of 127.0.0.1:6101.
#[test]
#[ignore = "needs root and WISPD_BIN; serves for LS6_SERVE_SECS"]
fn serve_a_relay_for_an_outside_client() {
    let bin = PathBuf::from(std::env::var("WISPD_BIN").expect("WISPD_BIN"));
    let dir =
        PathBuf::from(std::env::var("LS6_E2E_DIR").unwrap_or_else(|_| "/tmp/ls6-e2e".to_owned()));
    let secs: u64 = std::env::var("LS6_SERVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);
    std::fs::create_dir_all(&dir).unwrap();
    Leftovers::sweep();
    let _leftovers = Leftovers;
    let _inet = Inet::up();
    let _wispd = Wispd::start(&bin, &dir, 9, false);
    println!("serving ws://127.0.0.1:{WS_PORT}/ for {secs} s");
    std::thread::sleep(Duration::from_secs(secs));
}

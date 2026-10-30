//! Plain RFC 6455 `ws://` listener. No TLS, no HTTP/2, no extended CONNECT —
//! HTTP/1.1 `Upgrade: websocket` over a TCP stream. Reuses
//! [`wisp_ws_h2::H2ServeContext`] for shared per-listener state.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use thiserror::Error;
use tokio::net::{TcpListener, TcpSocket};
use tokio_websockets::{Config, Limits, ServerBuilder};
use tracing::{debug, info, warn};
use wisp_config::{
    is_client_ip_allowed, is_trusted_proxy_ip, resolve_client_ip_checked, IngressMode, Secret,
    WispServerOptions, WispWtServerOptions,
};
use wisp_dos::is_connection_start_allowed;
use wisp_iphash::hash_client_ip_keyed;
use wisp_origin::{is_origin_allowed, origin_from_headers, origin_headers_valid};
use wisp_reports::{emit_report, ConnectionContext, ReportErrorType, ReportInput, Transport};
use wisp_wisp_server::ServerContext;
use wisp_ws_h2::{listener::ConnectionView, websocket::serve_websocket, H2ServeContext};

use crate::accept::{is_resource_exhaustion, AcceptBudget, AcceptGuard, Refusals, ACCEPT_BACKOFF};
use crate::ws_http1::{accept_upgrade, read_upgrade, reject_upgrade};

const WS_SOCKET_BUF: usize = 1024 * 1024;
const WS_FLUSH_THRESHOLD: usize = 1024 * 1024;

/// Header the trusted front sends with the shared `trusted_edge_secret`.
pub const EDGE_SECRET_HEADER: &str = "x-wisp-edge-secret";

#[derive(Debug, Error)]
pub enum WsPlainListenerError {
    #[error("bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid bind address {host}:{port}: {source}")]
    BadAddr {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct WsPlainListenerConfig {
    pub bind_addr: SocketAddr,
    pub trust_forwarded_headers: bool,
    /// Under `trusted_edge`, upgrades must carry this in
    /// [`EDGE_SECRET_HEADER`] before `X-Forwarded-For` is believed. `None`
    /// keeps the address-only trust of the loopback listener.
    pub trusted_edge_secret: Option<Secret>,
}

impl WsPlainListenerConfig {
    pub fn try_from_wisp_wt(
        cfg: &WispWtServerOptions,
    ) -> Result<Option<Self>, WsPlainListenerError> {
        if !cfg.websocket.enabled
            || !matches!(
                cfg.websocket.ingress_mode,
                IngressMode::TrustedEdge | IngressMode::DirectPlain
            )
        {
            return Ok(None);
        }
        let (host, port, addrs_input) = if let Some(addr) = cfg.websocket.bind_addr.as_deref() {
            (addr.to_owned(), 0u16, addr.to_owned())
        } else {
            (
                cfg.websocket.host.clone(),
                cfg.websocket.port,
                format!("{}:{}", cfg.websocket.host, cfg.websocket.port),
            )
        };
        let bind_addr = addrs_input
            .as_str()
            .to_socket_addrs()
            .map_err(|source| WsPlainListenerError::BadAddr {
                host: host.clone(),
                port,
                source,
            })?
            .next()
            .ok_or_else(|| WsPlainListenerError::BadAddr {
                host: host.clone(),
                port,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "host did not resolve to any address",
                ),
            })?;
        Ok(Some(Self {
            bind_addr,
            trust_forwarded_headers: cfg.websocket.ingress_mode == IngressMode::TrustedEdge,
            trusted_edge_secret: cfg
                .websocket
                .trusted_edge_secret
                .clone()
                .filter(|_| cfg.websocket.ingress_mode == IngressMode::TrustedEdge),
        }))
    }
}

pub async fn serve_ws_plain_listener(
    cfg: WsPlainListenerConfig,
    ctx: Arc<H2ServeContext>,
) -> Result<(), WsPlainListenerError> {
    let listener = bind_ws_plain_listener(&cfg)?;
    serve_bound_ws_plain_listener(listener, cfg, ctx).await
}

/// Binds the listening socket now, so an address in use or a permission
/// error reaches the caller instead of ending a spawned accept loop.
/// Needs a Tokio runtime context.
pub fn bind_ws_plain_listener(
    cfg: &WsPlainListenerConfig,
) -> Result<TcpListener, WsPlainListenerError> {
    bind_with_backlog(cfg.bind_addr).map_err(|source| WsPlainListenerError::Bind {
        addr: cfg.bind_addr,
        source,
    })
}

/// Runs the accept loop on a socket from [`bind_ws_plain_listener`].
pub async fn serve_bound_ws_plain_listener(
    listener: TcpListener,
    cfg: WsPlainListenerConfig,
    ctx: Arc<H2ServeContext>,
) -> Result<(), WsPlainListenerError> {
    info!(addr = %cfg.bind_addr, "wisp ws-plain listener ready");
    let preauth = AcceptBudget::new(
        ctx.options.max_connections,
        ctx.options.max_connections_per_ip,
    );
    let refusals = Refusals::new(64);

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "ws-plain accept error");
                if is_resource_exhaustion(&e) {
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
                continue;
            }
        };
        let client_ip = peer.ip().to_string();
        // A trusted front carries many clients on one address; it is held to
        // the listener's total only, and its clients to their own caps after
        // the upgrade.
        let per_ip = (!(cfg.trust_forwarded_headers
            && is_trusted_proxy_ip(&client_ip, &ctx.options)))
        .then_some(peer.ip());
        let Some(preauth_guard) = preauth.try_admit(per_ip) else {
            debug!(peer = %peer, "ws-plain pre-authentication cap reached");
            refusals.refuse(tcp);
            continue;
        };
        tune_accepted(&tcp);
        let ctx = ctx.clone();
        let edge_secret = cfg.trusted_edge_secret.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                tcp,
                client_ip,
                ctx,
                cfg.trust_forwarded_headers,
                edge_secret,
                preauth_guard,
            )
            .await
            {
                debug!(peer = %peer, error = %e, "ws-plain connection ended");
            }
        });
    }
}

fn bind_with_backlog(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    let _ = socket.set_nodelay(true);
    socket.bind(addr)?;
    socket.listen(1024)
}

fn tune_accepted(tcp: &tokio::net::TcpStream) {
    let _ = tcp.set_nodelay(true);
    let sock = socket2::SockRef::from(tcp);
    let _ = sock.set_recv_buffer_size(WS_SOCKET_BUF);
    let _ = sock.set_send_buffer_size(WS_SOCKET_BUF);
}

async fn handle_connection(
    tcp: tokio::net::TcpStream,
    client_ip: String,
    ctx: Arc<H2ServeContext>,
    trust_forwarded_headers: bool,
    edge_secret: Option<Secret>,
    preauth_guard: AcceptGuard,
) -> Result<(), std::io::Error> {
    let timeout =
        std::time::Duration::from_millis(ctx.options.handshake_timeout_ms.unwrap_or(10_000));
    let pending = tokio::time::timeout(timeout, read_upgrade(tcp))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upgrade timed out"))??;

    // The front proves itself before anything it says is believed, so another
    // local process cannot pick a client identity by sending X-Forwarded-For.
    if trust_forwarded_headers {
        if let Some(secret) = edge_secret.as_ref() {
            if !edge_secret_matches(&pending.info.headers, secret.as_bytes()) {
                debug!("ws-plain: rejecting upgrade without the edge secret");
                reject_upgrade(pending, "403 Forbidden").await?;
                return Ok(());
            }
        }
    }

    let path = pending.info.path.clone();
    if !ctx.path_is_endpoint_scope(&path) {
        debug!("ws-plain: not the endpoint");
        reject_upgrade(pending, "404 Not Found").await?;
        return Ok(());
    }

    // Everything that does not depend on a token runs before one is resolved,
    // so a banned, foreign-origin or flooding client never reaches the token
    // resolver (which may call out to the host's handler).
    let base = ctx.base_options();
    if !origin_headers_valid(&pending.info.headers) {
        let reported_ip = report_client_ip(&pending, &client_ip, trust_forwarded_headers, &base);
        report_rejection(
            ReportErrorType::OriginBlocked,
            reported_ip.as_deref(),
            None,
            403,
            None,
        );
        reject_upgrade(pending, "403 Forbidden").await?;
        return Ok(());
    }
    let origin = origin_from_headers(&pending.info.headers).map(|s| s.to_owned());
    if !is_origin_allowed(origin.as_deref(), &base) {
        debug!(?origin, "ws-plain: rejecting websocket: origin policy");
        let reported_ip = report_client_ip(&pending, &client_ip, trust_forwarded_headers, &base);
        report_rejection(
            ReportErrorType::OriginBlocked,
            reported_ip.as_deref(),
            origin.as_deref(),
            403,
            None,
        );
        reject_upgrade(pending, "403 Forbidden").await?;
        return Ok(());
    }

    let client_ip = if trust_forwarded_headers {
        let (xff, duplicate_forwarded) = {
            let mut forwarded_values = pending.info.headers.get_all("x-forwarded-for").iter();
            let xff = forwarded_values
                .next()
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            (xff, forwarded_values.next().is_some())
        };
        if duplicate_forwarded {
            debug!("ws-plain: rejecting duplicate forwarded client headers");
            reject_upgrade(pending, "403 Forbidden").await?;
            return Ok(());
        }
        if xff.is_none() || !is_trusted_proxy_ip(&client_ip, &base) {
            debug!(peer_ip = %client_ip, "ws-plain: rejecting untrusted edge peer");
            reject_upgrade(pending, "403 Forbidden").await?;
            return Ok(());
        }
        let Some(resolved) = resolve_client_ip_checked(&client_ip, xff.as_deref(), &base) else {
            debug!("ws-plain: rejecting invalid forwarded client chain");
            reject_upgrade(pending, "403 Forbidden").await?;
            return Ok(());
        };
        resolved
    } else {
        client_ip
    };
    if !is_client_ip_allowed(&client_ip, &base) {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: client IP policy");
        report_rejection(
            ReportErrorType::ClientBlocked,
            Some(&client_ip),
            origin.as_deref(),
            403,
            None,
        );
        reject_upgrade(pending, "403 Forbidden").await?;
        return Ok(());
    }
    let client_hash = hash_client_ip_keyed(Some(&client_ip));
    if ctx.ip_bans.is_banned(client_hash.as_deref()) {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: banned IP hash");
        emit_report(
            ReportErrorType::IpHashBanned,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some(client_ip.clone()),
                    client_ip_hash: client_hash,
                    transport: Some(Transport::Ws),
                    origin: origin.clone(),
                }),
                transport_close_code: Some(403),
                ..Default::default()
            },
        );
        reject_upgrade(pending, "403 Forbidden").await?;
        return Ok(());
    }
    if !ctx.token_attempt_allowed(&client_ip, &path, &base) {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: token attempt rate");
        report_rejection(
            ReportErrorType::ConnectionRateLimited,
            Some(&client_ip),
            origin.as_deref(),
            429,
            Some("token_attempt"),
        );
        reject_upgrade(pending, "429 Too Many Requests").await?;
        return Ok(());
    }
    let Some(view) = ctx.view_for_path(&path, Some(base.clone())).await else {
        debug!("ws-plain: authentication rejected");
        reject_upgrade(pending, "404 Not Found").await?;
        return Ok(());
    };
    // A token's limit profile is a full option set and may carry its own
    // origin or client lists.
    if !Arc::ptr_eq(&view.options, &base)
        && (!is_origin_allowed(origin.as_deref(), &view.options)
            || !is_client_ip_allowed(&client_ip, &view.options))
    {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: token profile origin or client policy");
        reject_upgrade(pending, "403 Forbidden").await?;
        return Ok(());
    }
    let store = ctx.dos.clone();
    if !is_connection_start_allowed(&client_ip, &view.options, &store) {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: connection-start rate");
        report_rejection(
            ReportErrorType::ConnectionRateLimited,
            Some(&client_ip),
            origin.as_deref(),
            429,
            Some("connection_start"),
        );
        reject_upgrade(pending, "429 Too Many Requests").await?;
        return Ok(());
    }
    let _conn_guard = match ctx.connection_limiter.try_acquire(
        &client_ip,
        view.options.max_connections,
        view.options.max_connections_per_ip,
    ) {
        Some(g) => g,
        None => {
            debug!(client_ip = %client_ip, "ws-plain: rejecting: connection concurrency cap");
            report_rejection(
                ReportErrorType::ConnectionLimit,
                Some(&client_ip),
                origin.as_deref(),
                429,
                Some("max_connections"),
            );
            reject_upgrade(pending, "429 Too Many Requests").await?;
            return Ok(());
        }
    };

    let client_advertises_v2 = pending.info.advertises_v2;
    let io = accept_upgrade(pending).await?;
    // Upgraded: the connection limiter now counts this client, so its
    // pre-authentication slot goes back to the listener.
    drop(preauth_guard);
    let ws_max_payload = (view.server_options.max_binary_frame_bytes as usize)
        .max(view.server_options.max_text_frame_bytes as usize)
        .saturating_add(1024);
    let ws = ServerBuilder::new()
        .config(Config::default().flush_threshold(WS_FLUSH_THRESHOLD))
        .limits(Limits::default().max_payload_len(Some(ws_max_payload)))
        .serve(io);
    let server_ctx = build_server_ctx(client_ip, client_hash, &ctx, &view, client_advertises_v2);
    if let Err(error) = serve_websocket(ws, server_ctx).await {
        debug!(%error, "wisp-ws-plain connection ended with error");
    }
    Ok(())
}

/// Whether any `x-wisp-edge-secret` header equals `secret`. The comparison does
/// not stop at the first differing byte, and a wrong-length value is compared
/// over the same number of bytes as the secret, so timing reveals neither where
/// a guess diverges nor how long the secret is.
fn edge_secret_matches(headers: &http::HeaderMap, secret: &[u8]) -> bool {
    let mut matched = false;
    for value in headers.get_all(EDGE_SECRET_HEADER) {
        matched |= constant_time_eq(value.as_bytes(), secret);
    }
    matched
}

fn constant_time_eq(provided: &[u8], expected: &[u8]) -> bool {
    let mut diff = provided.len() ^ expected.len();
    for (i, want) in expected.iter().enumerate() {
        let got = provided.get(i).copied().unwrap_or(0);
        diff |= usize::from(got ^ want);
    }
    diff == 0
}

/// Report a rejected upgrade the way the ws-h2 service does, so the panel sees
/// plain-listener abuse too. Emission is rate limited per client hash and
/// report type inside `emit_report`.
fn report_rejection(
    error_type: ReportErrorType,
    client_ip: Option<&str>,
    origin: Option<&str>,
    close_code: i32,
    limit_type: Option<&str>,
) {
    emit_report(
        error_type,
        ReportInput {
            context: Some(ConnectionContext {
                client_ip: client_ip.map(str::to_owned),
                transport: Some(Transport::Ws),
                origin: origin.map(str::to_owned),
                ..Default::default()
            }),
            origin: origin.map(str::to_owned),
            transport_close_code: Some(close_code),
            limit_type: limit_type.map(str::to_owned),
            ..Default::default()
        },
    );
}

/// Client address to attach to a report raised before the forwarded-for chain
/// has been resolved (the origin checks run first). Behind a trusted edge the
/// socket peer is the edge itself, so hashing it would let the panel ban the
/// edge: report the forwarded client only when the peer is a trusted proxy
/// that sent exactly one resolvable header, and otherwise report no address.
fn report_client_ip(
    pending: &crate::ws_http1::PendingUpgrade,
    peer_ip: &str,
    trust_forwarded_headers: bool,
    options: &WispServerOptions,
) -> Option<String> {
    if !trust_forwarded_headers {
        return Some(peer_ip.to_owned());
    }
    let mut values = pending.info.headers.get_all("x-forwarded-for").iter();
    let xff = values.next()?.to_str().ok()?;
    if values.next().is_some() || !is_trusted_proxy_ip(peer_ip, options) {
        return None;
    }
    resolve_client_ip_checked(peer_ip, Some(xff), options)
}

fn build_server_ctx(
    client_ip: String,
    client_hash: Option<String>,
    ctx: &H2ServeContext,
    view: &ConnectionView,
    client_advertises_v2: bool,
) -> ServerContext {
    let proxy_controller = ctx.proxy_template.as_ref().map(|t| {
        t.spawn(
            view.server_options.proxy_control_limits(),
            view.auth_policy.allowed_proxy_providers.clone(),
        )
    });
    ServerContext::new(
        client_ip,
        client_hash,
        view.options.clone(),
        view.server_options.clone(),
        proxy_controller,
        client_advertises_v2,
        ctx.dos.clone(),
    )
    .with_cancel(ctx.shutdown.child_token())
    .with_tunnels(ctx.tunnels.clone())
    .with_principal(view.principal.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wisp_config::{WispAuthRegistry, WispServerOptions};
    use wisp_dos::{ConnectionLimiter, DosGuard};
    use wisp_iphash::IpHashBans;
    use wisp_reports::{set_report_hook, Report, ReportErrorType};

    const UPGRADE: &[u8] = b"GET /wisp HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

    /// Start a plain listener on a free loopback port and return its address.
    async fn spawn_listener(ip_bans: Arc<IpHashBans>) -> SocketAddr {
        spawn_listener_with(ip_bans, false, None).await
    }

    async fn spawn_listener_with(
        ip_bans: Arc<IpHashBans>,
        trust_forwarded_headers: bool,
        trusted_edge_secret: Option<Secret>,
    ) -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let bind_addr = probe.local_addr().expect("read reserved address");
        drop(probe);
        let mut options = WispServerOptions {
            block_blank_origins: false,
            parse_real_ip: true,
            ..WispServerOptions::default()
        };
        options.auth.required = false;
        let ctx = Arc::new(
            H2ServeContext::with_template_and_auth(
                Arc::new(options),
                false,
                None,
                WispAuthRegistry::default(),
                Arc::new(DosGuard::new()),
                Arc::new(ConnectionLimiter::new()),
            )
            .with_ip_bans(ip_bans),
        );
        let cfg = WsPlainListenerConfig {
            bind_addr,
            trust_forwarded_headers,
            trusted_edge_secret,
        };
        tokio::spawn(serve_ws_plain_listener(cfg, ctx));
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(bind_addr).await.is_ok() {
                return bind_addr;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("ws-plain listener did not come up");
    }

    async fn status_line(addr: SocketAddr) -> String {
        status_line_with(addr, "").await
    }

    /// Send the upgrade with `extra` header lines (each ending in CRLF) added.
    async fn status_line_with(addr: SocketAddr, extra: &str) -> String {
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect test client");
        let request = String::from_utf8(UPGRADE.to_vec())
            .expect("ascii request")
            .replacen("\r\n\r\n", &format!("\r\n{extra}\r\n"), 1);
        client
            .write_all(request.as_bytes())
            .await
            .expect("write upgrade");
        let mut head = vec![0u8; 64];
        let read = client.read(&mut head).await.expect("read status line");
        String::from_utf8_lossy(&head[..read])
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    /// The report hook is process-wide, so tests that install one take turns.
    static HOOK_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn refuses_banned_client_with_403_and_reports_it() {
        let _turn = HOOK_TURN.lock().await;
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        set_report_hook(Some(Arc::new(move |report: &Report| {
            if report.error_type == ReportErrorType::IpHashBanned {
                let _ = report_tx.send(report.ip_hash.clone());
            }
        })));

        let bans = Arc::new(IpHashBans::new());
        let addr = spawn_listener(bans.clone()).await;

        let first = status_line(addr).await;
        assert!(first.contains("101"), "unbanned client got {first:?}");

        let banned = hash_client_ip_keyed(Some("127.0.0.1")).unwrap();
        bans.replace([banned.clone()]);
        assert!(status_line(addr).await.contains("403"));
        assert_eq!(report_rx.recv().await, Some(Some(banned)));

        bans.replace(Vec::<String>::new());
        assert!(status_line(addr).await.contains("101"));
        set_report_hook(None);
    }

    /// Counts token resolutions and accepts every token.
    struct CountingResolver(Arc<std::sync::atomic::AtomicUsize>);

    impl wisp_config::WispAuthResolver for CountingResolver {
        fn resolve(&self, _token: String) -> wisp_config::WispAuthResolveFuture {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Some(wisp_config::WispAuthTokenPolicy::default()) })
        }
    }

    #[tokio::test]
    async fn bans_origin_and_attempt_budget_run_before_token_resolution() {
        // Emits reports, so it takes its turn with the tests that collect them.
        let _turn = HOOK_TURN.lock().await;
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let bind_addr = probe.local_addr().expect("read reserved address");
        drop(probe);
        let options = WispServerOptions {
            block_blank_origins: false,
            origin_whitelist: Some(vec!["https://good.example".to_owned()]),
            max_connection_starts_per_ip_per_minute: 2,
            ..WispServerOptions::default()
        };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let registry = WispAuthRegistry::default();
        registry.set_resolver(Arc::new(CountingResolver(calls.clone())));
        let bans = Arc::new(IpHashBans::new());
        let ctx = Arc::new(
            H2ServeContext::with_template_and_auth(
                Arc::new(options),
                false,
                None,
                registry,
                Arc::new(DosGuard::new()),
                Arc::new(ConnectionLimiter::new()),
            )
            .with_ip_bans(bans.clone()),
        );
        let cfg = WsPlainListenerConfig {
            bind_addr,
            trust_forwarded_headers: false,
            trusted_edge_secret: None,
        };
        tokio::spawn(serve_ws_plain_listener(cfg, ctx));
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(bind_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let token_upgrade = |origin: &str| -> Vec<u8> {
            String::from_utf8(UPGRADE.to_vec())
                .unwrap()
                .replacen("GET /wisp ", "GET /wisp/some-token ", 1)
                .replacen("\r\n\r\n", &format!("\r\nOrigin: {origin}\r\n\r\n"), 1)
                .into_bytes()
        };
        let send = |request: Vec<u8>| async move {
            let mut client = tokio::net::TcpStream::connect(bind_addr).await.unwrap();
            client.write_all(&request).await.unwrap();
            let mut head = vec![0u8; 64];
            let read = client.read(&mut head).await.unwrap();
            String::from_utf8_lossy(&head[..read]).into_owned()
        };
        let resolutions = || calls.load(std::sync::atomic::Ordering::SeqCst);

        assert!(send(token_upgrade("https://evil.example"))
            .await
            .contains("403"));
        assert_eq!(
            resolutions(),
            0,
            "a foreign origin never reaches the resolver"
        );

        bans.replace([hash_client_ip_keyed(Some("127.0.0.1")).unwrap()]);
        assert!(send(token_upgrade("https://good.example"))
            .await
            .contains("403"));
        assert_eq!(
            resolutions(),
            0,
            "a banned client never reaches the resolver"
        );
        bans.replace(Vec::<String>::new());

        // Two starts per minute allow eight token attempts, then 429 without
        // resolving.
        for _ in 0..8 {
            send(token_upgrade("https://good.example")).await;
        }
        let attempts = resolutions();
        assert!(attempts <= 8);
        assert!(send(token_upgrade("https://good.example"))
            .await
            .contains("429"));
        assert_eq!(resolutions(), attempts);
    }

    #[tokio::test]
    async fn trusted_edge_requires_the_edge_secret() {
        let secret = "e".repeat(32);
        let addr = spawn_listener_with(
            Arc::new(IpHashBans::new()),
            true,
            Some(Secret::new(secret.clone())),
        )
        .await;
        let xff = "X-Forwarded-For: 203.0.113.7\r\n";

        assert!(status_line_with(addr, xff).await.contains("403"));
        let wrong = format!("{xff}x-wisp-edge-secret: {}\r\n", "w".repeat(32));
        assert!(status_line_with(addr, &wrong).await.contains("403"));
        let short = format!("{xff}x-wisp-edge-secret: {}\r\n", &secret[..31]);
        assert!(status_line_with(addr, &short).await.contains("403"));
        let long = format!("{xff}x-wisp-edge-secret: {secret}x\r\n");
        assert!(status_line_with(addr, &long).await.contains("403"));
        let empty = format!("{xff}x-wisp-edge-secret: \r\n");
        assert!(status_line_with(addr, &empty).await.contains("403"));
        let right = format!("{xff}x-wisp-edge-secret: {secret}\r\n");
        assert!(status_line_with(addr, &right).await.contains("101"));
    }

    #[tokio::test]
    async fn malformed_forwarded_entry_does_not_fail_the_upgrade() {
        let secret = "e".repeat(32);
        let addr = spawn_listener_with(
            Arc::new(IpHashBans::new()),
            true,
            Some(Secret::new(secret.clone())),
        )
        .await;
        for xff in ["unknown", "1.2.3.4:5678", "[::1]:80", "1.2.3.4, , "] {
            let headers = format!("X-Forwarded-For: {xff}\r\nx-wisp-edge-secret: {secret}\r\n");
            let status = status_line_with(addr, &headers).await;
            assert!(status.contains("101"), "{xff:?} got {status:?}");
        }
    }

    #[tokio::test]
    async fn trusted_edge_without_a_configured_secret_ignores_the_header() {
        let addr = spawn_listener_with(Arc::new(IpHashBans::new()), true, None).await;
        let status = status_line_with(addr, "X-Forwarded-For: 203.0.113.7\r\n").await;
        assert!(status.contains("101"), "got {status:?}");
    }

    async fn spawn_listener_with_options(options: WispServerOptions) -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let bind_addr = probe.local_addr().expect("read reserved address");
        drop(probe);
        let ctx = Arc::new(H2ServeContext::with_template_and_auth(
            Arc::new(options),
            false,
            None,
            WispAuthRegistry::default(),
            Arc::new(DosGuard::new()),
            Arc::new(ConnectionLimiter::new()),
        ));
        let cfg = WsPlainListenerConfig {
            bind_addr,
            trust_forwarded_headers: false,
            trusted_edge_secret: None,
        };
        let listener = bind_ws_plain_listener(&cfg).expect("bind test listener");
        tokio::spawn(serve_bound_ws_plain_listener(listener, cfg, ctx));
        bind_addr
    }

    fn open_options() -> WispServerOptions {
        let mut options = WispServerOptions {
            block_blank_origins: false,
            ..WispServerOptions::default()
        };
        options.auth.required = false;
        options
    }

    /// Upgrades a v1 session and returns the socket past the response head.
    async fn upgraded(addr: SocketAddr) -> tokio::net::TcpStream {
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect test client");
        client.write_all(UPGRADE).await.expect("write upgrade");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            client
                .read_exact(&mut byte)
                .await
                .expect("read upgrade response");
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 101"),
            "{:?}",
            String::from_utf8_lossy(&head)
        );
        client
    }

    /// A masked client frame, as RFC 6455 requires of clients.
    fn client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let mut frame = vec![0x80 | opcode];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        frame
    }

    /// Reads one server frame (unmasked, short) and returns its opcode and
    /// payload, or `None` at end of stream.
    async fn server_frame(client: &mut tokio::net::TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        client.read_exact(&mut head).await.ok()?;
        let len = match head[1] & 0x7f {
            126 => {
                let mut ext = [0u8; 2];
                client.read_exact(&mut ext).await.ok()?;
                usize::from(u16::from_be_bytes(ext))
            }
            127 => {
                let mut ext = [0u8; 8];
                client.read_exact(&mut ext).await.ok()?;
                usize::try_from(u64::from_be_bytes(ext)).ok()?
            }
            short => usize::from(short),
        };
        let mut payload = vec![0u8; len];
        client.read_exact(&mut payload).await.ok()?;
        Some((head[0] & 0x0f, payload))
    }

    /// Wisp CONTINUE for stream 0: a valid packet the server ignores.
    const WISP_NOOP: &[u8] = &[0x03, 0, 0, 0, 0, 0, 0, 0, 0];

    #[tokio::test]
    async fn idle_upgraded_session_closes_after_idle_timeout() {
        let mut options = open_options();
        options.idle_timeout_ms = Some(400);
        let addr = spawn_listener_with_options(options).await;
        let mut client = upgraded(addr).await;
        client
            .write_all(&client_frame(0x2, WISP_NOOP))
            .await
            .expect("send first frame");
        let closed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while server_frame(&mut client).await.is_some() {}
        })
        .await;
        assert!(closed.is_ok(), "the idle session was never closed");
    }

    #[tokio::test]
    async fn silent_peer_is_dropped_even_with_a_stream_open() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(socket);
        });
        let mut options = open_options();
        options.idle_timeout_ms = Some(400);
        options.stream_idle_timeout_ms = Some(60_000);
        options.protocol_inspection = false;
        options.allow_direct_ip = true;
        options.allow_loopback_ips = true;
        options.allow_private_ips = true;
        options.port_whitelist = Some(vec![port]);
        let addr = spawn_listener_with_options(options).await;
        let mut client = upgraded(addr).await;
        let mut connect = vec![0x01, 1, 0, 0, 0, 0x01];
        connect.extend_from_slice(&port.to_le_bytes());
        connect.extend_from_slice(b"127.0.0.1");
        client
            .write_all(&client_frame(0x2, &connect))
            .await
            .expect("send CONNECT");
        // Pings go unanswered; the open stream does not keep the peer alive.
        let mut pings = 0;
        let closed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while let Some((opcode, _)) = server_frame(&mut client).await {
                if opcode == 0x9 {
                    pings += 1;
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "the silent peer was never dropped");
        assert!(pings > 0, "the server never pinged");
        hold.abort();
    }

    #[tokio::test]
    async fn answering_pings_keeps_a_quiet_session_open() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(socket);
        });
        let mut options = open_options();
        options.idle_timeout_ms = Some(400);
        options.stream_idle_timeout_ms = Some(60_000);
        options.protocol_inspection = false;
        options.allow_direct_ip = true;
        options.allow_loopback_ips = true;
        options.allow_private_ips = true;
        options.port_whitelist = Some(vec![port]);
        let addr = spawn_listener_with_options(options).await;
        let mut client = upgraded(addr).await;
        let mut connect = vec![0x01, 1, 0, 0, 0, 0x01];
        connect.extend_from_slice(&port.to_le_bytes());
        connect.extend_from_slice(b"127.0.0.1");
        client
            .write_all(&client_frame(0x2, &connect))
            .await
            .expect("send CONNECT");
        let answered = tokio::time::timeout(std::time::Duration::from_millis(1500), async {
            while let Some((opcode, payload)) = server_frame(&mut client).await {
                if opcode == 0x9 {
                    client
                        .write_all(&client_frame(0xA, &payload))
                        .await
                        .expect("send pong");
                }
            }
        })
        .await;
        assert!(answered.is_err(), "a session that answers pings was closed");
        hold.abort();
    }

    #[tokio::test]
    async fn full_listener_answers_503_and_upgrades_free_their_slot() {
        // The 429 below emits a report, which must not reach another test's
        // hook.
        let _turn = HOOK_TURN.lock().await;
        let mut options = open_options();
        options.max_connections = 1;
        let addr = spawn_listener_with_options(options).await;

        // The only pre-authentication slot is taken by a client that has not
        // sent its request yet.
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let busy = status_line(addr).await;
        assert!(busy.contains("503"), "got {busy:?}");

        // Once it upgrades, the slot is free again: the next client is
        // answered by the connection limiter instead.
        slow.write_all(UPGRADE).await.unwrap();
        let mut head = [0u8; 12];
        slow.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 101");
        let next = status_line(addr).await;
        assert!(next.contains("429"), "got {next:?}");
    }

    #[test]
    fn constant_time_eq_compares_whole_values() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abd", b"abc"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"", b"abc"));
    }

    #[tokio::test]
    async fn reports_origin_and_rate_limit_rejections() {
        let _turn = HOOK_TURN.lock().await;
        let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel();
        set_report_hook(Some(Arc::new(move |report: &Report| {
            let _ = report_tx.send((
                report.error_type,
                report.ip_hash.clone(),
                report.origin.clone(),
                report.limit_type.clone(),
            ));
        })));

        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let addr = probe.local_addr().expect("read reserved address");
        drop(probe);
        let mut options = WispServerOptions {
            origin_whitelist: Some(vec!["https://ok.test".to_owned()]),
            max_connection_starts_per_ip_per_minute: 1,
            ..WispServerOptions::default()
        };
        options.auth.required = false;
        let ctx = Arc::new(H2ServeContext::with_template_and_auth(
            Arc::new(options),
            false,
            None,
            WispAuthRegistry::default(),
            Arc::new(DosGuard::new()),
            Arc::new(ConnectionLimiter::new()),
        ));
        let cfg = WsPlainListenerConfig {
            bind_addr: addr,
            trust_forwarded_headers: false,
            trusted_edge_secret: None,
        };
        tokio::spawn(serve_ws_plain_listener(cfg, ctx));
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        async fn status_with_origin(addr: SocketAddr, origin: &str) -> String {
            let request = format!(
                "GET /wisp HTTP/1.1\r\nHost: localhost\r\nOrigin: {origin}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            );
            let mut client = tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect test client");
            client
                .write_all(request.as_bytes())
                .await
                .expect("write upgrade");
            let mut head = vec![0u8; 64];
            let read = client.read(&mut head).await.expect("read status line");
            String::from_utf8_lossy(&head[..read])
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        }

        let loopback = wisp_iphash::hash_client_ip_keyed(Some("127.0.0.1"));
        // Origin rejections happen before the start budget is spent.
        assert!(status_with_origin(addr, "https://evil.test")
            .await
            .contains("403"));
        assert_eq!(
            report_rx.recv().await,
            Some((
                ReportErrorType::OriginBlocked,
                loopback.clone(),
                Some("https://evil.test".to_owned()),
                None
            ))
        );
        // The first allowed connection spends the single start token.
        assert!(status_with_origin(addr, "https://ok.test")
            .await
            .contains("101"));
        assert!(status_with_origin(addr, "https://ok.test")
            .await
            .contains("429"));
        assert_eq!(
            report_rx.recv().await,
            Some((
                ReportErrorType::ConnectionRateLimited,
                loopback,
                Some("https://ok.test".to_owned()),
                Some("connection_start".to_owned())
            ))
        );
        set_report_hook(None);
    }
}

//! Plain RFC 6455 `ws://` listener. No TLS, no HTTP/2, no extended CONNECT —
//! HTTP/1.1 `Upgrade: websocket` over a TCP stream. Reuses
//! [`wisp_ws_h2::H2ServeContext`] for shared per-listener state.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use thiserror::Error;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Semaphore;
use tokio_websockets::{Config, Limits, ServerBuilder};
use tracing::{debug, info, warn};
use wisp_config::{
    is_client_ip_allowed, is_trusted_proxy_ip, resolve_client_ip_checked, IngressMode,
    WispWtServerOptions,
};
use wisp_dos::is_connection_start_allowed;
use wisp_iphash::hash_client_ip;
use wisp_origin::{is_origin_allowed, origin_from_headers, origin_headers_valid};
use wisp_reports::{emit_report, ConnectionContext, ReportErrorType, ReportInput, Transport};
use wisp_wisp_server::ServerContext;
use wisp_ws_h2::{listener::ConnectionView, websocket::serve_websocket, H2ServeContext};

use crate::ws_http1::{accept_upgrade, read_upgrade, reject_upgrade};

const WS_SOCKET_BUF: usize = 1024 * 1024;
const WS_FLUSH_THRESHOLD: usize = 1024 * 1024;

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
        }))
    }
}

pub async fn serve_ws_plain_listener(
    cfg: WsPlainListenerConfig,
    ctx: Arc<H2ServeContext>,
) -> Result<(), WsPlainListenerError> {
    let listener =
        bind_with_backlog(cfg.bind_addr).map_err(|source| WsPlainListenerError::Bind {
            addr: cfg.bind_addr,
            source,
        })?;
    info!(addr = %cfg.bind_addr, "wisp ws-plain listener ready");
    let preauth_limit = usize::try_from(ctx.options.max_connections)
        .ok()
        .filter(|limit| *limit > 0)
        .unwrap_or(4096);
    let preauth = Arc::new(Semaphore::new(preauth_limit));

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "ws-plain accept error");
                continue;
            }
        };
        tune_accepted(&tcp);
        let ctx = ctx.clone();
        let client_ip = peer.ip().to_string();
        let Ok(preauth_permit) = preauth.clone().try_acquire_owned() else {
            debug!(peer = %peer, "ws-plain pre-authentication cap reached");
            continue;
        };
        tokio::spawn(async move {
            let _preauth_permit = preauth_permit;
            if let Err(e) =
                handle_connection(tcp, client_ip, ctx, cfg.trust_forwarded_headers).await
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
) -> Result<(), std::io::Error> {
    let timeout =
        std::time::Duration::from_millis(ctx.options.handshake_timeout_ms.unwrap_or(10_000));
    let pending = tokio::time::timeout(timeout, read_upgrade(tcp))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upgrade timed out"))??;

    let path = pending.info.path.as_str();
    let Some(view) = ctx.context_for_path(path).await else {
        debug!("ws-plain: endpoint or authentication rejected");
        reject_upgrade(pending, "404 Not Found").await?;
        return Ok(());
    };

    if !origin_headers_valid(&pending.info.headers) {
        reject_upgrade(pending, "403 Forbidden").await?;
        return Ok(());
    }
    let origin = origin_from_headers(&pending.info.headers).map(|s| s.to_owned());
    if !is_origin_allowed(origin.as_deref(), &view.options) {
        debug!(?origin, "ws-plain: rejecting websocket: origin policy");
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
        if xff.is_none() || !is_trusted_proxy_ip(&client_ip, &view.options) {
            debug!(peer_ip = %client_ip, "ws-plain: rejecting untrusted edge peer");
            reject_upgrade(pending, "403 Forbidden").await?;
            return Ok(());
        }
        let Some(resolved) = resolve_client_ip_checked(&client_ip, xff.as_deref(), &view.options)
        else {
            debug!("ws-plain: rejecting invalid forwarded client chain");
            reject_upgrade(pending, "403 Forbidden").await?;
            return Ok(());
        };
        resolved
    } else {
        client_ip
    };
    if !is_client_ip_allowed(&client_ip, &view.options) {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: client IP policy");
        reject_upgrade(pending, "403 Forbidden").await?;
        return Ok(());
    }
    let client_hash = hash_client_ip(Some(&client_ip), None);
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
    let store = ctx.dos.clone();
    if !is_connection_start_allowed(&client_ip, &view.options, &store) {
        debug!(client_ip = %client_ip, "ws-plain: rejecting: connection-start rate");
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
            reject_upgrade(pending, "429 Too Many Requests").await?;
            return Ok(());
        }
    };

    let client_advertises_v2 = pending.info.advertises_v2;
    let io = accept_upgrade(pending).await?;
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
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let bind_addr = probe.local_addr().expect("read reserved address");
        drop(probe);
        let mut options = WispServerOptions {
            block_blank_origins: false,
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
            trust_forwarded_headers: false,
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
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect test client");
        client.write_all(UPGRADE).await.expect("write upgrade");
        let mut head = vec![0u8; 64];
        let read = client.read(&mut head).await.expect("read status line");
        String::from_utf8_lossy(&head[..read])
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    async fn refuses_banned_client_with_403_and_reports_it() {
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

        let banned = hash_client_ip(Some("127.0.0.1"), None).unwrap();
        bans.replace([banned.clone()]);
        assert!(status_line(addr).await.contains("403"));
        assert_eq!(report_rx.recv().await, Some(Some(banned)));

        bans.replace(Vec::<String>::new());
        assert!(status_line(addr).await.contains("101"));
        set_report_hook(None);
    }
}

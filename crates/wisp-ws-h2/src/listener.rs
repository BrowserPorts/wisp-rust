//! Per-connection driver: rustls-terminated TCP into hyper http2 server with
//! extended CONNECT enabled into service dispatch in `service.rs`.

use std::sync::{Arc, Mutex};

use hyper::server::conn::http2::Builder as Http2Builder;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use wisp_config::{
    endpoint_matches, endpoint_path_token, WispAuthRegistry, WispAuthTokenPolicy,
    WispServerOptions, WispWtServerOptions, WISP_BASE_LIMIT_PROFILE,
};
use wisp_dos::{is_ip_budget_allowed, ConnectionLimiter, DosGuard, MINUTE_MS};
use wisp_iphash::IpHashBans;
use wisp_wisp_server::{ProxyControllerTemplate, ServerOptions};

use crate::service::handle_request;

#[derive(Debug, Error)]
pub enum H2Error {
    #[error("hyper http2 server error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// Shared per-listener state. One instance is built at startup and cloned
/// (cheaply, via `Arc`) into each accepted connection.
#[derive(Clone)]
pub struct H2ServeContext {
    pub options: Arc<WispServerOptions>,
    pub server_options: Arc<ServerOptions>,
    /// Whether the proxy-control extension should be advertised. Driven by
    /// `[wisp.proxy_control]` config.
    pub proxy_control_enabled: bool,
    pub auth_registry: WispAuthRegistry,
    /// Optional shared provider-registry template. The per-connection
    /// service code calls `template.spawn()` to mint a fresh
    /// `Arc<ProxyController>` for each accepted client so per-connection
    /// state (rules, current proxy, rate-limiter) is never shared across
    /// tenants. `None` when proxy_control is disabled or no providers are
    /// registered.
    pub proxy_template: Option<Arc<ProxyControllerTemplate>>,
    pub dos: Arc<DosGuard>,
    pub connection_limiter: Arc<ConnectionLimiter>,
    /// Banned client IP hashes, checked before any Wisp traffic is served.
    /// Replaced wholesale at runtime; share one set across listeners with
    /// [`H2ServeContext::with_ip_bans`].
    pub ip_bans: Arc<IpHashBans>,
    pub shutdown: CancellationToken,
}

impl H2ServeContext {
    pub fn with_template_and_auth(
        options: Arc<WispServerOptions>,
        proxy_control_enabled: bool,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
        auth_registry: WispAuthRegistry,
        dos: Arc<DosGuard>,
        connection_limiter: Arc<ConnectionLimiter>,
    ) -> Self {
        let server_options = Arc::new(ServerOptions::from_wisp(&options, proxy_control_enabled));
        Self {
            options,
            server_options,
            proxy_control_enabled,
            auth_registry,
            proxy_template,
            dos,
            connection_limiter,
            ip_bans: Arc::new(IpHashBans::new()),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn with_ip_bans(mut self, ip_bans: Arc<IpHashBans>) -> Self {
        self.ip_bans = ip_bans;
        self
    }

    pub fn with_shutdown_token(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Build a context from the merged wisp config. If the WS sub-section
    /// supplies its own endpoint, swap it onto the base options so the
    /// service's `endpoint_matches` check honors it without disturbing the
    /// WT endpoint.
    pub fn from_wisp_wt_with_template_and_auth(
        cfg: &WispWtServerOptions,
        proxy_template: Option<Arc<ProxyControllerTemplate>>,
        auth_registry: WispAuthRegistry,
        dos: Arc<DosGuard>,
        connection_limiter: Arc<ConnectionLimiter>,
    ) -> Self {
        let mut base = cfg.base.clone();
        if let Some(ep) = &cfg.websocket.endpoint {
            base.endpoint = ep.clone();
        }
        let proxy_control_enabled = cfg
            .websocket
            .proxy_control_enabled
            .unwrap_or(cfg.proxy_control_enabled);
        Self::with_template_and_auth(
            Arc::new(base),
            proxy_control_enabled,
            proxy_template,
            auth_registry,
            dos,
            connection_limiter,
        )
    }

    /// Options for a connection that presents no token: the live `__base`
    /// profile, or the startup options. Checks that do not depend on a token
    /// (bans, client IP, origin, the token attempt budget) run against these
    /// before any token is resolved.
    pub fn base_options(&self) -> Arc<WispServerOptions> {
        self.auth_registry
            .profile(WISP_BASE_LIMIT_PROFILE)
            .map(Arc::new)
            .unwrap_or_else(|| self.options.clone())
    }

    /// Spends one token resolution from the client IP's budget, or `true`
    /// without spending anything when `path` carries no token. Resolving a
    /// token can call out to the host's handler, so an IP gets
    /// [`TOKEN_ATTEMPTS_PER_START`] times its connection-start rate in
    /// attempts and no more.
    pub fn token_attempt_allowed(
        &self,
        client_ip: &str,
        path: &str,
        base: &WispServerOptions,
    ) -> bool {
        if endpoint_path_token(path, &self.options.endpoint).is_none() {
            return true;
        }
        is_ip_budget_allowed(
            client_ip,
            "auth:token_attempt",
            base.max_connection_starts_per_ip_per_minute
                .saturating_mul(TOKEN_ATTEMPTS_PER_START),
            MINUTE_MS,
            &self.dos,
        )
    }

    pub async fn context_for_path(&self, path: &str) -> Option<ConnectionView> {
        self.view_for_path(path, None).await
    }

    /// [`Self::context_for_path`] reusing `base` (from
    /// [`Self::base_options`]) for a connection without a token.
    pub async fn view_for_path(
        &self,
        path: &str,
        base: Option<Arc<WispServerOptions>>,
    ) -> Option<ConnectionView> {
        let (options, auth_policy) =
            if let Some(token) = endpoint_path_token(path, &self.options.endpoint) {
                if !self.options.auth.token_path {
                    return None;
                }
                let resolved = tokio::time::timeout(
                    std::time::Duration::from_millis(self.options.auth.resolver_timeout_ms),
                    self.auth_registry.resolve(token.to_owned(), &self.options),
                )
                .await
                .ok()??;
                (Arc::new(resolved.options), resolved.policy)
            } else if endpoint_matches(path, &self.options.endpoint) {
                if self.options.auth.required {
                    return None;
                }
                let base = base.unwrap_or_else(|| self.base_options());
                (base, WispAuthTokenPolicy::default())
            } else {
                return None;
            };
        let server_options = if Arc::ptr_eq(&options, &self.options) {
            self.server_options.clone()
        } else {
            Arc::new(ServerOptions::from_wisp(
                &options,
                self.proxy_control_enabled,
            ))
        };
        Some(ConnectionView {
            options,
            server_options,
            auth_policy,
        })
    }

    pub fn path_is_endpoint_scope(&self, path: &str) -> bool {
        endpoint_matches(path, &self.options.endpoint)
            || endpoint_path_token(path, &self.options.endpoint).is_some()
    }
}

/// Token resolutions an IP may attempt per connection start it is allowed.
pub const TOKEN_ATTEMPTS_PER_START: u64 = 4;

#[derive(Clone)]
pub struct ConnectionView {
    pub options: Arc<WispServerOptions>,
    pub server_options: Arc<ServerOptions>,
    pub auth_policy: WispAuthTokenPolicy,
}

/// Drive one accepted connection. The caller is responsible for the TCP
/// accept and TLS termination — this function takes the post-TLS duplex
/// (any `tokio::io::AsyncRead + AsyncWrite + Unpin + Send + 'static` works,
/// e.g. `tokio_rustls::server::TlsStream<TcpStream>`).
///
/// `client_ip` is the peer-IP string (already extracted from the TCP
/// `peer_addr`); the service uses it for DoS / hashing.
pub async fn accept_h2_connection<I>(
    io: I,
    client_ip: String,
    ctx: Arc<H2ServeContext>,
) -> Result<(), H2Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    accept_h2_connection_with_preauth(io, client_ip, ctx, None).await
}

/// Like [`accept_h2_connection`], holding the listener's pre-authentication
/// slot `preauth` until the first WebSocket upgrade succeeds. A connection
/// that has not upgraded within the handshake timeout is closed, so idle
/// TLS connections cannot hold slots.
pub async fn accept_h2_connection_with_preauth<I>(
    io: I,
    client_ip: String,
    ctx: Arc<H2ServeContext>,
    preauth: Option<Box<dyn Send + Sync>>,
) -> Result<(), H2Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = Http2Builder::new(TokioExecutor::new());
    builder.enable_connect_protocol();

    let shutdown = ctx.shutdown.clone();
    let upgrade_deadline =
        std::time::Duration::from_millis(ctx.options.handshake_timeout_ms.unwrap_or(10_000).max(1));
    let awaiting_upgrade = preauth.is_some();
    let preauth = Arc::new(Mutex::new(preauth));
    let svc_preauth = preauth.clone();
    let svc = service_fn(move |req| {
        let ctx = ctx.clone();
        let client_ip = client_ip.clone();
        let preauth = svc_preauth.clone();
        async move {
            let response = handle_request(req, client_ip, ctx).await;
            if response
                .as_ref()
                .is_ok_and(|response| response.status() == hyper::StatusCode::OK)
            {
                preauth
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
            }
            response
        }
    });

    let conn = builder.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    let deadline = tokio::time::sleep(upgrade_deadline);
    tokio::pin!(deadline);
    let mut deadline_armed = awaiting_upgrade;
    let result = loop {
        tokio::select! {
            result = &mut conn => break result,
            _ = shutdown.cancelled() => return Ok(()),
            _ = &mut deadline, if deadline_armed => {
                deadline_armed = false;
                let upgraded = preauth
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_none();
                if !upgraded {
                    debug!("h2 connection made no upgrade in time, closing");
                    return Ok(());
                }
            }
        }
    };
    if let Err(err) = result {
        let msg = err.to_string();
        if is_clean_disconnect(&msg) {
            debug!(error = %msg, "h2 connection closed");
        } else {
            warn!(error = %msg, "h2 connection error");
        }
        return Err(H2Error::Hyper(err));
    }
    Ok(())
}

fn is_clean_disconnect(msg: &str) -> bool {
    msg.contains("connection reset")
        || msg.contains("broken pipe")
        || msg.contains("connection closed")
        || msg.contains("NO_ERROR")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Slot(Arc<AtomicBool>);

    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn connection_without_an_upgrade_is_closed_and_frees_its_slot() {
        let options = WispServerOptions {
            handshake_timeout_ms: Some(200),
            ..WispServerOptions::default()
        };
        let ctx = Arc::new(H2ServeContext::with_template_and_auth(
            Arc::new(options),
            false,
            None,
            WispAuthRegistry::default(),
            Arc::new(DosGuard::new()),
            Arc::new(ConnectionLimiter::new()),
        ));
        // The peer connects and never speaks.
        let (_client, server) = tokio::io::duplex(1024);
        let freed = Arc::new(AtomicBool::new(false));
        let slot: Box<dyn Send + Sync> = Box::new(Slot(freed.clone()));
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            accept_h2_connection_with_preauth(server, "127.0.0.1".to_owned(), ctx, Some(slot)),
        )
        .await
        .expect("a connection that never upgraded was kept open")
        .expect("closed cleanly");
        assert!(freed.load(Ordering::SeqCst));
    }
}

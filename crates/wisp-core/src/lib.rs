//! Public façade for embedding wisp-wt-rust as a library or driving it from
//! the `wispd` binary.
//!
//! Surface:
//!
//! - [`RuntimeConfig`] — fully-validated runtime config derived from the
//!   parsed TOML (`wisp_config::WispWtServerOptions`).
//! - [`Runtime`] — owns the cancellation token and the per-process shared
//!   state (DoS guard, banned IP hashes, advanced-extension flags). `Runtime::start` is the
//!   one-stop launch point.
//! - [`shutdown`] helpers that close the cancellation token and wait for
//!   sessions to drain up to `idle_timeout_ms`.
//!
//! The actual H3/WebTransport listener is wired in `wisp-server` once an
//! `MsQuicListener` is plumbed through. This module owns the orchestration
//! around it — config, cancellation, mode selection.

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use wisp_config::{
    build_wisp_wt_options, load_toml, ReloadingTokenResolver, WispAuthRegistry, WispAuthResolver,
    WispServerOptions, WispWtServerOptions,
};
use wisp_dos::{ConnectionLimiter, DosGuard};
use wisp_iphash::IpHashBans;
use wisp_tun::{TunnelConfig, TunnelService};

#[cfg(feature = "ws")]
use tokio::task::JoinHandle;
#[cfg(feature = "ws")]
use tracing::info;
#[cfg(feature = "ws")]
use wisp_config::IngressMode;
#[cfg(feature = "ws")]
use wisp_proxy_base::SharedProvider;
#[cfg(feature = "ws")]
use wisp_proxy_mullvad::{MullvadProxyConfig, MullvadProxyProvider};
#[cfg(feature = "ws")]
use wisp_proxy_resi::{ResidentialProxyConfig, ResidentialProxyProvider};
#[cfg(feature = "ws")]
use wisp_router::{
    bind_ws_h2_listener, bind_ws_plain_listener, serve_bound_ws_h2_listener,
    serve_bound_ws_plain_listener, WsH2ListenerConfig, WsH2ListenerError, WsPlainListenerConfig,
    WsPlainListenerError,
};
#[cfg(feature = "ws")]
use wisp_wisp_server::{ProxyControllerTemplate, ProxyRuntimePolicy};
#[cfg(feature = "ws")]
use wisp_ws_h2::H2ServeContext;

#[cfg(all(feature = "quic", feature = "ws"))]
use wisp_server::H3WsContext;
#[cfg(feature = "quic")]
pub use wisp_server::ServeHandle;
#[cfg(feature = "quic")]
use wisp_server::{serve as serve_listener, ServeError, ServeExtras};

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("config: {0}")]
    Config(#[from] wisp_config::ConfigError),
    #[error("rate-limit backend: {0}")]
    Dos(#[from] wisp_dos::DosError),
    #[error("ip hash key: {0}")]
    IpHashKey(#[from] wisp_iphash::KeyError),
    #[error("wisp_wt.enabled is false; not binding listener")]
    ListenerDisabled,
    #[error("ip_tunnel: {0}")]
    Tunnels(String),
    #[cfg(feature = "quic")]
    #[error("serve: {0}")]
    Serve(#[from] ServeError),
    #[cfg(feature = "ws")]
    #[error("ws-h2: {0}")]
    WsH2(#[from] WsH2ListenerError),
    #[cfg(feature = "ws")]
    #[error("ws-plain: {0}")]
    WsPlain(#[from] WsPlainListenerError),
}

/// One-shot bootstrap config. Built from `WispWtServerOptions` or read from
/// disk by [`RuntimeConfig::from_toml`].
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub options: Arc<WispWtServerOptions>,
    pub log_level: String,
}

impl RuntimeConfig {
    pub fn from_options(options: WispWtServerOptions) -> Result<Self, CoreError> {
        options.validate()?;
        Ok(Self {
            options: Arc::new(options),
            log_level: "info".to_owned(),
        })
    }

    pub fn from_toml(path: &Path) -> Result<Self, CoreError> {
        let parsed = load_toml(path)?;
        let options = build_wisp_wt_options(&parsed);
        Self::from_options(options)
    }

    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Install a global `fmt` subscriber filtered by [`RuntimeConfig::log_level`]
    /// (any `EnvFilter` directive string, e.g. `info` or `wisp_server=debug`).
    /// For embedders that have no subscriber of their own, such as the napi
    /// addon. `Ok(true)` means this call installed it, `Ok(false)` that a
    /// subscriber already existed and was left alone, and an invalid level is
    /// an error rather than a silent fallback.
    pub fn init_tracing(&self) -> Result<bool, String> {
        let filter = tracing_subscriber::EnvFilter::try_new(&self.log_level)
            .map_err(|error| format!("invalid log level {:?}: {error}", self.log_level))?;
        Ok(tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .is_ok())
    }
}

/// Live runtime handle. Drop to stop accepting new sessions and let in-flight
/// sessions finish; call [`Runtime::shutdown`] for a bounded drain.
pub struct Runtime {
    cfg: RuntimeConfig,
    cancel: CancellationToken,
    dos: Arc<DosGuard>,
    connection_limiter: Arc<ConnectionLimiter>,
    ip_bans: Arc<IpHashBans>,
    auth: WispAuthRegistry,
    file_auth: Option<Arc<ReloadingTokenResolver>>,
    #[cfg(feature = "ws")]
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
    tunnels: Option<Arc<TunnelService>>,
}

impl Runtime {
    /// Build the runtime state. Does **not** start a listener — call
    /// [`Runtime::bind`] for that.
    pub fn start(cfg: RuntimeConfig) -> Result<Self, CoreError> {
        // Read WISP_IP_HASH_KEY now so a malformed key stops the start, and an
        // unset one is warned about once at startup.
        wisp_iphash::init_process_key()?;
        let dos = Arc::new(DosGuard::from_options(&cfg.options.base)?);
        #[cfg(feature = "ws")]
        wisp_wisp_server::set_max_buffered_bytes_total(cfg.options.base.max_buffered_bytes_total);
        #[cfg(feature = "ws")]
        let proxy_template = build_proxy_template(&cfg.options);
        if !cfg.options.enabled {
            warn!("wispd: wisp_wt.enabled = false — listener will not be opened");
        }
        let auth = WispAuthRegistry::default();
        let file_auth = cfg
            .options
            .base
            .auth
            .token_file
            .as_ref()
            .map(ReloadingTokenResolver::load)
            .transpose()?
            .map(Arc::new);
        if let Some(resolver) = &file_auth {
            auth.set_file_resolver(resolver.clone());
        }
        Ok(Self {
            cfg,
            cancel: CancellationToken::new(),
            dos,
            connection_limiter: Arc::new(ConnectionLimiter::new()),
            ip_bans: Arc::new(IpHashBans::new()),
            auth,
            file_auth,
            #[cfg(feature = "ws")]
            proxy_template,
            tunnels: None,
        })
    }

    /// Starts the IP tunnel engine when `[ip_tunnel]` is enabled: on Linux
    /// one network namespace per tunnel, which needs `CAP_NET_ADMIN` and
    /// `CAP_SYS_ADMIN`; without them, or on another system, the start fails
    /// instead of offering tunnels it cannot build. Call before binding
    /// listeners; a no-op when the table is off.
    pub async fn start_tunnels(&mut self) -> Result<(), CoreError> {
        let opts = &self.cfg.options;
        if !opts.ip_tunnel.enabled {
            return Ok(());
        }
        let cfg = TunnelConfig::from_options(&opts.ip_tunnel, &opts.base)?;
        #[cfg(target_os = "linux")]
        {
            let backend = wisp_tun::netns::NetnsBackend::start(Arc::new(cfg.clone()))
                .await
                .map_err(|e| CoreError::Tunnels(e.to_string()))?;
            self.tunnels = Some(TunnelService::new(cfg, backend, self.dos.clone()));
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cfg;
            Err(CoreError::Tunnels(
                wisp_tun::privileges::check().unwrap_err(),
            ))
        }
    }

    /// Uses a tunnel engine the caller built, for embedders and tests that
    /// bring their own backend. Call before binding listeners.
    pub fn with_tunnels(mut self, tunnels: Arc<TunnelService>) -> Self {
        self.tunnels = Some(tunnels);
        self
    }

    /// The IP tunnel engine, when one is running.
    pub fn tunnels(&self) -> Option<Arc<TunnelService>> {
        self.tunnels.clone()
    }

    fn warn_if_tunnels_missing(&self) {
        if self.cfg.options.ip_tunnel.enabled && self.tunnels.is_none() {
            warn!("ip_tunnel.enabled is set but the tunnel engine was not started; tunnels are not offered");
        }
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn dos(&self) -> Arc<DosGuard> {
        self.dos.clone()
    }

    /// Number of client connections currently open across every transport.
    pub fn active_connections(&self) -> u64 {
        self.connection_limiter.active()
    }

    /// Use a ban set the caller already owns, so bans accepted before the
    /// runtime exists carry over. Call before binding any listener; listeners
    /// bound earlier keep the set they were given.
    pub fn with_ip_bans(mut self, ip_bans: Arc<IpHashBans>) -> Self {
        self.ip_bans = ip_bans;
        self
    }

    /// The live banned-IP-hash set. Replacing its contents takes effect for
    /// the next connection on every listener, with no restart.
    pub fn ip_bans(&self) -> Arc<IpHashBans> {
        self.ip_bans.clone()
    }

    pub fn auth_registry(&self) -> WispAuthRegistry {
        self.auth.clone()
    }

    pub fn set_auth_resolver(&self, resolver: Arc<dyn WispAuthResolver>) {
        self.auth.set_resolver(resolver);
    }

    pub fn clear_auth_resolver(&self) {
        self.auth.clear_resolver();
    }

    pub fn reload_auth_tokens(&self) -> Result<bool, CoreError> {
        let Some(resolver) = &self.file_auth else {
            return Ok(false);
        };
        resolver.reload()?;
        Ok(true)
    }

    pub fn register_limit_profile(&self, name: String, options: WispServerOptions) -> bool {
        // The process byte budget follows the base limits only; a named
        // profile cannot raise it for everyone.
        #[cfg(feature = "ws")]
        if name == wisp_config::WISP_BASE_LIMIT_PROFILE {
            wisp_wisp_server::set_max_buffered_bytes_total(options.max_buffered_bytes_total);
        }
        self.auth.register_profile(name, options)
    }

    pub fn remove_limit_profile(&self, name: &str) -> Option<WispServerOptions> {
        self.auth.remove_profile(name)
    }

    pub fn limit_profile(&self, name: &str) -> Option<WispServerOptions> {
        self.auth.profile(name)
    }

    pub fn list_limit_profiles(&self) -> Vec<(String, WispServerOptions)> {
        self.auth.list_profiles()
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.cfg
    }

    #[cfg(feature = "ws")]
    pub fn proxy_template(&self) -> Option<Arc<ProxyControllerTemplate>> {
        self.proxy_template.clone()
    }

    /// Trigger graceful shutdown and wait up to `idle_timeout_ms` for
    /// sessions to finish on their own.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let drain_ms = self.cfg.options.base.idle_timeout_ms.unwrap_or(15_000);
        let deadline = time::Instant::now() + Duration::from_millis(drain_ms);
        while self.connection_limiter.active() != 0 && time::Instant::now() < deadline {
            time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Bind the msquic listener and start dispatching wisp-wt sessions.
    /// Returns the live [`ServeHandle`]; drop it (or call `shutdown`) to stop.
    /// Separate from [`Runtime::start`] so unit tests can build a runtime
    /// without a real cert/key on disk.
    #[cfg(feature = "quic")]
    pub async fn bind(&self) -> Result<ServeHandle, CoreError> {
        if !self.cfg.options.enabled {
            warn!("wispd: wisp_wt.enabled = false — refusing to bind listener");
            return Err(CoreError::ListenerDisabled);
        }
        self.warn_if_tunnels_missing();
        #[cfg(feature = "ws")]
        let ws_ctx = if self.cfg.options.websocket.enabled {
            let template = self.proxy_template.clone();
            Some(Arc::new(
                H3WsContext::from_wisp_wt_with_template_and_auth(
                    &self.cfg.options,
                    template,
                    self.auth.clone(),
                    self.dos.clone(),
                    self.connection_limiter.clone(),
                )
                .with_ip_bans(self.ip_bans.clone())
                .with_shutdown_token(self.cancel.clone())
                .with_tunnels(self.tunnels.clone()),
            ))
        } else {
            None
        };
        #[cfg(not(feature = "ws"))]
        let ws_ctx = None;

        #[cfg(feature = "ws")]
        let extras = ServeExtras {
            proxy_template: self.proxy_template.clone(),
            ip_bans: self.ip_bans.clone(),
            tunnels: self.tunnels.clone(),
        };
        #[cfg(not(feature = "ws"))]
        let extras = ServeExtras {
            ip_bans: self.ip_bans.clone(),
            tunnels: self.tunnels.clone(),
            ..ServeExtras::default()
        };
        let handle = serve_listener(
            self.cfg.options.clone(),
            self.dos.clone(),
            self.cancel.clone(),
            ws_ctx,
            self.connection_limiter.clone(),
            self.auth.clone(),
            extras,
        )
        .await?;
        Ok(handle)
    }

    /// Bind the WS-over-H2 listener if `[wisp_websocket].enabled = true`.
    /// Returns `Ok(None)` when the section is absent or disabled so callers
    /// can run the WT side alone. The socket is bound (and the TLS identity
    /// loaded) before this returns, so those errors come back as `Err`. The returned `JoinHandle` resolves when
    /// the accept loop exits (typically: process shutdown). The cancellation
    /// token from this runtime is honored — `Runtime::shutdown` will drop
    /// the listener.
    #[cfg(feature = "ws")]
    pub fn bind_ws(&self) -> Result<Option<JoinHandle<()>>, CoreError> {
        let opts = &self.cfg.options;
        if !opts.websocket.enabled {
            return Ok(None);
        }
        self.warn_if_tunnels_missing();
        let template = self.proxy_template.clone();
        let ctx = Arc::new(
            H2ServeContext::from_wisp_wt_with_template_and_auth(
                opts,
                template,
                self.auth.clone(),
                self.dos.clone(),
                self.connection_limiter.clone(),
            )
            .with_ip_bans(self.ip_bans.clone())
            .with_shutdown_token(self.cancel.clone())
            .with_tunnels(self.tunnels.clone()),
        );
        let cancel = self.cancel.clone();

        if matches!(
            opts.websocket.ingress_mode,
            IngressMode::TrustedEdge | IngressMode::DirectPlain
        ) {
            let Some(cfg) = WsPlainListenerConfig::try_from_wisp_wt(opts)? else {
                return Ok(None);
            };
            let bind_addr = cfg.bind_addr;
            // Bound here, not in the task, so a bind error fails the start.
            let listener = bind_ws_plain_listener(&cfg)?;
            info!(addr = %bind_addr, "wispd: launching ws-plain listener");
            let handle = tokio::spawn(async move {
                tokio::select! {
                    res = serve_bound_ws_plain_listener(listener, cfg, ctx) => {
                        if let Err(e) = res {
                            warn!(addr = %bind_addr, error = %e, "ws-plain listener exited");
                        }
                    }
                    _ = cancel.cancelled() => {
                        info!(addr = %bind_addr, "ws-plain listener cancelled");
                    }
                }
            });
            return Ok(Some(handle));
        }

        let Some(cfg) = WsH2ListenerConfig::try_from_wisp_wt(opts)? else {
            return Ok(None);
        };
        let bind_addr = cfg.bind_addr;
        let (listener, acceptor) = bind_ws_h2_listener(&cfg)?;
        info!(addr = %bind_addr, "wispd: launching ws-h2 listener");
        let handle = tokio::spawn(async move {
            tokio::select! {
                res = serve_bound_ws_h2_listener(listener, acceptor, cfg, ctx) => {
                    if let Err(e) = res {
                        warn!(addr = %bind_addr, error = %e, "ws-h2 listener exited");
                    }
                }
                _ = cancel.cancelled() => {
                    info!(addr = %bind_addr, "ws-h2 listener cancelled");
                }
            }
        });
        Ok(Some(handle))
    }
}

/// Build the shared proxy provider template from config. Returns `None`
/// when no provider is enabled — the providers (Mullvad relay cache,
/// reqwest client) are non-trivial to construct, so we skip when nothing
/// can use them. The order of providers determines which one wins
/// `can_resolve` ties: explicit config (Mullvad first by tradition) before
/// fallbacks. The template is shared across all connections; each
/// connection calls `template.spawn()` to mint its own per-connection
/// controller with isolated state.
#[cfg(feature = "ws")]
pub fn build_proxy_template(opts: &WispWtServerOptions) -> Option<Arc<ProxyControllerTemplate>> {
    let ws_proxy_control = opts
        .websocket
        .proxy_control_enabled
        .unwrap_or(opts.proxy_control_enabled);
    if !(opts.proxy_control_enabled || ws_proxy_control) {
        return None;
    }
    let mut providers: Vec<SharedProvider> = Vec::new();
    if let Some(mv) = &opts.mullvad {
        providers.push(Arc::new(MullvadProxyProvider::new(Some(
            MullvadProxyConfig {
                relay_api: mv.relay_api.clone(),
                wireproxy_socks5: mv.wireproxy_socks5.clone(),
            },
        ))));
    }
    if let Some(re) = &opts.resi {
        let cfg = ResidentialProxyConfig {
            bearer_token: re.bearer_token.clone().unwrap_or_default(),
            wireproxy_socks5: re.wireproxy_socks5.clone(),
            cookie: re.cookie.clone(),
            api_base: re.api_base.clone(),
            country: re.country.clone(),
            ip_type: re.ip_type.clone(),
        };
        providers.push(Arc::new(ResidentialProxyProvider::new(Some(cfg))));
    }
    if providers.is_empty() {
        return None;
    }
    let template = ProxyControllerTemplate::new(providers);
    if opts.base.force_proxy {
        template.set_policy(ProxyRuntimePolicy {
            force_proxy: true,
            default_provider: if opts.resi.is_some() {
                Some("resi".to_owned())
            } else if opts.mullvad.is_some() {
                Some("mullvad".to_owned())
            } else {
                None
            },
            default_country: opts.resi.as_ref().map(|cfg| cfg.country.clone()),
            default_city: None,
            default_ip_type: opts.resi.as_ref().map(|cfg| cfg.ip_type.clone()),
        });
    }
    Some(Arc::new(template))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_builds_from_defaults() {
        let cfg = RuntimeConfig::from_options(WispWtServerOptions::default())
            .expect("default options validate");
        let rt = Runtime::start(cfg).expect("runtime start");
        let _ = rt.dos();
        let _ = rt.cancel_token();
        assert!(!rt.cancel_token().is_cancelled());
    }

    #[tokio::test]
    async fn shutdown_cancels_token_and_drains() {
        let mut opts = WispWtServerOptions::default();
        opts.base.idle_timeout_ms = Some(10);
        let cfg = RuntimeConfig::from_options(opts).expect("default options validate");
        let rt = Runtime::start(cfg).unwrap();
        let tok = rt.cancel_token();
        assert!(!tok.is_cancelled());
        rt.shutdown().await;
        assert!(tok.is_cancelled());
    }

    #[cfg(feature = "ws")]
    #[tokio::test]
    async fn bind_ws_returns_the_bind_error() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let port = taken.local_addr().expect("reserved address").port();
        let mut opts = WispWtServerOptions::default();
        opts.websocket.enabled = true;
        opts.websocket.ingress_mode = IngressMode::DirectPlain;
        opts.websocket.host = "127.0.0.1".to_owned();
        opts.websocket.port = port;
        let rt = Runtime::start(RuntimeConfig::from_options(opts).expect("options validate"))
            .expect("runtime start");
        let err = rt.bind_ws().expect_err("the port is taken");
        assert!(
            matches!(err, CoreError::WsPlain(WsPlainListenerError::Bind { .. })),
            "got {err:?}"
        );
        drop(taken);
    }

    #[test]
    fn bans_are_shared_and_live() {
        let rt =
            Runtime::start(RuntimeConfig::from_options(WispWtServerOptions::default()).unwrap())
                .unwrap();
        let bans = rt.ip_bans();
        assert!(!bans.is_banned(Some("abc")));
        rt.ip_bans().replace(["abc"]);
        assert!(bans.is_banned(Some("abc")), "every handle sees the swap");
        assert_eq!(rt.active_connections(), 0);
    }

    #[test]
    fn with_ip_bans_adopts_an_existing_set() {
        let owned = Arc::new(IpHashBans::new());
        owned.replace(["abc"]);
        let rt =
            Runtime::start(RuntimeConfig::from_options(WispWtServerOptions::default()).unwrap())
                .unwrap()
                .with_ip_bans(owned.clone());
        assert!(rt.ip_bans().is_banned(Some("abc")));
        owned.replace(["def"]);
        assert!(rt.ip_bans().is_banned(Some("def")));
        assert!(!rt.ip_bans().is_banned(Some("abc")));
    }

    #[tokio::test]
    async fn tunnels_stay_off_unless_enabled() {
        let mut rt =
            Runtime::start(RuntimeConfig::from_options(WispWtServerOptions::default()).unwrap())
                .unwrap();
        rt.start_tunnels()
            .await
            .expect("a disabled table starts nothing");
        assert!(rt.tunnels().is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn tunnels_are_refused_off_linux() {
        let mut opts = WispWtServerOptions::default();
        opts.ip_tunnel.enabled = true;
        let mut rt = Runtime::start(RuntimeConfig::from_options(opts).unwrap()).unwrap();
        assert!(matches!(
            rt.start_tunnels().await,
            Err(CoreError::Tunnels(_))
        ));
    }

    #[test]
    fn from_options_rejects_zero_max_proxy_rules() {
        let mut opts = WispWtServerOptions::default();
        opts.base.max_proxy_rules_per_connection = 0;
        let res = RuntimeConfig::from_options(opts);
        assert!(matches!(res, Err(CoreError::Config(_))));
    }

    #[cfg(feature = "ws")]
    #[test]
    fn build_proxy_template_honors_websocket_override() {
        use wisp_config::MullvadProviderConfig;

        let mut opts = WispWtServerOptions {
            proxy_control_enabled: false,
            mullvad: Some(MullvadProviderConfig {
                relay_api: "https://example.test/relays".to_owned(),
                wireproxy_socks5: None,
            }),
            ..WispWtServerOptions::default()
        };
        opts.websocket.proxy_control_enabled = Some(true);
        assert!(
            build_proxy_template(&opts).is_some(),
            "WS-only proxy_control override must still build providers"
        );

        opts.websocket.proxy_control_enabled = Some(false);
        assert!(
            build_proxy_template(&opts).is_none(),
            "disabled override with global off must skip providers"
        );
    }
}

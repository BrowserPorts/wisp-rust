//! Public façade for embedding wisp-wt-rust as a library or driving it from
//! the `wispd` binary.
//!
//! Surface:
//!
//! - [`RuntimeConfig`] — fully-validated runtime config derived from the
//!   parsed TOML (`wisp_config::WispWtServerOptions`).
//! - [`Runtime`] — owns the cancellation token and the per-process shared
//!   state (DoS guard, advanced-extension flags). `Runtime::start` is the
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
use tracing::{info, warn};
use wisp_config::{
    build_wisp_wt_options, load_toml, WispAuthRegistry, WispAuthResolver, WispServerOptions,
    WispWtServerOptions,
};
use wisp_dos::DosGuard;

#[cfg(feature = "ws")]
use tokio::task::JoinHandle;
#[cfg(feature = "ws")]
use wisp_proxy_base::SharedProvider;
#[cfg(feature = "ws")]
use wisp_proxy_mullvad::{MullvadProxyConfig, MullvadProxyProvider};
#[cfg(feature = "ws")]
use wisp_proxy_resi::{ResidentialProxyConfig, ResidentialProxyProvider};
#[cfg(feature = "ws")]
use wisp_router::{
    serve_ws_h2_listener, serve_ws_plain_listener, WsH2ListenerConfig, WsH2ListenerError,
    WsPlainListenerConfig, WsPlainListenerError,
};
#[cfg(feature = "ws")]
use wisp_wisp_server::{ProxyControllerTemplate, ProxyRuntimePolicy};
#[cfg(feature = "ws")]
use wisp_ws_h2::H2ServeContext;

#[cfg(all(feature = "quic", feature = "ws"))]
use wisp_server::H3WsContext;
#[cfg(feature = "quic")]
use wisp_server::{serve as serve_listener, ServeError, ServeHandle};

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("config: {0}")]
    Config(#[from] wisp_config::ConfigError),
    #[error("runtime: {0}")]
    Runtime(String),
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
    pub bench_mode: bool,
    pub log_level: String,
}

impl RuntimeConfig {
    pub fn from_options(options: WispWtServerOptions) -> Result<Self, CoreError> {
        options.base.validate()?;
        Ok(Self {
            options: Arc::new(options),
            bench_mode: false,
            log_level: "info".to_owned(),
        })
    }

    pub fn from_toml(path: &Path) -> Result<Self, CoreError> {
        let parsed = load_toml(path)?;
        let options = build_wisp_wt_options(&parsed);
        Self::from_options(options)
    }

    pub fn with_bench_mode(mut self, on: bool) -> Self {
        self.bench_mode = on;
        self
    }

    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }
}

/// Live runtime handle. Drop to stop accepting new sessions and let in-flight
/// sessions finish; call [`Runtime::shutdown`] for a bounded drain.
pub struct Runtime {
    cfg: RuntimeConfig,
    cancel: CancellationToken,
    dos: Arc<DosGuard>,
    auth: WispAuthRegistry,
    #[cfg(feature = "ws")]
    proxy_template: Option<Arc<ProxyControllerTemplate>>,
}

impl Runtime {
    /// Build the runtime state. Does **not** start a listener — call
    /// [`Runtime::bind`] for that.
    pub fn start(cfg: RuntimeConfig) -> Result<Self, CoreError> {
        let dos = Arc::new(DosGuard::new());
        #[cfg(feature = "ws")]
        let proxy_template = build_proxy_template(&cfg.options);
        if cfg.bench_mode {
            info!("wispd: bench mode enabled — skipping protocol inspection, raising connection limits");
        }
        if !cfg.options.enabled {
            warn!("wispd: wisp_wt.enabled = false — listener will not be opened");
        }
        Ok(Self {
            cfg,
            cancel: CancellationToken::new(),
            dos,
            auth: WispAuthRegistry::default(),
            #[cfg(feature = "ws")]
            proxy_template,
        })
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn dos(&self) -> Arc<DosGuard> {
        self.dos.clone()
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

    pub fn register_limit_profile(&self, name: String, options: WispServerOptions) -> bool {
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
        time::sleep(Duration::from_millis(drain_ms)).await;
    }

    /// Bind the msquic listener and start dispatching wisp-wt sessions.
    /// Returns the live [`ServeHandle`]; drop it (or call `shutdown`) to stop.
    /// Separate from [`Runtime::start`] so unit tests can build a runtime
    /// without a real cert/key on disk.
    #[cfg(feature = "quic")]
    pub async fn bind(&self) -> Result<ServeHandle, CoreError> {
        if !self.cfg.options.enabled {
            warn!("wispd: wisp_wt.enabled = false — refusing to bind listener");
            return Err(CoreError::Runtime(
                "wisp_wt.enabled is false; not binding".to_owned(),
            ));
        }
        // When the `ws` feature is on AND the websocket section is enabled,
        // build an H3WsContext so the same H3 listener also services
        // RFC 9220 WS-over-H3 (extended CONNECT :protocol=websocket). The
        // proxy controller is shared with the H2 WS path so policy state
        // (live rules, provider rotation) stays consistent across transports.
        #[cfg(feature = "ws")]
        let ws_ctx = if self.cfg.options.websocket.enabled {
            let template = self.proxy_template.clone();
            Some(Arc::new(H3WsContext::from_wisp_wt_with_template_and_auth(
                &self.cfg.options,
                template,
                self.auth.clone(),
            )))
        } else {
            None
        };
        #[cfg(not(feature = "ws"))]
        let ws_ctx = None;

        let handle = serve_listener(
            self.cfg.options.clone(),
            self.dos.clone(),
            self.cancel.clone(),
            ws_ctx,
        )
        .await?;
        Ok(handle)
    }

    /// Bind the WS-over-H2 listener if `[wisp_websocket].enabled = true`.
    /// Returns `Ok(None)` when the section is absent or disabled so callers
    /// can run the WT side alone. The returned `JoinHandle` resolves when
    /// the accept loop exits (typically: process shutdown). The cancellation
    /// token from this runtime is honored — `Runtime::shutdown` will drop
    /// the listener.
    #[cfg(feature = "ws")]
    pub fn bind_ws(&self) -> Result<Option<JoinHandle<()>>, CoreError> {
        let opts = &self.cfg.options;
        if !opts.websocket.enabled {
            return Ok(None);
        }
        let template = self.proxy_template.clone();
        let ctx = Arc::new(H2ServeContext::from_wisp_wt_with_template_and_auth(
            opts,
            template,
            self.auth.clone(),
        ));
        let cancel = self.cancel.clone();

        if opts.websocket.plain {
            let Some(cfg) = WsPlainListenerConfig::try_from_wisp_wt(opts)? else {
                return Ok(None);
            };
            let bind_addr = cfg.bind_addr;
            info!(addr = %bind_addr, "wispd: launching ws-plain listener");
            let handle = tokio::spawn(async move {
                tokio::select! {
                    res = serve_ws_plain_listener(cfg, ctx) => {
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
        info!(addr = %bind_addr, "wispd: launching ws-h2 listener");
        let handle = tokio::spawn(async move {
            tokio::select! {
                res = serve_ws_h2_listener(cfg, ctx) => {
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
    if !opts.proxy_control_enabled {
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

    #[test]
    fn from_options_rejects_zero_max_proxy_rules() {
        let mut opts = WispWtServerOptions::default();
        opts.base.max_proxy_rules_per_connection = 0;
        let res = RuntimeConfig::from_options(opts);
        assert!(matches!(res, Err(CoreError::Config(_))));
    }
}

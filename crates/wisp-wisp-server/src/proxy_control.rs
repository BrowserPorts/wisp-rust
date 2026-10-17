//! WISP_PROXY_CONTROL (extension 0x03) text-channel router.
//!
//! Text frames on the WebSocket carry JSON requests; the router dispatches
//! by `type` field, mutates [`ControllerState`], and returns a JSON reply.
//! The connection driver wraps each reply into one text-frame response.
//!
//! Provider implementations live in separate crates (e.g.
//! `wisp-proxy-mullvad`, `wisp-proxy-resi`) — the runtime/main wires
//! the concrete `Vec<SharedProvider>` into a [`ProxyControllerTemplate`]
//! once at startup, and per-connection code calls [`ProxyControllerTemplate::spawn`]
//! to mint a fresh [`ProxyController`] for each accepted client.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::net::TcpStream;
use tracing::warn;
use url::Url;

use wisp_dos::{is_ip_budget_allowed, DosGuard};
use wisp_proxy::HostPolicy;
use wisp_proxy_base::{
    open_proxy_tcp_socket_addr, ActiveProxy, ActiveProxyMetadata, ProxyLocationSelection,
    ProxyProvider, ProxyProviderLocations, ProxyProviderRequest, ProxyResolveError,
    ProxyTunnelError, SharedProvider,
};

use crate::stream::{connect_checked_tcp, ConnectError};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Debug, Clone, Copy)]
pub struct ProxyControlLimits {
    pub max_rules: usize,
    pub max_reply_bytes: usize,
    pub max_field_bytes: usize,
    pub upstream_ops_per_second: NonZeroU32,
    pub upstream_burst: NonZeroU32,
    pub mutation_ops_per_second: NonZeroU32,
    pub mutation_burst: NonZeroU32,
}

impl Default for ProxyControlLimits {
    fn default() -> Self {
        Self {
            max_rules: 256,
            max_reply_bytes: 64 * 1024,
            max_field_bytes: 256,
            upstream_ops_per_second: NonZeroU32::new(8).expect("nonzero"),
            upstream_burst: NonZeroU32::new(16).expect("nonzero"),
            mutation_ops_per_second: NonZeroU32::new(64).expect("nonzero"),
            mutation_burst: NonZeroU32::new(320).expect("nonzero"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProxyControlRequest {
    ProxySet {
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        country: Option<String>,
        #[serde(default)]
        city: Option<String>,
        #[serde(default)]
        ip_type: Option<String>,
    },
    ProxyRotate,
    ProxyOn,
    ProxyOff,
    ProxyMode {
        mode: String,
    },
    ProxyRule {
        domain: String,
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        country: Option<String>,
        #[serde(default)]
        city: Option<String>,
        #[serde(default)]
        ip_type: Option<String>,
    },
    ProxyRuleRemove {
        domain: String,
    },
    ProxyLocations {
        #[serde(default)]
        provider: Option<String>,
    },
    ProxyListProviders,
}

/// Route configuration accepted from the runtime bridge. Field names
/// serialize in camelCase because the bridge sends `routeId` / `targetUrls`
/// / `ipType`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRouteConfig {
    pub route_id: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub target_urls: Vec<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub ip_type: Option<String>,
}

/// Route snapshot returned to the runtime bridge. camelCase for the same
/// bridge-boundary reason as [`ProxyRouteConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRouteSnapshot {
    pub route_id: String,
    pub domains: Vec<String>,
    pub target_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<ActiveProxyMetadata>,
}

/// Caps on proxy switches (`proxy_set`, `proxy_rotate`, and the first
/// resolution of a rule), the operations that can claim a fresh paid exit.
/// `None` leaves that scope unlimited. The per-IP and per-token counters share
/// one window per key across connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyHopLimits {
    pub max_per_connection: Option<u32>,
    pub max_per_ip_per_day: Option<u32>,
    pub max_per_token_per_day: Option<u32>,
}

impl Default for ProxyHopLimits {
    fn default() -> Self {
        Self {
            max_per_connection: Some(64),
            max_per_ip_per_day: Some(256),
            max_per_token_per_day: Some(512),
        }
    }
}

const HOP_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_HOP_KEYS: usize = 4096;
const MAX_HOP_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, Copy)]
struct HopWindow {
    started: Instant,
    count: u32,
}

/// Which counter refused a hop, and its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HopDenied {
    scope: &'static str,
    limit: u32,
}

/// Runtime proxy policy exchanged with the runtime bridge. camelCase for the
/// same bridge-boundary reason as [`ProxyRouteConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRuntimePolicy {
    #[serde(default)]
    pub force_proxy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ip_type: Option<String>,
}

#[derive(Debug, Error)]
pub enum ProxyControlError {
    #[error("route_id is required")]
    MissingRouteId,
    #[error("route requires at least one domain or target URL")]
    MissingRouteTarget,
    #[error("route target URL is invalid: {0}")]
    InvalidRouteTarget(String),
}

#[derive(Debug, Error)]
pub enum ProxyConnectError {
    #[error("proxy resolve failed: {0}")]
    Resolve(#[from] ProxyResolveError),
    #[error("proxy tunnel failed: {0}")]
    Tunnel(#[from] ProxyTunnelError),
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("no provider matches the request")]
    NoProvider,
    #[error("provider is not configured")]
    ProviderNotConfigured,
    #[error("provider returned no proxy")]
    NoProxy,
    #[error("egress IP is blocked")]
    BlockedEgress,
    #[error("provider requires authentication")]
    ProviderRequiresAuthentication,
    #[error("proxy hop limit reached")]
    HopLimitExceeded,
}

#[derive(Debug, Default)]
struct ControllerState {
    enabled: bool,
    mode: String,
    current: Option<ActiveProxy>,
    rules: HashMap<String, ProxyProviderRequest>,
    /// Proxy resolved for a rule's request. Kept apart from `current` and
    /// `enabled` so one matching rule never turns proxying on for the rest of
    /// the connection.
    rule_proxies: Vec<(ProxyProviderRequest, ActiveProxy)>,
    client_ip: Option<String>,
    token_key: Option<String>,
    session_hops: u32,
}

#[derive(Debug, Clone)]
struct SharedProxyRoute {
    route_id: String,
    domains: Vec<String>,
    target_urls: Vec<String>,
    request: ProxyProviderRequest,
    active: Option<ActiveProxy>,
}

#[derive(Debug, Default)]
struct SharedControllerState {
    routes: HashMap<String, SharedProxyRoute>,
    domain_routes: HashMap<String, String>,
    blocked_egress_ips: HashSet<String>,
    policy: ProxyRuntimePolicy,
    hop_limits: ProxyHopLimits,
    hops: HashMap<String, HopWindow>,
}

impl SharedControllerState {
    fn hop_count(&self, key: &str, now: Instant) -> u32 {
        self.hops
            .get(key)
            .filter(|w| now.duration_since(w.started) < HOP_WINDOW)
            .map_or(0, |w| w.count)
    }

    fn bump_hop(&mut self, key: &str, now: Instant) {
        if let Some(window) = self.hops.get_mut(key) {
            if now.duration_since(window.started) < HOP_WINDOW {
                window.count = window.count.saturating_add(1);
            } else {
                *window = HopWindow {
                    started: now,
                    count: 1,
                };
            }
            return;
        }
        if self.hops.len() >= MAX_HOP_KEYS {
            self.hops
                .retain(|_, w| now.duration_since(w.started) < HOP_WINDOW);
        }
        if self.hops.len() >= MAX_HOP_KEYS {
            let oldest = self
                .hops
                .iter()
                .min_by_key(|(_, w)| w.started)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                self.hops.remove(&oldest);
            }
        }
        self.hops.insert(
            key.to_owned(),
            HopWindow {
                started: now,
                count: 1,
            },
        );
    }

    /// Charge one hop to every scope that has a limit, or none of them when
    /// any scope is already at its limit.
    fn charge_hops(
        &mut self,
        scopes: &[(&'static str, String, u32)],
        now: Instant,
    ) -> Result<(), HopDenied> {
        for (scope, key, limit) in scopes {
            if self.hop_count(key, now) >= *limit {
                return Err(HopDenied {
                    scope,
                    limit: *limit,
                });
            }
        }
        for (_, key, _) in scopes {
            self.bump_hop(key, now);
        }
        Ok(())
    }
}

fn normalize_route(route: ProxyRouteConfig) -> Result<SharedProxyRoute, ProxyControlError> {
    let route_id = route.route_id.trim().to_owned();
    if route_id.is_empty() {
        return Err(ProxyControlError::MissingRouteId);
    }

    let mut domains = Vec::new();
    for domain in route.domains {
        let normalized = normalize_domain(&domain);
        if !normalized.is_empty() && !domains.contains(&normalized) {
            domains.push(normalized);
        }
    }

    let mut target_urls = Vec::new();
    for target in route.target_urls {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed = Url::parse(trimmed)
            .map_err(|_| ProxyControlError::InvalidRouteTarget(trimmed.to_owned()))?;
        let Some(host) = parsed.host_str() else {
            return Err(ProxyControlError::InvalidRouteTarget(trimmed.to_owned()));
        };
        let normalized_host = normalize_domain(host);
        if !domains.contains(&normalized_host) {
            domains.push(normalized_host);
        }
        if !target_urls.iter().any(|v| v == trimmed) {
            target_urls.push(trimmed.to_owned());
        }
    }

    if domains.is_empty() {
        return Err(ProxyControlError::MissingRouteTarget);
    }

    Ok(SharedProxyRoute {
        route_id,
        domains,
        target_urls,
        request: ProxyProviderRequest {
            provider: route.provider,
            country: route.country,
            city: route.city,
            ip_type: route.ip_type,
        },
        active: None,
    })
}

fn snapshot_route(route: &SharedProxyRoute) -> ProxyRouteSnapshot {
    ProxyRouteSnapshot {
        route_id: route.route_id.clone(),
        domains: route.domains.clone(),
        target_urls: route.target_urls.clone(),
        provider: route.request.provider.clone(),
        country: route.request.country.clone(),
        city: route.request.city.clone(),
        ip_type: route.request.ip_type.clone(),
        active: route.active.as_ref().map(ActiveProxyMetadata::from),
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn find_route_id_for_domain<'a>(
    routes: &'a HashMap<String, String>,
    domain: &str,
) -> Option<&'a String> {
    if let Some(route_id) = routes.get(domain) {
        return Some(route_id);
    }
    for (pattern, route_id) in routes {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if domain == suffix || domain.ends_with(&format!(".{suffix}")) {
                return Some(route_id);
            }
        } else if domain.ends_with(&format!(".{pattern}")) {
            return Some(route_id);
        }
    }
    None
}

fn sorted_blocked_ips(ips: &HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = ips.iter().cloned().collect();
    out.sort();
    out
}

fn proxy_egress_ip(proxy: &ActiveProxy) -> Option<String> {
    match proxy {
        ActiveProxy::Direct => None,
        ActiveProxy::Mullvad { relay, .. } => relay.as_ref().map(|r| r.ipv4_addr.clone()),
        ActiveProxy::Resi { proxy } => Some(proxy.host.clone()),
        ActiveProxy::ResiWireguard { .. } => None,
    }
}

/// Shared, process-lifetime template. Holds the heavy provider registry
/// (Mullvad relay cache, residential-proxy HTTP client, etc.). Cheap to
/// clone (a `Vec<Arc<dyn ProxyProvider>>`). Call [`Self::spawn`] per
/// accepted connection to mint a fresh per-connection [`ProxyController`]
/// that shares the providers but owns its own rules, current proxy,
/// enabled flag, and upstream rate limiter.
///
/// The per-connection split ensures a single abuser cannot starve every
/// other tenant's rate-limit budget, exhaust the rules cap for everyone, or
/// flip the shared "current proxy" out from under siblings.
pub struct ProxyControllerTemplate {
    providers: Vec<SharedProvider>,
    shared: Arc<Mutex<SharedControllerState>>,
}

impl ProxyControllerTemplate {
    pub fn new(providers: Vec<SharedProvider>) -> Self {
        Self {
            providers,
            shared: Arc::new(Mutex::new(SharedControllerState::default())),
        }
    }

    pub fn providers(&self) -> &[SharedProvider] {
        &self.providers
    }

    pub fn spawn(
        &self,
        limits: ProxyControlLimits,
        allowed_proxy_providers: Option<Vec<String>>,
    ) -> Arc<ProxyController> {
        Arc::new(ProxyController::new(
            self.providers.clone(),
            limits,
            self.shared.clone(),
            allowed_proxy_providers,
        ))
    }

    pub fn set_route(
        &self,
        route: ProxyRouteConfig,
    ) -> Result<ProxyRouteSnapshot, ProxyControlError> {
        let normalized = normalize_route(route)?;
        let route_id = normalized.route_id.clone();
        let snapshot = snapshot_route(&normalized);
        let mut guard = self.shared.lock();
        if let Some(previous) = guard.routes.remove(&route_id) {
            for domain in previous.domains {
                guard.domain_routes.remove(&domain);
            }
        }
        for domain in &normalized.domains {
            guard
                .domain_routes
                .insert(domain.clone(), normalized.route_id.clone());
        }
        guard.routes.insert(route_id, normalized);
        Ok(snapshot)
    }

    pub fn remove_route(&self, route_id: &str) -> Option<ProxyRouteSnapshot> {
        let mut guard = self.shared.lock();
        let removed = guard.routes.remove(route_id)?;
        for domain in &removed.domains {
            guard.domain_routes.remove(domain);
        }
        Some(snapshot_route(&removed))
    }

    pub fn list_routes(&self) -> Vec<ProxyRouteSnapshot> {
        let mut out: Vec<ProxyRouteSnapshot> = self
            .shared
            .lock()
            .routes
            .values()
            .map(snapshot_route)
            .collect();
        out.sort_by(|a, b| a.route_id.cmp(&b.route_id));
        out
    }

    pub async fn rotate_route(
        &self,
        route_id: &str,
    ) -> Result<Option<ProxyRouteSnapshot>, ProxyConnectError> {
        let (request, active) = {
            let guard = self.shared.lock();
            let Some(route) = guard.routes.get(route_id) else {
                return Ok(None);
            };
            (route.request.clone(), route.active.clone())
        };

        let next = if let Some(active) = active {
            let Some(provider) = self.find_by_id(active.provider_id()) else {
                return Err(ProxyConnectError::NoProvider);
            };
            match provider.rotate(&active).await? {
                Some(proxy) => proxy,
                None => self.resolve_request(&request).await?,
            }
        } else {
            self.resolve_request(&request).await?
        };

        let mut guard = self.shared.lock();
        let Some(route) = guard.routes.get_mut(route_id) else {
            return Ok(None);
        };
        route.active = Some(next);
        Ok(Some(snapshot_route(route)))
    }

    pub fn set_policy(&self, policy: ProxyRuntimePolicy) -> ProxyRuntimePolicy {
        let mut guard = self.shared.lock();
        guard.policy = policy;
        guard.policy.clone()
    }

    pub fn policy(&self) -> ProxyRuntimePolicy {
        self.shared.lock().policy.clone()
    }

    pub fn set_hop_limits(&self, limits: ProxyHopLimits) {
        self.shared.lock().hop_limits = limits;
    }

    pub fn hop_limits(&self) -> ProxyHopLimits {
        self.shared.lock().hop_limits
    }

    pub fn block_egress_ip(&self, ip: String) -> Vec<String> {
        let mut guard = self.shared.lock();
        guard.blocked_egress_ips.insert(ip);
        sorted_blocked_ips(&guard.blocked_egress_ips)
    }

    pub fn release_egress_ip(&self, ip: &str) -> Vec<String> {
        let mut guard = self.shared.lock();
        guard.blocked_egress_ips.remove(ip);
        sorted_blocked_ips(&guard.blocked_egress_ips)
    }

    pub fn egress_inventory(&self) -> Value {
        let guard = self.shared.lock();
        let mut routes: Vec<ProxyRouteSnapshot> =
            guard.routes.values().map(snapshot_route).collect();
        routes.sort_by(|a, b| a.route_id.cmp(&b.route_id));
        json!(EgressInventory {
            routes,
            blocked_egress_ips: sorted_blocked_ips(&guard.blocked_egress_ips),
            policy: guard.policy.clone(),
        })
    }

    fn find_by_id(&self, id: &str) -> Option<&SharedProvider> {
        self.providers.iter().find(|p| p.matches(id))
    }

    async fn resolve_request(
        &self,
        request: &ProxyProviderRequest,
    ) -> Result<ActiveProxy, ProxyConnectError> {
        let Some(provider) = self.providers.iter().find(|p| p.can_resolve(request)) else {
            return Err(ProxyConnectError::NoProvider);
        };
        if !provider.is_configured() {
            return Err(ProxyConnectError::ProviderNotConfigured);
        }
        match provider.resolve(request, None).await? {
            Some(proxy) => Ok(proxy),
            None => Err(ProxyConnectError::NoProxy),
        }
    }
}

/// Per-connection proxy controller. Holds the (shared) provider registry
/// plus the runtime state (enabled flag, mode, current proxy, per-domain
/// rules) and the per-connection rate limiter. One instance per accepted
/// WebSocket connection — minted by [`ProxyControllerTemplate::spawn`].
pub struct ProxyController {
    providers: Vec<SharedProvider>,
    state: Mutex<ControllerState>,
    shared: Arc<Mutex<SharedControllerState>>,
    upstream_limiter: DirectLimiter,
    mutation_limiter: DirectLimiter,
    /// Per-IP budgets shared across the client's connections, set once the
    /// connection driver knows the client. Absent, only the per-connection
    /// limiters above apply.
    ip_budget: OnceLock<IpBudget>,
    limits: ProxyControlLimits,
    allowed_proxy_providers: Option<HashSet<String>>,
}

struct IpBudget {
    client_ip: String,
    store: Arc<DosGuard>,
}

impl ProxyController {
    fn new(
        providers: Vec<SharedProvider>,
        limits: ProxyControlLimits,
        shared: Arc<Mutex<SharedControllerState>>,
        allowed_proxy_providers: Option<Vec<String>>,
    ) -> Self {
        let upstream_quota =
            Quota::per_second(limits.upstream_ops_per_second).allow_burst(limits.upstream_burst);
        let mutation_quota =
            Quota::per_second(limits.mutation_ops_per_second).allow_burst(limits.mutation_burst);
        Self {
            providers,
            state: Mutex::new(ControllerState {
                enabled: false,
                mode: "off".to_owned(),
                ..Default::default()
            }),
            shared,
            upstream_limiter: RateLimiter::direct(upstream_quota),
            mutation_limiter: RateLimiter::direct(mutation_quota),
            ip_budget: OnceLock::new(),
            limits,
            allowed_proxy_providers: allowed_proxy_providers.map(|providers| {
                providers
                    .into_iter()
                    .map(|provider| provider.trim().to_ascii_lowercase())
                    .filter(|provider| !provider.is_empty())
                    .collect()
            }),
        }
    }

    pub fn providers(&self) -> &[SharedProvider] {
        &self.providers
    }

    /// Charges this controller's rate budgets to `client_ip` in the shared
    /// limiter as well, so opening more connections does not multiply them.
    /// The first call wins.
    pub fn bind_ip_budget(&self, client_ip: String, store: Arc<DosGuard>) {
        let _ = self.ip_budget.set(IpBudget { client_ip, store });
    }

    /// One operation of `class` against the per-IP bucket, which holds `burst`
    /// operations and refills at `per_second`.
    fn ip_allows(&self, class: &str, burst: NonZeroU32, per_second: NonZeroU32) -> bool {
        let Some(budget) = self.ip_budget.get() else {
            return true;
        };
        let window_ms = (u64::from(burst.get()) * 1000 / u64::from(per_second.get())).max(1);
        is_ip_budget_allowed(
            &budget.client_ip,
            class,
            u64::from(burst.get()),
            window_ms,
            &budget.store,
        )
    }

    fn upstream_allowed(&self) -> bool {
        self.upstream_limiter.check().is_ok()
            && self.ip_allows(
                "proxy_control:upstream",
                self.limits.upstream_burst,
                self.limits.upstream_ops_per_second,
            )
    }

    fn mutation_allowed(&self) -> bool {
        self.mutation_limiter.check().is_ok()
            && self.ip_allows(
                "proxy_control:mutation",
                self.limits.mutation_burst,
                self.limits.mutation_ops_per_second,
            )
    }

    pub fn current(&self) -> Option<ActiveProxy> {
        self.state.lock().current.clone()
    }

    /// Tell the controller who is on the other end so hop limits can be kept
    /// per client IP and per token, and so hop reports can name the client.
    /// `token_key` is any stable per-token identifier; it is never reported.
    pub fn bind_client(&self, client_ip: &str, token_key: Option<&str>) {
        let bounded = |value: &str| value.chars().take(MAX_HOP_KEY_BYTES).collect::<String>();
        let mut guard = self.state.lock();
        guard.client_ip = Some(bounded(client_ip)).filter(|ip| !ip.is_empty());
        guard.token_key = token_key.map(bounded).filter(|key| !key.is_empty());
    }

    /// Count one proxy switch against the connection, client IP and token
    /// limits. On refusal nothing is charged and a hop-limit report is
    /// emitted.
    fn charge_hop(&self, request_type: &'static str, provider: &str) -> Result<(), HopDenied> {
        let limits = self.shared.lock().hop_limits;
        let (client_ip, token_key) = {
            let mut guard = self.state.lock();
            if let Some(limit) = limits.max_per_connection {
                if guard.session_hops >= limit {
                    drop(guard);
                    let denied = HopDenied {
                        scope: "session",
                        limit,
                    };
                    self.report_hop_denied(request_type, provider, denied);
                    return Err(denied);
                }
            }
            guard.session_hops = guard.session_hops.saturating_add(1);
            (guard.client_ip.clone(), guard.token_key.clone())
        };
        let mut scopes: Vec<(&'static str, String, u32)> = Vec::new();
        if let (Some(ip), Some(limit)) = (client_ip.as_deref(), limits.max_per_ip_per_day) {
            scopes.push(("ip", format!("ip:{ip}"), limit));
        }
        if let (Some(token), Some(limit)) = (token_key.as_deref(), limits.max_per_token_per_day) {
            scopes.push(("token", format!("token:{token}"), limit));
        }
        let charged = self.shared.lock().charge_hops(&scopes, Instant::now());
        if let Err(denied) = charged {
            let mut guard = self.state.lock();
            guard.session_hops = guard.session_hops.saturating_sub(1);
            drop(guard);
            self.report_hop_denied(request_type, provider, denied);
            return Err(denied);
        }
        Ok(())
    }

    fn report_context(&self) -> wisp_reports::ConnectionContext {
        wisp_reports::ConnectionContext {
            client_ip: self.state.lock().client_ip.clone(),
            ..Default::default()
        }
    }

    fn report_hop_denied(&self, request_type: &'static str, provider: &str, denied: HopDenied) {
        wisp_reports::emit_report(
            wisp_reports::ReportErrorType::ProxyHopLimitExceeded,
            wisp_reports::ReportInput {
                context: Some(self.report_context()),
                proxy_request_type: Some(request_type.to_owned()),
                provider: Some(provider.to_owned()),
                limit_type: Some(denied.scope.to_owned()),
                amount: Some(i64::from(denied.limit)),
                ..Default::default()
            },
        );
    }

    fn report_switch(&self, request_type: &'static str, provider: &str) {
        wisp_reports::emit_report(
            wisp_reports::ReportErrorType::ProxyControlSwitch,
            wisp_reports::ReportInput {
                context: Some(self.report_context()),
                proxy_request_type: Some(request_type.to_owned()),
                provider: Some(provider.to_owned()),
                ..Default::default()
            },
        );
    }

    /// Establish an upstream TCP connection for `host:port`, applying the
    /// per-connection domain rule, shared route, always-on current proxy,
    /// runtime default proxy, or direct connect in that order. Every path
    /// checks the host and resolves it through `policy` first, so each
    /// resolved address is checked against [`HostPolicy`] (IP lists, private,
    /// loopback and this host's own addresses) whether or not a proxy carries
    /// the stream, and a proxy only ever receives a checked IP address.
    pub async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
        force_proxy: bool,
        policy: &HostPolicy,
    ) -> Result<(TcpStream, Option<ActiveProxy>), ProxyConnectError> {
        if let Some(request) = self.rule_for_host(host) {
            if !is_direct_provider(request.provider.as_deref()) {
                let proxy = self.proxy_for_request(&request).await?;
                self.check_proxy_allowed(&proxy)?;
                let stream = open_checked_via_proxy(&proxy, host, port, policy).await?;
                return Ok((stream, Some(proxy)));
            }
        }

        if let Some((route_id, request, current)) = self.shared_route_for_host(host) {
            let proxy = if let Some(proxy) = current {
                proxy
            } else {
                let proxy = self.resolve_request(&request).await?;
                self.remember_route_proxy(&route_id, &proxy);
                proxy
            };
            self.check_proxy_allowed(&proxy)?;
            let stream = open_checked_via_proxy(&proxy, host, port, policy).await?;
            return Ok((stream, Some(proxy)));
        }

        if self.mode_is_always() {
            if let Some(proxy) = self.current_when_enabled() {
                self.check_proxy_allowed(&proxy)?;
                let stream = open_checked_via_proxy(&proxy, host, port, policy).await?;
                return Ok((stream, Some(proxy)));
            }
        }

        if let Some(request) = self.shared_default_request() {
            let proxy = self.resolve_request(&request).await?;
            self.check_proxy_allowed(&proxy)?;
            let stream = open_checked_via_proxy(&proxy, host, port, policy).await?;
            return Ok((stream, Some(proxy)));
        }

        if let Some(proxy) = self.current_when_enabled() {
            self.check_proxy_allowed(&proxy)?;
            let stream = open_checked_via_proxy(&proxy, host, port, policy).await?;
            return Ok((stream, Some(proxy)));
        }

        if force_proxy {
            return Err(ProxyConnectError::NoProxy);
        }

        let stream = connect_checked_tcp(host, port, policy).await?;
        Ok((stream, None))
    }

    /// `true` when a TCP stream to `host` would leave through a proxy: a
    /// rule, a shared route, the runtime default under force_proxy, or an
    /// enabled current proxy. UDP cannot be proxied, so such a destination
    /// must not get a direct UDP flow that shows the server's own address.
    pub fn routes_through_proxy(&self, host: &str) -> bool {
        if self
            .rule_for_host(host)
            .is_some_and(|request| !is_direct_provider(request.provider.as_deref()))
        {
            return true;
        }
        if self.shared_route_for_host(host).is_some() || self.shared.lock().policy.force_proxy {
            return true;
        }
        self.current_when_enabled().is_some()
    }

    fn find_for_request(&self, req: &ProxyProviderRequest) -> Option<&SharedProvider> {
        self.providers.iter().find(|p| p.can_resolve(req))
    }

    fn find_by_id(&self, id: &str) -> Option<&SharedProvider> {
        self.providers.iter().find(|p| p.matches(id))
    }

    async fn resolve_request(
        &self,
        request: &ProxyProviderRequest,
    ) -> Result<ActiveProxy, ProxyConnectError> {
        let Some(provider) = self.find_for_request(request) else {
            return Err(ProxyConnectError::NoProvider);
        };
        if !self.provider_is_allowed(provider.as_ref()) {
            return Err(ProxyConnectError::ProviderRequiresAuthentication);
        }
        if !provider.is_configured() {
            return Err(ProxyConnectError::ProviderNotConfigured);
        }
        match provider.resolve(request, None).await? {
            Some(proxy) => Ok(proxy),
            None => Err(ProxyConnectError::NoProxy),
        }
    }

    fn shared_route_for_host(
        &self,
        host: &str,
    ) -> Option<(String, ProxyProviderRequest, Option<ActiveProxy>)> {
        let normalized = normalize_domain(host);
        let guard = self.shared.lock();
        let route_id = find_route_id_for_domain(&guard.domain_routes, &normalized)?;
        let route = guard.routes.get(route_id)?;
        Some((
            route.route_id.clone(),
            route.request.clone(),
            route.active.clone(),
        ))
    }

    fn remember_route_proxy(&self, route_id: &str, proxy: &ActiveProxy) {
        if let Some(route) = self.shared.lock().routes.get_mut(route_id) {
            route.active = Some(proxy.clone());
        }
    }

    fn shared_default_request(&self) -> Option<ProxyProviderRequest> {
        let guard = self.shared.lock();
        if !guard.policy.force_proxy {
            return None;
        }
        Some(ProxyProviderRequest {
            provider: guard.policy.default_provider.clone(),
            country: guard.policy.default_country.clone(),
            city: guard.policy.default_city.clone(),
            ip_type: guard.policy.default_ip_type.clone(),
        })
    }

    fn current_when_enabled(&self) -> Option<ActiveProxy> {
        let guard = self.state.lock();
        if guard.enabled {
            guard.current.clone()
        } else {
            None
        }
    }

    fn mode_is_always(&self) -> bool {
        self.state.lock().mode == "always"
    }

    fn rule_for_host(&self, host: &str) -> Option<ProxyProviderRequest> {
        let domain = normalize_domain(host);
        let guard = self.state.lock();
        if let Some(req) = guard.rules.get(&domain) {
            return Some(req.clone());
        }
        let mut best: Option<(usize, ProxyProviderRequest)> = None;
        for (pattern, req) in &guard.rules {
            let suffix = pattern.strip_prefix("*.").unwrap_or(pattern.as_str());
            if domain == suffix || domain.ends_with(&format!(".{suffix}")) {
                let score = suffix.len();
                if best.as_ref().is_none_or(|(s, _)| score > *s) {
                    best = Some((score, req.clone()));
                }
            }
        }
        best.map(|(_, req)| req)
    }

    async fn proxy_for_request(
        &self,
        request: &ProxyProviderRequest,
    ) -> Result<ActiveProxy, ProxyConnectError> {
        if let Some(current) = self.current_when_enabled() {
            if proxy_satisfies_request(&current, request) {
                return Ok(current);
            }
        }
        let cached = self
            .state
            .lock()
            .rule_proxies
            .iter()
            .find(|(cached, _)| cached == request)
            .map(|(_, proxy)| proxy.clone());
        if let Some(proxy) = cached {
            return Ok(proxy);
        }
        let provider = request.provider.as_deref().unwrap_or_default();
        if self.charge_hop("proxy_rule", provider).is_err() {
            return Err(ProxyConnectError::HopLimitExceeded);
        }
        let proxy = self.resolve_request(request).await?;
        // Remember the proxy for this rule only. A rule must not flip the
        // connection-wide `current` or `enabled`, which would send every
        // other host through the proxy too.
        let mut guard = self.state.lock();
        if let Some(entry) = guard.rule_proxies.iter_mut().find(|(r, _)| r == request) {
            entry.1 = proxy.clone();
        } else {
            if guard.rule_proxies.len() >= self.limits.max_rules.max(1) {
                guard.rule_proxies.remove(0);
            }
            guard.rule_proxies.push((request.clone(), proxy.clone()));
        }
        Ok(proxy)
    }

    fn check_proxy_allowed(&self, proxy: &ActiveProxy) -> Result<(), ProxyConnectError> {
        let Some(ip) = proxy_egress_ip(proxy) else {
            return Ok(());
        };
        if self.shared.lock().blocked_egress_ips.contains(&ip) {
            return Err(ProxyConnectError::BlockedEgress);
        }
        Ok(())
    }

    /// Dispatch a single proxy-control request. Returns the JSON reply the
    /// connection driver should write back as a text frame.
    pub async fn dispatch(&self, req: ProxyControlRequest) -> Value {
        match req {
            ProxyControlRequest::ProxySet {
                provider,
                country,
                city,
                ip_type,
            } => {
                self.dispatch_proxy_set(provider, country, city, ip_type)
                    .await
            }
            ProxyControlRequest::ProxyRotate => self.dispatch_proxy_rotate().await,
            ProxyControlRequest::ProxyOn => {
                if !self.mutation_allowed() {
                    return json!(ProxyStateReply::rate_limited());
                }
                self.state.lock().enabled = true;
                json!(ProxyStateReply::enabled(true))
            }
            ProxyControlRequest::ProxyOff => {
                if !self.mutation_allowed() {
                    return json!(ProxyStateReply::rate_limited());
                }
                let mut guard = self.state.lock();
                guard.enabled = false;
                guard.current = None;
                json!(ProxyStateReply::enabled(false))
            }
            ProxyControlRequest::ProxyMode { mode } => {
                if !self.mutation_allowed() {
                    return json!(ProxyModeReply::error("rate limited"));
                }
                if mode.len() > self.limits.max_field_bytes {
                    return json!(ProxyModeReply::error("mode too long"));
                }
                self.state.lock().mode = mode.clone();
                json!(ProxyModeReply::ok(mode))
            }
            ProxyControlRequest::ProxyRule {
                domain,
                provider,
                country,
                city,
                ip_type,
            } => {
                self.dispatch_proxy_rule(domain, provider, country, city, ip_type)
                    .await
            }
            ProxyControlRequest::ProxyRuleRemove { domain } => {
                if !self.mutation_allowed() {
                    return json!(ProxyRuleRemovedReply::rate_limited(domain));
                }
                let removed = self.state.lock().rules.remove(&domain).is_some();
                json!(ProxyRuleRemovedReply::removed(domain, removed))
            }
            ProxyControlRequest::ProxyLocations { provider } => {
                self.dispatch_proxy_locations(provider).await
            }
            ProxyControlRequest::ProxyListProviders => {
                if !self.mutation_allowed() {
                    return json!(ProxyListReply::rate_limited());
                }
                let providers: Vec<ProviderEntry> = self
                    .providers
                    .iter()
                    .map(|p| ProviderEntry {
                        id: p.id().to_owned(),
                        name: p.name().to_owned(),
                        aliases: p.aliases().iter().map(|a| (*a).to_owned()).collect(),
                        configured: p.is_configured(),
                        available: p.is_configured() && self.provider_is_allowed(p.as_ref()),
                        location_selection: p.location_selection(),
                    })
                    .collect();
                json!(ProxyListReply::ok(providers))
            }
        }
    }

    async fn dispatch_proxy_set(
        &self,
        provider: Option<String>,
        country: Option<String>,
        city: Option<String>,
        ip_type: Option<String>,
    ) -> Value {
        if !self.upstream_allowed() {
            return json!(ProxySetReply::error("rate limited"));
        }
        if let Some(bad) = oversized_field(
            &[
                provider.as_deref(),
                country.as_deref(),
                city.as_deref(),
                ip_type.as_deref(),
            ],
            self.limits.max_field_bytes,
        ) {
            return json!(ProxySetReply::error(format!("field too long: {bad}")));
        }
        let request = ProxyProviderRequest {
            provider: provider.clone(),
            country,
            city,
            ip_type,
        };
        let Some(p) = self.find_for_request(&request) else {
            return json!(ProxySetReply::error("no provider matches the request"));
        };
        if !self.provider_is_allowed(p.as_ref()) {
            return json!(ProxySetReply::error("provider requires authentication"));
        }
        if !p.is_configured() {
            return json!(ProxySetReply::error(p.unconfigured_message().to_string()));
        }
        if self.charge_hop("proxy_set", p.id()).is_err() {
            return json!(ProxySetReply::error("hop limit reached"));
        }
        match p.resolve(&request, None).await {
            Ok(Some(proxy)) => {
                let mut guard = self.state.lock();
                guard.current = Some(proxy.clone());
                guard.enabled = true;
                drop(guard);
                self.report_switch("proxy_set", p.id());
                json!(ProxySetReply::ok(proxy))
            }
            Ok(None) => json!(ProxySetReply::error("provider returned no proxy")),
            Err(e) => {
                warn!(provider = p.id(), error = %e, "proxy_set: resolve failed");
                json!(ProxySetReply::error(e.to_string()))
            }
        }
    }

    async fn dispatch_proxy_rotate(&self) -> Value {
        if !self.upstream_allowed() {
            return json!(ProxyRotateReply::error("rate limited"));
        }
        let prev = self.state.lock().current.clone();
        let Some(prev) = prev else {
            return json!(ProxyRotateReply::error("no active proxy"));
        };
        let Some(p) = self.find_by_id(prev.provider_id()) else {
            return json!(ProxyRotateReply::error("provider not registered"));
        };
        if !self.provider_is_allowed(p.as_ref()) {
            return json!(ProxyRotateReply::error("provider requires authentication"));
        }
        if self.charge_hop("proxy_rotate", p.id()).is_err() {
            return json!(ProxyRotateReply::error("hop limit reached"));
        }
        match p.rotate(&prev).await {
            Ok(Some(proxy)) => {
                self.state.lock().current = Some(proxy.clone());
                self.report_switch("proxy_rotate", p.id());
                json!(ProxyRotateReply::ok(proxy))
            }
            Ok(None) => json!(ProxyRotateReply::error("rotation returned no new proxy")),
            Err(e) => json!(ProxyRotateReply::error(e.to_string())),
        }
    }

    async fn dispatch_proxy_rule(
        &self,
        domain: String,
        provider: Option<String>,
        country: Option<String>,
        city: Option<String>,
        ip_type: Option<String>,
    ) -> Value {
        if !self.mutation_allowed() {
            return json!(ProxyRuleSetReply::error(Some(domain), "rate limited"));
        }
        if domain.len() > self.limits.max_field_bytes {
            return json!(ProxyRuleSetReply::error(None, "domain too long"));
        }
        if let Some(bad) = oversized_field(
            &[
                provider.as_deref(),
                country.as_deref(),
                city.as_deref(),
                ip_type.as_deref(),
            ],
            self.limits.max_field_bytes,
        ) {
            return json!(ProxyRuleSetReply::error(
                Some(domain),
                format!("field too long: {bad}"),
            ));
        }
        let request = ProxyProviderRequest {
            provider,
            country,
            city,
            ip_type,
        };
        if request.provider.is_some() && !is_direct_provider(request.provider.as_deref()) {
            let Some(p) = self.find_for_request(&request) else {
                return json!(ProxyRuleSetReply::error(
                    Some(domain),
                    "no provider matches the request",
                ));
            };
            if !self.provider_is_allowed(p.as_ref()) {
                return json!(ProxyRuleSetReply::error(
                    Some(domain),
                    "provider requires authentication",
                ));
            }
        }
        let domain = normalize_domain(&domain);
        if domain.is_empty() {
            return json!(ProxyRuleSetReply::error(None, "invalid domain"));
        }
        let mut guard = self.state.lock();
        if guard.rules.len() >= self.limits.max_rules && !guard.rules.contains_key(&domain) {
            return json!(ProxyRuleSetReply::error(Some(domain), "rule cap reached"));
        }
        guard.rules.insert(domain.clone(), request);
        drop(guard);
        json!(ProxyRuleSetReply::ok(domain))
    }

    async fn dispatch_proxy_locations(&self, provider: Option<String>) -> Value {
        if !self.upstream_allowed() {
            return json!(ProxyLocationsReply::error("rate limited"));
        }
        let target = provider.as_deref();
        let max_reply_bytes = self.limits.max_reply_bytes;
        let per_provider_cap = max_reply_bytes / 2;
        let reply_overhead: usize = 64;
        let mut out: Vec<ProviderLocations> = Vec::with_capacity(self.providers.len());
        let mut running_bytes: usize = reply_overhead;
        let mut truncated = false;
        for p in &self.providers {
            if let Some(t) = target {
                if !p.matches(t) {
                    continue;
                }
            }
            if !self.provider_is_allowed(p.as_ref()) {
                continue;
            }
            match p.locations().await {
                Ok(Some(locs)) => {
                    let entry = ProviderLocations {
                        provider: p.id().to_owned(),
                        name: p.name().to_owned(),
                        locations: locs,
                    };
                    let entry_bytes = match measure_json_capped(&entry, per_provider_cap) {
                        MeasureResult::Within(n) => n,
                        MeasureResult::Overflow => usize::MAX,
                    };
                    if entry_bytes > per_provider_cap {
                        warn!(
                            provider = p.id(),
                            bytes = entry_bytes,
                            cap = per_provider_cap,
                            "proxy_locations: provider entry exceeds per-provider cap, skipping",
                        );
                        truncated = true;
                        continue;
                    }
                    if running_bytes.saturating_add(entry_bytes) > max_reply_bytes {
                        warn!(
                            bytes = running_bytes + entry_bytes,
                            cap = max_reply_bytes,
                            "proxy_locations: reply budget exhausted, stopping accumulation",
                        );
                        truncated = true;
                        break;
                    }
                    running_bytes = running_bytes.saturating_add(entry_bytes);
                    out.push(entry);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(provider = p.id(), error = %e, "proxy_locations: failed");
                }
            }
        }
        json!(ProxyLocationsReply::ok(out, truncated))
    }

    fn provider_is_allowed(&self, provider: &dyn ProxyProvider) -> bool {
        if provider.matches("resi") || provider.matches("mysterium") || provider.matches("mullvad")
        {
            return self
                .allowed_proxy_providers
                .as_ref()
                .map(|allowed| provider_allowed_by_set(provider, allowed))
                .unwrap_or(false);
        }
        self.allowed_proxy_providers
            .as_ref()
            .map(|allowed| provider_allowed_by_set(provider, allowed))
            .unwrap_or(true)
    }
}

/// Addresses of one name tried through a proxy at most.
const MAX_PROXIED_DIAL_ADDRS: usize = 4;

/// Opens `host:port` through `proxy` after checking the host and resolving it
/// through `policy`, so the address policy applies to proxied streams too. The
/// proxy receives an IP literal and resolves nothing itself.
async fn open_checked_via_proxy(
    proxy: &ActiveProxy,
    host: &str,
    port: u16,
    policy: &HostPolicy,
) -> Result<TcpStream, ProxyConnectError> {
    let addrs = policy
        .resolve(host, port)
        .await
        .map_err(|e| ProxyConnectError::Connect(ConnectError::Policy(e)))?;
    let mut last = None;
    for addr in addrs.into_iter().take(MAX_PROXIED_DIAL_ADDRS) {
        match open_proxy_tcp_socket_addr(proxy, addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(match last {
        Some(e) => ProxyConnectError::Tunnel(e),
        None => ProxyConnectError::NoProxy,
    })
}

fn is_direct_provider(provider: Option<&str>) -> bool {
    matches!(provider, Some("none") | Some("direct") | Some(""))
}

fn proxy_satisfies_request(proxy: &ActiveProxy, request: &ProxyProviderRequest) -> bool {
    if let Some(provider) = request.provider.as_deref() {
        if !is_direct_provider(Some(provider))
            && !proxy.provider_id().eq_ignore_ascii_case(provider)
        {
            return false;
        }
    }
    match proxy {
        ActiveProxy::Mullvad {
            relay: Some(relay), ..
        } => {
            if let Some(country) = request.country.as_deref() {
                if !country.is_empty() && !relay.country_code.eq_ignore_ascii_case(country) {
                    return false;
                }
            }
            if let Some(city) = request.city.as_deref() {
                if !city.is_empty() && !relay.city_code.eq_ignore_ascii_case(city) {
                    return false;
                }
            }
            true
        }
        ActiveProxy::Resi { proxy } => request
            .country
            .as_deref()
            .filter(|country| !country.is_empty())
            .is_none_or(|country| proxy.country.eq_ignore_ascii_case(country)),
        ActiveProxy::ResiWireguard { country, .. } => request
            .country
            .as_deref()
            .filter(|requested| !requested.is_empty())
            .is_none_or(|requested| country.eq_ignore_ascii_case(requested)),
        _ => request.country.is_none() && request.city.is_none(),
    }
}

fn provider_allowed_by_set(provider: &dyn ProxyProvider, allowed: &HashSet<String>) -> bool {
    allowed.iter().any(|requested| provider.matches(requested))
}

#[derive(Serialize)]
struct EgressInventory {
    routes: Vec<ProxyRouteSnapshot>,
    #[serde(rename = "blockedEgressIps")]
    blocked_egress_ips: Vec<String>,
    policy: ProxyRuntimePolicy,
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_set_result")]
struct ProxySetReply {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<ActiveProxyMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProxySetReply {
    fn ok(active: ActiveProxy) -> Self {
        Self {
            ok: true,
            active: Some(ActiveProxyMetadata::from(&active)),
            error: None,
        }
    }
    fn error(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            active: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_rotate_result")]
struct ProxyRotateReply {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<ActiveProxyMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProxyRotateReply {
    fn ok(active: ActiveProxy) -> Self {
        Self {
            ok: true,
            active: Some(ActiveProxyMetadata::from(&active)),
            error: None,
        }
    }
    fn error(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            active: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_state")]
struct ProxyStateReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProxyStateReply {
    fn enabled(enabled: bool) -> Self {
        Self {
            ok: None,
            enabled: Some(enabled),
            error: None,
        }
    }
    fn rate_limited() -> Self {
        Self {
            ok: Some(false),
            enabled: None,
            error: Some("rate limited".to_owned()),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_mode")]
struct ProxyModeReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProxyModeReply {
    fn ok(mode: String) -> Self {
        Self {
            ok: None,
            mode: Some(mode),
            error: None,
        }
    }
    fn error(error: impl Into<String>) -> Self {
        Self {
            ok: Some(false),
            mode: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_rule_set")]
struct ProxyRuleSetReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProxyRuleSetReply {
    fn ok(domain: String) -> Self {
        Self {
            domain: Some(domain),
            ok: true,
            error: None,
        }
    }
    fn error(domain: Option<String>, error: impl Into<String>) -> Self {
        Self {
            domain,
            ok: false,
            error: Some(error.into()),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_rule_removed")]
struct ProxyRuleRemovedReply {
    domain: String,
    removed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProxyRuleRemovedReply {
    fn removed(domain: String, removed: bool) -> Self {
        Self {
            domain,
            removed,
            error: None,
        }
    }
    fn rate_limited(domain: String) -> Self {
        Self {
            domain,
            removed: false,
            error: Some("rate limited".to_owned()),
        }
    }
}

#[derive(Serialize)]
struct ProviderEntry {
    id: String,
    name: String,
    aliases: Vec<String>,
    configured: bool,
    available: bool,
    #[serde(rename = "locationSelection")]
    location_selection: ProxyLocationSelection,
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_list")]
struct ProxyListReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    providers: Option<Vec<ProviderEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ProxyListReply {
    fn ok(providers: Vec<ProviderEntry>) -> Self {
        Self {
            ok: None,
            providers: Some(providers),
            error: None,
        }
    }
    fn rate_limited() -> Self {
        Self {
            ok: Some(false),
            providers: None,
            error: Some("rate limited".to_owned()),
        }
    }
}

#[derive(Serialize)]
struct ProviderLocations {
    provider: String,
    name: String,
    locations: ProxyProviderLocations,
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_locations_result")]
struct ProxyLocationsReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    providers: Option<Vec<ProviderLocations>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
}

impl ProxyLocationsReply {
    fn ok(providers: Vec<ProviderLocations>, truncated: bool) -> Self {
        Self {
            ok: None,
            providers: Some(providers),
            error: None,
            truncated,
        }
    }
    fn error(error: impl Into<String>) -> Self {
        Self {
            ok: Some(false),
            providers: None,
            error: Some(error.into()),
            truncated: false,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename = "proxy_control_error")]
struct ProxyControlErrorReply {
    ok: bool,
    error: String,
}

impl ProxyControlErrorReply {
    fn new(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
        }
    }
}

/// Serialize a normalized `proxy_control_error` text-frame reply
/// (`{type:"proxy_control_error", ok:false, error:"..."}`).
pub(crate) fn proxy_control_error_frame(error: &str) -> String {
    serde_json::to_string(&ProxyControlErrorReply::new(error))
        .unwrap_or_else(|_| String::from(r#"{"type":"proxy_control_error","ok":false,"error":""}"#))
}

/// Streaming length sink. `serde_json::to_writer` pushes bytes into this; the
/// moment the running count crosses `cap` we return an error so the serializer
/// aborts. Avoids materializing the full provider tree into a `String` just to
/// measure it.
struct LengthCappedWriter {
    written: usize,
    cap: usize,
    overflow: bool,
}

impl std::io::Write for LengthCappedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next = self.written.saturating_add(buf.len());
        if next > self.cap {
            self.written = next;
            self.overflow = true;
            return Err(std::io::Error::other("cap exceeded"));
        }
        self.written = next;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

enum MeasureResult {
    Within(usize),
    Overflow,
}

fn measure_json_capped<T: Serialize>(value: &T, cap: usize) -> MeasureResult {
    let mut sink = LengthCappedWriter {
        written: 0,
        cap,
        overflow: false,
    };
    match serde_json::to_writer(&mut sink, value) {
        Ok(()) => MeasureResult::Within(sink.written),
        Err(_) => MeasureResult::Overflow,
    }
}

/// At most 256 bytes of `text`, cut on a character boundary.
fn truncate_for_log(text: &str) -> &str {
    let mut end = text.len().min(256);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn oversized_field<'a>(fields: &[Option<&'a str>], max: usize) -> Option<&'a str> {
    for f in fields.iter().flatten() {
        if f.len() > max {
            return Some(*f);
        }
    }
    None
}

/// Try to parse a text frame as a proxy_control request and dispatch it.
/// Returns the JSON reply (already serialized) on success, or `None` if the
/// text wasn't a valid request shape — invalid text frames are silently
/// dropped so unrelated cross-extension noise does not tear down the channel.
pub async fn handle_proxy_control_text(
    controller: &Arc<ProxyController>,
    text: &str,
) -> Option<String> {
    let req: ProxyControlRequest = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(e) => {
            // The parse error can quote the frame, up to the whole 64 KiB, so
            // bound it and escape it (Debug) before it reaches the log.
            let detail = e.to_string();
            warn!(
                error = ?truncate_for_log(&detail),
                len = detail.len(),
                "proxy_control: ignoring malformed text frame"
            );
            return None;
        }
    };
    let reply = controller.dispatch(req).await;
    let s = serde_json::to_string(&reply).ok()?;
    if s.len() > controller.limits.max_reply_bytes {
        warn!(
            len = s.len(),
            "proxy_control: reply too large, replacing with error"
        );
        return serde_json::to_string(&ProxyControlErrorReply::new("reply too large")).ok();
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use wisp_proxy_base::{
        ProxyProvider, ProxyProviderContext, ProxyProviderLocations, ProxyResolveError,
    };

    struct DummyProvider {
        id: &'static str,
        configured: bool,
    }

    #[async_trait]
    impl ProxyProvider for DummyProvider {
        fn id(&self) -> &str {
            self.id
        }
        fn name(&self) -> &str {
            self.id
        }
        fn is_configured(&self) -> bool {
            self.configured
        }
        async fn resolve(
            &self,
            _req: &ProxyProviderRequest,
            _ctx: Option<&ProxyProviderContext>,
        ) -> Result<Option<ActiveProxy>, ProxyResolveError> {
            Ok(Some(ActiveProxy::Direct))
        }
        async fn rotate(
            &self,
            _proxy: &ActiveProxy,
        ) -> Result<Option<ActiveProxy>, ProxyResolveError> {
            Ok(Some(ActiveProxy::Direct))
        }
        async fn locations(&self) -> Result<Option<ProxyProviderLocations>, ProxyResolveError> {
            Ok(Some(ProxyProviderLocations {
                countries: vec![],
                top_countries: None,
            }))
        }
    }

    fn test_controller(
        providers: Vec<SharedProvider>,
        limits: ProxyControlLimits,
    ) -> Arc<ProxyController> {
        ProxyControllerTemplate::new(providers).spawn(limits, None)
    }

    /// Direct IPs are allowed so a literal reaches the address checks.
    fn loopback_policy() -> HostPolicy {
        let opts = wisp_config::WispServerOptions {
            allow_direct_ip: true,
            port_whitelist: None,
            ..wisp_config::WispServerOptions::default()
        };
        HostPolicy::from_options(&opts)
    }

    #[tokio::test]
    async fn dispatch_proxy_set_writes_state_and_returns_active() {
        let controller = test_controller(
            vec![Arc::new(DummyProvider {
                id: "dummy",
                configured: true,
            })],
            ProxyControlLimits::default(),
        );
        let reply = controller
            .dispatch(ProxyControlRequest::ProxySet {
                provider: Some("dummy".into()),
                country: None,
                city: None,
                ip_type: None,
            })
            .await;
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["type"], "proxy_set_result");
        assert!(controller.current().is_some());
    }

    #[tokio::test]
    async fn dispatch_list_providers() {
        let controller = test_controller(
            vec![
                Arc::new(DummyProvider {
                    id: "a",
                    configured: true,
                }),
                Arc::new(DummyProvider {
                    id: "b",
                    configured: false,
                }),
            ],
            ProxyControlLimits::default(),
        );
        let reply = controller
            .dispatch(ProxyControlRequest::ProxyListProviders)
            .await;
        let providers = reply["providers"].as_array().expect("array");
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0]["id"], "a");
        assert_eq!(providers[1]["configured"], false);
    }

    #[tokio::test]
    async fn dispatch_proxy_off_clears_state() {
        let controller = test_controller(
            vec![Arc::new(DummyProvider {
                id: "x",
                configured: true,
            })],
            ProxyControlLimits::default(),
        );
        controller
            .dispatch(ProxyControlRequest::ProxySet {
                provider: Some("x".into()),
                country: None,
                city: None,
                ip_type: None,
            })
            .await;
        assert!(controller.current().is_some());
        controller.dispatch(ProxyControlRequest::ProxyOff).await;
        assert!(controller.current().is_none());
    }

    #[tokio::test]
    async fn handle_proxy_control_text_drops_invalid_json() {
        let controller = test_controller(vec![], ProxyControlLimits::default());
        assert!(handle_proxy_control_text(&controller, "not json")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn proxy_control_error_reply_is_normalized() {
        let reply = ProxyControlErrorReply::new("boom");
        let value = json!(reply);
        assert_eq!(value["type"], "proxy_control_error");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "boom");
    }

    #[test]
    fn public_proxy_dtos_redact_residential_credentials() {
        let active = ActiveProxy::Resi {
            proxy: wisp_proxy_base::ResidentialProxy {
                host: "proxy.example".to_owned(),
                port: 8443,
                username: "secret-user".to_owned(),
                password: "secret-password".to_owned(),
                country: "us".to_owned(),
            },
        };
        let reply = ProxySetReply::ok(active.clone());
        let value = json!(reply);

        assert_eq!(value["type"], "proxy_set_result");
        assert_eq!(value["ok"], true);
        assert_eq!(value["active"]["type"], "resi");
        assert_eq!(value["active"]["proxy"]["host"], "proxy.example");
        assert!(value["active"]["proxy"].get("username").is_none());
        assert!(value["active"]["proxy"].get("password").is_none());

        let route = SharedProxyRoute {
            route_id: "route".to_owned(),
            domains: vec!["example.com".to_owned()],
            target_urls: Vec::new(),
            request: ProxyProviderRequest::default(),
            active: Some(active),
        };
        let value = json!(snapshot_route(&route));
        assert_eq!(value["active"]["type"], "resi");
        assert!(value["active"]["proxy"].get("username").is_none());
        assert!(value["active"]["proxy"].get("password").is_none());
    }

    #[tokio::test]
    async fn proxy_rule_cap_rejects_after_max() {
        let limits = ProxyControlLimits::default();
        let controller = test_controller(vec![], limits);
        for i in 0..limits.max_rules {
            let reply = controller
                .dispatch(ProxyControlRequest::ProxyRule {
                    domain: format!("d{i}.example"),
                    provider: None,
                    country: None,
                    city: None,
                    ip_type: None,
                })
                .await;
            assert_eq!(reply["ok"], true);
        }
        let reply = controller
            .dispatch(ProxyControlRequest::ProxyRule {
                domain: "overflow.example".into(),
                provider: None,
                country: None,
                city: None,
                ip_type: None,
            })
            .await;
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "rule cap reached");
        let reply = controller
            .dispatch(ProxyControlRequest::ProxyRule {
                domain: "d0.example".into(),
                provider: None,
                country: None,
                city: None,
                ip_type: None,
            })
            .await;
        assert_eq!(reply["ok"], true);
    }

    #[tokio::test]
    async fn proxy_rule_rejects_oversized_field() {
        let limits = ProxyControlLimits::default();
        let controller = test_controller(vec![], limits);
        let huge = "a".repeat(limits.max_field_bytes + 1);
        let reply = controller
            .dispatch(ProxyControlRequest::ProxyRule {
                domain: huge.clone(),
                provider: None,
                country: None,
                city: None,
                ip_type: None,
            })
            .await;
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "domain too long");

        let reply = controller
            .dispatch(ProxyControlRequest::ProxyRule {
                domain: "ok.example".into(),
                provider: Some(huge.clone()),
                country: None,
                city: None,
                ip_type: None,
            })
            .await;
        assert_eq!(reply["ok"], false);
        assert!(reply["error"]
            .as_str()
            .map(|s| s.starts_with("field too long"))
            .unwrap_or(false));
    }

    #[tokio::test]
    async fn template_spawn_returns_isolated_controllers() {
        let template = ProxyControllerTemplate::new(vec![Arc::new(DummyProvider {
            id: "t",
            configured: true,
        })]);
        let limits = ProxyControlLimits::default();
        let a = template.spawn(limits, None);
        let b = template.spawn(limits, None);
        a.dispatch(ProxyControlRequest::ProxySet {
            provider: Some("t".into()),
            country: None,
            city: None,
            ip_type: None,
        })
        .await;
        assert!(a.current().is_some());
        assert!(
            b.current().is_none(),
            "spawned controllers must not share state"
        );
    }

    #[tokio::test]
    async fn proxied_streams_get_the_resolved_address_policy() {
        let controller = test_controller(
            vec![Arc::new(DummyProvider {
                id: "dummy",
                configured: true,
            })],
            ProxyControlLimits::default(),
        );
        assert!(!controller.routes_through_proxy("example.com"));
        controller
            .dispatch(ProxyControlRequest::ProxySet {
                provider: Some("dummy".into()),
                country: None,
                city: None,
                ip_type: None,
            })
            .await;
        assert!(controller.current().is_some());
        assert!(controller.routes_through_proxy("example.com"));

        let err = controller
            .connect_tcp("127.0.0.1", 80, false, &loopback_policy())
            .await
            .expect_err("a proxied stream to loopback must be refused");
        assert!(
            matches!(
                err,
                ProxyConnectError::Connect(ConnectError::Policy(
                    wisp_proxy::ProxyError::LoopbackBlocked(_)
                ))
            ),
            "got {err:?}"
        );
        let err = controller
            .connect_tcp("16843009", 80, false, &loopback_policy())
            .await
            .expect_err("numeric aliases are not names on the proxied path either");
        assert!(matches!(
            err,
            ProxyConnectError::Connect(ConnectError::Policy(wisp_proxy::ProxyError::InvalidHost))
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = |blacklist: Option<Vec<String>>| {
            HostPolicy::from_options(&wisp_config::WispServerOptions {
                allow_direct_ip: true,
                allow_private_ips: true,
                allow_loopback_ips: true,
                port_whitelist: None,
                ip_blacklist: blacklist,
                ..wisp_config::WispServerOptions::default()
            })
        };
        let err = controller
            .connect_tcp(
                "127.0.0.1",
                port,
                false,
                &open(Some(vec!["127.0.0.0/8".to_owned()])),
            )
            .await
            .expect_err("ip_blacklist applies to proxied streams");
        assert!(matches!(
            err,
            ProxyConnectError::Connect(ConnectError::Policy(wisp_proxy::ProxyError::HostBlocked(
                _
            )))
        ));
        let (stream, active) = controller
            .connect_tcp("127.0.0.1", port, false, &open(None))
            .await
            .expect("an allowed address goes through the proxy");
        assert!(active.is_some());
        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn connect_tcp_direct_fallback_rejects_loopback_via_policy() {
        let controller = test_controller(vec![], ProxyControlLimits::default());
        let policy = loopback_policy();
        let err = controller
            .connect_tcp("127.0.0.1", 80, false, &policy)
            .await
            .expect_err("loopback direct connect must be blocked by policy");
        assert!(
            matches!(
                err,
                ProxyConnectError::Connect(ConnectError::Policy(
                    wisp_proxy::ProxyError::LoopbackBlocked(_)
                ))
            ),
            "expected typed policy rejection, got {err:?}"
        );
    }

    #[tokio::test]
    async fn per_ip_budget_is_shared_across_connections() {
        let limits = ProxyControlLimits {
            mutation_ops_per_second: NonZeroU32::new(1).unwrap(),
            mutation_burst: NonZeroU32::new(2).unwrap(),
            ..ProxyControlLimits::default()
        };
        let store = Arc::new(DosGuard::new());
        let template = ProxyControllerTemplate::new(vec![]);
        let a = template.spawn(limits, None);
        let b = template.spawn(limits, None);
        let other_ip = template.spawn(limits, None);
        a.bind_ip_budget("203.0.113.9".to_owned(), store.clone());
        b.bind_ip_budget("203.0.113.9".to_owned(), store.clone());
        other_ip.bind_ip_budget("203.0.113.10".to_owned(), store);

        for _ in 0..2 {
            let reply = a.dispatch(ProxyControlRequest::ProxyOn).await;
            assert!(reply["error"].is_null(), "{reply}");
        }
        // The second connection from the same IP finds the budget spent,
        // although its own per-connection bucket is untouched.
        let reply = b.dispatch(ProxyControlRequest::ProxyOn).await;
        assert_eq!(reply["error"], "rate limited", "{reply}");
        let reply = other_ip.dispatch(ProxyControlRequest::ProxyOn).await;
        assert!(reply["error"].is_null(), "{reply}");
    }

    #[test]
    fn logged_control_text_is_cut_on_a_char_boundary() {
        let long = "\u{e9}".repeat(1000);
        let cut = truncate_for_log(&long);
        assert!(cut.len() <= 256 && long.starts_with(cut));
        assert_eq!(truncate_for_log("short"), "short");
    }

    fn hop_controller(
        template: &ProxyControllerTemplate,
        ip: &str,
        token: Option<&str>,
    ) -> Arc<ProxyController> {
        let controller = template.spawn(ProxyControlLimits::default(), None);
        controller.bind_client(ip, token);
        controller
    }

    fn set_request(provider: &str) -> ProxyControlRequest {
        ProxyControlRequest::ProxySet {
            provider: Some(provider.into()),
            country: None,
            city: None,
            ip_type: None,
        }
    }

    fn hop_template(provider: &'static str, limits: ProxyHopLimits) -> ProxyControllerTemplate {
        let template = ProxyControllerTemplate::new(vec![Arc::new(DummyProvider {
            id: provider,
            configured: true,
        })]);
        template.set_hop_limits(limits);
        template
    }

    #[tokio::test]
    async fn connection_hop_limit_refuses_further_switches() {
        let template = hop_template(
            "dummy",
            ProxyHopLimits {
                max_per_connection: Some(2),
                max_per_ip_per_day: None,
                max_per_token_per_day: None,
            },
        );
        let controller = hop_controller(&template, "198.51.100.1", None);
        for _ in 0..2 {
            let reply = controller.dispatch(set_request("dummy")).await;
            assert_eq!(reply["ok"], true);
        }
        let reply = controller.dispatch(set_request("dummy")).await;
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "hop limit reached");
    }

    #[tokio::test]
    async fn ip_and_token_hop_limits_span_connections() {
        let template = hop_template(
            "dummy",
            ProxyHopLimits {
                max_per_connection: None,
                max_per_ip_per_day: Some(2),
                max_per_token_per_day: Some(1),
            },
        );
        let a = hop_controller(&template, "198.51.100.2", Some("tok-a"));
        assert_eq!(a.dispatch(set_request("dummy")).await["ok"], true);
        // Same token on a new connection from another IP is refused.
        let b = hop_controller(&template, "198.51.100.3", Some("tok-a"));
        assert_eq!(b.dispatch(set_request("dummy")).await["ok"], false);
        // A refused hop is not charged to the IP either.
        let c = hop_controller(&template, "198.51.100.3", Some("tok-c"));
        assert_eq!(c.dispatch(set_request("dummy")).await["ok"], true);
        // Same IP, new connection and token: the IP counter is shared.
        let d = hop_controller(&template, "198.51.100.2", Some("tok-d"));
        assert_eq!(d.dispatch(set_request("dummy")).await["ok"], true);
        let e = hop_controller(&template, "198.51.100.2", Some("tok-e"));
        assert_eq!(e.dispatch(set_request("dummy")).await["ok"], false);
    }

    #[test]
    fn hop_windows_expire_and_stay_bounded() {
        let mut shared = SharedControllerState::default();
        let t0 = Instant::now();
        let scope = [("ip", "ip:x".to_owned(), 1)];
        assert!(shared.charge_hops(&scope, t0).is_ok());
        assert_eq!(
            shared.charge_hops(&scope, t0),
            Err(HopDenied {
                scope: "ip",
                limit: 1
            })
        );
        assert!(shared
            .charge_hops(&scope, t0 + HOP_WINDOW + Duration::from_secs(1))
            .is_ok());
        for index in 0..MAX_HOP_KEYS + 10 {
            let scope = [("ip", format!("ip:{index}"), 5)];
            shared.charge_hops(&scope, t0).unwrap();
        }
        assert_eq!(shared.hops.len(), MAX_HOP_KEYS);
    }

    #[tokio::test]
    async fn hop_reports_are_emitted_for_denials_and_switches() {
        use parking_lot::Mutex as PlMutex;
        type Seen = (String, Option<String>, Option<String>);
        let seen: Arc<PlMutex<Vec<Seen>>> = Arc::new(PlMutex::new(Vec::new()));
        let sink = seen.clone();
        wisp_reports::set_report_hook(Some(Arc::new(move |report: &wisp_reports::Report| {
            if report.provider.as_deref() == Some("hookprov") {
                sink.lock().push((
                    report.report_code.to_owned(),
                    report.proxy_request_type.clone(),
                    report.limit_type.clone(),
                ));
            }
        })));
        let template = hop_template(
            "hookprov",
            ProxyHopLimits {
                max_per_connection: Some(1),
                max_per_ip_per_day: None,
                max_per_token_per_day: None,
            },
        );
        let controller = hop_controller(&template, "198.51.100.9", None);
        controller.dispatch(set_request("hookprov")).await;
        controller.dispatch(set_request("hookprov")).await;
        wisp_reports::set_report_hook(None);
        let seen = seen.lock().clone();
        assert_eq!(
            seen,
            vec![
                (
                    "WISP_PROXY_CONTROL_SWITCH".to_owned(),
                    Some("proxy_set".to_owned()),
                    None
                ),
                (
                    "WISP_PROXY_HOP_LIMIT_EXCEEDED".to_owned(),
                    Some("proxy_set".to_owned()),
                    Some("session".to_owned())
                ),
            ]
        );
    }

    #[tokio::test]
    async fn rule_resolution_does_not_enable_proxying_for_the_connection() {
        let controller = test_controller(
            vec![Arc::new(DummyProvider {
                id: "dummy",
                configured: true,
            })],
            ProxyControlLimits::default(),
        );
        let request = ProxyProviderRequest {
            provider: Some("dummy".into()),
            ..Default::default()
        };
        controller.proxy_for_request(&request).await.unwrap();
        assert!(controller.current().is_none());
        assert!(controller.current_when_enabled().is_none());
        assert!(!controller.state.lock().enabled);
        // The second use comes from the per-rule cache and costs no hop.
        controller.proxy_for_request(&request).await.unwrap();
        assert_eq!(controller.state.lock().session_hops, 1);
    }

    #[tokio::test]
    async fn rule_hop_limit_applies_to_new_resolutions() {
        let template = hop_template(
            "dummy",
            ProxyHopLimits {
                max_per_connection: Some(1),
                max_per_ip_per_day: None,
                max_per_token_per_day: None,
            },
        );
        let controller = hop_controller(&template, "198.51.100.10", None);
        let first = ProxyProviderRequest {
            provider: Some("dummy".into()),
            country: Some("us".into()),
            ..Default::default()
        };
        let second = ProxyProviderRequest {
            provider: Some("dummy".into()),
            country: Some("de".into()),
            ..Default::default()
        };
        controller.proxy_for_request(&first).await.unwrap();
        let err = controller.proxy_for_request(&second).await.unwrap_err();
        assert!(matches!(err, ProxyConnectError::HopLimitExceeded), "{err}");
    }
}

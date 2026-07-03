//! STELLITE_PROXY_CONTROL (extension 0x03) text-channel router.
//!
//! Wire-compatible with `stellite-wisp/src/wisp/server.ts#handleText`.
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
use std::sync::Arc;

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

use wisp_proxy_base::{
    open_proxy_tcp_socket, ActiveProxy, ProxyProvider, ProxyProviderRequest, ProxyResolveError,
    ProxyTunnelError, SharedProvider,
};

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
    pub active: Option<ActiveProxy>,
}

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
    #[error("direct connect failed: {0}")]
    Direct(#[from] std::io::Error),
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
}

#[derive(Debug, Default)]
struct ControllerState {
    enabled: bool,
    mode: String,
    current: Option<ActiveProxy>,
    rules: HashMap<String, ProxyProviderRequest>,
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
        active: route.active.clone(),
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
    }
}

/// Shared, process-lifetime template. Holds the heavy provider registry
/// (Mullvad relay cache, residential-proxy HTTP client, etc.). Cheap to
/// clone (a `Vec<Arc<dyn ProxyProvider>>`). Call [`Self::spawn`] per
/// accepted connection to mint a fresh per-connection [`ProxyController`]
/// that shares the providers but owns its own rules, current proxy,
/// enabled flag, and upstream rate limiter.
///
/// Audit-2 fix #55 split this off from `ProxyController` so a single
/// abuser cannot starve every other tenant's rate-limit budget, exhaust
/// the rules cap for everyone, or flip the shared "current proxy" out
/// from under siblings.
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
        let mut routes: Vec<Value> = guard
            .routes
            .values()
            .map(|route| serde_json::to_value(snapshot_route(route)).unwrap_or(Value::Null))
            .collect();
        routes.sort_by(|a, b| {
            let left = a.get("routeId").and_then(Value::as_str).unwrap_or_default();
            let right = b.get("routeId").and_then(Value::as_str).unwrap_or_default();
            left.cmp(right)
        });
        json!({
            "routes": routes,
            "blockedEgressIps": sorted_blocked_ips(&guard.blocked_egress_ips),
            "policy": guard.policy,
        })
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
    limits: ProxyControlLimits,
    allowed_proxy_providers: Option<HashSet<String>>,
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

    pub fn current(&self) -> Option<ActiveProxy> {
        self.state.lock().current.clone()
    }

    pub async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
        force_proxy: bool,
    ) -> Result<(TcpStream, Option<ActiveProxy>), ProxyConnectError> {
        if let Some((route_id, request, current)) = self.shared_route_for_host(host) {
            let proxy = if let Some(proxy) = current {
                proxy
            } else {
                let proxy = self.resolve_request(&request).await?;
                self.remember_route_proxy(&route_id, &proxy);
                proxy
            };
            self.check_proxy_allowed(&proxy)?;
            let stream = open_proxy_tcp_socket(&proxy, host, port).await?;
            return Ok((stream, Some(proxy)));
        }

        if let Some(request) = self.shared_default_request() {
            let proxy = self.resolve_request(&request).await?;
            self.check_proxy_allowed(&proxy)?;
            let stream = open_proxy_tcp_socket(&proxy, host, port).await?;
            return Ok((stream, Some(proxy)));
        }

        if let Some(proxy) = self.current_when_enabled() {
            self.check_proxy_allowed(&proxy)?;
            let stream = open_proxy_tcp_socket(&proxy, host, port).await?;
            return Ok((stream, Some(proxy)));
        }

        if force_proxy {
            return Err(ProxyConnectError::NoProxy);
        }

        let stream = TcpStream::connect((host, port)).await?;
        Ok((stream, None))
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
                if self.upstream_limiter.check().is_err() {
                    return json!({
                        "type": "proxy_set_result",
                        "ok": false,
                        "error": "rate limited",
                    });
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
                    return json!({
                        "type": "proxy_set_result",
                        "ok": false,
                        "error": format!("field too long: {bad}"),
                    });
                }
                let request = ProxyProviderRequest {
                    provider: provider.clone(),
                    country,
                    city,
                    ip_type,
                };
                let provider_ref = self.find_for_request(&request);
                let Some(p) = provider_ref else {
                    return json!({
                        "type": "proxy_set_result",
                        "ok": false,
                        "error": "no provider matches the request",
                    });
                };
                if !self.provider_is_allowed(p.as_ref()) {
                    return json!({
                        "type": "proxy_set_result",
                        "ok": false,
                        "error": "provider requires authentication",
                    });
                }
                if !p.is_configured() {
                    return json!({
                        "type": "proxy_set_result",
                        "ok": false,
                        "error": p.unconfigured_message(),
                    });
                }
                match p.resolve(&request, None).await {
                    Ok(Some(proxy)) => {
                        let mut guard = self.state.lock();
                        guard.current = Some(proxy.clone());
                        guard.enabled = true;
                        drop(guard);
                        json!({
                            "type": "proxy_set_result",
                            "ok": true,
                            "active": proxy,
                        })
                    }
                    Ok(None) => json!({
                        "type": "proxy_set_result",
                        "ok": false,
                        "error": "provider returned no proxy",
                    }),
                    Err(e) => {
                        warn!(provider = p.id(), error = %e, "proxy_set: resolve failed");
                        json!({
                            "type": "proxy_set_result",
                            "ok": false,
                            "error": e.to_string(),
                        })
                    }
                }
            }
            ProxyControlRequest::ProxyRotate => {
                if self.upstream_limiter.check().is_err() {
                    return json!({
                        "type": "proxy_rotate_result",
                        "ok": false,
                        "error": "rate limited",
                    });
                }
                let prev = self.state.lock().current.clone();
                let Some(prev) = prev else {
                    return json!({
                        "type": "proxy_rotate_result",
                        "ok": false,
                        "error": "no active proxy",
                    });
                };
                let provider_ref = self.find_by_id(prev.provider_id());
                let Some(p) = provider_ref else {
                    return json!({
                        "type": "proxy_rotate_result",
                        "ok": false,
                        "error": "provider not registered",
                    });
                };
                if !self.provider_is_allowed(p.as_ref()) {
                    return json!({
                        "type": "proxy_rotate_result",
                        "ok": false,
                        "error": "provider requires authentication",
                    });
                }
                match p.rotate(&prev).await {
                    Ok(Some(proxy)) => {
                        self.state.lock().current = Some(proxy.clone());
                        json!({
                            "type": "proxy_rotate_result",
                            "ok": true,
                            "active": proxy,
                        })
                    }
                    Ok(None) => json!({
                        "type": "proxy_rotate_result",
                        "ok": false,
                        "error": "rotation returned no new proxy",
                    }),
                    Err(e) => json!({
                        "type": "proxy_rotate_result",
                        "ok": false,
                        "error": e.to_string(),
                    }),
                }
            }
            ProxyControlRequest::ProxyOn => {
                if self.mutation_limiter.check().is_err() {
                    return json!({"type": "proxy_state", "ok": false, "error": "rate limited"});
                }
                self.state.lock().enabled = true;
                json!({"type": "proxy_state", "enabled": true})
            }
            ProxyControlRequest::ProxyOff => {
                if self.mutation_limiter.check().is_err() {
                    return json!({"type": "proxy_state", "ok": false, "error": "rate limited"});
                }
                let mut guard = self.state.lock();
                guard.enabled = false;
                guard.current = None;
                json!({"type": "proxy_state", "enabled": false})
            }
            ProxyControlRequest::ProxyMode { mode } => {
                if self.mutation_limiter.check().is_err() {
                    return json!({"type": "proxy_mode", "ok": false, "error": "rate limited"});
                }
                if mode.len() > self.limits.max_field_bytes {
                    return json!({"type": "proxy_mode", "ok": false, "error": "mode too long"});
                }
                self.state.lock().mode = mode.clone();
                json!({"type": "proxy_mode", "mode": mode})
            }
            ProxyControlRequest::ProxyRule {
                domain,
                provider,
                country,
                city,
                ip_type,
            } => {
                if self.mutation_limiter.check().is_err() {
                    return json!({
                        "type": "proxy_rule_set",
                        "domain": domain,
                        "ok": false,
                        "error": "rate limited",
                    });
                }
                if domain.len() > self.limits.max_field_bytes {
                    return json!({
                        "type": "proxy_rule_set",
                        "ok": false,
                        "error": "domain too long",
                    });
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
                    return json!({
                        "type": "proxy_rule_set",
                        "domain": domain,
                        "ok": false,
                        "error": format!("field too long: {bad}"),
                    });
                }
                let request = ProxyProviderRequest {
                    provider,
                    country,
                    city,
                    ip_type,
                };
                if request.provider.is_some() {
                    let provider_ref = self.find_for_request(&request);
                    let Some(p) = provider_ref else {
                        return json!({
                            "type": "proxy_rule_set",
                            "domain": domain,
                            "ok": false,
                            "error": "no provider matches the request",
                        });
                    };
                    if !self.provider_is_allowed(p.as_ref()) {
                        return json!({
                            "type": "proxy_rule_set",
                            "domain": domain,
                            "ok": false,
                            "error": "provider requires authentication",
                        });
                    }
                }
                let mut guard = self.state.lock();
                if guard.rules.len() >= self.limits.max_rules && !guard.rules.contains_key(&domain)
                {
                    return json!({
                        "type": "proxy_rule_set",
                        "domain": domain,
                        "ok": false,
                        "error": "rule cap reached",
                    });
                }
                guard.rules.insert(domain.clone(), request);
                drop(guard);
                json!({"type": "proxy_rule_set", "domain": domain, "ok": true})
            }
            ProxyControlRequest::ProxyRuleRemove { domain } => {
                if self.mutation_limiter.check().is_err() {
                    return json!({
                        "type": "proxy_rule_removed",
                        "domain": domain,
                        "removed": false,
                        "error": "rate limited",
                    });
                }
                let removed = self.state.lock().rules.remove(&domain).is_some();
                json!({"type": "proxy_rule_removed", "domain": domain, "removed": removed})
            }
            ProxyControlRequest::ProxyLocations { provider } => {
                if self.upstream_limiter.check().is_err() {
                    return json!({
                        "type": "proxy_locations_result",
                        "ok": false,
                        "error": "rate limited",
                    });
                }
                let target = provider.as_deref();
                // Audit-2 fix #56: enforce the cumulative reply-size budget
                // INSIDE the provider loop. Previously we materialized every
                // provider's full ProxyProviderLocations into a Vec<Value>,
                // serialized the whole tree to a String, and only then
                // checked the cap — a misbehaving provider returning 500 MB
                // of country names spent 1 GB of heap before the check
                // engaged. Now we serialize each provider's entry on its
                // own, check both a per-provider sub-cap and the running
                // total against MAX_PROXY_CONTROL_REPLY_BYTES, and bail out
                // early if anything overflows.
                let max_reply_bytes = self.limits.max_reply_bytes;
                let per_provider_cap = max_reply_bytes / 2;
                let reply_overhead: usize = 64;
                let mut out: Vec<Value> = Vec::with_capacity(self.providers.len());
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
                            let entry = json!({
                                "provider": p.id(),
                                "name": p.name(),
                                "locations": locs,
                            });
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
                let mut reply = json!({"type": "proxy_locations_result", "providers": out});
                if truncated {
                    reply["truncated"] = Value::Bool(true);
                }
                reply
            }
            ProxyControlRequest::ProxyListProviders => {
                if self.mutation_limiter.check().is_err() {
                    return json!({
                        "type": "proxy_list",
                        "ok": false,
                        "error": "rate limited",
                    });
                }
                let list: Vec<Value> = self
                    .providers
                    .iter()
                    .filter(|p| self.provider_is_allowed(p.as_ref()))
                    .map(|p| {
                        json!({
                            "id": p.id(),
                            "name": p.name(),
                            "aliases": p.aliases(),
                            "configured": p.is_configured(),
                        })
                    })
                    .collect();
                json!({"type": "proxy_list", "providers": list})
            }
        }
    }

    fn provider_is_allowed(&self, provider: &dyn ProxyProvider) -> bool {
        if provider.matches("resi") || provider.matches("mysterium") {
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

fn provider_allowed_by_set(provider: &dyn ProxyProvider, allowed: &HashSet<String>) -> bool {
    allowed.iter().any(|requested| provider.matches(requested))
}

/// Audit-3 fix #66: streaming length sink. `serde_json::to_writer` pushes
/// bytes into this; the moment the running count crosses `cap` we return
/// `ErrorKind::Other` so the serializer aborts. Avoids the
/// `to_string().len()` round-trip that materialized the full provider tree
/// into a `String` (2-3x heap) just to measure it.
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

fn measure_json_capped(value: &Value, cap: usize) -> MeasureResult {
    let mut sink = LengthCappedWriter {
        written: 0,
        cap,
        overflow: false,
    };
    match serde_json::to_writer(&mut sink, value) {
        Ok(()) => MeasureResult::Within(sink.written),
        Err(_) if sink.overflow => MeasureResult::Overflow,
        Err(_) => MeasureResult::Overflow,
    }
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
/// dropped to match the legacy server's tolerance for cross-extension noise.
pub async fn handle_proxy_control_text(
    controller: &Arc<ProxyController>,
    text: &str,
) -> Option<String> {
    let req: ProxyControlRequest = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "proxy_control: ignoring malformed text frame");
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
        let err = json!({"type": "proxy_control_error", "error": "reply too large"});
        return serde_json::to_string(&err).ok();
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
                provider: Some("anything".into()),
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
}

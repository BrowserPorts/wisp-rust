//! Strict-object TOML config loader for wisp-wt.
//!
//! Every `[wisp.*]` and `[wisp_wt]` section has a typed struct with
//! `#[serde(deny_unknown_fields)]`. There is no `[wisp_wt.advanced]` block:
//! there are no extension toggles — the protocol is fixed, and msquic
//! features (BBR, datagram priority, stream priority) are configured
//! unconditionally at engine startup.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("toml parse error in {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("config validation: {0}")]
    Validate(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

pub const WISP_BASE_LIMIT_PROFILE: &str = "__base";

// ----------------------------------------------------------- enum types ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowedProtocol {
    Http,
    Https,
    Http2,
    Ws,
    H3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsMethod {
    Lookup,
    Resolve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsResultOrder {
    Verbatim,
    Ipv4first,
    Ipv6first,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitBackend {
    Auto,
    Memory,
    Redis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WispVersion {
    V1,
    V2,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WtEngine {
    /// Compatibility shims; the Rust runtime always uses msquic regardless.
    Bun,
    Fails,
    Msquic,
}

// ----------------------------------------------------- runtime options ----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WispServerOptions {
    pub endpoint: String,
    pub domain_blacklist: Option<Vec<String>>,
    pub domain_whitelist: Option<Vec<String>>,
    pub hostname_blacklist: Option<Vec<String>>,
    pub hostname_whitelist: Option<Vec<String>>,
    pub ip_blacklist: Option<Vec<String>>,
    pub ip_whitelist: Option<Vec<String>>,
    pub port_blacklist: Option<Vec<u16>>,
    pub port_whitelist: Option<Vec<u16>>,
    pub origin_blacklist: Option<Vec<String>>,
    pub origin_whitelist: Option<Vec<String>>,
    pub block_blank_origins: bool,
    pub allow_direct_ip: bool,
    pub allow_direct_ip_with_domain_policy: bool,
    pub allow_private_ips: bool,
    pub allow_loopback_ips: bool,
    pub client_ip_blacklist: Option<Vec<String>>,
    pub client_ip_whitelist: Option<Vec<String>>,
    pub stream_limit_per_host: i64,
    pub stream_limit_total: u64,
    pub allow_udp_streams: bool,
    pub allow_tcp_streams: bool,
    pub dns_ttl: u64,
    pub dns_method: DnsMethod,
    pub dns_servers: Option<Vec<String>>,
    pub dns_result_order: DnsResultOrder,
    pub dns_negative_ttl: u64,
    pub dns_cache_max_entries: u64,
    pub max_dns_resolutions_per_ip_per_minute: u64,
    pub max_dns_resolutions_per_minute: u64,
    pub max_unique_hostnames_per_ip_per_minute: u64,
    pub parse_real_ip: bool,
    pub parse_real_ip_from: Vec<String>,
    pub buffer_size: u64,
    pub continue_threshold: u64,
    pub max_connections: u64,
    pub max_connections_per_ip: u64,
    pub max_binary_frame_bytes: u64,
    pub max_text_frame_bytes: u64,
    pub max_host_bytes: u64,
    pub max_pending_packets_per_stream: u64,
    pub max_session_hops: Option<u64>,
    pub max_daily_hops_per_ip: Option<u64>,
    pub max_connection_starts_per_ip_per_minute: u64,
    pub max_connection_starts_per_minute: u64,
    pub max_tcp_stream_opens_per_connection_per_minute: u64,
    pub max_tcp_stream_opens_per_ip_per_minute: u64,
    pub max_tcp_bytes_per_connection_per_second: u64,
    pub max_tcp_bytes_per_ip_per_second: u64,
    pub max_datagrams_per_connection_per_second: u64,
    pub max_datagram_bytes_per_connection_per_second: u64,
    pub max_datagrams_per_ip_per_second: u64,
    pub max_datagram_bytes_per_ip_per_second: u64,
    pub datagram_rate_limit_strikes: u64,
    pub datagram_rate_limit_strike_window_ms: u64,
    pub max_control_messages_per_connection_per_minute: u64,
    pub max_control_messages_per_ip_per_minute: u64,
    pub max_binary_packets_per_connection_per_minute: u64,
    pub max_concurrent_proxy_control_handlers: u64,
    pub proxy_control_ext_payload_max_bytes: u64,
    pub max_proxy_rules_per_connection: u64,
    pub max_proxy_control_reply_bytes: u64,
    pub max_proxy_rule_field_bytes: u64,
    pub proxy_control_upstream_ops_per_second: u32,
    pub proxy_control_upstream_burst: u32,
    pub proxy_control_mutation_ops_per_second: u32,
    pub proxy_control_mutation_burst: u32,
    pub rate_limit_backend: RateLimitBackend,
    pub redis_rate_limit_url: Option<String>,
    pub redis_rate_limit_key_prefix: String,
    pub redis_rate_limit_hash_tag: String,
    pub redis_rate_limit_fail_open: bool,
    pub stream_idle_timeout_ms: Option<u64>,
    pub protocol_inspection: bool,
    pub protocol_inspection_allowed_protocols: Vec<AllowedProtocol>,
    pub protocol_inspection_max_bytes: u64,
    pub protocol_inspection_timeout_ms: Option<u64>,
    pub protocol_inspection_allow_h2c: bool,
    pub protocol_inspection_allow_tls_without_alpn: bool,
    pub protocol_inspection_allow_quic_initial: bool,
    pub localhost_violation_ban_ms: u64,
    pub security_violation_ban_ms: u64,
    pub force_proxy: bool,
    pub connect_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
    pub handshake_timeout_ms: Option<u64>,
    pub wisp_version: WispVersion,
    pub auth: WispAuthOptions,
}

impl Default for WispServerOptions {
    fn default() -> Self {
        let buf = 16 * 1024 * 1024_u64;
        Self {
            endpoint: "/wisp".to_owned(),
            domain_blacklist: None,
            domain_whitelist: None,
            hostname_blacklist: None,
            hostname_whitelist: None,
            ip_blacklist: None,
            ip_whitelist: None,
            port_blacklist: None,
            port_whitelist: Some(vec![80, 443]),
            origin_blacklist: None,
            origin_whitelist: None,
            block_blank_origins: true,
            allow_direct_ip: true,
            allow_direct_ip_with_domain_policy: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
            client_ip_blacklist: None,
            client_ip_whitelist: None,
            stream_limit_per_host: -1,
            stream_limit_total: 64,
            allow_udp_streams: true,
            allow_tcp_streams: true,
            dns_ttl: 120,
            dns_method: DnsMethod::Lookup,
            dns_servers: None,
            dns_result_order: DnsResultOrder::Verbatim,
            dns_negative_ttl: 60,
            dns_cache_max_entries: 4096,
            max_dns_resolutions_per_ip_per_minute: 120,
            max_dns_resolutions_per_minute: 2048,
            max_unique_hostnames_per_ip_per_minute: 60,
            parse_real_ip: true,
            parse_real_ip_from: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
            buffer_size: buf,
            continue_threshold: (buf * 90) / 100,
            max_connections: 512,
            max_connections_per_ip: 32,
            max_binary_frame_bytes: buf,
            max_text_frame_bytes: 64 * 1024,
            max_host_bytes: 253,
            max_pending_packets_per_stream: 128,
            max_session_hops: Some(16),
            max_daily_hops_per_ip: None,
            max_connection_starts_per_ip_per_minute: 120,
            max_connection_starts_per_minute: 4096,
            max_tcp_stream_opens_per_connection_per_minute: 120,
            max_tcp_stream_opens_per_ip_per_minute: 480,
            max_tcp_bytes_per_connection_per_second: 64 * 1024 * 1024,
            max_tcp_bytes_per_ip_per_second: 256 * 1024 * 1024,
            max_datagrams_per_connection_per_second: 4096,
            max_datagram_bytes_per_connection_per_second: 32 * 1024 * 1024,
            max_datagrams_per_ip_per_second: 16384,
            max_datagram_bytes_per_ip_per_second: 128 * 1024 * 1024,
            datagram_rate_limit_strikes: 3,
            datagram_rate_limit_strike_window_ms: 10_000,
            max_control_messages_per_connection_per_minute: 60,
            max_control_messages_per_ip_per_minute: 240,
            max_binary_packets_per_connection_per_minute: 0,
            max_concurrent_proxy_control_handlers: 16,
            proxy_control_ext_payload_max_bytes: 256,
            max_proxy_rules_per_connection: 256,
            max_proxy_control_reply_bytes: 64 * 1024,
            max_proxy_rule_field_bytes: 256,
            proxy_control_upstream_ops_per_second: 8,
            proxy_control_upstream_burst: 16,
            proxy_control_mutation_ops_per_second: 64,
            proxy_control_mutation_burst: 320,
            rate_limit_backend: RateLimitBackend::Auto,
            redis_rate_limit_url: None,
            redis_rate_limit_key_prefix: "wisp-wt".to_owned(),
            redis_rate_limit_hash_tag: "rate-limit".to_owned(),
            redis_rate_limit_fail_open: false,
            stream_idle_timeout_ms: Some(60_000),
            protocol_inspection: true,
            protocol_inspection_allowed_protocols: vec![
                AllowedProtocol::Http,
                AllowedProtocol::Https,
                AllowedProtocol::Http2,
                AllowedProtocol::Ws,
                AllowedProtocol::H3,
            ],
            protocol_inspection_max_bytes: 64 * 1024,
            protocol_inspection_timeout_ms: Some(10_000),
            protocol_inspection_allow_h2c: true,
            protocol_inspection_allow_tls_without_alpn: true,
            protocol_inspection_allow_quic_initial: false,
            localhost_violation_ban_ms: 30 * 60 * 1000,
            security_violation_ban_ms: 30 * 60 * 1000,
            force_proxy: false,
            connect_timeout_ms: Some(10_000),
            idle_timeout_ms: Some(120_000),
            handshake_timeout_ms: Some(10_000),
            wisp_version: WispVersion::Auto,
            auth: WispAuthOptions::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WispAuthOptions {
    pub required: bool,
    pub token_path: bool,
}

impl Default for WispAuthOptions {
    fn default() -> Self {
        Self {
            required: false,
            token_path: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WispAuthTokenPolicy {
    pub limit_profile: Option<String>,
    pub allowed_proxy_providers: Option<Vec<String>>,
    pub domain_blacklist: Option<Vec<String>>,
    pub domain_whitelist: Option<Vec<String>>,
    pub hostname_blacklist: Option<Vec<String>>,
    pub hostname_whitelist: Option<Vec<String>>,
    pub ip_blacklist: Option<Vec<String>>,
    pub ip_whitelist: Option<Vec<String>>,
    pub port_blacklist: Option<Vec<u16>>,
    pub port_whitelist: Option<Vec<u16>>,
    pub allow_direct_ip: Option<bool>,
    pub allow_direct_ip_with_domain_policy: Option<bool>,
    pub allow_private_ips: Option<bool>,
    pub allow_loopback_ips: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct WispResolvedAuth {
    pub options: WispServerOptions,
    pub policy: WispAuthTokenPolicy,
}

impl WispAuthTokenPolicy {
    pub fn apply_to(&self, base: &WispServerOptions) -> WispServerOptions {
        let mut out = base.clone();
        if let Some(v) = self
            .domain_blacklist
            .clone()
            .or_else(|| self.hostname_blacklist.clone())
        {
            out.domain_blacklist = Some(v.clone());
            out.hostname_blacklist = Some(v);
        }
        if let Some(v) = self
            .domain_whitelist
            .clone()
            .or_else(|| self.hostname_whitelist.clone())
        {
            out.domain_whitelist = Some(v.clone());
            out.hostname_whitelist = Some(v);
        }
        if let Some(v) = self.ip_blacklist.clone() {
            out.ip_blacklist = Some(v);
        }
        if let Some(v) = self.ip_whitelist.clone() {
            out.ip_whitelist = Some(v);
        }
        if let Some(v) = self.port_blacklist.clone() {
            out.port_blacklist = Some(v);
        }
        if let Some(v) = self.port_whitelist.clone() {
            out.port_whitelist = Some(v);
        }
        if let Some(v) = self.allow_direct_ip {
            out.allow_direct_ip = v;
        }
        if let Some(v) = self.allow_direct_ip_with_domain_policy {
            out.allow_direct_ip_with_domain_policy = v;
        }
        if let Some(v) = self.allow_private_ips {
            out.allow_private_ips = v;
        }
        if let Some(v) = self.allow_loopback_ips {
            out.allow_loopback_ips = v;
        }
        out
    }
}

pub type WispAuthResolveFuture =
    Pin<Box<dyn Future<Output = Option<WispAuthTokenPolicy>> + Send + 'static>>;

pub trait WispAuthResolver: Send + Sync {
    fn resolve(&self, token: String) -> WispAuthResolveFuture;
}

#[derive(Clone, Default)]
pub struct WispAuthRegistry {
    profiles: Arc<RwLock<HashMap<String, WispServerOptions>>>,
    resolver: Arc<RwLock<Option<Arc<dyn WispAuthResolver>>>>,
}

impl WispAuthRegistry {
    pub fn register_profile(&self, name: String, options: WispServerOptions) -> bool {
        let normalized = name.trim();
        if normalized.is_empty() || normalized.contains('/') {
            return false;
        }
        self.profiles
            .write()
            .expect("wisp auth profile registry poisoned")
            .insert(normalized.to_owned(), options);
        true
    }

    pub fn remove_profile(&self, name: &str) -> Option<WispServerOptions> {
        self.profiles
            .write()
            .expect("wisp auth profile registry poisoned")
            .remove(name)
    }

    pub fn profile(&self, name: &str) -> Option<WispServerOptions> {
        self.profiles
            .read()
            .expect("wisp auth profile registry poisoned")
            .get(name)
            .cloned()
    }

    pub fn list_profiles(&self) -> Vec<(String, WispServerOptions)> {
        let mut out: Vec<(String, WispServerOptions)> = self
            .profiles
            .read()
            .expect("wisp auth profile registry poisoned")
            .iter()
            .map(|(name, options)| (name.clone(), options.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn set_resolver(&self, resolver: Arc<dyn WispAuthResolver>) {
        self.resolver
            .write()
            .expect("wisp auth token registry poisoned")
            .replace(resolver);
    }

    pub fn clear_resolver(&self) {
        self.resolver
            .write()
            .expect("wisp auth token registry poisoned")
            .take();
    }

    pub async fn resolve(
        &self,
        token: String,
        base: &WispServerOptions,
    ) -> Option<WispResolvedAuth> {
        let resolver = self
            .resolver
            .read()
            .expect("wisp auth token registry poisoned")
            .clone()?;
        let policy = resolver.resolve(token).await?;
        self.resolve_policy(policy, base)
    }

    fn resolve_policy(
        &self,
        policy: WispAuthTokenPolicy,
        base: &WispServerOptions,
    ) -> Option<WispResolvedAuth> {
        let profile_base = if let Some(profile) = policy.limit_profile.as_deref() {
            self.profile(profile)?
        } else {
            base.clone()
        };
        let options = policy.apply_to(&profile_base);
        Some(WispResolvedAuth { options, policy })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WispWtServerOptions {
    pub base: WispServerOptions,
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub max_datagram_bytes: u32,
    pub wt_engine: WtEngine,
    /// Wisp-over-WebSocket server. Independent of the WT side — both
    /// can be enabled simultaneously (one on UDP/QUIC, one on TCP/H2).
    /// The cert/key default to the WT pair when omitted so a single
    /// PEM identity covers both transports on the same hostname.
    pub websocket: WispWebSocketOptions,
    /// Whether the STELLITE_PROXY_CONTROL (0x03) extension is advertised
    /// on either transport. Mirrors `wisp.proxy.proxy_control_enabled`
    /// from the bun reference; defaults off so existing configs stay
    /// quiet about it.
    pub proxy_control_enabled: bool,
    /// Mullvad provider config (None when section absent or disabled).
    pub mullvad: Option<MullvadProviderConfig>,
    /// Residential provider config (None when section absent or disabled).
    pub resi: Option<ResiProviderConfig>,
}

/// Resolved Mullvad config — the validated subset of [`WispMullvadToml`]
/// after defaulting. The provider crate consumes this without re-parsing.
#[derive(Debug, Clone, PartialEq)]
pub struct MullvadProviderConfig {
    pub relay_api: String,
    pub wireproxy_socks5: Option<String>,
}

/// Resolved residential provider config.
#[derive(Debug, Clone, PartialEq)]
pub struct ResiProviderConfig {
    pub bearer_token: Option<String>,
    pub cookie: Option<String>,
    pub api_base: String,
    pub country: String,
    pub ip_type: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WispWebSocketOptions {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    /// Optional unified `host:port` (or IPv6 `[::]:port`) string. When
    /// set, wins over `host` + `port`. Useful for deployments that
    /// configure listeners via a single env-var-style address.
    pub bind_addr: Option<String>,
    /// When None, falls back to `WispWtServerOptions::cert_path` at
    /// runtime — same identity, single PEM pair on shared hostnames.
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    /// WS-specific endpoint path. Defaults to the same value as
    /// `base.endpoint` because most deployments terminate WS and WT on
    /// the same URL.
    pub endpoint: Option<String>,
    /// Per-transport override for the STELLITE_PROXY_CONTROL extension
    /// advertisement. `None` inherits the value from
    /// `WispWtServerOptions::proxy_control_enabled` so a single root-level
    /// toggle continues to apply to both transports unless explicitly
    /// overridden here.
    pub proxy_control_enabled: Option<bool>,
    /// When true, runs an RFC 6455 plain `ws://` listener (no TLS, HTTP/1.1
    /// Upgrade) instead of the default `wss://` HTTP/2 extended-CONNECT
    /// listener. Wispmark and bench harnesses speak the plain variant; the
    /// HTTP/2 variant is the production deployment shape. Cert/key inputs
    /// are ignored when plain.
    pub plain: bool,
}

impl Default for WispWebSocketOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "0.0.0.0".to_owned(),
            port: 443,
            bind_addr: None,
            cert_path: None,
            key_path: None,
            endpoint: None,
            proxy_control_enabled: None,
            plain: false,
        }
    }
}

impl Default for WispWtServerOptions {
    fn default() -> Self {
        let base = WispServerOptions {
            endpoint: "/wisp-wt".to_owned(),
            ..Default::default()
        };
        Self {
            base,
            enabled: false,
            host: "0.0.0.0".to_owned(),
            port: 4433,
            cert_path: None,
            key_path: None,
            max_datagram_bytes: 65_535,
            wt_engine: WtEngine::Msquic,
            websocket: WispWebSocketOptions::default(),
            proxy_control_enabled: false,
            mullvad: None,
            resi: None,
        }
    }
}

// --------------------------------------------------------------- helpers ---

pub fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return "/wisp".to_owned();
    }
    if trimmed == "/" {
        return "/".to_owned();
    }
    let with_leading = if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{}", trimmed)
    };
    let stripped = with_leading.trim_end_matches('/');
    if stripped.is_empty() {
        "/wisp".to_owned()
    } else {
        stripped.to_owned()
    }
}

pub fn endpoint_matches(pathname: &str, endpoint: &str) -> bool {
    let n = normalize_endpoint(endpoint);
    pathname == n || pathname == format!("{}/", n)
}

pub fn endpoint_path_token<'a>(pathname: &'a str, endpoint: &str) -> Option<&'a str> {
    if endpoint_matches(pathname, endpoint) {
        return None;
    }
    let n = normalize_endpoint(endpoint);
    let suffix = if n == "/" {
        pathname.strip_prefix('/')?
    } else {
        let prefix = format!("{}/", n);
        pathname.strip_prefix(&prefix)?
    };
    let token = suffix.trim_end_matches('/');
    if token.is_empty() || token.contains('/') {
        None
    } else {
        Some(token)
    }
}

// ----------------------------------------------------------- TOML schemas --

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispServerToml {
    pub endpoint: Option<String>,
    pub buffer_size: Option<u64>,
    pub continue_threshold: Option<u64>,
    pub allow_tcp_streams: Option<bool>,
    pub allow_udp_streams: Option<bool>,
    pub stream_limit_per_host: Option<i64>,
    pub stream_limit_total: Option<u64>,
    pub wisp_version: Option<WispVersion>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispDestinationToml {
    pub domain_blacklist: Option<Vec<String>>,
    pub domain_whitelist: Option<Vec<String>>,
    pub hostname_blacklist: Option<Vec<String>>,
    pub hostname_whitelist: Option<Vec<String>>,
    pub ip_blacklist: Option<Vec<String>>,
    pub ip_whitelist: Option<Vec<String>>,
    pub port_blacklist: Option<Vec<u16>>,
    pub port_whitelist: Option<Vec<u16>>,
    pub allow_direct_ip: Option<bool>,
    pub allow_direct_ip_with_domain_policy: Option<bool>,
    pub allow_private_ips: Option<bool>,
    pub allow_loopback_ips: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispOriginToml {
    pub origin_blacklist: Option<Vec<String>>,
    pub origin_whitelist: Option<Vec<String>>,
    pub block_blank_origins: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispClientToml {
    pub client_ip_blacklist: Option<Vec<String>>,
    pub client_ip_whitelist: Option<Vec<String>>,
    pub parse_real_ip: Option<bool>,
    pub parse_real_ip_from: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispDnsToml {
    pub dns_ttl: Option<u64>,
    pub dns_method: Option<DnsMethod>,
    pub dns_servers: Option<Vec<String>>,
    pub dns_result_order: Option<DnsResultOrder>,
    pub dns_negative_ttl: Option<u64>,
    pub dns_cache_max_entries: Option<u64>,
    pub max_dns_resolutions_per_ip_per_minute: Option<u64>,
    pub max_dns_resolutions_per_minute: Option<u64>,
    pub max_unique_hostnames_per_ip_per_minute: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispLimitsToml {
    pub max_connections: Option<u64>,
    pub max_connections_per_ip: Option<u64>,
    pub max_binary_frame_bytes: Option<u64>,
    pub max_text_frame_bytes: Option<u64>,
    pub max_host_bytes: Option<u64>,
    pub max_pending_packets_per_stream: Option<u64>,
    pub max_connection_starts_per_ip_per_minute: Option<u64>,
    pub max_connection_starts_per_minute: Option<u64>,
    pub max_tcp_stream_opens_per_connection_per_minute: Option<u64>,
    pub max_tcp_stream_opens_per_ip_per_minute: Option<u64>,
    pub max_tcp_bytes_per_connection_per_second: Option<u64>,
    pub max_tcp_bytes_per_ip_per_second: Option<u64>,
    pub max_datagrams_per_connection_per_second: Option<u64>,
    pub max_datagram_bytes_per_connection_per_second: Option<u64>,
    pub max_datagrams_per_ip_per_second: Option<u64>,
    pub max_datagram_bytes_per_ip_per_second: Option<u64>,
    pub datagram_rate_limit_strikes: Option<u64>,
    pub datagram_rate_limit_strike_window_ms: Option<u64>,
    pub max_control_messages_per_connection_per_minute: Option<u64>,
    pub max_control_messages_per_ip_per_minute: Option<u64>,
    pub max_binary_packets_per_connection_per_minute: Option<u64>,
    pub max_concurrent_proxy_control_handlers: Option<u64>,
    pub proxy_control_ext_payload_max_bytes: Option<u64>,
    pub max_proxy_rules_per_connection: Option<u64>,
    pub max_proxy_control_reply_bytes: Option<u64>,
    pub max_proxy_rule_field_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispRateLimitToml {
    pub backend: Option<RateLimitBackend>,
    pub redis_key_prefix: Option<String>,
    pub redis_hash_tag: Option<String>,
    pub redis_fail_open: Option<bool>,
    pub redis_url: Option<String>,
    pub proxy_control_upstream_ops_per_second: Option<u32>,
    pub proxy_control_upstream_burst: Option<u32>,
    pub proxy_control_mutation_ops_per_second: Option<u32>,
    pub proxy_control_mutation_burst: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispTimeoutsToml {
    pub stream_idle_timeout_ms: Option<u64>,
    pub connect_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
    pub handshake_timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispProtocolInspectionToml {
    pub enabled: Option<bool>,
    pub allowed_protocols: Option<Vec<AllowedProtocol>>,
    pub max_bytes: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub allow_h2c: Option<bool>,
    pub allow_tls_without_alpn: Option<bool>,
    pub allow_quic_initial: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispSecurityToml {
    pub localhost_violation_ban_ms: Option<u64>,
    pub security_violation_ban_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispProxyToml {
    pub force_proxy: Option<bool>,
    pub max_session_hops: Option<NullableU64>,
    pub max_daily_hops_per_ip: Option<NullableU64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispAuthToml {
    pub required: Option<bool>,
    pub token_path: Option<bool>,
}

/// Mirrors TS `nullableInt`: accepts a non-negative int, or the strings
/// `"none" | "null" | "unset"` to mean explicit `None`.
#[derive(Debug, Clone, Copy)]
pub enum NullableU64 {
    Set(u64),
    Unset,
}

impl<'de> serde::Deserialize<'de> for NullableU64 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::{Error, Unexpected};
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            N(u64),
            S(String),
        }
        match Either::deserialize(d)? {
            Either::N(n) => Ok(NullableU64::Set(n)),
            Either::S(s) => match s.as_str() {
                "none" | "null" | "unset" => Ok(NullableU64::Unset),
                other => Err(D::Error::invalid_value(
                    Unexpected::Str(other),
                    &"one of \"none\", \"null\", \"unset\"",
                )),
            },
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispToml {
    pub server: Option<WispServerToml>,
    pub destination: Option<WispDestinationToml>,
    pub origin: Option<WispOriginToml>,
    pub client: Option<WispClientToml>,
    pub dns: Option<WispDnsToml>,
    pub limits: Option<WispLimitsToml>,
    pub rate_limit: Option<WispRateLimitToml>,
    pub timeouts: Option<WispTimeoutsToml>,
    pub protocol_inspection: Option<WispProtocolInspectionToml>,
    pub security: Option<WispSecurityToml>,
    pub proxy: Option<WispProxyToml>,
    pub auth: Option<WispAuthToml>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispWtToml {
    pub enabled: Option<bool>,
    pub endpoint: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub max_datagram_bytes: Option<u32>,
    pub wt_engine: Option<WtEngine>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispWebSocketToml {
    pub enabled: Option<bool>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub bind_addr: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub endpoint: Option<String>,
    pub proxy_control_enabled: Option<bool>,
    pub plain: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispProxyControlToml {
    pub enabled: Option<bool>,
}

/// `[wisp_proxy_mullvad]` — Mullvad WireGuard SOCKS5 provider config.
/// Mirrors the bun reference `proxy.mullvad`. Absent or `enabled = false`
/// keeps the provider out of the registry entirely.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WispMullvadToml {
    pub enabled: Option<bool>,
    pub relay_api: Option<String>,
    pub wireproxy_socks5: Option<String>,
}

/// `[wisp_proxy_resi]` — residential / partner HTTP-API proxy provider.
/// Mirrors the bun reference `proxy.residential`. The bearer token is
/// required; we still register the provider when missing so the client gets
/// a clear "not configured" error rather than silent absence.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WispResiToml {
    pub enabled: Option<bool>,
    pub bearer_token: Option<String>,
    pub cookie: Option<String>,
    pub api_base: Option<String>,
    pub country: Option<String>,
    pub ip_type: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispWtConfigToml {
    pub wisp: Option<WispToml>,
    pub wisp_wt: Option<WispWtToml>,
    /// `[wisp.websocket]` block — Wisp v2 over WebSocket transport
    /// settings. Independent of `[wisp_wt]`; both can be enabled.
    pub wisp_websocket: Option<WispWebSocketToml>,
    /// `[wisp.proxy_control]` block — toggles the STELLITE_PROXY_CONTROL
    /// extension (0x03) advertisement.
    pub wisp_proxy_control: Option<WispProxyControlToml>,
    /// `[wisp_proxy_mullvad]` — provider config for the Mullvad SOCKS5 relay set.
    pub wisp_proxy_mullvad: Option<WispMullvadToml>,
    /// `[wisp_proxy_resi]` — provider config for residential / partner proxies.
    pub wisp_proxy_resi: Option<WispResiToml>,
    /// Free-form proxy adapter section; not validated structurally.
    pub proxy: Option<toml::Value>,
}

// ------------------------------------------------------------- loaders -----

pub fn parse_toml(raw: &str, source: &str) -> Result<WispWtConfigToml> {
    toml::from_str::<WispWtConfigToml>(raw).map_err(|e| ConfigError::Parse {
        path: source.to_owned(),
        source: e,
    })
}

pub fn load_toml(path: &Path) -> Result<WispWtConfigToml> {
    if !path.exists() {
        return Ok(WispWtConfigToml::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    parse_toml(&raw, &path.display().to_string())
}

// --------------------------------------------------- merge into options ----

fn merge_wisp(opts: &mut WispServerOptions, t: &WispToml) {
    if let Some(s) = &t.server {
        if let Some(v) = &s.endpoint {
            opts.endpoint = normalize_endpoint(v);
        }
        if let Some(v) = s.buffer_size {
            opts.buffer_size = v;
        }
        if let Some(v) = s.continue_threshold {
            opts.continue_threshold = v;
        }
        if let Some(v) = s.allow_tcp_streams {
            opts.allow_tcp_streams = v;
        }
        if let Some(v) = s.allow_udp_streams {
            opts.allow_udp_streams = v;
        }
        if let Some(v) = s.stream_limit_per_host {
            opts.stream_limit_per_host = v;
        }
        if let Some(v) = s.stream_limit_total {
            opts.stream_limit_total = v;
        }
        if let Some(v) = s.wisp_version {
            opts.wisp_version = v;
        }
    }
    if let Some(d) = &t.destination {
        let dbl = d
            .domain_blacklist
            .clone()
            .or_else(|| d.hostname_blacklist.clone());
        if let Some(v) = dbl {
            opts.domain_blacklist = Some(v.clone());
            opts.hostname_blacklist = Some(v);
        }
        let dwl = d
            .domain_whitelist
            .clone()
            .or_else(|| d.hostname_whitelist.clone());
        if let Some(v) = dwl {
            opts.domain_whitelist = Some(v.clone());
            opts.hostname_whitelist = Some(v);
        }
        if let Some(v) = d.ip_blacklist.clone() {
            opts.ip_blacklist = Some(v);
        }
        if let Some(v) = d.ip_whitelist.clone() {
            opts.ip_whitelist = Some(v);
        }
        if let Some(v) = d.port_blacklist.clone() {
            opts.port_blacklist = Some(v);
        }
        if let Some(v) = d.port_whitelist.clone() {
            opts.port_whitelist = Some(v);
        }
        if let Some(v) = d.allow_direct_ip {
            opts.allow_direct_ip = v;
        }
        if let Some(v) = d.allow_direct_ip_with_domain_policy {
            opts.allow_direct_ip_with_domain_policy = v;
        }
        if let Some(v) = d.allow_private_ips {
            opts.allow_private_ips = v;
        }
        if let Some(v) = d.allow_loopback_ips {
            opts.allow_loopback_ips = v;
        }
    }
    if let Some(o) = &t.origin {
        if let Some(v) = o.origin_blacklist.clone() {
            opts.origin_blacklist = Some(v);
        }
        if let Some(v) = o.origin_whitelist.clone() {
            opts.origin_whitelist = Some(v);
        }
        if let Some(v) = o.block_blank_origins {
            opts.block_blank_origins = v;
        }
    }
    if let Some(c) = &t.client {
        if let Some(v) = c.client_ip_blacklist.clone() {
            opts.client_ip_blacklist = Some(v);
        }
        if let Some(v) = c.client_ip_whitelist.clone() {
            opts.client_ip_whitelist = Some(v);
        }
        if let Some(v) = c.parse_real_ip {
            opts.parse_real_ip = v;
        }
        if let Some(v) = c.parse_real_ip_from.clone() {
            opts.parse_real_ip_from = v;
        }
    }
    if let Some(d) = &t.dns {
        if let Some(v) = d.dns_ttl {
            opts.dns_ttl = v;
        }
        if let Some(v) = d.dns_method {
            opts.dns_method = v;
        }
        if let Some(v) = d.dns_servers.clone() {
            opts.dns_servers = Some(v);
        }
        if let Some(v) = d.dns_result_order {
            opts.dns_result_order = v;
        }
        if let Some(v) = d.dns_negative_ttl {
            opts.dns_negative_ttl = v;
        }
        if let Some(v) = d.dns_cache_max_entries {
            opts.dns_cache_max_entries = v;
        }
        if let Some(v) = d.max_dns_resolutions_per_ip_per_minute {
            opts.max_dns_resolutions_per_ip_per_minute = v;
        }
        if let Some(v) = d.max_dns_resolutions_per_minute {
            opts.max_dns_resolutions_per_minute = v;
        }
        if let Some(v) = d.max_unique_hostnames_per_ip_per_minute {
            opts.max_unique_hostnames_per_ip_per_minute = v;
        }
    }
    if let Some(l) = &t.limits {
        macro_rules! set {
            ($f:ident) => {
                if let Some(v) = l.$f {
                    opts.$f = v;
                }
            };
        }
        set!(max_connections);
        set!(max_connections_per_ip);
        set!(max_binary_frame_bytes);
        set!(max_text_frame_bytes);
        set!(max_host_bytes);
        set!(max_pending_packets_per_stream);
        set!(max_connection_starts_per_ip_per_minute);
        set!(max_connection_starts_per_minute);
        set!(max_tcp_stream_opens_per_connection_per_minute);
        set!(max_tcp_stream_opens_per_ip_per_minute);
        set!(max_tcp_bytes_per_connection_per_second);
        set!(max_tcp_bytes_per_ip_per_second);
        set!(max_datagrams_per_connection_per_second);
        set!(max_datagram_bytes_per_connection_per_second);
        set!(max_datagrams_per_ip_per_second);
        set!(max_datagram_bytes_per_ip_per_second);
        set!(datagram_rate_limit_strikes);
        set!(datagram_rate_limit_strike_window_ms);
        set!(max_control_messages_per_connection_per_minute);
        set!(max_control_messages_per_ip_per_minute);
        set!(max_binary_packets_per_connection_per_minute);
        set!(max_concurrent_proxy_control_handlers);
        set!(proxy_control_ext_payload_max_bytes);
        set!(max_proxy_rules_per_connection);
        set!(max_proxy_control_reply_bytes);
        set!(max_proxy_rule_field_bytes);
    }
    if let Some(r) = &t.rate_limit {
        if let Some(v) = r.backend {
            opts.rate_limit_backend = v;
        }
        if let Some(v) = r.redis_key_prefix.clone() {
            opts.redis_rate_limit_key_prefix = v;
        }
        if let Some(v) = r.redis_hash_tag.clone() {
            opts.redis_rate_limit_hash_tag = v;
        }
        if let Some(v) = r.redis_fail_open {
            opts.redis_rate_limit_fail_open = v;
        }
        if let Some(v) = r.redis_url.clone() {
            opts.redis_rate_limit_url = Some(v);
        }
        if let Some(v) = r.proxy_control_upstream_ops_per_second {
            opts.proxy_control_upstream_ops_per_second = v;
        }
        if let Some(v) = r.proxy_control_upstream_burst {
            opts.proxy_control_upstream_burst = v;
        }
        if let Some(v) = r.proxy_control_mutation_ops_per_second {
            opts.proxy_control_mutation_ops_per_second = v;
        }
        if let Some(v) = r.proxy_control_mutation_burst {
            opts.proxy_control_mutation_burst = v;
        }
    }
    if let Some(to) = &t.timeouts {
        if let Some(v) = to.stream_idle_timeout_ms {
            opts.stream_idle_timeout_ms = Some(v);
        }
        if let Some(v) = to.connect_timeout_ms {
            opts.connect_timeout_ms = Some(v);
        }
        if let Some(v) = to.idle_timeout_ms {
            opts.idle_timeout_ms = Some(v);
        }
        if let Some(v) = to.handshake_timeout_ms {
            opts.handshake_timeout_ms = Some(v);
        }
    }
    if let Some(i) = &t.protocol_inspection {
        if let Some(v) = i.enabled {
            opts.protocol_inspection = v;
        }
        if let Some(v) = i.allowed_protocols.clone() {
            opts.protocol_inspection_allowed_protocols = v;
        }
        if let Some(v) = i.max_bytes {
            opts.protocol_inspection_max_bytes = v;
        }
        if let Some(v) = i.timeout_ms {
            opts.protocol_inspection_timeout_ms = Some(v);
        }
        if let Some(v) = i.allow_h2c {
            opts.protocol_inspection_allow_h2c = v;
        }
        if let Some(v) = i.allow_tls_without_alpn {
            opts.protocol_inspection_allow_tls_without_alpn = v;
        }
        if let Some(v) = i.allow_quic_initial {
            opts.protocol_inspection_allow_quic_initial = v;
        }
    }
    if let Some(s) = &t.security {
        if let Some(v) = s.localhost_violation_ban_ms {
            opts.localhost_violation_ban_ms = v;
        }
        if let Some(v) = s.security_violation_ban_ms {
            opts.security_violation_ban_ms = v;
        }
    }
    if let Some(p) = &t.proxy {
        if let Some(v) = p.force_proxy {
            opts.force_proxy = v;
        }
        match p.max_session_hops {
            Some(NullableU64::Set(n)) => opts.max_session_hops = Some(n),
            Some(NullableU64::Unset) => opts.max_session_hops = None,
            None => {}
        }
        match p.max_daily_hops_per_ip {
            Some(NullableU64::Set(n)) => opts.max_daily_hops_per_ip = Some(n),
            Some(NullableU64::Unset) => opts.max_daily_hops_per_ip = None,
            None => {}
        }
    }
    if let Some(a) = &t.auth {
        if let Some(v) = a.required {
            opts.auth.required = v;
        }
        if let Some(v) = a.token_path {
            opts.auth.token_path = v;
        }
    }
}

pub fn build_wisp_wt_options(toml_cfg: &WispWtConfigToml) -> WispWtServerOptions {
    let mut out = WispWtServerOptions::default();
    if let Some(w) = &toml_cfg.wisp {
        merge_wisp(&mut out.base, w);
    }
    if let Some(wt) = &toml_cfg.wisp_wt {
        if let Some(v) = wt.enabled {
            out.enabled = v;
        }
        if let Some(v) = &wt.endpoint {
            out.base.endpoint = normalize_endpoint(v);
        }
        if let Some(v) = &wt.host {
            out.host = v.clone();
        }
        if let Some(v) = wt.port {
            out.port = v;
        }
        if let Some(v) = &wt.cert_path {
            out.cert_path = Some(v.clone());
        }
        if let Some(v) = &wt.key_path {
            out.key_path = Some(v.clone());
        }
        if let Some(v) = wt.max_datagram_bytes {
            out.max_datagram_bytes = v;
        }
        if let Some(v) = wt.wt_engine {
            out.wt_engine = v;
        }
    }
    if let Some(ws) = &toml_cfg.wisp_websocket {
        if let Some(v) = ws.enabled {
            out.websocket.enabled = v;
        }
        if let Some(v) = &ws.host {
            out.websocket.host = v.clone();
        }
        if let Some(v) = ws.port {
            out.websocket.port = v;
        }
        if let Some(v) = &ws.bind_addr {
            out.websocket.bind_addr = Some(v.clone());
        }
        if let Some(v) = &ws.cert_path {
            out.websocket.cert_path = Some(v.clone());
        }
        if let Some(v) = &ws.key_path {
            out.websocket.key_path = Some(v.clone());
        }
        if let Some(v) = &ws.endpoint {
            out.websocket.endpoint = Some(normalize_endpoint(v));
        }
        if let Some(v) = ws.proxy_control_enabled {
            out.websocket.proxy_control_enabled = Some(v);
        }
        if let Some(v) = ws.plain {
            out.websocket.plain = v;
        }
    }
    if let Some(pc) = &toml_cfg.wisp_proxy_control {
        if let Some(v) = pc.enabled {
            out.proxy_control_enabled = v;
        }
    }
    if let Some(mv) = &toml_cfg.wisp_proxy_mullvad {
        if mv.enabled.unwrap_or(false) {
            out.mullvad = Some(MullvadProviderConfig {
                relay_api: mv
                    .relay_api
                    .clone()
                    .unwrap_or_else(|| "https://api.mullvad.net/www/relays/all/".to_owned()),
                wireproxy_socks5: mv.wireproxy_socks5.clone(),
            });
        }
    }
    if let Some(re) = &toml_cfg.wisp_proxy_resi {
        if re.enabled.unwrap_or(false) {
            out.resi = Some(ResiProviderConfig {
                bearer_token: re.bearer_token.clone(),
                cookie: re.cookie.clone(),
                api_base: re
                    .api_base
                    .clone()
                    .unwrap_or_else(|| "https://api.mysterium.network".to_owned()),
                country: re.country.clone().unwrap_or_default(),
                ip_type: re
                    .ip_type
                    .clone()
                    .unwrap_or_else(|| "residential".to_owned()),
            });
        }
    }
    out
}

pub fn load_wisp_wt_options(path: &Path) -> Result<WispWtServerOptions> {
    let cfg = load_toml(path)?;
    let built = build_wisp_wt_options(&cfg);
    built.base.validate()?;
    Ok(built)
}

impl WispServerOptions {
    pub fn validate(&self) -> Result<()> {
        if self.max_proxy_rules_per_connection == 0 {
            return Err(ConfigError::Validate(
                "wisp.limits.max_proxy_rules_per_connection must be > 0".into(),
            ));
        }
        if self.max_proxy_control_reply_bytes == 0 {
            return Err(ConfigError::Validate(
                "wisp.limits.max_proxy_control_reply_bytes must be > 0".into(),
            ));
        }
        if self.max_proxy_rule_field_bytes == 0 {
            return Err(ConfigError::Validate(
                "wisp.limits.max_proxy_rule_field_bytes must be > 0".into(),
            ));
        }
        if self.protocol_inspection && self.protocol_inspection_max_bytes == 0 {
            return Err(ConfigError::Validate(
                "wisp.protocol_inspection.max_bytes must be > 0 when inspection is enabled".into(),
            ));
        }
        Ok(())
    }
}

pub fn validate_wisp_version_with_proxy_control(
    wisp_version: WispVersion,
    proxy_control_enabled: bool,
) -> Result<()> {
    if matches!(wisp_version, WispVersion::V1) && proxy_control_enabled {
        return Err(ConfigError::Validate(
            "wisp.server.wisp_version=v1 is incompatible with proxy_control_enabled (v1 has no extension mechanism)".into(),
        ));
    }
    Ok(())
}

// ------------------------------------------------------------- tests -------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_ts_reference() {
        let o = WispServerOptions::default();
        assert_eq!(o.endpoint, "/wisp");
        assert_eq!(o.port_whitelist, Some(vec![80, 443]));
        assert!(o.block_blank_origins);
        assert_eq!(o.buffer_size, 16 * 1024 * 1024);
        assert_eq!(o.continue_threshold, (16 * 1024 * 1024 * 90) / 100);
        assert_eq!(o.parse_real_ip_from, vec!["127.0.0.1", "::1"]);
        assert_eq!(o.max_session_hops, Some(16));
        assert_eq!(o.rate_limit_backend, RateLimitBackend::Auto);
    }

    #[test]
    fn wt_defaults() {
        let o = WispWtServerOptions::default();
        assert_eq!(o.base.endpoint, "/wisp-wt");
        assert_eq!(o.host, "0.0.0.0");
        assert_eq!(o.port, 4433);
        assert_eq!(o.max_datagram_bytes, 65_535);
    }

    #[test]
    fn normalize_endpoint_examples() {
        assert_eq!(normalize_endpoint(""), "/wisp");
        assert_eq!(normalize_endpoint("/"), "/");
        assert_eq!(normalize_endpoint("wisp"), "/wisp");
        assert_eq!(normalize_endpoint("/wisp/"), "/wisp");
        assert_eq!(normalize_endpoint("/wisp-wt//"), "/wisp-wt");
    }

    #[test]
    fn endpoint_token_examples() {
        assert_eq!(
            endpoint_path_token("/wisp/token-1", "/wisp"),
            Some("token-1")
        );
        assert_eq!(
            endpoint_path_token("/wisp/token-1/", "/wisp"),
            Some("token-1")
        );
        assert_eq!(endpoint_path_token("/wisp", "/wisp"), None);
        assert_eq!(endpoint_path_token("/wisp/a/b", "/wisp"), None);
    }

    #[test]
    fn parse_minimal_toml() {
        let raw = r#"
            [wisp_wt]
            enabled = true
            host = "127.0.0.1"
            port = 5433
            cert_path = "/etc/cert.pem"
            key_path = "/etc/key.pem"
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert!(o.enabled);
        assert_eq!(o.host, "127.0.0.1");
        assert_eq!(o.port, 5433);
        assert_eq!(o.cert_path.as_deref(), Some("/etc/cert.pem"));
    }

    #[test]
    fn parses_auth_toml() {
        let raw = r#"
            [wisp.auth]
            required = true
            token_path = true
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert!(o.base.auth.required);
        assert!(o.base.auth.token_path);
    }

    #[test]
    fn rejects_unknown_keys() {
        let raw = r#"
            [wisp_wt]
            enabled = true
            mystery = 1
        "#;
        let err = parse_toml(raw, "test").expect_err("unknown key should reject");
        let s = format!("{err}");
        assert!(s.contains("mystery"), "{}", s);
    }

    #[test]
    fn domain_alias_into_hostname() {
        let raw = r#"
            [wisp.destination]
            domain_blacklist = ["bad.example"]
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert_eq!(
            o.base.domain_blacklist.as_deref(),
            Some(&["bad.example".to_owned()][..])
        );
        assert_eq!(
            o.base.hostname_blacklist.as_deref(),
            Some(&["bad.example".to_owned()][..])
        );
    }

    #[test]
    fn nullable_u64_unset() {
        let raw = r#"
            [wisp.proxy]
            max_session_hops = "none"
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert_eq!(o.base.max_session_hops, None);
    }

    #[test]
    fn parse_wisp_websocket_block() {
        let raw = r#"
            [wisp_wt]
            cert_path = "/etc/wt.pem"
            key_path = "/etc/wt.key"

            [wisp_websocket]
            enabled = true
            host = "127.0.0.1"
            port = 8443
            endpoint = "wisp-ws"

            [wisp_proxy_control]
            enabled = true
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert!(o.websocket.enabled);
        assert_eq!(o.websocket.host, "127.0.0.1");
        assert_eq!(o.websocket.port, 8443);
        assert_eq!(o.websocket.endpoint.as_deref(), Some("/wisp-ws"));
        // Cert/key omitted on the WS side — should stay None at the config
        // layer; the WT cert/key fallback happens in the router projection.
        assert_eq!(o.websocket.cert_path, None);
        assert_eq!(o.websocket.key_path, None);
        assert_eq!(o.cert_path.as_deref(), Some("/etc/wt.pem"));
        assert!(o.proxy_control_enabled);
    }

    #[test]
    fn ws_disabled_by_default() {
        let raw = r#"
            [wisp_wt]
            enabled = true
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert!(!o.websocket.enabled);
        assert!(!o.proxy_control_enabled);
    }

    #[test]
    fn ws_bind_addr_and_proxy_control_override() {
        let raw = r#"
            [wisp_wt]
            cert_path = "/etc/wt.pem"
            key_path = "/etc/wt.key"

            [wisp_websocket]
            enabled = true
            bind_addr = "[::]:8443"
            proxy_control_enabled = true
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert!(o.websocket.enabled);
        assert_eq!(o.websocket.bind_addr.as_deref(), Some("[::]:8443"));
        assert_eq!(o.websocket.proxy_control_enabled, Some(true));
        assert!(!o.proxy_control_enabled);
    }

    #[test]
    fn ws_section_rejects_unknown_keys() {
        let raw = r#"
            [wisp_websocket]
            enabled = true
            mystery = "?"
        "#;
        let err = parse_toml(raw, "test").expect_err("unknown key should reject");
        assert!(format!("{err}").contains("mystery"));
    }
}

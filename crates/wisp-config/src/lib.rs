//! Strict-object TOML config loader for the Wisp WebTransport server.
//!
//! Every `[wisp.*]` and `[wisp_wt]` section has a typed struct with
//! `#[serde(deny_unknown_fields)]`. There is no `[wisp_wt.advanced]` block:
//! there are no extension toggles — the protocol is fixed, and msquic
//! features (BBR, datagram priority, stream priority) are configured
//! unconditionally at engine startup.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use thiserror::Error;

mod narrow;
mod origin_pattern;

pub use narrow::{normalize_domain_pattern, normalize_hostname};
pub use origin_pattern::{parse_origin_pattern, serialize_origin, OriginPattern};

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

/// A rate/count cap that may be explicitly uncapped.
///
/// TOML input accepts a non-negative integer for [`Limit::Max`] or `-1` for
/// [`Limit::Unlimited`]. TOML integers are `i64`, so the out-of-range
/// `u64::MAX` cap is not expressible directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Unlimited,
    Max(u64),
}

impl Limit {
    /// Collapse to the `u64` no-cap sentinel the DoS guard consumes, where
    /// [`Limit::Unlimited`] becomes `u64::MAX` (treated as "no cap").
    pub fn to_sentinel(self) -> u64 {
        match self {
            Limit::Unlimited => u64::MAX,
            Limit::Max(n) => n,
        }
    }

    /// Project onto `Option<u64>`, where [`Limit::Unlimited`] means the value
    /// is absent entirely rather than an infinite cap.
    pub fn to_option(self) -> Option<u64> {
        match self {
            Limit::Unlimited => None,
            Limit::Max(n) => Some(n),
        }
    }
}

impl<'de> Deserialize<'de> for Limit {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        match i64::deserialize(d)? {
            -1 => Ok(Limit::Unlimited),
            n if n >= 0 => Ok(Limit::Max(n as u64)),
            n => Err(serde::de::Error::custom(format!(
                "invalid limit {n}; expected -1 or a non-negative integer"
            ))),
        }
    }
}

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
#[serde(rename_all = "snake_case")]
pub enum IngressMode {
    DirectTls,
    DirectPlain,
    TrustedEdge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostPortRule {
    pub host: String,
    pub port: u16,
}

impl HostPortRule {
    pub fn normalized_host(&self) -> Option<String> {
        let host = self.host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.len() > 253 || self.port == 0 {
            return None;
        }
        if host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        }) {
            return None;
        }
        Some(host)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WispServerOptions {
    pub endpoint: String,
    pub domain_blacklist: Option<Vec<String>>,
    pub domain_whitelist: Option<Vec<String>>,
    pub ip_blacklist: Option<Vec<String>>,
    pub ip_whitelist: Option<Vec<String>>,
    pub port_blacklist: Option<Vec<u16>>,
    pub port_whitelist: Option<Vec<u16>>,
    /// Ports UDP streams may reach. `None` makes UDP follow `port_whitelist`;
    /// `Some` limits UDP to exactly these ports, with no host exceptions.
    pub udp_port_whitelist: Option<Vec<u16>>,
    pub host_port_whitelist: Option<Vec<HostPortRule>>,
    pub origin_blacklist: Option<Vec<String>>,
    pub origin_whitelist: Option<Vec<String>>,
    pub block_blank_origins: bool,
    pub allow_direct_ip: bool,
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
    /// Unwritten upload bytes one stream may hold before the server stops
    /// granting it CONTINUE credit. A soft threshold: credit resumes as the
    /// upstream drains, and the hard bounds are the per-connection and
    /// process-wide byte budgets.
    pub max_pending_bytes_per_stream: u64,
    pub max_egress_queue_bytes: u64,
    /// Upload bytes one connection may hold across all of its streams before
    /// the server stops reading the client until some of them drain.
    #[serde(default = "default_max_ingress_bytes_per_connection")]
    pub max_ingress_bytes_per_connection: u64,
    /// Upload and egress bytes held by every connection of the process
    /// together. Process-wide: read from the base options when the runtime
    /// starts and when the base limits are patched, ignored in other limit
    /// profiles.
    #[serde(default = "default_max_buffered_bytes_total")]
    pub max_buffered_bytes_total: u64,
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
    /// Leading bits of an IPv6 address that identify one client for per-IP
    /// limits (16..=64). Process-wide, applied when the runtime starts.
    pub rate_limit_ipv6_prefix: u8,
    pub stream_idle_timeout_ms: Option<u64>,
    pub protocol_inspection: bool,
    pub protocol_inspection_allowed_protocols: Vec<AllowedProtocol>,
    pub protocol_inspection_max_bytes: u64,
    pub protocol_inspection_timeout_ms: Option<u64>,
    pub protocol_inspection_allow_h2c: bool,
    pub protocol_inspection_allow_tls_without_alpn: bool,
    pub protocol_inspection_allow_quic_initial: bool,
    pub force_proxy: bool,
    pub connect_timeout_ms: Option<u64>,
    pub idle_timeout_ms: Option<u64>,
    pub handshake_timeout_ms: Option<u64>,
    pub wisp_version: WispVersion,
    pub auth: WispAuthOptions,
}

fn default_max_ingress_bytes_per_connection() -> u64 {
    8 * 1024 * 1024
}

fn default_max_buffered_bytes_total() -> u64 {
    128 * 1024 * 1024
}

impl Default for WispServerOptions {
    fn default() -> Self {
        // Memory is bounded per frame, per connection and per process. The
        // WebSocket decoder sizes its buffer from a frame's declared length,
        // so every open connection can pin one maximum frame before sending
        // a byte of it; Wisp clients send TLS records and socket writes of at
        // most 64 KiB, so 256 KiB leaves room without letting a few hundred
        // half-sent frames fill the front's 512 MiB.
        let max_frame = 256 * 1024_u64;
        let packet_window = 256_u64;
        Self {
            endpoint: "/wisp".to_owned(),
            domain_blacklist: None,
            domain_whitelist: None,
            ip_blacklist: None,
            ip_whitelist: None,
            port_blacklist: None,
            port_whitelist: Some(vec![80, 443]),
            udp_port_whitelist: None,
            host_port_whitelist: None,
            origin_blacklist: None,
            origin_whitelist: None,
            block_blank_origins: true,
            allow_direct_ip: false,
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
            // Global budgets are backstops, not fairness tools: the per-IP
            // limits already bound each client, and a global bucket that a
            // few dozen busy addresses can drain (the old 2048 DNS and 4096
            // start budgets fell to 18 and 35 IPs) denies every other user.
            // 60000 per minute is 500 clients running flat out at the per-IP
            // limits, so only a flood across hundreds of addresses reaches it.
            max_dns_resolutions_per_minute: 60_000,
            max_unique_hostnames_per_ip_per_minute: 60,
            parse_real_ip: true,
            parse_real_ip_from: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
            buffer_size: packet_window,
            continue_threshold: 230,
            max_connections: 512,
            max_connections_per_ip: 32,
            max_binary_frame_bytes: max_frame,
            max_text_frame_bytes: 64 * 1024,
            max_host_bytes: 253,
            max_pending_packets_per_stream: 512,
            max_pending_bytes_per_stream: 1024 * 1024,
            max_egress_queue_bytes: 4 * 1024 * 1024,
            max_ingress_bytes_per_connection: default_max_ingress_bytes_per_connection(),
            max_buffered_bytes_total: default_max_buffered_bytes_total(),
            max_connection_starts_per_ip_per_minute: 120,
            max_connection_starts_per_minute: 60_000,
            max_tcp_stream_opens_per_connection_per_minute: 120,
            max_tcp_stream_opens_per_ip_per_minute: 480,
            max_tcp_bytes_per_connection_per_second: 64 * 1024 * 1024,
            max_tcp_bytes_per_ip_per_second: 256 * 1024 * 1024,
            // UDP reaches any public address, so a high budget makes the
            // server a flood source. These are an eighth of the old values,
            // still enough for a QUIC or game session per connection.
            max_datagrams_per_connection_per_second: 512,
            max_datagram_bytes_per_connection_per_second: 4 * 1024 * 1024,
            max_datagrams_per_ip_per_second: 2048,
            max_datagram_bytes_per_ip_per_second: 16 * 1024 * 1024,
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
            rate_limit_backend: RateLimitBackend::Memory,
            redis_rate_limit_url: None,
            redis_rate_limit_key_prefix: "wisp".to_owned(),
            redis_rate_limit_hash_tag: "rate-limit".to_owned(),
            rate_limit_ipv6_prefix: 56,
            stream_idle_timeout_ms: Some(60_000),
            protocol_inspection: true,
            protocol_inspection_allowed_protocols: vec![
                AllowedProtocol::Http,
                AllowedProtocol::Https,
                AllowedProtocol::Http2,
                AllowedProtocol::Ws,
            ],
            protocol_inspection_max_bytes: 64 * 1024,
            protocol_inspection_timeout_ms: Some(10_000),
            protocol_inspection_allow_h2c: false,
            protocol_inspection_allow_tls_without_alpn: false,
            protocol_inspection_allow_quic_initial: false,
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
    pub token_file: Option<String>,
    pub resolver_timeout_ms: u64,
}

impl Default for WispAuthOptions {
    fn default() -> Self {
        Self {
            required: true,
            token_path: true,
            token_file: None,
            resolver_timeout_ms: 1_000,
        }
    }
}

/// Per-token restrictions. Unknown keys are rejected, so a misspelled
/// restriction cannot leave a token unrestricted. A policy only narrows the
/// options it is applied to, see [`WispAuthTokenPolicy::apply_to`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WispAuthTokenPolicy {
    #[serde(alias = "limit_profile")]
    pub limit_profile: Option<String>,
    #[serde(alias = "allowed_proxy_providers")]
    pub allowed_proxy_providers: Option<Vec<String>>,
    // The hostname spellings are the names the TypeScript type documents.
    #[serde(
        alias = "domain_blacklist",
        alias = "hostnameBlacklist",
        alias = "hostname_blacklist"
    )]
    pub domain_blacklist: Option<Vec<String>>,
    #[serde(
        alias = "domain_whitelist",
        alias = "hostnameWhitelist",
        alias = "hostname_whitelist"
    )]
    pub domain_whitelist: Option<Vec<String>>,
    #[serde(alias = "ip_blacklist")]
    pub ip_blacklist: Option<Vec<String>>,
    #[serde(alias = "ip_whitelist")]
    pub ip_whitelist: Option<Vec<String>>,
    #[serde(alias = "port_blacklist")]
    pub port_blacklist: Option<Vec<u16>>,
    #[serde(alias = "port_whitelist")]
    pub port_whitelist: Option<Vec<u16>>,
    #[serde(alias = "host_port_whitelist")]
    pub host_port_whitelist: Option<Vec<HostPortRule>>,
    #[serde(alias = "allow_direct_ip")]
    pub allow_direct_ip: Option<bool>,
    #[serde(alias = "allow_private_ips")]
    pub allow_private_ips: Option<bool>,
    #[serde(alias = "allow_loopback_ips")]
    pub allow_loopback_ips: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct WispResolvedAuth {
    pub options: WispServerOptions,
    pub policy: WispAuthTokenPolicy,
}

impl WispAuthTokenPolicy {
    /// Applies this policy to `base` and returns the narrower options.
    ///
    /// A token can only restrict what its base already allows: blacklists are
    /// unioned with the base, whitelists are intersected with it, and the
    /// `allow_*` switches can be turned off but never on. A whitelist whose
    /// intersection is empty allows nothing, which fails validation of the
    /// result, so such a token is refused. Use a limit profile as the base to
    /// grant a token more than the default.
    pub fn apply_to(&self, base: &WispServerOptions) -> WispServerOptions {
        use narrow::{
            intersect_domains, intersect_host_ports, intersect_ip_rules, intersect_ports, union,
        };
        let mut out = base.clone();
        if let Some(v) = &self.domain_blacklist {
            out.domain_blacklist = Some(union(base.domain_blacklist.as_deref(), v));
        }
        if let Some(v) = &self.domain_whitelist {
            out.domain_whitelist = Some(intersect_domains(base.domain_whitelist.as_deref(), v));
        }
        if let Some(v) = &self.ip_blacklist {
            out.ip_blacklist = Some(union(base.ip_blacklist.as_deref(), v));
        }
        if let Some(v) = &self.ip_whitelist {
            out.ip_whitelist = Some(intersect_ip_rules(base.ip_whitelist.as_deref(), v));
        }
        if let Some(v) = &self.port_blacklist {
            out.port_blacklist = Some(union(base.port_blacklist.as_deref(), v));
        }
        if let Some(v) = &self.port_whitelist {
            out.port_whitelist = Some(intersect_ports(base.port_whitelist.as_deref(), v));
            // UDP that has its own list is narrowed by the token's ports too.
            out.udp_port_whitelist = base
                .udp_port_whitelist
                .as_deref()
                .map(|udp| intersect_ports(Some(v), udp));
        }
        if self.port_whitelist.is_some() || self.host_port_whitelist.is_some() {
            out.host_port_whitelist = intersect_host_ports(
                base.port_whitelist.as_deref(),
                base.host_port_whitelist.as_deref(),
                self.port_whitelist.as_deref(),
                self.host_port_whitelist.as_deref(),
                out.port_whitelist.as_deref(),
            );
        }
        if let Some(v) = self.allow_direct_ip {
            out.allow_direct_ip = base.allow_direct_ip && v;
        }
        if let Some(v) = self.allow_private_ips {
            out.allow_private_ips = base.allow_private_ips && v;
        }
        if let Some(v) = self.allow_loopback_ips {
            out.allow_loopback_ips = base.allow_loopback_ips && v;
        }
        out
    }

    /// Checks the policy on its own: list entries must parse, and an explicit
    /// empty whitelist (which would allow nothing) is an error.
    pub fn validate(&self) -> Result<()> {
        for (name, len) in [
            (
                "domainWhitelist",
                self.domain_whitelist.as_ref().map(Vec::len),
            ),
            ("ipWhitelist", self.ip_whitelist.as_ref().map(Vec::len)),
            ("portWhitelist", self.port_whitelist.as_ref().map(Vec::len)),
        ] {
            if len == Some(0) {
                return Err(ConfigError::Validate(format!(
                    "token policy {name} must not be empty, leave it out to inherit the base list"
                )));
            }
        }
        for (name, entries) in [
            ("domainBlacklist", self.domain_blacklist.as_ref()),
            ("domainWhitelist", self.domain_whitelist.as_ref()),
        ] {
            for entry in entries.into_iter().flatten() {
                if normalize_domain_pattern(entry).is_none() {
                    return Err(ConfigError::Validate(format!(
                        "token policy {name} contains invalid domain pattern {entry}"
                    )));
                }
            }
        }
        for (name, entries) in [
            ("ipBlacklist", self.ip_blacklist.as_ref()),
            ("ipWhitelist", self.ip_whitelist.as_ref()),
        ] {
            for entry in entries.into_iter().flatten() {
                if let Err(reason) = parse_cidr(entry) {
                    return Err(ConfigError::Validate(format!(
                        "token policy {name} contains invalid IP or CIDR {entry} ({reason})"
                    )));
                }
            }
        }
        for rule in self.host_port_whitelist.iter().flatten() {
            if rule.normalized_host().is_none() {
                return Err(ConfigError::Validate(format!(
                    "token policy hostPortWhitelist contains invalid host or port {}:{}",
                    rule.host, rule.port
                )));
            }
        }
        Ok(())
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
    file_resolver: Arc<RwLock<Option<Arc<dyn WispAuthResolver>>>>,
    resolver: Arc<RwLock<Option<Arc<dyn WispAuthResolver>>>>,
}

impl WispAuthRegistry {
    pub fn register_profile(&self, name: String, options: WispServerOptions) -> bool {
        let normalized = name.trim();
        if normalized.is_empty() || normalized.contains('/') || options.validate().is_err() {
            return false;
        }
        write_recover(&self.profiles).insert(normalized.to_owned(), options);
        true
    }

    pub fn remove_profile(&self, name: &str) -> Option<WispServerOptions> {
        write_recover(&self.profiles).remove(name)
    }

    pub fn profile(&self, name: &str) -> Option<WispServerOptions> {
        read_recover(&self.profiles).get(name).cloned()
    }

    pub fn list_profiles(&self) -> Vec<(String, WispServerOptions)> {
        let mut out: Vec<(String, WispServerOptions)> = read_recover(&self.profiles)
            .iter()
            .map(|(name, options)| (name.clone(), options.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn set_resolver(&self, resolver: Arc<dyn WispAuthResolver>) {
        write_recover(&self.resolver).replace(resolver);
    }

    pub fn set_file_resolver(&self, resolver: Arc<dyn WispAuthResolver>) {
        write_recover(&self.file_resolver).replace(resolver);
    }

    pub fn clear_resolver(&self) {
        write_recover(&self.resolver).take();
    }

    pub async fn resolve(
        &self,
        token: String,
        base: &WispServerOptions,
    ) -> Option<WispResolvedAuth> {
        let file_resolver = read_recover(&self.file_resolver).clone();
        if let Some(resolver) = file_resolver {
            if let Some(policy) = resolver.resolve(token.clone()).await {
                return self.resolve_policy(policy, base);
            }
        }
        let resolver = read_recover(&self.resolver).clone()?;
        let policy = resolver.resolve(token).await?;
        self.resolve_policy(policy, base)
    }

    fn resolve_policy(
        &self,
        policy: WispAuthTokenPolicy,
        base: &WispServerOptions,
    ) -> Option<WispResolvedAuth> {
        // A token with no profile gets the same limits as an anonymous
        // connection, which run from the `__base` profile. Falling back to the
        // static startup options here would leave runtime limit patches
        // (which land in `__base`) unreachable for those tokens.
        let profile_base = if let Some(profile) = policy.limit_profile.as_deref() {
            self.profile(profile)?
        } else {
            self.profile(WISP_BASE_LIMIT_PROFILE)
                .unwrap_or_else(|| base.clone())
        };
        if let Err(error) = policy.validate() {
            tracing::warn!(error = %error, "refusing token with an invalid policy");
            return None;
        }
        let options = policy.apply_to(&profile_base);
        options.validate().ok()?;
        Some(WispResolvedAuth { options, policy })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFileDocument {
    version: u32,
    tokens: Vec<TokenFileEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFileEntry {
    id: String,
    sha256: String,
    #[serde(default)]
    policy: WispAuthTokenPolicy,
}

/// Token policies keyed by the SHA-256 digest of the bearer token. The key
/// probed is the digest of the presented token, so lookup timing says nothing
/// useful about stored tokens, and a lookup clones only the matching policy.
type LoadedTokens = HashMap<[u8; 32], WispAuthTokenPolicy>;

/// Reloadable, hashed standalone token source. Raw bearer tokens never enter
/// the file and are not retained by the server.
pub struct ReloadingTokenResolver {
    path: std::path::PathBuf,
    tokens: RwLock<Arc<LoadedTokens>>,
}

impl ReloadingTokenResolver {
    pub fn load(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let path = path.into();
        let tokens = load_token_file(&path)?;
        Ok(Self {
            path,
            tokens: RwLock::new(Arc::new(tokens)),
        })
    }

    pub fn reload(&self) -> Result<()> {
        let replacement = load_token_file(&self.path)?;
        *write_recover(&self.tokens) = Arc::new(replacement);
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl WispAuthResolver for ReloadingTokenResolver {
    fn resolve(&self, token: String) -> WispAuthResolveFuture {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let policy = read_recover(&self.tokens).get(&digest).cloned();
        Box::pin(async move { policy })
    }
}

fn load_token_file(path: &Path) -> Result<LoadedTokens> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::Validate(format!(
                "token file {} must not be accessible by group or other users",
                path.display()
            )));
        }
    }
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let document: TokenFileDocument =
        toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;
    if document.version != 1 {
        return Err(ConfigError::Validate(format!(
            "token file {} has unsupported version {}",
            path.display(),
            document.version
        )));
    }
    if document.tokens.is_empty() {
        return Err(ConfigError::Validate(format!(
            "token file {} contains no tokens",
            path.display()
        )));
    }
    let mut loaded = HashMap::with_capacity(document.tokens.len());
    let mut ids = std::collections::HashSet::new();
    for entry in document.tokens {
        if entry.id.trim().is_empty() || !ids.insert(entry.id.clone()) {
            return Err(ConfigError::Validate(
                "token ids must be non-empty and unique".into(),
            ));
        }
        let bytes = hex::decode(&entry.sha256).map_err(|_| {
            ConfigError::Validate(format!("token {} has an invalid SHA-256 digest", entry.id))
        })?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            ConfigError::Validate(format!("token {} has an invalid SHA-256 digest", entry.id))
        })?;
        entry.policy.validate().map_err(|error| {
            ConfigError::Validate(format!("token {} has an invalid policy: {error}", entry.id))
        })?;
        if loaded.insert(digest, entry.policy).is_some() {
            return Err(ConfigError::Validate("token digests must be unique".into()));
        }
    }
    Ok(loaded)
}

fn read_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_recover<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    /// Enables the wisp-wt WebTransport-to-WebTransport bridge extension.
    pub webtransport_proxy_enabled: bool,
    /// Upstream WebTransport sessions allowed per downstream session.
    pub max_proxy_sessions_per_connection: u32,
    /// Concurrent bridged streams allowed per upstream session.
    pub max_proxy_substreams_per_session: u32,
    /// Wisp-over-WebSocket server. Independent of the WT side — both
    /// can be enabled simultaneously (one on UDP/QUIC, one on TCP/H2).
    /// The cert/key default to the WT pair when omitted so a single
    /// PEM identity covers both transports on the same hostname.
    pub websocket: WispWebSocketOptions,
    /// Whether the WISP_PROXY_CONTROL (0x03) extension is advertised.
    /// When enabled (or overridden per WebSocket section), the runtime builds
    /// a provider template and advertises the extension on WS and, when the
    /// WebTransport listener is up, on WT as well.
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
    pub wireproxy_socks5: Option<String>,
    pub cookie: Option<String>,
    pub api_base: String,
    pub country: String,
    pub ip_type: String,
}

/// Shortest accepted `trusted_edge_secret`.
pub const MIN_TRUSTED_EDGE_SECRET_BYTES: usize = 32;

/// A configured secret that never prints its value, so deriving `Debug` on a
/// struct that holds one cannot leak it into a log.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
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
    /// Per-transport override for the WISP_PROXY_CONTROL extension
    /// advertisement. `None` inherits the value from
    /// `WispWtServerOptions::proxy_control_enabled` so a single root-level
    /// toggle continues to apply to both transports unless explicitly
    /// overridden here.
    pub proxy_control_enabled: Option<bool>,
    /// `direct_tls` terminates TLS in this process. `trusted_edge` accepts
    /// HTTP/1.1 WebSocket upgrades from a private, explicitly trusted reverse
    /// proxy and must not be exposed directly to clients.
    pub ingress_mode: IngressMode,
    /// Shared secret the trusted front sends in the `x-wisp-edge-secret`
    /// header. When set under `trusted_edge`, the plain listener refuses
    /// upgrades without it before it believes `X-Forwarded-For`, so another
    /// local process cannot choose a client identity. At least
    /// [`MIN_TRUSTED_EDGE_SECRET_BYTES`] bytes.
    pub trusted_edge_secret: Option<Secret>,
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
            ingress_mode: IngressMode::DirectTls,
            trusted_edge_secret: None,
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
            webtransport_proxy_enabled: false,
            max_proxy_sessions_per_connection: 4,
            max_proxy_substreams_per_session: 64,
            websocket: WispWebSocketOptions::default(),
            proxy_control_enabled: false,
            mullvad: None,
            resi: None,
        }
    }
}

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
    if token.is_empty() || token.len() > MAX_ENDPOINT_PATH_TOKEN_BYTES || token.contains('/') {
        None
    } else {
        Some(token)
    }
}

pub const MAX_ENDPOINT_PATH_TOKEN_BYTES: usize = 1024;

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
    pub ip_blacklist: Option<Vec<String>>,
    pub ip_whitelist: Option<Vec<String>>,
    pub port_blacklist: Option<Vec<u16>>,
    pub port_whitelist: Option<Vec<u16>>,
    pub udp_port_whitelist: Option<Vec<u16>>,
    pub host_port_whitelist: Option<Vec<HostPortRule>>,
    pub allow_direct_ip: Option<bool>,
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
    pub max_dns_resolutions_per_ip_per_minute: Option<Limit>,
    pub max_dns_resolutions_per_minute: Option<Limit>,
    pub max_unique_hostnames_per_ip_per_minute: Option<Limit>,
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
    pub max_pending_bytes_per_stream: Option<u64>,
    pub max_egress_queue_bytes: Option<u64>,
    pub max_ingress_bytes_per_connection: Option<u64>,
    pub max_buffered_bytes_total: Option<u64>,
    pub max_connection_starts_per_ip_per_minute: Option<Limit>,
    pub max_connection_starts_per_minute: Option<Limit>,
    pub max_tcp_stream_opens_per_connection_per_minute: Option<Limit>,
    pub max_tcp_stream_opens_per_ip_per_minute: Option<Limit>,
    pub max_tcp_bytes_per_connection_per_second: Option<Limit>,
    pub max_tcp_bytes_per_ip_per_second: Option<Limit>,
    pub max_datagrams_per_connection_per_second: Option<Limit>,
    pub max_datagram_bytes_per_connection_per_second: Option<Limit>,
    pub max_datagrams_per_ip_per_second: Option<Limit>,
    pub max_datagram_bytes_per_ip_per_second: Option<Limit>,
    pub datagram_rate_limit_strikes: Option<u64>,
    pub datagram_rate_limit_strike_window_ms: Option<u64>,
    pub max_control_messages_per_connection_per_minute: Option<Limit>,
    pub max_control_messages_per_ip_per_minute: Option<Limit>,
    pub max_binary_packets_per_connection_per_minute: Option<Limit>,
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
    pub redis_url: Option<String>,
    /// IPv6 prefix length (16..=64) that per-IP limits aggregate to.
    pub ipv6_prefix: Option<u8>,
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
pub struct WispProxyToml {
    pub force_proxy: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispAuthToml {
    pub required: Option<bool>,
    pub token_path: Option<bool>,
    pub token_file: Option<String>,
    pub resolver_timeout_ms: Option<u64>,
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
    pub webtransport_proxy_enabled: Option<bool>,
    pub max_proxy_sessions_per_connection: Option<u32>,
    pub max_proxy_substreams_per_session: Option<u32>,
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
    pub ingress_mode: Option<IngressMode>,
    pub trusted_edge_secret: Option<Secret>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WispProxyControlToml {
    pub enabled: Option<bool>,
}

/// `[wisp_proxy_mullvad]` — Mullvad WireGuard SOCKS5 provider config.
/// Absent or `enabled = false` keeps the provider out of the registry entirely.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WispMullvadToml {
    pub enabled: Option<bool>,
    pub relay_api: Option<String>,
    pub wireproxy_socks5: Option<String>,
}

/// `[wisp_proxy_resi]` — Mysterium API or WireGuard SOCKS5 provider.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WispResiToml {
    pub enabled: Option<bool>,
    pub bearer_token: Option<String>,
    pub wireproxy_socks5: Option<String>,
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
    /// `[wisp_websocket]` block — Wisp v2 over WebSocket transport
    /// settings. Independent of `[wisp_wt]`; both can be enabled.
    pub wisp_websocket: Option<WispWebSocketToml>,
    /// `[wisp_proxy_control]` block — toggles the WISP_PROXY_CONTROL
    /// extension (0x03) advertisement.
    pub wisp_proxy_control: Option<WispProxyControlToml>,
    /// `[wisp_proxy_mullvad]` — provider config for the Mullvad SOCKS5 relay set.
    pub wisp_proxy_mullvad: Option<WispMullvadToml>,
    /// `[wisp_proxy_resi]` — provider config for residential / partner proxies.
    pub wisp_proxy_resi: Option<WispResiToml>,
}

pub fn parse_toml(raw: &str, source: &str) -> Result<WispWtConfigToml> {
    toml::from_str::<WispWtConfigToml>(raw).map_err(|e| ConfigError::Parse {
        path: source.to_owned(),
        source: e,
    })
}

/// Read and parse a config file. A missing or unreadable file is an error, so
/// a mistyped path can never start a server with defaults and no listeners.
/// Callers that really want defaults for an absent file use
/// [`load_toml_or_default`].
pub fn load_toml(path: &Path) -> Result<WispWtConfigToml> {
    let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    parse_toml(&raw, &path.display().to_string())
}

/// Explicit opt-in to the old behavior: defaults when the file does not exist.
/// Any other failure (permissions, parse errors) is still an error.
pub fn load_toml_or_default(path: &Path) -> Result<WispWtConfigToml> {
    if !path.exists() {
        return Ok(WispWtConfigToml::default());
    }
    load_toml(path)
}

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
        if let Some(v) = d.domain_blacklist.clone() {
            opts.domain_blacklist = Some(v);
        }
        if let Some(v) = d.domain_whitelist.clone() {
            opts.domain_whitelist = Some(v);
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
        if let Some(v) = d.udp_port_whitelist.clone() {
            opts.udp_port_whitelist = Some(v);
        }
        if let Some(v) = d.host_port_whitelist.clone() {
            opts.host_port_whitelist = Some(v);
        }
        if let Some(v) = d.allow_direct_ip {
            opts.allow_direct_ip = v;
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
            opts.max_dns_resolutions_per_ip_per_minute = v.to_sentinel();
        }
        if let Some(v) = d.max_dns_resolutions_per_minute {
            opts.max_dns_resolutions_per_minute = v.to_sentinel();
        }
        if let Some(v) = d.max_unique_hostnames_per_ip_per_minute {
            opts.max_unique_hostnames_per_ip_per_minute = v.to_sentinel();
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
        macro_rules! set_lim {
            ($f:ident) => {
                if let Some(v) = l.$f {
                    opts.$f = v.to_sentinel();
                }
            };
        }
        set!(max_connections);
        set!(max_connections_per_ip);
        set!(max_binary_frame_bytes);
        set!(max_text_frame_bytes);
        set!(max_host_bytes);
        set!(max_pending_packets_per_stream);
        set!(max_pending_bytes_per_stream);
        set!(max_egress_queue_bytes);
        set!(max_ingress_bytes_per_connection);
        set!(max_buffered_bytes_total);
        set_lim!(max_connection_starts_per_ip_per_minute);
        set_lim!(max_connection_starts_per_minute);
        set_lim!(max_tcp_stream_opens_per_connection_per_minute);
        set_lim!(max_tcp_stream_opens_per_ip_per_minute);
        set_lim!(max_tcp_bytes_per_connection_per_second);
        set_lim!(max_tcp_bytes_per_ip_per_second);
        set_lim!(max_datagrams_per_connection_per_second);
        set_lim!(max_datagram_bytes_per_connection_per_second);
        set_lim!(max_datagrams_per_ip_per_second);
        set_lim!(max_datagram_bytes_per_ip_per_second);
        set!(datagram_rate_limit_strikes);
        set!(datagram_rate_limit_strike_window_ms);
        set_lim!(max_control_messages_per_connection_per_minute);
        set_lim!(max_control_messages_per_ip_per_minute);
        set_lim!(max_binary_packets_per_connection_per_minute);
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
        if let Some(v) = r.redis_url.clone() {
            opts.redis_rate_limit_url = Some(v);
        }
        if let Some(v) = r.ipv6_prefix {
            opts.rate_limit_ipv6_prefix = v;
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
    if let Some(p) = &t.proxy {
        if let Some(v) = p.force_proxy {
            opts.force_proxy = v;
        }
    }
    if let Some(a) = &t.auth {
        if let Some(v) = a.required {
            opts.auth.required = v;
        }
        if let Some(v) = a.token_path {
            opts.auth.token_path = v;
        }
        if let Some(v) = &a.token_file {
            opts.auth.token_file = Some(v.clone());
        }
        if let Some(v) = a.resolver_timeout_ms {
            opts.auth.resolver_timeout_ms = v;
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
        if let Some(v) = wt.webtransport_proxy_enabled {
            out.webtransport_proxy_enabled = v;
        }
        if let Some(v) = wt.max_proxy_sessions_per_connection {
            out.max_proxy_sessions_per_connection = v;
        }
        if let Some(v) = wt.max_proxy_substreams_per_session {
            out.max_proxy_substreams_per_session = v;
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
        if let Some(v) = ws.ingress_mode {
            out.websocket.ingress_mode = v;
        }
        if let Some(v) = &ws.trusted_edge_secret {
            out.websocket.trusted_edge_secret = Some(v.clone());
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
                wireproxy_socks5: re.wireproxy_socks5.clone(),
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
    built.validate()?;
    Ok(built)
}

impl WispWtServerOptions {
    pub fn validate(&self) -> Result<()> {
        use std::net::{IpAddr, SocketAddr};

        self.base.validate()?;
        if self.base.auth.required && !self.base.auth.token_path {
            return Err(ConfigError::Validate(
                "wisp.auth.required=true requires token_path=true".into(),
            ));
        }
        if self.base.auth.resolver_timeout_ms == 0 {
            return Err(ConfigError::Validate(
                "wisp.auth.resolver_timeout_ms must be > 0".into(),
            ));
        }
        if self.enabled && (self.cert_path.is_none() || self.key_path.is_none()) {
            return Err(ConfigError::Validate(
                "enabled WebTransport requires cert_path and key_path".into(),
            ));
        }
        if self.webtransport_proxy_enabled {
            if !self.enabled {
                return Err(ConfigError::Validate(
                    "webtransport_proxy_enabled requires WebTransport to be enabled".into(),
                ));
            }
            if self.max_proxy_sessions_per_connection == 0 {
                return Err(ConfigError::Validate(
                    "max_proxy_sessions_per_connection must be > 0".into(),
                ));
            }
            if self.max_proxy_substreams_per_session == 0 {
                return Err(ConfigError::Validate(
                    "max_proxy_substreams_per_session must be > 0".into(),
                ));
            }
        }
        if let Some(secret) = &self.websocket.trusted_edge_secret {
            if secret.as_bytes().len() < MIN_TRUSTED_EDGE_SECRET_BYTES {
                return Err(ConfigError::Validate(format!(
                    "wisp_websocket.trusted_edge_secret must be at least {MIN_TRUSTED_EDGE_SECRET_BYTES} bytes"
                )));
            }
            if self.websocket.enabled && self.websocket.ingress_mode != IngressMode::TrustedEdge {
                tracing::warn!(
                    "wisp_websocket.trusted_edge_secret is ignored unless ingress_mode is trusted_edge"
                );
            }
        }
        if self.websocket.enabled {
            match self.websocket.ingress_mode {
                IngressMode::DirectTls => {
                    let cert = self
                        .websocket
                        .cert_path
                        .as_ref()
                        .or(self.cert_path.as_ref());
                    let key = self.websocket.key_path.as_ref().or(self.key_path.as_ref());
                    if cert.is_none() || key.is_none() {
                        return Err(ConfigError::Validate(
                            "direct_tls WebSocket ingress requires cert_path and key_path".into(),
                        ));
                    }
                }
                IngressMode::DirectPlain => {
                    let bind_ip = if let Some(bind) = self.websocket.bind_addr.as_deref() {
                        bind.parse::<SocketAddr>().ok().map(|addr| addr.ip())
                    } else {
                        self.websocket.host.parse::<IpAddr>().ok()
                    };
                    if !bind_ip.is_some_and(|ip| ip.is_loopback()) {
                        return Err(ConfigError::Validate(
                            "direct_plain WebSocket ingress may only bind a loopback address"
                                .into(),
                        ));
                    }
                }
                IngressMode::TrustedEdge => {
                    let bind_ip = if let Some(bind) = self.websocket.bind_addr.as_deref() {
                        bind.parse::<SocketAddr>().ok().map(|addr| addr.ip())
                    } else {
                        self.websocket.host.parse::<IpAddr>().ok()
                    };
                    let Some(bind_ip) = bind_ip else {
                        return Err(ConfigError::Validate(
                            "trusted_edge WebSocket ingress requires a literal private or loopback bind address".into(),
                        ));
                    };
                    if !bind_ip.is_loopback() && !is_private_address(bind_ip) {
                        return Err(ConfigError::Validate(
                            "trusted_edge WebSocket ingress cannot bind a public or unspecified address".into(),
                        ));
                    }
                    if !self.base.parse_real_ip || self.base.parse_real_ip_from.is_empty() {
                        return Err(ConfigError::Validate(
                            "trusted_edge WebSocket ingress requires parse_real_ip and parse_real_ip_from".into(),
                        ));
                    }
                }
            }
        }
        let ws_proxy_control = self
            .websocket
            .proxy_control_enabled
            .unwrap_or(self.proxy_control_enabled);
        if (self.proxy_control_enabled || ws_proxy_control)
            && self.mullvad.is_none()
            && self.resi.is_none()
        {
            return Err(ConfigError::Validate(
                "proxy control requires at least one configured provider".into(),
            ));
        }
        if let Some(resi) = &self.resi {
            let has_api = resi
                .bearer_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            let has_wireguard = resi
                .wireproxy_socks5
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            if has_api == has_wireguard {
                return Err(ConfigError::Validate(
                    "Mysterium requires exactly one of bearer_token or wireproxy_socks5".into(),
                ));
            }
        }
        validate_wisp_version_with_proxy_control(
            self.base.wisp_version,
            self.proxy_control_enabled || ws_proxy_control,
        )
    }
}

fn is_private_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

impl WispServerOptions {
    pub fn validate(&self) -> Result<()> {
        if self.buffer_size < 2 || self.buffer_size > u32::MAX as u64 {
            return Err(ConfigError::Validate(
                "wisp.server.buffer_size must be between 2 and u32::MAX packets".into(),
            ));
        }
        if self.continue_threshold == 0 || self.continue_threshold >= self.buffer_size {
            return Err(ConfigError::Validate(
                "wisp.server.continue_threshold must be between 1 and buffer_size - 1 packets"
                    .into(),
            ));
        }
        if self.max_pending_packets_per_stream == 0
            || self.max_pending_bytes_per_stream == 0
            || self.max_egress_queue_bytes == 0
            || self.max_ingress_bytes_per_connection == 0
            || self.max_buffered_bytes_total == 0
        {
            return Err(ConfigError::Validate(
                "Wisp pending packet and byte limits must be greater than zero".into(),
            ));
        }
        if self.max_pending_packets_per_stream < self.buffer_size
            || self.max_pending_packets_per_stream > 4096
        {
            return Err(ConfigError::Validate(
                "wisp.limits.max_pending_packets_per_stream must cover buffer_size and be at most 4096"
                    .into(),
            ));
        }
        if self.max_egress_queue_bytes < self.max_binary_frame_bytes
            || self.max_egress_queue_bytes < self.max_text_frame_bytes
            || self.max_egress_queue_bytes > u32::MAX as u64
        {
            return Err(ConfigError::Validate(
                "wisp.limits.max_egress_queue_bytes must fit u32 and hold one maximum frame".into(),
            ));
        }
        if let Some(servers) = &self.dns_servers {
            for server in servers {
                if server.parse::<std::net::IpAddr>().is_err() {
                    return Err(ConfigError::Validate(format!(
                        "wisp.dns.dns_servers contains invalid IP address {server}"
                    )));
                }
            }
        }
        for (name, entries) in [
            (
                "wisp.client.parse_real_ip_from",
                Some(&self.parse_real_ip_from),
            ),
            (
                "wisp.client.client_ip_blacklist",
                self.client_ip_blacklist.as_ref(),
            ),
            (
                "wisp.client.client_ip_whitelist",
                self.client_ip_whitelist.as_ref(),
            ),
            ("wisp.destination.ip_blacklist", self.ip_blacklist.as_ref()),
            ("wisp.destination.ip_whitelist", self.ip_whitelist.as_ref()),
        ] {
            if let Some(entries) = entries {
                for entry in entries {
                    if let Err(reason) = parse_cidr(entry) {
                        return Err(ConfigError::Validate(format!(
                            "{name} contains invalid IP or CIDR {entry} ({reason})"
                        )));
                    }
                }
                warn_catch_all(name, entries);
            }
        }
        // A missing whitelist is unrestricted and a present one admits only
        // what it lists. These lists once read an empty value as "no
        // restriction", so an empty one is an error rather than a silent
        // switch to "nothing allowed". The origin whitelist always meant
        // "nothing allowed" when empty and keeps that meaning.
        for (name, len) in [
            (
                "wisp.destination.domain_whitelist",
                self.domain_whitelist.as_ref().map(Vec::len),
            ),
            (
                "wisp.destination.ip_whitelist",
                self.ip_whitelist.as_ref().map(Vec::len),
            ),
            (
                "wisp.destination.port_whitelist",
                self.port_whitelist.as_ref().map(Vec::len),
            ),
            (
                "wisp.destination.udp_port_whitelist",
                self.udp_port_whitelist.as_ref().map(Vec::len),
            ),
            (
                "wisp.client.client_ip_whitelist",
                self.client_ip_whitelist.as_ref().map(Vec::len),
            ),
        ] {
            if len == Some(0) {
                return Err(ConfigError::Validate(format!(
                    "{name} must not be empty, remove the key to leave it unrestricted"
                )));
            }
        }
        for (name, entries) in [
            (
                "wisp.destination.domain_blacklist",
                self.domain_blacklist.as_ref(),
            ),
            (
                "wisp.destination.domain_whitelist",
                self.domain_whitelist.as_ref(),
            ),
        ] {
            for entry in entries.into_iter().flatten() {
                if normalize_domain_pattern(entry).is_none() {
                    return Err(ConfigError::Validate(format!(
                        "{name} contains invalid domain pattern {entry}"
                    )));
                }
            }
        }
        for (name, entries) in [
            (
                "wisp.origin.origin_blacklist",
                self.origin_blacklist.as_ref(),
            ),
            (
                "wisp.origin.origin_whitelist",
                self.origin_whitelist.as_ref(),
            ),
        ] {
            for entry in entries.into_iter().flatten() {
                parse_origin_pattern(entry)
                    .map_err(|error| ConfigError::Validate(format!("{name}: {error}")))?;
            }
        }
        if let Some(rules) = &self.host_port_whitelist {
            for rule in rules {
                if rule.normalized_host().is_none() {
                    return Err(ConfigError::Validate(format!(
                        "wisp.destination.host_port_whitelist contains invalid host or port {}:{}",
                        rule.host, rule.port
                    )));
                }
            }
        }
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
        if self.protocol_inspection_allow_quic_initial {
            return Err(ConfigError::Validate(
                "QUIC Initial inspection is not supported on proxied TCP streams".into(),
            ));
        }
        // Zero semantics. Rate limits are token buckets where 0 would deny
        // every request, so it is rejected: use -1 for "no cap" or a real
        // number. The exceptions are documented per key: max_connections and
        // max_connections_per_ip (0 = unlimited), stream_limit_total
        // (0 = unlimited) and max_binary_packets_per_connection_per_minute
        // (0 = disabled, the default).
        for (name, value) in [
            (
                "max_connection_starts_per_ip_per_minute",
                self.max_connection_starts_per_ip_per_minute,
            ),
            (
                "max_connection_starts_per_minute",
                self.max_connection_starts_per_minute,
            ),
            (
                "max_tcp_stream_opens_per_connection_per_minute",
                self.max_tcp_stream_opens_per_connection_per_minute,
            ),
            (
                "max_tcp_stream_opens_per_ip_per_minute",
                self.max_tcp_stream_opens_per_ip_per_minute,
            ),
            (
                "max_tcp_bytes_per_connection_per_second",
                self.max_tcp_bytes_per_connection_per_second,
            ),
            (
                "max_tcp_bytes_per_ip_per_second",
                self.max_tcp_bytes_per_ip_per_second,
            ),
            (
                "max_datagrams_per_connection_per_second",
                self.max_datagrams_per_connection_per_second,
            ),
            (
                "max_datagram_bytes_per_connection_per_second",
                self.max_datagram_bytes_per_connection_per_second,
            ),
            (
                "max_datagrams_per_ip_per_second",
                self.max_datagrams_per_ip_per_second,
            ),
            (
                "max_datagram_bytes_per_ip_per_second",
                self.max_datagram_bytes_per_ip_per_second,
            ),
            (
                "max_control_messages_per_connection_per_minute",
                self.max_control_messages_per_connection_per_minute,
            ),
            (
                "max_control_messages_per_ip_per_minute",
                self.max_control_messages_per_ip_per_minute,
            ),
            (
                "max_dns_resolutions_per_ip_per_minute",
                self.max_dns_resolutions_per_ip_per_minute,
            ),
            (
                "max_dns_resolutions_per_minute",
                self.max_dns_resolutions_per_minute,
            ),
            (
                "max_unique_hostnames_per_ip_per_minute",
                self.max_unique_hostnames_per_ip_per_minute,
            ),
        ] {
            if value == 0 {
                return Err(ConfigError::Validate(format!(
                    "{name} must be > 0 (use -1 for no cap)"
                )));
            }
        }
        if self.stream_limit_per_host == 0 || self.stream_limit_per_host < -1 {
            return Err(ConfigError::Validate(
                "wisp.server.stream_limit_per_host must be -1 (no cap) or >= 1".into(),
            ));
        }
        if self.max_binary_frame_bytes == 0 || self.max_text_frame_bytes == 0 {
            return Err(ConfigError::Validate(
                "wisp.limits.max_binary_frame_bytes and max_text_frame_bytes must be > 0".into(),
            ));
        }
        if self.datagram_rate_limit_strikes == 0 || self.datagram_rate_limit_strike_window_ms == 0 {
            return Err(ConfigError::Validate(
                "wisp.limits.datagram_rate_limit_strikes and strike_window_ms must be > 0".into(),
            ));
        }
        // The Wisp CONNECT wire format caps a hostname at 255 octets and the
        // WebSocket path parses with exactly that bound, so a larger value
        // could never take effect there. Smaller values are enforced on
        // WebTransport streams only.
        if self.max_host_bytes == 0 || self.max_host_bytes > 255 {
            return Err(ConfigError::Validate(
                "wisp.limits.max_host_bytes must be between 1 and 255".into(),
            ));
        }
        for (name, value) in [
            ("stream_idle_timeout_ms", self.stream_idle_timeout_ms),
            ("connect_timeout_ms", self.connect_timeout_ms),
            ("idle_timeout_ms", self.idle_timeout_ms),
            ("handshake_timeout_ms", self.handshake_timeout_ms),
            (
                "protocol_inspection_timeout_ms",
                self.protocol_inspection_timeout_ms,
            ),
        ] {
            if value == Some(0) {
                return Err(ConfigError::Validate(format!(
                    "wisp.timeouts.{name} must be > 0 (omit the key for the default)"
                )));
            }
        }
        if !(16..=64).contains(&self.rate_limit_ipv6_prefix) {
            return Err(ConfigError::Validate(
                "wisp.rate_limit.ipv6_prefix must be between 16 and 64".into(),
            ));
        }
        match self.rate_limit_backend {
            RateLimitBackend::Memory => {
                if self.redis_rate_limit_url.is_some() {
                    return Err(ConfigError::Validate(
                        "redis_url is only valid when wisp.rate_limit.backend=redis".into(),
                    ));
                }
            }
            RateLimitBackend::Redis => {
                let url = self.redis_rate_limit_url.as_deref().unwrap_or_default();
                if url.trim().is_empty() {
                    return Err(ConfigError::Validate(
                        "wisp.rate_limit.backend=redis requires redis_url".into(),
                    ));
                }
                let prefix = self.redis_rate_limit_key_prefix.trim().trim_matches(':');
                if prefix.is_empty() || prefix.contains(['{', '}']) {
                    return Err(ConfigError::Validate(
                        "redis_key_prefix must not be empty or contain braces".into(),
                    ));
                }
                let tag = self.redis_rate_limit_hash_tag.trim();
                if tag.is_empty() || tag.contains(['{', '}']) {
                    return Err(ConfigError::Validate(
                        "redis_hash_tag must not be empty or contain braces".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Resolve the effective client IP from the direct socket peer and an optional
/// `X-Forwarded-For` header, honoring `parse_real_ip` / `parse_real_ip_from`.
///
/// The header is trusted only when the direct peer is itself within one of the
/// `parse_real_ip_from` trusted-proxy CIDRs; otherwise the raw peer is returned
/// (a client cannot spoof its IP by sending the header directly). When trusted,
/// the chain is walked right-to-left and the first hop that is not itself a
/// trusted proxy is taken as the real client. See [`walk_forwarded_chain`] for
/// how malformed entries are handled.
pub fn resolve_client_ip(
    peer_ip: &str,
    forwarded_for: Option<&str>,
    opts: &WispServerOptions,
) -> String {
    use std::net::IpAddr;
    if !opts.parse_real_ip {
        return peer_ip.to_owned();
    }
    let Some(xff) = forwarded_for else {
        return peer_ip.to_owned();
    };
    let Ok(peer) = peer_ip.parse::<IpAddr>() else {
        return peer_ip.to_owned();
    };
    if !ip_in_trusted(peer, &opts.parse_real_ip_from) {
        return peer_ip.to_owned();
    }
    walk_forwarded_chain(peer, xff, &opts.parse_real_ip_from).to_string()
}

/// Like [`resolve_client_ip`], but `None` when the peer is not a trusted proxy
/// or sent no header, so a caller that requires a trusted edge can refuse the
/// connection. A malformed forwarded entry never produces `None`.
pub fn resolve_client_ip_checked(
    peer_ip: &str,
    forwarded_for: Option<&str>,
    opts: &WispServerOptions,
) -> Option<String> {
    use std::net::IpAddr;
    if !opts.parse_real_ip {
        return Some(peer_ip.to_owned());
    }
    let xff = forwarded_for?;
    let peer = peer_ip.parse::<IpAddr>().ok()?;
    if !ip_in_trusted(peer, &opts.parse_real_ip_from) {
        return None;
    }
    Some(walk_forwarded_chain(peer, xff, &opts.parse_real_ip_from).to_string())
}

/// Walk an `X-Forwarded-For` chain from the right and return the first hop
/// that is not a trusted proxy. Empty entries are skipped. Entries may carry a
/// port (`1.2.3.4:5678`, `[::1]:80`); the port is dropped. An entry that does
/// not parse ends the walk without being believed, and the nearest trusted hop
/// seen so far (the peer when none) stands in for it, so a header from a
/// filtering proxy such as `unknown` degrades to a shared identity instead of a
/// refused connection. A chain made only of trusted hops resolves to its
/// leftmost one.
fn walk_forwarded_chain(peer: std::net::IpAddr, xff: &str, trusted: &[String]) -> std::net::IpAddr {
    let mut nearest_trusted = peer;
    for entry in xff.rsplit(',') {
        if entry.trim().is_empty() {
            continue;
        }
        let Some(ip) = parse_forwarded_entry(entry) else {
            return nearest_trusted;
        };
        if !ip_in_trusted(ip, trusted) {
            return ip;
        }
        nearest_trusted = ip;
    }
    nearest_trusted
}

/// One `X-Forwarded-For` entry as an address: a bare IPv4 or IPv6 address,
/// `IPv4:port`, or `[IPv6]` with an optional `:port`.
fn parse_forwarded_entry(entry: &str) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    fn is_port(port: &str) -> bool {
        !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok()
    }
    let entry = entry.trim();
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || tail.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        return host.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    let (host, port) = entry.rsplit_once(':')?;
    if !is_port(port) {
        return None;
    }
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

pub fn is_client_ip_allowed(client_ip: &str, opts: &WispServerOptions) -> bool {
    let Ok(ip) = client_ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    if opts
        .client_ip_blacklist
        .as_ref()
        .is_some_and(|entries| entries.iter().any(|entry| cidr_contains(entry, ip)))
    {
        return false;
    }
    // An empty whitelist admits nobody; validation refuses one.
    opts.client_ip_whitelist
        .as_ref()
        .is_none_or(|entries| entries.iter().any(|entry| cidr_contains(entry, ip)))
}

pub fn is_trusted_proxy_ip(peer_ip: &str, opts: &WispServerOptions) -> bool {
    peer_ip
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip_in_trusted(ip, &opts.parse_real_ip_from))
}

fn ip_in_trusted(ip: std::net::IpAddr, cidrs: &[String]) -> bool {
    cidrs.iter().any(|c| cidr_contains(c, ip))
}

fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    parse_cidr(cidr).is_ok_and(|cidr| cidr.contains(ip))
}

/// A parsed CIDR rule. IPv4-mapped IPv6 rules are stored as the IPv4 range
/// they cover, because candidate addresses are canonicalized the same way
/// before they are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cidr {
    V4 { net: u32, prefix: u8 },
    V6 { net: u128, prefix: u8 },
}

impl Cidr {
    fn contains(self, ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        match (self, ip.to_canonical()) {
            (Cidr::V4 { net, prefix }, IpAddr::V4(c)) => {
                prefix_match(u128::from(net), u128::from(u32::from(c)), prefix, 32)
            }
            (Cidr::V6 { net, prefix }, IpAddr::V6(c)) => {
                prefix_match(net, u128::from(c), prefix, 128)
            }
            _ => false,
        }
    }
}

/// Parse an IP or `IP/prefix` rule. The prefix must be plain decimal digits
/// within the family's range. A mapped IPv6 rule (`::ffff:a.b.c.d/N`) counts
/// its prefix over 128 bits, so it needs N of at least 96 and covers the
/// matching IPv4 range; a shorter prefix would reach beyond the mapped space and
/// is refused.
fn parse_cidr(entry: &str) -> std::result::Result<Cidr, &'static str> {
    use std::net::IpAddr;
    let entry = entry.trim();
    if entry.is_empty() {
        return Err("empty entry");
    }
    let (addr_s, prefix_s) = match entry.split_once('/') {
        Some((addr, prefix)) => (addr.trim(), Some(prefix.trim())),
        None => (entry, None),
    };
    let addr = addr_s.parse::<IpAddr>().map_err(|_| "not an IP address")?;
    let prefix = match prefix_s {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("prefix length must be decimal digits");
            }
            Some(p.parse::<u8>().map_err(|_| "prefix length out of range")?)
        }
    };
    match addr {
        IpAddr::V4(v4) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return Err("IPv4 prefix length must be at most 32");
            }
            Ok(Cidr::V4 {
                net: u32::from(v4),
                prefix,
            })
        }
        IpAddr::V6(v6) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return Err("IPv6 prefix length must be at most 128");
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                if prefix < 96 {
                    return Err("IPv4-mapped IPv6 prefix length must be at least 96");
                }
                return Ok(Cidr::V4 {
                    net: u32::from(v4),
                    prefix: prefix - 96,
                });
            }
            Ok(Cidr::V6 {
                net: u128::from(v6),
                prefix,
            })
        }
    }
}

/// Warn about `/0` rules. A `/0` covers one address family only, so a lone
/// `0.0.0.0/0` leaves IPv6 unmatched (and `::/0` leaves IPv4 unmatched); list
/// both to cover both. In the trusted-proxy list a catch-all lets every peer
/// forge `X-Forwarded-For`.
fn warn_catch_all(name: &str, entries: &[String]) {
    let mut v4 = false;
    let mut v6 = false;
    for entry in entries {
        match parse_cidr(entry) {
            Ok(Cidr::V4 { prefix: 0, .. }) => v4 = true,
            Ok(Cidr::V6 { prefix: 0, .. }) => v6 = true,
            _ => {}
        }
    }
    if name == "wisp.client.parse_real_ip_from" {
        if v4 || v6 {
            tracing::warn!(
                "{name} trusts every {} peer; any client can forge X-Forwarded-For",
                match (v4, v6) {
                    (true, true) => "IPv4 and IPv6",
                    (true, false) => "IPv4",
                    _ => "IPv6",
                }
            );
        }
    } else if v4 != v6 {
        tracing::warn!(
            "{name} has a catch-all rule for {} only; add {} to cover the other address family",
            if v4 { "IPv4" } else { "IPv6" },
            if v4 { "::/0" } else { "0.0.0.0/0" }
        );
    }
}

fn prefix_match(net: u128, cand: u128, prefix: u8, total: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = u32::from(total - prefix);
    (net >> shift) == (cand >> shift)
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

/// The option fields typed [`Limit`] in the TOML, by their JSON (camelCase)
/// names. [`WispServerOptions`] stores them as `u64` with `u64::MAX` meaning no
/// cap, which a JSON caller cannot send exactly (JS reads it back as a BigInt),
/// so JSON callers spell it `-1`, as TOML does. Other fields keep their own
/// meaning: `streamLimitPerHost` is an `i64` where `-1` is a real value, and
/// `maxConnections` uses `0` for unlimited.
pub const LIMIT_OPTION_FIELDS: &[&str] = &[
    "maxDnsResolutionsPerIpPerMinute",
    "maxDnsResolutionsPerMinute",
    "maxUniqueHostnamesPerIpPerMinute",
    "maxConnectionStartsPerIpPerMinute",
    "maxConnectionStartsPerMinute",
    "maxTcpStreamOpensPerConnectionPerMinute",
    "maxTcpStreamOpensPerIpPerMinute",
    "maxTcpBytesPerConnectionPerSecond",
    "maxTcpBytesPerIpPerSecond",
    "maxDatagramsPerConnectionPerSecond",
    "maxDatagramBytesPerConnectionPerSecond",
    "maxDatagramsPerIpPerSecond",
    "maxDatagramBytesPerIpPerSecond",
    "maxControlMessagesPerConnectionPerMinute",
    "maxControlMessagesPerIpPerMinute",
    "maxBinaryPacketsPerConnectionPerMinute",
];

/// In serialized [`WispServerOptions`], report the no-cap sentinel of each
/// [`LIMIT_OPTION_FIELDS`] entry as `-1`.
pub fn unlimited_to_minus_one(options: &mut serde_json::Value) {
    let Some(fields) = options.as_object_mut() else {
        return;
    };
    for name in LIMIT_OPTION_FIELDS {
        if let Some(field) = fields.get_mut(*name) {
            if field.as_u64() == Some(u64::MAX) {
                *field = serde_json::Value::from(-1);
            }
        }
    }
}

/// In a JSON patch of [`WispServerOptions`], turn `-1` into the no-cap
/// sentinel for each [`LIMIT_OPTION_FIELDS`] entry and leave every other field
/// alone.
pub fn minus_one_to_unlimited(patch: &mut serde_json::Value) {
    let Some(fields) = patch.as_object_mut() else {
        return;
    };
    for name in LIMIT_OPTION_FIELDS {
        if let Some(field) = fields.get_mut(*name) {
            if field.as_i64() == Some(-1) || field.as_f64() == Some(-1.0) {
                *field = serde_json::Value::from(u64::MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        let o = WispServerOptions::default();
        assert_eq!(o.endpoint, "/wisp");
        assert_eq!(o.port_whitelist, Some(vec![80, 443]));
        assert!(o.block_blank_origins);
        assert_eq!(o.buffer_size, 256);
        assert_eq!(o.continue_threshold, 230);
        assert_eq!(o.max_pending_packets_per_stream, 512);
        assert_eq!(o.max_pending_bytes_per_stream, 1024 * 1024);
        assert_eq!(o.max_binary_frame_bytes, 256 * 1024);
        assert_eq!(o.max_egress_queue_bytes, 4 * 1024 * 1024);
        assert_eq!(o.max_ingress_bytes_per_connection, 8 * 1024 * 1024);
        assert_eq!(o.max_buffered_bytes_total, 128 * 1024 * 1024);
        assert_eq!(o.parse_real_ip_from, vec!["127.0.0.1", "::1"]);
        assert_eq!(o.rate_limit_backend, RateLimitBackend::Memory);
    }

    #[test]
    fn flow_control_limits_cover_advertised_window() {
        let mut options = WispServerOptions::default();
        options.max_pending_packets_per_stream = options.buffer_size - 1;
        assert!(options.validate().is_err());

        // The per-stream byte limit only paces credit, so it may be smaller
        // than a frame; the byte budgets must still be non-zero.
        options = WispServerOptions::default();
        options.max_pending_bytes_per_stream = options.max_binary_frame_bytes - 1;
        assert!(options.validate().is_ok());
        options.max_ingress_bytes_per_connection = 0;
        assert!(options.validate().is_err());
        options = WispServerOptions::default();
        options.max_buffered_bytes_total = 0;
        assert!(options.validate().is_err());

        options = WispServerOptions::default();
        options.continue_threshold = options.buffer_size;
        assert!(options.validate().is_err());
    }

    #[test]
    fn resolve_client_ip_trust_boundary() {
        let mut o = WispServerOptions {
            parse_real_ip: true,
            parse_real_ip_from: vec!["10.0.0.0/8".to_owned(), "127.0.0.1".to_owned()],
            ..Default::default()
        };

        assert_eq!(
            resolve_client_ip("203.0.113.9", Some("1.2.3.4"), &o),
            "203.0.113.9"
        );
        assert_eq!(
            resolve_client_ip("10.1.2.3", Some("1.2.3.4, 10.9.9.9"), &o),
            "1.2.3.4"
        );
        assert_eq!(resolve_client_ip("10.1.2.3", None, &o), "10.1.2.3");
        o.parse_real_ip = false;
        assert_eq!(
            resolve_client_ip("10.1.2.3", Some("1.2.3.4"), &o),
            "10.1.2.3"
        );
    }

    fn trusting(from: &[&str]) -> WispServerOptions {
        WispServerOptions {
            parse_real_ip: true,
            parse_real_ip_from: from.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn malformed_forwarded_entries_do_not_reject_the_upgrade() {
        let o = trusting(&["127.0.0.1", "::1"]);
        let resolve = |xff: &str| resolve_client_ip_checked("127.0.0.1", Some(xff), &o);
        // The only entry is unparseable, so the peer stands in.
        assert_eq!(resolve("unknown").as_deref(), Some("127.0.0.1"));
        assert_eq!(resolve("").as_deref(), Some("127.0.0.1"));
        assert_eq!(resolve(" , ,").as_deref(), Some("127.0.0.1"));
        // Ports are dropped from both forms.
        assert_eq!(resolve("1.2.3.4:5678").as_deref(), Some("1.2.3.4"));
        assert_eq!(resolve("[2001:db8::7]:443").as_deref(), Some("2001:db8::7"));
        assert_eq!(resolve("[2001:db8::7]").as_deref(), Some("2001:db8::7"));
        // Empty entries are skipped.
        assert_eq!(resolve("1.2.3.4,, ").as_deref(), Some("1.2.3.4"));
        assert_eq!(resolve(",1.2.3.4").as_deref(), Some("1.2.3.4"));
        // An unparseable first-untrusted entry is not skipped to reach a
        // spoofable entry on its left.
        assert_eq!(resolve("9.9.9.9, unknown").as_deref(), Some("127.0.0.1"));
        assert_eq!(
            resolve("9.9.9.9, unknown, ::1").as_deref(),
            Some("::1"),
            "falls back to the nearest trusted hop"
        );
        assert_eq!(resolve("1.2.3.4:99999").as_deref(), Some("127.0.0.1"));
        assert_eq!(resolve("1.2.3.4:").as_deref(), Some("127.0.0.1"));
        // Stops at the first untrusted hop; entries to its left are ignored.
        assert_eq!(
            resolve("6.6.6.6, 1.2.3.4, 127.0.0.1").as_deref(),
            Some("1.2.3.4")
        );
        // A chain of trusted hops resolves to its leftmost hop.
        assert_eq!(resolve("::1, 127.0.0.1").as_deref(), Some("::1"));
        // Still refuses an untrusted peer or a missing header.
        assert_eq!(
            resolve_client_ip_checked("203.0.113.9", Some("1.2.3.4"), &o),
            None
        );
        assert_eq!(resolve_client_ip_checked("127.0.0.1", None, &o), None);
        // The unchecked form agrees.
        assert_eq!(
            resolve_client_ip("127.0.0.1", Some("unknown"), &o),
            "127.0.0.1"
        );
    }

    #[test]
    fn operator_trusted_proxy_list_replaces_the_loopback_default() {
        let raw = r#"
            [wisp.client]
            parse_real_ip = true
            parse_real_ip_from = ["127.0.0.1", "::1", "173.245.48.0/20"]
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert_eq!(
            o.base.parse_real_ip_from,
            vec!["127.0.0.1", "::1", "173.245.48.0/20"]
        );
        assert!(is_trusted_proxy_ip("173.245.48.9", &o.base));
        assert!(!is_trusted_proxy_ip("173.245.64.9", &o.base));
    }

    #[test]
    fn cidr_prefixes_are_validated() {
        for bad in [
            "10.0.0.0/+8",
            "10.0.0.0/",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "10.0.0.0/8/9",
            "10.0.0.0/0x8",
            "2001:db8::/129",
            "",
            "unknown",
            "::ffff:10.0.0.0/64",
        ] {
            let o = WispServerOptions {
                parse_real_ip_from: vec![bad.to_owned()],
                ..Default::default()
            };
            assert!(o.validate().is_err(), "{bad:?} should be rejected");
        }
        for good in [
            "10.0.0.0/8",
            "10.0.0.1",
            "2001:db8::/32",
            "::1",
            "::ffff:10.0.0.0/104",
        ] {
            let o = WispServerOptions {
                parse_real_ip_from: vec![good.to_owned()],
                ..Default::default()
            };
            assert!(o.validate().is_ok(), "{good:?} should be accepted");
        }
    }

    #[test]
    fn mapped_ipv6_cidr_matches_the_mapped_ipv4_address() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(cidr_contains("::ffff:10.0.0.0/104", ip("10.1.2.3")));
        assert!(cidr_contains("::ffff:10.0.0.0/104", ip("::ffff:10.1.2.3")));
        assert!(cidr_contains("::ffff:a00:0/104", ip("10.1.2.3")));
        assert!(!cidr_contains("::ffff:10.0.0.0/104", ip("11.0.0.1")));
        assert!(cidr_contains("::ffff:10.0.0.1", ip("10.0.0.1")));
        assert!(!cidr_contains("::ffff:10.0.0.1", ip("10.0.0.2")));
        assert!(cidr_contains("::ffff:0.0.0.0/96", ip("203.0.113.5")));
        assert!(!cidr_contains("::ffff:0.0.0.0/96", ip("2001:db8::1")));
        // Shorter prefixes are refused by validation and never match.
        assert!(!cidr_contains("::ffff:10.0.0.0/64", ip("10.1.2.3")));
        assert!(parse_cidr("::ffff:10.0.0.0/64").is_err());
    }

    #[test]
    fn catch_all_rules_cover_one_family() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(cidr_contains("0.0.0.0/0", ip("203.0.113.5")));
        assert!(!cidr_contains("0.0.0.0/0", ip("2001:db8::1")));
        assert!(cidr_contains("::/0", ip("2001:db8::1")));
        assert!(!cidr_contains("::/0", ip("203.0.113.5")));
        // A catch-all trusted proxy range is accepted (with a warning).
        let o = WispServerOptions {
            parse_real_ip_from: vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()],
            ..Default::default()
        };
        assert!(o.validate().is_ok());
    }

    #[test]
    fn trusted_edge_secret_comes_from_toml_and_is_validated() {
        let raw = format!(
            r#"
            [wisp_websocket]
            enabled = true
            host = "127.0.0.1"
            port = 4001
            ingress_mode = "trusted_edge"
            trusted_edge_secret = "{}"
        "#,
            "s".repeat(32)
        );
        let cfg = parse_toml(&raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        let secret = o.websocket.trusted_edge_secret.as_ref().expect("secret");
        assert_eq!(secret.as_bytes(), "s".repeat(32).as_bytes());
        assert!(o.validate().is_ok());
        assert!(
            !format!("{o:?}").contains(&"s".repeat(32)),
            "the secret must not appear in Debug output"
        );

        let mut short = o.clone();
        short.websocket.trusted_edge_secret = Some(Secret::new("s".repeat(31)));
        assert!(short.validate().is_err());
        short.websocket.trusted_edge_secret = Some(Secret::new(""));
        assert!(short.validate().is_err());

        let mut unset = o;
        unset.websocket.trusted_edge_secret = None;
        assert!(unset.validate().is_ok());
    }

    #[test]
    fn redis_backend_requires_complete_explicit_config() {
        let mut o = WispServerOptions {
            rate_limit_backend: RateLimitBackend::Redis,
            ..Default::default()
        };
        assert!(o.validate().is_err());
        o.redis_rate_limit_url = Some("redis://127.0.0.1/".to_owned());
        assert!(o.validate().is_ok());

        o.redis_rate_limit_hash_tag = "bad{tag}".to_owned();
        assert!(o.validate().is_err());
        o.redis_rate_limit_hash_tag = "rate-limit".to_owned();
        o.redis_rate_limit_key_prefix = "bad{prefix}".to_owned();
        assert!(o.validate().is_err());
        o.redis_rate_limit_key_prefix = "wisp".to_owned();
    }

    #[test]
    fn memory_backend_rejects_redis_options() {
        let o = WispServerOptions {
            redis_rate_limit_url: Some("redis://127.0.0.1/".to_owned()),
            ..Default::default()
        };
        assert!(o.validate().is_err());
    }

    #[test]
    fn automatic_backend_is_rejected() {
        let raw = r#"
            [wisp.rate_limit]
            backend = "auto"
        "#;
        assert!(parse_toml(raw, "test").is_err());
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
    fn trusted_edge_rejects_public_bind() {
        let mut options = WispWtServerOptions::default();
        options.websocket.enabled = true;
        options.websocket.ingress_mode = IngressMode::TrustedEdge;
        options.websocket.host = "0.0.0.0".to_owned();
        assert!(options.validate().is_err());
        options.websocket.host = "127.0.0.1".to_owned();
        assert!(options.validate().is_ok());
    }

    #[test]
    fn direct_plain_accepts_only_loopback_bind() {
        let mut options = WispWtServerOptions::default();
        options.websocket.enabled = true;
        options.websocket.ingress_mode = IngressMode::DirectPlain;
        options.websocket.host = "127.0.0.1".into();
        assert!(options.validate().is_ok());

        options.websocket.host = "0.0.0.0".into();
        assert!(options.validate().is_err());
    }

    #[test]
    fn direct_tls_rejects_missing_identity() {
        let mut options = WispWtServerOptions::default();
        options.websocket.enabled = true;
        assert!(options.validate().is_err());
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
        let long = format!("/wisp/{}/", "a".repeat(487));
        assert_eq!(endpoint_path_token(&long, "/wisp").map(str::len), Some(487));
        let too_long = format!("/wisp/{}/", "a".repeat(MAX_ENDPOINT_PATH_TOKEN_BYTES + 1));
        assert_eq!(endpoint_path_token(&too_long, "/wisp"), None);
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
    fn domain_policy_has_one_canonical_name() {
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
        let legacy = r#"
            [wisp.destination]
            hostname_blacklist = ["bad.example"]
        "#;
        assert!(parse_toml(legacy, "test").is_err());
    }

    #[test]
    fn fixed_transport_engine_rejects_engine_selector() {
        let raw = r#"
            [wisp_wt]
            wt_engine = "msquic"
        "#;
        assert!(parse_toml(raw, "test").is_err());
    }

    #[test]
    fn removed_hop_limit_is_rejected() {
        let raw = r#"
            [wisp.proxy]
            max_session_hops = -1
        "#;
        assert!(parse_toml(raw, "test").is_err());
    }

    #[test]
    fn limit_negative_sentinel_is_unlimited() {
        let raw = r#"
            [wisp.limits]
            max_connection_starts_per_minute = -1
            max_tcp_bytes_per_ip_per_second = -1
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert_eq!(o.base.max_connection_starts_per_minute, u64::MAX);
        assert_eq!(o.base.max_tcp_bytes_per_ip_per_second, u64::MAX);
    }

    #[test]
    fn limit_non_negative_maps_through() {
        let raw = r#"
            [wisp.limits]
            max_connection_starts_per_minute = 4096
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert_eq!(o.base.max_connection_starts_per_minute, 4096);
    }

    #[test]
    fn limit_rejects_bad_string() {
        let raw = r#"
            [wisp.limits]
            max_connection_starts_per_minute = "banana"
        "#;
        assert!(parse_toml(raw, "test").is_err());
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
        assert!(!o.webtransport_proxy_enabled);
    }

    #[test]
    fn parses_webtransport_proxy_limits() {
        let raw = r#"
            [wisp_wt]
            enabled = true
            cert_path = "/etc/wt.pem"
            key_path = "/etc/wt.key"
            webtransport_proxy_enabled = true
            max_proxy_sessions_per_connection = 3
            max_proxy_substreams_per_session = 24
        "#;
        let cfg = parse_toml(raw, "test").expect("parse");
        let o = build_wisp_wt_options(&cfg);
        assert!(o.webtransport_proxy_enabled);
        assert_eq!(o.max_proxy_sessions_per_connection, 3);
        assert_eq!(o.max_proxy_substreams_per_session, 24);
        o.validate().expect("valid WT proxy settings");
    }

    #[test]
    fn webtransport_proxy_requires_webtransport_listener() {
        let options = WispWtServerOptions {
            webtransport_proxy_enabled: true,
            ..Default::default()
        };
        assert!(options.validate().is_err());
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
    fn hashed_token_file_loads_and_reloads() {
        let path = std::env::temp_dir().join(format!(
            "wisp-token-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let first = hex::encode(Sha256::digest(b"first-secret"));
        std::fs::write(
            &path,
            format!(
                "version = 1\n[[tokens]]\nid = \"first\"\nsha256 = \"{first}\"\n[tokens.policy]\nport_whitelist = [443]\n"
            ),
        )
        .expect("write token file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set token permissions");
        }
        let resolver = ReloadingTokenResolver::load(&path).expect("load tokens");
        let policy = futures::executor::block_on(resolver.resolve("first-secret".to_owned()))
            .expect("known token");
        assert_eq!(policy.port_whitelist, Some(vec![443]));

        let second = hex::encode(Sha256::digest(b"second-secret"));
        std::fs::write(
            &path,
            format!("version = 1\n[[tokens]]\nid = \"second\"\nsha256 = \"{second}\"\n"),
        )
        .expect("replace token file");
        resolver.reload().expect("reload tokens");
        assert!(futures::executor::block_on(resolver.resolve("first-secret".to_owned())).is_none());
        assert!(
            futures::executor::block_on(resolver.resolve("second-secret".to_owned())).is_some()
        );
        std::fs::remove_file(path).expect("remove token file");
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

    #[test]
    fn auth_registry_rejects_invalid_profile_names() {
        let reg = WispAuthRegistry::default();
        assert!(!reg.register_profile("".to_owned(), WispServerOptions::default()));
        assert!(!reg.register_profile("a/b".to_owned(), WispServerOptions::default()));
        assert!(reg.register_profile("good".to_owned(), WispServerOptions::default()));
        assert!(reg.profile("good").is_some());
    }

    #[test]
    fn limit_option_fields_are_all_options_and_match_the_toml_limits() {
        let serialized = serde_json::to_value(WispServerOptions::default()).unwrap();
        for name in LIMIT_OPTION_FIELDS {
            assert!(serialized.get(*name).is_some(), "{name} is not an option");
        }
        // Every `Limit` in the TOML sections must be listed, so a new one
        // cannot silently miss the -1 mapping.
        let toml_limits = [
            "max_dns_resolutions_per_ip_per_minute",
            "max_dns_resolutions_per_minute",
            "max_unique_hostnames_per_ip_per_minute",
            "max_connection_starts_per_ip_per_minute",
            "max_connection_starts_per_minute",
            "max_tcp_stream_opens_per_connection_per_minute",
            "max_tcp_stream_opens_per_ip_per_minute",
            "max_tcp_bytes_per_connection_per_second",
            "max_tcp_bytes_per_ip_per_second",
            "max_datagrams_per_connection_per_second",
            "max_datagram_bytes_per_connection_per_second",
            "max_datagrams_per_ip_per_second",
            "max_datagram_bytes_per_ip_per_second",
            "max_control_messages_per_connection_per_minute",
            "max_control_messages_per_ip_per_minute",
            "max_binary_packets_per_connection_per_minute",
        ];
        assert_eq!(toml_limits.len(), LIMIT_OPTION_FIELDS.len());
        let source = include_str!("lib.rs");
        for snake in toml_limits {
            assert!(
                source.contains(&format!("pub {snake}: Option<Limit>,")),
                "{snake} is not a Limit in the TOML"
            );
            let camel: String = snake
                .split('_')
                .enumerate()
                .map(|(i, part)| {
                    if i == 0 {
                        part.to_owned()
                    } else {
                        part[..1].to_uppercase() + &part[1..]
                    }
                })
                .collect();
            assert!(LIMIT_OPTION_FIELDS.contains(&camel.as_str()), "{camel}");
        }
    }

    #[test]
    fn patch_minus_one_means_unlimited_for_limit_fields_only() {
        let mut patch = serde_json::json!({
            "maxTcpBytesPerIpPerSecond": -1,
            "maxConnectionStartsPerMinute": -1.0,
            "maxDnsResolutionsPerMinute": -1,
            "streamLimitPerHost": -1,
            "maxDatagramsPerIpPerSecond": 7,
            "maxConnections": -1,
        });
        minus_one_to_unlimited(&mut patch);
        assert_eq!(patch["maxTcpBytesPerIpPerSecond"], u64::MAX);
        assert_eq!(patch["maxConnectionStartsPerMinute"], u64::MAX);
        assert_eq!(patch["maxDnsResolutionsPerMinute"], u64::MAX);
        assert_eq!(patch["streamLimitPerHost"], -1);
        assert_eq!(patch["maxDatagramsPerIpPerSecond"], 7);
        assert_eq!(
            patch["maxConnections"], -1,
            "plain counters keep their value"
        );
    }

    #[test]
    fn reported_sentinel_is_minus_one_and_round_trips() {
        let options = WispServerOptions {
            max_tcp_bytes_per_ip_per_second: u64::MAX,
            max_connection_starts_per_minute: 30,
            stream_limit_per_host: -1,
            ..WispServerOptions::default()
        };
        let mut reported = serde_json::to_value(&options).unwrap();
        unlimited_to_minus_one(&mut reported);
        assert_eq!(reported["maxTcpBytesPerIpPerSecond"], -1);
        assert_eq!(reported["maxConnectionStartsPerMinute"], 30);
        assert_eq!(reported["streamLimitPerHost"], -1);

        minus_one_to_unlimited(&mut reported);
        let back: WispServerOptions = serde_json::from_value(reported).unwrap();
        assert_eq!(back, options);
    }

    fn tweaked(edit: impl FnOnce(&mut WispServerOptions)) -> WispServerOptions {
        let mut options = WispServerOptions::default();
        edit(&mut options);
        options
    }

    #[test]
    fn zero_rate_limits_are_rejected_but_documented_zeroes_stay() {
        assert!(WispServerOptions::default().validate().is_ok());
        assert!(tweaked(|o| o.max_connection_starts_per_minute = 0)
            .validate()
            .is_err());
        assert!(tweaked(|o| o.max_connection_starts_per_minute = u64::MAX)
            .validate()
            .is_ok());
        assert!(tweaked(|o| o.max_dns_resolutions_per_ip_per_minute = 0)
            .validate()
            .is_err());

        // Counters where 0 means unlimited, and the disabled-by-default limit.
        let o = WispServerOptions {
            max_connections: 0,
            max_connections_per_ip: 0,
            stream_limit_total: 0,
            max_binary_packets_per_connection_per_minute: 0,
            ..WispServerOptions::default()
        };
        assert!(o.validate().is_ok());

        assert!(tweaked(|o| o.stream_limit_per_host = 0).validate().is_err());
        assert!(tweaked(|o| o.stream_limit_per_host = -5)
            .validate()
            .is_err());
        assert!(tweaked(|o| o.stream_limit_per_host = 4).validate().is_ok());
        assert!(tweaked(|o| o.datagram_rate_limit_strikes = 0)
            .validate()
            .is_err());
        assert!(tweaked(|o| o.handshake_timeout_ms = Some(0))
            .validate()
            .is_err());
    }

    #[test]
    fn host_byte_and_ipv6_prefix_bounds() {
        assert!(tweaked(|o| o.max_host_bytes = 256).validate().is_err());
        assert!(tweaked(|o| o.max_host_bytes = 255).validate().is_ok());
        assert!(tweaked(|o| o.max_host_bytes = 0).validate().is_err());

        assert_eq!(WispServerOptions::default().rate_limit_ipv6_prefix, 56);
        assert!(tweaked(|o| o.rate_limit_ipv6_prefix = 128)
            .validate()
            .is_err());
        assert!(tweaked(|o| o.rate_limit_ipv6_prefix = 48)
            .validate()
            .is_ok());
    }

    #[test]
    fn global_budgets_are_backstops() {
        let o = WispServerOptions::default();
        // Two hundred clients at the per-IP limits must fit under the global
        // buckets, otherwise a modest crowd locks everyone else out.
        assert!(
            o.max_connection_starts_per_minute >= 200 * o.max_connection_starts_per_ip_per_minute
        );
        assert!(o.max_dns_resolutions_per_minute >= 200 * o.max_dns_resolutions_per_ip_per_minute);
    }

    #[test]
    fn token_without_profile_uses_the_base_profile() {
        let registry = WispAuthRegistry::default();
        let startup = WispServerOptions::default();
        let mut patched = startup.clone();
        patched.max_tcp_stream_opens_per_ip_per_minute = 7;
        assert!(registry.register_profile(WISP_BASE_LIMIT_PROFILE.to_owned(), patched));

        let resolved = registry
            .resolve_policy(WispAuthTokenPolicy::default(), &startup)
            .expect("policy resolves");
        assert_eq!(resolved.options.max_tcp_stream_opens_per_ip_per_minute, 7);

        // Without a registered base profile the startup options still apply.
        let bare = WispAuthRegistry::default();
        let resolved = bare
            .resolve_policy(WispAuthTokenPolicy::default(), &startup)
            .expect("policy resolves");
        assert_eq!(
            resolved.options.max_tcp_stream_opens_per_ip_per_minute,
            startup.max_tcp_stream_opens_per_ip_per_minute
        );
    }

    #[test]
    fn rate_limit_ipv6_prefix_parses_from_toml() {
        let parsed = parse_toml("[wisp.rate_limit]\nipv6_prefix = 48\n", "test").unwrap();
        let options = build_wisp_wt_options(&parsed);
        assert_eq!(options.base.rate_limit_ipv6_prefix, 48);
    }
    fn token_policy(json: serde_json::Value) -> WispAuthTokenPolicy {
        serde_json::from_value(json).expect("policy")
    }

    #[test]
    fn token_policy_rejects_unknown_fields() {
        assert!(serde_json::from_value::<WispAuthTokenPolicy>(
            serde_json::json!({ "portWhitlist": [443] })
        )
        .is_err());
        assert!(
            serde_json::from_value::<WispAuthTokenPolicy>(serde_json::json!({
                "hostPortWhitelist": [{ "host": "a.example", "port": 1, "extra": 1 }]
            }))
            .is_err()
        );
        assert!(toml::from_str::<WispAuthTokenPolicy>("port_whitlist = [443]\n").is_err());
        // The names the TypeScript type documents still work.
        let policy = token_policy(serde_json::json!({ "hostnameBlacklist": ["bad.example"] }));
        assert_eq!(
            policy.domain_blacklist,
            Some(vec!["bad.example".to_owned()])
        );
    }

    #[test]
    fn token_policy_only_narrows_the_base() {
        let base = WispServerOptions {
            domain_blacklist: Some(vec!["a.example".to_owned()]),
            port_whitelist: Some(vec![80, 443]),
            udp_port_whitelist: Some(vec![443, 3478]),
            ..WispServerOptions::default()
        };
        let out = token_policy(serde_json::json!({
            "portWhitelist": [443, 8080],
            "domainBlacklist": ["b.example"],
            "allowPrivateIps": true,
            "allowDirectIp": true,
            "allowLoopbackIps": true,
        }))
        .apply_to(&base);
        assert_eq!(out.port_whitelist, Some(vec![443]));
        assert_eq!(out.udp_port_whitelist, Some(vec![443]));
        assert_eq!(
            out.domain_blacklist,
            Some(vec!["a.example".to_owned(), "b.example".to_owned()])
        );
        assert!(!out.allow_private_ips && !out.allow_direct_ip && !out.allow_loopback_ips);

        // A base with no whitelist takes the token's list as the restriction.
        let open = WispServerOptions {
            port_whitelist: None,
            ..WispServerOptions::default()
        };
        let out = token_policy(serde_json::json!({ "portWhitelist": [22] })).apply_to(&open);
        assert_eq!(out.port_whitelist, Some(vec![22]));

        // Switches the base already grants can be turned off.
        let permissive = WispServerOptions {
            allow_direct_ip: true,
            ..WispServerOptions::default()
        };
        let out = token_policy(serde_json::json!({ "allowDirectIp": false })).apply_to(&permissive);
        assert!(!out.allow_direct_ip);
    }

    #[test]
    fn token_with_empty_or_disjoint_whitelist_is_refused() {
        let registry = WispAuthRegistry::default();
        let base = WispServerOptions::default();
        for policy in [
            serde_json::json!({ "portWhitelist": [] }),
            serde_json::json!({ "domainWhitelist": [] }),
            serde_json::json!({ "ipWhitelist": [] }),
            // Disjoint from the base [80, 443]: nothing would be left.
            serde_json::json!({ "portWhitelist": [8080] }),
            serde_json::json!({ "ipWhitelist": ["not-an-ip"] }),
        ] {
            assert!(
                registry
                    .resolve_policy(token_policy(policy.clone()), &base)
                    .is_none(),
                "{policy} must be refused"
            );
        }
        assert!(registry
            .resolve_policy(
                token_policy(serde_json::json!({ "portWhitelist": [443] })),
                &base
            )
            .is_some());
    }

    #[test]
    fn empty_whitelists_fail_validation_and_none_stays_unrestricted() {
        assert!(WispServerOptions::default().validate().is_ok());
        for edit in [
            (|o: &mut WispServerOptions| o.port_whitelist = Some(vec![])) as fn(&mut _),
            |o| o.udp_port_whitelist = Some(vec![]),
            |o| o.domain_whitelist = Some(vec![]),
            |o| o.ip_whitelist = Some(vec![]),
            |o| o.client_ip_whitelist = Some(vec![]),
        ] {
            let mut o = WispServerOptions::default();
            edit(&mut o);
            assert!(o.validate().is_err());
        }
        let mut o = WispServerOptions {
            client_ip_whitelist: Some(vec![]),
            ..WispServerOptions::default()
        };
        assert!(!is_client_ip_allowed("203.0.113.1", &o));
        o.client_ip_whitelist = None;
        assert!(is_client_ip_allowed("203.0.113.1", &o));
    }

    #[test]
    fn invalid_domain_and_origin_patterns_fail_validation() {
        for edit in [
            (|o: &mut WispServerOptions| o.domain_blacklist = Some(vec!["bad..example".to_owned()]))
                as fn(&mut _),
            |o| o.domain_whitelist = Some(vec!["*".to_owned()]),
            |o| o.origin_blacklist = Some(vec!["https://*.example.com:abc".to_owned()]),
            |o| o.origin_whitelist = Some(vec!["example.com".to_owned()]),
        ] {
            let mut o = WispServerOptions::default();
            edit(&mut o);
            assert!(o.validate().is_err());
        }
        let o = WispServerOptions {
            domain_blacklist: Some(vec!["*.Example.COM.".to_owned()]),
            origin_whitelist: Some(vec!["https://*.example.com".to_owned()]),
            ..WispServerOptions::default()
        };
        assert!(o.validate().is_ok());
    }

    #[test]
    fn udp_port_whitelist_parses_under_destination() {
        let parsed = parse_toml(
            "[wisp.destination]\nport_whitelist = [80, 443]\nudp_port_whitelist = [443]\n",
            "test",
        )
        .unwrap();
        let options = build_wisp_wt_options(&parsed);
        assert_eq!(options.base.udp_port_whitelist, Some(vec![443]));
        assert_eq!(
            build_wisp_wt_options(&parse_toml("", "test").unwrap())
                .base
                .udp_port_whitelist,
            None
        );
    }

    #[test]
    fn token_file_rejects_misspelled_or_empty_policies() {
        let digest = hex::encode(Sha256::digest(b"some-secret"));
        for policy in ["port_whitlist = [443]\n", "port_whitelist = []\n"] {
            let path = std::env::temp_dir().join(format!(
                "wisp-token-policy-{}-{}.toml",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::write(
                &path,
                format!(
                    "version = 1\n[[tokens]]\nid = \"t\"\nsha256 = \"{digest}\"\n[tokens.policy]\n{policy}"
                ),
            )
            .expect("write token file");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("set token permissions");
            }
            assert!(
                ReloadingTokenResolver::load(&path).is_err(),
                "{policy:?} must not load"
            );
            std::fs::remove_file(path).expect("remove token file");
        }
    }

    #[test]
    fn host_port_rule_rejects_unknown_fields() {
        assert!(serde_json::from_value::<HostPortRule>(
            serde_json::json!({ "host": "a.example", "port": 1, "prot": 2 })
        )
        .is_err());
    }
}

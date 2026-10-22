//! Default outbound proxy adapters: TCP and UDP.
//!
//! Backend-agnostic on purpose — the server crate owns the bridge between the
//! transport side and these adapters, which speak only tokio sockets and a
//! `hickory-resolver` DNS client.

// The one unsafe module reads interface addresses with getifaddrs.
#![deny(unsafe_code)]

mod local_addrs;

use bytes::Bytes;
use hickory_resolver::{
    config::{LookupIpStrategy, NameServerConfig, ResolverConfig, GOOGLE},
    net::runtime::TokioRuntimeProvider,
    TokioResolver,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};
use wisp_config::{
    normalize_domain_pattern, normalize_hostname, DnsMethod, DnsResultOrder, WispServerOptions,
};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("dns lookup failed for {host}: {source}")]
    DnsLookup {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("dns resolver returned no addresses for {0}")]
    DnsEmpty(String),
    #[error("host '{0}' resolved to a blocked address (private/loopback/ip-literal not allowed)")]
    HostBlocked(String),
    #[error("port {0} not in allowlist")]
    PortBlocked(u16),
    #[error("connect timed out after {0:?}")]
    ConnectTimeout(Duration),
    #[error("tcp connect: {0}")]
    Connect(#[source] std::io::Error),
    #[error("udp bind: {0}")]
    UdpBind(#[source] std::io::Error),
    #[error("host '{0}' not in domain whitelist")]
    DomainNotWhitelisted(String),
    #[error("loopback ip {0} not allowed")]
    LoopbackBlocked(IpAddr),
    #[error("private ip {0} not allowed")]
    PrivateBlocked(IpAddr),
    #[error("address {0} belongs to this server")]
    LocalAddressBlocked(IpAddr),
    #[error("destination host is not a valid name or address")]
    InvalidHost,
}

/// A destination host in its one canonical spelling. Every matcher and the
/// resolver see this form, never the string the client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedHost {
    Ip(IpAddr),
    /// Lowercase, no trailing dot, valid labels, never a numeric alias.
    Name(String),
}

impl std::fmt::Display for NormalizedHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Name(name) => f.write_str(name),
        }
    }
}

/// Normalizes a client-supplied destination host, or `None` when it is not a
/// valid IP literal or DNS name.
///
/// IPv6 literals are accepted bare or in brackets and IPv4-mapped ones become
/// IPv4. A name that classic `inet_aton` parsing would read as an IPv4
/// address is rejected: its last label is all digits or `0x` hex
/// (`16843009`, `0x01010101`, `1.1.1`, `0177.0.0.1`, `1.1.1.1.`). Such a name
/// would pass for a hostname here while a system resolver dials it as a
/// literal, and no top-level domain looks like that, so nothing real is lost.
pub fn normalize_host(raw: &str) -> Option<NormalizedHost> {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(|ip| NormalizedHost::Ip(canonical_ip(IpAddr::V6(ip))));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(NormalizedHost::Ip(canonical_ip(ip)));
    }
    let name = normalize_hostname(trimmed)?;
    if is_ipv4_alias(&name) {
        return None;
    }
    Some(NormalizedHost::Name(name))
}

/// `true` for a normalized name that `inet_aton` style parsers accept as an
/// IPv4 address: the last label is decimal or octal digits, or `0x` hex.
fn is_ipv4_alias(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x")
}

/// Connection-establishment policy gates, derived from [`WispServerOptions`].
///
/// A whitelist that is `None` is unrestricted. `Some` admits only what it
/// lists, so an empty one admits nothing. Domain patterns are stored
/// normalized, the same way destination hosts are.
#[derive(Debug, Clone)]
pub struct HostPolicy {
    pub domain_blacklist: Vec<String>,
    pub domain_whitelist: Option<Vec<String>>,
    pub ip_blacklist: Vec<IpPattern>,
    pub ip_whitelist: Option<Vec<IpPattern>>,
    pub port_blacklist: Vec<u16>,
    pub port_whitelist: Option<Vec<u16>>,
    /// Ports for UDP streams. `None` means UDP follows `port_whitelist`.
    pub udp_port_whitelist: Option<Vec<u16>>,
    /// Exceptions to `port_whitelist`, never a restriction on their own.
    pub host_port_whitelist: Vec<(String, u16)>,
    pub allow_direct_ip: bool,
    pub allow_private_ips: bool,
    pub allow_loopback_ips: bool,
    /// Resolver settings for [`HostPolicy::resolve`].
    pub dns: DnsSettings,
}

impl HostPolicy {
    pub fn from_options(o: &WispServerOptions) -> Self {
        let domain_patterns = |list: &[String]| -> Vec<String> {
            list.iter()
                .filter_map(|entry| normalize_domain_pattern(entry))
                .collect()
        };
        Self {
            domain_blacklist: domain_patterns(o.domain_blacklist.as_deref().unwrap_or_default()),
            domain_whitelist: o.domain_whitelist.as_deref().map(domain_patterns),
            ip_blacklist: patterns_from_options(o.ip_blacklist.as_deref()),
            ip_whitelist: o
                .ip_whitelist
                .as_deref()
                .map(|list| patterns_from_options(Some(list))),
            port_blacklist: o.port_blacklist.clone().unwrap_or_default(),
            port_whitelist: o.port_whitelist.clone(),
            udp_port_whitelist: o.udp_port_whitelist.clone(),
            host_port_whitelist: o
                .host_port_whitelist
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(|rule| rule.normalized_host().map(|host| (host, rule.port)))
                .collect(),
            allow_direct_ip: o.allow_direct_ip,
            allow_private_ips: o.allow_private_ips,
            allow_loopback_ips: o.allow_loopback_ips,
            dns: DnsSettings::from_options(o),
        }
    }

    pub fn check(&self, host: &str, port: u16) -> Result<(), ProxyError> {
        self.check_host(host, port).map(|_| ())
    }

    /// Runs the TCP destination gates and returns the normalized host, which
    /// the caller must use from here on instead of the original string.
    pub fn check_host(&self, host: &str, port: u16) -> Result<NormalizedHost, ProxyError> {
        self.check_inner(host, port, false)
    }

    /// Like [`Self::check_host`] for a UDP stream, which has to satisfy
    /// `udp_port_whitelist` instead when one is set.
    pub fn check_udp_host(&self, host: &str, port: u16) -> Result<NormalizedHost, ProxyError> {
        self.check_inner(host, port, true)
    }

    fn check_inner(&self, host: &str, port: u16, udp: bool) -> Result<NormalizedHost, ProxyError> {
        let normalized = normalize_host(host).ok_or(ProxyError::InvalidHost)?;
        if port == 0 {
            return Err(ProxyError::PortBlocked(0));
        }
        if self.port_blacklist.contains(&port) {
            return Err(ProxyError::PortBlocked(port));
        }
        let udp_ports = self.udp_port_whitelist.as_ref().filter(|_| udp);
        // Host and port exceptions widen port_whitelist, for TCP and for UDP
        // that follows it, never an explicit UDP list.
        let scoped = udp_ports.is_none() && self.host_rule_admits(&normalized, port);
        if let Some(allowed) = udp_ports.or(self.port_whitelist.as_ref()) {
            if !allowed.contains(&port) && !scoped {
                return Err(ProxyError::PortBlocked(port));
            }
        }
        match &normalized {
            NormalizedHost::Ip(ip) => {
                // An address a host and port rule names is one the operator
                // chose to reach directly, so the rule stands in for
                // allow_direct_ip; the address gates below still apply.
                if !self.allow_direct_ip && !scoped {
                    return Err(ProxyError::HostBlocked(ip.to_string()));
                }
                self.check_ip(*ip)?;
            }
            NormalizedHost::Name(name) => {
                if let Some(whitelist) = &self.domain_whitelist {
                    if !whitelist.iter().any(|p| host_matches(name, p)) {
                        return Err(ProxyError::DomainNotWhitelisted(name.clone()));
                    }
                }
                if self.domain_blacklist.iter().any(|p| host_matches(name, p)) {
                    return Err(ProxyError::HostBlocked(name.clone()));
                }
            }
        }
        Ok(normalized)
    }

    fn host_rule_admits(&self, host: &NormalizedHost, port: u16) -> bool {
        let key = host.to_string();
        self.host_port_whitelist
            .iter()
            .any(|(allowed_host, allowed_port)| {
                *allowed_port == port && host_rule_matches(allowed_host, host, &key)
            })
    }

    /// Whether a TCP destination that passed [`Self::check_host`] is there
    /// only because a host and port rule names it: port_whitelist is set and
    /// leaves the port out. The operator chose that exact destination and
    /// port, so what it speaks is theirs to decide and protocol inspection,
    /// which holds web ports to web protocols, does not apply to it.
    pub fn admitted_only_by_host_rule(&self, host: &NormalizedHost, port: u16) -> bool {
        self.port_whitelist
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&port))
            && self.host_rule_admits(host, port)
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), ProxyError> {
        let ip = canonical_ip(ip);
        if let Some(whitelist) = &self.ip_whitelist {
            if !whitelist.iter().any(|p| p.contains(ip)) {
                return Err(ProxyError::HostBlocked(ip.to_string()));
            }
        }
        if self.ip_blacklist.iter().any(|p| p.contains(ip)) {
            return Err(ProxyError::HostBlocked(ip.to_string()));
        }
        if !self.allow_loopback_ips && ip.is_loopback() {
            return Err(ProxyError::LoopbackBlocked(ip));
        }
        if !self.allow_private_ips && is_private(ip) {
            return Err(ProxyError::PrivateBlocked(ip));
        }
        // The unspecified address and the server's own addresses reach the
        // same listeners loopback does, so they follow the loopback switch.
        if !self.allow_loopback_ips && (ip.is_unspecified() || local_addrs::is_local_address(ip)) {
            return Err(ProxyError::LocalAddressBlocked(ip));
        }
        Ok(())
    }

    /// Checks `host:port` as a TCP destination, resolves a name through the
    /// shared cached resolver and checks every address it returns. The
    /// addresses come back in the configured result order, ready to dial.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
        let host = self.check_host(host, port)?;
        self.resolve_checked(&host, port).await
    }

    /// [`Self::resolve`] for a UDP destination.
    pub async fn resolve_udp(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
        let host = self.check_udp_host(host, port)?;
        self.resolve_checked(&host, port).await
    }

    /// Resolves a host that already passed [`Self::check_host`] or
    /// [`Self::check_udp_host`] and checks every address. One blocked
    /// address fails the whole answer, so a name cannot mix a public and a
    /// private address and hope the private one is dialed.
    pub async fn resolve_checked(
        &self,
        host: &NormalizedHost,
        port: u16,
    ) -> Result<Vec<SocketAddr>, ProxyError> {
        let ips = match host {
            NormalizedHost::Ip(ip) => vec![*ip],
            NormalizedHost::Name(name) => shared_dns(&self.dns)?.lookup_all(name).await?,
        };
        for ip in &ips {
            self.check_ip(*ip)?;
        }
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPattern {
    addr: IpAddr,
    prefix: u8,
}

impl IpPattern {
    fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (addr_raw, prefix_raw) = match trimmed.split_once('/') {
            Some(parts) => parts,
            None => (trimmed, ""),
        };
        let parsed = addr_raw.parse::<IpAddr>().ok()?;
        let max_prefix = match parsed {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = if prefix_raw.is_empty() {
            max_prefix
        } else {
            prefix_raw.parse::<u8>().ok()?
        };
        if prefix > max_prefix {
            return None;
        }
        // A mapped rule (`::ffff:a.b.c.d/N`) counts N over 128 bits, and
        // candidates are canonicalized to IPv4 before matching, so it becomes
        // the IPv4 range it covers. Config validation refuses N below 96.
        if let IpAddr::V6(v6) = parsed {
            if let Some(v4) = v6.to_ipv4_mapped() {
                let prefix = prefix.checked_sub(96)?;
                return Some(Self {
                    addr: IpAddr::V4(v4),
                    prefix,
                });
            }
        }
        Some(Self {
            addr: parsed,
            prefix,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        match (self.addr, ip) {
            (IpAddr::V4(pattern), IpAddr::V4(candidate)) => prefix_match(
                u32::from(pattern) as u128,
                u32::from(candidate) as u128,
                self.prefix,
                32,
            ),
            (IpAddr::V6(pattern), IpAddr::V6(candidate)) => {
                prefix_match(u128::from(pattern), u128::from(candidate), self.prefix, 128)
            }
            _ => false,
        }
    }
}

/// A `host_port_whitelist` host against a destination: an address range
/// (`a.b.c.d/N`) holds every IP inside it, anything else is the exact host.
fn host_rule_matches(rule: &str, host: &NormalizedHost, key: &str) -> bool {
    if rule.contains('/') {
        return match host {
            NormalizedHost::Ip(ip) => {
                IpPattern::parse(rule).is_some_and(|range| range.contains(*ip))
            }
            NormalizedHost::Name(_) => false,
        };
    }
    rule == key
}

fn patterns_from_options(values: Option<&[String]>) -> Vec<IpPattern> {
    values
        .unwrap_or_default()
        .iter()
        .filter_map(|value| IpPattern::parse(value))
        .collect()
}

fn prefix_match(pattern: u128, candidate: u128, prefix: u8, total_bits: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = u32::from(total_bits - prefix);
    (pattern >> shift) == (candidate >> shift)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Matches a normalized host against a normalized pattern. `*.example.com`
/// covers the apex and every name below it.
fn host_matches(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|head| head.ends_with('.'))
    } else {
        host == pattern
    }
}

/// Treats an address as non-globally-routable and therefore unsafe to proxy to.
///
/// For IPv6, the unique-local range `fc00::/7` (RFC 4193) and the link-local
/// range `fe80::/10` (RFC 4291) are matched via their leading-segment masks.
fn is_private(ip: IpAddr) -> bool {
    const V6_ULA_MASK: u16 = 0xfe00;
    const V6_ULA_PREFIX: u16 = 0xfc00;
    const V6_LINK_LOCAL_MASK: u16 = 0xffc0;
    const V6_LINK_LOCAL_PREFIX: u16 = 0xfe80;
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || octets[0] >= 224
        }
        IpAddr::V6(v6) => {
            let lead = v6.segments()[0];
            v6.is_unspecified()
                || v6.is_multicast()
                || (lead & V6_ULA_MASK) == V6_ULA_PREFIX
                || (lead & V6_LINK_LOCAL_MASK) == V6_LINK_LOCAL_PREFIX
                || v6.segments()[..4] == [0x0100, 0, 0, 0]
                || v6.segments()[..2] == [0x2001, 0x0db8]
                || (lead & 0xe000) != 0x2000
        }
    }
}

/// The `dns_*` options a resolver is built from. Resolvers are shared between
/// connections whose settings are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    pub servers: Vec<IpAddr>,
    pub method: DnsMethod,
    pub result_order: DnsResultOrder,
    pub ttl: u64,
    pub negative_ttl: u64,
    pub cache_max_entries: u64,
    /// Bound on one lookup, from `connect_timeout_ms`.
    pub timeout: Duration,
}

impl DnsSettings {
    pub fn from_options(o: &WispServerOptions) -> Self {
        Self {
            servers: o
                .dns_servers
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            method: o.dns_method,
            result_order: o.dns_result_order,
            ttl: o.dns_ttl,
            negative_ttl: o.dns_negative_ttl,
            cache_max_entries: o.dns_cache_max_entries,
            timeout: Duration::from_millis(o.connect_timeout_ms.unwrap_or(10_000).max(1)),
        }
    }
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self::from_options(&WispServerOptions::default())
    }
}

/// Async DNS resolver backed by `hickory-resolver`.
#[derive(Clone)]
pub struct DnsClient {
    resolver: Arc<TokioResolver>,
    method: DnsMethod,
    connect_timeout: Duration,
    result_order: DnsResultOrder,
}

impl DnsClient {
    pub fn new(o: &WispServerOptions) -> Result<Self, ProxyError> {
        Self::from_settings(&DnsSettings::from_options(o))
    }

    /// Builds the resolver. With no `dns_servers` it follows the system
    /// configuration (resolv.conf and the hosts file) and falls back to
    /// Google public DNS when that cannot be read.
    pub fn from_settings(settings: &DnsSettings) -> Result<Self, ProxyError> {
        let mut builder = if settings.servers.is_empty() {
            TokioResolver::builder_tokio().unwrap_or_else(|_| {
                TokioResolver::builder_with_config(
                    ResolverConfig::udp_and_tcp(&GOOGLE),
                    TokioRuntimeProvider::default(),
                )
            })
        } else {
            TokioResolver::builder_with_config(
                ResolverConfig::from_parts(
                    None,
                    Vec::new(),
                    settings
                        .servers
                        .iter()
                        .copied()
                        .map(NameServerConfig::udp_and_tcp)
                        .collect(),
                ),
                TokioRuntimeProvider::default(),
            )
        };
        let opts = builder.options_mut();
        opts.cache_size = settings.cache_max_entries;
        // Ask for A and AAAA together so a dial can fall back across families.
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        if settings.ttl > 0 {
            opts.positive_min_ttl = Some(Duration::from_secs(settings.ttl));
            opts.positive_max_ttl = Some(Duration::from_secs(settings.ttl));
        }
        if settings.negative_ttl > 0 {
            opts.negative_min_ttl = Some(Duration::from_secs(settings.negative_ttl));
            opts.negative_max_ttl = Some(Duration::from_secs(settings.negative_ttl));
        }
        let resolver = builder.build().map_err(|e| ProxyError::DnsLookup {
            host: "resolver initialization".to_owned(),
            source: std::io::Error::other(e),
        })?;
        Ok(Self {
            resolver: Arc::new(resolver),
            method: settings.method,
            connect_timeout: settings.timeout,
            result_order: settings.result_order,
        })
    }

    /// Resolves `host` and honors `dns_method`: `lookup` keeps one address.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ProxyError> {
        let mut addrs = self.lookup_all(host).await?;
        if matches!(self.method, DnsMethod::Lookup) {
            addrs.truncate(1);
        }
        Ok(addrs)
    }

    /// Resolves `host` to every address, ordered by `dns_result_order`, for a
    /// caller that dials them with fallback. Answers are cached by the
    /// resolver and the lookup is bounded by the connect timeout.
    pub async fn lookup_all(&self, host: &str) -> Result<Vec<IpAddr>, ProxyError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![canonical_ip(ip)]);
        }
        // A trailing dot makes the name fully qualified, so the system search
        // list never appends a local suffix to a client-chosen name.
        let fqdn = if host.ends_with('.') {
            host.to_owned()
        } else {
            format!("{host}.")
        };
        let lookup = tokio::time::timeout(self.connect_timeout, self.resolver.lookup_ip(fqdn))
            .await
            .map_err(|_| ProxyError::ConnectTimeout(self.connect_timeout))?
            .map_err(|e| ProxyError::DnsLookup {
                host: host.to_owned(),
                source: std::io::Error::other(e),
            })?;
        let mut addrs: Vec<IpAddr> = lookup.iter().map(canonical_ip).collect();
        addrs.dedup();
        match self.result_order {
            DnsResultOrder::Verbatim => {}
            DnsResultOrder::Ipv4first => addrs.sort_by_key(|ip| ip.is_ipv6()),
            DnsResultOrder::Ipv6first => addrs.sort_by_key(|ip| ip.is_ipv4()),
        }
        if addrs.is_empty() {
            return Err(ProxyError::DnsEmpty(host.to_owned()));
        }
        Ok(addrs)
    }
}

/// Resolvers in use, keyed by the runtime that drives them and their
/// settings. A resolver's background tasks live on the runtime that first
/// used it, so a resolver is never handed to another runtime.
type SharedResolvers = Vec<((tokio::runtime::Id, DnsSettings), Arc<DnsClient>)>;

static SHARED_RESOLVERS: Mutex<SharedResolvers> = Mutex::new(Vec::new());

/// More distinct settings than this only happen with many limit profiles that
/// each set their own `dns_*` keys; the oldest resolver is dropped then.
const MAX_SHARED_RESOLVERS: usize = 16;

/// The process-wide cached resolver for `settings` on the current runtime,
/// created on first use. Outside a runtime a fresh, unshared one is built.
pub fn shared_dns(settings: &DnsSettings) -> Result<Arc<DnsClient>, ProxyError> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return DnsClient::from_settings(settings).map(Arc::new);
    };
    let key = (handle.id(), settings.clone());
    let mut shared = SHARED_RESOLVERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, client)) = shared.iter().find(|(k, _)| *k == key) {
        return Ok(client.clone());
    }
    let client = Arc::new(DnsClient::from_settings(settings)?);
    if shared.len() >= MAX_SHARED_RESOLVERS {
        shared.remove(0);
    }
    shared.push((key, client.clone()));
    Ok(client)
}

/// Outbound TCP connector: policy, DNS, connect, set_nodelay, keepalive.
pub struct TcpConnector {
    destination: DestinationResolver,
    connect_timeout: Duration,
    keepalive: Option<Duration>,
}

/// Resolves a destination and applies the configured hostname and IP policy
/// before a transport connects to any returned address.
pub struct DestinationResolver {
    dns: DnsClient,
    policy: HostPolicy,
}

impl DestinationResolver {
    pub fn from_options(opts: &WispServerOptions) -> Result<Self, ProxyError> {
        Ok(Self {
            dns: DnsClient::new(opts)?,
            policy: HostPolicy::from_options(opts),
        })
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
        let host = self.policy.check_host(host, port)?;
        self.resolve_normalized(host, port).await
    }

    /// [`Self::resolve`] for a UDP destination.
    pub async fn resolve_udp(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
        let host = self.policy.check_udp_host(host, port)?;
        self.resolve_normalized(host, port).await
    }

    async fn resolve_normalized(
        &self,
        host: NormalizedHost,
        port: u16,
    ) -> Result<Vec<SocketAddr>, ProxyError> {
        let ips = match host {
            NormalizedHost::Ip(ip) => vec![ip],
            NormalizedHost::Name(name) => self.dns.resolve(&name).await?,
        };
        for ip in &ips {
            self.policy.check_ip(*ip)?;
        }
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

impl TcpConnector {
    pub fn from_options(opts: &WispServerOptions) -> Result<Self, ProxyError> {
        let destination = DestinationResolver::from_options(opts)?;
        let connect_timeout = Duration::from_millis(opts.connect_timeout_ms.unwrap_or(10_000));
        let keepalive = opts
            .stream_idle_timeout_ms
            .map(|ms| Duration::from_millis(ms.max(1_000)));
        Ok(Self {
            destination,
            connect_timeout,
            keepalive,
        })
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, ProxyError> {
        let addrs = self.destination.resolve(host, port).await?;
        let mut last: Option<ProxyError> = None;
        for addr in addrs {
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(sock)) => {
                    let _ = sock.set_nodelay(true);
                    if let Some(ka) = self.keepalive {
                        apply_keepalive(&sock, ka);
                    }
                    return Ok(sock);
                }
                Ok(Err(e)) => last = Some(ProxyError::Connect(e)),
                Err(_) => last = Some(ProxyError::ConnectTimeout(self.connect_timeout)),
            }
        }
        Err(last.unwrap_or_else(|| ProxyError::DnsEmpty(host.to_owned())))
    }
}

fn apply_keepalive(sock: &TcpStream, interval: Duration) {
    let sk = socket2::SockRef::from(sock);
    let _ = sk.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(interval));
}

/// Outbound UDP socket: bind ephemeral, connect to peer, ready for send/recv.
pub struct UdpConnector {
    destination: DestinationResolver,
}

impl UdpConnector {
    pub fn from_options(opts: &WispServerOptions) -> Result<Self, ProxyError> {
        Ok(Self {
            destination: DestinationResolver::from_options(opts)?,
        })
    }

    pub async fn bind(&self, host: &str, port: u16) -> Result<UdpSocket, ProxyError> {
        let addrs = self.destination.resolve_udp(host, port).await?;
        let peer = addrs[0];
        let bind_addr = match peer {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        };
        let sock = UdpSocket::bind(bind_addr)
            .await
            .map_err(ProxyError::UdpBind)?;
        sock.connect(peer).await.map_err(ProxyError::UdpBind)?;
        Ok(sock)
    }
}

/// Re-frame helper: the datagram parser (`wisp_wire::parse_datagram`)
/// already strips kind/flow-id, so the payload goes through unchanged.
pub fn shape_udp_outbound(payload: Bytes) -> Bytes {
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pattern_matches_wildcard() {
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("example.com", "*.example.com"));
        assert!(!host_matches("evil.com", "*.example.com"));
        assert!(!host_matches("notexample.com", "*.example.com"));
        assert!(host_matches("example.com", "example.com"));
    }

    #[test]
    fn private_ip_classification() {
        assert!(is_private("10.0.0.1".parse().unwrap()));
        assert!(is_private("192.168.0.1".parse().unwrap()));
        assert!(is_private("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private("::ffff:169.254.0.1".parse().unwrap()));
        assert!(is_private("fc00::1".parse().unwrap()));
        assert!(is_private("fe80::1".parse().unwrap()));
        assert!(!is_private("8.8.8.8".parse().unwrap()));
        assert!(!is_private("::ffff:8.8.8.8".parse().unwrap()));
        assert!(is_private("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn policy_blocks_port_and_host() {
        let p = HostPolicy {
            domain_blacklist: vec!["bad.example".to_owned()],
            domain_whitelist: None,
            ip_blacklist: vec![],
            ip_whitelist: None,
            port_blacklist: vec![],
            port_whitelist: Some(vec![80, 443]),
            udp_port_whitelist: None,
            host_port_whitelist: vec![],
            allow_direct_ip: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
            dns: DnsSettings::default(),
        };
        assert!(p.check("good.example", 443).is_ok());
        assert!(matches!(
            p.check("bad.example", 443),
            Err(ProxyError::HostBlocked(_))
        ));
        assert!(matches!(
            p.check("good.example", 22),
            Err(ProxyError::PortBlocked(22))
        ));
        assert!(matches!(
            p.check("1.2.3.4", 80),
            Err(ProxyError::HostBlocked(_))
        ));
    }

    #[test]
    fn domain_policy_does_not_enable_direct_ip() {
        let p = HostPolicy {
            domain_blacklist: vec!["evil.example".to_owned()],
            domain_whitelist: None,
            ip_blacklist: vec![],
            ip_whitelist: None,
            port_blacklist: vec![],
            port_whitelist: Some(vec![80]),
            udp_port_whitelist: None,
            host_port_whitelist: vec![],
            allow_direct_ip: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
            dns: DnsSettings::default(),
        };
        assert!(p.check("8.8.8.8", 80).is_err());
    }

    #[test]
    fn whitelist_enforced_when_set() {
        let p = HostPolicy {
            domain_blacklist: vec![],
            domain_whitelist: Some(vec!["*.allowed.example".to_owned()]),
            ip_blacklist: vec![],
            ip_whitelist: None,
            port_blacklist: vec![],
            port_whitelist: None,
            udp_port_whitelist: None,
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
            dns: DnsSettings::default(),
        };
        assert!(p.check("api.allowed.example", 80).is_ok());
        assert!(matches!(
            p.check("other.example", 80),
            Err(ProxyError::DomainNotWhitelisted(_))
        ));
    }

    #[test]
    fn policy_blocks_ipv4_mapped_ipv6_loopback_and_private() {
        let p = HostPolicy {
            domain_blacklist: vec![],
            domain_whitelist: None,
            ip_blacklist: vec![],
            ip_whitelist: None,
            port_blacklist: vec![],
            port_whitelist: Some(vec![80]),
            udp_port_whitelist: None,
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
            dns: DnsSettings::default(),
        };
        assert!(matches!(
            p.check("::ffff:127.0.0.1", 80),
            Err(ProxyError::LoopbackBlocked(_))
        ));
        assert!(matches!(
            p.check("::ffff:10.0.0.1", 80),
            Err(ProxyError::PrivateBlocked(_))
        ));
        assert!(p.check("::ffff:8.8.8.8", 80).is_ok());
    }

    #[test]
    fn ip_allowlist_supports_cidr() {
        let p = HostPolicy {
            domain_blacklist: vec![],
            domain_whitelist: None,
            ip_blacklist: vec![],
            ip_whitelist: Some(vec![IpPattern::parse("8.8.8.0/24").unwrap()]),
            port_blacklist: vec![],
            port_whitelist: Some(vec![443]),
            udp_port_whitelist: None,
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
            dns: DnsSettings::default(),
        };
        assert!(p.check("8.8.8.8", 443).is_ok());
        assert!(matches!(
            p.check("1.1.1.1", 443),
            Err(ProxyError::HostBlocked(_))
        ));
    }

    #[test]
    fn ip_blacklist_supports_ipv6_cidr() {
        let p = HostPolicy {
            domain_blacklist: vec![],
            domain_whitelist: None,
            ip_blacklist: vec![IpPattern::parse("2001:db8::/32").unwrap()],
            ip_whitelist: None,
            port_blacklist: vec![],
            port_whitelist: Some(vec![443]),
            udp_port_whitelist: None,
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
            dns: DnsSettings::default(),
        };
        assert!(matches!(
            p.check("2001:db8::1", 443),
            Err(ProxyError::HostBlocked(_))
        ));
    }

    #[tokio::test]
    async fn destination_resolver_checks_literal_ip_before_connect() {
        let mut opts = WispServerOptions {
            allow_direct_ip: true,
            ..WispServerOptions::default()
        };
        let resolver = DestinationResolver::from_options(&opts).unwrap();
        assert!(matches!(
            resolver.resolve("127.0.0.1", 443).await,
            Err(ProxyError::LoopbackBlocked(_))
        ));

        opts.allow_private_ips = true;
        opts.allow_loopback_ips = true;
        let resolver = DestinationResolver::from_options(&opts).unwrap();
        assert_eq!(
            resolver.resolve("127.0.0.1", 443).await.unwrap(),
            vec!["127.0.0.1:443".parse().unwrap()]
        );
    }

    fn policy_from(edit: impl FnOnce(&mut WispServerOptions)) -> HostPolicy {
        let mut opts = WispServerOptions::default();
        edit(&mut opts);
        HostPolicy::from_options(&opts)
    }

    #[test]
    fn trailing_dot_and_case_do_not_bypass_domain_lists() {
        let p = policy_from(|o| {
            o.domain_blacklist = Some(vec![
                "Blocked.Example.".to_owned(),
                "*.wild.example".to_owned(),
            ])
        });
        for host in [
            "blocked.example.",
            "BLOCKED.example",
            " blocked.example ",
            "a.wild.example.",
            "wild.example.",
        ] {
            assert!(
                matches!(p.check(host, 443), Err(ProxyError::HostBlocked(_))),
                "{host:?} must be blocked"
            );
        }
        assert!(p.check("fine.example.", 443).is_ok());
        assert_eq!(
            p.check_host("Fine.Example.", 443).unwrap(),
            NormalizedHost::Name("fine.example".to_owned())
        );

        let p = policy_from(|o| o.domain_whitelist = Some(vec!["*.allowed.example".to_owned()]));
        assert!(p.check("api.allowed.example.", 443).is_ok());
        assert!(matches!(
            p.check("notallowed.example", 443),
            Err(ProxyError::DomainNotWhitelisted(_))
        ));
    }

    #[test]
    fn empty_labels_and_junk_hosts_are_rejected() {
        let p = policy_from(|_| {});
        for host in [
            "",
            ".",
            "a..example",
            "example.com..",
            "evil.com\r\nX: y",
            "a b.example",
            "victim:25",
            "user@host.example",
            "a/b.example",
            "fe80::1%en0",
        ] {
            assert!(
                matches!(p.check(host, 443), Err(ProxyError::InvalidHost)),
                "{host:?} must be rejected"
            );
        }
    }

    #[test]
    fn numeric_ipv4_aliases_never_count_as_names() {
        let p = policy_from(|o| o.allow_direct_ip = false);
        for host in [
            "16843009",
            "0x01010101",
            "0X01010101",
            "1.1.1",
            "1.65793",
            "0177.0.0.1",
            "1.1.1.1.",
            "8.8.8.010",
            "foo.0x1",
            "foo.123",
        ] {
            assert!(
                matches!(p.check(host, 443), Err(ProxyError::InvalidHost)),
                "{host:?} must be rejected"
            );
        }
        for host in [
            "1.1.1.1",
            "[2606:4700::1111]",
            "2606:4700::1111",
            "[::ffff:1.1.1.1]",
        ] {
            assert!(
                matches!(p.check(host, 443), Err(ProxyError::HostBlocked(_))),
                "{host:?} is a literal and direct IPs are off"
            );
        }
        assert!(p.check("1e100.net", 443).is_ok());
        assert!(p.check("123.example", 443).is_ok());
    }

    #[test]
    fn bracketed_ipv6_is_checked_as_an_address() {
        let p = policy_from(|o| o.allow_direct_ip = true);
        assert!(matches!(
            p.check("[::1]", 443),
            Err(ProxyError::LoopbackBlocked(_))
        ));
        assert!(matches!(
            p.check("[::ffff:10.0.0.1]", 443),
            Err(ProxyError::PrivateBlocked(_))
        ));
        assert_eq!(
            p.check_host("[2606:4700::1111]", 443).unwrap(),
            NormalizedHost::Ip("2606:4700::1111".parse().unwrap())
        );
    }

    #[test]
    fn own_and_unspecified_addresses_follow_the_loopback_switch() {
        let p = policy_from(|o| {
            o.allow_direct_ip = true;
            o.allow_private_ips = true;
        });
        for ip in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            assert!(
                p.check_ip(ip.parse().unwrap()).is_err(),
                "{ip} reaches local listeners"
            );
        }
        let local = local_addrs_for_test();
        for ip in &local {
            assert!(p.check_ip(*ip).is_err(), "{ip} is this host");
        }
        let open = policy_from(|o| {
            o.allow_direct_ip = true;
            o.allow_private_ips = true;
            o.allow_loopback_ips = true;
        });
        for ip in &local {
            assert!(open.check_ip(*ip).is_ok());
        }
    }

    /// A non-loopback address of this host when there is one, so the test
    /// reaches the interface check rather than the loopback check.
    fn local_addrs_for_test() -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = ["127.0.0.1", "::1"]
            .iter()
            .map(|ip| ip.parse().unwrap())
            .filter(|ip| local_addrs::is_local_address(*ip))
            .collect();
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("192.0.2.1:9").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    if local_addrs::is_local_address(addr.ip()) {
                        out.push(addr.ip());
                    }
                }
            }
        }
        out
    }

    #[test]
    fn explicit_empty_whitelists_admit_nothing() {
        let p = policy_from(|o| {
            o.port_whitelist = Some(vec![]);
        });
        assert!(matches!(
            p.check("a.example", 443),
            Err(ProxyError::PortBlocked(443))
        ));
        let p = policy_from(|o| o.domain_whitelist = Some(vec![]));
        assert!(matches!(
            p.check("a.example", 443),
            Err(ProxyError::DomainNotWhitelisted(_))
        ));
        let p = policy_from(|o| o.ip_whitelist = Some(vec![]));
        assert!(p.check_ip("8.8.8.8".parse().unwrap()).is_err());
        let p = policy_from(|o| o.port_whitelist = None);
        assert!(p.check("a.example", 22).is_ok());
    }

    #[test]
    fn udp_port_whitelist_limits_udp_only() {
        let p = policy_from(|o| {
            o.port_whitelist = Some(vec![80, 443]);
            o.udp_port_whitelist = Some(vec![443]);
            o.host_port_whitelist = Some(vec![wisp_config::HostPortRule {
                host: "game.example".to_owned(),
                port: 13002,
            }]);
        });
        assert!(p.check_udp_host("a.example", 443).is_ok());
        assert!(matches!(
            p.check_udp_host("a.example", 80),
            Err(ProxyError::PortBlocked(80))
        ));
        assert!(p.check_host("a.example", 80).is_ok());
        // Host exceptions never widen an explicit UDP list.
        assert!(p.check_host("game.example", 13002).is_ok());
        assert!(p.check_udp_host("game.example", 13002).is_err());

        // Without a UDP list, UDP follows port_whitelist and its exceptions.
        let p = policy_from(|o| {
            o.host_port_whitelist = Some(vec![wisp_config::HostPortRule {
                host: "game.example".to_owned(),
                port: 13002,
            }]);
        });
        assert!(p.check_udp_host("a.example", 80).is_ok());
        assert!(p.check_udp_host("game.example.", 13002).is_ok());
        assert!(p.check_udp_host("a.example", 53).is_err());
    }

    #[test]
    fn host_port_ranges_cover_every_address_inside() {
        let p = policy_from(|o| {
            o.port_whitelist = Some(vec![80, 443]);
            o.host_port_whitelist = Some(vec![wisp_config::HostPortRule {
                host: "162.254.192.0/21".to_owned(),
                port: 27017,
            }]);
        });
        assert!(p.check_host("162.254.193.47", 27017).is_ok());
        assert!(p.check_host("162.254.199.255", 27017).is_ok());
        assert!(p.check_host("::ffff:162.254.193.47", 27017).is_ok());
        assert!(matches!(
            p.check_host("162.254.200.1", 27017),
            Err(ProxyError::PortBlocked(27017))
        ));
        assert!(matches!(
            p.check_host("162.254.193.47", 27018),
            Err(ProxyError::PortBlocked(27018))
        ));
        // The rule lets its addresses in without allow_direct_ip, only on its port
        assert!(matches!(
            p.check_host("162.254.193.47", 443),
            Err(ProxyError::HostBlocked(_))
        ));
        let cm: NormalizedHost = p.check_host("162.254.193.47", 27017).unwrap();
        assert!(p.admitted_only_by_host_rule(&cm, 27017));
        // A range holds addresses only, never a name that resolves into it
        assert!(matches!(
            p.check_host("cm.example", 27017),
            Err(ProxyError::PortBlocked(27017))
        ));
        // And the address gates still apply inside it
        let p = policy_from(|o| {
            o.host_port_whitelist = Some(vec![wisp_config::HostPortRule {
                host: "10.0.0.0/8".to_owned(),
                port: 27017,
            }]);
        });
        assert!(matches!(
            p.check_host("10.1.2.3", 27017),
            Err(ProxyError::PrivateBlocked(_))
        ));
    }

    #[test]
    fn mapped_ipv6_rules_cover_the_ipv4_range() {
        let rule = IpPattern::parse("::ffff:5.188.124.0/120").unwrap();
        assert!(rule.contains("5.188.124.21".parse().unwrap()));
        assert!(rule.contains("::ffff:5.188.124.21".parse().unwrap()));
        assert!(!rule.contains("5.188.125.1".parse().unwrap()));
        assert!(IpPattern::parse("::ffff:5.188.124.21").is_some());
        assert!(IpPattern::parse("::ffff:0.0.0.0/64").is_none());
        let p = policy_from(|o| {
            o.allow_direct_ip = true;
            o.ip_blacklist = Some(vec!["::ffff:5.188.124.21/128".to_owned()]);
        });
        assert!(matches!(
            p.check("5.188.124.21", 443),
            Err(ProxyError::HostBlocked(_))
        ));
    }

    #[tokio::test]
    async fn policy_resolve_checks_literals_and_shares_resolvers() {
        let p = policy_from(|o| o.allow_direct_ip = true);
        assert!(matches!(
            p.resolve("127.0.0.1", 443).await,
            Err(ProxyError::LoopbackBlocked(_))
        ));
        assert!(matches!(
            p.resolve("16843009", 443).await,
            Err(ProxyError::InvalidHost)
        ));
        let open = policy_from(|o| {
            o.allow_direct_ip = true;
            o.allow_loopback_ips = true;
            o.allow_private_ips = true;
        });
        assert_eq!(
            open.resolve("[::1]", 443).await.unwrap(),
            vec!["[::1]:443".parse().unwrap()]
        );
        let first = shared_dns(&DnsSettings::default()).unwrap();
        let second = shared_dns(&DnsSettings::default()).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let other = DnsSettings {
            servers: vec!["192.0.2.53".parse().unwrap()],
            ..DnsSettings::default()
        };
        assert!(!Arc::ptr_eq(&first, &shared_dns(&other).unwrap()));
    }
}

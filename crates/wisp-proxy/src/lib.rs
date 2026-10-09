//! Default outbound proxy adapters: TCP and UDP.
//!
//! Backend-agnostic on purpose — the server crate owns the bridge between the
//! transport side and these adapters, which speak only tokio sockets and a
//! `hickory-resolver` DNS client.

#![forbid(unsafe_code)]

use bytes::Bytes;
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts, GOOGLE},
    net::runtime::TokioRuntimeProvider,
    TokioResolver,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};
use wisp_config::{DnsMethod, DnsResultOrder, WispServerOptions};

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
}

/// Connection-establishment policy gates, derived from [`WispServerOptions`].
#[derive(Debug, Clone)]
pub struct HostPolicy {
    pub domain_blacklist: Vec<String>,
    pub domain_whitelist: Vec<String>,
    pub ip_blacklist: Vec<IpPattern>,
    pub ip_whitelist: Vec<IpPattern>,
    pub port_blacklist: Vec<u16>,
    pub port_whitelist: Vec<u16>,
    pub host_port_whitelist: Vec<(String, u16)>,
    pub allow_direct_ip: bool,
    pub allow_private_ips: bool,
    pub allow_loopback_ips: bool,
}

impl HostPolicy {
    pub fn from_options(o: &WispServerOptions) -> Self {
        let domain_blacklist = o.domain_blacklist.clone().unwrap_or_default();
        let domain_whitelist = o.domain_whitelist.clone().unwrap_or_default();
        Self {
            domain_blacklist,
            domain_whitelist,
            ip_blacklist: patterns_from_options(o.ip_blacklist.as_deref()),
            ip_whitelist: patterns_from_options(o.ip_whitelist.as_deref()),
            port_blacklist: o.port_blacklist.clone().unwrap_or_default(),
            port_whitelist: o.port_whitelist.clone().unwrap_or_default(),
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
        }
    }

    pub fn check(&self, host: &str, port: u16) -> Result<(), ProxyError> {
        if port == 0 {
            return Err(ProxyError::PortBlocked(0));
        }
        if self.port_blacklist.contains(&port) {
            return Err(ProxyError::PortBlocked(port));
        }
        let normalized_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let scoped_port_allowed =
            self.host_port_whitelist
                .iter()
                .any(|(allowed_host, allowed_port)| {
                    allowed_host == &normalized_host && *allowed_port == port
                });
        if !self.port_whitelist.is_empty()
            && !self.port_whitelist.contains(&port)
            && !scoped_port_allowed
        {
            return Err(ProxyError::PortBlocked(port));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !self.allow_direct_ip {
                return Err(ProxyError::HostBlocked(host.to_owned()));
            }
            self.check_ip(ip)?;
            return Ok(());
        }
        if !self.domain_whitelist.is_empty()
            && !self.domain_whitelist.iter().any(|p| host_matches(host, p))
        {
            return Err(ProxyError::DomainNotWhitelisted(host.to_owned()));
        }
        if self.domain_blacklist.iter().any(|p| host_matches(host, p)) {
            return Err(ProxyError::HostBlocked(host.to_owned()));
        }
        Ok(())
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), ProxyError> {
        let ip = canonical_ip(ip);
        if !self.ip_whitelist.is_empty() && !self.ip_whitelist.iter().any(|p| p.contains(ip)) {
            return Err(ProxyError::HostBlocked(ip.to_string()));
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
        Ok(())
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
        let addr = canonical_ip(addr_raw.parse::<IpAddr>().ok()?);
        let max_prefix = match addr {
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
        Some(Self { addr, prefix })
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

fn host_matches(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
    } else {
        host.eq_ignore_ascii_case(pattern)
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
        let method = o.dns_method;
        let servers: Vec<IpAddr> = o
            .dns_servers
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let mut opts = ResolverOpts::default();
        opts.cache_size = o.dns_cache_max_entries;
        if o.dns_ttl > 0 {
            opts.positive_min_ttl = Some(Duration::from_secs(o.dns_ttl));
            opts.positive_max_ttl = Some(Duration::from_secs(o.dns_ttl));
        }
        if o.dns_negative_ttl > 0 {
            opts.negative_min_ttl = Some(Duration::from_secs(o.dns_negative_ttl));
            opts.negative_max_ttl = Some(Duration::from_secs(o.dns_negative_ttl));
        }
        let config = if servers.is_empty() {
            ResolverConfig::udp_and_tcp(&GOOGLE)
        } else {
            ResolverConfig::from_parts(
                None,
                Vec::new(),
                servers
                    .iter()
                    .copied()
                    .map(NameServerConfig::udp_and_tcp)
                    .collect(),
            )
        };
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| ProxyError::DnsLookup {
                host: "resolver initialization".to_owned(),
                source: std::io::Error::other(e),
            })?;
        let connect_timeout = Duration::from_millis(o.connect_timeout_ms.unwrap_or(10_000));
        Ok(Self {
            resolver: Arc::new(resolver),
            method,
            connect_timeout,
            result_order: o.dns_result_order,
        })
    }

    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ProxyError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![canonical_ip(ip)]);
        }
        let lookup = tokio::time::timeout(self.connect_timeout, self.resolver.lookup_ip(host))
            .await
            .map_err(|_| ProxyError::ConnectTimeout(self.connect_timeout))?
            .map_err(|e| ProxyError::DnsLookup {
                host: host.to_owned(),
                source: std::io::Error::other(e),
            })?;
        let mut addrs: Vec<IpAddr> = lookup.iter().map(canonical_ip).collect();
        match self.result_order {
            DnsResultOrder::Verbatim => {}
            DnsResultOrder::Ipv4first => addrs.sort_by_key(|ip| ip.is_ipv6()),
            DnsResultOrder::Ipv6first => addrs.sort_by_key(|ip| ip.is_ipv4()),
        }
        if matches!(self.method, DnsMethod::Lookup) {
            addrs.truncate(1);
        }
        if addrs.is_empty() {
            return Err(ProxyError::DnsEmpty(host.to_owned()));
        }
        Ok(addrs)
    }
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
        self.policy.check(host, port)?;
        let ips = self.dns.resolve(host).await?;
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
        let addrs = self.destination.resolve(host, port).await?;
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
        assert!(host_matches("Example.com", "example.com"));
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
            domain_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![80, 443],
            host_port_whitelist: vec![],
            allow_direct_ip: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
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
            domain_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![80],
            host_port_whitelist: vec![],
            allow_direct_ip: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
        };
        assert!(p.check("8.8.8.8", 80).is_err());
    }

    #[test]
    fn whitelist_enforced_when_set() {
        let p = HostPolicy {
            domain_blacklist: vec![],
            domain_whitelist: vec!["*.allowed.example".to_owned()],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![],
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
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
            domain_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![80],
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
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
            domain_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![IpPattern::parse("8.8.8.0/24").unwrap()],
            port_blacklist: vec![],
            port_whitelist: vec![443],
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
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
            domain_whitelist: vec![],
            ip_blacklist: vec![IpPattern::parse("2001:db8::/32").unwrap()],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![443],
            host_port_whitelist: vec![],
            allow_direct_ip: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
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
}

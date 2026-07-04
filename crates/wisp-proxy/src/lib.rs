//! Default proxy adapters: TCP, UDP, WT-proxy. Mirrors `wisp-wt/src/proxy/*`.
//!
//! Backend-agnostic on purpose — the wisp-wt server (`wisp-server`) owns
//! the bridge between the WT side (msquic adapter) and these adapters,
//! which speak only tokio sockets and a `hickory-resolver` DNS client.

#![forbid(unsafe_code)]

use bytes::Bytes;
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};
use wisp_config::{DnsMethod, WispServerOptions};

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
    #[error("policy: {0}")]
    Policy(&'static str),
}

/// Connection-establishment policy gates, derived from [`WispServerOptions`].
#[derive(Debug, Clone)]
pub struct HostPolicy {
    pub hostname_blacklist: Vec<String>,
    pub hostname_whitelist: Vec<String>,
    pub ip_blacklist: Vec<IpPattern>,
    pub ip_whitelist: Vec<IpPattern>,
    pub port_blacklist: Vec<u16>,
    pub port_whitelist: Vec<u16>,
    pub allow_direct_ip: bool,
    pub allow_direct_ip_with_domain_policy: bool,
    pub allow_private_ips: bool,
    pub allow_loopback_ips: bool,
}

impl HostPolicy {
    pub fn from_options(o: &WispServerOptions) -> Self {
        // domain_blacklist / hostname_blacklist are aliases per `config.ts`.
        let hostname_blacklist = match (&o.hostname_blacklist, &o.domain_blacklist) {
            (Some(v), _) => v.clone(),
            (None, Some(v)) => v.clone(),
            _ => Vec::new(),
        };
        let hostname_whitelist = match (&o.hostname_whitelist, &o.domain_whitelist) {
            (Some(v), _) => v.clone(),
            (None, Some(v)) => v.clone(),
            _ => Vec::new(),
        };
        Self {
            hostname_blacklist,
            hostname_whitelist,
            ip_blacklist: patterns_from_options(o.ip_blacklist.as_deref()),
            ip_whitelist: patterns_from_options(o.ip_whitelist.as_deref()),
            port_blacklist: o.port_blacklist.clone().unwrap_or_default(),
            port_whitelist: o.port_whitelist.clone().unwrap_or_default(),
            allow_direct_ip: o.allow_direct_ip,
            allow_direct_ip_with_domain_policy: o.allow_direct_ip_with_domain_policy,
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
        if !self.port_whitelist.is_empty() && !self.port_whitelist.contains(&port) {
            return Err(ProxyError::PortBlocked(port));
        }
        if !self.hostname_whitelist.is_empty()
            && !self
                .hostname_whitelist
                .iter()
                .any(|p| host_matches(host, p))
        {
            return Err(ProxyError::Policy("hostname not in whitelist"));
        }
        if self
            .hostname_blacklist
            .iter()
            .any(|p| host_matches(host, p))
        {
            return Err(ProxyError::HostBlocked(host.to_owned()));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            let has_domain_policy =
                !self.hostname_whitelist.is_empty() || !self.hostname_blacklist.is_empty();
            if !self.allow_direct_ip
                && (!self.allow_direct_ip_with_domain_policy || !has_domain_policy)
            {
                return Err(ProxyError::HostBlocked(host.to_owned()));
            }
            self.check_ip(ip)?;
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
            return Err(ProxyError::Policy("loopback ip not allowed"));
        }
        if !self.allow_private_ips && is_private(ip) {
            return Err(ProxyError::Policy("private ip not allowed"));
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

fn is_private(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local() || v4.is_broadcast() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10
        }
    }
}

/// Async DNS resolver backed by `hickory-resolver`.
#[derive(Clone)]
pub struct DnsClient {
    resolver: Arc<TokioAsyncResolver>,
    method: DnsMethod,
    connect_timeout: Duration,
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
        opts.cache_size = o.dns_cache_max_entries.max(64) as usize;
        if o.dns_ttl > 0 {
            opts.positive_min_ttl = Some(Duration::from_secs(o.dns_ttl));
            opts.positive_max_ttl = Some(Duration::from_secs(o.dns_ttl));
        }
        if o.dns_negative_ttl > 0 {
            opts.negative_min_ttl = Some(Duration::from_secs(o.dns_negative_ttl));
            opts.negative_max_ttl = Some(Duration::from_secs(o.dns_negative_ttl));
        }
        let config = if servers.is_empty() {
            ResolverConfig::default()
        } else {
            let group = NameServerConfigGroup::from_ips_clear(&servers, 53, true);
            ResolverConfig::from_parts(None, Vec::new(), group)
        };
        let resolver = TokioAsyncResolver::tokio(config, opts);
        let connect_timeout = Duration::from_millis(o.connect_timeout_ms.unwrap_or(10_000));
        Ok(Self {
            resolver: Arc::new(resolver),
            method,
            connect_timeout,
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
    dns: DnsClient,
    policy: HostPolicy,
    connect_timeout: Duration,
    keepalive: Option<Duration>,
}

impl TcpConnector {
    pub fn from_options(opts: &WispServerOptions) -> Result<Self, ProxyError> {
        let dns = DnsClient::new(opts)?;
        let policy = HostPolicy::from_options(opts);
        let connect_timeout = Duration::from_millis(opts.connect_timeout_ms.unwrap_or(10_000));
        // Borrow stream idle as the TCP keepalive interval if set.
        let keepalive = opts
            .stream_idle_timeout_ms
            .map(|ms| Duration::from_millis(ms.max(1_000)));
        Ok(Self {
            dns,
            policy,
            connect_timeout,
            keepalive,
        })
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, ProxyError> {
        self.policy.check(host, port)?;
        let addrs = self.dns.resolve(host).await?;
        for ip in &addrs {
            self.policy.check_ip(*ip)?;
        }
        let mut last: Option<ProxyError> = None;
        for ip in addrs {
            let sa = SocketAddr::new(ip, port);
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(sa)).await {
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
    // SockRef borrows the fd from the TcpStream without taking ownership, so
    // the keepalive setting applies in-place and no drop reclaims the fd.
    let sk = socket2::SockRef::from(sock);
    let _ = sk.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(interval));
}

/// Outbound UDP socket: bind ephemeral, connect to peer, ready for send/recv.
pub struct UdpConnector {
    dns: DnsClient,
    policy: HostPolicy,
}

impl UdpConnector {
    pub fn from_options(opts: &WispServerOptions) -> Result<Self, ProxyError> {
        let dns = DnsClient::new(opts)?;
        let policy = HostPolicy::from_options(opts);
        Ok(Self { dns, policy })
    }

    pub async fn bind(&self, host: &str, port: u16) -> Result<UdpSocket, ProxyError> {
        self.policy.check(host, port)?;
        let addrs = self.dns.resolve(host).await?;
        for ip in &addrs {
            self.policy.check_ip(*ip)?;
        }
        let peer = SocketAddr::new(addrs[0], port);
        let bind_addr = match peer {
            SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().unwrap(),
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
        assert!(!is_private("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn policy_blocks_port_and_host() {
        let p = HostPolicy {
            hostname_blacklist: vec!["bad.example".to_owned()],
            hostname_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![80, 443],
            allow_direct_ip: false,
            allow_direct_ip_with_domain_policy: false,
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
    fn allow_direct_ip_with_domain_policy_kicks_in() {
        let p = HostPolicy {
            hostname_blacklist: vec!["evil.example".to_owned()],
            hostname_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![80],
            allow_direct_ip: false,
            allow_direct_ip_with_domain_policy: true,
            allow_private_ips: false,
            allow_loopback_ips: false,
        };
        assert!(p.check("8.8.8.8", 80).is_ok());
    }

    #[test]
    fn whitelist_enforced_when_set() {
        let p = HostPolicy {
            hostname_blacklist: vec![],
            hostname_whitelist: vec!["*.allowed.example".to_owned()],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![],
            allow_direct_ip: true,
            allow_direct_ip_with_domain_policy: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
        };
        assert!(p.check("api.allowed.example", 80).is_ok());
        assert!(matches!(
            p.check("other.example", 80),
            Err(ProxyError::Policy(_))
        ));
    }

    #[test]
    fn policy_blocks_ipv4_mapped_ipv6_loopback_and_private() {
        let p = HostPolicy {
            hostname_blacklist: vec![],
            hostname_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![80],
            allow_direct_ip: true,
            allow_direct_ip_with_domain_policy: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
        };
        assert!(matches!(
            p.check("::ffff:127.0.0.1", 80),
            Err(ProxyError::Policy(_))
        ));
        assert!(matches!(
            p.check("::ffff:10.0.0.1", 80),
            Err(ProxyError::Policy(_))
        ));
        assert!(p.check("::ffff:8.8.8.8", 80).is_ok());
    }

    #[test]
    fn ip_allowlist_supports_cidr() {
        let p = HostPolicy {
            hostname_blacklist: vec![],
            hostname_whitelist: vec![],
            ip_blacklist: vec![],
            ip_whitelist: vec![IpPattern::parse("8.8.8.0/24").unwrap()],
            port_blacklist: vec![],
            port_whitelist: vec![443],
            allow_direct_ip: true,
            allow_direct_ip_with_domain_policy: false,
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
            hostname_blacklist: vec![],
            hostname_whitelist: vec![],
            ip_blacklist: vec![IpPattern::parse("2001:db8::/32").unwrap()],
            ip_whitelist: vec![],
            port_blacklist: vec![],
            port_whitelist: vec![443],
            allow_direct_ip: true,
            allow_direct_ip_with_domain_policy: false,
            allow_private_ips: false,
            allow_loopback_ips: false,
        };
        assert!(matches!(
            p.check("2001:db8::1", 443),
            Err(ProxyError::HostBlocked(_))
        ));
    }
}

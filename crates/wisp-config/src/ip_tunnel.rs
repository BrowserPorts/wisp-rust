//! `[ip_tunnel]`: the relay side of the IP_TUNNEL extension (0xF3).
//!
//! Each tunnel gets a small network of its own: a network namespace whose
//! TUN device holds the gateway of a home-style LAN (by default
//! `192.168.1.0/24` via `.1`, the client at `.100`), joined to the host by a
//! veth pair numbered from `transit_prefix`, with NAT on the way out. Every
//! tunnel can therefore be handed the same addresses. IPv6 is offered only
//! when the relay has a routed prefix (`ipv6_prefix`), from which each tunnel
//! gets its own `/ipv6_tunnel_prefix_len`; without one tunnels are IPv4 only.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{ConfigError, Result, WispServerOptions};

/// How a tunnel flow the destination policy refuses is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelReject {
    /// ICMP administratively prohibited (code 13, ICMPv6 code 1), as a
    /// firewall that rejects.
    #[default]
    Icmp,
    /// A TCP reset for TCP, ICMP for everything else.
    Reset,
    /// Silence.
    Drop,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IpTunnelOptions {
    pub enabled: bool,
    /// The LAN every tunnel sees, as a CIDR.
    pub ipv4_lan: String,
    /// The relay's address on that LAN: the client's default gateway.
    pub ipv4_gateway: String,
    /// The address assigned to the client.
    pub ipv4_client: String,
    /// A routed IPv6 prefix the relay owns. `None` offers IPv4 only.
    pub ipv6_prefix: Option<String>,
    /// Length of the prefix each tunnel gets out of `ipv6_prefix`.
    pub ipv6_tunnel_prefix_len: u8,
    /// IPv4 prefix the per-tunnel veth pairs are numbered from, one /30 each.
    pub transit_prefix: String,
    /// Prefix of the network namespace names (`<prefix>-<id>`). Namespaces
    /// with this prefix left by an earlier run are deleted at startup.
    pub netns_prefix: String,
    /// Interface NAT leaves through. `None` masquerades on any interface
    /// that is not a tunnel's.
    pub egress_interface: Option<String>,
    pub link_mtu: u16,
    pub max_packet: u16,
    pub max_tunnels_per_connection: u16,
    pub max_tunnels_total: u32,
    /// How long a tunnel outlives its connection, waiting to be resumed.
    /// 0 turns resume off.
    pub resume_grace_s: u32,
    pub reject_with: TunnelReject,
    /// Forward ICMP and ICMPv6 echo.
    pub icmp_echo: bool,
    /// Resolvers handed to clients; reachable on port 53 even when they are
    /// private addresses.
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub max_flows_per_tunnel: u32,
    pub max_new_flows_per_tunnel_per_minute: u64,
    pub max_packets_per_tunnel_per_second: u64,
    pub max_bytes_per_tunnel_per_second: u64,
    pub max_packets_per_ip_per_second: u64,
    pub max_bytes_per_ip_per_second: u64,
}

impl Default for IpTunnelOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv4_lan: "192.168.1.0/24".to_owned(),
            ipv4_gateway: "192.168.1.1".to_owned(),
            ipv4_client: "192.168.1.100".to_owned(),
            ipv6_prefix: None,
            ipv6_tunnel_prefix_len: 64,
            transit_prefix: "10.231.0.0/16".to_owned(),
            netns_prefix: "wtun".to_owned(),
            egress_interface: None,
            link_mtu: 1500,
            max_packet: 1500,
            max_tunnels_per_connection: 1,
            max_tunnels_total: 256,
            resume_grace_s: 30,
            reject_with: TunnelReject::Icmp,
            icmp_echo: true,
            dns_servers: Vec::new(),
            dns_search: Vec::new(),
            max_flows_per_tunnel: 4096,
            max_new_flows_per_tunnel_per_minute: 1200,
            max_packets_per_tunnel_per_second: 20_000,
            max_bytes_per_tunnel_per_second: 25 * 1024 * 1024,
            max_packets_per_ip_per_second: 40_000,
            max_bytes_per_ip_per_second: 64 * 1024 * 1024,
        }
    }
}

/// The checked, typed form of [`IpTunnelOptions`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedIpTunnel {
    pub ipv4_lan: (Ipv4Addr, u8),
    pub ipv4_gateway: Ipv4Addr,
    pub ipv4_client: Ipv4Addr,
    pub ipv6_prefix: Option<(Ipv6Addr, u8)>,
    pub ipv6_tunnel_prefix_len: u8,
    pub transit_prefix: (Ipv4Addr, u8),
    pub dns_servers: Vec<IpAddr>,
}

/// Longest search list carried in a DNS_CONFIG capsule.
pub const MAX_DNS_SEARCH_BYTES: usize = 1024;
/// Most resolvers handed to a client.
pub const MAX_DNS_SERVERS: usize = 8;

fn invalid(msg: String) -> ConfigError {
    ConfigError::Validate(format!("ip_tunnel: {msg}"))
}

fn parse_cidr4(field: &str, value: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, len) = value
        .split_once('/')
        .ok_or_else(|| invalid(format!("{field} {value:?} is not an IPv4 CIDR")))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|_| invalid(format!("{field} {value:?} is not an IPv4 CIDR")))?;
    let len: u8 = len
        .parse()
        .ok()
        .filter(|l| *l <= 32)
        .ok_or_else(|| invalid(format!("{field} {value:?} has a bad prefix length")))?;
    Ok((mask4(addr, len), len))
}

fn parse_cidr6(field: &str, value: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, len) = value
        .split_once('/')
        .ok_or_else(|| invalid(format!("{field} {value:?} is not an IPv6 CIDR")))?;
    let addr: Ipv6Addr = addr
        .parse()
        .map_err(|_| invalid(format!("{field} {value:?} is not an IPv6 CIDR")))?;
    let len: u8 = len
        .parse()
        .ok()
        .filter(|l| *l <= 128)
        .ok_or_else(|| invalid(format!("{field} {value:?} has a bad prefix length")))?;
    Ok((mask6(addr, len), len))
}

fn mask4(addr: Ipv4Addr, len: u8) -> Ipv4Addr {
    let m = if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    };
    Ipv4Addr::from(u32::from(addr) & m)
}

fn mask6(addr: Ipv6Addr, len: u8) -> Ipv6Addr {
    let m = if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    };
    Ipv6Addr::from(u128::from(addr) & m)
}

fn in4(net: (Ipv4Addr, u8), ip: Ipv4Addr) -> bool {
    mask4(ip, net.1) == net.0
}

impl IpTunnelOptions {
    /// Parses and checks every field. `base` is the widest destination
    /// policy any connection gets: tunnels cannot honour a name policy, and
    /// they cannot leave through an upstream proxy provider.
    pub fn resolve(&self, base: &WispServerOptions) -> Result<ResolvedIpTunnel> {
        if base.force_proxy {
            return Err(invalid(
                "cannot be enabled with force_proxy: tunnel packets leave through the relay's own NAT"
                    .to_owned(),
            ));
        }
        let lan = parse_cidr4("ipv4_lan", &self.ipv4_lan)?;
        if lan.1 > 30 {
            return Err(invalid("ipv4_lan must hold at least a /30".to_owned()));
        }
        let gateway: Ipv4Addr = self.ipv4_gateway.parse().map_err(|_| {
            invalid(format!(
                "ipv4_gateway {:?} is not an address",
                self.ipv4_gateway
            ))
        })?;
        let client: Ipv4Addr = self.ipv4_client.parse().map_err(|_| {
            invalid(format!(
                "ipv4_client {:?} is not an address",
                self.ipv4_client
            ))
        })?;
        let broadcast = Ipv4Addr::from(u32::from(lan.0) | (u32::MAX >> lan.1));
        for (name, ip) in [("ipv4_gateway", gateway), ("ipv4_client", client)] {
            if !in4(lan, ip) || ip == lan.0 || ip == broadcast {
                return Err(invalid(format!(
                    "{name} {ip} is not a host address of ipv4_lan"
                )));
            }
        }
        if gateway == client {
            return Err(invalid(
                "ipv4_gateway and ipv4_client must differ".to_owned(),
            ));
        }
        let transit = parse_cidr4("transit_prefix", &self.transit_prefix)?;
        if transit.1 > 29 {
            return Err(invalid(
                "transit_prefix must hold at least two /30s".to_owned(),
            ));
        }
        if in4(transit, lan.0) || in4(lan, transit.0) {
            return Err(invalid("transit_prefix and ipv4_lan overlap".to_owned()));
        }
        let ipv6_prefix = match &self.ipv6_prefix {
            Some(p) => {
                let p = parse_cidr6("ipv6_prefix", p)?;
                if self.ipv6_tunnel_prefix_len < p.1 || self.ipv6_tunnel_prefix_len > 120 {
                    return Err(invalid(
                        "ipv6_tunnel_prefix_len must lie between ipv6_prefix's length and 120"
                            .to_owned(),
                    ));
                }
                Some(p)
            }
            None => None,
        };
        if self.link_mtu < 1280 {
            return Err(invalid("link_mtu must be at least 1280".to_owned()));
        }
        if self.max_packet < self.link_mtu {
            return Err(invalid("max_packet must be at least link_mtu".to_owned()));
        }
        if self.max_tunnels_per_connection == 0 || self.max_tunnels_total == 0 {
            return Err(invalid("tunnel limits must be at least 1".to_owned()));
        }
        if self.max_flows_per_tunnel == 0
            || self.max_new_flows_per_tunnel_per_minute == 0
            || self.max_packets_per_tunnel_per_second == 0
            || self.max_bytes_per_tunnel_per_second == 0
            || self.max_packets_per_ip_per_second == 0
            || self.max_bytes_per_ip_per_second == 0
        {
            return Err(invalid(
                "flow and rate limits must be positive (-1 for unlimited)".to_owned(),
            ));
        }
        let prefix = self.netns_prefix.as_str();
        if prefix.is_empty()
            || prefix.len() > 16
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(invalid(
                "netns_prefix must be 1-16 lowercase letters or digits".to_owned(),
            ));
        }
        if let Some(ifname) = &self.egress_interface {
            if ifname.is_empty()
                || ifname.len() > 15
                || !ifname
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err(invalid(format!(
                    "egress_interface {ifname:?} is not an interface name"
                )));
            }
        }
        if self.dns_servers.len() > MAX_DNS_SERVERS {
            return Err(invalid(format!("at most {MAX_DNS_SERVERS} dns_servers")));
        }
        let dns_servers = self
            .dns_servers
            .iter()
            .map(|s| {
                s.parse::<IpAddr>()
                    .map_err(|_| invalid(format!("dns_servers entry {s:?} is not an address")))
            })
            .collect::<Result<Vec<_>>>()?;
        let search_len: usize = self.dns_search.iter().map(|s| s.len() + 1).sum();
        if search_len > MAX_DNS_SEARCH_BYTES
            || self
                .dns_search
                .iter()
                .any(|s| s.is_empty() || s.contains(char::is_whitespace))
        {
            return Err(invalid(
                "dns_search must be names without spaces, 1 KiB in all".to_owned(),
            ));
        }
        if base.domain_whitelist.is_some() {
            tracing::warn!(
                "ip_tunnel: connections whose options carry a domain_whitelist cannot open tunnels: \
                 the relay sees only addresses"
            );
        }
        Ok(ResolvedIpTunnel {
            ipv4_lan: lan,
            ipv4_gateway: gateway,
            ipv4_client: client,
            ipv6_prefix,
            ipv6_tunnel_prefix_len: self.ipv6_tunnel_prefix_len,
            transit_prefix: transit,
            dns_servers,
        })
    }
}

/// `[ip_tunnel]` as written in the TOML file. Rate limits accept `-1` for
/// unlimited, like the `[wisp.limits]` table.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpTunnelToml {
    pub enabled: Option<bool>,
    pub ipv4_lan: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv4_client: Option<String>,
    pub ipv6_prefix: Option<String>,
    pub ipv6_tunnel_prefix_len: Option<u8>,
    pub transit_prefix: Option<String>,
    pub netns_prefix: Option<String>,
    pub egress_interface: Option<String>,
    pub link_mtu: Option<u16>,
    pub max_packet: Option<u16>,
    pub max_tunnels_per_connection: Option<u16>,
    pub max_tunnels_total: Option<u32>,
    pub resume_grace_s: Option<u32>,
    pub reject_with: Option<TunnelReject>,
    pub icmp_echo: Option<bool>,
    pub dns_servers: Option<Vec<String>>,
    pub dns_search: Option<Vec<String>>,
    pub max_flows_per_tunnel: Option<u32>,
    pub max_new_flows_per_tunnel_per_minute: Option<crate::Limit>,
    pub max_packets_per_tunnel_per_second: Option<crate::Limit>,
    pub max_bytes_per_tunnel_per_second: Option<crate::Limit>,
    pub max_packets_per_ip_per_second: Option<crate::Limit>,
    pub max_bytes_per_ip_per_second: Option<crate::Limit>,
}

impl IpTunnelToml {
    pub(crate) fn merge_into(&self, out: &mut IpTunnelOptions) {
        macro_rules! set {
            ($($field:ident),*) => {$(
                if let Some(v) = &self.$field {
                    out.$field = v.clone();
                }
            )*};
        }
        set!(
            enabled,
            ipv4_lan,
            ipv4_gateway,
            ipv4_client,
            ipv6_tunnel_prefix_len,
            transit_prefix,
            netns_prefix,
            link_mtu,
            max_packet,
            max_tunnels_per_connection,
            max_tunnels_total,
            resume_grace_s,
            reject_with,
            icmp_echo,
            dns_servers,
            dns_search,
            max_flows_per_tunnel
        );
        if let Some(v) = &self.ipv6_prefix {
            out.ipv6_prefix = Some(v.clone());
        }
        if let Some(v) = &self.egress_interface {
            out.egress_interface = Some(v.clone());
        }
        macro_rules! limit {
            ($($field:ident),*) => {$(
                if let Some(v) = self.$field {
                    out.$field = v.to_sentinel();
                }
            )*};
        }
        limit!(
            max_new_flows_per_tunnel_per_minute,
            max_packets_per_tunnel_per_second,
            max_bytes_per_tunnel_per_second,
            max_packets_per_ip_per_second,
            max_bytes_per_ip_per_second
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(edit: impl FnOnce(&mut IpTunnelOptions)) -> Result<ResolvedIpTunnel> {
        let mut o = IpTunnelOptions {
            enabled: true,
            ..IpTunnelOptions::default()
        };
        edit(&mut o);
        o.resolve(&WispServerOptions::default())
    }

    #[test]
    fn defaults_resolve_to_the_reference_lan() {
        let r = resolve(|_| {}).unwrap();
        assert_eq!(r.ipv4_lan, (Ipv4Addr::new(192, 168, 1, 0), 24));
        assert_eq!(r.ipv4_gateway, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(r.ipv4_client, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(r.ipv6_prefix, None);
    }

    #[test]
    fn rejects_bad_addressing() {
        assert!(resolve(|o| o.ipv4_client = "192.168.2.100".into()).is_err());
        assert!(resolve(|o| o.ipv4_client = "192.168.1.255".into()).is_err());
        assert!(resolve(|o| o.ipv4_gateway = "192.168.1.100".into()).is_err());
        assert!(resolve(|o| o.ipv4_lan = "192.168.1.0/31".into()).is_err());
        assert!(resolve(|o| o.transit_prefix = "192.168.0.0/16".into()).is_err());
        assert!(resolve(|o| o.ipv6_prefix = Some("2001:db8::/48".into())).is_ok());
        assert!(resolve(|o| {
            o.ipv6_prefix = Some("2001:db8::/64".into());
            o.ipv6_tunnel_prefix_len = 56;
        })
        .is_err());
        assert!(resolve(|o| o.link_mtu = 1200).is_err());
        assert!(resolve(|o| o.max_packet = 1400).is_err());
        assert!(resolve(|o| o.netns_prefix = "Bad Prefix".into()).is_err());
        assert!(resolve(|o| o.dns_servers = vec!["resolver".into()]).is_err());
        assert!(resolve(|o| o.dns_search = vec!["a b".into()]).is_err());
    }

    #[test]
    fn refuses_force_proxy() {
        let o = IpTunnelOptions {
            enabled: true,
            ..IpTunnelOptions::default()
        };
        let base = WispServerOptions {
            force_proxy: true,
            ..WispServerOptions::default()
        };
        assert!(o.resolve(&base).is_err());
    }
}

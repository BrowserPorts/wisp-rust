//! The tunnel engine's settings, resolved once from `[ip_tunnel]` and the
//! base destination options.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use wisp_config::{ConfigError, IpTunnelOptions, TunnelReject, WispServerOptions};
use wisp_dos::TunnelLimits;
use wisp_ip::info::flags;
use wisp_ip::{Prefix, ServerInfo};

/// Which transport a tunnel rides; it decides the datagram flags the server
/// offers and the LINK capsule's datagram size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// Wisp v2 over WebSocket: one DATA per packet, reliable.
    WebSocket,
    /// wisp-wt: datagrams with fragments when both sides set DATAGRAMS,
    /// else one uni stream per tunnel and direction.
    WebTransport,
}

/// The static part of the relay's own nftables rules, from the widest
/// destination policy any connection gets (a credential only narrows it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backstop {
    pub block_private: bool,
    pub block_loopback: bool,
    /// Address and CIDR entries of the base `ip_blacklist`.
    pub blacklist: Vec<Prefix>,
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// The LAN every tunnel sees (on-link for the client).
    pub lan: Prefix,
    pub gateway4: Ipv4Addr,
    pub client4: Ipv4Addr,
    /// Routed IPv6 pool and the length of each tunnel's share of it.
    pub ipv6_pool: Option<(Ipv6Addr, u8)>,
    pub ipv6_tunnel_len: u8,
    /// Numbering of the per-tunnel veth pairs, one /30 each.
    pub transit: (Ipv4Addr, u8),
    pub netns_prefix: String,
    pub egress_interface: Option<String>,
    pub link_mtu: u16,
    pub max_packet: u16,
    pub max_tunnels_per_connection: u16,
    pub max_tunnels_total: u32,
    /// Zero turns resume off.
    pub resume_grace: Duration,
    pub reject: TunnelReject,
    pub icmp_echo: bool,
    pub dns_servers: Vec<IpAddr>,
    /// Search names separated by one space, as DNS_CONFIG carries them.
    pub dns_search: String,
    pub max_flows: u32,
    pub limits: TunnelLimits,
    pub backstop: Backstop,
}

/// Link-local address of the IPv6 gateway on every tunnel's link.
pub const IPV6_GATEWAY_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

/// Route metric of the default routes handed to clients.
pub const DEFAULT_ROUTE_METRIC: u32 = 100;

impl TunnelConfig {
    pub fn from_options(
        options: &IpTunnelOptions,
        base: &WispServerOptions,
    ) -> Result<Self, ConfigError> {
        let r = options.resolve(base)?;
        let lan = Prefix::new(IpAddr::V4(r.ipv4_lan.0), r.ipv4_lan.1)
            .expect("resolve checked the length");
        let blacklist = base
            .ip_blacklist
            .iter()
            .flatten()
            .filter_map(|entry| parse_prefix(entry))
            .collect();
        Ok(Self {
            lan,
            gateway4: r.ipv4_gateway,
            client4: r.ipv4_client,
            ipv6_pool: r.ipv6_prefix,
            ipv6_tunnel_len: r.ipv6_tunnel_prefix_len,
            transit: r.transit_prefix,
            netns_prefix: options.netns_prefix.clone(),
            egress_interface: options.egress_interface.clone(),
            link_mtu: options.link_mtu,
            max_packet: options.max_packet,
            max_tunnels_per_connection: options.max_tunnels_per_connection,
            max_tunnels_total: options.max_tunnels_total,
            resume_grace: Duration::from_secs(u64::from(options.resume_grace_s)),
            reject: options.reject_with,
            icmp_echo: options.icmp_echo,
            dns_servers: r.dns_servers,
            dns_search: options.dns_search.join(" "),
            max_flows: options.max_flows_per_tunnel,
            limits: TunnelLimits {
                packets_per_tunnel_per_second: options.max_packets_per_tunnel_per_second,
                bytes_per_tunnel_per_second: options.max_bytes_per_tunnel_per_second,
                packets_per_ip_per_second: options.max_packets_per_ip_per_second,
                bytes_per_ip_per_second: options.max_bytes_per_ip_per_second,
                new_flows_per_tunnel_per_minute: options.max_new_flows_per_tunnel_per_minute,
            },
            backstop: Backstop {
                block_private: !base.allow_private_ips,
                block_loopback: !base.allow_loopback_ips,
                blacklist,
            },
        })
    }

    pub fn resume_enabled(&self) -> bool {
        !self.resume_grace.is_zero()
    }

    /// The server's INFO entry for `binding`.
    pub fn server_info(&self, binding: Binding) -> ServerInfo {
        let mut f = flags::IPV4;
        if self.ipv6_pool.is_some() {
            f |= flags::IPV6;
        }
        if binding == Binding::WebTransport {
            f |= flags::DATAGRAMS | flags::FRAGMENTS;
        }
        if self.resume_enabled() {
            f |= flags::RESUME;
        }
        if self.icmp_echo {
            f |= flags::ICMP_ECHO;
        }
        ServerInfo::v1(
            f,
            self.max_tunnels_per_connection,
            self.link_mtu,
            self.max_packet,
        )
    }
}

/// `a.b.c.d`, `a.b.c.d/n` and the IPv6 forms; ranges are left to the
/// per-flow policy.
fn parse_prefix(entry: &str) -> Option<Prefix> {
    let entry = entry.trim();
    match entry.split_once('/') {
        Some((addr, len)) => Prefix::new(addr.parse().ok()?, len.parse().ok()?),
        None => entry.parse().ok().map(Prefix::host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> IpTunnelOptions {
        IpTunnelOptions {
            enabled: true,
            ..IpTunnelOptions::default()
        }
    }

    #[test]
    fn server_info_follows_the_options() {
        let cfg = TunnelConfig::from_options(&enabled(), &WispServerOptions::default()).unwrap();
        let ws = cfg.server_info(Binding::WebSocket);
        assert_eq!(ws.flags, flags::IPV4 | flags::RESUME | flags::ICMP_ECHO);
        let wt = cfg.server_info(Binding::WebTransport);
        assert!(wt.flags & flags::DATAGRAMS != 0 && wt.flags & flags::FRAGMENTS != 0);
        assert_eq!(
            (wt.link_mtu, wt.max_packet, wt.max_tunnels),
            (1500, 1500, 1)
        );

        let mut v6 = enabled();
        v6.ipv6_prefix = Some("2001:db8:42::/48".to_owned());
        v6.resume_grace_s = 0;
        v6.icmp_echo = false;
        let cfg = TunnelConfig::from_options(&v6, &WispServerOptions::default()).unwrap();
        assert_eq!(
            cfg.server_info(Binding::WebSocket).flags,
            flags::IPV4 | flags::IPV6
        );
    }

    #[test]
    fn backstop_takes_the_base_blacklist() {
        let base = WispServerOptions {
            ip_blacklist: Some(vec![
                "5.188.124.21/32".to_owned(),
                "9.9.9.9".to_owned(),
                "1.1.1.1-1.1.1.9".to_owned(),
            ]),
            allow_private_ips: true,
            ..WispServerOptions::default()
        };
        let cfg = TunnelConfig::from_options(&enabled(), &base).unwrap();
        assert_eq!(cfg.backstop.blacklist.len(), 2);
        assert!(!cfg.backstop.block_private);
        assert!(cfg.backstop.block_loopback);
    }
}

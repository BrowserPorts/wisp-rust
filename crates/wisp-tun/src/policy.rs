//! What a tunnel lets out: the checks on the first packet of a new flow.

use std::net::IpAddr;

use wisp_ip::packet::{proto, PacketInfo};
use wisp_proxy::HostPolicy;

use crate::config::TunnelConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Start the flow.
    Forward,
    /// The destination policy refuses it: answer as configured.
    Refuse(&'static str),
    /// Never forwarded and never answered.
    Drop(&'static str),
}

/// Destinations a router never forwards off the link: unspecified,
/// broadcast, multicast and link-local addresses.
pub fn never_forwarded(dst: IpAddr) -> bool {
    match dst {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.is_loopback()
        }
    }
}

/// Neighbour discovery and router discovery (ICMPv6 133-137) and MLD never
/// cross the relay; the client's own virtual router answers them.
fn is_link_control(info: &PacketInfo) -> bool {
    info.protocol == proto::ICMPV6 && matches!(info.icmp_type, 130..=137 | 143)
}

/// The verdict on the first packet of a flow the client starts.
/// `to_gateway` says the destination is one of the gateway's own addresses,
/// which answers echo as a home router does and nothing else.
pub fn new_flow(
    cfg: &TunnelConfig,
    policy: &HostPolicy,
    info: &PacketInfo,
    to_gateway: bool,
) -> Verdict {
    if to_gateway && info.is_echo_request() && cfg.icmp_echo {
        return Verdict::Forward;
    }
    if never_forwarded(info.dst) || is_link_control(info) {
        return Verdict::Drop("link-local or multicast destination");
    }
    match info.protocol {
        proto::TCP | proto::UDP => {
            let udp = info.protocol == proto::UDP;
            // The resolvers handed out in DNS_CONFIG are the tunnel's own
            // DHCP-style resolvers, reachable even when they are private.
            if info.dst_port == 53 && cfg.dns_servers.contains(&info.dst) {
                return Verdict::Forward;
            }
            match policy.check_addr_port(info.dst, info.dst_port, udp) {
                Ok(()) => Verdict::Forward,
                Err(_) => Verdict::Refuse("destination policy"),
            }
        }
        proto::ICMP | proto::ICMPV6 if info.is_echo_request() => {
            if !cfg.icmp_echo {
                return Verdict::Drop("ICMP echo not offered");
            }
            match policy.check_ip(info.dst) {
                Ok(()) => Verdict::Forward,
                Err(_) => Verdict::Refuse("destination policy"),
            }
        }
        proto::ICMP | proto::ICMPV6 => Verdict::Drop("ICMP without a flow"),
        _ => Verdict::Drop("protocol not forwarded"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_config::{IpTunnelOptions, WispServerOptions};
    use wisp_ip::packet::Fragment;

    fn cfg(edit: impl FnOnce(&mut IpTunnelOptions)) -> TunnelConfig {
        let mut o = IpTunnelOptions {
            enabled: true,
            dns_servers: vec!["10.0.0.53".to_owned()],
            ..IpTunnelOptions::default()
        };
        edit(&mut o);
        TunnelConfig::from_options(&o, &WispServerOptions::default()).unwrap()
    }

    fn packet(protocol: u8, dst: &str, port: u16) -> PacketInfo {
        PacketInfo {
            src: "192.168.1.100".parse().unwrap(),
            dst: dst.parse().unwrap(),
            protocol,
            ttl: 64,
            transport_offset: 20,
            fragment: Fragment::None,
            src_port: 40000,
            dst_port: port,
            icmp_type: if protocol == proto::ICMP { 8 } else { 0 },
            icmp_code: 0,
            tcp_flags: 0,
            quoted: None,
        }
    }

    fn policy() -> HostPolicy {
        HostPolicy::from_options(&WispServerOptions::default())
    }

    fn new_flow_t(c: &TunnelConfig, p: &HostPolicy, i: &PacketInfo) -> Verdict {
        new_flow(c, p, i, false)
    }

    #[test]
    fn the_gateway_answers_echo_only() {
        let c = cfg(|_| {});
        assert_eq!(
            new_flow(&c, &policy(), &packet(proto::ICMP, "192.168.1.1", 0), true),
            Verdict::Forward
        );
        assert!(matches!(
            new_flow(&c, &policy(), &packet(proto::TCP, "192.168.1.1", 80), true),
            Verdict::Refuse(_)
        ));
    }

    #[test]
    fn public_destinations_on_allowed_ports_pass() {
        let c = cfg(|_| {});
        assert_eq!(
            new_flow_t(&c, &policy(), &packet(proto::TCP, "93.184.216.34", 443)),
            Verdict::Forward
        );
        assert!(matches!(
            new_flow_t(&c, &policy(), &packet(proto::TCP, "93.184.216.34", 25)),
            Verdict::Refuse(_)
        ));
    }

    #[test]
    fn private_loopback_and_metadata_are_refused() {
        let c = cfg(|_| {});
        for dst in ["10.1.2.3", "127.0.0.1", "192.168.1.1", "100.64.0.1"] {
            assert!(
                matches!(
                    new_flow_t(&c, &policy(), &packet(proto::TCP, dst, 443)),
                    Verdict::Refuse(_)
                ),
                "{dst}"
            );
        }
        // Link-local, metadata included, is never forwarded at all.
        assert!(matches!(
            new_flow_t(&c, &policy(), &packet(proto::TCP, "169.254.169.254", 80)),
            Verdict::Drop(_)
        ));
        assert!(matches!(
            new_flow_t(&c, &policy(), &packet(proto::UDP, "224.0.0.251", 5353)),
            Verdict::Drop(_)
        ));
    }

    #[test]
    fn handed_out_resolvers_are_reachable_on_port_53() {
        let c = cfg(|_| {});
        assert_eq!(
            new_flow_t(&c, &policy(), &packet(proto::UDP, "10.0.0.53", 53)),
            Verdict::Forward
        );
        assert!(matches!(
            new_flow_t(&c, &policy(), &packet(proto::UDP, "10.0.0.53", 443)),
            Verdict::Refuse(_)
        ));
    }

    #[test]
    fn echo_follows_the_option_and_other_protocols_drop() {
        assert_eq!(
            new_flow_t(&cfg(|_| {}), &policy(), &packet(proto::ICMP, "1.1.1.1", 7)),
            Verdict::Forward
        );
        assert!(matches!(
            new_flow_t(
                &cfg(|o| o.icmp_echo = false),
                &policy(),
                &packet(proto::ICMP, "1.1.1.1", 7)
            ),
            Verdict::Drop(_)
        ));
        assert!(matches!(
            new_flow_t(&cfg(|_| {}), &policy(), &packet(47, "1.1.1.1", 0)),
            Verdict::Drop(_)
        ));
    }
}

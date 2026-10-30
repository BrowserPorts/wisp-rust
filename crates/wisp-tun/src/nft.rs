//! nftables rules of the namespace backend, as text for `nft -f -`.
//!
//! Two tables. The relay's own namespace gets `inet wisp_tun`: masquerade
//! for the transit prefix, no packet from one tunnel's veth to another's, no
//! connection into a tunnel that it did not start, and no packet from a
//! tunnel to the relay itself. Each tunnel's namespace gets `inet wisp`: the
//! static backstop behind the per-flow policy (only the tunnel's own source
//! addresses, no private, loopback, transit or blacklisted destination, a cap
//! on live connections) and masquerade of the LAN onto the transit address.
//! The rules are generated, never read back, and kept free of anything a
//! client sends.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use wisp_config::TunnelReject;

use crate::backend::NetworkPlan;
use crate::config::TunnelConfig;

/// Name pattern of the host side of every tunnel's veth pair.
pub const HOST_VETH_PATTERN: &str = "wtv*";
/// The tunnel namespace's interface towards the host.
pub const NS_UPLINK: &str = "eth0";
/// The tunnel namespace's TUN device.
pub const NS_TUN: &str = "tun0";

/// Addresses no tunnel reaches when private destinations are blocked; the
/// same ranges `wisp-proxy` treats as private.
const PRIVATE4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
];
const LOOPBACK4: &[&str] = &["127.0.0.0/8"];
/// Everything outside global unicast 2000::/3, and documentation space.
const PRIVATE6: &[&str] = &["::/3", "4000::/2", "8000::/1", "2001:db8::/32", "100::/64"];
const LOOPBACK6: &[&str] = &["::1/128"];

fn set_elements(entries: &[String]) -> String {
    entries.join(", ")
}

/// The relay namespace's table.
pub fn host_ruleset(cfg: &TunnelConfig) -> String {
    let (transit, len) = cfg.transit;
    let masquerade = match &cfg.egress_interface {
        Some(ifname) => format!("ip saddr {transit}/{len} oifname \"{ifname}\" masquerade"),
        None => format!("ip saddr {transit}/{len} oifname != \"{HOST_VETH_PATTERN}\" masquerade"),
    };
    format!(
        "table inet wisp_tun
delete table inet wisp_tun
table inet wisp_tun {{
\tchain forward {{
\t\ttype filter hook forward priority filter - 1; policy accept;
\t\tiifname \"{v}\" oifname \"{v}\" drop
\t\toifname \"{v}\" ct state established,related accept
\t\toifname \"{v}\" drop
\t}}
\tchain input {{
\t\ttype filter hook input priority filter - 1; policy accept;
\t\tiifname \"{v}\" ct state established,related accept
\t\tiifname \"{v}\" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept
\t\tiifname \"{v}\" drop
\t}}
\tchain postrouting {{
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\t{masquerade}
\t}}
}}
",
        v = HOST_VETH_PATTERN,
    )
}

fn reject_rules(cfg: &TunnelConfig, matcher: &str, out: &mut String) {
    match cfg.reject {
        TunnelReject::Icmp => {
            let _ = writeln!(out, "\t\t{matcher} reject with icmpx type admin-prohibited");
        }
        TunnelReject::Reset => {
            let _ = writeln!(out, "\t\t{matcher} meta l4proto tcp reject with tcp reset");
            let _ = writeln!(out, "\t\t{matcher} reject with icmpx type admin-prohibited");
        }
        TunnelReject::Drop => {
            let _ = writeln!(out, "\t\t{matcher} drop");
        }
    }
}

/// The table of one tunnel's namespace.
pub fn tunnel_ruleset(cfg: &TunnelConfig, plan: &NetworkPlan) -> String {
    let b = &cfg.backstop;
    let mut blocked4: Vec<String> = Vec::new();
    let mut blocked6: Vec<String> = Vec::new();
    if b.block_private {
        blocked4.extend(PRIVATE4.iter().map(|s| s.to_string()));
        blocked6.extend(PRIVATE6.iter().map(|s| s.to_string()));
    } else {
        // Link-local, cloud metadata included, is never forwarded.
        blocked4.push("169.254.0.0/16".to_owned());
        blocked6.push("fe80::/10".to_owned());
    }
    if b.block_loopback {
        blocked4.extend(LOOPBACK4.iter().map(|s| s.to_string()));
        blocked6.extend(LOOPBACK6.iter().map(|s| s.to_string()));
    }
    blocked4.push(format!("{}/{}", cfg.transit.0, cfg.transit.1));
    for p in &b.blacklist {
        let entry = format!("{}/{}", p.network(), p.len());
        match p.addr() {
            IpAddr::V4(_) => blocked4.push(entry),
            IpAddr::V6(_) => blocked6.push(entry),
        }
    }
    let dns4: Vec<String> = plan
        .dns_servers
        .iter()
        .filter(|a| a.is_ipv4())
        .map(|a| a.to_string())
        .collect();
    let dns6: Vec<String> = plan
        .dns_servers
        .iter()
        .filter(|a| a.is_ipv6())
        .map(|a| a.to_string())
        .collect();

    let (lan, lan_len) = plan.lan;
    let mut out = String::new();
    out.push_str("table inet wisp\ndelete table inet wisp\ntable inet wisp {\n");
    let _ = writeln!(
        out,
        "\tset blocked4 {{\n\t\ttype ipv4_addr; flags interval; auto-merge;\n\t\telements = {{ {} }}\n\t}}",
        set_elements(&blocked4)
    );
    let _ = writeln!(
        out,
        "\tset blocked6 {{\n\t\ttype ipv6_addr; flags interval; auto-merge;\n\t\telements = {{ {} }}\n\t}}",
        set_elements(&blocked6)
    );
    let _ = writeln!(
        out,
        "\tchain forward {{\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state invalid drop\n\t\tiifname \"{NS_UPLINK}\" oifname \"{NS_TUN}\" ct state established,related accept\n\t\tiifname \"{NS_TUN}\" oifname \"{NS_UPLINK}\" jump outbound\n\t}}"
    );
    out.push_str("\tchain outbound {\n");
    let _ = writeln!(out, "\t\tip saddr != {lan}/{lan_len} drop");
    let _ = writeln!(out, "\t\tip saddr {} drop", plan.gateway4);
    match (plan.ipv6, plan.gateway6()) {
        (Some((p, len)), Some(gw)) => {
            let _ = writeln!(out, "\t\tip6 saddr != {p}/{len} drop");
            let _ = writeln!(out, "\t\tip6 saddr {{ {p}, {gw} }} drop");
        }
        _ => out.push_str("\t\tmeta nfproto ipv6 drop\n"),
    }
    if !dns4.is_empty() {
        let _ = writeln!(
            out,
            "\t\tip daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept",
            dns4.join(", ")
        );
    }
    if !dns6.is_empty() {
        let _ = writeln!(
            out,
            "\t\tip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept",
            dns6.join(", ")
        );
    }
    reject_rules(cfg, "ip daddr @blocked4", &mut out);
    reject_rules(cfg, "ip6 daddr @blocked6", &mut out);
    let _ = writeln!(
        out,
        "\t\tct state new ct count over {} drop",
        plan.max_flows
    );
    out.push_str("\t\taccept\n\t}\n");
    let _ = writeln!(
        out,
        "\tchain input {{\n\t\ttype filter hook input priority filter; policy drop;\n\t\tiif \"lo\" accept\n\t\tct state established,related accept\n\t\tiifname \"{NS_TUN}\" icmp type echo-request accept\n\t\ticmpv6 type {{ echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept\n\t}}"
    );
    let _ = writeln!(
        out,
        "\tchain postrouting {{\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname \"{NS_UPLINK}\" ip saddr {lan}/{lan_len} masquerade\n\t}}"
    );
    out.push_str("}\n");
    out
}

/// The /30 of transit slot `slot`: the host side takes `.1`, the namespace
/// side `.2`.
pub fn transit_pair(transit: (Ipv4Addr, u8), slot: u32) -> (Ipv4Addr, Ipv4Addr) {
    let base = u32::from(transit.0) + slot * 4;
    (Ipv4Addr::from(base + 1), Ipv4Addr::from(base + 2))
}

/// Transit slots a prefix holds.
pub fn transit_slots(transit: (Ipv4Addr, u8)) -> u32 {
    1u32 << (30 - u32::from(transit.1.min(30)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_config::{IpTunnelOptions, WispServerOptions};

    fn cfg(edit: impl FnOnce(&mut IpTunnelOptions)) -> TunnelConfig {
        let mut o = IpTunnelOptions {
            enabled: true,
            dns_servers: vec!["1.1.1.1".to_owned()],
            ..IpTunnelOptions::default()
        };
        edit(&mut o);
        let base = WispServerOptions {
            ip_blacklist: Some(vec!["5.188.124.21/32".to_owned()]),
            ..WispServerOptions::default()
        };
        TunnelConfig::from_options(&o, &base).unwrap()
    }

    fn plan(cfg: &TunnelConfig, v6: bool) -> NetworkPlan {
        NetworkPlan {
            id: 7,
            lan: (Ipv4Addr::new(192, 168, 1, 0), 24),
            gateway4: cfg.gateway4,
            client4: cfg.client4,
            ipv6: v6.then(|| ("2001:db8:42:7::".parse().unwrap(), 64)),
            link_mtu: 1500,
            max_packet: 1500,
            max_flows: 4096,
            dns_servers: cfg.dns_servers.clone(),
        }
    }

    #[test]
    fn tunnel_rules_hold_the_backstop() {
        let c = cfg(|_| {});
        let rules = tunnel_ruleset(&c, &plan(&c, false));
        assert!(rules.contains("10.0.0.0/8"));
        assert!(rules.contains("127.0.0.0/8"));
        assert!(
            rules.contains("10.231.0.0/16"),
            "other tunnels and the host"
        );
        assert!(rules.contains("5.188.124.21/32"), "the base blacklist");
        assert!(rules.contains("ip saddr != 192.168.1.0/24 drop"));
        assert!(rules.contains("meta nfproto ipv6 drop"));
        assert!(rules.contains("ip daddr { 1.1.1.1 } meta l4proto { tcp, udp } th dport 53 accept"));
        assert!(rules.contains("reject with icmpx type admin-prohibited"));
        assert!(rules.contains("ct state new ct count over 4096 drop"));
        assert!(rules.contains("oifname \"eth0\" ip saddr 192.168.1.0/24 masquerade"));
        assert!(rules.contains("ct state established,related accept"));
        // DNS before the blocked sets, the cap last.
        let dns = rules.find("th dport 53").unwrap();
        let blocked = rules.find("@blocked4 reject").unwrap();
        let cap = rules.find("ct count").unwrap();
        assert!(dns < blocked && blocked < cap);
    }

    #[test]
    fn tunnel_rules_for_ipv6_and_other_rejects() {
        let c = cfg(|o| o.reject_with = TunnelReject::Reset);
        let rules = tunnel_ruleset(&c, &plan(&c, true));
        assert!(rules.contains("ip6 saddr != 2001:db8:42:7::/64 drop"));
        assert!(rules.contains("ip6 saddr { 2001:db8:42:7::, 2001:db8:42:7::1 } drop"));
        assert!(rules.contains("reject with tcp reset"));
        let c = cfg(|o| o.reject_with = TunnelReject::Drop);
        let rules = tunnel_ruleset(&c, &plan(&c, false));
        assert!(rules.contains("ip daddr @blocked4 drop"));
        assert!(!rules.contains("reject"));
    }

    #[test]
    fn host_rules_isolate_tunnels() {
        let c = cfg(|_| {});
        let rules = host_ruleset(&c);
        assert!(rules.starts_with("table inet wisp_tun\ndelete table inet wisp_tun\n"));
        assert!(rules.contains("iifname \"wtv*\" oifname \"wtv*\" drop"));
        assert!(rules.contains("oifname \"wtv*\" drop"));
        assert!(rules.contains("ip saddr 10.231.0.0/16 oifname != \"wtv*\" masquerade"));
        let c = cfg(|o| o.egress_interface = Some("ens5".to_owned()));
        assert!(host_ruleset(&c).contains("oifname \"ens5\" masquerade"));
    }

    #[test]
    fn transit_numbering() {
        let t = (Ipv4Addr::new(10, 231, 0, 0), 16);
        assert_eq!(
            transit_pair(t, 0),
            (Ipv4Addr::new(10, 231, 0, 1), Ipv4Addr::new(10, 231, 0, 2))
        );
        assert_eq!(
            transit_pair(t, 65),
            (Ipv4Addr::new(10, 231, 1, 5), Ipv4Addr::new(10, 231, 1, 6))
        );
        assert_eq!(transit_slots(t), 16384);
    }
}

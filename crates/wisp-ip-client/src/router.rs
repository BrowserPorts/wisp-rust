//! The virtual router: the gateway the machine's kernel sees on `eth0`.
//!
//! The relay's tunnel network holds the real gateway (192.168.1.1 on the
//! tunnel namespace's TUN, LS-5) and does the routing: TTL, ICMP errors,
//! NAT. What it cannot do is answer on the machine's Ethernet link, since
//! only IP packets cross the tunnel. This router stands in for the
//! gateway's link layer:
//!
//! - **ARP.** It answers requests for the gateway's IPv4 address with its
//!   own Ethernet address, and nothing else: another address on the LAN has
//!   no host behind it, as on a home network with one machine.
//! - **Neighbour discovery.** It answers neighbour solicitations for the
//!   gateway's link-local address (`fe80::1`, from the relay's route) and
//!   for the gateway's global address.
//! - **Router advertisements**, only when the relay routes an IPv6 prefix to
//!   the tunnel (decision LD3b): on start, every `ra_interval_ms`, and in
//!   answer to a router solicitation. The machine's own kernel then forms
//!   its addresses by SLAAC and takes its default route, as a Debian host
//!   behind a home router does. Without a routed prefix it stays silent,
//!   and the machine is IPv4-only with a link-local address, as on an
//!   IPv4-only network.
//! - **Everything else for the gateway's Ethernet address** is an IP packet
//!   for the tunnel, cut to its header's length. Broadcast, multicast and
//!   link-local traffic never crosses (section 7 rule 4): the relay would
//!   drop it, and a router does not forward it.
//!
//! Packets from the tunnel go to the machine's Ethernet address, from the
//! gateway's. The router does not decrement TTL: the relay's namespace is the
//! hop.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ether::{
    self, build_arp, build_frame, build_icmpv6, build_na, build_ra, ethertype, icmpv6,
    is_ipv6_link_local, is_multicast, na_flags, nd_options, ns_target, parse_arp, parse_frame,
    parse_icmpv6, Advertisement, Arp, Mac, ALL_NODES, ARP_REPLY, ARP_REQUEST, BROADCAST,
};
use crate::manager::LinkConfig;

/// The gateway's link-local address when the relay's route names none.
pub const DEFAULT_GATEWAY_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

/// RFC 4861's `MIN_DELAY_BETWEEN_RAS`.
pub const MIN_DELAY_BETWEEN_RAS_MS: u64 = 3_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterConfig {
    /// The gateway's Ethernet address. The machine config should give one
    /// with a router vendor's prefix, as a real home router has.
    pub gateway_mac: Mac,
    /// The machine's `eth0` address. Learnt from the first frame when not
    /// given.
    pub host_mac: Option<Mac>,
    /// `AdvDefaultLifetime`: how long a router advertisement keeps the
    /// machine's default route.
    pub router_lifetime_s: u16,
    /// Interval of unsolicited router advertisements.
    pub ra_interval_ms: u64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            gateway_mac: [0x02, 0x57, 0x49, 0x50, 0x54, 0x01],
            host_mac: None,
            router_lifetime_s: 1800,
            ra_interval_ms: 200_000,
        }
    }
}

/// Why a frame from the machine went nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Not an Ethernet II frame, or a malformed packet inside one.
    Malformed,
    /// For another Ethernet address.
    NotForGateway,
    /// ARP for an address other than the gateway's, or not a request.
    Arp,
    /// Neighbour discovery the router does not answer (DAD, other targets,
    /// advertisements from the host, MLD).
    NeighbourDiscovery,
    /// Broadcast, multicast or link-local: never routed.
    LinkLocal,
    /// No tunnel configuration for this family yet.
    Unconfigured,
    /// Neither IPv4, IPv6 nor ARP.
    Protocol(u16),
}

/// What the router made of one frame from the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromWire {
    /// An IP packet for the tunnel.
    Forward(Vec<u8>),
    /// A frame back to the machine (ARP reply, NA, RA, echo reply).
    Reply(Vec<u8>),
    Drop(DropReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct V6 {
    prefix: Ipv6Addr,
    prefix_len: u8,
    valid_s: u32,
    preferred_s: u32,
    gateway_ll: Ipv6Addr,
    gateway_global: Option<Ipv6Addr>,
    dns: Vec<Ipv6Addr>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RouterStats {
    pub arp_replies: u64,
    pub neighbour_advertisements: u64,
    pub router_advertisements: u64,
    pub forwarded: u64,
    pub delivered: u64,
    pub dropped: u64,
}

pub struct Router {
    cfg: RouterConfig,
    host_mac: Option<Mac>,
    gateway4: Option<Ipv4Addr>,
    lan4: Option<(Ipv4Addr, u8)>,
    v6: Option<V6>,
    link_mtu: u16,
    next_ra_ms: Option<u64>,
    last_ra_ms: Option<u64>,
    pending: VecDeque<Vec<u8>>,
    stats: RouterStats,
}

impl Router {
    pub fn new(cfg: RouterConfig) -> Self {
        Self {
            cfg,
            host_mac: cfg.host_mac,
            gateway4: None,
            lan4: None,
            v6: None,
            link_mtu: 1500,
            next_ra_ms: None,
            last_ra_ms: None,
            pending: VecDeque::new(),
            stats: RouterStats::default(),
        }
    }

    pub fn stats(&self) -> RouterStats {
        self.stats
    }

    pub fn host_mac(&self) -> Option<Mac> {
        self.host_mac
    }

    pub fn gateway_mac(&self) -> Mac {
        self.cfg.gateway_mac
    }

    /// Whether router advertisements are being sent.
    pub fn advertises_ipv6(&self) -> bool {
        self.v6.is_some()
    }

    /// Takes the tunnel's configuration. A routed IPv6 prefix starts router
    /// advertisements at once.
    pub fn configure(&mut self, cfg: &LinkConfig, now_ms: u64) {
        self.link_mtu = cfg.link.link_mtu;
        self.gateway4 = cfg.gateway4();
        self.lan4 = cfg.ipv4().map(|a| match a.prefix.addr() {
            IpAddr::V4(v4) => (v4, a.prefix.len()),
            IpAddr::V6(_) => unreachable!("ipv4() returns IPv4"),
        });
        let v6 = cfg.ipv6().map(|a| {
            let IpAddr::V6(addr) = a.prefix.addr() else {
                unreachable!("ipv6() returns IPv6")
            };
            let gw = cfg.gateway6();
            let len = a.prefix.len();
            let bits =
                u128::from(addr) & (u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0));
            V6 {
                prefix: Ipv6Addr::from(bits),
                prefix_len: len,
                valid_s: a.valid_lft,
                preferred_s: a.preferred_lft,
                gateway_ll: gw
                    .filter(is_ipv6_link_local)
                    .unwrap_or(DEFAULT_GATEWAY_LINK_LOCAL),
                gateway_global: gw.filter(|g| !is_ipv6_link_local(g)),
                dns: cfg
                    .dns
                    .iter()
                    .flat_map(|d| d.servers.iter())
                    .filter_map(|s| match s {
                        IpAddr::V6(v6) => Some(*v6),
                        IpAddr::V4(_) => None,
                    })
                    .collect(),
            }
        });
        let changed = v6 != self.v6;
        self.v6 = v6;
        if self.v6.is_some() {
            if changed {
                self.advertise(now_ms, false);
            }
        } else {
            self.next_ra_ms = None;
        }
    }

    /// The tunnel is gone for good. A last advertisement with a router
    /// lifetime of 0 withdraws the machine's IPv6 default route.
    pub fn deconfigure(&mut self, now_ms: u64) {
        if self.v6.is_some() {
            self.advertise(now_ms, true);
        }
        self.v6 = None;
        self.gateway4 = None;
        self.lan4 = None;
        self.next_ra_ms = None;
    }

    /// The next frame the router wants on the wire by itself.
    pub fn poll_frame(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    pub fn poll_timeout(&self) -> Option<u64> {
        self.next_ra_ms
    }

    pub fn handle_timeout(&mut self, now_ms: u64) {
        if self.next_ra_ms.is_some_and(|t| now_ms >= t) {
            self.advertise(now_ms, false);
        }
    }

    fn advertise(&mut self, now_ms: u64, withdraw: bool) {
        let Some(v6) = &self.v6 else {
            return;
        };
        let slaac = v6.prefix_len == 64;
        let ra = Advertisement {
            cur_hop_limit: 64,
            router_lifetime_s: if withdraw {
                0
            } else {
                self.cfg.router_lifetime_s
            },
            source_mac: self.cfg.gateway_mac,
            mtu: Some(u32::from(self.link_mtu)),
            prefix: Some((
                v6.prefix,
                v6.prefix_len,
                slaac,
                v6.valid_s,
                if withdraw { 0 } else { v6.preferred_s },
            )),
            rdnss: v6.dns.clone(),
            rdnss_lifetime_s: if withdraw {
                0
            } else {
                u32::from(self.cfg.router_lifetime_s)
            },
        };
        let packet = build_icmpv6(v6.gateway_ll, ALL_NODES, 255, build_ra(&ra));
        self.pending.push_back(build_frame(
            ether::ipv6_multicast_mac(ALL_NODES),
            self.cfg.gateway_mac,
            ethertype::IPV6,
            &packet,
        ));
        self.stats.router_advertisements += 1;
        self.last_ra_ms = Some(now_ms);
        self.next_ra_ms = (!withdraw).then_some(now_ms + self.cfg.ra_interval_ms);
    }

    /// One frame from the machine's `eth0`.
    pub fn from_wire(&mut self, frame: &[u8], now_ms: u64) -> FromWire {
        let out = self.classify(frame, now_ms);
        match &out {
            FromWire::Forward(_) => self.stats.forwarded += 1,
            FromWire::Reply(_) => {}
            FromWire::Drop(_) => self.stats.dropped += 1,
        }
        out
    }

    fn classify(&mut self, frame: &[u8], now_ms: u64) -> FromWire {
        let Some(f) = parse_frame(frame) else {
            return FromWire::Drop(DropReason::Malformed);
        };
        let for_gateway = f.dst == self.cfg.gateway_mac;
        if !for_gateway && !is_multicast(&f.dst) {
            return FromWire::Drop(DropReason::NotForGateway);
        }
        if self.host_mac.is_none() && !is_multicast(&f.src) {
            self.host_mac = Some(f.src);
        }
        match f.ethertype {
            ethertype::ARP => self.arp(f.payload),
            ethertype::IPV4 => {
                let Some(p) = ether::ip_packet(f.ethertype, f.payload) else {
                    return FromWire::Drop(DropReason::Malformed);
                };
                if !for_gateway {
                    return FromWire::Drop(DropReason::LinkLocal);
                }
                if self.gateway4.is_none() {
                    return FromWire::Drop(DropReason::Unconfigured);
                }
                let dst = ether::ipv4_dst(p);
                if dst.is_broadcast()
                    || dst.is_multicast()
                    || dst.is_link_local()
                    || dst.is_unspecified()
                    || self.is_lan_broadcast(dst)
                {
                    return FromWire::Drop(DropReason::LinkLocal);
                }
                FromWire::Forward(p.to_vec())
            }
            ethertype::IPV6 => {
                let Some(p) = ether::ip_packet(f.ethertype, f.payload) else {
                    return FromWire::Drop(DropReason::Malformed);
                };
                self.ipv6(f.src, for_gateway, p, now_ms)
            }
            other => FromWire::Drop(DropReason::Protocol(other)),
        }
    }

    fn is_lan_broadcast(&self, dst: Ipv4Addr) -> bool {
        let Some((addr, len)) = self.lan4 else {
            return false;
        };
        if len >= 31 {
            return false;
        }
        let host_bits = u32::MAX >> len;
        u32::from(dst) == (u32::from(addr) | host_bits)
    }

    fn arp(&mut self, payload: &[u8]) -> FromWire {
        let Some(req) = parse_arp(payload) else {
            return FromWire::Drop(DropReason::Malformed);
        };
        let Some(gw) = self.gateway4 else {
            return FromWire::Drop(DropReason::Unconfigured);
        };
        if req.op != ARP_REQUEST || req.target_ip != gw || is_multicast(&req.sender_mac) {
            // Probes and announcements for the machine's own address, and
            // requests for hosts that do not exist, go unanswered.
            return FromWire::Drop(DropReason::Arp);
        }
        let reply = Arp {
            op: ARP_REPLY,
            sender_mac: self.cfg.gateway_mac,
            sender_ip: gw,
            target_mac: req.sender_mac,
            target_ip: req.sender_ip,
        };
        self.stats.arp_replies += 1;
        FromWire::Reply(build_frame(
            req.sender_mac,
            self.cfg.gateway_mac,
            ethertype::ARP,
            &build_arp(&reply),
        ))
    }

    fn ipv6(&mut self, src_mac: Mac, for_gateway: bool, p: &[u8], now_ms: u64) -> FromWire {
        let dst = ether::ipv6_dst(p);
        let src = ether::ipv6_src(p);
        if p[6] == 58 {
            if let Some(m) = parse_icmpv6(p) {
                match m.ty {
                    icmpv6::ROUTER_SOLICITATION => return self.solicited_ra(&m, now_ms),
                    icmpv6::NEIGHBOR_SOLICITATION => return self.neighbour(src_mac, &m),
                    icmpv6::ROUTER_ADVERTISEMENT
                    | icmpv6::NEIGHBOR_ADVERTISEMENT
                    | icmpv6::REDIRECT
                    | icmpv6::MLD_QUERY
                    | icmpv6::MLD_REPORT
                    | icmpv6::MLD_DONE
                    | icmpv6::MLDV2_REPORT => {
                        return FromWire::Drop(DropReason::NeighbourDiscovery)
                    }
                    icmpv6::ECHO_REQUEST
                        if for_gateway && self.v6.as_ref().is_some_and(|v| v.gateway_ll == dst) =>
                    {
                        return self.echo_reply(src_mac, &m);
                    }
                    _ => {}
                }
            }
        }
        if !for_gateway || dst.is_multicast() || is_ipv6_link_local(&dst) {
            return FromWire::Drop(DropReason::LinkLocal);
        }
        if is_ipv6_link_local(&src) || src.is_unspecified() {
            return FromWire::Drop(DropReason::LinkLocal);
        }
        if self.v6.is_none() {
            return FromWire::Drop(DropReason::Unconfigured);
        }
        FromWire::Forward(p.to_vec())
    }

    fn solicited_ra(&mut self, m: &ether::Icmpv6<'_>, now_ms: u64) -> FromWire {
        if self.v6.is_none() || m.hop_limit != 255 || m.code != 0 {
            return FromWire::Drop(DropReason::NeighbourDiscovery);
        }
        if self
            .last_ra_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < MIN_DELAY_BETWEEN_RAS_MS)
        {
            // Too soon after the last one; the next periodic one follows.
            return FromWire::Drop(DropReason::NeighbourDiscovery);
        }
        self.advertise(now_ms, false);
        match self.pending.pop_back() {
            Some(frame) => FromWire::Reply(frame),
            None => FromWire::Drop(DropReason::NeighbourDiscovery),
        }
    }

    fn neighbour(&mut self, src_mac: Mac, m: &ether::Icmpv6<'_>) -> FromWire {
        let Some(v6) = &self.v6 else {
            return FromWire::Drop(DropReason::NeighbourDiscovery);
        };
        let Some(target) = ns_target(m.msg) else {
            return FromWire::Drop(DropReason::Malformed);
        };
        if m.hop_limit != 255 || m.code != 0 || target.is_multicast() {
            return FromWire::Drop(DropReason::NeighbourDiscovery);
        }
        let ours = target == v6.gateway_ll || Some(target) == v6.gateway_global;
        if !ours || m.src.is_unspecified() {
            // Duplicate address detection by the machine, or a neighbour
            // that does not exist.
            return FromWire::Drop(DropReason::NeighbourDiscovery);
        }
        let to_mac = nd_options(m.msg, 24)
            .and_then(|opts| {
                opts.into_iter()
                    .find(|(ty, body)| *ty == ether::nd_option::SOURCE_LINK_ADDR && body.len() >= 6)
                    .map(|(_, body)| {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&body[..6]);
                        mac
                    })
            })
            .unwrap_or(src_mac);
        let na = build_na(
            target,
            na_flags::ROUTER | na_flags::SOLICITED | na_flags::OVERRIDE,
            self.cfg.gateway_mac,
        );
        self.stats.neighbour_advertisements += 1;
        FromWire::Reply(build_frame(
            to_mac,
            self.cfg.gateway_mac,
            ethertype::IPV6,
            &build_icmpv6(target, m.src, 255, na),
        ))
    }

    fn echo_reply(&mut self, src_mac: Mac, m: &ether::Icmpv6<'_>) -> FromWire {
        let mut reply = m.msg.to_vec();
        reply[0] = icmpv6::ECHO_REPLY;
        FromWire::Reply(build_frame(
            src_mac,
            self.cfg.gateway_mac,
            ethertype::IPV6,
            &build_icmpv6(m.dst, m.src, 64, reply),
        ))
    }

    /// One IP packet from the tunnel, framed for the machine. `None` before
    /// the machine's Ethernet address is known, or for a packet that is not
    /// IPv4 or IPv6.
    pub fn to_wire(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let ty = match packet.first()? >> 4 {
            4 => ethertype::IPV4,
            6 => ethertype::IPV6,
            _ => {
                self.stats.dropped += 1;
                return None;
            }
        };
        let Some(mac) = self.host_mac else {
            self.stats.dropped += 1;
            return None;
        };
        self.stats.delivered += 1;
        Some(build_frame(mac, self.cfg.gateway_mac, ty, packet))
    }
}

/// Whether `mac` is the broadcast address.
pub fn is_broadcast(mac: &Mac) -> bool {
    *mac == BROADCAST
}

#[cfg(test)]
mod tests;

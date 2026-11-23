//! The machine manager: what the relay's open confirmation means for the
//! machine's `eth0`, as NetworkManager would apply a DHCP lease on a Debian
//! host (PLAN section 3.4).
//!
//! The confirmation's `ADDRESS_ASSIGN`, `ROUTE_ADVERTISEMENT`, `LINK` and
//! `DNS_CONFIG` capsules become a [`LinkConfig`]. [`plan`] turns a change
//! from one configuration to the next into a [`ConfigPlan`]:
//!
//! - the link's MTU from `LINK`, the machine's Ethernet address, and up;
//! - each IPv4 address with its lifetimes, and each IPv4 route with the
//!   relay's metric (`proto dhcp`, the address as preferred source);
//! - IPv6: with a routed /64 the virtual router advertises the prefix and
//!   the machine's kernel forms its own addresses and default route
//!   (SLAAC), so the plan only makes the kernel accept advertisements. A
//!   prefix of any other length cannot be used by SLAAC, so its address and
//!   routes are set as for IPv4;
//! - the resolvers and search list from `DNS_CONFIG`, for `/etc/resolv.conf`
//!   (Ferrochrome's WasmFS image and gex's VFS read files, not the kernel);
//! - what the previous configuration had and the next one lacks is removed.
//!
//! [`MachineManager`] carries a plan out. The netkernel's implementation is
//! [`crate::nkrpc::NkrpcManager`], whose calls go over NKRPC (LS-4, LS-7);
//! tests use a Linux network namespace.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use wisp_ip::{AssignedAddress, Capsule, DnsConfig, LinkParams, RouteEntry};

use crate::ether::Mac;
use crate::netlink::NetlinkOp;

/// The tunnel's configuration of the machine's link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    pub addresses: Vec<AssignedAddress>,
    pub routes: Vec<RouteEntry>,
    pub link: LinkParams,
    pub dns: Option<DnsConfig>,
}

impl LinkConfig {
    /// The configuration in an open confirmation. `None` unless it carries
    /// `ADDRESS_ASSIGN`, `ROUTE_ADVERTISEMENT` and `LINK`.
    pub fn from_capsules(capsules: &[Capsule]) -> Option<Self> {
        let mut addresses = None;
        let mut routes = None;
        let mut link = None;
        let mut dns = None;
        for c in capsules {
            match c {
                Capsule::AddressAssign(a) => addresses = Some(a.clone()),
                Capsule::RouteAdvertisement(r) => routes = Some(r.clone()),
                Capsule::Link(l) => link = Some(*l),
                Capsule::DnsConfig(d) => dns = Some(d.clone()),
                _ => {}
            }
        }
        Some(Self {
            addresses: addresses?,
            routes: routes?,
            link: link?,
            dns,
        })
    }

    /// Applies later control: each capsule replaces its part. Returns
    /// whether anything changed.
    pub fn update(&mut self, capsules: &[Capsule]) -> bool {
        let before = self.clone();
        for c in capsules {
            match c {
                Capsule::AddressAssign(a) => self.addresses = a.clone(),
                Capsule::RouteAdvertisement(r) => self.routes = r.clone(),
                Capsule::Link(l) => self.link = *l,
                Capsule::DnsConfig(d) => self.dns = Some(d.clone()),
                _ => {}
            }
        }
        *self != before
    }

    /// The first IPv4 address.
    pub fn ipv4(&self) -> Option<&AssignedAddress> {
        self.addresses.iter().find(|a| a.prefix.is_ipv4())
    }

    /// The first IPv6 address.
    pub fn ipv6(&self) -> Option<&AssignedAddress> {
        self.addresses.iter().find(|a| !a.prefix.is_ipv4())
    }

    /// The gateway of the IPv4 default route.
    pub fn gateway4(&self) -> Option<Ipv4Addr> {
        self.default_route(true).and_then(|r| match r.gateway {
            IpAddr::V4(g) => Some(g),
            IpAddr::V6(_) => None,
        })
    }

    /// The gateway of the IPv6 default route.
    pub fn gateway6(&self) -> Option<Ipv6Addr> {
        self.default_route(false).and_then(|r| match r.gateway {
            IpAddr::V6(g) => Some(g),
            IpAddr::V4(_) => None,
        })
    }

    fn default_route(&self, v4: bool) -> Option<&RouteEntry> {
        self.routes
            .iter()
            .filter(|r| r.dest.is_ipv4() == v4)
            .min_by_key(|r| r.dest.len())
    }

    /// Whether the machine's IPv6 addresses come from SLAAC on the routed
    /// prefix (a /64) rather than from this plan.
    pub fn ipv6_by_slaac(&self) -> bool {
        self.ipv6().is_some_and(|a| a.prefix.len() == 64)
    }

    /// Addresses and routes this plan sets itself.
    fn static_addresses(&self) -> impl Iterator<Item = &AssignedAddress> {
        let slaac = self.ipv6_by_slaac();
        self.addresses
            .iter()
            .filter(move |a| a.prefix.is_ipv4() || !slaac)
    }

    fn static_routes(&self) -> impl Iterator<Item = &RouteEntry> {
        let slaac = self.ipv6_by_slaac();
        let has_v6 = self.ipv6().is_some();
        self.routes
            .iter()
            .filter(move |r| r.dest.is_ipv4() || (has_v6 && !slaac))
    }
}

/// The machine's interface the tunnel configures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSpec {
    /// Kernel name, `eth0` on the reference.
    pub name: String,
    pub ifindex: u32,
    /// The machine config's Ethernet address for it.
    pub mac: Mac,
}

/// One write under `/proc/sys/net`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlWrite {
    /// Path below `/proc/sys/net`, such as `ipv6/conf/eth0/accept_ra`.
    pub path: String,
    pub value: String,
}

/// What `/etc/resolv.conf` is to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverConfig {
    pub servers: Vec<IpAddr>,
    pub search: Vec<String>,
}

impl ResolverConfig {
    pub fn from_dns(dns: &DnsConfig) -> Self {
        Self {
            servers: dns.servers.clone(),
            search: dns
                .search
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }

    /// The file, in the layout NetworkManager writes.
    pub fn resolv_conf(&self) -> String {
        let mut out = String::from("# Generated by the uplink from the tunnel's DNS_CONFIG\n");
        if !self.search.is_empty() {
            out.push_str("search ");
            out.push_str(&self.search.join(" "));
            out.push('\n');
        }
        for s in &self.servers {
            out.push_str(&format!("nameserver {s}\n"));
        }
        out
    }
}

/// Everything one change of configuration does to the machine, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigPlan {
    pub netlink: Vec<NetlinkOp>,
    pub sysctl: Vec<SysctlWrite>,
    /// `Some` when `/etc/resolv.conf` is to change.
    pub resolver: Option<ResolverConfig>,
}

impl ConfigPlan {
    pub fn is_empty(&self) -> bool {
        self.netlink.is_empty() && self.sysctl.is_empty() && self.resolver.is_none()
    }
}

fn same_address(a: &AssignedAddress, b: &AssignedAddress) -> bool {
    a.prefix == b.prefix
}

fn same_route(a: &RouteEntry, b: &RouteEntry) -> bool {
    a.dest == b.dest && a.gateway == b.gateway && a.metric == b.metric
}

/// The operations that take the machine from `previous` to `next` (`None`:
/// the tunnel is gone for good, and what it configured is removed, as when a
/// lease ends; the link stays up).
pub fn plan(
    iface: &InterfaceSpec,
    previous: Option<&LinkConfig>,
    next: Option<&LinkConfig>,
) -> ConfigPlan {
    let mut p = ConfigPlan::default();
    let ifindex = iface.ifindex;
    let empty = LinkConfig {
        addresses: Vec::new(),
        routes: Vec::new(),
        link: LinkParams {
            link_mtu: 0,
            max_packet: 0,
            max_datagram_payload: 0,
        },
        dns: None,
    };
    let prev = previous.unwrap_or(&empty);
    let target = next.unwrap_or(&empty);

    // Routes and addresses the next configuration no longer has.
    for r in prev.static_routes() {
        if !target.static_routes().any(|n| same_route(n, r)) {
            p.netlink.push(NetlinkOp::DelRoute {
                ifindex,
                dest: r.dest,
                gateway: r.gateway,
                metric: r.metric,
            });
        }
    }
    for a in prev.static_addresses() {
        if !target.static_addresses().any(|n| same_address(n, a)) {
            p.netlink.push(NetlinkOp::DelAddress {
                ifindex,
                prefix: a.prefix,
            });
        }
    }

    if let Some(next) = next {
        if previous.is_none_or(|prev| prev.link.link_mtu != next.link.link_mtu) {
            p.netlink.push(NetlinkOp::SetLink {
                ifindex,
                mac: previous.is_none().then_some(iface.mac),
                mtu: Some(u32::from(next.link.link_mtu)),
                up: true,
            });
        }
        if next.ipv6_by_slaac() && !prev.ipv6_by_slaac() {
            p.sysctl.push(SysctlWrite {
                path: format!("ipv6/conf/{}/accept_ra", iface.name),
                value: "1".to_owned(),
            });
        }
        for a in next.static_addresses() {
            let unchanged = prev.static_addresses().any(|o| o == a);
            if !unchanged {
                p.netlink.push(NetlinkOp::AddAddress {
                    ifindex,
                    prefix: a.prefix,
                    valid_lft: a.valid_lft,
                    preferred_lft: a.preferred_lft,
                });
            }
        }
        for r in next.static_routes() {
            if !prev.static_routes().any(|o| same_route(o, r)) {
                let prefsrc = next
                    .static_addresses()
                    .find(|a| a.prefix.is_ipv4() == r.dest.is_ipv4())
                    .map(|a| a.prefix.addr());
                p.netlink.push(NetlinkOp::AddRoute {
                    ifindex,
                    dest: r.dest,
                    gateway: r.gateway,
                    metric: r.metric,
                    prefsrc,
                });
            }
        }
    }

    let dns_before = previous.and_then(|c| c.dns.as_ref());
    let dns_after = next.and_then(|c| c.dns.as_ref());
    if dns_before != dns_after {
        p.resolver = Some(
            dns_after
                .map(ResolverConfig::from_dns)
                .unwrap_or(ResolverConfig {
                    servers: Vec::new(),
                    search: Vec::new(),
                }),
        );
    }
    p
}

/// Carries configuration plans out on a machine. Implementations supply
/// [`Self::execute`] and keep the configuration last applied; the provided
/// methods compute the plans.
pub trait MachineManager {
    type Error;

    fn interface(&self) -> &InterfaceSpec;

    /// The configuration this manager last applied.
    fn current(&self) -> Option<&LinkConfig>;

    fn set_current(&mut self, config: Option<LinkConfig>);

    /// Performs every operation of `plan`, in order.
    fn execute(&mut self, plan: &ConfigPlan) -> Result<(), Self::Error>;

    /// Makes the machine's link match `next`. Returns the plan carried out.
    fn configure(&mut self, next: &LinkConfig) -> Result<ConfigPlan, Self::Error> {
        let p = plan(self.interface(), self.current(), Some(next));
        self.execute(&p)?;
        self.set_current(Some(next.clone()));
        Ok(p)
    }

    /// Removes what the tunnel configured.
    fn deconfigure(&mut self) -> Result<ConfigPlan, Self::Error> {
        let p = plan(self.interface(), self.current(), None);
        self.execute(&p)?;
        self.set_current(None);
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_ip::capsule::FOREVER;
    use wisp_ip::Prefix;

    fn iface() -> InterfaceSpec {
        InterfaceSpec {
            name: "eth0".to_owned(),
            ifindex: 2,
            mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
        }
    }

    fn addr(s: &str, len: u8) -> AssignedAddress {
        AssignedAddress {
            prefix: Prefix::new(s.parse().unwrap(), len).unwrap(),
            valid_lft: FOREVER,
            preferred_lft: FOREVER,
        }
    }

    fn route(dest: &str, len: u8, gw: &str) -> RouteEntry {
        RouteEntry {
            dest: Prefix::new(dest.parse().unwrap(), len).unwrap(),
            gateway: gw.parse().unwrap(),
            metric: 100,
        }
    }

    /// What LS-5's relay confirms for an IPv4 and IPv6 tunnel.
    fn ls5_confirmation(v6: bool) -> Vec<Capsule> {
        let mut addresses = vec![addr("192.168.1.100", 24)];
        let mut routes = vec![route("0.0.0.0", 0, "192.168.1.1")];
        if v6 {
            addresses.push(addr("2001:db8:42:7::100", 64));
            routes.push(route("::", 0, "fe80::1"));
        }
        vec![
            Capsule::AddressAssign(addresses),
            Capsule::RouteAdvertisement(routes),
            Capsule::Link(LinkParams {
                link_mtu: 1500,
                max_packet: 1500,
                max_datagram_payload: 0,
            }),
            Capsule::DnsConfig(DnsConfig {
                servers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
                search: "lan home.arpa".to_owned(),
            }),
        ]
    }

    #[test]
    fn a_confirmation_needs_addresses_routes_and_link() {
        let caps = ls5_confirmation(false);
        assert!(LinkConfig::from_capsules(&caps).is_some());
        assert!(LinkConfig::from_capsules(&caps[1..]).is_none());
        assert!(LinkConfig::from_capsules(&caps[..2]).is_none());
    }

    #[test]
    fn first_plan_sets_link_address_route_and_resolvers() {
        let cfg = LinkConfig::from_capsules(&ls5_confirmation(false)).unwrap();
        let p = plan(&iface(), None, Some(&cfg));
        let lines: Vec<String> = p.netlink.iter().map(|o| o.to_string()).collect();
        assert_eq!(
            lines,
            [
                "ip link set dev #2 address 52:54:00:12:34:56 mtu 1500 up",
                "ip addr replace 192.168.1.100/24 dev #2 valid_lft forever preferred_lft forever",
                "ip route replace 0.0.0.0/0 via 192.168.1.1 dev #2 proto dhcp src 192.168.1.100 metric 100",
            ]
        );
        assert!(p.sysctl.is_empty());
        let resolv = p.resolver.unwrap().resolv_conf();
        assert!(resolv.contains("search lan home.arpa\n"));
        assert!(resolv.contains("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"));
    }

    #[test]
    fn a_routed_slash_64_is_left_to_slaac() {
        let cfg = LinkConfig::from_capsules(&ls5_confirmation(true)).unwrap();
        assert!(cfg.ipv6_by_slaac());
        let p = plan(&iface(), None, Some(&cfg));
        assert!(p
            .netlink
            .iter()
            .all(|o| !o.to_string().contains("2001:db8") && !o.to_string().contains("::/0")));
        assert_eq!(
            p.sysctl,
            [SysctlWrite {
                path: "ipv6/conf/eth0/accept_ra".to_owned(),
                value: "1".to_owned(),
            }]
        );
    }

    #[test]
    fn other_ipv6_prefix_lengths_are_set_directly() {
        let mut caps = ls5_confirmation(true);
        if let Capsule::AddressAssign(a) = &mut caps[0] {
            a[1] = addr("2001:db8:42:7::100", 112);
        }
        let cfg = LinkConfig::from_capsules(&caps).unwrap();
        let p = plan(&iface(), None, Some(&cfg));
        let lines: Vec<String> = p.netlink.iter().map(|o| o.to_string()).collect();
        assert!(lines
            .iter()
            .any(|l| l.starts_with("ip addr replace 2001:db8:42:7::100/112")));
        assert!(lines.iter().any(|l| l.starts_with(
            "ip route replace ::/0 via fe80::1 dev #2 proto dhcp src 2001:db8:42:7::100"
        )));
    }

    #[test]
    fn an_unchanged_configuration_needs_nothing() {
        let cfg = LinkConfig::from_capsules(&ls5_confirmation(true)).unwrap();
        assert!(plan(&iface(), Some(&cfg), Some(&cfg)).is_empty());
    }

    #[test]
    fn a_new_address_replaces_the_old_one() {
        let old = LinkConfig::from_capsules(&ls5_confirmation(false)).unwrap();
        let mut new = old.clone();
        assert!(new.update(&[Capsule::AddressAssign(vec![addr("192.168.1.101", 24)])]));
        let lines: Vec<String> = plan(&iface(), Some(&old), Some(&new))
            .netlink
            .iter()
            .map(|o| o.to_string())
            .collect();
        assert_eq!(
            lines,
            [
                "ip addr del 192.168.1.100/24 dev #2",
                "ip addr replace 192.168.1.101/24 dev #2 valid_lft forever preferred_lft forever",
            ]
        );
    }

    #[test]
    fn deconfiguring_removes_routes_then_addresses_and_resolvers() {
        let cfg = LinkConfig::from_capsules(&ls5_confirmation(false)).unwrap();
        let p = plan(&iface(), Some(&cfg), None);
        let lines: Vec<String> = p.netlink.iter().map(|o| o.to_string()).collect();
        assert_eq!(
            lines,
            [
                "ip route del 0.0.0.0/0 via 192.168.1.1 dev #2 metric 100",
                "ip addr del 192.168.1.100/24 dev #2",
            ]
        );
        assert_eq!(p.resolver.unwrap().servers, Vec::<IpAddr>::new());
    }

    struct Recorder {
        iface: InterfaceSpec,
        current: Option<LinkConfig>,
        plans: Vec<ConfigPlan>,
    }

    impl MachineManager for Recorder {
        type Error = ();
        fn interface(&self) -> &InterfaceSpec {
            &self.iface
        }
        fn current(&self) -> Option<&LinkConfig> {
            self.current.as_ref()
        }
        fn set_current(&mut self, config: Option<LinkConfig>) {
            self.current = config;
        }
        fn execute(&mut self, plan: &ConfigPlan) -> Result<(), ()> {
            self.plans.push(plan.clone());
            Ok(())
        }
    }

    #[test]
    fn the_trait_keeps_what_it_applied() {
        let cfg = LinkConfig::from_capsules(&ls5_confirmation(false)).unwrap();
        let mut m = Recorder {
            iface: iface(),
            current: None,
            plans: Vec::new(),
        };
        m.configure(&cfg).unwrap();
        assert!(m.configure(&cfg).unwrap().is_empty());
        m.deconfigure().unwrap();
        assert_eq!(m.plans.len(), 3);
        assert!(m.current.is_none());
    }
}

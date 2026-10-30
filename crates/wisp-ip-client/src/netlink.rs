//! The rtnetlink messages the machine manager sends, byte for byte as
//! Linux's `NETLINK_ROUTE` takes them (`include/uapi/linux/rtnetlink.h`,
//! `if_link.h`, `if_addr.h`). Netlink is little-endian on every machine this
//! runs on and has no pointers, so the same bytes serve the wasm32 netkernel
//! and a native Linux kernel (NKRPC SPEC-r2 section 3.8).
//!
//! Each operation is one request with `NLM_F_REQUEST | NLM_F_ACK`; Linux
//! answers each with an `NLMSG_ERROR` whose error is 0 on success. Adds use
//! `NLM_F_CREATE | NLM_F_REPLACE`, as `ip addr replace` and NetworkManager do,
//! so a renewed lease refreshes its lifetimes instead of failing with
//! `EEXIST`.

use std::fmt;
use std::net::IpAddr;

use wisp_ip::Prefix;

use crate::ether::Mac;

pub const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_CREATE: u16 = 0x400;

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const IFF_UP: u32 = 0x1;

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_MTU: u16 = 4;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_BROADCAST: u16 = 4;
pub const IFA_CACHEINFO: u16 = 6;

pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_TABLE: u16 = 15;

pub const RT_TABLE_MAIN: u8 = 254;
/// Routes learnt from the network's configuration service, as a DHCP
/// client installs them (`proto dhcp` in `ip route`).
pub const RTPROT_DHCP: u8 = 16;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
/// Matches any scope on delete, as `ip route del` sends.
pub const RT_SCOPE_NOWHERE: u8 = 255;
pub const RTN_UNICAST: u8 = 1;

/// One rtnetlink request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkOp {
    /// `ip link set dev <if> [address <mac>] [mtu <mtu>] up`.
    SetLink {
        ifindex: u32,
        mac: Option<Mac>,
        mtu: Option<u32>,
        up: bool,
    },
    /// `ip addr replace <prefix> [brd +] dev <if> valid_lft .. preferred_lft ..`.
    AddAddress {
        ifindex: u32,
        prefix: Prefix,
        valid_lft: u32,
        preferred_lft: u32,
    },
    /// `ip addr del <prefix> dev <if>`.
    DelAddress { ifindex: u32, prefix: Prefix },
    /// `ip route replace <dest> via <gateway> dev <if> proto dhcp [src ..] metric ..`.
    AddRoute {
        ifindex: u32,
        dest: Prefix,
        gateway: IpAddr,
        metric: u32,
        prefsrc: Option<IpAddr>,
    },
    /// `ip route del <dest> via <gateway> dev <if> metric ..`.
    DelRoute {
        ifindex: u32,
        dest: Prefix,
        gateway: IpAddr,
        metric: u32,
    },
}

fn family(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    }
}

fn addr_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Appends one `rtattr`, padded to 4 bytes.
fn attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    let len = 4 + data.len();
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn message(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(NLMSG_HDRLEN + body.len());
    m.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_le_bytes());
    m.extend_from_slice(&ty.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_pid: to the kernel
    m.extend_from_slice(body);
    m
}

fn ifaddrmsg(prefix: &Prefix, ifindex: u32) -> Vec<u8> {
    let mut b = vec![family(prefix.addr()), prefix.len(), 0, RT_SCOPE_UNIVERSE];
    b.extend_from_slice(&ifindex.to_le_bytes());
    b
}

fn rtmsg(dest: &Prefix, protocol: u8, scope: u8, ty: u8) -> Vec<u8> {
    let mut b = vec![
        family(dest.addr()),
        dest.len(),
        0, // src_len
        0, // tos
        RT_TABLE_MAIN,
        protocol,
        scope,
        ty,
    ];
    b.extend_from_slice(&0u32.to_le_bytes()); // rtm_flags
    b
}

fn route_attrs(b: &mut Vec<u8>, ifindex: u32, dest: &Prefix, gateway: IpAddr, metric: u32) {
    if !dest.is_empty() {
        attr(b, RTA_DST, &addr_bytes(dest.network()));
    }
    attr(b, RTA_TABLE, &u32::from(RT_TABLE_MAIN).to_le_bytes());
    attr(b, RTA_GATEWAY, &addr_bytes(gateway));
    attr(b, RTA_OIF, &ifindex.to_le_bytes());
    attr(b, RTA_PRIORITY, &metric.to_le_bytes());
}

impl NetlinkOp {
    pub fn message_type(&self) -> u16 {
        match self {
            NetlinkOp::SetLink { .. } => RTM_NEWLINK,
            NetlinkOp::AddAddress { .. } => RTM_NEWADDR,
            NetlinkOp::DelAddress { .. } => RTM_DELADDR,
            NetlinkOp::AddRoute { .. } => RTM_NEWROUTE,
            NetlinkOp::DelRoute { .. } => RTM_DELROUTE,
        }
    }

    /// The request, with sequence number `seq`.
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let ack = NLM_F_REQUEST | NLM_F_ACK;
        let add = ack | NLM_F_CREATE | NLM_F_REPLACE;
        match self {
            NetlinkOp::SetLink {
                ifindex,
                mac,
                mtu,
                up,
            } => {
                // struct ifinfomsg: family, pad, type, index, flags, change.
                let mut b = vec![AF_UNSPEC, 0];
                b.extend_from_slice(&0u16.to_le_bytes());
                b.extend_from_slice(&(*ifindex as i32).to_le_bytes());
                b.extend_from_slice(&(if *up { IFF_UP } else { 0 }).to_le_bytes());
                b.extend_from_slice(&IFF_UP.to_le_bytes());
                if let Some(mac) = mac {
                    attr(&mut b, IFLA_ADDRESS, mac);
                }
                if let Some(mtu) = mtu {
                    attr(&mut b, IFLA_MTU, &mtu.to_le_bytes());
                }
                message(RTM_NEWLINK, ack, seq, &b)
            }
            NetlinkOp::AddAddress {
                ifindex,
                prefix,
                valid_lft,
                preferred_lft,
            } => {
                let mut b = ifaddrmsg(prefix, *ifindex);
                let local = addr_bytes(prefix.addr());
                attr(&mut b, IFA_LOCAL, &local);
                attr(&mut b, IFA_ADDRESS, &local);
                if let IpAddr::V4(v4) = prefix.addr() {
                    if prefix.len() < 31 {
                        let brd = u32::from(v4) | (u32::MAX >> prefix.len());
                        attr(&mut b, IFA_BROADCAST, &brd.to_be_bytes());
                    }
                }
                // struct ifa_cacheinfo: preferred, valid, cstamp, tstamp.
                let mut ci = Vec::with_capacity(16);
                ci.extend_from_slice(&preferred_lft.to_le_bytes());
                ci.extend_from_slice(&valid_lft.to_le_bytes());
                ci.extend_from_slice(&[0; 8]);
                attr(&mut b, IFA_CACHEINFO, &ci);
                message(RTM_NEWADDR, add, seq, &b)
            }
            NetlinkOp::DelAddress { ifindex, prefix } => {
                let mut b = ifaddrmsg(prefix, *ifindex);
                attr(&mut b, IFA_LOCAL, &addr_bytes(prefix.addr()));
                message(RTM_DELADDR, ack, seq, &b)
            }
            NetlinkOp::AddRoute {
                ifindex,
                dest,
                gateway,
                metric,
                prefsrc,
            } => {
                let mut b = rtmsg(dest, RTPROT_DHCP, RT_SCOPE_UNIVERSE, RTN_UNICAST);
                route_attrs(&mut b, *ifindex, dest, *gateway, *metric);
                if let Some(src) = prefsrc.filter(|s| s.is_ipv4() == dest.is_ipv4()) {
                    attr(&mut b, RTA_PREFSRC, &addr_bytes(src));
                }
                message(RTM_NEWROUTE, add, seq, &b)
            }
            NetlinkOp::DelRoute {
                ifindex,
                dest,
                gateway,
                metric,
            } => {
                let mut b = rtmsg(dest, 0, RT_SCOPE_NOWHERE, RTN_UNICAST);
                route_attrs(&mut b, *ifindex, dest, *gateway, *metric);
                message(RTM_DELROUTE, ack, seq, &b)
            }
        }
    }
}

impl fmt::Display for NetlinkOp {
    /// The `ip` command that does the same, for logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetlinkOp::SetLink {
                ifindex,
                mac,
                mtu,
                up,
            } => {
                write!(f, "ip link set dev #{ifindex}")?;
                if let Some(m) = mac {
                    write!(
                        f,
                        " address {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        m[0], m[1], m[2], m[3], m[4], m[5]
                    )?;
                }
                if let Some(mtu) = mtu {
                    write!(f, " mtu {mtu}")?;
                }
                f.write_str(if *up { " up" } else { " down" })
            }
            NetlinkOp::AddAddress {
                ifindex,
                prefix,
                valid_lft,
                preferred_lft,
            } => {
                let life = |v: u32| {
                    if v == u32::MAX {
                        "forever".to_owned()
                    } else {
                        format!("{v}")
                    }
                };
                write!(
                    f,
                    "ip addr replace {prefix} dev #{ifindex} valid_lft {} preferred_lft {}",
                    life(*valid_lft),
                    life(*preferred_lft)
                )
            }
            NetlinkOp::DelAddress { ifindex, prefix } => {
                write!(f, "ip addr del {prefix} dev #{ifindex}")
            }
            NetlinkOp::AddRoute {
                ifindex,
                dest,
                gateway,
                metric,
                prefsrc,
            } => {
                write!(
                    f,
                    "ip route replace {dest} via {gateway} dev #{ifindex} proto dhcp"
                )?;
                if let Some(src) = prefsrc.filter(|s| s.is_ipv4() == dest.is_ipv4()) {
                    write!(f, " src {src}")?;
                }
                write!(f, " metric {metric}")
            }
            NetlinkOp::DelRoute {
                ifindex,
                dest,
                gateway,
                metric,
            } => write!(
                f,
                "ip route del {dest} via {gateway} dev #{ifindex} metric {metric}"
            ),
        }
    }
}

/// The kernel's answer to request `seq` in `buf` (one or more netlink
/// messages): `Some(Ok(()))` for an acknowledgement, `Some(Err(errno))` for
/// an error (positive errno), `None` when `buf` holds no answer to `seq`.
pub fn parse_ack(buf: &[u8], seq: u32) -> Option<Result<(), i32>> {
    let mut off = 0usize;
    while buf.len() - off >= NLMSG_HDRLEN {
        let len = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            return None;
        }
        let ty = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
        let mseq = u32::from_le_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]);
        if ty == NLMSG_ERROR && mseq == seq && len >= NLMSG_HDRLEN + 4 {
            let p = off + NLMSG_HDRLEN;
            let err = i32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            return Some(if err == 0 { Ok(()) } else { Err(-err) });
        }
        off += (len + 3) & !3;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn attrs(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= body.len() {
            let len = usize::from(u16::from_le_bytes([body[i], body[i + 1]]));
            let ty = u16::from_le_bytes([body[i + 2], body[i + 3]]);
            out.push((ty, body[i + 4..i + len].to_vec()));
            i += (len + 3) & !3;
        }
        out
    }

    #[test]
    fn set_link_carries_mtu_address_and_up() {
        let op = NetlinkOp::SetLink {
            ifindex: 2,
            mac: Some([0x52, 0x54, 0, 0x12, 0x34, 0x56]),
            mtu: Some(1500),
            up: true,
        };
        let m = op.encode(7);
        assert_eq!(
            u32::from_le_bytes(m[0..4].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(u16::from_le_bytes([m[4], m[5]]), RTM_NEWLINK);
        assert_eq!(u16::from_le_bytes([m[6], m[7]]), NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(u32::from_le_bytes(m[8..12].try_into().unwrap()), 7);
        // ifinfomsg: index 2, flags IFF_UP, change IFF_UP.
        assert_eq!(
            &m[16..32],
            &[0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]
        );
        let a = attrs(&m[32..]);
        assert_eq!(a[0], (IFLA_ADDRESS, vec![0x52, 0x54, 0, 0x12, 0x34, 0x56]));
        assert_eq!(a[1], (IFLA_MTU, 1500u32.to_le_bytes().to_vec()));
        assert_eq!(m.len() % 4, 0);
    }

    #[test]
    fn address_has_broadcast_and_lifetimes() {
        let prefix = Prefix::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 24).unwrap();
        let m = NetlinkOp::AddAddress {
            ifindex: 2,
            prefix,
            valid_lft: u32::MAX,
            preferred_lft: 3600,
        }
        .encode(1);
        assert_eq!(u16::from_le_bytes([m[4], m[5]]), RTM_NEWADDR);
        assert_eq!(
            u16::from_le_bytes([m[6], m[7]]),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        );
        assert_eq!(&m[16..24], &[AF_INET, 24, 0, 0, 2, 0, 0, 0]);
        let a = attrs(&m[24..]);
        assert_eq!(a[0], (IFA_LOCAL, vec![192, 168, 1, 100]));
        assert_eq!(a[1], (IFA_ADDRESS, vec![192, 168, 1, 100]));
        assert_eq!(a[2], (IFA_BROADCAST, vec![192, 168, 1, 255]));
        assert_eq!(a[3].0, IFA_CACHEINFO);
        assert_eq!(&a[3].1[0..4], &3600u32.to_le_bytes());
        assert_eq!(&a[3].1[4..8], &u32::MAX.to_le_bytes());
    }

    #[test]
    fn default_route_has_no_destination_attribute() {
        let dest = Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap();
        let m = NetlinkOp::AddRoute {
            ifindex: 2,
            dest,
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            metric: 100,
            prefsrc: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
        }
        .encode(3);
        assert_eq!(u16::from_le_bytes([m[4], m[5]]), RTM_NEWROUTE);
        assert_eq!(
            &m[16..28],
            &[
                AF_INET,
                0,
                0,
                0,
                RT_TABLE_MAIN,
                RTPROT_DHCP,
                0,
                RTN_UNICAST,
                0,
                0,
                0,
                0
            ]
        );
        let types: Vec<u16> = attrs(&m[28..]).iter().map(|(t, _)| *t).collect();
        assert_eq!(
            types,
            [RTA_TABLE, RTA_GATEWAY, RTA_OIF, RTA_PRIORITY, RTA_PREFSRC]
        );
    }

    #[test]
    fn acks_and_errors_are_read() {
        let mut ack = Vec::new();
        ack.extend_from_slice(&36u32.to_le_bytes());
        ack.extend_from_slice(&NLMSG_ERROR.to_le_bytes());
        ack.extend_from_slice(&0u16.to_le_bytes());
        ack.extend_from_slice(&9u32.to_le_bytes());
        ack.extend_from_slice(&0u32.to_le_bytes());
        ack.extend_from_slice(&0i32.to_le_bytes());
        ack.extend_from_slice(&[0; 16]);
        assert_eq!(parse_ack(&ack, 9), Some(Ok(())));
        assert_eq!(parse_ack(&ack, 8), None);
        ack[16..20].copy_from_slice(&(-17i32).to_le_bytes());
        assert_eq!(parse_ack(&ack, 9), Some(Err(17)));
    }
}

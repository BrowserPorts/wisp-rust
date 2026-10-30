//! The machine manager on the netkernel: which NKRPC calls carry a
//! [`ConfigPlan`] (NKRPC SPEC-r2, `work/net-stack/L/nkrpc/SPEC-r2.md`).
//!
//! The manager is an NKRPC client kernel of its own (SPEC-r2 section 0.1,
//! `client_kind` 3 in `HELLO`), with the netkernel's own ABI (wasm32, no
//! translation, section 0.3) and root credentials with a full capability
//! bound (section 7.3). Each plan becomes ordinary Linux system calls in the
//! netkernel's asm-generic numbering (section 0.2):
//!
//! | Step | Call |
//! |---|---|
//! | the interface index | `ioctl(NK_FD_DEVCTL, SIOCGIFINDEX, struct ifreq)` (section 3.7) |
//! | open rtnetlink | `socket(AF_NETLINK, SOCK_RAW \| SOCK_CLOEXEC, NETLINK_ROUTE)` |
//! | extended acks | `setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, 1)` |
//! | each operation | `sendto(fd, msg, len, 0, {AF_NETLINK, pid 0}, 12)`, then `recvfrom(fd, buf, 8192, 0)` for its `NLMSG_ERROR` |
//! | done | `close(fd)` |
//! | each sysctl | `openat(NK_FD_PROCSYSNET, path, O_WRONLY \| O_CLOEXEC)`, `write(fd, value)`, `close(fd)` (section 3.9) |
//!
//! `/etc/resolv.conf` is not the netkernel's: the browser instance writes it
//! into WasmFS's `/etc` image, and gex into its VFS when it attaches.
//!
//! The NKRPC client itself (framing, carriers, the request header of
//! section 1.1) arrives with LS-4 and LS-7. Until then [`NkrpcManager`]
//! computes the calls and reports them as [`NkrpcUnavailable`], so a test
//! can check the script and LS-7 can run it unchanged.

use crate::manager::{ConfigPlan, InterfaceSpec, LinkConfig, MachineManager};

/// asm-generic system-call numbers (the netkernel's numbering).
pub mod nr {
    pub const IOCTL: u32 = 29;
    pub const OPENAT: u32 = 56;
    pub const CLOSE: u32 = 57;
    pub const WRITE: u32 = 64;
    pub const SOCKET: u32 = 198;
    pub const SENDTO: u32 = 206;
    pub const RECVFROM: u32 = 207;
    pub const SETSOCKOPT: u32 = 208;
}

/// NKRPC pseudo descriptors (SPEC-r2 appendix A).
pub const NK_FD_DEVCTL: i64 = -2;
pub const NK_FD_PROCSYSNET: i64 = -4;

pub const AF_NETLINK: i64 = 16;
pub const SOCK_RAW: i64 = 3;
pub const SOCK_CLOEXEC: i64 = 0o2000000;
pub const NETLINK_ROUTE: i64 = 0;
pub const SOL_NETLINK: i64 = 270;
pub const NETLINK_EXT_ACK: i64 = 11;
pub const O_WRONLY: i64 = 0o1;
pub const O_CLOEXEC: i64 = 0o2000000;
pub const SIOCGIFINDEX: i64 = 0x8933;

/// Receive buffer for one acknowledgement (an `NLMSG_ERROR` with the
/// request echoed and extended-ack attributes).
pub const ACK_BUFFER: usize = 8192;

/// A descriptor a call names: one returned by an earlier call of the script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fd {
    /// A pseudo descriptor of SPEC-r2.
    Pseudo(i64),
    /// The result of call number `n` of the script.
    ResultOf(usize),
}

/// One argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Int(i64),
    Fd(Fd),
    /// A readable segment: bytes the call reads (`NK_SEG_R`).
    In(Vec<u8>),
    /// A writable segment of this many bytes (`NK_SEG_W`).
    Out(usize),
    /// A NUL-terminated path in a readable segment.
    Path(String),
    Null,
}

/// One system call of the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NkCall {
    pub name: &'static str,
    pub nr: u32,
    pub args: Vec<Arg>,
}

/// The script exists but no NKRPC session does yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NkrpcUnavailable {
    pub calls: Vec<NkCall>,
}

impl std::fmt::Display for NkrpcUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no NKRPC session (LS-4/LS-7); {} calls were not sent",
            self.calls.len()
        )
    }
}

impl std::error::Error for NkrpcUnavailable {}

/// `struct ifreq` for `SIOCGIFINDEX`: the name, NUL-padded to 16 bytes, and
/// room for the index the kernel writes: 32 bytes on wasm32 (16 for the
/// name, 16 for the union, whose largest member `struct ifmap` is 16 bytes
/// with 32-bit `long`).
pub fn ifreq_for(name: &str) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    let n = name.len().min(15);
    b[..n].copy_from_slice(&name.as_bytes()[..n]);
    b
}

/// `struct sockaddr_nl` for the kernel: family, pad, pid 0, groups 0.
pub fn sockaddr_nl_kernel() -> Vec<u8> {
    let mut b = vec![0u8; 12];
    b[0..2].copy_from_slice(&16u16.to_le_bytes());
    b
}

/// The manager whose calls go to the netkernel over NKRPC.
pub struct NkrpcManager {
    iface: InterfaceSpec,
    current: Option<LinkConfig>,
    seq: u32,
}

impl NkrpcManager {
    pub fn new(iface: InterfaceSpec) -> Self {
        Self {
            iface,
            current: None,
            seq: 1,
        }
    }

    /// The call that finds `eth0`'s index, before the first plan.
    pub fn ifindex_call(name: &str) -> NkCall {
        NkCall {
            name: "ioctl",
            nr: nr::IOCTL,
            args: vec![
                Arg::Fd(Fd::Pseudo(NK_FD_DEVCTL)),
                Arg::Int(SIOCGIFINDEX),
                Arg::In(ifreq_for(name)),
            ],
        }
    }

    /// The system calls that carry out `plan`, in order.
    pub fn calls(&mut self, plan: &ConfigPlan) -> Vec<NkCall> {
        let mut calls = Vec::new();
        if !plan.netlink.is_empty() {
            calls.push(NkCall {
                name: "socket",
                nr: nr::SOCKET,
                args: vec![
                    Arg::Int(AF_NETLINK),
                    Arg::Int(SOCK_RAW | SOCK_CLOEXEC),
                    Arg::Int(NETLINK_ROUTE),
                ],
            });
            let sock = Fd::ResultOf(0);
            calls.push(NkCall {
                name: "setsockopt",
                nr: nr::SETSOCKOPT,
                args: vec![
                    Arg::Fd(sock),
                    Arg::Int(SOL_NETLINK),
                    Arg::Int(NETLINK_EXT_ACK),
                    Arg::In(1i32.to_le_bytes().to_vec()),
                    Arg::Int(4),
                ],
            });
            for op in &plan.netlink {
                let msg = op.encode(self.seq);
                self.seq = self.seq.wrapping_add(1).max(1);
                let len = msg.len() as i64;
                calls.push(NkCall {
                    name: "sendto",
                    nr: nr::SENDTO,
                    args: vec![
                        Arg::Fd(sock),
                        Arg::In(msg),
                        Arg::Int(len),
                        Arg::Int(0),
                        Arg::In(sockaddr_nl_kernel()),
                        Arg::Int(12),
                    ],
                });
                calls.push(NkCall {
                    name: "recvfrom",
                    nr: nr::RECVFROM,
                    args: vec![
                        Arg::Fd(sock),
                        Arg::Out(ACK_BUFFER),
                        Arg::Int(ACK_BUFFER as i64),
                        Arg::Int(0),
                        Arg::Null,
                        Arg::Null,
                    ],
                });
            }
            calls.push(NkCall {
                name: "close",
                nr: nr::CLOSE,
                args: vec![Arg::Fd(sock)],
            });
        }
        for w in &plan.sysctl {
            let open = calls.len();
            calls.push(NkCall {
                name: "openat",
                nr: nr::OPENAT,
                args: vec![
                    Arg::Fd(Fd::Pseudo(NK_FD_PROCSYSNET)),
                    Arg::Path(w.path.clone()),
                    Arg::Int(O_WRONLY | O_CLOEXEC),
                ],
            });
            let value = format!("{}\n", w.value).into_bytes();
            let len = value.len() as i64;
            calls.push(NkCall {
                name: "write",
                nr: nr::WRITE,
                args: vec![Arg::Fd(Fd::ResultOf(open)), Arg::In(value), Arg::Int(len)],
            });
            calls.push(NkCall {
                name: "close",
                nr: nr::CLOSE,
                args: vec![Arg::Fd(Fd::ResultOf(open))],
            });
        }
        calls
    }
}

impl MachineManager for NkrpcManager {
    type Error = NkrpcUnavailable;

    fn interface(&self) -> &InterfaceSpec {
        &self.iface
    }

    fn current(&self) -> Option<&LinkConfig> {
        self.current.as_ref()
    }

    fn set_current(&mut self, config: Option<LinkConfig>) {
        self.current = config;
    }

    fn execute(&mut self, plan: &ConfigPlan) -> Result<(), NkrpcUnavailable> {
        let calls = self.calls(plan);
        if calls.is_empty() {
            return Ok(());
        }
        Err(NkrpcUnavailable { calls })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{plan, LinkConfig, SysctlWrite};
    use wisp_ip::capsule::FOREVER;
    use wisp_ip::{AssignedAddress, LinkParams, Prefix, RouteEntry};

    fn cfg() -> LinkConfig {
        LinkConfig {
            addresses: vec![AssignedAddress {
                prefix: Prefix::new("192.168.1.100".parse().unwrap(), 24).unwrap(),
                valid_lft: FOREVER,
                preferred_lft: FOREVER,
            }],
            routes: vec![RouteEntry {
                dest: Prefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
                gateway: "192.168.1.1".parse().unwrap(),
                metric: 100,
            }],
            link: LinkParams {
                link_mtu: 1500,
                max_packet: 1500,
                max_datagram_payload: 0,
            },
            dns: None,
        }
    }

    fn iface() -> InterfaceSpec {
        InterfaceSpec {
            name: "eth0".to_owned(),
            ifindex: 2,
            mac: [2, 0, 0, 0, 0, 0x64],
        }
    }

    #[test]
    fn a_plan_becomes_netlink_calls_on_one_socket() {
        let mut m = NkrpcManager::new(iface());
        let err = m.configure(&cfg()).unwrap_err();
        let names: Vec<&str> = err.calls.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            [
                "socket",
                "setsockopt",
                "sendto",
                "recvfrom",
                "sendto",
                "recvfrom",
                "sendto",
                "recvfrom",
                "close"
            ]
        );
        assert_eq!(err.calls[0].nr, 198);
        assert_eq!(
            err.calls[0].args,
            [Arg::Int(16), Arg::Int(3 | 0o2000000), Arg::Int(0)]
        );
        // The first sendto carries the RTM_NEWLINK request, sequence 1.
        let Arg::In(msg) = &err.calls[2].args[1] else {
            panic!("sendto carries the message");
        };
        assert_eq!(u16::from_le_bytes([msg[4], msg[5]]), 16);
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 1);
        assert!(m.current().is_none(), "nothing was applied");
    }

    #[test]
    fn sysctls_go_through_the_procsysnet_descriptor() {
        let mut m = NkrpcManager::new(iface());
        let mut p = plan(&iface(), None, None);
        p.sysctl.push(SysctlWrite {
            path: "ipv6/conf/eth0/accept_ra".to_owned(),
            value: "1".to_owned(),
        });
        let calls = m.calls(&p);
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].args[0], Arg::Fd(Fd::Pseudo(-4)));
        assert_eq!(
            calls[0].args[1],
            Arg::Path("ipv6/conf/eth0/accept_ra".to_owned())
        );
        assert_eq!(calls[1].args[1], Arg::In(b"1\n".to_vec()));
        assert_eq!(calls[2].args[0], Arg::Fd(Fd::ResultOf(0)));
    }

    #[test]
    fn the_index_comes_from_devctl() {
        let c = NkrpcManager::ifindex_call("eth0");
        assert_eq!(c.nr, 29);
        assert_eq!(c.args[0], Arg::Fd(Fd::Pseudo(-2)));
        let Arg::In(ifr) = &c.args[2] else { panic!() };
        assert_eq!(&ifr[..5], b"eth0\0");
        assert_eq!(ifr.len(), 32);
    }
}

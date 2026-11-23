//! The Linux backend: one network namespace per tunnel (decision LD3).
//!
//! ```text
//!   client ── wisp ──> relay ── TUN tun0 (192.168.1.1/24) ┐
//!                            [namespace <prefix>-<id>]    ├─ forward, nft "inet wisp", masquerade
//!                              eth0 (10.231.x.2/30) ──────┘
//!                                │ veth
//!   relay namespace:           wtv<id> (10.231.x.1/30) ── nft "inet wisp_tun", masquerade ── egress
//! ```
//!
//! Every tunnel can be given the same LAN, the kernel routes and translates
//! (TTL, Time Exceeded, ICMP errors, conntrack per namespace), and tunnels
//! cannot reach each other. A routed IPv6 prefix, when the tunnel has one, is
//! routed to the namespace over the veth's link-local addresses without NAT.
//!
//! The TUN device is created in the relay's namespace and then moved into the
//! tunnel's; its descriptor keeps working there. Setup runs `ip` and `nft`;
//! teardown deletes the namespace, which takes the veth pair with it, after
//! the TUN descriptor is closed.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::backend::{Backend, BackendError, Device, DeviceGuard, NetworkPlan, DEVICE_QUEUE};
use crate::config::{TunnelConfig, IPV6_GATEWAY_LINK_LOCAL};
use crate::nft;
use crate::tun_fd::TunFd;

/// Host-side link-local address of every veth, the namespace's IPv6 next hop.
const HOST_LINK_LOCAL: &str = "fe80::1";
/// Namespace-side link-local address of every veth.
const NS_LINK_LOCAL: &str = "fe80::2";

pub struct NetnsBackend {
    cfg: Arc<TunnelConfig>,
    slots: Arc<Mutex<SlotPool>>,
}

struct SlotPool {
    next: u32,
    size: u32,
    free: BTreeSet<u32>,
}

impl SlotPool {
    fn take(&mut self) -> Option<u32> {
        if let Some(s) = self.free.pop_first() {
            return Some(s);
        }
        (self.next < self.size).then(|| {
            self.next += 1;
            self.next - 1
        })
    }
}

/// Runs `program args`, feeding `stdin` when given; the error carries the
/// program's own message.
async fn run(program: &str, args: &[&str], stdin: Option<&str>) -> Result<(), BackendError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| BackendError::Setup(format!("{program}: {e}")))?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(input.as_bytes())
            .await
            .map_err(|e| BackendError::Setup(format!("{program}: {e}")))?;
        drop(pipe);
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| BackendError::Setup(format!("{program}: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(BackendError::Setup(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// `ip [-n ns] -batch -` with one command per line.
async fn ip_batch(netns: Option<&str>, lines: &[String]) -> Result<(), BackendError> {
    let script = lines.join("\n") + "\n";
    match netns {
        Some(ns) => run("ip", &["-n", ns, "-batch", "-"], Some(&script)).await,
        None => run("ip", &["-batch", "-"], Some(&script)).await,
    }
}

impl NetnsBackend {
    /// Checks privileges, removes namespaces an earlier run left behind,
    /// turns forwarding on and installs the relay's own table.
    pub async fn start(cfg: Arc<TunnelConfig>) -> Result<Arc<Self>, BackendError> {
        crate::privileges::check().map_err(BackendError::Unavailable)?;
        Self::remove_stale(&cfg.netns_prefix).await;
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| BackendError::Setup(format!("net.ipv4.ip_forward: {e}")))?;
        if cfg.ipv6_pool.is_some() {
            std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
                .map_err(|e| BackendError::Setup(format!("net.ipv6.conf.all.forwarding: {e}")))?;
        }
        run("nft", &["-f", "-"], Some(&nft::host_ruleset(&cfg))).await?;
        let slots = Arc::new(Mutex::new(SlotPool {
            next: 0,
            size: nft::transit_slots(cfg.transit),
            free: BTreeSet::new(),
        }));
        Ok(Arc::new(Self { cfg, slots }))
    }

    async fn remove_stale(prefix: &str) {
        let Ok(out) = Command::new("ip")
            .args(["netns", "list"])
            .stderr(Stdio::null())
            .output()
            .await
        else {
            return;
        };
        let wanted = format!("{prefix}-");
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let name = line.split_whitespace().next().unwrap_or("");
            if name.starts_with(&wanted) && name[wanted.len()..].bytes().all(|b| b.is_ascii_digit())
            {
                tracing::info!(
                    netns = name,
                    "wisp-tun: removing a namespace left by an earlier run"
                );
                let _ = run("ip", &["netns", "del", name], None).await;
            }
        }
        // Host ends of veth pairs whose namespaces are already gone.
        if let Ok(links) = std::fs::read_dir("/sys/class/net") {
            for link in links.flatten() {
                let name = link.file_name().to_string_lossy().into_owned();
                if let Some(id) = name.strip_prefix("wtv") {
                    if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) {
                        let _ = run("ip", &["link", "del", &name], None).await;
                    }
                }
            }
        }
    }

    /// Removes the relay's own table, for an orderly shutdown and for tests.
    pub async fn stop(&self) -> Result<(), BackendError> {
        run("nft", &["delete", "table", "inet", "wisp_tun"], None).await
    }

    async fn build(&self, plan: &NetworkPlan, slot: u32) -> Result<TunFd, BackendError> {
        let id = plan.id;
        let ns = format!("{}-{id}", self.cfg.netns_prefix);
        let host_if = format!("wtv{id}");
        let peer_if = format!("wtp{id}");
        let tun_if = format!("wtt{id}");
        let (host_addr, ns_addr) = nft::transit_pair(self.cfg.transit, slot);
        let lan_len = plan.lan.1;

        // A host link of this name can only be left over from a namespace
        // whose teardown has not finished.
        if std::path::Path::new(&format!("/sys/class/net/{host_if}")).exists() {
            let _ = run("ip", &["link", "del", &host_if], None).await;
        }
        run("ip", &["netns", "add", &ns], None).await?;
        let tun =
            TunFd::open(&tun_if).map_err(|e| BackendError::Setup(format!("TUN {tun_if}: {e}")))?;

        let mut host = vec![
            format!("link add {host_if} type veth peer name {peer_if} netns {ns}"),
            format!("link set {tun_if} netns {ns}"),
            format!("addr add {host_addr}/30 dev {host_if}"),
        ];
        if plan.ipv6.is_some() {
            host.push(format!("addr add {HOST_LINK_LOCAL}/64 dev {host_if} nodad"));
        }
        host.push(format!("link set {host_if} up"));
        if let Some((p, len)) = plan.ipv6 {
            host.push(format!(
                "route add {p}/{len} via {NS_LINK_LOCAL} dev {host_if}"
            ));
        }
        ip_batch(None, &host).await?;

        let mut sysctl = vec![
            "netns",
            "exec",
            &ns,
            "sysctl",
            "-q",
            "-w",
            "net.ipv4.ip_forward=1",
            "net.ipv6.conf.all.accept_ra=0",
            "net.ipv6.conf.default.accept_ra=0",
            "net.ipv6.conf.default.accept_dad=0",
        ];
        if plan.ipv6.is_some() {
            sysctl.push("net.ipv6.conf.all.forwarding=1");
        } else {
            // An IPv4-only tunnel's link carries no IPv6 at all, not even the
            // kernel's own MLD reports.
            sysctl.push("net.ipv6.conf.all.disable_ipv6=1");
            sysctl.push("net.ipv6.conf.default.disable_ipv6=1");
        }
        run("ip", &sysctl, None).await?;

        let mut inner = vec![
            "link set lo up".to_owned(),
            format!("link set {peer_if} name {}", nft::NS_UPLINK),
            format!("addr add {ns_addr}/30 dev {}", nft::NS_UPLINK),
        ];
        if plan.ipv6.is_some() {
            inner.push(format!(
                "addr add {NS_LINK_LOCAL}/64 dev {} nodad",
                nft::NS_UPLINK
            ));
        }
        inner.push(format!("link set {} up", nft::NS_UPLINK));
        inner.push(format!("link set {tun_if} name {}", nft::NS_TUN));
        inner.push(format!("link set {} mtu {}", nft::NS_TUN, plan.link_mtu));
        inner.push(format!(
            "addr add {}/{lan_len} dev {}",
            plan.gateway4,
            nft::NS_TUN
        ));
        if let (Some((_, len)), Some(gw)) = (plan.ipv6, plan.gateway6()) {
            inner.push(format!("addr add {gw}/{len} dev {} nodad", nft::NS_TUN));
            inner.push(format!(
                "addr add {IPV6_GATEWAY_LINK_LOCAL}/64 dev {} nodad",
                nft::NS_TUN
            ));
        }
        inner.push(format!("link set {} up", nft::NS_TUN));
        inner.push(format!(
            "route add default via {host_addr} dev {}",
            nft::NS_UPLINK
        ));
        if plan.ipv6.is_some() {
            inner.push(format!(
                "route add ::/0 via {HOST_LINK_LOCAL} dev {}",
                nft::NS_UPLINK
            ));
        }
        ip_batch(Some(&ns), &inner).await?;

        run(
            "ip",
            &["netns", "exec", &ns, "nft", "-f", "-"],
            Some(&nft::tunnel_ruleset(&self.cfg, plan)),
        )
        .await?;
        Ok(tun)
    }
}

/// Owns one tunnel's namespace: closes the TUN and deletes the namespace
/// when dropped.
struct Namespace {
    name: String,
    host_if: String,
    stop: CancellationToken,
    slot: u32,
    slots: Arc<Mutex<SlotPool>>,
}

impl Drop for Namespace {
    fn drop(&mut self) {
        self.stop.cancel();
        let name = std::mem::take(&mut self.name);
        let host_if = std::mem::take(&mut self.host_if);
        let slot = self.slot;
        let slots = self.slots.clone();
        // Deleting the host end of the veth takes both ends at once; the
        // namespace itself is destroyed by the kernel in the background.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    // Let the I/O tasks drop the TUN descriptor first.
                    tokio::task::yield_now().await;
                    let _ = run("ip", &["link", "del", &host_if], None).await;
                    if let Err(e) = run("ip", &["netns", "del", &name], None).await {
                        tracing::warn!(netns = %name, error = %e, "wisp-tun: namespace teardown failed");
                    }
                    slots.lock().free.insert(slot);
                });
            }
            Err(_) => {
                for args in [["link", "del", &host_if], ["netns", "del", &name]] {
                    let _ = std::process::Command::new("ip")
                        .args(args)
                        .stderr(Stdio::null())
                        .status();
                }
                slots.lock().free.insert(slot);
            }
        }
    }
}

#[async_trait]
impl Backend for NetnsBackend {
    async fn create(&self, plan: NetworkPlan) -> Result<Device, BackendError> {
        let slot = self.slots.lock().take().ok_or(BackendError::Exhausted)?;
        let ns = format!("{}-{}", self.cfg.netns_prefix, plan.id);
        let tun = match self.build(&plan, slot).await {
            Ok(tun) => Arc::new(tun),
            Err(e) => {
                let _ = run("ip", &["netns", "del", &ns], None).await;
                self.slots.lock().free.insert(slot);
                return Err(e);
            }
        };
        let stop = CancellationToken::new();
        let (to_network, mut outbound) = mpsc::channel::<Bytes>(DEVICE_QUEUE);
        let (inbound, from_network) = mpsc::channel::<Bytes>(DEVICE_QUEUE);

        let reader = tun.clone();
        let reader_stop = stop.clone();
        let mtu = usize::from(plan.max_packet.max(plan.link_mtu));
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 64];
            loop {
                tokio::select! {
                    _ = reader_stop.cancelled() => return,
                    read = reader.read(&mut buf) => match read {
                        Ok(0) => return,
                        Ok(n) => {
                            // A full queue drops, as a congested link does.
                            if let Err(mpsc::error::TrySendError::Closed(_)) =
                                inbound.try_send(Bytes::copy_from_slice(&buf[..n]))
                            {
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "wisp-tun: TUN read failed");
                            return;
                        }
                    },
                }
            }
        });
        let writer = tun;
        let writer_stop = stop.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = writer_stop.cancelled() => return,
                    packet = outbound.recv() => {
                        let Some(packet) = packet else { return };
                        if let Err(e) = writer.write(&packet).await {
                            tracing::debug!(error = %e, "wisp-tun: TUN write failed");
                        }
                    }
                }
            }
        });
        tracing::debug!(netns = %ns, slot, "wisp-tun: tunnel namespace ready");
        Ok(Device {
            to_network,
            from_network,
            guard: DeviceGuard::new(Namespace {
                name: ns,
                host_if: format!("wtv{}", plan.id),
                stop,
                slot,
                slots: self.slots.clone(),
            }),
        })
    }

    fn name(&self) -> &'static str {
        "netns"
    }
}

/// The address the relay's side of transit slot `slot` holds, for tests
/// that check routing.
pub fn host_transit_address(cfg: &TunnelConfig, slot: u32) -> Ipv4Addr {
    nft::transit_pair(cfg.transit, slot).0
}

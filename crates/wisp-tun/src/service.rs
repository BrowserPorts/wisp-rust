//! The process-wide tunnel engine and the per-tunnel packet path.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use rand::RngCore;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wisp_config::TunnelReject;
use wisp_dos::{
    is_tunnel_flow_open_allowed, is_tunnel_packet_allowed, ConnectionDosGuard, DosGuard,
};
use wisp_ip::capsule::{error_code, want, FOREVER};
use wisp_ip::info::flags;
use wisp_ip::packet::{proto, Fragment, PacketInfo};
use wisp_ip::{
    close_reason, inspect, AssignedAddress, Capsule, DnsConfig, LinkParams, Negotiated, Prefix,
    ResumeToken, RouteEntry,
};
use wisp_proxy::HostPolicy;

use crate::backend::{Backend, Device, DeviceGuard, NetworkPlan};
use crate::config::{TunnelConfig, DEFAULT_ROUTE_METRIC, IPV6_GATEWAY_LINK_LOCAL};
use crate::flow::{related_outbound, Flow, FlowKey, FlowTable};
use crate::icmp;
use crate::policy::{self, Verdict};
use crate::resume::ResumeStore;

/// How long a resume waits for the connection that still holds the tunnel
/// to let go of it.
const STEAL_WAIT: Duration = Duration::from_secs(2);

/// Answers to refused packets queued towards the client.
const REPLY_QUEUE: usize = 64;

const ATTRIBUTION: &str = "wisp_tun::attribution";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpenError {
    #[error("this credential may not open tunnels")]
    Blocked,
    #[error("no address family the client asked for is offered")]
    FamilyNotOffered,
    #[error("too many tunnels")]
    TooMany,
    #[error("no address left for another tunnel")]
    NoAddress,
    #[error("tunnel network: {0}")]
    Network(String),
}

impl OpenError {
    /// The Wisp close reason the refusal is sent with.
    pub fn close_reason(&self) -> u8 {
        match self {
            OpenError::Blocked => close_reason::BLOCKED,
            OpenError::FamilyNotOffered | OpenError::NoAddress => close_reason::INVALID_INFO,
            OpenError::TooMany => close_reason::THROTTLED,
            OpenError::Network(_) => close_reason::NETWORK_ERROR,
        }
    }

    /// The informative ERROR capsule sent before the close, when the
    /// extension has a code for the refusal.
    pub fn error_capsule(&self) -> Option<Capsule> {
        let code = match self {
            OpenError::FamilyNotOffered => error_code::FAMILY_NOT_OFFERED,
            OpenError::TooMany => error_code::TOO_MANY_TUNNELS,
            OpenError::NoAddress => error_code::NO_ADDRESS,
            OpenError::Blocked | OpenError::Network(_) => return None,
        };
        Some(Capsule::Error {
            code,
            message: self.to_string(),
        })
    }
}

/// One OPEN, as the transport parsed it.
#[derive(Clone)]
pub struct OpenRequest {
    /// The OPEN capsule's `want` bits.
    pub want: u16,
    /// The RESUME capsule's token, if the OPEN carried one.
    pub resume: Option<ResumeToken>,
    /// Who the connection authenticated as; resume tokens are bound to it.
    pub principal: Option<String>,
    pub client_ip: String,
    /// The connection's destination policy (its credential's).
    pub policy: Arc<HostPolicy>,
    pub negotiated: Negotiated,
    /// The LINK capsule's datagram payload: 0 on the WebSocket binding.
    pub max_datagram_payload: u16,
}

/// A tunnel that is open, with the capsules of its open confirmation.
pub struct Opened {
    pub tunnel: Tunnel,
    pub confirmation: Vec<Capsule>,
    /// The tunnel existed before: a resume.
    pub resumed: bool,
}

/// Why a packet was not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    RateLimited,
    TooLarge,
    Malformed,
    /// The source is not one of the tunnel's addresses.
    Spoofed,
    /// Link-local, multicast, neighbour discovery or another protocol.
    NotForwarded,
    /// A fragment or ICMP error that belongs to no flow of the tunnel.
    NoFlow,
    /// The tunnel already holds its maximum of live flows.
    FlowLimit,
    /// The tunnel started too many flows this minute.
    FlowRate,
    /// The network's queue was full.
    Congested,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Forwarded,
    /// The destination policy refused a new flow; any answer is queued to
    /// the client.
    Refused,
    Dropped(DropReason),
}

/// Routed IPv6 prefixes handed out one per tunnel.
struct V6Pool {
    base: u128,
    shift: u32,
    size: u64,
    next: u64,
    free: BTreeSet<u64>,
}

impl V6Pool {
    fn new(base: Ipv6Addr, base_len: u8, tunnel_len: u8) -> Self {
        let bits = u32::from(tunnel_len - base_len).min(32);
        Self {
            base: u128::from(base),
            shift: 128 - u32::from(tunnel_len),
            size: 1u64 << bits,
            next: 0,
            free: BTreeSet::new(),
        }
    }

    fn take(&mut self) -> Option<u64> {
        if let Some(i) = self.free.pop_first() {
            return Some(i);
        }
        (self.next < self.size).then(|| {
            self.next += 1;
            self.next - 1
        })
    }

    fn prefix(&self, index: u64) -> Ipv6Addr {
        Ipv6Addr::from(self.base | (u128::from(index) << self.shift))
    }
}

/// The process-wide tunnel engine. One per relay; both transports open their
/// tunnels through it.
pub struct TunnelService {
    cfg: Arc<TunnelConfig>,
    backend: Arc<dyn Backend>,
    dos: Arc<DosGuard>,
    store: Arc<ResumeStore>,
    live: Arc<AtomicU32>,
    next_id: AtomicU64,
    v6: Option<Arc<Mutex<V6Pool>>>,
}

impl TunnelService {
    pub fn new(cfg: TunnelConfig, backend: Arc<dyn Backend>, dos: Arc<DosGuard>) -> Arc<Self> {
        let v6 = cfg
            .ipv6_pool
            .map(|(base, len)| Arc::new(Mutex::new(V6Pool::new(base, len, cfg.ipv6_tunnel_len))));
        tracing::info!(
            backend = backend.name(),
            lan = %cfg.lan,
            ipv6 = cfg.ipv6_pool.is_some(),
            "wisp-tun: IP tunnels enabled"
        );
        Arc::new(Self {
            cfg: Arc::new(cfg),
            backend,
            dos,
            store: Arc::new(ResumeStore::default()),
            live: Arc::new(AtomicU32::new(0)),
            next_id: AtomicU64::new(1),
            v6,
        })
    }

    pub fn config(&self) -> &TunnelConfig {
        &self.cfg
    }

    /// Tunnels open or waiting to be resumed.
    pub fn live_tunnels(&self) -> u32 {
        self.live.load(Ordering::Relaxed)
    }

    /// Opens a tunnel, or resumes one when the request carries a valid
    /// token. An invalid token yields a new tunnel whose confirmation carries
    /// an informative ERROR (resume token rejected).
    pub async fn open(&self, req: OpenRequest) -> Result<Opened, OpenError> {
        if req.policy.domain_whitelist.is_some() {
            return Err(OpenError::Blocked);
        }
        let resume_on = self.cfg.resume_enabled() && req.negotiated.has(flags::RESUME);
        let mut resume_rejected = false;
        if let Some(token) = req.resume {
            if resume_on {
                if let Some(tunnel) = self
                    .store
                    .take(&token, req.principal.as_deref(), STEAL_WAIT)
                    .await
                {
                    return Ok(self.reattach(tunnel, &req));
                }
            }
            resume_rejected = true;
        }

        let want_v4 = req.want & want::IPV4 != 0 && req.negotiated.has(flags::IPV4);
        let want_v6 =
            req.want & want::IPV6 != 0 && req.negotiated.has(flags::IPV6) && self.v6.is_some();
        if !want_v4 && !want_v6 {
            return Err(OpenError::FamilyNotOffered);
        }
        if self.live.fetch_add(1, Ordering::AcqRel) >= self.cfg.max_tunnels_total {
            self.live.fetch_sub(1, Ordering::AcqRel);
            return Err(OpenError::TooMany);
        }
        let mut lease = Lease {
            v4: want_v4,
            v6: None,
            live: self.live.clone(),
        };
        if want_v6 {
            let pool = self.v6.as_ref().expect("checked above");
            let index = pool.lock().take().ok_or(OpenError::NoAddress)?;
            let prefix = pool.lock().prefix(index);
            lease.v6 = Some(V6Lease {
                prefix,
                len: self.cfg.ipv6_tunnel_len,
                index,
                pool: pool.clone(),
            });
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let plan = NetworkPlan {
            id,
            lan: match self.cfg.lan.network() {
                IpAddr::V4(n) => (n, self.cfg.lan.len()),
                IpAddr::V6(_) => unreachable!("the LAN is IPv4"),
            },
            gateway4: self.cfg.gateway4,
            client4: self.cfg.client4,
            ipv6: lease.v6.as_ref().map(|v| (v.prefix, v.len)),
            link_mtu: self.cfg.link_mtu,
            max_packet: self.cfg.max_packet,
            max_flows: self.cfg.max_flows,
            dns_servers: self.cfg.dns_servers.clone(),
        };
        let device = self
            .backend
            .create(plan)
            .await
            .map_err(|e| OpenError::Network(e.to_string()))?;
        let token = resume_on.then(random_token);
        let tunnel = Tunnel::new(id, self, lease, device, &req, token);
        if let Some(token) = token {
            self.store
                .attach(token, req.principal.clone(), tunnel.steal.clone());
        }
        tracing::info!(
            target: ATTRIBUTION,
            tunnel = id,
            principal = req.principal.as_deref().unwrap_or("-"),
            client_ip = %req.client_ip,
            ipv4 = want_v4,
            ipv6 = ?tunnel.shared.lease.v6.as_ref().map(|v| v.prefix),
            "tunnel opened"
        );
        let mut confirmation = tunnel.confirmation(&req);
        if resume_rejected {
            confirmation.push(Capsule::Error {
                code: error_code::RESUME_REJECTED,
                message: "resume token rejected; this is a new tunnel".to_owned(),
            });
        }
        Ok(Opened {
            tunnel,
            confirmation,
            resumed: false,
        })
    }

    fn reattach(&self, mut tunnel: Tunnel, req: &OpenRequest) -> Opened {
        {
            let mut attach = tunnel.shared.attach.lock();
            attach.client_ip = req.client_ip.clone();
            attach.policy = req.policy.clone();
        }
        let token = random_token();
        *tunnel.shared.token.lock() = Some(token);
        tunnel.steal = CancellationToken::new();
        self.store
            .attach(token, req.principal.clone(), tunnel.steal.clone());
        tracing::info!(
            target: ATTRIBUTION,
            tunnel = tunnel.id(),
            principal = req.principal.as_deref().unwrap_or("-"),
            client_ip = %req.client_ip,
            "tunnel resumed"
        );
        let confirmation = tunnel.confirmation(req);
        Opened {
            tunnel,
            confirmation,
            resumed: true,
        }
    }
}

fn random_token() -> ResumeToken {
    let mut token = [0u8; wisp_ip::capsule::TOKEN_LEN];
    rand::thread_rng().fill_bytes(&mut token);
    token
}

struct V6Lease {
    prefix: Ipv6Addr,
    len: u8,
    index: u64,
    pool: Arc<Mutex<V6Pool>>,
}

impl V6Lease {
    fn gateway(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.prefix) | 1)
    }

    fn client(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.prefix) | 0x100)
    }
}

/// What a tunnel holds: its address families and its share of the limits.
/// Released when the tunnel ends.
struct Lease {
    v4: bool,
    v6: Option<V6Lease>,
    live: Arc<AtomicU32>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(v6) = &self.v6 {
            v6.pool.lock().free.insert(v6.index);
        }
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Attachment {
    client_ip: String,
    policy: Arc<HostPolicy>,
}

struct Shared {
    id: u64,
    cfg: Arc<TunnelConfig>,
    lease: Lease,
    principal: Option<String>,
    attach: Mutex<Attachment>,
    flows: Mutex<FlowTable>,
    to_network: mpsc::Sender<Bytes>,
    replies: mpsc::Sender<Bytes>,
    meter: ConnectionDosGuard,
    dos: Arc<DosGuard>,
    token: Mutex<Option<ResumeToken>>,
    store: Arc<ResumeStore>,
    _device: DeviceGuard,
}

/// One open tunnel, owned by the task that delivers its packets to the
/// client. [`TunnelHandle`]s let the connection's reader feed it.
pub struct Tunnel {
    shared: Arc<Shared>,
    from_network: mpsc::Receiver<Bytes>,
    replies_rx: mpsc::Receiver<Bytes>,
    steal: CancellationToken,
}

/// The client-to-network side of a tunnel, cheap to clone.
#[derive(Clone)]
pub struct TunnelHandle(Arc<Shared>);

impl Tunnel {
    fn new(
        id: u64,
        service: &TunnelService,
        lease: Lease,
        device: Device,
        req: &OpenRequest,
        token: Option<ResumeToken>,
    ) -> Self {
        let (replies, replies_rx) = mpsc::channel(REPLY_QUEUE);
        let shared = Arc::new(Shared {
            id,
            cfg: service.cfg.clone(),
            lease,
            principal: req.principal.clone(),
            attach: Mutex::new(Attachment {
                client_ip: req.client_ip.clone(),
                policy: req.policy.clone(),
            }),
            flows: Mutex::new(FlowTable::new(service.cfg.max_flows as usize)),
            to_network: device.to_network,
            replies,
            meter: ConnectionDosGuard::new(),
            dos: service.dos.clone(),
            token: Mutex::new(token),
            store: service.store.clone(),
            _device: device.guard,
        });
        Self {
            shared,
            from_network: device.from_network,
            replies_rx,
            steal: CancellationToken::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.shared.id
    }

    pub fn handle(&self) -> TunnelHandle {
        TunnelHandle(self.shared.clone())
    }

    /// The next packet for the client: an answer to a refused packet, or a
    /// packet from the network that belongs to one of the tunnel's flows.
    pub async fn recv(&mut self) -> Option<Bytes> {
        loop {
            tokio::select! {
                biased;
                Some(reply) = self.replies_rx.recv() => return Some(reply),
                packet = self.from_network.recv() => {
                    let packet = packet?;
                    if self.shared.admit_inbound(&packet) {
                        return Some(packet);
                    }
                }
            }
        }
    }

    /// Resolves when another connection resumes this tunnel. The holder then
    /// stops delivering it and calls [`Tunnel::detach`]. The future does not
    /// borrow the tunnel, so it can wait beside [`Tunnel::recv`].
    pub fn stolen(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        self.steal.clone().cancelled_owned()
    }

    /// Ends the tunnel now: a CLOSE from either side.
    pub fn close(self) {
        if let Some(token) = self.shared.token.lock().take() {
            self.shared.store.forget(&token);
        }
    }

    /// The connection ended without closing the tunnel: keep it for the
    /// resume grace period when it has a token, else end it.
    pub fn detach(self) {
        let token = *self.shared.token.lock();
        match token {
            Some(token) if self.shared.cfg.resume_enabled() => {
                let store = self.shared.store.clone();
                let grace = self.shared.cfg.resume_grace;
                tracing::debug!(tunnel = self.id(), "wisp-tun: tunnel parked for resume");
                store.park(token, self, grace);
            }
            _ => self.close(),
        }
    }

    fn confirmation(&self, req: &OpenRequest) -> Vec<Capsule> {
        let s = &self.shared;
        let cfg = &s.cfg;
        let mut addresses = Vec::new();
        let mut routes = Vec::new();
        if s.lease.v4 {
            addresses.push(AssignedAddress {
                prefix: Prefix::new(IpAddr::V4(cfg.client4), cfg.lan.len())
                    .expect("a valid LAN length"),
                valid_lft: FOREVER,
                preferred_lft: FOREVER,
            });
            routes.push(RouteEntry {
                dest: Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).expect("/0"),
                gateway: IpAddr::V4(cfg.gateway4),
                metric: DEFAULT_ROUTE_METRIC,
            });
        }
        if let Some(v6) = &s.lease.v6 {
            addresses.push(AssignedAddress {
                prefix: Prefix::new(IpAddr::V6(v6.client()), v6.len).expect("a valid length"),
                valid_lft: FOREVER,
                preferred_lft: FOREVER,
            });
            routes.push(RouteEntry {
                dest: Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).expect("/0"),
                gateway: IpAddr::V6(IPV6_GATEWAY_LINK_LOCAL),
                metric: DEFAULT_ROUTE_METRIC,
            });
        }
        let mut out = vec![
            Capsule::AddressAssign(addresses),
            Capsule::RouteAdvertisement(routes),
            Capsule::Link(LinkParams {
                link_mtu: cfg.link_mtu,
                max_packet: cfg.max_packet,
                max_datagram_payload: req.max_datagram_payload,
            }),
        ];
        if !cfg.dns_servers.is_empty() || !cfg.dns_search.is_empty() {
            out.push(Capsule::DnsConfig(DnsConfig {
                servers: cfg.dns_servers.clone(),
                search: cfg.dns_search.clone(),
            }));
        }
        if let Some(token) = *s.token.lock() {
            out.push(Capsule::ResumeToken {
                grace_s: cfg.resume_grace.as_secs().min(u64::from(u32::MAX)) as u32,
                token,
            });
        }
        out
    }
}

impl TunnelHandle {
    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// Takes one packet the client sent. Never blocks: a packet that cannot
    /// be forwarded at once is dropped, as a router drops it.
    pub fn forward(&self, packet: Bytes) -> Outcome {
        self.0.forward(packet)
    }
}

impl Shared {
    fn forward(&self, packet: Bytes) -> Outcome {
        let (client_ip, policy) = {
            let a = self.attach.lock();
            (a.client_ip.clone(), a.policy.clone())
        };
        if !is_tunnel_packet_allowed(
            &client_ip,
            &self.meter,
            &self.cfg.limits,
            packet.len() as u64,
            &self.dos,
        ) {
            return Outcome::Dropped(DropReason::RateLimited);
        }
        if packet.len() > usize::from(self.cfg.max_packet) {
            return Outcome::Dropped(DropReason::TooLarge);
        }
        let Ok(info) = inspect(&packet) else {
            return Outcome::Dropped(DropReason::Malformed);
        };
        if !self.source_ok(info.src) {
            if info.src.is_ipv6() && self.cfg.reject != TunnelReject::Drop {
                if let Some(from) = self.reply_source(&info) {
                    self.reply(icmp::unreachable(
                        &packet,
                        &info,
                        from,
                        icmp::V6_SOURCE_FAILED,
                    ));
                }
            }
            return Outcome::Dropped(DropReason::Spoofed);
        }
        let now = Instant::now();
        {
            let mut flows = self.flows.lock();
            let expired = flows.maybe_sweep(now);
            self.log_closed(&expired);
            if let Some(related) = related_outbound(&flows, &info) {
                if !related {
                    return Outcome::Dropped(DropReason::NoFlow);
                }
            } else {
                let key = FlowKey::outbound(&info);
                if !flows.touch_out(&key, &info, packet.len(), now) {
                    let to_gateway = self.is_gateway(info.dst);
                    match policy::new_flow(&self.cfg, &policy, &info, to_gateway) {
                        Verdict::Forward => {}
                        Verdict::Drop(_) => return Outcome::Dropped(DropReason::NotForwarded),
                        Verdict::Refuse(why) => {
                            drop(flows);
                            tracing::debug!(
                                tunnel = self.id,
                                proto = info.protocol,
                                dst = %info.dst,
                                dport = info.dst_port,
                                why,
                                "wisp-tun: flow refused"
                            );
                            self.refuse(&packet, &info);
                            return Outcome::Refused;
                        }
                    }
                    let (room, expired) = flows.make_room(now);
                    self.log_closed(&expired);
                    if !room {
                        return Outcome::Dropped(DropReason::FlowLimit);
                    }
                    if !is_tunnel_flow_open_allowed(&self.meter, &self.cfg.limits) {
                        return Outcome::Dropped(DropReason::FlowRate);
                    }
                    flows.insert(key, packet.len(), now);
                    tracing::info!(
                        target: ATTRIBUTION,
                        tunnel = self.id,
                        principal = self.principal.as_deref().unwrap_or("-"),
                        client_ip = %client_ip,
                        proto = info.protocol,
                        src = %info.src,
                        sport = info.src_port,
                        dst = %info.dst,
                        dport = info.dst_port,
                        "flow opened"
                    );
                }
            }
        }
        match self.to_network.try_send(packet) {
            Ok(()) => Outcome::Forwarded,
            Err(mpsc::error::TrySendError::Full(_)) => Outcome::Dropped(DropReason::Congested),
            Err(mpsc::error::TrySendError::Closed(_)) => Outcome::Dropped(DropReason::Closed),
        }
    }

    /// A packet from the network goes to the client only when it answers one
    /// of the tunnel's flows, is an ICMP error about one, or comes from the
    /// gateway itself.
    fn admit_inbound(&self, packet: &[u8]) -> bool {
        let Ok(info) = inspect(packet) else {
            return false;
        };
        if !self.is_client_address(info.dst) {
            return false;
        }
        if self.is_gateway(info.src) {
            return true;
        }
        let now = Instant::now();
        let mut flows = self.flows.lock();
        if info.fragment == Fragment::Later {
            return flows.has_pair(info.protocol, info.dst, info.src);
        }
        if info.is_icmp_error() {
            return info
                .quoted
                .is_some_and(|q| flows.contains(&FlowKey::quoted_outbound(&q)));
        }
        flows.touch_in(&FlowKey::inbound(&info), &info, packet.len(), now)
    }

    fn source_ok(&self, src: IpAddr) -> bool {
        match src {
            IpAddr::V4(v4) => {
                let lan = self.cfg.lan;
                let host_bits = u32::MAX >> lan.len();
                let raw = u32::from(v4);
                self.lease.v4
                    && lan.contains(src)
                    && v4 != self.cfg.gateway4
                    && raw & host_bits != 0
                    && raw & host_bits != host_bits
            }
            IpAddr::V6(v6) => self.lease.v6.as_ref().is_some_and(|l| {
                Prefix::new(IpAddr::V6(l.prefix), l.len).is_some_and(|p| p.contains(src))
                    && v6 != l.gateway()
                    && v6 != l.prefix
            }),
        }
    }

    fn is_client_address(&self, dst: IpAddr) -> bool {
        match dst {
            IpAddr::V4(v4) => {
                self.lease.v4 && self.cfg.lan.contains(dst) && v4 != self.cfg.gateway4
            }
            IpAddr::V6(_) => self.lease.v6.as_ref().is_some_and(|l| {
                Prefix::new(IpAddr::V6(l.prefix), l.len).is_some_and(|p| p.contains(dst))
            }),
        }
    }

    fn is_gateway(&self, src: IpAddr) -> bool {
        match src {
            IpAddr::V4(v4) => v4 == self.cfg.gateway4,
            IpAddr::V6(v6) => {
                v6 == IPV6_GATEWAY_LINK_LOCAL
                    || self.lease.v6.as_ref().is_some_and(|l| v6 == l.gateway())
            }
        }
    }

    fn reply_source(&self, info: &PacketInfo) -> Option<IpAddr> {
        match info.src {
            IpAddr::V4(_) => Some(IpAddr::V4(self.cfg.gateway4)),
            IpAddr::V6(_) => Some(IpAddr::V6(
                self.lease
                    .v6
                    .as_ref()
                    .map_or(IPV6_GATEWAY_LINK_LOCAL, V6Lease::gateway),
            )),
        }
    }

    fn refuse(&self, packet: &[u8], info: &PacketInfo) {
        let answer = match self.cfg.reject {
            TunnelReject::Drop => None,
            TunnelReject::Reset if info.protocol == proto::TCP => icmp::tcp_reset(packet, info),
            TunnelReject::Icmp | TunnelReject::Reset => {
                let code = if info.is_ipv4() {
                    icmp::V4_ADMIN_PROHIBITED
                } else {
                    icmp::V6_ADMIN_PROHIBITED
                };
                self.reply_source(info)
                    .and_then(|from| icmp::unreachable(packet, info, from, code))
            }
        };
        self.reply(answer);
    }

    fn reply(&self, answer: Option<Vec<u8>>) {
        if let Some(answer) = answer {
            let _ = self.replies.try_send(Bytes::from(answer));
        }
    }

    fn log_closed(&self, flows: &[(FlowKey, Flow)]) {
        for (key, flow) in flows {
            tracing::info!(
                target: ATTRIBUTION,
                tunnel = self.id,
                proto = key.protocol,
                src = %key.local,
                sport = key.local_port,
                dst = %key.remote,
                dport = key.remote_port,
                packets_out = flow.packets_out,
                packets_in = flow.packets_in,
                bytes_out = flow.bytes_out,
                bytes_in = flow.bytes_in,
                secs = flow.last.duration_since(flow.opened).as_secs(),
                "flow closed"
            );
        }
    }
}

impl std::ops::Drop for Shared {
    fn drop(&mut self) {
        let flows = self.flows.get_mut().drain();
        self.log_closed(&flows);
        tracing::info!(target: ATTRIBUTION, tunnel = self.id, "tunnel closed");
    }
}

#[cfg(test)]
mod tests;

//! The flows a tunnel's client started, keyed by protocol, addresses and
//! ports as seen on the client's side of the NAT.
//!
//! The kernel's conntrack keeps the authoritative NAT state; this table is the
//! relay's own record of which 5-tuples passed the destination policy, so a
//! flow is checked once and not per packet, the live flow count is bounded,
//! and only replies to these flows reach the client. An idle flow is
//! forgotten after its protocol's timeout; a later packet of it is checked
//! again as a new flow.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use wisp_ip::packet::{proto, tcp_flags, Fragment, PacketInfo, Quoted};

/// Idle time after which a TCP flow is forgotten (RFC 5382's minimum for an
/// established mapping).
pub const TCP_IDLE: Duration = Duration::from_secs(7440);
/// Idle time of a TCP flow after a FIN or RST.
pub const TCP_CLOSING_IDLE: Duration = Duration::from_secs(120);
pub const UDP_IDLE: Duration = Duration::from_secs(180);
pub const ICMP_IDLE: Duration = Duration::from_secs(30);

/// How often a busy table looks for idle flows.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: u8,
    /// The client's address and port (echo identifier for ICMP).
    pub local: IpAddr,
    pub local_port: u16,
    /// The remote address and port.
    pub remote: IpAddr,
    pub remote_port: u16,
}

impl FlowKey {
    /// The key of a packet the client sends.
    pub fn outbound(info: &PacketInfo) -> Self {
        Self {
            protocol: info.protocol,
            local: info.src,
            local_port: info.src_port,
            remote: info.dst,
            remote_port: info.dst_port,
        }
    }

    /// The key of a packet sent to the client.
    pub fn inbound(info: &PacketInfo) -> Self {
        Self {
            protocol: info.protocol,
            local: info.dst,
            local_port: info.dst_port,
            remote: info.src,
            remote_port: info.src_port,
        }
    }

    /// The key of the flow an ICMP error quotes, when the quoted packet went
    /// from the client to the remote side.
    pub fn quoted_outbound(q: &Quoted) -> Self {
        Self {
            protocol: q.protocol,
            local: q.src,
            local_port: q.src_port,
            remote: q.dst,
            remote_port: q.dst_port,
        }
    }

    /// The key of the flow an ICMP error quotes, when the quoted packet came
    /// from the remote side to the client.
    pub fn quoted_inbound(q: &Quoted) -> Self {
        Self {
            protocol: q.protocol,
            local: q.dst,
            local_port: q.dst_port,
            remote: q.src,
            remote_port: q.src_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub opened: Instant,
    pub last: Instant,
    pub closing: bool,
    pub packets_out: u64,
    pub packets_in: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

impl Flow {
    fn idle_limit(&self, protocol: u8) -> Duration {
        match protocol {
            proto::TCP if self.closing => TCP_CLOSING_IDLE,
            proto::TCP => TCP_IDLE,
            proto::UDP => UDP_IDLE,
            _ => ICMP_IDLE,
        }
    }
}

pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    cap: usize,
    last_sweep: Instant,
}

impl FlowTable {
    pub fn new(cap: usize) -> Self {
        Self {
            flows: HashMap::new(),
            cap: cap.max(1),
            last_sweep: Instant::now(),
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.flows.contains_key(key)
    }

    /// Counts an outbound packet of a known flow; `false` when the flow is
    /// not (or no longer) known.
    pub fn touch_out(
        &mut self,
        key: &FlowKey,
        info: &PacketInfo,
        bytes: usize,
        now: Instant,
    ) -> bool {
        let Some(flow) = self.flows.get_mut(key) else {
            return false;
        };
        if now.duration_since(flow.last) >= flow.idle_limit(key.protocol) {
            self.flows.remove(key);
            return false;
        }
        flow.last = now;
        flow.packets_out += 1;
        flow.bytes_out += bytes as u64;
        if info.tcp_flags & (tcp_flags::FIN | tcp_flags::RST) != 0 {
            flow.closing = true;
        }
        true
    }

    /// Counts an inbound packet of a known flow; `false` when unknown.
    pub fn touch_in(
        &mut self,
        key: &FlowKey,
        info: &PacketInfo,
        bytes: usize,
        now: Instant,
    ) -> bool {
        let Some(flow) = self.flows.get_mut(key) else {
            return false;
        };
        flow.last = now;
        flow.packets_in += 1;
        flow.bytes_in += bytes as u64;
        if info.tcp_flags & (tcp_flags::FIN | tcp_flags::RST) != 0 {
            flow.closing = true;
        }
        true
    }

    /// Whether the table has room for one more flow, after forgetting the
    /// idle ones if it is full. The forgotten flows are returned for the
    /// attribution log.
    pub fn make_room(&mut self, now: Instant) -> (bool, Vec<(FlowKey, Flow)>) {
        let expired = if self.flows.len() >= self.cap {
            self.sweep(now)
        } else {
            Vec::new()
        };
        (self.flows.len() < self.cap, expired)
    }

    pub fn insert(&mut self, key: FlowKey, bytes: usize, now: Instant) {
        self.flows.insert(
            key,
            Flow {
                opened: now,
                last: now,
                closing: false,
                packets_out: 1,
                packets_in: 0,
                bytes_out: bytes as u64,
                bytes_in: 0,
            },
        );
    }

    /// Whether some live flow joins `local` and `remote` with `protocol`: the
    /// test for an IP fragment after the first, which carries no ports.
    pub fn has_pair(&self, protocol: u8, local: IpAddr, remote: IpAddr) -> bool {
        self.flows
            .keys()
            .any(|k| k.protocol == protocol && k.local == local && k.remote == remote)
    }

    /// Forgets idle flows, at most once per sweep interval unless forced by a
    /// full table.
    pub fn maybe_sweep(&mut self, now: Instant) -> Vec<(FlowKey, Flow)> {
        if now.duration_since(self.last_sweep) < SWEEP_EVERY {
            return Vec::new();
        }
        self.sweep(now)
    }

    fn sweep(&mut self, now: Instant) -> Vec<(FlowKey, Flow)> {
        self.last_sweep = now;
        let idle: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(k, f)| now.duration_since(f.last) >= f.idle_limit(k.protocol))
            .map(|(k, _)| *k)
            .collect();
        idle.into_iter()
            .filter_map(|k| self.flows.remove(&k).map(|f| (k, f)))
            .collect()
    }

    /// Every flow, for the attribution log when the tunnel ends.
    pub fn drain(&mut self) -> Vec<(FlowKey, Flow)> {
        self.flows.drain().collect()
    }
}

/// Whether a packet the client sends belongs to an existing flow without
/// being one: a later IP fragment, or an ICMP error about a reply the client
/// received.
pub(crate) fn related_outbound(table: &FlowTable, info: &PacketInfo) -> Option<bool> {
    if info.fragment == Fragment::Later {
        return Some(table.has_pair(info.protocol, info.src, info.dst));
    }
    if info.is_icmp_error() {
        return Some(
            info.quoted
                .is_some_and(|q| table.contains(&FlowKey::quoted_inbound(&q))),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> FlowKey {
        FlowKey {
            protocol: proto::UDP,
            local: "192.168.1.100".parse().unwrap(),
            local_port: port,
            remote: "1.1.1.1".parse().unwrap(),
            remote_port: 53,
        }
    }

    fn info() -> PacketInfo {
        PacketInfo {
            src: "192.168.1.100".parse().unwrap(),
            dst: "1.1.1.1".parse().unwrap(),
            protocol: proto::UDP,
            ttl: 64,
            transport_offset: 20,
            fragment: Fragment::None,
            src_port: 1,
            dst_port: 53,
            icmp_type: 0,
            icmp_code: 0,
            tcp_flags: 0,
            quoted: None,
        }
    }

    #[test]
    fn cap_holds_until_idle_flows_go() {
        let t0 = Instant::now();
        let mut table = FlowTable::new(2);
        table.insert(key(1), 10, t0);
        table.insert(key(2), 10, t0);
        assert!(!table.make_room(t0 + Duration::from_secs(1)).0);
        let (room, expired) = table.make_room(t0 + UDP_IDLE);
        assert!(room);
        assert_eq!(expired.len(), 2);
        assert!(table.is_empty());
    }

    #[test]
    fn idle_flow_is_unknown_again() {
        let t0 = Instant::now();
        let mut table = FlowTable::new(8);
        table.insert(key(1), 10, t0);
        assert!(table.touch_out(&key(1), &info(), 10, t0 + Duration::from_secs(1)));
        assert!(!table.touch_out(&key(1), &info(), 10, t0 + Duration::from_secs(1) + UDP_IDLE));
        assert!(!table.contains(&key(1)));
    }

    #[test]
    fn pairs_cover_later_fragments() {
        let t0 = Instant::now();
        let mut table = FlowTable::new(8);
        table.insert(key(1), 10, t0);
        assert!(table.has_pair(proto::UDP, key(1).local, key(1).remote));
        assert!(!table.has_pair(proto::TCP, key(1).local, key(1).remote));
    }
}

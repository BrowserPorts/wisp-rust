//! UDP flow registry. Mirrors `WispWtUdpFlow` (`wisp-wt/src/wt/server.ts`).
//!
//! Each open UDP_OPEN frame creates a `UdpFlow` keyed by a server-assigned
//! `flow_id`. Inbound packets from the client (via datagram OR — when 0x09
//! PER_FLOW_UDP_UNI is negotiated — a per-flow uni stream) are pushed onto the
//! flow's `tx`. The send pump on the flow forwards them to the upstream UDP
//! socket. Replies from the socket go back as datagrams (with the negotiated
//! priority class when 0x0a is on) or, in per-flow-uni mode, as chunks on the
//! flow's server→client uni stream.

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// What carrier the client opened the flow with. Server reuses the same
/// carrier for replies so the framing is symmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCarrier {
    Datagram,
    PerFlowUni,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpPriorityClass {
    Bulk = 0,
    #[default]
    Normal = 1,
    Interactive = 2,
}

#[derive(Debug)]
pub struct UdpFlow {
    pub flow_id: u32,
    pub carrier: UdpCarrier,
    pub priority: UdpPriorityClass,
    pub tx: mpsc::Sender<Bytes>,
}

/// Registry of UDP flows for a single connection.
#[derive(Debug, Default)]
pub struct UdpFlowRegistry {
    next_id: AtomicU32,
    flows: DashMap<u32, Arc<UdpFlow>>,
}

impl UdpFlowRegistry {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU32::new(1),
            flows: DashMap::new(),
        }
    }

    pub fn allocate(
        &self,
        carrier: UdpCarrier,
        priority: UdpPriorityClass,
        send_buffer: usize,
    ) -> (Arc<UdpFlow>, mpsc::Receiver<Bytes>) {
        let flow_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(send_buffer);
        let flow = Arc::new(UdpFlow {
            flow_id,
            carrier,
            priority,
            tx,
        });
        self.flows.insert(flow_id, flow.clone());
        (flow, rx)
    }

    pub fn get(&self, flow_id: u32) -> Option<Arc<UdpFlow>> {
        self.flows.get(&flow_id).map(|e| e.clone())
    }

    pub fn remove(&self, flow_id: u32) -> Option<Arc<UdpFlow>> {
        self.flows.remove(&flow_id).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Drop all flows. Senders on the held mpsc channels go away, which the
    /// pump tasks observe as graceful shutdown.
    pub fn clear(&self) {
        self.flows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allocate_assigns_monotonic_ids() {
        let reg = UdpFlowRegistry::new();
        let (a, _) = reg.allocate(UdpCarrier::Datagram, UdpPriorityClass::Normal, 8);
        let (b, _) = reg.allocate(UdpCarrier::Datagram, UdpPriorityClass::Normal, 8);
        assert!(b.flow_id > a.flow_id);
        assert_eq!(reg.len(), 2);
    }

    #[tokio::test]
    async fn remove_deletes_flow() {
        let reg = UdpFlowRegistry::new();
        let (flow, _) = reg.allocate(UdpCarrier::PerFlowUni, UdpPriorityClass::Interactive, 8);
        let id = flow.flow_id;
        assert!(reg.get(id).is_some());
        let taken = reg.remove(id).unwrap();
        assert_eq!(taken.flow_id, id);
        assert!(reg.get(id).is_none());
    }

    #[tokio::test]
    async fn tx_round_trips_payload() {
        let reg = UdpFlowRegistry::new();
        let (flow, mut rx) = reg.allocate(UdpCarrier::Datagram, UdpPriorityClass::Normal, 8);
        flow.tx.send(Bytes::from_static(b"hello")).await.unwrap();
        let got = rx.recv().await.unwrap();
        assert_eq!(got.as_ref(), b"hello");
    }
}

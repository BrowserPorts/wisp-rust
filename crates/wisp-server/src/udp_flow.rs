//! UDP flow registry.
//!
//! Each UDP_OPEN frame creates a flow keyed by a server-assigned `flow_id`.
//! Inbound datagrams from the client are routed onto the flow's `upstream_tx`;
//! a per-flow send pump forwards them to the upstream UDP socket, and socket
//! replies travel back to the client as datagrams. Closing a flow cancels its
//! pump tasks via the flow's [`CancellationToken`].

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Live per-flow handle: the channel that feeds client datagrams to the
/// upstream send pump, plus the token that shuts the flow's pumps down.
pub struct UdpFlowHandle {
    pub upstream_tx: mpsc::Sender<Bytes>,
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOutcome {
    Queued,
    Full,
    Closed,
    Unknown,
}

/// Registry of active UDP flows for a single connection.
#[derive(Default)]
pub struct UdpFlowRegistry {
    flows: DashMap<u32, UdpFlowHandle>,
    next_id: AtomicU32,
}

impl UdpFlowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a fresh non-zero flow id not currently in use.
    pub fn alloc_id(&self) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            if id != 0 && !self.flows.contains_key(&id) {
                return id;
            }
        }
    }

    pub fn insert(&self, id: u32, handle: UdpFlowHandle) {
        self.flows.insert(id, handle);
    }

    pub fn remove(&self, flow_id: u32) -> Option<UdpFlowHandle> {
        self.flows.remove(&flow_id).map(|(_, h)| h)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Attempt to forward a client datagram without blocking the connection
    /// demultiplexer behind a saturated flow.
    pub fn route(&self, flow_id: u32, payload: Bytes) -> RouteOutcome {
        let Some(entry) = self.flows.get(&flow_id) else {
            return RouteOutcome::Unknown;
        };
        match entry.upstream_tx.try_send(payload) {
            Ok(()) => RouteOutcome::Queued,
            Err(mpsc::error::TrySendError::Full(_)) => RouteOutcome::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => RouteOutcome::Closed,
        }
    }

    /// Cancel and remove a single flow.
    pub fn close(&self, flow_id: u32) {
        if let Some((_, h)) = self.flows.remove(&flow_id) {
            h.cancel.cancel();
        }
    }

    /// Cancel every flow and clear the registry.
    pub fn shutdown_all(&self) {
        for entry in self.flows.iter() {
            entry.value().cancel.cancel();
        }
        self.flows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(capacity: usize) -> (UdpFlowHandle, mpsc::Receiver<Bytes>) {
        let (upstream_tx, rx) = mpsc::channel(capacity);
        (
            UdpFlowHandle {
                upstream_tx,
                cancel: CancellationToken::new(),
            },
            rx,
        )
    }

    #[test]
    fn alloc_id_is_non_zero_and_unique() {
        let reg = UdpFlowRegistry::new();
        let a = reg.alloc_id();
        let b = reg.alloc_id();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn route_forwards_to_upstream_tx() {
        let reg = UdpFlowRegistry::new();
        let id = reg.alloc_id();
        let (h, mut rx) = handle(1);
        reg.insert(id, h);
        assert_eq!(
            reg.route(id, Bytes::from_static(b"hello")),
            RouteOutcome::Queued
        );
        assert_eq!(rx.recv().await.unwrap().as_ref(), b"hello");
    }

    #[test]
    fn route_reports_backpressure_and_unknown_flows() {
        let reg = UdpFlowRegistry::new();
        let id = reg.alloc_id();
        let (h, _rx) = handle(1);
        reg.insert(id, h);
        assert_eq!(
            reg.route(id, Bytes::from_static(b"first")),
            RouteOutcome::Queued
        );
        assert_eq!(
            reg.route(id, Bytes::from_static(b"second")),
            RouteOutcome::Full
        );
        assert_eq!(
            reg.route(id + 1, Bytes::from_static(b"unknown")),
            RouteOutcome::Unknown
        );
    }

    #[test]
    fn route_reports_closed_pump() {
        let reg = UdpFlowRegistry::new();
        let id = reg.alloc_id();
        let (h, rx) = handle(1);
        drop(rx);
        reg.insert(id, h);
        assert_eq!(
            reg.route(id, Bytes::from_static(b"closed")),
            RouteOutcome::Closed
        );
    }

    #[test]
    fn close_cancels_and_removes() {
        let reg = UdpFlowRegistry::new();
        let id = reg.alloc_id();
        let (h, _rx) = handle(1);
        let token = h.cancel.clone();
        reg.insert(id, h);
        assert_eq!(reg.len(), 1);
        reg.close(id);
        assert!(token.is_cancelled());
        assert!(reg.is_empty());
    }

    #[test]
    fn shutdown_all_cancels_every_flow() {
        let reg = UdpFlowRegistry::new();
        let (h1, _r1) = handle(1);
        let (h2, _r2) = handle(1);
        let t1 = h1.cancel.clone();
        let t2 = h2.cancel.clone();
        reg.insert(reg.alloc_id(), h1);
        reg.insert(reg.alloc_id(), h2);
        reg.shutdown_all();
        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
        assert!(reg.is_empty());
    }
}

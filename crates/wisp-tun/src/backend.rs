//! Where a tunnel's packets go: a network made for one tunnel.

use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;
use tokio::sync::mpsc;

/// Packets queued towards the network or the client per tunnel. A full
/// queue drops, as a congested link does.
pub const DEVICE_QUEUE: usize = 1024;

/// Everything a backend needs to build one tunnel's network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    pub id: u64,
    /// The LAN (network address and length), its gateway and the client.
    pub lan: (Ipv4Addr, u8),
    pub gateway4: Ipv4Addr,
    pub client4: Ipv4Addr,
    /// The tunnel's routed IPv6 prefix, when it has one; the gateway takes
    /// `::1` in it.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub link_mtu: u16,
    pub max_packet: u16,
    /// Live connections the network's conntrack may hold for the tunnel.
    pub max_flows: u32,
    /// Resolvers clients may reach on port 53 even when private.
    pub dns_servers: Vec<std::net::IpAddr>,
}

impl NetworkPlan {
    /// The IPv6 gateway's global address: `::1` of the tunnel's prefix.
    pub fn gateway6(&self) -> Option<Ipv6Addr> {
        self.ipv6.map(|(p, _)| Ipv6Addr::from(u128::from(p) | 1))
    }
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("no transit address left for another tunnel")]
    Exhausted,
    #[error("{0}")]
    Setup(String),
    #[error("tunnel networks are not available: {0}")]
    Unavailable(String),
}

/// Tears the network down when dropped.
pub struct DeviceGuard(#[allow(dead_code)] Box<dyn Send + Sync>);

impl DeviceGuard {
    pub fn new(inner: impl Send + Sync + 'static) -> Self {
        Self(Box::new(inner))
    }
}

/// One tunnel's network: packets in, packets out, and the guard that keeps
/// it alive.
pub struct Device {
    pub to_network: mpsc::Sender<Bytes>,
    pub from_network: mpsc::Receiver<Bytes>,
    pub guard: DeviceGuard,
}

#[async_trait]
pub trait Backend: Send + Sync + 'static {
    /// Builds the network for one tunnel.
    async fn create(&self, plan: NetworkPlan) -> Result<Device, BackendError>;
    /// A short name for logs.
    fn name(&self) -> &'static str;
}

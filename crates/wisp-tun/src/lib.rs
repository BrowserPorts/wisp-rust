//! The relay side of IP tunnels (extension 0xF3): the network a tunnel's
//! packets enter, and the rules on the way.
//!
//! The transports ([`wisp-wisp-server`] for Wisp over WebSocket,
//! [`wisp-server`] for wisp-wt) open a [`Tunnel`] through the process-wide
//! [`TunnelService`], hand it every packet the client sends with
//! [`TunnelHandle::forward`], and deliver what [`Tunnel::recv`] returns. In
//! between, per packet from the client:
//!
//! 1. the tunnel's and the client address's packet and byte budgets;
//! 2. IP header validation (`wisp-ip`) and source validation (BCP 38): the
//!    source must be one of the tunnel's own addresses;
//! 3. link-local, multicast, neighbour discovery and protocols other than
//!    TCP, UDP and ICMP are never forwarded;
//! 4. the first packet of a new flow, keyed by protocol, addresses and ports,
//!    goes through the connection's destination policy (`wisp-proxy`'s
//!    address and port gates, per credential), the live flow cap and the new
//!    flow rate; a refusal is answered as a rejecting firewall would answer
//!    it (ICMP administratively prohibited, a TCP reset, or silence);
//! 5. the packet enters the tunnel's network.
//!
//! On Linux that network is a namespace of its own ([`netns`]): a TUN device
//! holding the LAN's gateway, a veth pair to the host, nftables masquerade,
//! and a static backstop (no inbound, no private or loopback destinations,
//! no other tunnel, a conntrack cap). The kernel then routes as a home router
//! does: it decrements the TTL, sends Time Exceeded, translates ICMP errors
//! and keeps each tunnel's conntrack apart. [`memory::MemoryBackend`] stands
//! in for it in tests and on hosts without the privileges.
//!
//! A tunnel outlives a dropped connection for the resume grace period
//! (section 8 of the extension): its network, addresses and flows wait for
//! the same credential to come back with the single-use token.

#![deny(unsafe_code)]

pub mod backend;
pub mod config;
pub mod flow;
pub mod icmp;
pub mod memory;
pub mod nft;
pub mod policy;
pub mod privileges;
mod resume;
mod service;

#[cfg(target_os = "linux")]
pub mod netns;
#[cfg(target_os = "linux")]
mod tun_fd;

pub use backend::{Backend, BackendError, Device, DeviceGuard, NetworkPlan};
pub use config::{Binding, TunnelConfig};
pub use service::{
    DropReason, OpenError, OpenRequest, Opened, Outcome, Tunnel, TunnelHandle, TunnelService,
};

use wisp_config::WispServerOptions;

/// Whether a connection whose (credential-narrowed) options are `options` may
/// open tunnels at all. A domain whitelist cannot be honoured, since a tunnel
/// carries only addresses, so such a credential is refused rather than let
/// around its list.
pub fn credential_may_open(options: &WispServerOptions) -> bool {
    options.allow_ip_tunnel && options.domain_whitelist.is_none()
}

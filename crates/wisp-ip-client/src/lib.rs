//! The client side of the `IP_TUNNEL` extension (0xF3, version 1): the uplink
//! of a machine that runs a whole network stack and reaches the internet
//! through a wisp-rust relay.
//!
//! The machine's kernel (Ferrochrome's netkernel) sees an ordinary Ethernet
//! link `eth0`. Its frames come here through the wire device's frame ring.
//! The [`router`] answers ARP and neighbour discovery for the gateway the
//! relay names, sends router advertisements when the relay routes an IPv6
//! prefix to the tunnel, and turns every other frame for the gateway into an
//! IP packet for the tunnel. The [`mux`] carries those packets on one of the
//! two Wisp bindings:
//!
//! - **WebTransport** (wisp-wt): control frames 0x0b-0x0e on the control
//!   bidi, packets in datagrams of kind `IP`, split in two when a 1500-byte
//!   packet does not fit the session's live datagram limit
//!   (`WebTransportDatagramDuplexStream.maxDatagramSize`), or one uni stream
//!   per direction when the session has no datagrams.
//! - **WebSocket** (Wisp v2): `TUNNEL` packets for control and one `DATA`
//!   packet per IP packet, for networks that block UDP.
//!
//! [`Uplink`] ties them together for the machine's one link: it opens the
//! tunnel when a carrier comes up, resumes it within the relay's grace period
//! when the carrier drops (decision LD13), and reports the relay's
//! configuration as a [`LinkConfig`]. The [`manager`] turns that
//! configuration into the netlink operations NetworkManager would perform on
//! a Debian host, and names the NKRPC calls that carry them to the netkernel.
//!
//! Nothing here does I/O or reads a clock. Callers pass the carrier's bytes,
//! the wire's frames and the time in milliseconds, and drain
//! [`Uplink::poll_output`]. The same code runs natively in tests and as a
//! `wasm32-unknown-unknown` module ([`abi`]) driven by the
//! `wisp-ip-carrier` package in the uplink Worker.

#![deny(unsafe_code)]

pub mod abi;
pub mod ether;
pub mod manager;
pub mod mux;
pub mod netlink;
pub mod nkrpc;
pub mod router;
pub mod uplink;

#[cfg(test)]
mod testutil;

pub use manager::{plan, ConfigPlan, InterfaceSpec, LinkConfig, MachineManager, ResolverConfig};
pub use mux::{Carrier, Mux, MuxEvent, Transmit};
pub use router::{Router, RouterConfig};
pub use uplink::{Event, LinkDownReason, Output, Uplink, UplinkConfig, UplinkStats};

/// Bytes of `[class][kind][tunnel_id]` in front of every tunnel datagram.
pub const DATAGRAM_HEADER: usize = 6;

/// Packets at most this long ride the interactive datagram class (TCP
/// acknowledgements, DNS), as section 6.2 of the extension recommends.
pub const INTERACTIVE_MAX: usize = 128;

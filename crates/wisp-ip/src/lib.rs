//! Wire pieces of the `IP_TUNNEL` extension (id 0xF3, version 1), shared by
//! the relay and its clients on both Wisp transports.
//!
//! A client that runs a whole network stack exchanges complete IPv4 and IPv6
//! packets with the relay, which forwards them as a router with NAT. The
//! extension is negotiated through an INFO entry whose payload starts with
//! the magic `WIPT`; tunnel control travels as capsules
//! `[type:u16][length:u16][value]`, modelled on RFC 9484's address and route
//! capsules. All integers are little-endian, as everywhere in Wisp.
//!
//! - [`info`]: the INFO payloads and the negotiation check.
//! - [`capsule`]: the capsule codec, with the bit-15 rule for unknown types.
//! - [`frag`]: the fragment header that splits a packet over WebTransport
//!   datagrams, and the bounded reassembler.
//! - [`packet`]: IP header validation, the addresses, protocol and ports a
//!   relay keys its flows by, and the Internet checksum.
//!
//! The crate has no I/O and no allocation beyond `alloc`, so the same code
//! runs in the relay and in a `wasm32-unknown-unknown` client.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod capsule;
pub mod frag;
pub mod info;
pub mod packet;

pub use capsule::{
    encode_capsules, parse_capsules, AssignedAddress, Capsule, CapsuleError, DnsConfig, LinkParams,
    Prefix, ResumeToken, RouteEntry,
};
pub use frag::{FragError, FragHeader, Reassembled, Reassembler};
pub use info::{negotiate, ClientInfo, InfoError, Negotiated, ServerInfo};
pub use packet::{inspect, PacketError, PacketInfo};

/// Extension id of `IP_TUNNEL` in both the Wisp v2 and the wisp-wt id space.
pub const EXTENSION_ID: u8 = 0xf3;

/// First four bytes of both INFO payloads. A peer that uses 0xF3 for
/// something else does not send them, and the extension is then not
/// negotiated.
pub const MAGIC: [u8; 4] = *b"WIPT";

/// The extension version this crate implements.
pub const VERSION: u8 = 1;

/// Wisp close reasons a tunnel is closed with.
pub mod close_reason {
    pub const VOLUNTARY: u8 = 0x02;
    pub const NETWORK_ERROR: u8 = 0x03;
    /// A bad capsule, a bad magic in a later message, or an invalid token.
    pub const INVALID_INFO: u8 = 0x41;
    /// The credential may not open tunnels.
    pub const BLOCKED: u8 = 0x48;
    pub const THROTTLED: u8 = 0x49;
}

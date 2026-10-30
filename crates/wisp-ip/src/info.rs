//! INFO entries of the extension and the negotiation check.
//!
//! Server entry (14 bytes; a server may append more, which a version 1 client
//! ignores):
//!
//! ```text
//! 0  4  magic        "WIPT"
//! 4  1  ver_min
//! 5  1  ver_max
//! 6  2  flags        see [`flags`]
//! 8  2  max_tunnels  tunnels allowed at once on the connection (>= 1)
//! 10 2  link_mtu     MTU the client configures on its link (1280..=65535)
//! 12 2  max_packet   largest packet accepted (>= 1280, >= link_mtu)
//! ```
//!
//! Client entry (7 bytes): `"WIPT"`, the chosen version, and the subset of
//! the server's flags it will use.
//!
//! The extension is negotiated when both entries are present, both magics
//! match and the client's version lies in the server's range. Anything else
//! leaves it off without closing the connection, since absence is how Wisp
//! says "not supported".

use alloc::vec::Vec;
use core::fmt;

use crate::{MAGIC, VERSION};

/// Length of the server entry this version writes.
pub const SERVER_INFO_LEN: usize = 14;
/// Length of the client entry this version writes.
pub const CLIENT_INFO_LEN: usize = 7;
/// Smallest link MTU a server may announce (IPv6's minimum).
pub const MIN_LINK_MTU: u16 = 1280;

/// Flag bits of both entries. Bits 6-15 are reserved: sent as 0 and ignored.
pub mod flags {
    /// The relay forwards IPv4.
    pub const IPV4: u16 = 1 << 0;
    /// The relay forwards IPv6.
    pub const IPV6: u16 = 1 << 1;
    /// WebTransport binding: tunnel packets may ride datagrams.
    pub const DATAGRAMS: u16 = 1 << 2;
    /// WebTransport binding: fragmented datagrams are accepted.
    pub const FRAGMENTS: u16 = 1 << 3;
    /// Tunnels can be resumed after the connection drops.
    pub const RESUME: u16 = 1 << 4;
    /// ICMP and ICMPv6 echo are forwarded.
    pub const ICMP_ECHO: u16 = 1 << 5;
    /// Every flag version 1 defines.
    pub const KNOWN: u16 = IPV4 | IPV6 | DATAGRAMS | FRAGMENTS | RESUME | ICMP_ECHO;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoError {
    TooShort,
    BadMagic,
    /// `ver_min` above `ver_max`, or a version of 0.
    BadVersionRange,
    /// `max_tunnels` of 0.
    NoTunnels,
    LinkMtu(u16),
    MaxPacket(u16),
}

impl fmt::Display for InfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InfoError::TooShort => f.write_str("IP_TUNNEL INFO entry too short"),
            InfoError::BadMagic => f.write_str("IP_TUNNEL INFO entry has the wrong magic"),
            InfoError::BadVersionRange => f.write_str("IP_TUNNEL INFO version range invalid"),
            InfoError::NoTunnels => f.write_str("IP_TUNNEL INFO allows no tunnels"),
            InfoError::LinkMtu(v) => write!(f, "IP_TUNNEL link_mtu {v} out of range"),
            InfoError::MaxPacket(v) => write!(f, "IP_TUNNEL max_packet {v} out of range"),
        }
    }
}

impl core::error::Error for InfoError {}

/// The server's INFO entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerInfo {
    pub ver_min: u8,
    pub ver_max: u8,
    pub flags: u16,
    pub max_tunnels: u16,
    pub link_mtu: u16,
    pub max_packet: u16,
}

impl ServerInfo {
    /// An entry offering version 1 only.
    pub fn v1(flags: u16, max_tunnels: u16, link_mtu: u16, max_packet: u16) -> Self {
        Self {
            ver_min: VERSION,
            ver_max: VERSION,
            flags,
            max_tunnels,
            link_mtu,
            max_packet,
        }
    }

    /// The ranges section 4.1 requires of a server entry.
    pub fn validate(&self) -> Result<(), InfoError> {
        if self.ver_min == 0 || self.ver_min > self.ver_max {
            return Err(InfoError::BadVersionRange);
        }
        if self.max_tunnels == 0 {
            return Err(InfoError::NoTunnels);
        }
        if self.link_mtu < MIN_LINK_MTU {
            return Err(InfoError::LinkMtu(self.link_mtu));
        }
        if self.max_packet < MIN_LINK_MTU || self.max_packet < self.link_mtu {
            return Err(InfoError::MaxPacket(self.max_packet));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SERVER_INFO_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(self.ver_min);
        out.push(self.ver_max);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.max_tunnels.to_le_bytes());
        out.extend_from_slice(&self.link_mtu.to_le_bytes());
        out.extend_from_slice(&self.max_packet.to_le_bytes());
        out
    }

    /// Parses and validates a server entry. Bytes after offset 14 are ignored.
    pub fn parse(payload: &[u8]) -> Result<Self, InfoError> {
        if payload.len() < 4 {
            return Err(InfoError::TooShort);
        }
        if payload[..4] != MAGIC {
            return Err(InfoError::BadMagic);
        }
        if payload.len() < SERVER_INFO_LEN {
            return Err(InfoError::TooShort);
        }
        let info = Self {
            ver_min: payload[4],
            ver_max: payload[5],
            flags: u16::from_le_bytes([payload[6], payload[7]]),
            max_tunnels: u16::from_le_bytes([payload[8], payload[9]]),
            link_mtu: u16::from_le_bytes([payload[10], payload[11]]),
            max_packet: u16::from_le_bytes([payload[12], payload[13]]),
        };
        info.validate()?;
        Ok(info)
    }
}

/// The client's INFO entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientInfo {
    pub version: u8,
    pub flags: u16,
}

impl ClientInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLIENT_INFO_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out
    }

    /// Parses a client entry. Bytes after offset 7 are ignored, as a later
    /// version may append fields.
    pub fn parse(payload: &[u8]) -> Result<Self, InfoError> {
        if payload.len() < 4 {
            return Err(InfoError::TooShort);
        }
        if payload[..4] != MAGIC {
            return Err(InfoError::BadMagic);
        }
        if payload.len() < CLIENT_INFO_LEN {
            return Err(InfoError::TooShort);
        }
        Ok(Self {
            version: payload[4],
            flags: u16::from_le_bytes([payload[5], payload[6]]),
        })
    }
}

/// What both sides agreed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    pub version: u8,
    /// The client's flags limited to what the server offered and this
    /// version defines.
    pub flags: u16,
    pub max_tunnels: u16,
    pub link_mtu: u16,
    pub max_packet: u16,
}

impl Negotiated {
    pub fn has(&self, flag: u16) -> bool {
        self.flags & flag == flag
    }
}

/// The server's side of the check: `Some` when the client's entry carries the
/// magic and a version in the server's range.
pub fn negotiate(server: &ServerInfo, client_payload: &[u8]) -> Option<Negotiated> {
    let client = ClientInfo::parse(client_payload).ok()?;
    if client.version < server.ver_min || client.version > server.ver_max {
        return None;
    }
    Some(Negotiated {
        version: client.version,
        flags: client.flags & server.flags & flags::KNOWN,
        max_tunnels: server.max_tunnels,
        link_mtu: server.link_mtu,
        max_packet: server.max_packet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> ServerInfo {
        ServerInfo::v1(0x3f, 1, 1500, 1500)
    }

    #[test]
    fn server_entry_matches_the_spec_example() {
        // EXTENSION.md 6.1: F3 0E 00 00 00 | 57 49 50 54 01 01 3F 00 01 00 DC 05 DC 05
        let bytes = server().encode();
        assert_eq!(
            bytes,
            [0x57, 0x49, 0x50, 0x54, 0x01, 0x01, 0x3f, 0x00, 0x01, 0x00, 0xdc, 0x05, 0xdc, 0x05]
        );
        assert_eq!(ServerInfo::parse(&bytes).unwrap(), server());
    }

    #[test]
    fn server_entry_ignores_appended_bytes() {
        let mut bytes = server().encode();
        bytes.extend_from_slice(&[9, 9, 9]);
        assert_eq!(ServerInfo::parse(&bytes).unwrap(), server());
    }

    #[test]
    fn server_entry_rejects_bad_fields() {
        assert_eq!(ServerInfo::parse(b"WIP"), Err(InfoError::TooShort));
        let mut bytes = server().encode();
        bytes[0] = b'X';
        assert_eq!(ServerInfo::parse(&bytes), Err(InfoError::BadMagic));
        assert_eq!(
            ServerInfo::v1(0, 0, 1500, 1500).validate(),
            Err(InfoError::NoTunnels)
        );
        assert_eq!(
            ServerInfo::v1(0, 1, 1200, 1500).validate(),
            Err(InfoError::LinkMtu(1200))
        );
        assert_eq!(
            ServerInfo::v1(0, 1, 1500, 1400).validate(),
            Err(InfoError::MaxPacket(1400))
        );
        let mut reversed = server();
        reversed.ver_min = 2;
        assert_eq!(reversed.validate(), Err(InfoError::BadVersionRange));
    }

    #[test]
    fn client_entry_round_trips() {
        let client = ClientInfo {
            version: 1,
            flags: flags::IPV4 | flags::DATAGRAMS,
        };
        let bytes = client.encode();
        assert_eq!(bytes.len(), CLIENT_INFO_LEN);
        assert_eq!(ClientInfo::parse(&bytes).unwrap(), client);
    }

    #[test]
    fn negotiation_needs_magic_and_version_in_range() {
        let client = ClientInfo {
            version: 1,
            flags: flags::KNOWN | 0x8000,
        };
        let neg = negotiate(&server(), &client.encode()).expect("negotiated");
        assert_eq!(neg.flags, 0x3f, "reserved bits are dropped");
        assert!(neg.has(flags::RESUME));

        let mut wrong_magic = client.encode();
        wrong_magic[3] = b'U';
        assert!(negotiate(&server(), &wrong_magic).is_none());

        let too_new = ClientInfo {
            version: 2,
            flags: 0,
        };
        assert!(negotiate(&server(), &too_new.encode()).is_none());
        let too_old = ClientInfo {
            version: 0,
            flags: 0,
        };
        assert!(negotiate(&server(), &too_old.encode()).is_none());
        assert!(negotiate(&server(), &[]).is_none());
    }

    #[test]
    fn negotiated_flags_are_the_intersection() {
        let offer = ServerInfo::v1(flags::IPV4 | flags::RESUME, 2, 1500, 1500);
        let client = ClientInfo {
            version: 1,
            flags: flags::IPV4 | flags::IPV6 | flags::DATAGRAMS,
        };
        let neg = negotiate(&offer, &client.encode()).unwrap();
        assert_eq!(neg.flags, flags::IPV4);
        assert!(!neg.has(flags::RESUME));
        assert_eq!(neg.max_tunnels, 2);
    }
}

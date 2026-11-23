//! Packets split over WebTransport datagrams (section 6.3).
//!
//! Chrome's WebTransport client uses 1250-byte QUIC packets, so one datagram
//! holds about 1200 bytes, less than the 1500-byte link MTU the tunnel keeps.
//! A packet that does not fit is split into 2 to 15 pieces:
//!
//! ```text
//! frag = 0x00                                    the rest is one whole packet
//! frag = (count << 4) | index, then pkt_id:u16   a piece; 2 <= count <= 15
//! ```
//!
//! Pieces other than the last are at least [`MIN_PIECE_LEN`] bytes. A
//! receiver keeps at most [`REASSEMBLY_SLOTS`] incomplete packets per tunnel
//! and drops one after [`REASSEMBLY_TIMEOUT_MS`] without its last piece. A
//! piece whose `count` disagrees with an earlier piece of the same `pkt_id`,
//! or that repeats an index, discards the packet: losing a piece loses the
//! packet, and the client's TCP retransmits it as after any loss.

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

/// Header byte of a datagram that carries a whole packet.
pub const WHOLE: u8 = 0x00;
/// Most pieces one packet may be split into.
pub const MAX_PIECES: u8 = 15;
/// Shortest piece other than the last.
pub const MIN_PIECE_LEN: usize = 256;
/// Header length of a piece: the count and index byte and `pkt_id`.
pub const PIECE_HEADER_LEN: usize = 3;
/// Incomplete packets a receiver keeps per tunnel.
pub const REASSEMBLY_SLOTS: usize = 64;
/// How long an incomplete packet waits for its last piece.
pub const REASSEMBLY_TIMEOUT_MS: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragError {
    /// No header byte, or a piece header cut short.
    Truncated,
    /// A count outside 2..=15 or an index not below the count.
    BadHeader(u8),
    /// The packet needs more than 15 pieces of the room given.
    TooLarge,
    /// The room per datagram cannot hold a minimum-size piece.
    NoRoom,
}

impl fmt::Display for FragError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FragError::Truncated => f.write_str("fragment header truncated"),
            FragError::BadHeader(b) => write!(f, "invalid fragment header {b:#04x}"),
            FragError::TooLarge => f.write_str("packet needs more than 15 pieces"),
            FragError::NoRoom => f.write_str("datagram too small for a piece"),
        }
    }
}

impl core::error::Error for FragError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragHeader {
    Whole,
    Piece { count: u8, index: u8, pkt_id: u16 },
}

impl FragHeader {
    /// Parses the header at the start of `buf` and returns the rest.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), FragError> {
        let (&first, rest) = buf.split_first().ok_or(FragError::Truncated)?;
        if first == WHOLE {
            return Ok((FragHeader::Whole, rest));
        }
        let count = first >> 4;
        let index = first & 0x0f;
        if !(2..=MAX_PIECES).contains(&count) || index >= count {
            return Err(FragError::BadHeader(first));
        }
        if rest.len() < 2 {
            return Err(FragError::Truncated);
        }
        let pkt_id = u16::from_le_bytes([rest[0], rest[1]]);
        Ok((
            FragHeader::Piece {
                count,
                index,
                pkt_id,
            },
            &rest[2..],
        ))
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            FragHeader::Whole => 1,
            FragHeader::Piece { .. } => PIECE_HEADER_LEN,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            FragHeader::Whole => out.push(WHOLE),
            FragHeader::Piece {
                count,
                index,
                pkt_id,
            } => {
                out.push((count << 4) | index);
                out.extend_from_slice(&pkt_id.to_le_bytes());
            }
        }
    }
}

/// How to carry a packet of `len` bytes in datagrams with `room` bytes for
/// the fragment header and data each: one whole packet when it fits, else the
/// fewest pieces, each filled before the next.
pub fn split(
    len: usize,
    room: usize,
    pkt_id: u16,
) -> Result<Vec<(FragHeader, Range<usize>)>, FragError> {
    if len < room {
        return Ok(alloc::vec![(FragHeader::Whole, 0..len)]);
    }
    let piece = room
        .checked_sub(PIECE_HEADER_LEN)
        .ok_or(FragError::NoRoom)?;
    if piece < MIN_PIECE_LEN {
        return Err(FragError::NoRoom);
    }
    let count = len.div_ceil(piece);
    if count > usize::from(MAX_PIECES) {
        return Err(FragError::TooLarge);
    }
    Ok((0..count)
        .map(|i| {
            let start = i * piece;
            let end = (start + piece).min(len);
            (
                FragHeader::Piece {
                    count: count as u8,
                    index: i as u8,
                    pkt_id,
                },
                start..end,
            )
        })
        .collect())
}

/// Why a reassembler threw a packet away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// A piece's count disagreed with an earlier piece of the same packet.
    CountMismatch,
    /// An index arrived twice.
    Duplicate,
    /// A piece other than the last was shorter than [`MIN_PIECE_LEN`].
    ShortPiece,
    /// The pieces add up to more than the largest packet accepted.
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reassembled {
    /// A whole packet, ready to forward.
    Packet(Vec<u8>),
    /// The piece was kept; the packet is not complete yet.
    Pending,
    /// The packet this piece belongs to was dropped.
    Discarded(Discard),
}

struct Partial {
    pkt_id: u16,
    count: u8,
    have: u16,
    bytes: usize,
    started_ms: u64,
    pieces: Vec<Option<Vec<u8>>>,
}

/// Per-tunnel, per-direction reassembly with the section 6.3 bounds.
/// Time is the caller's monotonic clock in milliseconds.
pub struct Reassembler {
    partials: Vec<Partial>,
    max_packet: usize,
    slots: usize,
    timeout_ms: u64,
    dropped: u64,
}

impl Reassembler {
    pub fn new(max_packet: usize) -> Self {
        Self::with_limits(max_packet, REASSEMBLY_SLOTS, REASSEMBLY_TIMEOUT_MS)
    }

    pub fn with_limits(max_packet: usize, slots: usize, timeout_ms: u64) -> Self {
        Self {
            partials: Vec::new(),
            max_packet,
            slots: slots.max(1),
            timeout_ms,
            dropped: 0,
        }
    }

    /// Incomplete packets currently held.
    pub fn pending(&self) -> usize {
        self.partials.len()
    }

    /// Packets dropped so far: discarded, timed out or evicted.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Drops every incomplete packet older than the timeout.
    pub fn expire(&mut self, now_ms: u64) {
        let timeout = self.timeout_ms;
        let before = self.partials.len();
        self.partials
            .retain(|p| now_ms.saturating_sub(p.started_ms) < timeout);
        self.dropped += (before - self.partials.len()) as u64;
    }

    /// Takes one datagram's fragment header and data.
    pub fn push(&mut self, now_ms: u64, header: FragHeader, data: &[u8]) -> Reassembled {
        let (count, index, pkt_id) = match header {
            FragHeader::Whole => {
                if data.len() > self.max_packet {
                    self.dropped += 1;
                    return Reassembled::Discarded(Discard::TooLarge);
                }
                return Reassembled::Packet(data.to_vec());
            }
            FragHeader::Piece {
                count,
                index,
                pkt_id,
            } => (count, index, pkt_id),
        };
        self.expire(now_ms);
        let pos = match self.partials.iter().position(|p| p.pkt_id == pkt_id) {
            Some(pos) => pos,
            None => {
                if self.partials.len() >= self.slots {
                    // The oldest incomplete packet is the likeliest to have
                    // lost a piece already.
                    let oldest = self
                        .partials
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, p)| p.started_ms)
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.partials.swap_remove(oldest);
                    self.dropped += 1;
                }
                self.partials.push(Partial {
                    pkt_id,
                    count,
                    have: 0,
                    bytes: 0,
                    started_ms: now_ms,
                    pieces: (0..count).map(|_| None).collect(),
                });
                self.partials.len() - 1
            }
        };
        let partial = &mut self.partials[pos];
        let verdict = if partial.count != count {
            Some(Discard::CountMismatch)
        } else if partial.have & (1 << index) != 0 {
            Some(Discard::Duplicate)
        } else if index + 1 < count && data.len() < MIN_PIECE_LEN {
            Some(Discard::ShortPiece)
        } else if partial.bytes + data.len() > self.max_packet {
            Some(Discard::TooLarge)
        } else {
            None
        };
        if let Some(reason) = verdict {
            self.partials.swap_remove(pos);
            self.dropped += 1;
            return Reassembled::Discarded(reason);
        }
        partial.have |= 1 << index;
        partial.bytes += data.len();
        partial.pieces[usize::from(index)] = Some(data.to_vec());
        if partial.have.count_ones() < u32::from(count) {
            return Reassembled::Pending;
        }
        let done = self.partials.swap_remove(pos);
        let mut packet = Vec::with_capacity(done.bytes);
        for piece in done.pieces.into_iter().flatten() {
            packet.extend_from_slice(&piece);
        }
        Reassembled::Packet(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn datagrams(packet: &[u8], room: usize, pkt_id: u16) -> Vec<Vec<u8>> {
        split(packet.len(), room, pkt_id)
            .unwrap()
            .into_iter()
            .map(|(h, r)| {
                let mut d = Vec::new();
                h.encode(&mut d);
                d.extend_from_slice(&packet[r]);
                d
            })
            .collect()
    }

    fn feed(r: &mut Reassembler, now: u64, d: &[u8]) -> Reassembled {
        let (h, rest) = FragHeader::parse(d).unwrap();
        r.push(now, h, rest)
    }

    fn packet(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn small_packet_rides_whole() {
        let p = packet(100);
        let d = datagrams(&p, 1197, 1);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0][0], WHOLE);
        let mut r = Reassembler::new(1500);
        assert_eq!(feed(&mut r, 0, &d[0]), Reassembled::Packet(p));
    }

    #[test]
    fn mtu_packet_splits_in_two_and_reassembles_in_any_order() {
        let p = packet(1500);
        let d = datagrams(&p, 1197, 0xbeef);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0][0], 0x20);
        assert_eq!(d[1][0], 0x21);
        assert_eq!(&d[0][1..3], &0xbeefu16.to_le_bytes());
        assert!(d.iter().all(|x| x.len() <= 1197));
        let mut r = Reassembler::new(1500);
        assert_eq!(feed(&mut r, 0, &d[1]), Reassembled::Pending);
        assert_eq!(feed(&mut r, 5, &d[0]), Reassembled::Packet(p));
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn header_round_trips_and_rejects_bad_counts() {
        let mut out = Vec::new();
        FragHeader::Piece {
            count: 15,
            index: 14,
            pkt_id: 0x1234,
        }
        .encode(&mut out);
        assert_eq!(out, vec![0xfe, 0x34, 0x12]);
        assert_eq!(
            FragHeader::parse(&out).unwrap().0,
            FragHeader::Piece {
                count: 15,
                index: 14,
                pkt_id: 0x1234
            }
        );
        // count 1, index >= count, truncated pkt_id, empty.
        assert_eq!(
            FragHeader::parse(&[0x10, 0, 0]),
            Err(FragError::BadHeader(0x10))
        );
        assert_eq!(
            FragHeader::parse(&[0x22, 0, 0]),
            Err(FragError::BadHeader(0x22))
        );
        assert_eq!(FragHeader::parse(&[0x20, 0]), Err(FragError::Truncated));
        assert_eq!(FragHeader::parse(&[]), Err(FragError::Truncated));
    }

    #[test]
    fn split_limits() {
        assert_eq!(split(5000, 200, 0), Err(FragError::NoRoom));
        assert_eq!(split(65_000, 1200, 0), Err(FragError::TooLarge));
        let pieces = split(4000, 300, 0).unwrap();
        assert_eq!(pieces.len(), 14);
        assert!(pieces[..13].iter().all(|(_, r)| r.len() == 297));
    }

    #[test]
    fn conflicting_count_discards_the_packet() {
        let mut r = Reassembler::new(4000);
        let first = [&[0x20u8, 7, 0][..], &[1u8; 300][..]].concat();
        let other = [&[0x31u8, 7, 0][..], &[1u8; 300][..]].concat();
        assert_eq!(feed(&mut r, 0, &first), Reassembled::Pending);
        assert_eq!(
            feed(&mut r, 1, &other),
            Reassembled::Discarded(Discard::CountMismatch)
        );
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn duplicate_index_discards_the_packet() {
        let mut r = Reassembler::new(4000);
        let piece = [&[0x30u8, 9, 0][..], &[1u8; 300][..]].concat();
        assert_eq!(feed(&mut r, 0, &piece), Reassembled::Pending);
        assert_eq!(
            feed(&mut r, 1, &piece),
            Reassembled::Discarded(Discard::Duplicate)
        );
        assert_eq!(r.pending(), 0);
        assert_eq!(r.dropped(), 1);
    }

    #[test]
    fn short_middle_piece_and_oversize_are_discarded() {
        let mut r = Reassembler::new(1500);
        let short = [&[0x20u8, 1, 0][..], &[1u8; 100][..]].concat();
        assert_eq!(
            feed(&mut r, 0, &short),
            Reassembled::Discarded(Discard::ShortPiece)
        );
        let big0 = [&[0x20u8, 2, 0][..], &[1u8; 1000][..]].concat();
        let big1 = [&[0x21u8, 2, 0][..], &[1u8; 600][..]].concat();
        assert_eq!(feed(&mut r, 0, &big0), Reassembled::Pending);
        assert_eq!(
            feed(&mut r, 0, &big1),
            Reassembled::Discarded(Discard::TooLarge)
        );
        assert_eq!(
            feed(&mut r, 0, &[&[0u8][..], &[1u8; 1501][..]].concat()),
            Reassembled::Discarded(Discard::TooLarge)
        );
    }

    #[test]
    fn incomplete_packets_time_out_after_1000_ms() {
        let mut r = Reassembler::new(1500);
        let p = packet(1500);
        let d = datagrams(&p, 1197, 3);
        assert_eq!(feed(&mut r, 0, &d[0]), Reassembled::Pending);
        r.expire(999);
        assert_eq!(r.pending(), 1);
        r.expire(1000);
        assert_eq!(r.pending(), 0);
        // The late second piece starts a new packet that never completes.
        assert_eq!(feed(&mut r, 1001, &d[1]), Reassembled::Pending);
        assert_eq!(r.dropped(), 1);
    }

    #[test]
    fn at_most_64_incomplete_packets_are_kept() {
        let mut r = Reassembler::new(1500);
        for id in 0..70u16 {
            let piece = [&[0x20u8][..], &id.to_le_bytes()[..], &[1u8; 300][..]].concat();
            assert_eq!(feed(&mut r, u64::from(id), &piece), Reassembled::Pending);
        }
        assert_eq!(r.pending(), REASSEMBLY_SLOTS);
        assert_eq!(r.dropped(), 6);
        // The oldest were evicted: completing packet 0 starts over, 69 completes.
        let last = [&[0x21u8][..], &69u16.to_le_bytes()[..], &[2u8; 10][..]].concat();
        assert!(matches!(feed(&mut r, 70, &last), Reassembled::Packet(p) if p.len() == 310));
        let first = [&[0x21u8][..], &0u16.to_le_bytes()[..], &[2u8; 10][..]].concat();
        assert_eq!(feed(&mut r, 71, &first), Reassembled::Pending);
    }
}

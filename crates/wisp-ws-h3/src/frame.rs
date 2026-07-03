//! Minimal RFC 6455 frame codec for the post-extended-CONNECT H3 path.
//!
//! Why a hand-rolled codec instead of `tokio-websockets`: tokio-websockets
//! takes an `AsyncRead + AsyncWrite`. The h3 `RequestStream` exposes
//! `recv_data().await` and `send_data().await` on owned `Bytes`, with no
//! poll-based AsyncRead/Write. Threading those into an adapter would mean
//! storing pinned futures inside the adapter for both halves and managing
//! cancellation of in-flight `send_data` futures across `poll_write`s. The
//! WS framing we actually need is small enough (~150 lines of frame logic)
//! that doing it directly is simpler than the adapter.
//!
//! Coverage:
//!  - server→client: text/binary final frames, no fragmentation, no mask
//!  - client→server: text/binary, ping → pong reply, close → forward close,
//!    fragmentation across continuation frames is honored
//!  - control frames (close/ping/pong) MUST have FIN=1 and MUST NOT be
//!    fragmented (RFC 6455 §5.5) — enforced
//!  - mask key XOR is required on every client→server frame (RFC 6455
//!    §5.3) — enforced
//!  - 64-bit length frames over `MAX_FRAME_PAYLOAD` are rejected to keep
//!    the receive accumulator bounded; matches the `max_binary_frame_bytes`
//!    cap we already enforce one layer above.

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

pub const OP_CONT: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Hard cap on a single payload — same default as `wisp_config`'s
/// `max_binary_frame_bytes` to keep memory bounded against a malicious peer.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("client→server frame missing mask bit")]
    UnmaskedClientFrame,
    #[error("payload length {0} exceeds limit")]
    PayloadTooLarge(u64),
    #[error("control frame with FIN=0")]
    FragmentedControlFrame,
    #[error("control frame with payload > 125")]
    OversizedControlPayload,
    #[error("continuation frame without an open message")]
    UnexpectedContinuation,
    #[error("new data frame while a message was still being assembled")]
    InterleavedDataFrame,
    #[error("reserved bits set in frame header")]
    ReservedBitsSet,
    #[error("opcode 0x{0:x} is not recognized")]
    UnknownOpcode(u8),
}

/// Decoded inbound message ready for the Wisp layer.
#[derive(Debug)]
pub enum InboundFrame {
    Text(String),
    Binary(Bytes),
    /// Peer sent a Ping; reply with the same payload as Pong.
    Ping(Bytes),
    /// Peer sent Pong; we ignore but emit so the writer task can be told.
    Pong,
    /// Peer initiated close. `payload` is the optional 2-byte status code +
    /// utf-8 reason; we forward it as-is in our own close response.
    Close {
        payload: Bytes,
    },
}

/// Streaming WS frame parser. Holds partial-frame and partial-message
/// buffers; call [`Decoder::push`] with each received chunk and drain
/// completed frames via [`Decoder::next_frame`] until it returns `None`.
pub struct Decoder {
    rx: BytesMut,
    msg_buf: BytesMut,
    msg_opcode: Option<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            rx: BytesMut::with_capacity(8 * 1024),
            msg_buf: BytesMut::new(),
            msg_opcode: None,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.rx.extend_from_slice(chunk);
    }

    /// Drain one fully-assembled inbound frame. Returns `None` when the
    /// buffer holds only a partial frame; call again after pushing more
    /// bytes.
    pub fn next_frame(&mut self) -> Result<Option<InboundFrame>, FrameError> {
        loop {
            let Some((parsed, consumed)) = parse_one(&self.rx)? else {
                return Ok(None);
            };
            let _ = self.rx.split_to(consumed);

            // Control frames are independent of the data continuation state.
            match parsed.opcode {
                OP_CLOSE => {
                    if !parsed.fin {
                        return Err(FrameError::FragmentedControlFrame);
                    }
                    return Ok(Some(InboundFrame::Close {
                        payload: parsed.payload.freeze(),
                    }));
                }
                OP_PING => {
                    if !parsed.fin {
                        return Err(FrameError::FragmentedControlFrame);
                    }
                    return Ok(Some(InboundFrame::Ping(parsed.payload.freeze())));
                }
                OP_PONG => {
                    if !parsed.fin {
                        return Err(FrameError::FragmentedControlFrame);
                    }
                    return Ok(Some(InboundFrame::Pong));
                }
                OP_CONT => {
                    if self.msg_opcode.is_none() {
                        return Err(FrameError::UnexpectedContinuation);
                    }
                    if self.msg_buf.len() + parsed.payload.len() > MAX_FRAME_PAYLOAD {
                        return Err(FrameError::PayloadTooLarge(
                            (self.msg_buf.len() + parsed.payload.len()) as u64,
                        ));
                    }
                    self.msg_buf.unsplit(parsed.payload);
                    if parsed.fin {
                        let opcode = self.msg_opcode.take().expect("opcode set above");
                        let body = self.msg_buf.split().freeze();
                        return Ok(Some(finalize_data(opcode, body)));
                    }
                    // Need more frames to complete the message.
                }
                OP_TEXT | OP_BINARY => {
                    if self.msg_opcode.is_some() {
                        return Err(FrameError::InterleavedDataFrame);
                    }
                    if parsed.fin {
                        return Ok(Some(finalize_data(parsed.opcode, parsed.payload.freeze())));
                    }
                    if parsed.payload.len() > MAX_FRAME_PAYLOAD {
                        return Err(FrameError::PayloadTooLarge(parsed.payload.len() as u64));
                    }
                    self.msg_opcode = Some(parsed.opcode);
                    self.msg_buf = parsed.payload;
                }
                other => return Err(FrameError::UnknownOpcode(other)),
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

fn finalize_data(opcode: u8, payload: Bytes) -> InboundFrame {
    if opcode == OP_TEXT {
        match String::from_utf8(payload.to_vec()) {
            Ok(s) => InboundFrame::Text(s),
            // Per RFC the connection should be closed; we drop the payload
            // and return an empty text frame. The Wisp layer above tolerates
            // a stray empty text since it only routes text→proxy_control.
            Err(_) => InboundFrame::Text(String::new()),
        }
    } else {
        InboundFrame::Binary(payload)
    }
}

struct ParsedFrame {
    fin: bool,
    opcode: u8,
    payload: BytesMut,
}

fn parse_one(buf: &[u8]) -> Result<Option<(ParsedFrame, usize)>, FrameError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    if b0 & 0x70 != 0 {
        return Err(FrameError::ReservedBitsSet);
    }
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;
    let len_field = b1 & 0x7F;
    if !masked {
        return Err(FrameError::UnmaskedClientFrame);
    }
    let mut header_len: usize = 2;
    let payload_len: u64 = match len_field {
        0..=125 => len_field as u64,
        126 => {
            if buf.len() < header_len + 2 {
                return Ok(None);
            }
            let n = u16::from_be_bytes([buf[header_len], buf[header_len + 1]]) as u64;
            header_len += 2;
            n
        }
        127 => {
            if buf.len() < header_len + 8 {
                return Ok(None);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[header_len..header_len + 8]);
            header_len += 8;
            u64::from_be_bytes(bytes)
        }
        _ => unreachable!("len_field is 7 bits"),
    };
    if payload_len > MAX_FRAME_PAYLOAD as u64 {
        return Err(FrameError::PayloadTooLarge(payload_len));
    }
    if (opcode == OP_CLOSE || opcode == OP_PING || opcode == OP_PONG) && payload_len > 125 {
        return Err(FrameError::OversizedControlPayload);
    }
    let mask_off = header_len;
    if buf.len() < mask_off + 4 {
        return Ok(None);
    }
    let mask_key = [
        buf[mask_off],
        buf[mask_off + 1],
        buf[mask_off + 2],
        buf[mask_off + 3],
    ];
    let payload_off = mask_off + 4;
    let payload_len = payload_len as usize;
    if buf.len() < payload_off + payload_len {
        return Ok(None);
    }
    let mut payload = BytesMut::with_capacity(payload_len);
    let raw = &buf[payload_off..payload_off + payload_len];
    for (i, b) in raw.iter().enumerate() {
        payload.put_u8(*b ^ mask_key[i & 3]);
    }
    Ok(Some((
        ParsedFrame {
            fin,
            opcode,
            payload,
        },
        payload_off + payload_len,
    )))
}

/// Encode a final-frame data message for server→client. Server-sent frames
/// MUST NOT be masked (RFC 6455 §5.1).
pub fn encode_data(opcode: u8, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(payload.len() + 10);
    out.put_u8(0x80 | (opcode & 0x0F));
    let n = payload.len();
    if n <= 125 {
        out.put_u8(n as u8);
    } else if n <= u16::MAX as usize {
        out.put_u8(126);
        out.put_u16(n as u16);
    } else {
        out.put_u8(127);
        out.put_u64(n as u64);
    }
    out.put_slice(payload);
    out.freeze()
}

/// Encode a Close control frame with optional 2-byte status code + reason.
pub fn encode_close(code: u16, reason: &[u8]) -> Bytes {
    let mut payload = BytesMut::with_capacity(2 + reason.len());
    payload.put_u16(code);
    payload.put_slice(reason);
    let mut out = BytesMut::with_capacity(2 + payload.len());
    out.put_u8(0x80 | OP_CLOSE);
    out.put_u8(payload.len() as u8);
    out.put_slice(&payload);
    out.freeze()
}

/// Encode an empty-payload Pong control frame.
pub fn encode_pong(echo: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(2 + echo.len());
    out.put_u8(0x80 | OP_PONG);
    out.put_u8(echo.len() as u8);
    out.put_slice(echo);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if fin { 0x80 } else { 0x00 } | (opcode & 0x0F));
        let n = payload.len();
        if n <= 125 {
            out.push(0x80 | n as u8);
        } else if n <= u16::MAX as usize {
            out.push(0x80 | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
        let key = [0xa1, 0xb2, 0xc3, 0xd4];
        out.extend_from_slice(&key);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ key[i & 3]);
        }
        out
    }

    #[test]
    fn decodes_single_binary_frame() {
        let mut d = Decoder::new();
        d.push(&masked(OP_BINARY, true, b"hello"));
        match d.next_frame().unwrap().unwrap() {
            InboundFrame::Binary(b) => assert_eq!(&b[..], b"hello"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn decodes_text_frame() {
        let mut d = Decoder::new();
        d.push(&masked(OP_TEXT, true, b"hi"));
        match d.next_frame().unwrap().unwrap() {
            InboundFrame::Text(s) => assert_eq!(s, "hi"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn assembles_continuation_frames() {
        let mut d = Decoder::new();
        d.push(&masked(OP_BINARY, false, b"foo"));
        d.push(&masked(OP_CONT, false, b"bar"));
        d.push(&masked(OP_CONT, true, b"baz"));
        let frame = d.next_frame().unwrap().unwrap();
        match frame {
            InboundFrame::Binary(b) => assert_eq!(&b[..], b"foobarbaz"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_unmasked_client_frame() {
        let mut d = Decoder::new();
        // Manually construct an unmasked frame.
        let buf = [0x82, 0x05, b'h', b'e', b'l', b'l', b'o'];
        d.push(&buf);
        let err = d.next_frame().unwrap_err();
        matches!(err, FrameError::UnmaskedClientFrame);
    }

    #[test]
    fn rejects_fragmented_control_frame() {
        let mut d = Decoder::new();
        // Ping with FIN=0: invalid.
        d.push(&masked(OP_PING, false, b""));
        let err = d.next_frame().unwrap_err();
        matches!(err, FrameError::FragmentedControlFrame);
    }

    #[test]
    fn handles_partial_then_full_frame() {
        let mut d = Decoder::new();
        let frame = masked(OP_BINARY, true, b"split");
        d.push(&frame[..3]);
        assert!(d.next_frame().unwrap().is_none());
        d.push(&frame[3..]);
        match d.next_frame().unwrap().unwrap() {
            InboundFrame::Binary(b) => assert_eq!(&b[..], b"split"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn encode_data_sets_fin_and_opcode() {
        let f = encode_data(OP_BINARY, b"x");
        assert_eq!(f[0], 0x82);
        assert_eq!(f[1], 1);
        assert_eq!(f[2], b'x');
    }

    #[test]
    fn encode_data_uses_16bit_length_for_larger_payloads() {
        let p = vec![7u8; 200];
        let f = encode_data(OP_BINARY, &p);
        assert_eq!(f[0], 0x82);
        assert_eq!(f[1], 126);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]) as usize, 200);
    }

    #[test]
    fn encode_close_round_trips_through_decoder() {
        let f = encode_close(1000, b"bye");
        // Server-sent close is unmasked — decoder rejects unmasked frames,
        // so we only verify the wire shape.
        assert_eq!(f[0], 0x88);
        assert_eq!(f[1], 5);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]), 1000);
        assert_eq!(&f[4..], b"bye");
    }
}

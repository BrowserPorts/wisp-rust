//! HTTP/HTTPS/H2c/WS/H3 packet inspection. Mirrors `wisp-wt/src/inspection.ts`.
//!
//! The TS module does full TLS ClientHello + HPACK + QUIC Initial decode. The
//! Rust port ships a focused subset that detects the common shapes (HTTP/1.x
//! request line, HTTP/2 connection preface, TLS ClientHello marker, WebSocket
//! Upgrade) so the server can gate against `protocol_inspection_allowed_protocols`
//! without writing a full HPACK decoder. Returns `NeedMore` until enough bytes
//! are buffered or the configured `protocol_inspection_max_bytes` cap is hit.

#![forbid(unsafe_code)]

use wisp_config::{AllowedProtocol, WispServerOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProtocol {
    Http,
    Https,
    Http2,
    Ws,
    H3,
    Unknown,
}

impl DetectedProtocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Http2 => "http2",
            Self::Ws => "ws",
            Self::H3 => "h3",
            Self::Unknown => "unknown",
        }
    }

    fn as_allowed(self) -> Option<AllowedProtocol> {
        match self {
            Self::Http => Some(AllowedProtocol::Http),
            Self::Https => Some(AllowedProtocol::Https),
            Self::Http2 => Some(AllowedProtocol::Http2),
            Self::Ws => Some(AllowedProtocol::Ws),
            Self::H3 => Some(AllowedProtocol::H3),
            Self::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectionDecision {
    Allow(DetectedProtocol),
    NeedMore,
    Block { reason: BlockReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Protocol not in `protocol_inspection_allowed_protocols`.
    ProtocolNotAllowed,
    /// H2c (HTTP/2 cleartext preface) and the policy disallows it.
    H2cDisallowed,
    /// TLS ClientHello with no ALPN and the policy disallows it.
    TlsWithoutAlpnDisallowed,
    /// QUIC Initial packet and the policy disallows it.
    QuicInitialDisallowed,
    /// Inspection buffer exceeded `max_bytes` without a decision.
    BufferExhausted,
}

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// One-shot detector: feed the first chunk of client bytes; returns a decision
/// or `NeedMore`.
pub fn inspect(buf: &[u8], options: &WispServerOptions) -> InspectionDecision {
    if !options.protocol_inspection {
        return InspectionDecision::Allow(DetectedProtocol::Unknown);
    }
    if buf.is_empty() {
        return InspectionDecision::NeedMore;
    }

    // HTTP/2 preface (h2c).
    if buf.len() < HTTP2_PREFACE.len() && HTTP2_PREFACE.starts_with(buf) {
        return InspectionDecision::NeedMore;
    }
    if buf.starts_with(HTTP2_PREFACE) {
        return gate(
            DetectedProtocol::Http2,
            options,
            !options.protocol_inspection_allow_h2c,
            BlockReason::H2cDisallowed,
        );
    }

    // TLS ClientHello: 0x16 record type, version major 0x03 (SSL3+).
    if buf[0] == 0x16 {
        if buf.len() < 5 {
            return InspectionDecision::NeedMore;
        }
        if buf[1] == 0x03 {
            let alpn_known = scan_tls_alpn(buf);
            let detected = alpn_known
                .as_ref()
                .and_then(|name| match name.as_slice() {
                    b"http/1.1" => Some(DetectedProtocol::Https),
                    b"h2" => Some(DetectedProtocol::Http2),
                    b"h3" => Some(DetectedProtocol::H3),
                    _ => None,
                })
                .unwrap_or(DetectedProtocol::Https);
            if alpn_known.is_none() && !options.protocol_inspection_allow_tls_without_alpn {
                return InspectionDecision::Block {
                    reason: BlockReason::TlsWithoutAlpnDisallowed,
                };
            }
            return gate(detected, options, false, BlockReason::ProtocolNotAllowed);
        }
    }

    // QUIC long-header Initial: first byte top two bits are 0b11 and packet
    // type in the next two is 0b00 — i.e. (b & 0xF0) == 0xC0.
    if (buf[0] & 0xF0) == 0xC0 {
        if !options.protocol_inspection_allow_quic_initial {
            return InspectionDecision::Block {
                reason: BlockReason::QuicInitialDisallowed,
            };
        }
        return gate(
            DetectedProtocol::H3,
            options,
            false,
            BlockReason::ProtocolNotAllowed,
        );
    }

    // HTTP/1.x request line.
    if let Some(end) = find_crlf(buf) {
        let line = &buf[..end];
        if looks_like_http1_line(line) {
            let is_ws = scan_for_ws_upgrade(buf);
            let protocol = if is_ws {
                DetectedProtocol::Ws
            } else {
                DetectedProtocol::Http
            };
            return gate(protocol, options, false, BlockReason::ProtocolNotAllowed);
        }
        // Header line found but not an HTTP/1.x request line → unknown plaintext.
        return InspectionDecision::Block {
            reason: BlockReason::ProtocolNotAllowed,
        };
    }

    // Not enough bytes yet — request more, up to `max_bytes`.
    if (buf.len() as u64) >= options.protocol_inspection_max_bytes {
        return InspectionDecision::Block {
            reason: BlockReason::BufferExhausted,
        };
    }
    InspectionDecision::NeedMore
}

fn gate(
    detected: DetectedProtocol,
    options: &WispServerOptions,
    forced_block: bool,
    forced_reason: BlockReason,
) -> InspectionDecision {
    if forced_block {
        return InspectionDecision::Block {
            reason: forced_reason,
        };
    }
    if let Some(allowed) = detected.as_allowed() {
        if !options
            .protocol_inspection_allowed_protocols
            .contains(&allowed)
        {
            return InspectionDecision::Block {
                reason: BlockReason::ProtocolNotAllowed,
            };
        }
    }
    InspectionDecision::Allow(detected)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn looks_like_http1_line(line: &[u8]) -> bool {
    // Crude: METHOD SP TARGET SP HTTP/1.x
    let s = match std::str::from_utf8(line) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut parts = s.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let _target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    ) && (version.starts_with("HTTP/1.0") || version.starts_with("HTTP/1.1"))
}

fn scan_for_ws_upgrade(buf: &[u8]) -> bool {
    // Look (case-insensitive) for "Upgrade: websocket".
    let needle = b"upgrade: websocket";
    if buf.len() < needle.len() {
        return false;
    }
    for i in 0..=buf.len() - needle.len() {
        let mut ok = true;
        for j in 0..needle.len() {
            let c = buf[i + j];
            let lower = if c.is_ascii_uppercase() { c + 32 } else { c };
            if lower != needle[j] {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}

/// Very small TLS ALPN extension scanner. Returns the first ALPN protocol if
/// found. We avoid a full ClientHello parser by sweeping for the ALPN
/// extension marker (0x00, 0x10) in the extension block; this is a best-effort
/// detector, not a security boundary (the server still terminates TLS via
/// msquic; this only informs `protocol_inspection_allowed_protocols`).
fn scan_tls_alpn(buf: &[u8]) -> Option<Vec<u8>> {
    // Skip TLS record header (5) + handshake header (4) + version (2) + random (32) = 43.
    let mut i = 43;
    if buf.len() <= i {
        return None;
    }
    // session_id
    let sid_len = *buf.get(i)? as usize;
    i += 1 + sid_len;
    // cipher_suites
    let cs_len = u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]) as usize;
    i += 2 + cs_len;
    // compression_methods
    let cm_len = *buf.get(i)? as usize;
    i += 1 + cm_len;
    // extensions length
    let ext_total = u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]) as usize;
    i += 2;
    let end = i + ext_total;
    while i + 4 <= end && i + 4 <= buf.len() {
        let ext_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let ext_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let body_start = i + 4;
        let body_end = body_start + ext_len;
        if body_end > buf.len() {
            return None;
        }
        if ext_type == 0x0010 {
            // ALPN: u16 list length, then [u8 len][protocol].
            if ext_len < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([buf[body_start], buf[body_start + 1]]) as usize;
            let mut j = body_start + 2;
            if j + list_len > body_end {
                return None;
            }
            if j + 1 > buf.len() {
                return None;
            }
            let plen = buf[j] as usize;
            j += 1;
            if j + plen <= buf.len() {
                return Some(buf[j..j + plen].to_vec());
            }
            return None;
        }
        i = body_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> WispServerOptions {
        WispServerOptions::default()
    }

    #[test]
    fn detects_http1() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            inspect(buf, &opts()),
            InspectionDecision::Allow(DetectedProtocol::Http)
        );
    }

    #[test]
    fn detects_websocket() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(
            inspect(buf, &opts()),
            InspectionDecision::Allow(DetectedProtocol::Ws)
        );
    }

    #[test]
    fn detects_h2c_preface() {
        let mut o = opts();
        o.protocol_inspection_allow_h2c = true;
        let r = inspect(HTTP2_PREFACE, &o);
        assert_eq!(r, InspectionDecision::Allow(DetectedProtocol::Http2));
    }

    #[test]
    fn blocks_h2c_when_disallowed() {
        let mut o = opts();
        o.protocol_inspection_allow_h2c = false;
        let r = inspect(HTTP2_PREFACE, &o);
        assert!(matches!(
            r,
            InspectionDecision::Block {
                reason: BlockReason::H2cDisallowed
            }
        ));
    }

    #[test]
    fn quic_initial_blocked_by_default() {
        let buf = [0xC0u8; 64];
        let r = inspect(&buf, &opts());
        assert!(matches!(
            r,
            InspectionDecision::Block {
                reason: BlockReason::QuicInitialDisallowed
            }
        ));
    }

    #[test]
    fn need_more_on_short_buffer() {
        let r = inspect(b"GE", &opts());
        assert_eq!(r, InspectionDecision::NeedMore);
    }

    #[test]
    fn inspection_disabled_short_circuits() {
        let mut o = opts();
        o.protocol_inspection = false;
        let r = inspect(b"\x00\x00\x00", &o);
        assert_eq!(r, InspectionDecision::Allow(DetectedProtocol::Unknown));
    }
}

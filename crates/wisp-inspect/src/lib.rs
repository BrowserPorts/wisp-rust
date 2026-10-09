//! HTTP/HTTPS/H2c/WS/H3 packet inspection.
//!
//! Ships a focused subset that detects the common shapes (HTTP/1.x request
//! line, HTTP/2 connection preface, TLS ClientHello marker, WebSocket Upgrade)
//! so the server can gate against `protocol_inspection_allowed_protocols`
//! without a full HPACK decoder. Returns `NeedMore` until enough bytes are
//! buffered or the configured `protocol_inspection_max_bytes` cap is hit.

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
    if (buf.len() as u64) > options.protocol_inspection_max_bytes {
        return InspectionDecision::Block {
            reason: BlockReason::BufferExhausted,
        };
    }

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

    if buf[0] == 0x16 {
        if buf.len() < 5 {
            return InspectionDecision::NeedMore;
        }
        if buf[1] == 0x03 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let total = 5_usize.saturating_add(record_len);
            if total as u64 > options.protocol_inspection_max_bytes {
                return InspectionDecision::Block {
                    reason: BlockReason::BufferExhausted,
                };
            }
            if buf.len() < total {
                return InspectionDecision::NeedMore;
            }
            let alpn = match parse_tls_alpn(&buf[..total]) {
                Ok(value) => value,
                Err(()) => {
                    return InspectionDecision::Block {
                        reason: BlockReason::ProtocolNotAllowed,
                    };
                }
            };
            let detected = alpn.unwrap_or(DetectedProtocol::Https);
            if alpn.is_none() && !options.protocol_inspection_allow_tls_without_alpn {
                return InspectionDecision::Block {
                    reason: BlockReason::TlsWithoutAlpnDisallowed,
                };
            }
            return gate(detected, options, false, BlockReason::ProtocolNotAllowed);
        }
    }

    if let Some(end) = find_crlf(buf) {
        let line = &buf[..end];
        if looks_like_http1_line(line) {
            if !buf.windows(4).any(|window| window == b"\r\n\r\n") {
                if (buf.len() as u64) >= options.protocol_inspection_max_bytes {
                    return InspectionDecision::Block {
                        reason: BlockReason::BufferExhausted,
                    };
                }
                return InspectionDecision::NeedMore;
            }
            let is_ws = match scan_for_ws_upgrade(buf) {
                Ok(value) => value,
                Err(()) => {
                    return InspectionDecision::Block {
                        reason: BlockReason::ProtocolNotAllowed,
                    };
                }
            };
            let protocol = if is_ws {
                DetectedProtocol::Ws
            } else {
                DetectedProtocol::Http
            };
            return gate(protocol, options, false, BlockReason::ProtocolNotAllowed);
        }
        return InspectionDecision::Block {
            reason: BlockReason::ProtocolNotAllowed,
        };
    }

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

fn scan_for_ws_upgrade(buf: &[u8]) -> Result<bool, ()> {
    let Ok(headers) = std::str::from_utf8(buf) else {
        return Err(());
    };
    let mut upgrade = false;
    let mut connection = false;
    for line in headers.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(());
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.bytes().any(|byte| byte < b' ' && byte != b'\t')
        {
            return Err(());
        }
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("websocket"));
        } else if name.eq_ignore_ascii_case("connection") {
            connection |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        }
    }
    Ok(upgrade && connection)
}

fn parse_tls_alpn(buf: &[u8]) -> Result<Option<DetectedProtocol>, ()> {
    if buf.len() < 9 || buf[0] != 0x16 || buf[5] != 0x01 {
        return Err(());
    }
    let handshake_len =
        (usize::from(buf[6]) << 16) | (usize::from(buf[7]) << 8) | usize::from(buf[8]);
    if handshake_len.saturating_add(9) > buf.len() {
        return Err(());
    }
    let mut i = 43;
    if buf.len() <= i {
        return Err(());
    }
    let sid_len = usize::from(*buf.get(i).ok_or(())?);
    i += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*buf.get(i).ok_or(())?, *buf.get(i + 1).ok_or(())?]) as usize;
    i += 2 + cs_len;
    let cm_len = usize::from(*buf.get(i).ok_or(())?);
    i += 1 + cm_len;
    let ext_total =
        u16::from_be_bytes([*buf.get(i).ok_or(())?, *buf.get(i + 1).ok_or(())?]) as usize;
    i += 2;
    let end = i.checked_add(ext_total).ok_or(())?;
    if end > buf.len() {
        return Err(());
    }
    while i < end {
        if i + 4 > end {
            return Err(());
        }
        let ext_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let ext_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let body_start = i + 4;
        let body_end = body_start.checked_add(ext_len).ok_or(())?;
        if body_end > end {
            return Err(());
        }
        if ext_type == 0x0010 {
            if ext_len < 2 {
                return Err(());
            }
            let list_len = u16::from_be_bytes([buf[body_start], buf[body_start + 1]]) as usize;
            let mut j = body_start + 2;
            if j.checked_add(list_len).ok_or(())? != body_end {
                return Err(());
            }
            while j < body_end {
                let plen = usize::from(*buf.get(j).ok_or(())?);
                j += 1;
                let protocol_end = j.checked_add(plen).ok_or(())?;
                if plen == 0 || protocol_end > body_end {
                    return Err(());
                }
                let detected = match &buf[j..protocol_end] {
                    b"http/1.1" => Some(DetectedProtocol::Https),
                    b"h2" => Some(DetectedProtocol::Http2),
                    b"h3" => Some(DetectedProtocol::H3),
                    _ => None,
                };
                if detected.is_some() {
                    return Ok(detected);
                }
                j = protocol_end;
            }
            return Ok(None);
        }
        i = body_end;
    }
    Ok(None)
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
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
        assert_eq!(
            inspect(buf, &opts()),
            InspectionDecision::Allow(DetectedProtocol::Ws)
        );
    }

    #[test]
    fn waits_for_complete_http_headers_before_classifying() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(inspect(buf, &opts()), InspectionDecision::NeedMore);
    }

    #[test]
    fn websocket_cannot_pass_as_http_from_a_partial_header() {
        let mut options = opts();
        options.protocol_inspection_allowed_protocols = vec![AllowedProtocol::Http];
        let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(inspect(partial, &options), InspectionDecision::NeedMore);
        let complete = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
        assert!(matches!(
            inspect(complete, &options),
            InspectionDecision::Block {
                reason: BlockReason::ProtocolNotAllowed
            }
        ));
    }

    #[test]
    fn waits_for_the_full_tls_record() {
        let buf = [0x16, 0x03, 0x03, 0x00, 0x20, 0x01];
        assert_eq!(inspect(&buf, &opts()), InspectionDecision::NeedMore);
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
    fn quic_shape_on_tcp_is_not_classified_as_h3() {
        let buf = [0xC0u8; 64];
        let r = inspect(&buf, &opts());
        assert_eq!(r, InspectionDecision::NeedMore);
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

//! HTTP/HTTPS/H2c/WS/H3 packet inspection.
//!
//! Ships a focused subset that detects the common shapes (HTTP/1.x request
//! line, HTTP/2 connection preface, TLS ClientHello marker, WebSocket Upgrade)
//! so the server can gate against `protocol_inspection_allowed_protocols`
//! without a full HPACK decoder. Returns `NeedMore` until enough bytes are
//! buffered or the configured `protocol_inspection_max_bytes` cap is hit.
//! [`Inspector`] keeps its scan offsets between calls, so a client that drips
//! one byte at a time costs linear work, and it rejects a stream as soon as
//! the first bytes match no accepted protocol.

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
    /// The TLS SNI or HTTP Host does not name the host the client asked to dial.
    HostMismatch,
}

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Methods a proxied HTTP/1.x request may start with, each with the space that
/// ends it. CONNECT and TRACE are deliberately absent: CONNECT opens a second
/// tunnel to a host of the client's choosing and TRACE reflects headers.
const HTTP_METHODS: [&[u8]; 7] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
];

/// Longest request line accepted before the stream is rejected.
const MAX_REQUEST_LINE: usize = 8 * 1024;

/// One-shot detector: feed the first chunk of client bytes; returns a decision
/// or `NeedMore`. Rescans `buf` from the start on every call, so callers that
/// buffer a drip-fed stream should hold an [`Inspector`] instead.
pub fn inspect(buf: &[u8], options: &WispServerOptions) -> InspectionDecision {
    Inspector::new(None).feed(buf, options)
}

/// Like [`inspect`], and additionally requires the TLS SNI or HTTP Host to
/// match `connect_host` (see [`Inspector::new`]).
pub fn inspect_for_host(
    buf: &[u8],
    options: &WispServerOptions,
    connect_host: &str,
) -> InspectionDecision {
    Inspector::new(Some(connect_host)).feed(buf, options)
}

/// Incremental detector for one stream. `feed` takes the whole buffer
/// accumulated so far (it only ever grows) and resumes scanning from the
/// offsets saved by the previous call, so total work is linear in the bytes
/// received no matter how finely the client splits them.
#[derive(Debug, Default)]
pub struct Inspector {
    /// Normalized CONNECT hostname the SNI or Host must match. `None` when no
    /// check applies: no hostname given, or the CONNECT target was an IP literal.
    expected_host: Option<String>,
    /// Bytes already searched for the end of the request line.
    line_scan: usize,
    line_end: Option<usize>,
    request_line_checked: bool,
    /// Bytes already searched for the blank line that ends the headers.
    head_scan: usize,
    /// Bytes examined by the incremental searches, for the linear-time test.
    #[cfg(test)]
    scanned: u64,
}

impl Inspector {
    /// `connect_host` is the hostname the client asked the proxy to dial. An
    /// IP literal (bare or bracketed) disables the SNI and Host check, since
    /// no name can be fronted behind it.
    pub fn new(connect_host: Option<&str>) -> Self {
        let expected_host = connect_host.and_then(|host| {
            let normalized = normalize_host(host);
            if normalized.parse::<std::net::IpAddr>().is_ok() {
                None
            } else {
                Some(normalized)
            }
        });
        Self {
            expected_host,
            ..Self::default()
        }
    }

    pub fn feed(&mut self, buf: &[u8], options: &WispServerOptions) -> InspectionDecision {
        if !options.protocol_inspection {
            return InspectionDecision::Allow(DetectedProtocol::Unknown);
        }
        if buf.is_empty() {
            return InspectionDecision::NeedMore;
        }
        let max_bytes = options.protocol_inspection_max_bytes;
        if (buf.len() as u64) > max_bytes {
            return InspectionDecision::Block {
                reason: BlockReason::BufferExhausted,
            };
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
            return self.feed_tls(buf, options);
        }

        // Reject as soon as the first bytes cannot begin any accepted protocol,
        // instead of buffering up to the cap waiting for a request line.
        let preface_partial = HTTP2_PREFACE.starts_with(buf);
        match http_method_prefix(buf) {
            MethodPrefix::Partial => return InspectionDecision::NeedMore,
            MethodPrefix::Complete => {}
            MethodPrefix::None if preface_partial => return InspectionDecision::NeedMore,
            MethodPrefix::None => {
                return InspectionDecision::Block {
                    reason: BlockReason::ProtocolNotAllowed,
                };
            }
        }
        self.feed_http1(buf, options)
    }

    fn feed_tls(&mut self, buf: &[u8], options: &WispServerOptions) -> InspectionDecision {
        let blocked = |reason| InspectionDecision::Block { reason };
        if buf.len() >= 2 && buf[1] != 0x03 {
            return blocked(BlockReason::ProtocolNotAllowed);
        }
        // Handshake type 1 is ClientHello; anything else is not a client's first flight.
        if buf.len() >= 6 && buf[5] != 0x01 {
            return blocked(BlockReason::ProtocolNotAllowed);
        }
        if buf.len() < 5 {
            return InspectionDecision::NeedMore;
        }
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total = 5_usize.saturating_add(record_len);
        if total as u64 > options.protocol_inspection_max_bytes {
            return blocked(BlockReason::BufferExhausted);
        }
        if buf.len() < total {
            return InspectionDecision::NeedMore;
        }
        let Ok(hello) = parse_client_hello(&buf[..total]) else {
            return blocked(BlockReason::ProtocolNotAllowed);
        };
        if let Some(expected) = &self.expected_host {
            let matches = hello
                .sni
                .as_deref()
                .is_some_and(|sni| normalize_host(sni) == *expected);
            if !matches {
                return blocked(BlockReason::HostMismatch);
            }
        }
        let detected = hello.alpn.unwrap_or(DetectedProtocol::Https);
        if hello.alpn.is_none() && !options.protocol_inspection_allow_tls_without_alpn {
            return blocked(BlockReason::TlsWithoutAlpnDisallowed);
        }
        gate(detected, options, false, BlockReason::ProtocolNotAllowed)
    }

    fn feed_http1(&mut self, buf: &[u8], options: &WispServerOptions) -> InspectionDecision {
        let blocked = |reason| InspectionDecision::Block { reason };
        let max_bytes = options.protocol_inspection_max_bytes;

        if self.line_end.is_none() {
            // A CRLF split across two feeds starts one byte before the resume point.
            let from = self.line_scan.saturating_sub(1);
            #[cfg(test)]
            {
                self.scanned += (buf.len() - from) as u64;
            }
            self.line_end = find_crlf(&buf[from..]).map(|at| from + at);
            self.line_scan = buf.len();
        }
        let Some(line_end) = self.line_end else {
            if buf.len() > MAX_REQUEST_LINE || (buf.len() as u64) >= max_bytes {
                return blocked(BlockReason::BufferExhausted);
            }
            return InspectionDecision::NeedMore;
        };
        if !self.request_line_checked {
            if line_end > MAX_REQUEST_LINE {
                return blocked(BlockReason::BufferExhausted);
            }
            if check_request_line(&buf[..line_end]).is_err() {
                return blocked(BlockReason::ProtocolNotAllowed);
            }
            self.request_line_checked = true;
        }

        let from = self.head_scan.saturating_sub(3).max(line_end);
        #[cfg(test)]
        {
            self.scanned += (buf.len() - from) as u64;
        }
        let Some(at) = find_head_end(&buf[from..]) else {
            self.head_scan = buf.len();
            if (buf.len() as u64) >= max_bytes {
                return blocked(BlockReason::BufferExhausted);
            }
            return InspectionDecision::NeedMore;
        };
        let head_end = from + at + 4;

        let Ok(head) = scan_headers(&buf[line_end..head_end]) else {
            return blocked(BlockReason::ProtocolNotAllowed);
        };
        if let Some(expected) = &self.expected_host {
            let matches = head
                .host
                .as_deref()
                .is_some_and(|host| normalize_host(host_without_port(host)) == *expected);
            if !matches {
                return blocked(BlockReason::HostMismatch);
            }
        }
        let protocol = if head.websocket {
            DetectedProtocol::Ws
        } else {
            DetectedProtocol::Http
        };
        gate(protocol, options, false, BlockReason::ProtocolNotAllowed)
    }
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

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[derive(Debug, PartialEq, Eq)]
enum MethodPrefix {
    /// `buf` starts with an accepted method and its trailing space.
    Complete,
    /// `buf` is a proper prefix of an accepted method.
    Partial,
    None,
}

fn http_method_prefix(buf: &[u8]) -> MethodPrefix {
    let mut partial = false;
    for method in HTTP_METHODS {
        if buf.starts_with(method) {
            return MethodPrefix::Complete;
        }
        partial |= method.starts_with(buf);
    }
    if partial {
        MethodPrefix::Partial
    } else {
        MethodPrefix::None
    }
}

/// Accepts only origin-form targets. Absolute-form (`GET http://host/`) and
/// authority-form targets name a destination other than the one dialed.
fn check_request_line(line: &[u8]) -> Result<(), ()> {
    if !line.iter().all(|byte| (b' '..=b'~').contains(byte)) {
        return Err(());
    }
    let mut parts = line.split(|&byte| byte == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(());
    };
    if !HTTP_METHODS
        .iter()
        .any(|allowed| &allowed[..allowed.len() - 1] == method)
    {
        return Err(());
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(());
    }
    if target.first() == Some(&b'/') || (method == b"OPTIONS" && target == b"*") {
        Ok(())
    } else {
        Err(())
    }
}

struct HeadInfo {
    websocket: bool,
    host: Option<String>,
}

/// Scans the header block (the bytes after the request line up to and
/// including the blank line). An `Upgrade` naming anything but websocket is
/// refused, and so is a request with more than one `Host`.
fn scan_headers(head: &[u8]) -> Result<HeadInfo, ()> {
    let mut upgrade = false;
    let mut connection = false;
    let mut host: Option<String> = None;
    for line in head.split(|&byte| byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").ok_or(())?;
        if line.is_empty() {
            break;
        }
        let colon = line.iter().position(|&byte| byte == b':').ok_or(())?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            || value.iter().any(|&byte| byte < b' ' && byte != b'\t')
        {
            return Err(());
        }
        let is = |wanted: &str| name.eq_ignore_ascii_case(wanted.as_bytes());
        if is("upgrade") {
            let value = std::str::from_utf8(value).map_err(|_| ())?;
            for token in value.split(',').map(str::trim) {
                if !token.eq_ignore_ascii_case("websocket") {
                    return Err(());
                }
            }
            upgrade = true;
        } else if is("connection") {
            let value = std::str::from_utf8(value).map_err(|_| ())?;
            connection |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if is("host") {
            if host.is_some() {
                return Err(());
            }
            let value = std::str::from_utf8(value).map_err(|_| ())?;
            host = Some(value.trim().to_owned());
        }
    }
    Ok(HeadInfo {
        websocket: upgrade && connection,
        host,
    })
}

/// Lowercases and drops brackets and one trailing dot, so `Example.COM.`,
/// `example.com` and `[::1]` compare the way DNS and URLs treat them.
fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed
        .strip_suffix('.')
        .unwrap_or(unbracketed)
        .to_ascii_lowercase()
}

/// Strips a `:port` from a Host header value, keeping an IPv6 literal whole.
fn host_without_port(value: &str) -> &str {
    if let Some(rest) = value.strip_prefix('[') {
        return match rest.find(']') {
            Some(close) => &value[..close + 2],
            None => value,
        };
    }
    match value.split_once(':') {
        Some((host, _port)) => host,
        None => value,
    }
}

struct ClientHello {
    alpn: Option<DetectedProtocol>,
    sni: Option<String>,
}

fn parse_client_hello(buf: &[u8]) -> Result<ClientHello, ()> {
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
    let mut hello = ClientHello {
        alpn: None,
        sni: None,
    };
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
        match ext_type {
            0x0000 if hello.sni.is_none() => {
                hello.sni = parse_sni(&buf[body_start..body_end])?;
            }
            0x0010 => {
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
                    if hello.alpn.is_none() {
                        hello.alpn = detected;
                    }
                    j = protocol_end;
                }
            }
            _ => {}
        }
        i = body_end;
    }
    Ok(hello)
}

/// First `host_name` entry of a server_name extension body.
fn parse_sni(body: &[u8]) -> Result<Option<String>, ()> {
    if body.len() < 2 {
        return Err(());
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let list = body.get(2..2 + list_len).ok_or(())?;
    let mut j = 0;
    while j < list.len() {
        if j + 3 > list.len() {
            return Err(());
        }
        let name_type = list[j];
        let name_len = u16::from_be_bytes([list[j + 1], list[j + 2]]) as usize;
        let name = list.get(j + 3..j + 3 + name_len).ok_or(())?;
        if name_type == 0 {
            return std::str::from_utf8(name)
                .map(|name| Some(name.to_owned()))
                .map_err(|_| ());
        }
        j += 3 + name_len;
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
    fn quic_shape_on_tcp_is_rejected_on_the_first_byte() {
        let buf = [0xC0u8; 64];
        let r = inspect(&buf, &opts());
        assert!(matches!(
            r,
            InspectionDecision::Block {
                reason: BlockReason::ProtocolNotAllowed
            }
        ));
        assert!(matches!(
            inspect(&buf[..1], &opts()),
            InspectionDecision::Block { .. }
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

    fn blocked(decision: InspectionDecision, expected: BlockReason) {
        assert_eq!(decision, InspectionDecision::Block { reason: expected });
    }

    /// A minimal ClientHello record carrying the given SNI and ALPN entries.
    fn client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut list = vec![0u8];
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name.as_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
            exts.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for protocol in alpn {
                list.push(protocol.len() as u8);
                list.extend_from_slice(protocol.as_bytes());
            }
            exts.extend_from_slice(&0x0010u16.to_be_bytes());
            exts.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn drip_fed_request_scans_in_linear_time() {
        let mut options = opts();
        options.protocol_inspection_max_bytes = 1 << 20;
        let mut request = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Pad: ".to_vec();
        request.resize(request.len() + 200_000, b'a');
        let mut inspector = Inspector::new(Some("example.com"));
        for end in 1..=request.len() {
            assert_eq!(
                inspector.feed(&request[..end], &options),
                InspectionDecision::NeedMore,
                "at {end}"
            );
        }
        // Every byte is examined by each of the two searches at most twice
        // (once, plus the small overlap), never once per fed packet.
        assert!(
            inspector.scanned <= 4 * request.len() as u64,
            "scanned {} bytes for a {} byte request",
            inspector.scanned,
            request.len()
        );
    }

    #[test]
    fn drip_fed_request_completes_and_classifies() {
        let request = b"GET /chat HTTP/1.1\r\nHost: Example.COM.:8080\r\nUpgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\n\r\n";
        let mut inspector = Inspector::new(Some("example.com"));
        let mut last = InspectionDecision::NeedMore;
        for end in 1..=request.len() {
            last = inspector.feed(&request[..end], &opts());
            if end < request.len() {
                assert_eq!(last, InspectionDecision::NeedMore, "at {end}");
            }
        }
        assert_eq!(last, InspectionDecision::Allow(DetectedProtocol::Ws));
    }

    #[test]
    fn crlf_split_across_feeds_is_found() {
        let request = b"GET / HTTP/1.1\r\n\r\n";
        let mut inspector = Inspector::new(None);
        assert_eq!(
            inspector.feed(&request[..15], &opts()),
            InspectionDecision::NeedMore
        );
        assert_eq!(
            inspector.feed(&request[..16], &opts()),
            InspectionDecision::NeedMore
        );
        assert_eq!(
            inspector.feed(request, &opts()),
            InspectionDecision::Allow(DetectedProtocol::Http)
        );
    }

    #[test]
    fn connect_and_trace_are_rejected() {
        for line in [
            &b"CONNECT evil.example:22 HTTP/1.1\r\nHost: evil.example:22\r\n\r\n"[..],
            b"TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ] {
            blocked(inspect(line, &opts()), BlockReason::ProtocolNotAllowed);
        }
        // The first byte is enough to rule out C and T methods.
        blocked(inspect(b"CONN", &opts()), BlockReason::ProtocolNotAllowed);
        blocked(inspect(b"TR", &opts()), BlockReason::ProtocolNotAllowed);
    }

    #[test]
    fn absolute_form_and_authority_form_targets_are_rejected() {
        for target in [
            "http://evil.example/",
            "HTTPS://evil.example/",
            "evil.example:80",
            "",
        ] {
            let request = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            blocked(
                inspect(request.as_bytes(), &opts()),
                BlockReason::ProtocolNotAllowed,
            );
        }
        let asterisk = b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            inspect(asterisk, &opts()),
            InspectionDecision::Allow(DetectedProtocol::Http)
        );
    }

    #[test]
    fn bad_request_line_is_rejected_before_the_headers_arrive() {
        blocked(
            inspect(b"GET http://evil.example/ HTTP/1.1\r\n", &opts()),
            BlockReason::ProtocolNotAllowed,
        );
        blocked(
            inspect(b"GET / HTTP/2\r\n", &opts()),
            BlockReason::ProtocolNotAllowed,
        );
    }

    #[test]
    fn non_websocket_upgrade_is_rejected() {
        for value in ["h2c", "tcp", "websocket, h2c"] {
            let request = format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: {value}\r\nConnection: upgrade\r\n\r\n"
            );
            blocked(
                inspect(request.as_bytes(), &opts()),
                BlockReason::ProtocolNotAllowed,
            );
        }
    }

    #[test]
    fn a_bare_line_feed_in_the_headers_is_rejected() {
        blocked(
            inspect(
                b"GET / HTTP/1.1\r\nHost: example.com\nX: y\r\n\r\n",
                &opts(),
            ),
            BlockReason::ProtocolNotAllowed,
        );
    }

    #[test]
    fn body_bytes_after_the_headers_are_not_parsed() {
        let mut request = b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        request.extend_from_slice(&[0xff, 0xfe, 0x00]);
        assert_eq!(
            inspect(&request, &opts()),
            InspectionDecision::Allow(DetectedProtocol::Http)
        );
    }

    #[test]
    fn host_header_must_match_the_connect_host() {
        let request = |host: &str| format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let check = |host: &str, connect: &str| {
            inspect_for_host(request(host).as_bytes(), &opts(), connect)
        };
        let allow = InspectionDecision::Allow(DetectedProtocol::Http);
        assert_eq!(check("example.com", "example.com"), allow);
        assert_eq!(check("EXAMPLE.com.", "example.COM"), allow);
        assert_eq!(check("example.com:8080", "example.com"), allow);
        blocked(
            check("evil.example", "example.com"),
            BlockReason::HostMismatch,
        );
        blocked(
            check("example.com.evil.example", "example.com"),
            BlockReason::HostMismatch,
        );
        // An IP literal target accepts any Host.
        assert_eq!(check("anything.example", "203.0.113.9"), allow);
        assert_eq!(check("anything.example", "[2001:db8::1]"), allow);
        // A missing Host cannot be matched to a name.
        blocked(
            inspect_for_host(b"GET / HTTP/1.0\r\n\r\n", &opts(), "example.com"),
            BlockReason::HostMismatch,
        );
        // Two Host headers are ambiguous.
        blocked(
            inspect_for_host(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: evil.example\r\n\r\n",
                &opts(),
                "example.com",
            ),
            BlockReason::ProtocolNotAllowed,
        );
    }

    #[test]
    fn tls_sni_must_match_the_connect_host() {
        let mut options = opts();
        options.protocol_inspection_allowed_protocols =
            vec![AllowedProtocol::Https, AllowedProtocol::Http2];
        let hello = client_hello(Some("Example.COM"), &["h2"]);
        assert_eq!(
            inspect_for_host(&hello, &options, "example.com."),
            InspectionDecision::Allow(DetectedProtocol::Http2)
        );
        blocked(
            inspect_for_host(&hello, &options, "other.example"),
            BlockReason::HostMismatch,
        );
        // No SNI at all cannot satisfy a name target, but any hello fits an IP.
        let no_sni = client_hello(None, &["h2"]);
        blocked(
            inspect_for_host(&no_sni, &options, "example.com"),
            BlockReason::HostMismatch,
        );
        assert_eq!(
            inspect_for_host(&no_sni, &options, "203.0.113.9"),
            InspectionDecision::Allow(DetectedProtocol::Http2)
        );
        // The one-shot API without a host keeps its old behavior.
        assert_eq!(
            inspect(&hello, &options),
            InspectionDecision::Allow(DetectedProtocol::Http2)
        );
    }

    #[test]
    fn tls_hello_split_across_feeds_waits_then_checks_sni() {
        let hello = client_hello(Some("example.com"), &["http/1.1"]);
        let mut inspector = Inspector::new(Some("evil.example"));
        for end in 1..hello.len() {
            assert_eq!(
                inspector.feed(&hello[..end], &opts()),
                InspectionDecision::NeedMore,
                "at {end}"
            );
        }
        blocked(inspector.feed(&hello, &opts()), BlockReason::HostMismatch);
    }
}

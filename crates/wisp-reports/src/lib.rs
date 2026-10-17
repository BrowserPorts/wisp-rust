//! Wisp security/report categorization and emission.
//!
//! The string report codes are stable wire identifiers so existing log
//! aggregators continue to work. Call [`emit_report`] from admit/reject/close
//! paths; it serializes a [`Report`] onto the `wisp_reports` tracing target
//! and hands the same report to the process-wide hook set with
//! [`set_report_hook`], so an embedder sees every report without a second
//! emission path.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wisp_iphash::hash_client_ip_keyed;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportCategory {
    RateLimit,
    Security,
    Protocol,
    ProxyControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportErrorType {
    IpHashBanned,
    SecurityRateLimited,
    OriginBlocked,
    ClientBlocked,
    ConnectionRateLimited,
    ConnectionLimit,
    TcpStreamOpenRateLimited,
    TcpByteRateLimited,
    DatagramDropped,
    DatagramRateLimited,
    ControlRateLimited,
    DnsRateLimited,
    StreamThrottled,
    StreamPolicyBlocked,
    LocalhostBlocked,
    SecurityBlocked,
    ProtocolInspectionBlocked,
    HostPolicyBlocked,
    InvalidPacket,
    InvalidInfo,
    FrameTooLarge,
    HandshakeTimeout,
    ProxyHopLimitExceeded,
    ProxyControlSwitch,
}

#[derive(Debug, Clone, Copy)]
pub struct ReportDefinition {
    pub report_code: &'static str,
    pub category: ReportCategory,
    pub explanation: &'static str,
}

impl ReportErrorType {
    /// The snake_case name this type serializes to, for callers that want the
    /// kind without going through JSON.
    pub fn kind(&self) -> &'static str {
        use ReportErrorType::*;
        match self {
            IpHashBanned => "ip_hash_banned",
            SecurityRateLimited => "security_rate_limited",
            OriginBlocked => "origin_blocked",
            ClientBlocked => "client_blocked",
            ConnectionRateLimited => "connection_rate_limited",
            ConnectionLimit => "connection_limit",
            TcpStreamOpenRateLimited => "tcp_stream_open_rate_limited",
            TcpByteRateLimited => "tcp_byte_rate_limited",
            DatagramDropped => "datagram_dropped",
            DatagramRateLimited => "datagram_rate_limited",
            ControlRateLimited => "control_rate_limited",
            DnsRateLimited => "dns_rate_limited",
            StreamThrottled => "stream_throttled",
            StreamPolicyBlocked => "stream_policy_blocked",
            LocalhostBlocked => "localhost_blocked",
            SecurityBlocked => "security_blocked",
            ProtocolInspectionBlocked => "protocol_inspection_blocked",
            HostPolicyBlocked => "host_policy_blocked",
            InvalidPacket => "invalid_packet",
            InvalidInfo => "invalid_info",
            FrameTooLarge => "frame_too_large",
            HandshakeTimeout => "handshake_timeout",
            ProxyHopLimitExceeded => "proxy_hop_limit_exceeded",
            ProxyControlSwitch => "proxy_control_switch",
        }
    }

    pub fn definition(&self) -> ReportDefinition {
        use ReportCategory::*;
        use ReportErrorType::*;
        match self {
            IpHashBanned => ReportDefinition {
                report_code: "WISP_IP_HASH_BANNED",
                category: Security,
                explanation:
                    "The client IP hash is banned, so the Wisp connection was rejected before proxy access was granted.",
            },
            SecurityRateLimited => ReportDefinition {
                report_code: "WISP_SECURITY_RATE_LIMITED",
                category: RateLimit,
                explanation:
                    "The client is temporarily rate limited after localhost or security misuse.",
            },
            OriginBlocked => ReportDefinition {
                report_code: "WISP_ORIGIN_BLOCKED",
                category: Security,
                explanation:
                    "The browser Origin header did not satisfy the configured Wisp origin policy.",
            },
            ClientBlocked => ReportDefinition {
                report_code: "WISP_CLIENT_BLOCKED",
                category: Security,
                explanation:
                    "The client IP did not satisfy the configured Wisp client allow or deny policy.",
            },
            ConnectionRateLimited => ReportDefinition {
                report_code: "WISP_CONNECTION_RATE_LIMITED",
                category: RateLimit,
                explanation: "The client exceeded the configured connection start rate limit.",
            },
            ConnectionLimit => ReportDefinition {
                report_code: "WISP_CONNECTION_LIMIT",
                category: RateLimit,
                explanation:
                    "The client or server exceeded the configured active Wisp connection limit.",
            },
            TcpStreamOpenRateLimited => ReportDefinition {
                report_code: "WISP_TCP_STREAM_OPEN_RATE_LIMITED",
                category: RateLimit,
                explanation: "The client exceeded the configured TCP stream-open rate limit.",
            },
            TcpByteRateLimited => ReportDefinition {
                report_code: "WISP_TCP_BYTE_RATE_LIMITED",
                category: RateLimit,
                explanation:
                    "The client exceeded the configured TCP byte-rate limit and the Wisp session was closed.",
            },
            DatagramDropped => ReportDefinition {
                report_code: "WISP_DATAGRAM_DROPPED",
                category: RateLimit,
                explanation:
                    "A UDP datagram exceeded the configured datagram rate limits and was dropped.",
            },
            DatagramRateLimited => ReportDefinition {
                report_code: "WISP_DATAGRAM_RATE_LIMITED",
                category: RateLimit,
                explanation:
                    "The client repeatedly exceeded datagram limits and the Wisp session was closed.",
            },
            ControlRateLimited => ReportDefinition {
                report_code: "WISP_CONTROL_RATE_LIMITED",
                category: RateLimit,
                explanation:
                    "The client exceeded the configured proxy-control message rate limit.",
            },
            DnsRateLimited => ReportDefinition {
                report_code: "WISP_DNS_RATE_LIMITED",
                category: RateLimit,
                explanation:
                    "The client exceeded the configured DNS resolution or unique-hostname rate limit.",
            },
            StreamThrottled => ReportDefinition {
                report_code: "WISP_STREAM_THROTTLED",
                category: RateLimit,
                explanation:
                    "The requested stream was throttled by a configured Wisp stream limit.",
            },
            StreamPolicyBlocked => ReportDefinition {
                report_code: "WISP_STREAM_POLICY_BLOCKED",
                category: Security,
                explanation:
                    "The requested stream was blocked by Wisp protocol, port, host, domain, or IP policy.",
            },
            LocalhostBlocked => ReportDefinition {
                report_code: "WISP_LOCALHOST_BLOCKED",
                category: Security,
                explanation:
                    "The client attempted to connect to localhost or a hostname resolving to localhost.",
            },
            SecurityBlocked => ReportDefinition {
                report_code: "WISP_SECURITY_BLOCKED",
                category: Security,
                explanation:
                    "Protocol inspection rejected the client traffic as unsafe for this Wisp server.",
            },
            ProtocolInspectionBlocked => ReportDefinition {
                report_code: "WISP_PROTOCOL_INSPECTION_BLOCKED",
                category: Security,
                explanation:
                    "Protocol inspection rejected traffic that did not match the allowed web protocols.",
            },
            HostPolicyBlocked => ReportDefinition {
                report_code: "WISP_HOST_POLICY_BLOCKED",
                category: Security,
                explanation:
                    "The destination host, IP, domain, or port was blocked by configured Wisp policy.",
            },
            InvalidPacket => ReportDefinition {
                report_code: "WISP_INVALID_PACKET",
                category: Protocol,
                explanation:
                    "The client sent malformed Wisp protocol data that could not be parsed.",
            },
            InvalidInfo => ReportDefinition {
                report_code: "WISP_INVALID_INFO",
                category: Protocol,
                explanation: "The client sent invalid Wisp extension or handshake metadata.",
            },
            FrameTooLarge => ReportDefinition {
                report_code: "WISP_FRAME_TOO_LARGE",
                category: Protocol,
                explanation:
                    "The client sent a Wisp frame larger than the configured maximum.",
            },
            HandshakeTimeout => ReportDefinition {
                report_code: "WISP_HANDSHAKE_TIMEOUT",
                category: Protocol,
                explanation:
                    "The client did not complete the Wisp handshake before the configured deadline.",
            },
            ProxyHopLimitExceeded => ReportDefinition {
                report_code: "WISP_PROXY_HOP_LIMIT_EXCEEDED",
                category: RateLimit,
                explanation: "The client exceeded the configured proxy hop limit.",
            },
            ProxyControlSwitch => ReportDefinition {
                report_code: "WISP_PROXY_CONTROL_SWITCH",
                category: ProxyControl,
                explanation:
                    "The client requested a proxy-control state change through the Wisp proxy-control extension.",
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Ws,
    Wt,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Ws => "ws",
            Transport::Wt => "wt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamType {
    Tcp,
    Udp,
    Webtransport,
}

impl StreamType {
    pub fn as_str(&self) -> &'static str {
        match self {
            StreamType::Tcp => "tcp",
            StreamType::Udp => "udp",
            StreamType::Webtransport => "webtransport",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolCode {
    pub transport_close_code: Option<i32>,
    pub wisp_close_code: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionContext {
    pub client_ip: Option<String>,
    pub client_ip_hash: Option<String>,
    pub transport: Option<Transport>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ReportInput {
    pub error_type: Option<ReportErrorType>,
    pub context: Option<ConnectionContext>,
    pub transport: Option<Transport>,
    pub origin: Option<String>,
    pub ip_hash: Option<String>,
    pub transport_close_code: Option<i32>,
    pub wisp_close_code: Option<i32>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub stream_type: Option<StreamType>,
    pub proxy_request_type: Option<String>,
    pub provider: Option<String>,
    pub limit_type: Option<String>,
    pub amount: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub error_type: ReportErrorType,
    pub report_code: &'static str,
    pub category: ReportCategory,
    pub protocol_code: ProtocolCode,
    pub explanation: &'static str,
    pub ip_hash: Option<String>,
    pub transport: Option<Transport>,
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_type: Option<StreamType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_request_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    pub occurred_at: i64,
}

/// Environment variable that turns destination hostnames back on in reports.
pub const HOSTNAMES_ENV: &str = "WISP_REPORT_HOSTNAMES";

/// Whether reports may carry destination hostnames. Off unless
/// `WISP_REPORT_HOSTNAMES` is `1` or `true`: a hostname next to an IP hash
/// links one client to the sites it visited.
fn hostnames_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var(HOSTNAMES_ENV)
            .is_ok_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "True"))
    })
}

fn gate_hostname(hostname: Option<String>, enabled: bool) -> Option<String> {
    hostname.filter(|_| enabled)
}

/// Longest origin a report carries. An Origin header can be megabytes long
/// and ends up in logs and in the report consumers.
pub const MAX_REPORT_ORIGIN_BYTES: usize = 256;

fn truncate_origin(mut origin: String) -> String {
    if origin.len() > MAX_REPORT_ORIGIN_BYTES {
        let mut end = MAX_REPORT_ORIGIN_BYTES;
        while !origin.is_char_boundary(end) {
            end -= 1;
        }
        origin.truncate(end);
    }
    origin
}

pub fn create_report(error_type: ReportErrorType, input: ReportInput) -> Report {
    let def = error_type.definition();
    let ctx = input.context;
    // Most call sites know the client IP but not its hash; derive it so every
    // report can be matched against the ban list. The transports hash with the
    // same process-wide key, so this agrees with the hash they check bans
    // against.
    let ip_hash = input
        .ip_hash
        .or_else(|| ctx.as_ref().and_then(|c| c.client_ip_hash.clone()))
        .or_else(|| {
            ctx.as_ref()
                .and_then(|c| hash_client_ip_keyed(c.client_ip.as_deref()))
        });
    let transport = input
        .transport
        .or_else(|| ctx.as_ref().and_then(|c| c.transport));
    let origin = input
        .origin
        .or_else(|| ctx.as_ref().and_then(|c| c.origin.clone()))
        .map(truncate_origin);
    Report {
        error_type,
        report_code: def.report_code,
        category: def.category,
        protocol_code: ProtocolCode {
            transport_close_code: input.transport_close_code,
            wisp_close_code: input.wisp_close_code,
        },
        explanation: def.explanation,
        ip_hash,
        transport,
        origin,
        hostname: gate_hostname(input.hostname, hostnames_enabled()),
        port: input.port,
        stream_type: input.stream_type,
        proxy_request_type: input.proxy_request_type,
        provider: input.provider,
        limit_type: input.limit_type,
        amount: input.amount,
        occurred_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
    }
}

impl Report {
    /// The optional fields this report carries as `(name, value)` pairs, in a
    /// fixed order. Values are raw: this is the structured view, so a consumer
    /// never has to split [`Report::detail`] and cannot be fooled by a value
    /// that contains `key=value` text.
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = Vec::new();
        if let Some(transport) = self.transport {
            fields.push(("transport", transport.as_str().to_owned()));
        }
        if let Some(origin) = &self.origin {
            fields.push(("origin", origin.clone()));
        }
        if let Some(hostname) = &self.hostname {
            fields.push(("hostname", hostname.clone()));
        }
        if let Some(port) = self.port {
            fields.push(("port", port.to_string()));
        }
        if let Some(stream_type) = self.stream_type {
            fields.push(("stream_type", stream_type.as_str().to_owned()));
        }
        if let Some(provider) = &self.provider {
            fields.push(("provider", provider.clone()));
        }
        if let Some(request) = &self.proxy_request_type {
            fields.push(("proxy_request_type", request.clone()));
        }
        if let Some(limit_type) = &self.limit_type {
            fields.push(("limit_type", limit_type.clone()));
        }
        if let Some(amount) = self.amount {
            fields.push(("amount", amount.to_string()));
        }
        if let Some(code) = self.protocol_code.transport_close_code {
            fields.push(("transport_close_code", code.to_string()));
        }
        if let Some(code) = self.protocol_code.wisp_close_code {
            fields.push(("wisp_close_code", code.to_string()));
        }
        fields
    }

    /// One-line `key=value` summary of the optional fields this report
    /// carries, or `None` when it carries none. Kept for compatibility with
    /// consumers that already parse it; new code should read the fields. The
    /// order is fixed so the output is stable for display and for tests, and
    /// whitespace and control characters inside a value (an Origin header is
    /// attacker text) are percent-escaped so a value cannot add fields.
    pub fn detail(&self) -> Option<String> {
        let parts: Vec<String> = self
            .fields()
            .into_iter()
            .map(|(name, value)| format!("{name}={}", escape_detail_value(&value)))
            .collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}

fn escape_detail_value(value: &str) -> std::borrow::Cow<'_, str> {
    if !value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return std::borrow::Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        if c.is_whitespace() || c.is_control() {
            let mut buf = [0_u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Emission budget per `(ip_hash, error_type)`: a burst of
/// [`REPORT_BURST`] reports per [`REPORT_WINDOW`], then silence until the
/// window turns over. A single noisy client therefore cannot flood the log or
/// the hook (and the panel behind it) while still leaving enough repeats for
/// a consumer to see that the client is persistent.
const REPORT_WINDOW: Duration = Duration::from_secs(10);
const REPORT_BURST: u32 = 20;
const REPORT_TRACKED_KEYS: usize = 8192;

type ThrottleKey = (String, ReportErrorType);

#[derive(Default)]
struct ReportThrottle {
    windows: HashMap<ThrottleKey, (Instant, u32)>,
}

impl ReportThrottle {
    fn admit(&mut self, ip_hash: Option<&str>, error_type: ReportErrorType, now: Instant) -> bool {
        let key = (ip_hash.unwrap_or_default().to_owned(), error_type);
        if let Some((start, count)) = self.windows.get_mut(&key) {
            if now.saturating_duration_since(*start) >= REPORT_WINDOW {
                *start = now;
                *count = 1;
                return true;
            }
            if *count >= REPORT_BURST {
                return false;
            }
            *count += 1;
            return true;
        }
        if self.windows.len() >= REPORT_TRACKED_KEYS {
            self.windows
                .retain(|_, (start, _)| now.saturating_duration_since(*start) < REPORT_WINDOW);
        }
        // Still full of live windows (hash churn): let this one through
        // untracked rather than dropping reports from unseen clients.
        if self.windows.len() < REPORT_TRACKED_KEYS {
            self.windows.insert(key, (now, 1));
        }
        true
    }
}

static THROTTLE: OnceLock<Mutex<ReportThrottle>> = OnceLock::new();
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Reports dropped by the per-hash emission budget since process start.
pub fn suppressed_report_count() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

/// Receives every report [`emit_report`] produces. Runs inline on the
/// connection path, so it must return quickly and never block.
pub type ReportHook = dyn Fn(&Report) + Send + Sync;

/// One hook per process, matching the process-wide tracing target reports
/// already go to.
static REPORT_HOOK: RwLock<Option<Arc<ReportHook>>> = RwLock::new(None);

/// Install the report hook, replacing any earlier one; `None` removes it.
pub fn set_report_hook(hook: Option<Arc<ReportHook>>) {
    *REPORT_HOOK.write().unwrap_or_else(PoisonError::into_inner) = hook;
}

/// Build a report and emit it on the `wisp_reports` tracing target as JSON,
/// then pass it to the hook from [`set_report_hook`]. Reports beyond the
/// per-`(ip_hash, error_type)` budget are counted and dropped, see
/// [`suppressed_report_count`].
/// Call this from admit/reject/close paths so aggregators can scrape stable
/// `report_code` values without parsing free-form log lines.
pub fn emit_report(error_type: ReportErrorType, input: ReportInput) {
    let report = create_report(error_type, input);
    let admitted = THROTTLE
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .admit(report.ip_hash.as_deref(), error_type, Instant::now());
    if !admitted {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    match serde_json::to_string(&report) {
        Ok(json) => {
            tracing::info!(
                target: "wisp_reports",
                report_code = report.report_code,
                category = ?report.category,
                report = %json,
                "wisp report"
            );
        }
        Err(error) => {
            tracing::warn!(
                target: "wisp_reports",
                report_code = report.report_code,
                error = %error,
                "failed to serialize wisp report"
            );
        }
    }
    // Clone the Arc out so the hook runs without the lock held; a hook that
    // calls set_report_hook cannot deadlock against itself.
    let hook = REPORT_HOOK
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(hook) = hook {
        hook(&report);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_codes_are_stable() {
        assert_eq!(
            ReportErrorType::OriginBlocked.definition().report_code,
            "WISP_ORIGIN_BLOCKED"
        );
        assert_eq!(
            ReportErrorType::HandshakeTimeout.definition().report_code,
            "WISP_HANDSHAKE_TIMEOUT"
        );
    }

    #[test]
    fn categories_are_stable() {
        assert!(matches!(
            ReportErrorType::DatagramDropped.definition().category,
            ReportCategory::RateLimit
        ));
        assert!(matches!(
            ReportErrorType::InvalidPacket.definition().category,
            ReportCategory::Protocol
        ));
    }

    #[test]
    fn report_origin_is_truncated_on_a_char_boundary() {
        let long = format!("https://{}", "\u{e9}".repeat(10_000));
        let r = create_report(
            ReportErrorType::OriginBlocked,
            ReportInput {
                origin: Some(long.clone()),
                ..Default::default()
            },
        );
        let origin = r.origin.expect("origin kept");
        assert!(origin.len() <= MAX_REPORT_ORIGIN_BYTES);
        assert!(long.starts_with(&origin));
        let short = create_report(
            ReportErrorType::OriginBlocked,
            ReportInput {
                origin: Some("https://example.com".to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(short.origin.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn create_report_inherits_context() {
        let r = create_report(
            ReportErrorType::OriginBlocked,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip_hash: Some("hashy".to_owned()),
                    transport: Some(Transport::Wt),
                    origin: Some("https://example.com".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert_eq!(r.ip_hash.as_deref(), Some("hashy"));
        assert_eq!(r.origin.as_deref(), Some("https://example.com"));
        assert!(matches!(r.transport, Some(Transport::Wt)));
    }

    #[test]
    fn serializes_with_snake_case_category() {
        let r = create_report(ReportErrorType::HostPolicyBlocked, ReportInput::default());
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"category\":\"security\""), "{}", s);
        assert!(
            s.contains("\"error_type\":\"host_policy_blocked\""),
            "{}",
            s
        );
    }

    #[test]
    fn emit_report_does_not_panic() {
        emit_report(
            ReportErrorType::OriginBlocked,
            ReportInput {
                origin: Some("https://example.test".to_owned()),
                transport: Some(Transport::Ws),
                ..Default::default()
            },
        );
    }

    #[test]
    fn kind_matches_the_serialized_name() {
        use ReportErrorType::*;
        for error_type in [
            IpHashBanned,
            SecurityRateLimited,
            OriginBlocked,
            ClientBlocked,
            ConnectionRateLimited,
            ConnectionLimit,
            TcpStreamOpenRateLimited,
            TcpByteRateLimited,
            DatagramDropped,
            DatagramRateLimited,
            ControlRateLimited,
            DnsRateLimited,
            StreamThrottled,
            StreamPolicyBlocked,
            LocalhostBlocked,
            SecurityBlocked,
            ProtocolInspectionBlocked,
            HostPolicyBlocked,
            InvalidPacket,
            InvalidInfo,
            FrameTooLarge,
            HandshakeTimeout,
            ProxyHopLimitExceeded,
            ProxyControlSwitch,
        ] {
            let serialized = serde_json::to_value(error_type).unwrap();
            assert_eq!(serialized.as_str(), Some(error_type.kind()));
        }
    }

    #[test]
    fn create_report_hashes_a_bare_client_ip() {
        let r = create_report(
            ReportErrorType::ClientBlocked,
            ReportInput {
                context: Some(ConnectionContext {
                    client_ip: Some("203.0.113.5".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert_eq!(
            r.ip_hash,
            hash_client_ip_keyed(Some("203.0.113.5")),
            "derived hash must match the one the transports ban on"
        );
    }

    #[test]
    fn hostname_is_dropped_unless_enabled() {
        assert_eq!(gate_hostname(Some("example.com".to_owned()), false), None);
        assert_eq!(
            gate_hostname(Some("example.com".to_owned()), true).as_deref(),
            Some("example.com")
        );
        assert_eq!(gate_hostname(None, true), None);
    }

    #[test]
    fn detail_lists_present_fields_in_order() {
        let r = create_report(
            ReportErrorType::ConnectionRateLimited,
            ReportInput {
                transport: Some(Transport::Ws),
                origin: Some("https://example.test".to_owned()),
                transport_close_code: Some(429),
                limit_type: Some("connection_start".to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(
            r.detail().as_deref(),
            Some(
                "transport=ws origin=https://example.test limit_type=connection_start \
                 transport_close_code=429"
            )
        );
        let bare = create_report(ReportErrorType::InvalidPacket, ReportInput::default());
        assert_eq!(bare.detail(), None);
    }

    #[test]
    fn hook_receives_emitted_reports() {
        use std::sync::mpsc;
        // The hook is process-wide and other tests emit concurrently, so the
        // receiver keeps only the report carrying this test's origin.
        let marker = "https://hook-test.example";
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        set_report_hook(Some(Arc::new(move |report: &Report| {
            if report.origin.as_deref() == Some(marker) {
                let _ = tx.lock().unwrap().send((
                    report.report_code,
                    report.error_type.kind(),
                    report.ip_hash.clone(),
                ));
            }
        })));
        emit_report(
            ReportErrorType::IpHashBanned,
            ReportInput {
                origin: Some(marker.to_owned()),
                ip_hash: Some("hashy".to_owned()),
                ..Default::default()
            },
        );
        let (code, kind, ip_hash) = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(code, "WISP_IP_HASH_BANNED");
        assert_eq!(kind, "ip_hash_banned");
        assert_eq!(ip_hash.as_deref(), Some("hashy"));

        set_report_hook(None);
        emit_report(
            ReportErrorType::IpHashBanned,
            ReportInput {
                origin: Some(marker.to_owned()),
                ..Default::default()
            },
        );
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "a removed hook must not be called"
        );
    }

    #[test]
    fn detail_escapes_values_that_could_forge_fields() {
        let r = create_report(
            ReportErrorType::OriginBlocked,
            ReportInput {
                origin: Some("https://a.test hostname=evil.test\nport=22".to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(
            r.detail().as_deref(),
            Some("origin=https://a.test%20hostname=evil.test%0Aport=22")
        );
        // The structured view keeps the raw value.
        assert_eq!(
            r.fields(),
            vec![(
                "origin",
                "https://a.test hostname=evil.test\nport=22".to_owned()
            )]
        );
    }

    #[test]
    fn fields_match_detail_for_plain_values() {
        let r = create_report(
            ReportErrorType::TcpByteRateLimited,
            ReportInput {
                transport: Some(Transport::Wt),
                port: Some(443),
                stream_type: Some(StreamType::Tcp),
                amount: Some(7),
                wisp_close_code: Some(0x48),
                ..Default::default()
            },
        );
        let joined = r
            .fields()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(r.detail().as_deref(), Some(joined.as_str()));
        assert!(joined.starts_with("transport=wt port=443"));
    }

    #[test]
    fn throttle_caps_a_hash_per_window_and_refreshes() {
        let mut throttle = ReportThrottle::default();
        let start = Instant::now();
        for _ in 0..REPORT_BURST {
            assert!(throttle.admit(Some("h1"), ReportErrorType::OriginBlocked, start));
        }
        assert!(!throttle.admit(Some("h1"), ReportErrorType::OriginBlocked, start));
        // Other hashes and other kinds are separate budgets.
        assert!(throttle.admit(Some("h2"), ReportErrorType::OriginBlocked, start));
        assert!(throttle.admit(Some("h1"), ReportErrorType::ClientBlocked, start));
        assert!(throttle.admit(
            Some("h1"),
            ReportErrorType::OriginBlocked,
            start + REPORT_WINDOW
        ));
    }

    #[test]
    fn throttle_stays_bounded_and_never_blocks_new_hashes() {
        let mut throttle = ReportThrottle::default();
        let now = Instant::now();
        for index in 0..REPORT_TRACKED_KEYS + 100 {
            assert!(throttle.admit(
                Some(&format!("hash-{index}")),
                ReportErrorType::ClientBlocked,
                now
            ));
        }
        assert!(throttle.windows.len() <= REPORT_TRACKED_KEYS);
        assert!(throttle.admit(Some("late"), ReportErrorType::ClientBlocked, now));
        // Once the windows expire the map drains on the next insert.
        assert!(throttle.admit(
            Some("later"),
            ReportErrorType::ClientBlocked,
            now + REPORT_WINDOW
        ));
        assert!(throttle.windows.len() < 10);
    }
}

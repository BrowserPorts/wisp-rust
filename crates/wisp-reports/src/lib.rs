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
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use wisp_iphash::hash_client_ip;

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

pub fn create_report(error_type: ReportErrorType, input: ReportInput) -> Report {
    let def = error_type.definition();
    let ctx = input.context;
    // Most call sites know the client IP but not its hash; derive it so every
    // report can be matched against the ban list. The transports hash without
    // a secret, so this agrees with the hash they check bans against.
    let ip_hash = input
        .ip_hash
        .or_else(|| ctx.as_ref().and_then(|c| c.client_ip_hash.clone()))
        .or_else(|| {
            ctx.as_ref()
                .and_then(|c| hash_client_ip(c.client_ip.as_deref(), None))
        });
    let transport = input
        .transport
        .or_else(|| ctx.as_ref().and_then(|c| c.transport));
    let origin = input
        .origin
        .or_else(|| ctx.as_ref().and_then(|c| c.origin.clone()));
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
        hostname: input.hostname,
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
    /// One-line `key=value` summary of the optional fields this report
    /// carries, or `None` when it carries none. The order is fixed so the
    /// output is stable for display and for tests.
    pub fn detail(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(transport) = self.transport {
            parts.push(format!("transport={}", transport.as_str()));
        }
        if let Some(origin) = &self.origin {
            parts.push(format!("origin={origin}"));
        }
        if let Some(hostname) = &self.hostname {
            parts.push(format!("hostname={hostname}"));
        }
        if let Some(port) = self.port {
            parts.push(format!("port={port}"));
        }
        if let Some(stream_type) = self.stream_type {
            parts.push(format!("stream_type={}", stream_type.as_str()));
        }
        if let Some(provider) = &self.provider {
            parts.push(format!("provider={provider}"));
        }
        if let Some(request) = &self.proxy_request_type {
            parts.push(format!("proxy_request_type={request}"));
        }
        if let Some(limit_type) = &self.limit_type {
            parts.push(format!("limit_type={limit_type}"));
        }
        if let Some(amount) = self.amount {
            parts.push(format!("amount={amount}"));
        }
        if let Some(code) = self.protocol_code.transport_close_code {
            parts.push(format!("transport_close_code={code}"));
        }
        if let Some(code) = self.protocol_code.wisp_close_code {
            parts.push(format!("wisp_close_code={code}"));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
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
/// then pass it to the hook from [`set_report_hook`].
/// Call this from admit/reject/close paths so aggregators can scrape stable
/// `report_code` values without parsing free-form log lines.
pub fn emit_report(error_type: ReportErrorType, input: ReportInput) {
    let report = create_report(error_type, input);
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
            hash_client_ip(Some("203.0.113.5"), None),
            "derived hash must match the one the transports ban on"
        );
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
}

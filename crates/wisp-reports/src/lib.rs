//! Wisp security/report categorization. Mirrors `wisp-wt/src/reports.ts` —
//! same string codes so existing log aggregators continue to work.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamType {
    Tcp,
    Udp,
    Webtransport,
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
    let ip_hash = input
        .ip_hash
        .or_else(|| ctx.as_ref().and_then(|c| c.client_ip_hash.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_codes_match_ts() {
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
    fn categories_match_ts() {
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
}

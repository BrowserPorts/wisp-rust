//! Pre-upgrade policy stack: origin, IP, DoS gates that must run before the
//! server responds to the H3 extended CONNECT.
//!
//! Origin enforcement runs unconditionally here: because `h3` surfaces the
//! request headers at upgrade time, every extended CONNECT is checked against
//! the origin policy before the session is accepted.

use http::{header, HeaderMap, HeaderValue, StatusCode};
use std::sync::Arc;
use wisp_config::{is_client_ip_allowed, WispServerOptions};
use wisp_dos::{is_connection_start_allowed, DosGuard};
use wisp_iphash::{hash_client_ip, IpHashBans};
use wisp_origin::{is_origin_allowed, origin_from_headers, origin_headers_valid, policy_headers};
use wisp_reports::{emit_report, ConnectionContext, ReportErrorType, ReportInput, Transport};

fn build_policy_headers(origin: Option<&str>, options: &WispServerOptions) -> HeaderMap {
    let (vary, acao) = policy_headers(origin, options);
    let mut h = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(vary) {
        h.insert(header::VARY, v);
    }
    if let Some(value) = acao {
        if let Ok(v) = HeaderValue::from_str(&value) {
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }
    h
}

#[derive(Debug, Clone)]
pub struct PreUpgradeRejection {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct PreUpgradePolicy {
    pub options: Arc<WispServerOptions>,
    pub dos: Arc<DosGuard>,
    pub iphash_secret: Option<Vec<u8>>,
    /// Banned client IP hashes, checked right after the hash is computed and
    /// before any rate-limit budget is spent on the connection.
    pub ip_bans: Arc<IpHashBans>,
}

impl PreUpgradePolicy {
    pub fn new(options: Arc<WispServerOptions>, dos: Arc<DosGuard>) -> Self {
        Self {
            options,
            dos,
            iphash_secret: None,
            ip_bans: Arc::new(IpHashBans::new()),
        }
    }

    pub fn with_ip_bans(mut self, ip_bans: Arc<IpHashBans>) -> Self {
        self.ip_bans = ip_bans;
        self
    }

    pub fn with_iphash_secret(mut self, secret: Vec<u8>) -> Self {
        self.iphash_secret = Some(secret);
        self
    }

    /// Run origin + DoS gates. `client_ip` is the canonical real IP after
    /// `parse_real_ip_from` has been applied. Returns `Ok(client_hash)` on
    /// pass; `Err(rejection)` on deny.
    pub fn check(
        &self,
        headers: &HeaderMap,
        client_ip: &str,
    ) -> Result<Option<String>, PreUpgradeRejection> {
        let origin = origin_from_headers(headers);
        if !origin_headers_valid(headers) {
            emit_report(
                ReportErrorType::OriginBlocked,
                ReportInput {
                    context: Some(ConnectionContext {
                        client_ip: Some(client_ip.to_owned()),
                        transport: Some(Transport::Wt),
                        ..Default::default()
                    }),
                    transport_close_code: Some(403),
                    ..Default::default()
                },
            );
            return Err(PreUpgradeRejection {
                status: StatusCode::FORBIDDEN,
                headers: build_policy_headers(None, &self.options),
                reason: "invalid origin headers",
            });
        }
        if !is_origin_allowed(origin, &self.options) {
            emit_report(
                ReportErrorType::OriginBlocked,
                ReportInput {
                    context: Some(ConnectionContext {
                        client_ip: Some(client_ip.to_owned()),
                        transport: Some(Transport::Wt),
                        origin: origin.map(|s| s.to_owned()),
                        ..Default::default()
                    }),
                    origin: origin.map(|s| s.to_owned()),
                    transport_close_code: Some(403),
                    ..Default::default()
                },
            );
            return Err(PreUpgradeRejection {
                status: StatusCode::FORBIDDEN,
                headers: build_policy_headers(origin, &self.options),
                reason: "origin policy",
            });
        }
        if !is_client_ip_allowed(client_ip, &self.options) {
            emit_report(
                ReportErrorType::ClientBlocked,
                ReportInput {
                    context: Some(ConnectionContext {
                        client_ip: Some(client_ip.to_owned()),
                        transport: Some(Transport::Wt),
                        origin: origin.map(|s| s.to_owned()),
                        ..Default::default()
                    }),
                    transport_close_code: Some(403),
                    ..Default::default()
                },
            );
            return Err(PreUpgradeRejection {
                status: StatusCode::FORBIDDEN,
                headers: build_policy_headers(origin, &self.options),
                reason: "client IP policy",
            });
        }
        let client_hash = hash_client_ip(Some(client_ip), self.iphash_secret.as_deref());
        if self.ip_bans.is_banned(client_hash.as_deref()) {
            emit_report(
                ReportErrorType::IpHashBanned,
                ReportInput {
                    context: Some(ConnectionContext {
                        client_ip: Some(client_ip.to_owned()),
                        client_ip_hash: client_hash,
                        transport: Some(Transport::Wt),
                        origin: origin.map(|s| s.to_owned()),
                    }),
                    transport_close_code: Some(403),
                    ..Default::default()
                },
            );
            return Err(PreUpgradeRejection {
                status: StatusCode::FORBIDDEN,
                headers: build_policy_headers(origin, &self.options),
                reason: "banned IP hash",
            });
        }
        if !is_connection_start_allowed(client_ip, &self.options, &self.dos) {
            emit_report(
                ReportErrorType::ConnectionRateLimited,
                ReportInput {
                    context: Some(ConnectionContext {
                        client_ip: Some(client_ip.to_owned()),
                        client_ip_hash: client_hash.clone(),
                        transport: Some(Transport::Wt),
                        origin: origin.map(|s| s.to_owned()),
                    }),
                    transport_close_code: Some(429),
                    limit_type: Some("connection_start".to_owned()),
                    ..Default::default()
                },
            );
            return Err(PreUpgradeRejection {
                status: StatusCode::TOO_MANY_REQUESTS,
                headers: build_policy_headers(origin, &self.options),
                reason: "connection-start rate limit",
            });
        }
        Ok(client_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use wisp_config::WispServerOptions;

    fn opts() -> Arc<WispServerOptions> {
        Arc::new(WispServerOptions::default())
    }

    #[test]
    fn allows_unset_origin_when_blank_origins_permitted() {
        let o = WispServerOptions {
            block_blank_origins: false,
            ..WispServerOptions::default()
        };
        let p = PreUpgradePolicy::new(Arc::new(o), Arc::new(DosGuard::new()));
        assert!(p.check(&HeaderMap::new(), "1.2.3.4").is_ok());
    }

    #[test]
    fn rejects_blank_origin_by_default() {
        let p = PreUpgradePolicy::new(opts(), Arc::new(DosGuard::new()));
        let rej = p.check(&HeaderMap::new(), "1.2.3.4").unwrap_err();
        assert_eq!(rej.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn rejects_blacklisted_origin() {
        let o = WispServerOptions {
            origin_blacklist: Some(vec!["https://evil.example".to_owned()]),
            ..WispServerOptions::default()
        };
        let p = PreUpgradePolicy::new(Arc::new(o), Arc::new(DosGuard::new()));
        let mut h = HeaderMap::new();
        h.insert("origin", HeaderValue::from_static("https://evil.example"));
        assert_eq!(
            p.check(&h, "1.2.3.4").unwrap_err().status,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn rejects_banned_ip_hash_before_rate_limits() {
        let o = WispServerOptions {
            block_blank_origins: false,
            ..WispServerOptions::default()
        };
        let bans = Arc::new(IpHashBans::new());
        let p = PreUpgradePolicy::new(Arc::new(o), Arc::new(DosGuard::new()))
            .with_ip_bans(bans.clone());
        assert!(p.check(&HeaderMap::new(), "1.2.3.4").is_ok());

        bans.replace([hash_client_ip(Some("1.2.3.4"), None).unwrap()]);
        let rej = p.check(&HeaderMap::new(), "1.2.3.4").unwrap_err();
        assert_eq!(rej.status, StatusCode::FORBIDDEN);
        assert_eq!(rej.reason, "banned IP hash");
        assert!(p.check(&HeaderMap::new(), "1.2.3.5").is_ok());

        bans.replace(Vec::<String>::new());
        assert!(p.check(&HeaderMap::new(), "1.2.3.4").is_ok());
    }
}

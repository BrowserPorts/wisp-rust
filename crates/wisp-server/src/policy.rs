//! Pre-upgrade policy stack: origin, IP, DoS gates that must run before the
//! server responds to the H3 extended CONNECT.
//!
//! Mirrors the equivalent block in `wisp-wt/src/wt/server.ts` that runs
//! inside the upgrade handler. The Bun WT binding bypassed origin
//! enforcement because it didn't surface request headers; with `h3` we
//! enforce unconditionally — this is one of the two Bun-dropped features
//! the Rust port restores.

use http::{header, HeaderMap, HeaderValue, StatusCode};
use std::sync::Arc;
use wisp_config::WispServerOptions;
use wisp_dos::{is_connection_start_allowed, DosGuard};
use wisp_iphash::hash_client_ip;
use wisp_origin::{is_origin_allowed, origin_from_headers, policy_headers};

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
}

impl PreUpgradePolicy {
    pub fn new(options: Arc<WispServerOptions>, dos: Arc<DosGuard>) -> Self {
        Self {
            options,
            dos,
            iphash_secret: None,
        }
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
        if !is_origin_allowed(origin, &self.options) {
            return Err(PreUpgradeRejection {
                status: StatusCode::FORBIDDEN,
                headers: build_policy_headers(origin, &self.options),
                reason: "origin policy",
            });
        }
        let client_hash = hash_client_ip(Some(client_ip), self.iphash_secret.as_deref());
        if !is_connection_start_allowed(client_ip, &self.options, &self.dos) {
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
        // Default config enforces block_blank_origins = true.
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
}

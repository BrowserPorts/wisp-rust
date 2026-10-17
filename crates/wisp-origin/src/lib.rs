//! Origin header parsing and allow/deny policy.
//!
//! msquic and the `h3` crate give us `http::Request<()>` with full headers, so
//! this policy is always enforced.

#![forbid(unsafe_code)]

use http::HeaderMap;
use url::Url;
use wisp_config::{parse_origin_pattern, serialize_origin, OriginPattern, WispServerOptions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedOrigin {
    Missing,
    Null,
    Origin(String),
    Invalid(String),
}

fn pattern_matches(p: &OriginPattern, origin: &ParsedOrigin) -> bool {
    match (p, origin) {
        (OriginPattern::Null, ParsedOrigin::Null) => true,
        (_, ParsedOrigin::Null) => false,
        (_, ParsedOrigin::Missing | ParsedOrigin::Invalid(_)) => false,
        (OriginPattern::Any, ParsedOrigin::Origin(_)) => true,
        (OriginPattern::Exact(v), ParsedOrigin::Origin(o)) => v == o,
        (
            OriginPattern::Wildcard {
                scheme,
                host_suffix,
                port,
            },
            ParsedOrigin::Origin(o),
        ) => {
            let Ok(url) = Url::parse(o) else {
                return false;
            };
            if url.scheme() != scheme {
                return false;
            }
            if url.port() != *port {
                return false;
            }
            let Some(host) = url.host_str() else {
                return false;
            };
            // Subdomains only; the apex needs its own exact entry.
            host.strip_suffix(host_suffix.as_str())
                .is_some_and(|head| head.len() > 1 && head.ends_with('.'))
        }
        (OriginPattern::Null, _) => false,
    }
}

/// `true` when some entry matches. An entry that does not parse never matches,
/// which is the safe side for a whitelist. Config validation rejects such
/// entries at load, so this only covers options that skipped validation.
fn list_matches(list: &Option<Vec<String>>, origin: &ParsedOrigin) -> bool {
    let Some(list) = list else {
        return false;
    };
    list.iter()
        .any(|e| parse_origin_pattern(e).is_ok_and(|p| pattern_matches(&p, origin)))
}

/// `true` when the blacklist holds an entry that does not parse. A blacklist
/// that cannot be read cannot be trusted to exclude anything, so the caller
/// denies every origin instead of failing open.
fn list_is_malformed(list: &Option<Vec<String>>) -> bool {
    list.as_ref()
        .is_some_and(|list| list.iter().any(|e| parse_origin_pattern(e).is_err()))
}

const ORIGIN_START: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn origin_start_ok(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty() && ORIGIN_START.contains(&bytes[0]) && s.contains("://")
}

pub fn parse_origin_header(origin: Option<&str>) -> ParsedOrigin {
    let Some(raw) = origin else {
        return ParsedOrigin::Missing;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ParsedOrigin::Missing;
    }
    if trimmed == "null" {
        return ParsedOrigin::Null;
    }
    if !origin_start_ok(trimmed) {
        return ParsedOrigin::Invalid(trimmed.to_owned());
    }
    match serialize_origin(trimmed) {
        Some(s) if s == trimmed => ParsedOrigin::Origin(s),
        _ => ParsedOrigin::Invalid(trimmed.to_owned()),
    }
}

pub fn origin_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
}

pub fn origin_headers_valid(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(http::header::ORIGIN).iter();
    let Some(first) = values.next() else {
        return true;
    };
    values.next().is_none() && first.to_str().is_ok()
}

pub fn is_origin_allowed(origin: Option<&str>, options: &WispServerOptions) -> bool {
    let parsed = parse_origin_header(origin);
    if matches!(parsed, ParsedOrigin::Invalid(_)) {
        return false;
    }
    // A whitelist that is present admits only what it lists, so an empty one
    // denies every origin. Leave it unset for no whitelist.
    if options.origin_whitelist.is_some() {
        return list_matches(&options.origin_whitelist, &parsed);
    }
    if list_is_malformed(&options.origin_blacklist)
        || list_matches(&options.origin_blacklist, &parsed)
    {
        return false;
    }
    if matches!(parsed, ParsedOrigin::Missing | ParsedOrigin::Null) {
        return !options.block_blank_origins;
    }
    true
}

/// Compute the policy headers to attach to either a successful upgrade or a
/// 403 rejection. Returns `(Vary, Access-Control-Allow-Origin)`.
pub fn policy_headers(
    origin: Option<&str>,
    options: &WispServerOptions,
) -> (&'static str, Option<String>) {
    if !is_origin_allowed(origin, options) {
        return ("Origin", None);
    }
    let parsed = parse_origin_header(origin);
    let acao = match parsed {
        ParsedOrigin::Origin(v) => Some(v),
        ParsedOrigin::Null => Some("null".to_owned()),
        _ => None,
    };
    ("Origin", acao)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> WispServerOptions {
        WispServerOptions::default()
    }

    #[test]
    fn parses_missing_and_null() {
        assert_eq!(parse_origin_header(None), ParsedOrigin::Missing);
        assert_eq!(parse_origin_header(Some("")), ParsedOrigin::Missing);
        assert_eq!(parse_origin_header(Some("null")), ParsedOrigin::Null);
    }

    #[test]
    fn parses_valid_origin() {
        assert_eq!(
            parse_origin_header(Some("https://example.com")),
            ParsedOrigin::Origin("https://example.com".to_owned())
        );
    }

    #[test]
    fn duplicate_origin_headers_are_invalid() {
        let mut headers = HeaderMap::new();
        headers.append(
            http::header::ORIGIN,
            "https://one.example".parse().expect("header"),
        );
        headers.append(
            http::header::ORIGIN,
            "https://two.example".parse().expect("header"),
        );
        assert!(!origin_headers_valid(&headers));
    }

    #[test]
    fn invalid_origin_with_path_rejected() {
        let s = "https://example.com/foo";
        match parse_origin_header(Some(s)) {
            ParsedOrigin::Invalid(_) => {}
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn default_block_blank_rejects_missing_origin() {
        let o = opts();
        assert!(o.block_blank_origins);
        assert!(!is_origin_allowed(None, &o));
        assert!(!is_origin_allowed(Some("null"), &o));
    }

    #[test]
    fn whitelist_exact_allows() {
        let mut o = opts();
        o.origin_whitelist = Some(vec!["https://good.example".to_owned()]);
        assert!(is_origin_allowed(Some("https://good.example"), &o));
        assert!(!is_origin_allowed(Some("https://evil.example"), &o));
    }

    #[test]
    fn blacklist_blocks_listed() {
        let mut o = opts();
        o.origin_blacklist = Some(vec!["https://evil.example".to_owned()]);
        assert!(!is_origin_allowed(Some("https://evil.example"), &o));
        assert!(is_origin_allowed(Some("https://good.example"), &o));
    }

    #[test]
    fn wildcard_suffix() {
        let mut o = opts();
        o.origin_whitelist = Some(vec!["https://*.example.com".to_owned()]);
        assert!(is_origin_allowed(Some("https://api.example.com"), &o));
        assert!(is_origin_allowed(Some("https://a.b.example.com"), &o));
        assert!(!is_origin_allowed(Some("https://example.com"), &o));
        assert!(!is_origin_allowed(Some("https://evilexample.com"), &o));
        assert!(!is_origin_allowed(Some("https://example.org"), &o));
        o.origin_whitelist = Some(vec![
            "https://*.example.com".to_owned(),
            "https://example.com".to_owned(),
        ]);
        assert!(is_origin_allowed(Some("https://example.com"), &o));
    }

    #[test]
    fn unparseable_blacklist_entry_denies_instead_of_failing_open() {
        let mut o = opts();
        o.block_blank_origins = false;
        o.origin_blacklist = Some(vec!["https://*.example.com:abc".to_owned()]);
        assert!(!is_origin_allowed(Some("https://good.example"), &o));
        assert!(!is_origin_allowed(None, &o));
        assert!(o.validate().is_err());
    }

    #[test]
    fn empty_whitelist_denies_every_origin() {
        let mut o = opts();
        o.block_blank_origins = false;
        o.origin_whitelist = Some(vec![]);
        assert!(!is_origin_allowed(Some("https://good.example"), &o));
        assert!(!is_origin_allowed(None, &o));
    }

    #[test]
    fn invalid_wildcard_port_does_not_widen_the_match() {
        let mut o = opts();
        o.origin_whitelist = Some(vec!["https://*.example.com:abc".to_owned()]);
        assert!(!is_origin_allowed(Some("https://api.example.com"), &o));
        assert!(!is_origin_allowed(Some("https://api.example.com:8443"), &o));
        assert!(o.validate().is_err());
    }

    #[test]
    fn wildcard_with_default_port_in_pattern_matches_canonical_origin() {
        let mut o = opts();
        o.origin_whitelist = Some(vec!["https://*.example.com:443".to_owned()]);
        assert!(is_origin_allowed(Some("https://api.example.com"), &o));
        let mut o2 = opts();
        o2.origin_whitelist = Some(vec!["http://*.example.com:80".to_owned()]);
        assert!(is_origin_allowed(Some("http://api.example.com"), &o2));
        let mut o3 = opts();
        o3.origin_whitelist = Some(vec!["https://*.example.com:8443".to_owned()]);
        assert!(!is_origin_allowed(Some("https://api.example.com"), &o3));
        assert!(is_origin_allowed(Some("https://api.example.com:8443"), &o3));
    }
}

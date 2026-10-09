//! Origin header parsing and allow/deny policy.
//!
//! msquic and the `h3` crate give us `http::Request<()>` with full headers, so
//! this policy is always enforced.

#![forbid(unsafe_code)]

use http::HeaderMap;
use url::Url;
use wisp_config::WispServerOptions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedOrigin {
    Missing,
    Null,
    Origin(String),
    Invalid(String),
}

#[derive(Debug, Clone)]
enum Pattern {
    Any,
    Null,
    Exact(String),
    Wildcard {
        scheme: String,
        host_suffix: String,
        port: Option<u16>,
    },
}

fn serialize_origin(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    let origin = url.origin();
    if !origin.is_tuple() {
        return None;
    }
    Some(origin.ascii_serialization())
}

fn normalize_configured_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    serialize_origin(trimmed)
}

fn parse_pattern(entry: &str) -> Option<Pattern> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "*" {
        return Some(Pattern::Any);
    }
    if trimmed == "null" {
        return Some(Pattern::Null);
    }
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        if let Some(after_star) = rest.strip_prefix("*.") {
            let (host, port) = match after_star.rsplit_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().ok()),
                None => (after_star, None),
            };
            if host.is_empty() {
                return None;
            }
            let scheme_lc = scheme.to_ascii_lowercase();
            let port = match (scheme_lc.as_str(), port) {
                ("https", Some(443))
                | ("http", Some(80))
                | ("ws", Some(80))
                | ("wss", Some(443)) => None,
                _ => port,
            };
            return Some(Pattern::Wildcard {
                scheme: scheme_lc,
                host_suffix: host.to_ascii_lowercase(),
                port,
            });
        }
    }
    normalize_configured_origin(trimmed).map(Pattern::Exact)
}

fn pattern_matches(p: &Pattern, origin: &ParsedOrigin) -> bool {
    match (p, origin) {
        (Pattern::Null, ParsedOrigin::Null) => true,
        (_, ParsedOrigin::Null) => false,
        (_, ParsedOrigin::Missing | ParsedOrigin::Invalid(_)) => false,
        (Pattern::Any, ParsedOrigin::Origin(_)) => true,
        (Pattern::Exact(v), ParsedOrigin::Origin(o)) => v == o,
        (
            Pattern::Wildcard {
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
            host == host_suffix || host.ends_with(&format!(".{host_suffix}"))
        }
        (Pattern::Null, _) => false,
    }
}

fn list_matches(list: &Option<Vec<String>>, origin: &ParsedOrigin) -> bool {
    let Some(list) = list else {
        return false;
    };
    list.iter()
        .any(|e| parse_pattern(e).is_some_and(|p| pattern_matches(&p, origin)))
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
    if options.origin_whitelist.is_some() {
        return list_matches(&options.origin_whitelist, &parsed);
    }
    if list_matches(&options.origin_blacklist, &parsed) {
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
        assert!(is_origin_allowed(Some("https://example.com"), &o));
        assert!(!is_origin_allowed(Some("https://example.org"), &o));
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

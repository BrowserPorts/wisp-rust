//! Syntax of `origin_blacklist` and `origin_whitelist` entries. The parser
//! lives here so config validation and the origin check read entries the same
//! way, and a malformed entry is an error at load rather than a silent no-op.

use url::Url;

use crate::normalize_hostname;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginPattern {
    Any,
    Null,
    Exact(String),
    /// Matches subdomains of `host_suffix` only. The apex needs its own exact
    /// entry.
    Wildcard {
        scheme: String,
        host_suffix: String,
        port: Option<u16>,
    },
}

/// Serializes `raw` as an origin, or `None` when it is not a tuple origin.
pub fn serialize_origin(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    let origin = url.origin();
    if !origin.is_tuple() {
        return None;
    }
    Some(origin.ascii_serialization())
}

/// Parses one configured origin entry: `*`, `null`, a full origin, or a
/// wildcard origin such as `https://*.example.com` with an optional port.
pub fn parse_origin_pattern(entry: &str) -> Result<OriginPattern, String> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err("origin entry is empty".to_owned());
    }
    if trimmed == "*" {
        return Ok(OriginPattern::Any);
    }
    if trimmed == "null" {
        return Ok(OriginPattern::Null);
    }
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        if let Some(after_star) = rest.strip_prefix("*.") {
            let scheme = scheme.to_ascii_lowercase();
            if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
                return Err(format!("origin entry {trimmed} has an unsupported scheme"));
            }
            let (host, port) = match after_star.split_once(':') {
                Some((host, port_raw)) => {
                    let port = port_raw
                        .bytes()
                        .all(|b| b.is_ascii_digit())
                        .then(|| port_raw.parse::<u16>().ok())
                        .flatten()
                        .filter(|port| *port != 0)
                        .ok_or_else(|| format!("origin entry {trimmed} has an invalid port"))?;
                    (host, Some(port))
                }
                None => (after_star, None),
            };
            // A trailing dot or path would never match a serialized origin,
            // so it is a typo rather than a pattern.
            if host.ends_with('.') || host.contains('/') {
                return Err(format!(
                    "origin entry {trimmed} has an invalid wildcard host"
                ));
            }
            let host_suffix = normalize_hostname(host)
                .ok_or_else(|| format!("origin entry {trimmed} has an invalid wildcard host"))?;
            let port = match (scheme.as_str(), port) {
                ("https", Some(443))
                | ("http", Some(80))
                | ("ws", Some(80))
                | ("wss", Some(443)) => None,
                _ => port,
            };
            return Ok(OriginPattern::Wildcard {
                scheme,
                host_suffix,
                port,
            });
        }
        if rest.contains('*') {
            return Err(format!(
                "origin entry {trimmed} may only use a wildcard as its first label"
            ));
        }
    }
    serialize_origin(trimmed)
        .map(OriginPattern::Exact)
        .ok_or_else(|| format!("origin entry {trimmed} is not a valid origin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_entry_kind() {
        assert_eq!(parse_origin_pattern("*"), Ok(OriginPattern::Any));
        assert_eq!(parse_origin_pattern(" null "), Ok(OriginPattern::Null));
        assert_eq!(
            parse_origin_pattern("https://Good.example/"),
            Ok(OriginPattern::Exact("https://good.example".to_owned()))
        );
        assert_eq!(
            parse_origin_pattern("https://*.Example.com:443"),
            Ok(OriginPattern::Wildcard {
                scheme: "https".to_owned(),
                host_suffix: "example.com".to_owned(),
                port: None,
            })
        );
        assert_eq!(
            parse_origin_pattern("https://*.example.com:8443"),
            Ok(OriginPattern::Wildcard {
                scheme: "https".to_owned(),
                host_suffix: "example.com".to_owned(),
                port: Some(8443),
            })
        );
    }

    #[test]
    fn rejects_malformed_entries() {
        for bad in [
            "",
            "good.example",
            "https://",
            "https://*.example.com:abc",
            "https://*.example.com:0",
            "https://*.example.com:99999",
            "https://*.example.com:+1",
            "https://*.example.com:",
            "https://*.",
            "https://*..example.com",
            "https://*.example.com.",
            "https://*.example.com/path",
            "ftp://*.example.com",
            "https://*.exa mple.com",
            "https://a.*.example.com",
        ] {
            assert!(parse_origin_pattern(bad).is_err(), "{bad} must be rejected");
        }
    }
}

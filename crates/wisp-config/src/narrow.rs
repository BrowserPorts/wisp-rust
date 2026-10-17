//! Destination host syntax and the narrowing of destination lists.
//!
//! Hostnames and domain patterns have one canonical spelling so configured
//! patterns and client-supplied hosts compare the same way. A token policy may
//! only restrict the options it is applied to, never widen them, so every list
//! combines with its base by union (blacklists) or intersection (whitelists).

use crate::{parse_cidr, prefix_match, Cidr, HostPortRule};

/// Trims, strips one trailing dot and lowercases a hostname, returning `None`
/// for anything that is not a syntactically valid DNS name. Empty labels (a
/// second trailing dot, `a..b`), over-long names and labels, and bytes other
/// than letters, digits, `-` and `_` are rejected.
pub fn normalize_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let host = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    valid.then_some(host)
}

/// Normalizes a destination domain pattern: a hostname, or `*.` followed by a
/// hostname (which matches that name and every name below it).
pub fn normalize_domain_pattern(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    match trimmed.strip_prefix("*.") {
        Some(rest) => normalize_hostname(rest).map(|host| format!("*.{host}")),
        None => normalize_hostname(trimmed),
    }
}

/// `true` when every host `inner` matches is also matched by `outer`. Both are
/// normalized patterns.
fn domain_covers(outer: &str, inner: &str) -> bool {
    let (inner_wild, inner_host) = match inner.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, inner),
    };
    match outer.strip_prefix("*.") {
        Some(suffix) => {
            inner_host == suffix
                || inner_host
                    .strip_suffix(suffix)
                    .is_some_and(|head| head.ends_with('.'))
        }
        None => !inner_wild && inner_host == outer,
    }
}

/// `true` when the network `inner` lies entirely inside the network `outer`.
fn cidr_covers(outer: Cidr, inner: Cidr) -> bool {
    match (outer, inner) {
        (
            Cidr::V4 {
                net: outer_net,
                prefix: outer_prefix,
            },
            Cidr::V4 {
                net: inner_net,
                prefix: inner_prefix,
            },
        ) => {
            outer_prefix <= inner_prefix
                && prefix_match(
                    u128::from(outer_net),
                    u128::from(inner_net),
                    outer_prefix,
                    32,
                )
        }
        (
            Cidr::V6 {
                net: outer_net,
                prefix: outer_prefix,
            },
            Cidr::V6 {
                net: inner_net,
                prefix: inner_prefix,
            },
        ) => outer_prefix <= inner_prefix && prefix_match(outer_net, inner_net, outer_prefix, 128),
        _ => false,
    }
}

/// Entries of both lists, without duplicates, for combining two blacklists.
pub(crate) fn union<T: Clone + PartialEq>(base: Option<&[T]>, extra: &[T]) -> Vec<T> {
    let mut out: Vec<T> = base.unwrap_or_default().to_vec();
    for item in extra {
        if !out.contains(item) {
            out.push(item.clone());
        }
    }
    out
}

/// Ports in both lists. A base of `None` is unrestricted, so the token's list
/// stands alone.
pub(crate) fn intersect_ports(base: Option<&[u16]>, token: &[u16]) -> Vec<u16> {
    let mut out = Vec::new();
    for port in token {
        if base.is_none_or(|base| base.contains(port)) && !out.contains(port) {
            out.push(*port);
        }
    }
    out
}

/// Intersection of two pattern lists, given `covers(outer, inner)` which says
/// whether `outer` matches everything `inner` matches. Suffix patterns and
/// CIDR networks either nest or are disjoint, so keeping each entry of one
/// list that some entry of the other list covers is the exact intersection.
/// Entries that do not parse are dropped; validation reports them.
fn intersect_patterns<P: Copy>(
    base: Option<&[String]>,
    token: &[String],
    parse: impl Fn(&str) -> Option<P>,
    covers: impl Fn(P, P) -> bool,
) -> Vec<String> {
    let Some(base) = base else {
        return token.to_vec();
    };
    let parsed = |list: &[String]| -> Vec<(P, String)> {
        list.iter()
            .filter_map(|entry| parse(entry).map(|p| (p, entry.trim().to_owned())))
            .collect()
    };
    let base = parsed(base);
    let token = parsed(token);
    let mut out: Vec<String> = Vec::new();
    for (pattern, entry) in &token {
        if base.iter().any(|(outer, _)| covers(*outer, *pattern)) && !out.contains(entry) {
            out.push(entry.clone());
        }
    }
    for (pattern, entry) in &base {
        if token.iter().any(|(outer, _)| covers(*outer, *pattern)) && !out.contains(entry) {
            out.push(entry.clone());
        }
    }
    out
}

pub(crate) fn intersect_domains(base: Option<&[String]>, token: &[String]) -> Vec<String> {
    let Some(base) = base else {
        return token.to_vec();
    };
    let normalized = |list: &[String]| -> Vec<String> {
        list.iter()
            .filter_map(|entry| normalize_domain_pattern(entry))
            .collect()
    };
    let base = normalized(base);
    let token = normalized(token);
    let mut out: Vec<String> = Vec::new();
    for (inner_list, outer_list) in [(&token, &base), (&base, &token)] {
        for pattern in inner_list {
            if outer_list.iter().any(|outer| domain_covers(outer, pattern))
                && !out.contains(pattern)
            {
                out.push(pattern.clone());
            }
        }
    }
    out
}

pub(crate) fn intersect_ip_rules(base: Option<&[String]>, token: &[String]) -> Vec<String> {
    intersect_patterns(base, token, |entry| parse_cidr(entry).ok(), cidr_covers)
}

/// Host and port rules are exceptions to a port whitelist. The result grants
/// `host:port` exactly when both sides grant it: each side allows a port that
/// is in its whitelist (or has no whitelist) or that one of its own rules
/// names for that host. `out_ports` is the already intersected whitelist,
/// and a rule it already covers is dropped as redundant.
pub(crate) fn intersect_host_ports(
    base_ports: Option<&[u16]>,
    base_rules: Option<&[HostPortRule]>,
    token_ports: Option<&[u16]>,
    token_rules: Option<&[HostPortRule]>,
    out_ports: Option<&[u16]>,
) -> Option<Vec<HostPortRule>> {
    if base_rules.is_none() && token_rules.is_none() {
        return None;
    }
    let normalized = |rules: Option<&[HostPortRule]>| -> Vec<(String, u16)> {
        rules
            .unwrap_or_default()
            .iter()
            .filter_map(|rule| rule.normalized_host().map(|host| (host, rule.port)))
            .collect()
    };
    let base_rules = normalized(base_rules);
    let token_rules = normalized(token_rules);
    let grants = |ports: Option<&[u16]>, rules: &[(String, u16)], host: &str, port: u16| {
        ports.is_none_or(|ports| ports.contains(&port))
            || rules.iter().any(|(h, p)| h == host && *p == port)
    };
    let mut out: Vec<HostPortRule> = Vec::new();
    for (host, port) in base_rules.iter().chain(token_rules.iter()) {
        if grants(base_ports, &base_rules, host, *port)
            && grants(token_ports, &token_rules, host, *port)
            && out_ports.is_some_and(|ports| !ports.contains(port))
            && !out
                .iter()
                .any(|rule| rule.host == *host && rule.port == *port)
        {
            out.push(HostPortRule {
                host: host.clone(),
                port: *port,
            });
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn rule(host: &str, port: u16) -> HostPortRule {
        HostPortRule {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn hostname_normalization_rejects_empty_labels_and_bad_bytes() {
        assert_eq!(
            normalize_hostname(" Example.COM. ").as_deref(),
            Some("example.com")
        );
        for bad in [
            "a..b",
            "example.com..",
            "",
            ".",
            "a b.example",
            "-a.example",
            "a-.example",
            "a/b.example",
            "a:443",
            "[::1]",
            "a\r\nb",
            "caf\u{e9}.example",
        ] {
            assert_eq!(normalize_hostname(bad), None, "{bad:?}");
        }
        assert_eq!(normalize_hostname(&"a".repeat(64)), None);
        assert_eq!(
            normalize_hostname("_dmarc.example").as_deref(),
            Some("_dmarc.example")
        );
    }

    #[test]
    fn domain_patterns_normalize() {
        assert_eq!(
            normalize_domain_pattern("*.Example.com.").as_deref(),
            Some("*.example.com")
        );
        assert_eq!(normalize_domain_pattern("*."), None);
        assert_eq!(normalize_domain_pattern("*"), None);
        assert_eq!(normalize_domain_pattern("a.*.com"), None);
    }

    #[test]
    fn port_intersection_only_narrows() {
        assert_eq!(intersect_ports(Some(&[80, 443]), &[443, 8080]), vec![443]);
        assert_eq!(intersect_ports(None, &[8080]), vec![8080]);
        assert!(intersect_ports(Some(&[80]), &[]).is_empty());
    }

    #[test]
    fn domain_intersection_keeps_nested_patterns() {
        let base = strings(&["*.example.com"]);
        let narrowed = intersect_domains(Some(&base), &strings(&["API.example.com.", "evil.org"]));
        assert_eq!(narrowed, strings(&["api.example.com"]));
        let widened = intersect_domains(Some(&strings(&["api.example.com"])), &strings(&["*.com"]));
        assert_eq!(widened, strings(&["api.example.com"]));
        assert!(intersect_domains(Some(&base), &strings(&["evil.org"])).is_empty());
        assert!(intersect_domains(Some(&base), &strings(&["notexample.com"])).is_empty());
        assert_eq!(
            intersect_domains(None, &strings(&["a.example"])),
            strings(&["a.example"])
        );
    }

    #[test]
    fn cidr_intersection_keeps_nested_networks() {
        let base = strings(&["8.8.0.0/16"]);
        let narrowed = intersect_ip_rules(Some(&base), &strings(&["8.8.8.0/24", "1.1.1.1"]));
        assert_eq!(narrowed, strings(&["8.8.8.0/24"]));
        let widened = intersect_ip_rules(Some(&strings(&["8.8.8.0/24"])), &strings(&["8.0.0.0/8"]));
        assert_eq!(widened, strings(&["8.8.8.0/24"]));
        assert!(intersect_ip_rules(Some(&base), &strings(&["2001:db8::/32"])).is_empty());
        let mapped = intersect_ip_rules(
            Some(&base),
            &strings(&["::ffff:8.8.8.8/128", "::ffff:9.9.9.9"]),
        );
        assert_eq!(mapped, strings(&["::ffff:8.8.8.8/128"]));
    }

    #[test]
    fn host_port_rules_are_granted_only_when_both_sides_grant_them() {
        // The base allows 80 and 443 plus game.example:13002. A token that
        // names another port for the same host gains nothing.
        let base_rules = vec![rule("Game.example.", 13002)];
        let kept = intersect_host_ports(
            Some(&[80, 443]),
            Some(&base_rules),
            None,
            Some(&[rule("game.example", 13002), rule("game.example", 1)]),
            Some(&[80, 443]),
        )
        .unwrap();
        assert_eq!(kept, vec![rule("game.example", 13002)]);

        // A token that narrows ports to 443 drops the base exception, unless
        // it grants the exception itself.
        let dropped = intersect_host_ports(
            Some(&[80, 443]),
            Some(&base_rules),
            Some(&[443]),
            None,
            Some(&[443]),
        )
        .unwrap();
        assert!(dropped.is_empty());
        let regranted = intersect_host_ports(
            Some(&[80, 443]),
            Some(&base_rules),
            Some(&[443]),
            Some(&[rule("game.example", 13002)]),
            Some(&[443]),
        )
        .unwrap();
        assert_eq!(regranted, vec![rule("game.example", 13002)]);

        // A base with no port whitelist grants any token exception.
        let open = intersect_host_ports(
            None,
            None,
            Some(&[443]),
            Some(&[rule("game.example", 13002)]),
            Some(&[443]),
        )
        .unwrap();
        assert_eq!(open, vec![rule("game.example", 13002)]);
        assert!(intersect_host_ports(None, None, Some(&[443]), None, Some(&[443])).is_none());
    }
}

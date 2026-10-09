//! Client-IP normalization and SHA-256 hashing.
//!
//! IPv4 → exact dotted-quad. IPv6 → first 4 hex groups + `:0:0:0:0/64` mask
//! (so the hash never identifies a single IPv6 device, just a /64).
//!
//! Input that does not parse as an IP address is unidentifiable: normalization
//! returns `None` so malformed header text is never hashed as an identity.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Normalize a client IP into a stable identity key, or `None` when the input
/// is not a parseable IP address. Callers must treat `None` as unidentifiable
/// (apply the strictest limit / reject) rather than substituting a default.
pub fn normalize_client_ip(ip: &str) -> Option<String> {
    let mut val = ip.trim().to_ascii_lowercase();
    if val.is_empty() {
        return None;
    }
    if val.starts_with('[') {
        if let Some(close) = val.find(']') {
            val = val[1..close].to_owned();
        }
    }
    if let Some(rest) = val.strip_prefix("::ffff:") {
        if rest.parse::<Ipv4Addr>().is_ok() {
            return Some(rest.to_owned());
        }
    }
    match val.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Some(v4.to_string()),
        Ok(IpAddr::V6(v6)) => Some(mask_ipv6_to_64(v6)),
        Err(_) => None,
    }
}

fn mask_ipv6_to_64(addr: Ipv6Addr) -> String {
    let s = addr.segments();
    format!(
        "{:04x}:{:04x}:{:04x}:{:04x}:0000:0000:0000:0000/64",
        s[0], s[1], s[2], s[3]
    )
}

/// Base64url-encoded SHA-256 (or HMAC-SHA256 when a secret is supplied) of the
/// normalized IP. Returns `None` when the input is absent or not a parseable IP.
pub fn hash_client_ip(ip: Option<&str>, secret: Option<&[u8]>) -> Option<String> {
    let normalized = normalize_client_ip(ip?)?;
    let digest = match secret {
        Some(s) => hmac_sha256(s, normalized.as_bytes()),
        None => sha256(normalized.as_bytes()),
    };
    Some(base64url_encode(&digest))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn base64url_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push(ALPHA[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_normalizes_to_self() {
        assert_eq!(
            normalize_client_ip("203.0.113.5").as_deref(),
            Some("203.0.113.5")
        );
    }

    #[test]
    fn mapped_ipv4_collapses() {
        assert_eq!(
            normalize_client_ip("::ffff:1.2.3.4").as_deref(),
            Some("1.2.3.4")
        );
    }

    #[test]
    fn ipv6_masked_to_64() {
        assert_eq!(
            normalize_client_ip("2001:db8:1234:5678:abcd:ef01:2345:6789").as_deref(),
            Some("2001:0db8:1234:5678:0000:0000:0000:0000/64")
        );
    }

    #[test]
    fn non_ip_string_returns_none() {
        assert_eq!(normalize_client_ip("not-an-ip"), None);
        assert_eq!(normalize_client_ip("example.com"), None);
        assert_eq!(normalize_client_ip("999.999.999.999"), None);
        assert_eq!(normalize_client_ip("   "), None);
    }

    #[test]
    fn non_ip_string_is_not_hashed() {
        assert_eq!(hash_client_ip(Some("not-an-ip"), None), None);
        assert_eq!(hash_client_ip(None, None), None);
    }

    #[test]
    fn hash_is_deterministic_base64url() {
        let h1 = hash_client_ip(Some("203.0.113.5"), None).unwrap();
        let h2 = hash_client_ip(Some("203.0.113.5"), None).unwrap();
        assert_eq!(h1, h2);
        assert!(!h1.contains('+') && !h1.contains('/') && !h1.contains('='));
    }

    #[test]
    fn hmac_changes_output() {
        let plain = hash_client_ip(Some("203.0.113.5"), None).unwrap();
        let keyed = hash_client_ip(Some("203.0.113.5"), Some(b"secret")).unwrap();
        assert_ne!(plain, keyed);
    }
}

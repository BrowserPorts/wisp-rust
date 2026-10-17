//! Client-IP normalization and SHA-256 hashing.
//!
//! IPv4 → exact dotted-quad. IPv6 → first 4 hex groups + `:0:0:0:0/64` mask
//! (so the hash never identifies a single IPv6 device, just a /64).
//!
//! Input that does not parse as an IP address is unidentifiable: normalization
//! returns `None` so malformed header text is never hashed as an identity.

#![forbid(unsafe_code)]

mod bans;

pub use bans::IpHashBans;

use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::OnceLock;

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
    // `to_canonical` folds every IPv4-mapped form (dotted `::ffff:1.2.3.4` and
    // hex `::ffff:102:304`) to the IPv4 address before any masking happens.
    match val.parse::<IpAddr>().ok()?.to_canonical() {
        IpAddr::V4(v4) => Some(v4.to_string()),
        // Loopback and the unspecified address are single hosts, not members of
        // a client /64. Masking them would put `::1` in the all-zero /64 bucket
        // that real `::/64` traffic also lands in.
        IpAddr::V6(v6) if v6.is_loopback() || v6.is_unspecified() => Some(exact_ipv6(v6)),
        IpAddr::V6(v6) => Some(mask_ipv6_to_64(v6)),
    }
}

fn exact_ipv6(addr: Ipv6Addr) -> String {
    let s = addr.segments();
    format!(
        "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]
    )
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

/// Environment variable that carries the process-wide HMAC key for IP hashes.
pub const KEY_ENV: &str = "WISP_IP_HASH_KEY";

/// Shortest accepted HMAC key. A shorter key adds little over the unkeyed hash.
pub const MIN_KEY_BYTES: usize = 32;

/// Why the process-wide IP hash key could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}

/// The key as read from the environment once; `Ok(None)` means unset.
static PROCESS_KEY: OnceLock<Result<Option<Vec<u8>>, KeyError>> = OnceLock::new();

fn parse_key(value: Option<std::ffi::OsString>) -> Result<Option<Vec<u8>>, KeyError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = value.into_encoded_bytes();
    if bytes.len() < MIN_KEY_BYTES {
        return Err(KeyError(format!(
            "{KEY_ENV} must be at least {MIN_KEY_BYTES} bytes"
        )));
    }
    Ok(Some(bytes))
}

fn process_key_entry() -> &'static Result<Option<Vec<u8>>, KeyError> {
    PROCESS_KEY.get_or_init(|| {
        let key = parse_key(std::env::var_os(KEY_ENV));
        match &key {
            Ok(Some(_)) => {}
            // Switching to a keyed hash changes every stored ban hash, so an
            // unset key keeps the unkeyed hash and says so once.
            Ok(None) => tracing::warn!(
                "{KEY_ENV} is not set; client IP hashes are unkeyed SHA-256 and can be reversed by enumeration"
            ),
            Err(error) => tracing::error!(%error, "client IP hashing key rejected"),
        }
        key
    })
}

/// Read the process-wide key from `WISP_IP_HASH_KEY` the first time this runs
/// and keep it for the life of the process. Call it at startup so a bad key
/// fails the start instead of silently hashing without a key.
pub fn init_process_key() -> Result<(), KeyError> {
    process_key_entry()
        .as_ref()
        .map(|_| ())
        .map_err(Clone::clone)
}

/// The process-wide HMAC key, or `None` when `WISP_IP_HASH_KEY` is unset (or
/// was rejected, which [`init_process_key`] reports).
pub fn process_key() -> Option<&'static [u8]> {
    process_key_entry().as_ref().ok()?.as_deref()
}

/// [`hash_client_ip`] with the process-wide key. Every live call site that
/// hashes a client for bans or reports goes through this, so they all agree.
pub fn hash_client_ip_keyed(ip: Option<&str>) -> Option<String> {
    hash_client_ip(ip, process_key())
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
    fn mapped_ipv4_hex_form_collapses_to_ipv4() {
        assert_eq!(
            normalize_client_ip("::ffff:102:304").as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            normalize_client_ip("[::ffff:102:304]:443").as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            normalize_client_ip("0:0:0:0:0:ffff:0102:0304").as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            hash_client_ip(Some("::ffff:102:304"), None),
            hash_client_ip(Some("1.2.3.4"), None)
        );
    }

    #[test]
    fn loopback_is_not_the_all_zero_slash_64() {
        let loopback = normalize_client_ip("::1").unwrap();
        let unspecified = normalize_client_ip("::").unwrap();
        let low = normalize_client_ip("::1:2:3:4").unwrap();
        assert_eq!(low, "0000:0000:0000:0000:0000:0000:0000:0000/64");
        assert_ne!(loopback, low);
        assert_ne!(unspecified, low);
        assert_ne!(loopback, unspecified);
        assert!(!loopback.ends_with("/64"));
        assert_ne!(
            hash_client_ip(Some("::1"), None),
            hash_client_ip(Some("::1:2:3:4"), None)
        );
    }

    #[test]
    fn key_must_be_long_enough() {
        assert_eq!(parse_key(None), Ok(None));
        assert!(parse_key(Some("short".into())).is_err());
        assert!(parse_key(Some("k".repeat(MIN_KEY_BYTES - 1).into())).is_err());
        assert_eq!(
            parse_key(Some("k".repeat(MIN_KEY_BYTES).into())),
            Ok(Some(vec![b'k'; MIN_KEY_BYTES]))
        );
    }

    #[test]
    fn keyed_hash_depends_on_key() {
        let a = hash_client_ip(Some("203.0.113.5"), Some(&[1u8; 32])).unwrap();
        let b = hash_client_ip(Some("203.0.113.5"), Some(&[2u8; 32])).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            a,
            hash_client_ip(Some("203.0.113.5"), Some(&[1u8; 32])).unwrap()
        );
    }

    #[test]
    fn hmac_changes_output() {
        let plain = hash_client_ip(Some("203.0.113.5"), None).unwrap();
        let keyed = hash_client_ip(Some("203.0.113.5"), Some(b"secret")).unwrap();
        assert_ne!(plain, keyed);
    }
}

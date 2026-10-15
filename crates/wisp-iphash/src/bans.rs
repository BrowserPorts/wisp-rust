//! Live set of banned client IP hashes.
//!
//! Entries are the strings [`crate::hash_client_ip`] produces. The transports
//! check every connection against this set before any Wisp traffic is served,
//! and an admin replaces the whole set at runtime, so reads must stay cheap
//! and a replacement must never leave a reader looking at a half-built set.

use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;

/// Shared ban list. Readers take the lock only long enough to probe the set;
/// [`IpHashBans::replace`] builds the new set off to the side and swaps it in,
/// so a replacement costs readers one pointer store.
#[derive(Debug, Default)]
pub struct IpHashBans {
    hashes: RwLock<Arc<HashSet<String>>>,
}

impl IpHashBans {
    pub fn new() -> Self {
        Self::default()
    }

    /// Swap in a whole new set and return how many distinct hashes it holds.
    /// Blank entries are dropped so a stray empty string can never match a
    /// client whose hash is absent.
    pub fn replace<I, S>(&self, hashes: I) -> usize
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let next: HashSet<String> = hashes
            .into_iter()
            .map(Into::into)
            .filter(|hash: &String| !hash.is_empty())
            .collect();
        let count = next.len();
        *self.hashes.write() = Arc::new(next);
        count
    }

    /// The current set. Cheap to hold across awaits; later replacements do not
    /// change a snapshot already taken.
    pub fn snapshot(&self) -> Arc<HashSet<String>> {
        self.hashes.read().clone()
    }

    pub fn len(&self) -> usize {
        self.hashes.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.read().is_empty()
    }

    /// Whether a client hash is banned. A client whose IP could not be hashed
    /// (`None`) is never banned here; the other policy gates already treat an
    /// unidentifiable address strictly.
    pub fn is_banned(&self, client_hash: Option<&str>) -> bool {
        let Some(hash) = client_hash else {
            return false;
        };
        self.hashes.read().contains(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_client_ip;

    #[test]
    fn empty_set_bans_nobody() {
        let bans = IpHashBans::new();
        assert!(bans.is_empty());
        assert!(!bans.is_banned(Some("anything")));
        assert!(!bans.is_banned(None));
    }

    #[test]
    fn matches_the_hash_of_a_client_ip() {
        let bans = IpHashBans::new();
        let banned = hash_client_ip(Some("203.0.113.5"), None).unwrap();
        let other = hash_client_ip(Some("203.0.113.6"), None).unwrap();
        assert_eq!(bans.replace([banned.clone()]), 1);
        assert!(bans.is_banned(Some(&banned)));
        assert!(!bans.is_banned(Some(&other)));
        assert!(!bans.is_banned(None));
    }

    #[test]
    fn replace_swaps_the_whole_set() {
        let bans = IpHashBans::new();
        bans.replace(["a", "b"]);
        let before = bans.snapshot();
        assert_eq!(bans.replace(["c"]), 1);
        assert!(!bans.is_banned(Some("a")));
        assert!(bans.is_banned(Some("c")));
        assert_eq!(bans.len(), 1);
        assert!(before.contains("a"), "earlier snapshot is unchanged");
    }

    #[test]
    fn replace_dedupes_and_drops_blanks() {
        let bans = IpHashBans::new();
        assert_eq!(bans.replace(["a", "a", "", "b"]), 2);
        assert!(!bans.is_banned(Some("")));
        assert_eq!(bans.replace(Vec::<String>::new()), 0);
        assert!(bans.is_empty());
    }
}

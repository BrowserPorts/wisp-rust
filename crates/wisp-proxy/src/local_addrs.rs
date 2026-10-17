//! Addresses assigned to this host's network interfaces. A client that dials
//! one of them reaches the server's own listeners through the proxy, so the
//! destination check denies them unless loopback destinations are allowed.
//!
//! The list is read with `getifaddrs` on first use and again once it is older
//! than [`REFRESH`], so an address added while the server runs is picked up
//! without a restart.

#![allow(unsafe_code)]

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const REFRESH: Duration = Duration::from_secs(30);

#[cfg(unix)]
fn enumerate() -> Vec<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs stores the head of a list it allocates in `head`. The
    // list is only read while it is alive and is released with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a non-null node of the live list.
        let entry = unsafe { &*cursor };
        if !entry.ifa_addr.is_null() {
            // SAFETY: a non-null ifa_addr points to a sockaddr whose family
            // says which wider structure it is, and every read is unaligned.
            unsafe {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let sin = (entry.ifa_addr as *const libc::sockaddr_in).read_unaligned();
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            sin.sin_addr.s_addr,
                        ))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = (entry.ifa_addr as *const libc::sockaddr_in6).read_unaligned();
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(not(unix))]
fn enumerate() -> Vec<IpAddr> {
    Vec::new()
}

type Snapshot = (Instant, Arc<HashSet<IpAddr>>);

static CACHE: Mutex<Option<Snapshot>> = Mutex::new(None);

fn snapshot() -> Arc<HashSet<IpAddr>> {
    let mut guard = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((at, set)) = guard.as_ref() {
        if at.elapsed() < REFRESH {
            return set.clone();
        }
    }
    let set: Arc<HashSet<IpAddr>> = Arc::new(
        enumerate()
            .into_iter()
            .map(|ip| ip.to_canonical())
            .collect(),
    );
    *guard = Some((Instant::now(), set.clone()));
    set
}

/// `true` when `ip` is assigned to one of this host's interfaces.
pub(crate) fn is_local_address(ip: IpAddr) -> bool {
    snapshot().contains(&ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn interface_addresses_are_listed() {
        assert!(is_local_address("127.0.0.1".parse().unwrap()));
        assert!(is_local_address("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_local_address("203.0.113.77".parse().unwrap()));
    }
}

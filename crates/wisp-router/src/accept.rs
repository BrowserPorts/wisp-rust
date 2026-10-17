//! Shared accept-loop policy: how many connections may be in their
//! pre-authentication phase at once, overall and per source address, what a
//! refused connection is told, and how the loop backs off when the process
//! runs out of descriptors or memory.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Pause after an accept error that means the process is out of descriptors,
/// buffers or memory. Retrying at once would spin on the same error.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Pre-authentication connections in flight, by source address.
type IpCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// Pre-authentication slots, released once a connection has upgraded (it is
/// then counted by the connection limiter) or has ended.
pub(crate) struct AcceptBudget {
    total: Arc<Semaphore>,
    per_ip_limit: usize,
    per_ip: IpCounts,
}

impl AcceptBudget {
    /// `total` 0 means 4096. `per_ip` 0 means no per-address cap.
    pub(crate) fn new(total: u64, per_ip: u64) -> Self {
        let total = usize::try_from(total)
            .ok()
            .filter(|limit| *limit > 0)
            .unwrap_or(4096);
        Self {
            total: Arc::new(Semaphore::new(total)),
            per_ip_limit: usize::try_from(per_ip).unwrap_or(usize::MAX),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Takes a slot for a connection from `ip`, or `None` when the listener
    /// or that address is at its cap. `ip` is `None` for a trusted front,
    /// which carries many clients and is only held to the overall cap.
    pub(crate) fn try_admit(&self, ip: Option<IpAddr>) -> Option<AcceptGuard> {
        let permit = self.total.clone().try_acquire_owned().ok()?;
        let per_ip = match ip.filter(|_| self.per_ip_limit > 0) {
            Some(ip) => {
                let key = per_ip_key(ip);
                let mut counts = self
                    .per_ip
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let count = counts.entry(key).or_insert(0);
                if *count >= self.per_ip_limit {
                    return None;
                }
                *count += 1;
                Some((key, self.per_ip.clone()))
            }
            None => None,
        };
        Some(AcceptGuard {
            _permit: permit,
            per_ip,
        })
    }
}

/// IPv6 clients usually hold a whole /64, so one is counted as one address.
fn per_ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let bits = u128::from(v6) & !((1u128 << 64) - 1);
                IpAddr::V6(Ipv6Addr::from(bits))
            }
        },
    }
}

/// One pre-authentication slot. Dropping it frees the slot.
pub(crate) struct AcceptGuard {
    _permit: OwnedSemaphorePermit,
    per_ip: Option<(IpAddr, IpCounts)>,
}

impl Drop for AcceptGuard {
    fn drop(&mut self) {
        let Some((key, counts)) = self.per_ip.take() else {
            return;
        };
        let mut counts = counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&key);
            }
        }
    }
}

/// Whether an accept error means the process is short of a resource, so
/// the loop should pause, rather than that one connection failed.
pub(crate) fn is_resource_exhaustion(error: &std::io::Error) -> bool {
    const ENOMEM: i32 = 12;
    const ENFILE: i32 = 23;
    const EMFILE: i32 = 24;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENOBUFS: i32 = 105;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const ENOBUFS: i32 = 55;
    error.kind() == std::io::ErrorKind::OutOfMemory
        || matches!(
            error.raw_os_error(),
            Some(ENOMEM | ENFILE | EMFILE | ENOBUFS)
        )
}

const BUSY_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Longest a refused client is given to send its request and take the 503.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(1);

/// Answers plain HTTP clients with 503 when the listener is full. Each
/// answer reads the request head first, so the close is not a reset that
/// discards the response, and the number of answers in flight is capped;
/// past the cap a refused connection is closed unanswered.
pub(crate) struct Refusals {
    slots: Arc<Semaphore>,
}

impl Refusals {
    pub(crate) fn new(max_in_flight: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(max_in_flight.max(1))),
        }
    }

    pub(crate) fn refuse(&self, tcp: TcpStream) {
        let Ok(slot) = self.slots.clone().try_acquire_owned() else {
            return;
        };
        tokio::spawn(async move {
            let _slot = slot;
            let _ = tokio::time::timeout(REFUSAL_TIMEOUT, answer_busy(tcp)).await;
        });
    }
}

async fn answer_busy(mut tcp: TcpStream) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8 * 1024 {
        let read = tcp.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
    }
    tcp.write_all(BUSY_RESPONSE).await?;
    tcp.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_cap_counts_concurrent_slots() {
        let budget = AcceptBudget::new(10, 2);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let first = budget.try_admit(Some(ip)).expect("first slot");
        let _second = budget.try_admit(Some(ip)).expect("second slot");
        assert!(
            budget.try_admit(Some(ip)).is_none(),
            "third is over the cap"
        );
        assert!(budget
            .try_admit(Some("203.0.113.2".parse().unwrap()))
            .is_some());
        drop(first);
        assert!(
            budget.try_admit(Some(ip)).is_some(),
            "a freed slot is reusable"
        );
    }

    #[test]
    fn trusted_front_is_held_only_to_the_total() {
        let budget = AcceptBudget::new(3, 1);
        let held: Vec<_> = (0..3).map(|_| budget.try_admit(None).unwrap()).collect();
        assert!(budget.try_admit(None).is_none());
        drop(held);
        assert!(budget.try_admit(None).is_some());
    }

    #[test]
    fn ipv6_slots_are_counted_per_64() {
        let budget = AcceptBudget::new(10, 1);
        let _a = budget
            .try_admit(Some("2001:db8:1:2::1".parse().unwrap()))
            .unwrap();
        assert!(budget
            .try_admit(Some("2001:db8:1:2::ffff".parse().unwrap()))
            .is_none());
        assert!(budget
            .try_admit(Some("2001:db8:1:3::1".parse().unwrap()))
            .is_some());
    }

    #[test]
    fn descriptor_exhaustion_is_a_resource_error() {
        assert!(is_resource_exhaustion(&std::io::Error::from_raw_os_error(
            24
        )));
        assert!(is_resource_exhaustion(&std::io::Error::from_raw_os_error(
            23
        )));
        assert!(!is_resource_exhaustion(&std::io::Error::from(
            std::io::ErrorKind::ConnectionAborted
        )));
    }
}

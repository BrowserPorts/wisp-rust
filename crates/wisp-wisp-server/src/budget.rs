//! Byte budgets for data the server holds on a client's behalf: upload bytes
//! waiting for a slow or still-connecting upstream, and egress frames waiting
//! for a slow client. Each connection has its own upload budget, and every
//! connection of the process shares one more, so neither one client nor many
//! together can grow the process without bound.
//!
//! A budget never refuses a charge. Bytes are charged after they have
//! already been read, and the reader checks [`Budgets::has_room`] before it
//! reads more: a full budget stops the client from being read (or the
//! upstream, for egress) until a charge is dropped. The overshoot is at most
//! one message per reader.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::Notify;
use wisp_config::WispServerOptions;

pub(crate) struct ByteBudget {
    used: AtomicUsize,
    limit: AtomicUsize,
    /// Woken when `used` drops below `limit`, or the limit changes.
    room: Notify,
}

impl ByteBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit: AtomicUsize::new(limit.max(1)),
            room: Notify::new(),
        }
    }

    fn set_limit(&self, limit: usize) {
        self.limit.store(limit.max(1), Ordering::SeqCst);
        self.room.notify_waiters();
    }

    pub(crate) fn has_room(&self) -> bool {
        self.used.load(Ordering::SeqCst) < self.limit.load(Ordering::SeqCst)
    }

    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }

    fn add(&self, bytes: usize) {
        self.used.fetch_add(bytes, Ordering::SeqCst);
    }

    fn sub(&self, bytes: usize) {
        let before = self.used.fetch_sub(bytes, Ordering::SeqCst);
        let after = before.saturating_sub(bytes);
        let limit = self.limit.load(Ordering::SeqCst);
        // Waiters only wait while the budget is full, so only the release
        // that frees it has to wake them.
        if before >= limit && after < limit {
            self.room.notify_waiters();
        }
    }
}

fn process_budget() -> &'static Arc<ByteBudget> {
    static PROCESS: OnceLock<Arc<ByteBudget>> = OnceLock::new();
    PROCESS.get_or_init(|| {
        let limit = WispServerOptions::default().max_buffered_bytes_total;
        Arc::new(ByteBudget::new(
            usize::try_from(limit).unwrap_or(usize::MAX),
        ))
    })
}

/// Sets the byte budget shared by every connection of the process
/// (`max_buffered_bytes_total`). The runtime calls it with the base options
/// when it starts and whenever the base limits change.
pub fn set_max_buffered_bytes_total(bytes: u64) {
    process_budget().set_limit(usize::try_from(bytes).unwrap_or(usize::MAX));
}

/// Bytes currently held across every connection of the process.
pub fn buffered_bytes_total() -> u64 {
    process_budget().used() as u64
}

/// A connection's own budget, if it has one, plus the process budget.
#[derive(Clone)]
pub(crate) struct Budgets {
    connection: Option<Arc<ByteBudget>>,
    process: Arc<ByteBudget>,
}

impl Budgets {
    pub(crate) fn for_connection(limit: u64) -> Self {
        Self {
            connection: Some(Arc::new(ByteBudget::new(
                usize::try_from(limit).unwrap_or(usize::MAX),
            ))),
            process: process_budget().clone(),
        }
    }

    pub(crate) fn process_only() -> Self {
        Self {
            connection: None,
            process: process_budget().clone(),
        }
    }

    pub(crate) fn has_room(&self) -> bool {
        self.process.has_room() && self.connection.as_ref().is_none_or(|c| c.has_room())
    }

    /// Bytes held against this connection's own budget.
    #[cfg(test)]
    pub(crate) fn connection_used(&self) -> usize {
        self.connection.as_ref().map_or(0, |c| c.used())
    }

    pub(crate) fn charge(&self, bytes: usize) -> BudgetCharge {
        if let Some(connection) = self.connection.as_ref() {
            connection.add(bytes);
        }
        self.process.add(bytes);
        BudgetCharge {
            budgets: self.clone(),
            bytes,
        }
    }

    /// Resolves once every budget has room.
    pub(crate) async fn room(&self) {
        if self.has_room() {
            return;
        }
        loop {
            let process = self.process.room.notified();
            tokio::pin!(process);
            process.as_mut().enable();
            match self.connection.as_ref() {
                Some(connection) => {
                    let own = connection.room.notified();
                    tokio::pin!(own);
                    own.as_mut().enable();
                    if self.has_room() {
                        return;
                    }
                    tokio::select! {
                        _ = process => {}
                        _ = own => {}
                    }
                }
                None => {
                    if self.has_room() {
                        return;
                    }
                    process.await;
                }
            }
        }
    }
}

/// Bytes held against [`Budgets`] until dropped.
pub(crate) struct BudgetCharge {
    budgets: Budgets,
    bytes: usize,
}

impl Drop for BudgetCharge {
    fn drop(&mut self) {
        if let Some(connection) = self.budgets.connection.as_ref() {
            connection.sub(self.bytes);
        }
        self.budgets.process.sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn charges_fill_and_release_the_connection_budget() {
        let budgets = Budgets::for_connection(10);
        assert!(budgets.has_room());
        let first = budgets.charge(6);
        assert!(budgets.has_room());
        let second = budgets.charge(6);
        assert!(!budgets.has_room(), "12 of 10 bytes is over budget");
        assert_eq!(budgets.connection_used(), 12);
        drop(first);
        assert!(budgets.has_room());
        drop(second);
        assert_eq!(budgets.connection_used(), 0);
    }

    #[tokio::test]
    async fn room_waits_for_a_release() {
        let budgets = Budgets::for_connection(4);
        let held = budgets.charge(8);
        let waiter = {
            let budgets = budgets.clone();
            tokio::spawn(async move { budgets.room().await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "a full budget has no room");
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("the release wakes the waiter")
            .unwrap();
    }
}

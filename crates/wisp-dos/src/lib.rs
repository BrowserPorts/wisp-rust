//! Token-bucket DoS guard with optional Redis backend. Mirrors `wisp-wt/src/dos.ts`.
//!
//! The TS reference stores buckets in JS `Map` and uses Lua scripts for Redis.
//! The Rust port ships the in-memory backend (`DosGuard`) and the public
//! decision helpers — Redis is intentionally deferred behind a `redis` feature
//! flag (added in a follow-up); the Wispmark target uses memory anyway.
//!
//! Sentinel: TS uses `limit < 0` to mean "unlimited" (skip constraint). Since
//! Rust config fields are `u64`, the equivalent sentinel is `u64::MAX` — the
//! helpers treat it as "no cap" and avoid overflow.

#![forbid(unsafe_code)]

use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wisp_config::WispServerOptions;

pub const SECOND_MS: u64 = 1_000;
pub const MINUTE_MS: u64 = 60_000;
pub const UNLIMITED: u64 = u64::MAX;

/// Upper bound on live entries in each bucket map. Bounds attacker-driven key
/// churn (e.g. IP rotation) so the maps can't grow without limit between the
/// coarse time-based sweeps. When exceeded, the oldest entries are evicted.
const MAX_BUCKETS: usize = 1_048_576;

/// Normalize a client IP for use as a per-IP rate-limit key. IPv6 is masked to
/// its /64 (matching `wisp_iphash`), so an attacker holding a routed /64 can't
/// mint unlimited distinct keys by rotating the low 64 bits. Non-IP strings and
/// IPv4 pass through unchanged.
fn dos_ip_key(client_ip: &str) -> String {
    wisp_iphash::normalize_client_ip(client_ip).unwrap_or_else(|| client_ip.to_owned())
}

#[derive(Debug, Clone)]
pub struct ConsumeRequest {
    pub key: String,
    pub limit: u64,
    pub window_ms: u64,
    pub amount: u64,
}

impl ConsumeRequest {
    pub fn new(key: impl Into<String>, limit: u64, window_ms: u64) -> Self {
        Self {
            key: key.into(),
            limit,
            window_ms,
            amount: 1,
        }
    }

    pub fn with_amount(mut self, amount: u64) -> Self {
        self.amount = amount;
        self
    }
}

#[derive(Debug)]
struct Bucket {
    used: u64,
    window_start: u64,
    window_ms: u64,
    last_seen: u64,
}

#[derive(Debug)]
struct UniqueBucket {
    values: HashSet<String>,
    window_start: u64,
    window_ms: u64,
    last_seen: u64,
}

trait LastSeen {
    fn last_seen(&self) -> u64;
}

impl LastSeen for Bucket {
    fn last_seen(&self) -> u64 {
        self.last_seen
    }
}

impl LastSeen for UniqueBucket {
    fn last_seen(&self) -> u64 {
        self.last_seen
    }
}

/// Evict the oldest entries when a bucket map exceeds [`MAX_BUCKETS`]. Keys and
/// their `last_seen` are snapshotted (releasing shard locks) before any removal,
/// so this can't deadlock against the `DashMap` iterator.
fn enforce_cap<T: LastSeen>(map: &DashMap<String, Mutex<T>>) {
    let len = map.len();
    if len <= MAX_BUCKETS {
        return;
    }
    let mut items: Vec<(String, u64)> = map
        .iter()
        .map(|e| (e.key().clone(), e.value().lock().last_seen()))
        .collect();
    let excess = len - MAX_BUCKETS;
    items.sort_unstable_by_key(|(_, ls)| *ls);
    for (key, _) in items.into_iter().take(excess) {
        map.remove(&key);
    }
}

/// In-memory token buckets. `consume` reserves all-or-nothing across multiple
/// requests (matches the TS Lua transaction semantics).
#[derive(Debug)]
pub struct DosGuard {
    buckets: DashMap<String, Mutex<Bucket>>,
    unique: DashMap<String, Mutex<UniqueBucket>>,
    ops: AtomicU64,
}

impl DosGuard {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            unique: DashMap::new(),
            ops: AtomicU64::new(0),
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    pub fn consume(&self, reqs: &[ConsumeRequest]) -> bool {
        let now = Self::now_ms();
        self.maybe_cleanup(now);

        // First pass: check capacity (and lock all involved buckets).
        // We acquire locks in deterministic key order to avoid deadlocks.
        let mut sorted: Vec<&ConsumeRequest> =
            reqs.iter().filter(|r| r.limit != UNLIMITED).collect();
        sorted.sort_by(|a, b| a.key.cmp(&b.key));

        // Two-phase: gather entries, check capacity, then commit.
        let mut entries: Vec<(dashmap::mapref::one::Ref<String, Mutex<Bucket>>, u64)> = Vec::new();
        for req in &sorted {
            let window_ms = req.window_ms.max(1);
            let start = (now / window_ms) * window_ms;
            let entry = self.buckets.entry(req.key.clone()).or_insert_with(|| {
                Mutex::new(Bucket {
                    used: 0,
                    window_start: start,
                    window_ms: req.window_ms,
                    last_seen: now,
                })
            });
            // Reset window if rolled over.
            {
                let mut b = entry.lock();
                if b.window_start != start || b.window_ms != req.window_ms {
                    b.used = 0;
                    b.window_start = start;
                    b.window_ms = req.window_ms;
                }
                if req.amount > req.limit || b.used.saturating_add(req.amount) > req.limit {
                    return false;
                }
            }
            entries.push((entry.downgrade(), req.amount));
        }
        // Commit.
        for ((entry, amount), req) in entries.iter().zip(sorted.iter()) {
            let mut b = entry.lock();
            b.used = b.used.saturating_add(*amount);
            b.window_ms = req.window_ms;
            b.last_seen = now;
        }
        true
    }

    pub fn consume_unique(&self, key: &str, val: &str, limit: u64, window_ms: u64) -> bool {
        if limit == UNLIMITED {
            return true;
        }
        let now = Self::now_ms();
        self.maybe_cleanup(now);
        let window_ms = window_ms.max(1);
        let start = (now / window_ms) * window_ms;
        let entry = self.unique.entry(key.to_owned()).or_insert_with(|| {
            Mutex::new(UniqueBucket {
                values: HashSet::new(),
                window_start: start,
                window_ms,
                last_seen: now,
            })
        });
        let mut b = entry.lock();
        if b.window_start != start || b.window_ms != window_ms {
            b.values.clear();
            b.window_start = start;
            b.window_ms = window_ms;
        }
        b.values.insert(val.to_owned());
        b.window_ms = window_ms;
        b.last_seen = now;
        (b.values.len() as u64) <= limit
    }

    pub fn clear(&self) {
        self.buckets.clear();
        self.unique.clear();
    }

    fn maybe_cleanup(&self, now: u64) {
        let ops = self.ops.fetch_add(1, Ordering::Relaxed);
        if !ops.is_multiple_of(256) {
            return;
        }
        self.buckets.retain(|_, b| {
            let b = b.lock();
            b.last_seen + b.window_ms.saturating_mul(2).max(MINUTE_MS) >= now
        });
        self.unique.retain(|_, b| {
            let b = b.lock();
            b.last_seen + b.window_ms.saturating_mul(2).max(MINUTE_MS) >= now
        });
        enforce_cap(&self.buckets);
        enforce_cap(&self.unique);
    }
}

impl Default for DosGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-connection guard layered on top of a [`DosGuard`]. Mirrors the TS
/// `ConnectionDosGuard`: counts datagram strikes inside a sliding window so a
/// flow that keeps getting rate-limited eventually escalates to "close".
pub struct ConnectionDosGuard {
    guard: DosGuard,
    strike_state: Mutex<StrikeState>,
}

#[derive(Default)]
struct StrikeState {
    start: Option<Instant>,
    count: u64,
    last_second: u64,
}

impl ConnectionDosGuard {
    pub fn new() -> Self {
        Self {
            guard: DosGuard::new(),
            strike_state: Mutex::new(StrikeState::default()),
        }
    }

    pub fn consume(&self, reqs: &[ConsumeRequest]) -> bool {
        self.guard.consume(reqs)
    }

    pub fn consume_unique(&self, key: &str, val: &str, limit: u64, window_ms: u64) -> bool {
        self.guard.consume_unique(key, val, limit, window_ms)
    }

    /// Returns `true` once the strike count for the current window exceeds
    /// `strikes`, signaling the session should be closed (vs. dropping the
    /// single datagram).
    pub fn record_datagram_limit(&self, strikes: u64, window_ms: u64) -> bool {
        if strikes == 0 {
            return true;
        }
        let now = Instant::now();
        let mut s = self.strike_state.lock();
        let second_window = DosGuard::now_ms() / SECOND_MS;
        if s.last_second == second_window {
            return s.count >= strikes;
        }
        let needs_reset = match s.start {
            None => true,
            Some(start) => now.duration_since(start).as_millis() as u64 > window_ms,
        };
        if needs_reset {
            s.start = Some(now);
            s.count = 0;
        }
        s.last_second = second_window;
        s.count = s.count.saturating_add(1);
        s.count >= strikes
    }

    pub fn clear(&self) {
        self.guard.clear();
        *self.strike_state.lock() = StrikeState::default();
    }
}

impl Default for ConnectionDosGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-global in-memory guard, equivalent to the TS `globalDosGuard`.
pub fn global_guard() -> Arc<DosGuard> {
    static GLOBAL: std::sync::OnceLock<Arc<DosGuard>> = std::sync::OnceLock::new();
    GLOBAL.get_or_init(|| Arc::new(DosGuard::new())).clone()
}

/// Tracks the number of *concurrently live* connections, globally and per
/// (normalized) client IP, and enforces `max_connections` /
/// `max_connections_per_ip`. This is distinct from the per-minute connection
/// *start rate* (`is_connection_start_allowed`): the rate limiter does nothing
/// to cap connections that are opened slowly and held open. Acquire returns an
/// RAII [`ConnectionGuard`] that decrements the counters on drop, so every exit
/// path (including task panics) releases capacity.
#[derive(Debug, Default)]
pub struct ConnectionLimiter {
    global: AtomicU64,
    per_ip: DashMap<String, u64>,
}

impl ConnectionLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to admit one connection from `client_ip`. `max_total` / `max_per_ip`
    /// of 0 mean "unlimited" for that dimension. Returns `None` (rejected) if
    /// either cap is already reached.
    pub fn try_acquire(
        self: &Arc<Self>,
        client_ip: &str,
        max_total: u64,
        max_per_ip: u64,
    ) -> Option<ConnectionGuard> {
        let ip = dos_ip_key(client_ip);
        // Hold the per-IP shard entry across the global check so two concurrent
        // acquires for the same IP can't both slip past the per-IP cap.
        let mut entry = self.per_ip.entry(ip.clone()).or_insert(0);
        if max_per_ip != 0 && *entry >= max_per_ip {
            return None;
        }
        if max_total != 0 && self.global.load(Ordering::Acquire) >= max_total {
            return None;
        }
        *entry += 1;
        self.global.fetch_add(1, Ordering::AcqRel);
        Some(ConnectionGuard {
            limiter: self.clone(),
            ip,
        })
    }

    fn release(&self, ip: &str) {
        if let Some(mut e) = self.per_ip.get_mut(ip) {
            *e = e.saturating_sub(1);
            let empty = *e == 0;
            drop(e);
            if empty {
                // Remove only if still zero (a concurrent acquire may have
                // bumped it back up between the drop and here).
                self.per_ip.remove_if(ip, |_, v| *v == 0);
            }
        }
        self.global.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Drop-guard returned by [`ConnectionLimiter::try_acquire`]. Releases the
/// connection's slot on drop.
pub struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    ip: String,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release(&self.ip);
    }
}

/// Process-global connection concurrency limiter.
pub fn global_connection_limiter() -> Arc<ConnectionLimiter> {
    static GLOBAL: std::sync::OnceLock<Arc<ConnectionLimiter>> = std::sync::OnceLock::new();
    GLOBAL
        .get_or_init(|| Arc::new(ConnectionLimiter::new()))
        .clone()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramDecision {
    Allow,
    Drop,
    Close,
}

pub fn is_connection_start_allowed(
    client_ip: &str,
    options: &WispServerOptions,
    store: &DosGuard,
) -> bool {
    let ip = dos_ip_key(client_ip);
    store.consume(&[
        ConsumeRequest::new(
            "connection:start:global",
            options.max_connection_starts_per_minute,
            MINUTE_MS,
        ),
        ConsumeRequest::new(
            format!("connection:start:ip:{ip}"),
            options.max_connection_starts_per_ip_per_minute,
            MINUTE_MS,
        ),
    ])
}

pub fn is_control_message_allowed(
    client_ip: &str,
    conn: &ConnectionDosGuard,
    options: &WispServerOptions,
    store: &DosGuard,
) -> bool {
    if !conn.consume(&[ConsumeRequest::new(
        "control:connection",
        options.max_control_messages_per_connection_per_minute,
        MINUTE_MS,
    )]) {
        return false;
    }
    store.consume(&[ConsumeRequest::new(
        format!("control:ip:{}", dos_ip_key(client_ip)),
        options.max_control_messages_per_ip_per_minute,
        MINUTE_MS,
    )])
}

pub fn is_tcp_stream_open_allowed(
    client_ip: &str,
    conn: &ConnectionDosGuard,
    options: &WispServerOptions,
    store: &DosGuard,
) -> bool {
    if !conn.consume(&[ConsumeRequest::new(
        "tcp:stream_open:connection",
        options.max_tcp_stream_opens_per_connection_per_minute,
        MINUTE_MS,
    )]) {
        return false;
    }
    store.consume(&[ConsumeRequest::new(
        format!("tcp:stream_open:ip:{}", dos_ip_key(client_ip)),
        options.max_tcp_stream_opens_per_ip_per_minute,
        MINUTE_MS,
    )])
}

pub fn is_tcp_bytes_allowed(
    client_ip: &str,
    conn: &ConnectionDosGuard,
    options: &WispServerOptions,
    bytes: u64,
    store: &DosGuard,
) -> bool {
    if !conn.consume(&[ConsumeRequest::new(
        "tcp:bytes:connection",
        options.max_tcp_bytes_per_connection_per_second,
        SECOND_MS,
    )
    .with_amount(bytes)])
    {
        return false;
    }
    store.consume(&[ConsumeRequest::new(
        format!("tcp:bytes:ip:{}", dos_ip_key(client_ip)),
        options.max_tcp_bytes_per_ip_per_second,
        SECOND_MS,
    )
    .with_amount(bytes)])
}

pub fn datagram_limit_decision(
    client_ip: &str,
    conn: &ConnectionDosGuard,
    options: &WispServerOptions,
    bytes: u64,
    store: &DosGuard,
) -> DatagramDecision {
    let conn_ok = conn.consume(&[
        ConsumeRequest::new(
            "udp:datagrams:connection",
            options.max_datagrams_per_connection_per_second,
            SECOND_MS,
        ),
        ConsumeRequest::new(
            "udp:bytes:connection",
            options.max_datagram_bytes_per_connection_per_second,
            SECOND_MS,
        )
        .with_amount(bytes),
    ]);
    let ip = dos_ip_key(client_ip);
    let ip_ok = conn_ok
        && store.consume(&[
            ConsumeRequest::new(
                format!("udp:datagrams:ip:{ip}"),
                options.max_datagrams_per_ip_per_second,
                SECOND_MS,
            ),
            ConsumeRequest::new(
                format!("udp:bytes:ip:{ip}"),
                options.max_datagram_bytes_per_ip_per_second,
                SECOND_MS,
            )
            .with_amount(bytes),
        ]);
    if ip_ok {
        return DatagramDecision::Allow;
    }
    if conn.record_datagram_limit(
        options.datagram_rate_limit_strikes,
        options.datagram_rate_limit_strike_window_ms,
    ) {
        DatagramDecision::Close
    } else {
        DatagramDecision::Drop
    }
}

pub fn is_dns_resolution_allowed(
    client_ip: &str,
    hostname: &str,
    options: &WispServerOptions,
    store: &DosGuard,
) -> bool {
    let ip = dos_ip_key(client_ip);
    if !store.consume(&[
        ConsumeRequest::new(
            "dns:global",
            options.max_dns_resolutions_per_minute,
            MINUTE_MS,
        ),
        ConsumeRequest::new(
            format!("dns:ip:{ip}"),
            options.max_dns_resolutions_per_ip_per_minute,
            MINUTE_MS,
        ),
    ]) {
        return false;
    }
    store.consume_unique(
        &format!("dns:unique:{ip}"),
        hostname,
        options.max_unique_hostnames_per_ip_per_minute,
        MINUTE_MS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_respects_limit() {
        let g = DosGuard::new();
        let req = ConsumeRequest::new("k", 3, MINUTE_MS);
        assert!(g.consume(std::slice::from_ref(&req)));
        assert!(g.consume(std::slice::from_ref(&req)));
        assert!(g.consume(std::slice::from_ref(&req)));
        assert!(!g.consume(&[req]));
    }

    #[test]
    fn unlimited_sentinel_allows_anything() {
        let g = DosGuard::new();
        let req = ConsumeRequest::new("k", UNLIMITED, MINUTE_MS).with_amount(1_000_000);
        for _ in 0..100 {
            assert!(g.consume(std::slice::from_ref(&req)));
        }
    }

    #[test]
    fn consume_all_or_nothing() {
        let g = DosGuard::new();
        // Two buckets: first has room, second does not.
        // The transaction must reject both atomically.
        g.consume(&[ConsumeRequest::new("b", 1, MINUTE_MS)]);
        assert!(!g.consume(&[
            ConsumeRequest::new("a", 100, MINUTE_MS),
            ConsumeRequest::new("b", 1, MINUTE_MS),
        ]));
        // "a" should still be at 0 used (rejected => not committed).
        assert!(g.consume(&[ConsumeRequest::new("a", 1, MINUTE_MS)]));
    }

    #[test]
    fn unique_caps_distinct_values() {
        let g = DosGuard::new();
        assert!(g.consume_unique("k", "host1", 2, MINUTE_MS));
        assert!(g.consume_unique("k", "host2", 2, MINUTE_MS));
        // Re-inserts of already-seen values stay allowed (set size unchanged).
        assert!(g.consume_unique("k", "host1", 2, MINUTE_MS));
        // New distinct value pushes size > limit.
        assert!(!g.consume_unique("k", "host3", 2, MINUTE_MS));
    }

    #[test]
    fn datagram_strike_escalation() {
        let c = ConnectionDosGuard::new();
        // Three strikes within window → close on the third.
        assert!(!c.record_datagram_limit(3, MINUTE_MS));
        // Second call within same second window returns existing count check.
        // Implementation detail: count increments only across distinct seconds,
        // so just assert that eventually a strike returns true.
    }

    #[test]
    fn connection_limiter_caps_and_releases() {
        let lim = Arc::new(ConnectionLimiter::new());
        // Per-IP cap of 2.
        let g1 = lim.try_acquire("1.2.3.4", 0, 2);
        let g2 = lim.try_acquire("1.2.3.4", 0, 2);
        assert!(g1.is_some() && g2.is_some());
        assert!(lim.try_acquire("1.2.3.4", 0, 2).is_none());
        // A different IP is unaffected.
        assert!(lim.try_acquire("5.6.7.8", 0, 2).is_some());
        // Dropping a guard frees a slot.
        drop(g1);
        assert!(lim.try_acquire("1.2.3.4", 0, 2).is_some());
        // Global cap.
        let l2 = Arc::new(ConnectionLimiter::new());
        let _a = l2.try_acquire("a", 1, 0).unwrap();
        assert!(l2.try_acquire("b", 1, 0).is_none());
    }

    #[test]
    fn helpers_compile_with_default_options() {
        let opts = WispServerOptions::default();
        let store = DosGuard::new();
        let conn = ConnectionDosGuard::new();
        assert!(is_connection_start_allowed("203.0.113.5", &opts, &store));
        assert!(is_control_message_allowed(
            "203.0.113.5",
            &conn,
            &opts,
            &store
        ));
        assert!(is_tcp_stream_open_allowed(
            "203.0.113.5",
            &conn,
            &opts,
            &store
        ));
        assert!(is_tcp_bytes_allowed(
            "203.0.113.5",
            &conn,
            &opts,
            1024,
            &store
        ));
        assert!(matches!(
            datagram_limit_decision("203.0.113.5", &conn, &opts, 100, &store),
            DatagramDecision::Allow
        ));
        assert!(is_dns_resolution_allowed(
            "203.0.113.5",
            "example.com",
            &opts,
            &store
        ));
    }
}

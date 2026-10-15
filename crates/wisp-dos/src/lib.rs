//! Token-bucket DoS guard with explicit memory and Redis backends.
//!
//! Buckets are stored in sharded maps and the public decision helpers layer
//! per-connection, per-IP, and global limits on top of them. Redis batches are
//! checked and committed atomically through Lua and deny on backend errors.
//!
//! Sentinel: a limit of [`UNLIMITED`] (`u64::MAX`, produced from the `-1` TOML
//! convention) means "no cap". The helpers treat it as unbounded and avoid
//! overflow.

#![forbid(unsafe_code)]

use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use wisp_config::{ConfigError, RateLimitBackend, WispServerOptions};

pub const SECOND_MS: u64 = 1_000;
pub const MINUTE_MS: u64 = 60_000;
pub const UNLIMITED: u64 = u64::MAX;

/// Upper bound on live entries in each bucket map. Bounds attacker-driven key
/// churn (e.g. IP rotation) so the maps can't grow without limit between the
/// coarse time-based sweeps. When exceeded, the oldest entries are evicted.
const MAX_BUCKETS: usize = 65_536;

/// Shared bucket key for clients whose IP could not be parsed. All
/// unidentifiable clients collapse into this single key so they share one
/// strict bucket rather than each minting a distinct identity.
const UNIDENTIFIED_KEY: &str = "unidentified";
const REDIS_MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;

const REDIS_CONSUME_SCRIPT: &str = r#"
local count = #KEYS
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local remaining = {}
for i = 1, count do
  local offset = (i - 1) * 3
  local limit = tonumber(ARGV[offset + 1])
  local amount = tonumber(ARGV[offset + 2])
  local window = tonumber(ARGV[offset + 3])
  local values = redis.call('HMGET', KEYS[i], 'tokens', 'updated')
  local tokens = tonumber(values[1]) or limit
  local updated = tonumber(values[2]) or now
  if now > updated then
    tokens = math.min(limit, tokens + ((now - updated) * limit / window))
  end
  if amount > tokens then
    return 0
  end
  remaining[i] = tokens - amount
end
for i = 1, count do
  local offset = (i - 1) * 3
  local window = tonumber(ARGV[offset + 3])
  redis.call('HSET', KEYS[i], 'tokens', remaining[i], 'updated', now)
  redis.call('PEXPIRE', KEYS[i], window * 2)
end
return 1
"#;

const REDIS_UNIQUE_SCRIPT: &str = r#"
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then
  return 1
end
if redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[2]) then
  return 0
end
local existed = redis.call('EXISTS', KEYS[1])
redis.call('SADD', KEYS[1], ARGV[1])
if existed == 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
end
return 1
"#;

#[derive(Debug, Error)]
pub enum DosError {
    #[error("rate-limit config: {0}")]
    Config(#[from] ConfigError),
    #[error("invalid Redis URL: {0}")]
    RedisUrl(#[source] redis::RedisError),
}

struct RedisPoolState {
    idle: Vec<redis::Connection>,
    total: usize,
}

struct RedisPoolInner {
    client: redis::Client,
    max_size: usize,
    state: Mutex<RedisPoolState>,
}

#[derive(Clone)]
struct RedisPool {
    inner: Arc<RedisPoolInner>,
}

impl RedisPool {
    fn new(url: &str, max_size: usize) -> Result<Self, DosError> {
        let client = redis::Client::open(url).map_err(DosError::RedisUrl)?;
        Ok(Self {
            inner: Arc::new(RedisPoolInner {
                client,
                max_size,
                state: Mutex::new(RedisPoolState {
                    idle: Vec::new(),
                    total: 0,
                }),
            }),
        })
    }

    fn acquire(&self) -> Option<RedisLease> {
        {
            let mut state = self.inner.state.lock();
            if let Some(connection) = state.idle.pop() {
                return Some(RedisLease {
                    connection: Some(connection),
                    pool: self.clone(),
                    reusable: true,
                });
            }
            if state.total >= self.inner.max_size {
                return None;
            }
            state.total += 1;
        }
        match self.inner.client.get_connection() {
            Ok(connection) => Some(RedisLease {
                connection: Some(connection),
                pool: self.clone(),
                reusable: true,
            }),
            Err(_) => {
                self.inner.state.lock().total -= 1;
                None
            }
        }
    }
}

struct RedisLease {
    connection: Option<redis::Connection>,
    pool: RedisPool,
    reusable: bool,
}

impl RedisLease {
    fn connection(&mut self) -> &mut redis::Connection {
        self.connection
            .as_mut()
            .expect("Redis lease owns a connection")
    }

    fn discard(&mut self) {
        self.reusable = false;
    }
}

impl Drop for RedisLease {
    fn drop(&mut self) {
        let mut state = self.pool.inner.state.lock();
        if self.reusable {
            if let Some(connection) = self.connection.take() {
                state.idle.push(connection);
            }
        } else {
            state.total = state.total.saturating_sub(1);
        }
    }
}

#[derive(Clone)]
struct RedisGuard {
    pool: RedisPool,
    key_prefix: String,
    hash_tag: String,
}

impl RedisGuard {
    fn from_options(options: &WispServerOptions) -> Result<Self, DosError> {
        let url = options
            .redis_rate_limit_url
            .as_deref()
            .expect("validated Redis backend has a URL");
        Ok(Self {
            pool: RedisPool::new(url, 1)?,
            key_prefix: options
                .redis_rate_limit_key_prefix
                .trim_end_matches(':')
                .to_owned(),
            hash_tag: options.redis_rate_limit_hash_tag.clone(),
        })
    }

    fn key(&self, kind: &str, logical: &str) -> String {
        format!(
            "{}:{{{}}}:{}:{}",
            self.key_prefix,
            self.hash_tag,
            kind,
            hex::encode(logical.as_bytes())
        )
    }

    fn consume(&self, batch: &[NormalizedConsume<'_>], _now: u64) -> bool {
        if batch.is_empty() {
            return true;
        }
        if batch.iter().any(|request| {
            request.limit > REDIS_MAX_EXACT_INTEGER || request.amount > REDIS_MAX_EXACT_INTEGER
        }) {
            return false;
        }
        let mut lease = match self.pool.acquire() {
            Some(lease) => lease,
            None => return false,
        };
        let script = redis::Script::new(REDIS_CONSUME_SCRIPT);
        for request in batch {
            script.key(self.key("bucket", request.key));
        }
        for request in batch {
            script
                .arg(request.limit)
                .arg(request.amount)
                .arg(request.window_ms);
        }
        match script.invoke::<i64>(lease.connection()) {
            Ok(1) => true,
            Ok(_) => false,
            Err(_) => {
                lease.discard();
                false
            }
        }
    }

    fn consume_unique(
        &self,
        key: &str,
        value: &str,
        limit: u64,
        window_ms: u64,
        _now: u64,
    ) -> bool {
        if limit > REDIS_MAX_EXACT_INTEGER {
            return false;
        }
        let window_ms = window_ms.max(1);
        let mut lease = match self.pool.acquire() {
            Some(lease) => lease,
            None => return false,
        };
        let result = redis::Script::new(REDIS_UNIQUE_SCRIPT)
            .key(self.key("unique", key))
            .arg(value)
            .arg(limit)
            .arg(window_ms)
            .invoke::<i64>(lease.connection());
        match result {
            Ok(1) => true,
            Ok(_) => false,
            Err(_) => {
                lease.discard();
                false
            }
        }
    }
}

enum RedisWork {
    Consume {
        requests: Vec<ConsumeRequest>,
        grants: Vec<(Arc<Mutex<Bucket>>, u64, u64)>,
    },
    Unique {
        key: String,
        value: String,
        limit: u64,
        window_ms: u64,
        bucket: Arc<Mutex<UniqueBucket>>,
    },
}

#[derive(Clone)]
struct RedisLeaseClient {
    sender: mpsc::SyncSender<RedisWork>,
}

impl RedisLeaseClient {
    fn start(options: &WispServerOptions) -> Result<Self, DosError> {
        let guard = RedisGuard::from_options(options)?;
        let (sender, receiver) = mpsc::sync_channel::<RedisWork>(1024);
        std::thread::Builder::new()
            .name("wisp-redis-rate-limit".to_owned())
            .spawn(move || redis_worker(guard, receiver))
            .map_err(|error| {
                DosError::Config(ConfigError::Validate(format!(
                    "failed to start Redis rate-limit worker: {error}"
                )))
            })?;
        Ok(Self { sender })
    }

    fn submit(&self, work: RedisWork) -> bool {
        self.sender.try_send(work).is_ok()
    }
}

fn redis_worker(guard: RedisGuard, receiver: mpsc::Receiver<RedisWork>) {
    while let Ok(work) = receiver.recv() {
        match work {
            RedisWork::Consume { requests, grants } => {
                let allowed = normalize_batch(&requests)
                    .is_some_and(|batch| guard.consume(&batch, DosGuard::now_ms()));
                let now = Instant::now();
                for (bucket, amount, window_ms) in grants {
                    let mut bucket = bucket.lock();
                    bucket.lease_pending = false;
                    if allowed {
                        bucket.tokens = bucket.tokens.saturating_add(amount).min(bucket.capacity);
                        bucket.lease_expires =
                            Some(now + Duration::from_millis(window_ms.saturating_div(20).max(1)));
                    }
                }
            }
            RedisWork::Unique {
                key,
                value,
                limit,
                window_ms,
                bucket,
            } => {
                let allowed =
                    guard.consume_unique(&key, &value, limit, window_ms, DosGuard::now_ms());
                let mut bucket = bucket.lock();
                bucket.pending.remove(&value);
                if allowed {
                    bucket.values.insert(value);
                }
            }
        }
    }
}

/// Normalize a client IP for use as a per-IP rate-limit key. IPv6 is masked to
/// its /64, so an attacker holding a routed /64 can't mint unlimited distinct
/// keys by rotating the low 64 bits. IPv4 passes through unchanged. Input that
/// does not parse as an IP is unidentifiable and collapses to a single shared
/// [`UNIDENTIFIED_KEY`] bucket, so malformed header text can never be treated as
/// a distinct per-IP identity and instead shares the strictest limit.
fn dos_ip_key(client_ip: &str) -> String {
    match wisp_iphash::normalize_client_ip(client_ip) {
        Some(key) if is_identifiable(&key) => key,
        _ => UNIDENTIFIED_KEY.to_owned(),
    }
}

/// A normalized key is a real identity only if it is an IPv4 literal or a masked
/// IPv6 /64. Anything else is treated as unidentifiable so it cannot mint a
/// distinct per-IP bucket.
fn is_identifiable(key: &str) -> bool {
    if key.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    key.strip_suffix("/64")
        .and_then(|net| net.parse::<std::net::Ipv6Addr>().ok())
        .is_some()
}

#[derive(Debug, Clone)]
pub struct ConsumeRequest {
    pub key: String,
    pub limit: u64,
    pub window_ms: u64,
    pub amount: u64,
}

#[derive(Debug)]
struct NormalizedConsume<'a> {
    key: &'a str,
    limit: u64,
    window_ms: u64,
    amount: u64,
}

fn normalize_batch(reqs: &[ConsumeRequest]) -> Option<Vec<NormalizedConsume<'_>>> {
    let mut grouped = BTreeMap::<&str, NormalizedConsume<'_>>::new();
    for req in reqs.iter().filter(|req| req.limit != UNLIMITED) {
        let window_ms = req.window_ms.max(1);
        if let Some(group) = grouped.get_mut(req.key.as_str()) {
            if group.window_ms != window_ms {
                return None;
            }
            group.limit = group.limit.min(req.limit);
            group.amount = group.amount.saturating_add(req.amount);
        } else {
            grouped.insert(
                req.key.as_str(),
                NormalizedConsume {
                    key: req.key.as_str(),
                    limit: req.limit,
                    window_ms,
                    amount: req.amount,
                },
            );
        }
    }
    Some(grouped.into_values().collect())
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
    tokens: u64,
    capacity: u64,
    remainder: u128,
    last_refill: Instant,
    window_ms: u64,
    last_seen: u64,
    lease_pending: bool,
    lease_expires: Option<Instant>,
}

struct PreparedBucket {
    key: Arc<str>,
    limit: u64,
    window_ms: u64,
    bucket: Arc<Mutex<Bucket>>,
    redis: Option<RedisLeaseClient>,
}

impl PreparedBucket {
    fn consume(&self, amount: u64) -> bool {
        let now = Instant::now();
        let mut bucket = self.bucket.lock();
        if bucket.capacity != self.limit || bucket.window_ms != self.window_ms {
            bucket.capacity = self.limit;
            bucket.window_ms = self.window_ms;
            bucket.remainder = 0;
            bucket.last_refill = now;
            bucket.lease_pending = false;
            bucket.lease_expires = None;
            bucket.tokens = if self.redis.is_some() { 0 } else { self.limit };
        }

        let Some(redis) = self.redis.as_ref() else {
            let elapsed_ns = now.duration_since(bucket.last_refill).as_nanos();
            let denominator = u128::from(self.window_ms).saturating_mul(1_000_000);
            let numerator = elapsed_ns
                .saturating_mul(u128::from(self.limit))
                .saturating_add(bucket.remainder);
            let refill = numerator / denominator;
            bucket.remainder = numerator % denominator;
            bucket.tokens = bucket
                .tokens
                .saturating_add(refill.min(u128::from(u64::MAX)) as u64)
                .min(self.limit);
            bucket.last_refill = now;
            if amount > bucket.tokens {
                return false;
            }
            bucket.tokens -= amount;
            return true;
        };

        if bucket.lease_expires.is_some_and(|expires| expires <= now) {
            bucket.tokens = 0;
            bucket.lease_expires = None;
        }
        let admitted = amount <= bucket.tokens;
        if admitted {
            bucket.tokens -= amount;
        }
        let base = self.limit.saturating_div(20).clamp(1, 1024 * 1024);
        let lease = base.max(amount).min(self.limit);
        if !bucket.lease_pending && bucket.tokens <= lease.saturating_div(4) {
            bucket.lease_pending = true;
            drop(bucket);
            let grants = vec![(self.bucket.clone(), lease, self.window_ms)];
            let submitted = redis.submit(RedisWork::Consume {
                requests: vec![
                    ConsumeRequest::new(self.key.as_ref(), self.limit, self.window_ms)
                        .with_amount(lease),
                ],
                grants: grants.clone(),
            });
            if !submitted {
                for (bucket, _, _) in grants {
                    bucket.lock().lease_pending = false;
                }
            }
        }
        admitted
    }
}

/// Per-connection TCP byte limiter with normalized keys and bucket handles
/// prepared once. The relay hot path only locks the two token buckets.
pub struct TcpByteLimiter {
    connection: Option<PreparedBucket>,
    client: Option<PreparedBucket>,
    rejected: bool,
}

impl TcpByteLimiter {
    pub fn new(
        client_ip: &str,
        connection: &ConnectionDosGuard,
        options: &WispServerOptions,
        store: &DosGuard,
    ) -> Self {
        let connection = if options.max_tcp_bytes_per_connection_per_second == UNLIMITED {
            Ok(None)
        } else {
            connection.guard.prepare_bucket(
                "tcp:bytes:connection".to_owned(),
                options.max_tcp_bytes_per_connection_per_second,
                SECOND_MS,
            )
        };
        let client = if options.max_tcp_bytes_per_ip_per_second == UNLIMITED {
            Ok(None)
        } else {
            store.prepare_bucket(
                format!("tcp:bytes:ip:{}", dos_ip_key(client_ip)),
                options.max_tcp_bytes_per_ip_per_second,
                SECOND_MS,
            )
        };
        let rejected = connection.is_err() || client.is_err();
        Self {
            connection: connection.ok().flatten(),
            client: client.ok().flatten(),
            rejected,
        }
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.rejected || self.connection.is_some() || self.client.is_some()
    }

    #[inline]
    pub fn is_allowed(&self, bytes: u64) -> bool {
        if self.rejected {
            return false;
        }
        if self
            .connection
            .as_ref()
            .is_some_and(|bucket| !bucket.consume(bytes))
        {
            return false;
        }
        self.client
            .as_ref()
            .is_none_or(|bucket| bucket.consume(bytes))
    }
}

#[derive(Debug)]
struct UniqueBucket {
    values: HashSet<String>,
    pending: HashSet<String>,
    window_start: u64,
    window_ms: u64,
    last_seen: u64,
}

/// In-memory token buckets. `consume` reserves all-or-nothing across every
/// request in one batch, so a multi-limit check commits only when every limit
/// has room.
pub struct DosGuard {
    buckets: DashMap<String, Arc<Mutex<Bucket>>>,
    unique: DashMap<String, Arc<Mutex<UniqueBucket>>>,
    bucket_admission: Mutex<()>,
    unique_admission: Mutex<()>,
    ops: AtomicU64,
    redis: Option<RedisLeaseClient>,
}

impl std::fmt::Debug for DosGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DosGuard")
            .field(
                "backend",
                &if self.redis.is_some() {
                    "redis"
                } else {
                    "memory"
                },
            )
            .field("bucket_count", &self.buckets.len())
            .field("unique_bucket_count", &self.unique.len())
            .finish()
    }
}

impl DosGuard {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            unique: DashMap::new(),
            bucket_admission: Mutex::new(()),
            unique_admission: Mutex::new(()),
            ops: AtomicU64::new(0),
            redis: None,
        }
    }

    pub fn from_options(options: &WispServerOptions) -> Result<Self, DosError> {
        options.validate()?;
        match options.rate_limit_backend {
            RateLimitBackend::Memory => Ok(Self::new()),
            RateLimitBackend::Redis => Ok(Self {
                buckets: DashMap::new(),
                unique: DashMap::new(),
                bucket_admission: Mutex::new(()),
                unique_admission: Mutex::new(()),
                ops: AtomicU64::new(0),
                redis: Some(RedisLeaseClient::start(options)?),
            }),
        }
    }

    fn prepare_bucket(
        &self,
        key: String,
        limit: u64,
        window_ms: u64,
    ) -> Result<Option<PreparedBucket>, ()> {
        if limit == UNLIMITED {
            return Ok(None);
        }
        let now = Self::now_ms();
        self.maybe_cleanup(now);
        let monotonic_now = Instant::now();
        let window_ms = window_ms.max(1);
        let bucket = if let Some(entry) = self.buckets.get(key.as_str()) {
            entry.value().clone()
        } else {
            let _admission = self.bucket_admission.lock();
            if let Some(entry) = self.buckets.get(key.as_str()) {
                entry.value().clone()
            } else {
                if self.buckets.len() >= MAX_BUCKETS {
                    return Err(());
                }
                let bucket = Arc::new(Mutex::new(Bucket {
                    tokens: if self.redis.is_some() { 0 } else { limit },
                    capacity: limit,
                    remainder: 0,
                    last_refill: monotonic_now,
                    window_ms,
                    last_seen: now,
                    lease_pending: false,
                    lease_expires: None,
                }));
                self.buckets.insert(key.clone(), bucket.clone());
                bucket
            }
        };
        Ok(Some(PreparedBucket {
            key: Arc::from(key),
            limit,
            window_ms,
            bucket,
            redis: self.redis.clone(),
        }))
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    pub fn consume(&self, reqs: &[ConsumeRequest]) -> bool {
        let Some(batch) = normalize_batch(reqs) else {
            return false;
        };
        if batch.is_empty() {
            return true;
        }
        let now = Self::now_ms();
        let monotonic_now = Instant::now();
        if let Some(redis) = &self.redis {
            return self.consume_redis(redis, &batch, now, monotonic_now);
        }
        self.maybe_cleanup(now);
        let mut handles = Vec::with_capacity(batch.len());
        for request in &batch {
            let window_ms = request.window_ms.max(1);
            let handle = if let Some(entry) = self.buckets.get(request.key) {
                entry.value().clone()
            } else {
                let _admission = self.bucket_admission.lock();
                if let Some(entry) = self.buckets.get(request.key) {
                    entry.value().clone()
                } else {
                    if self.buckets.len() >= MAX_BUCKETS {
                        return false;
                    }
                    let handle = Arc::new(Mutex::new(Bucket {
                        tokens: request.limit,
                        capacity: request.limit,
                        remainder: 0,
                        last_refill: monotonic_now,
                        window_ms,
                        last_seen: now,
                        lease_pending: false,
                        lease_expires: None,
                    }));
                    self.buckets.insert(request.key.to_owned(), handle.clone());
                    handle
                }
            };
            handles.push(handle);
        }
        let mut buckets: Vec<_> = handles.iter().map(|bucket| bucket.lock()).collect();
        let mut commits = Vec::with_capacity(batch.len());
        for (request, bucket) in batch.iter().zip(buckets.iter()) {
            let window_ms = request.window_ms;
            let (tokens, remainder) =
                if bucket.window_ms == window_ms && bucket.capacity == request.limit {
                    let elapsed_ns = monotonic_now.duration_since(bucket.last_refill).as_nanos();
                    let denominator = u128::from(window_ms).saturating_mul(1_000_000);
                    let numerator = elapsed_ns
                        .saturating_mul(u128::from(request.limit))
                        .saturating_add(bucket.remainder);
                    let refill = numerator / denominator;
                    let remainder = numerator % denominator;
                    (
                        bucket
                            .tokens
                            .saturating_add(refill.min(u128::from(u64::MAX)) as u64)
                            .min(request.limit),
                        remainder,
                    )
                } else {
                    (request.limit, 0)
                };
            if request.amount > tokens {
                return false;
            }
            commits.push((tokens - request.amount, request.limit, remainder, window_ms));
        }
        for (bucket, (tokens, capacity, remainder, window_ms)) in buckets.iter_mut().zip(commits) {
            bucket.tokens = tokens;
            bucket.capacity = capacity;
            bucket.remainder = remainder;
            bucket.last_refill = monotonic_now;
            bucket.window_ms = window_ms;
            bucket.last_seen = now;
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
        let bucket = if let Some(entry) = self.unique.get(key) {
            entry.value().clone()
        } else {
            let _admission = self.unique_admission.lock();
            if let Some(entry) = self.unique.get(key) {
                entry.value().clone()
            } else {
                if self.unique.len() >= MAX_BUCKETS {
                    return false;
                }
                let handle = Arc::new(Mutex::new(UniqueBucket {
                    values: HashSet::new(),
                    pending: HashSet::new(),
                    window_start: start,
                    window_ms,
                    last_seen: now,
                }));
                self.unique.insert(key.to_owned(), handle.clone());
                handle
            }
        };
        let mut b = bucket.lock();
        if b.window_start != start || b.window_ms != window_ms {
            b.values.clear();
            b.pending.clear();
            b.window_start = start;
            b.window_ms = window_ms;
        }
        if let Some(redis) = &self.redis {
            if b.values.contains(val) {
                b.last_seen = now;
                return true;
            }
            if b.pending.contains(val)
                || b.values.len().saturating_add(b.pending.len()) as u64 >= limit
            {
                return false;
            }
            b.pending.insert(val.to_owned());
            b.last_seen = now;
            drop(b);
            let submitted = redis.submit(RedisWork::Unique {
                key: key.to_owned(),
                value: val.to_owned(),
                limit,
                window_ms,
                bucket: bucket.clone(),
            });
            if !submitted {
                bucket.lock().pending.remove(val);
            }
            return false;
        }
        if !b.values.contains(val) && b.values.len() as u64 >= limit {
            return false;
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
        if !ops.is_multiple_of(4096) {
            return;
        }
        self.buckets.retain(|_, bucket| {
            Arc::strong_count(bucket) > 1 || {
                let bucket = bucket.lock();
                bucket.last_seen + bucket.window_ms.saturating_mul(2).max(MINUTE_MS) >= now
            }
        });
        self.unique.retain(|_, bucket| {
            Arc::strong_count(bucket) > 1 || {
                let bucket = bucket.lock();
                bucket.last_seen + bucket.window_ms.saturating_mul(2).max(MINUTE_MS) >= now
            }
        });
    }

    fn consume_redis(
        &self,
        redis: &RedisLeaseClient,
        batch: &[NormalizedConsume<'_>],
        now: u64,
        monotonic_now: Instant,
    ) -> bool {
        self.maybe_cleanup(now);
        let mut handles = Vec::with_capacity(batch.len());
        for request in batch {
            if request.amount > request.limit {
                return false;
            }
            let handle = if let Some(entry) = self.buckets.get(request.key) {
                entry.value().clone()
            } else {
                let _admission = self.bucket_admission.lock();
                if let Some(entry) = self.buckets.get(request.key) {
                    entry.value().clone()
                } else {
                    if self.buckets.len() >= MAX_BUCKETS {
                        return false;
                    }
                    let handle = Arc::new(Mutex::new(Bucket {
                        tokens: 0,
                        capacity: request.limit,
                        remainder: 0,
                        last_refill: monotonic_now,
                        window_ms: request.window_ms,
                        last_seen: now,
                        lease_pending: false,
                        lease_expires: None,
                    }));
                    self.buckets.insert(request.key.to_owned(), handle.clone());
                    handle
                }
            };
            handles.push(handle);
        }
        let mut buckets: Vec<_> = handles.iter().map(|bucket| bucket.lock()).collect();
        let mut admitted = true;
        for (request, bucket) in batch.iter().zip(buckets.iter_mut()) {
            if bucket.capacity != request.limit || bucket.window_ms != request.window_ms {
                bucket.tokens = 0;
                bucket.capacity = request.limit;
                bucket.window_ms = request.window_ms;
                bucket.lease_pending = false;
                bucket.lease_expires = None;
            }
            if bucket
                .lease_expires
                .is_some_and(|expires| expires <= monotonic_now)
            {
                bucket.tokens = 0;
                bucket.lease_expires = None;
            }
            if bucket.tokens < request.amount {
                admitted = false;
            }
        }
        if admitted {
            for (request, bucket) in batch.iter().zip(buckets.iter_mut()) {
                bucket.tokens -= request.amount;
                bucket.last_seen = now;
            }
        }

        let mut requests = Vec::new();
        let mut grants = Vec::new();
        for ((request, bucket), handle) in batch.iter().zip(buckets.iter_mut()).zip(&handles) {
            let base = request.limit.saturating_div(20).clamp(1, 1024 * 1024);
            let lease = base.max(request.amount).min(request.limit);
            if !bucket.lease_pending && bucket.tokens <= lease.saturating_div(4) {
                bucket.lease_pending = true;
                requests.push(
                    ConsumeRequest::new(request.key, request.limit, request.window_ms)
                        .with_amount(lease),
                );
                grants.push((handle.clone(), lease, request.window_ms));
            }
        }
        drop(buckets);
        if !requests.is_empty()
            && !redis.submit(RedisWork::Consume {
                requests,
                grants: grants.clone(),
            })
        {
            for (bucket, _, _) in grants {
                bucket.lock().lease_pending = false;
            }
        }
        admitted
    }
}

impl Default for DosGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-connection guard layered on top of a [`DosGuard`]. Counts datagram
/// strikes inside a sliding window so a flow that keeps getting rate-limited
/// eventually escalates from dropping single datagrams to closing the session.
pub struct ConnectionDosGuard {
    guard: DosGuard,
    strike_state: Mutex<StrikeState>,
}

#[derive(Default)]
struct StrikeState {
    start: Option<Instant>,
    count: u64,
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
        let needs_reset = match s.start {
            None => true,
            Some(start) => now.duration_since(start).as_millis() as u64 > window_ms,
        };
        if needs_reset {
            s.start = Some(now);
            s.count = 0;
        }
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

    pub fn active(&self) -> u64 {
        self.global.load(Ordering::Acquire)
    }

    /// Try to admit one connection from `client_ip`. `max_total` / `max_per_ip`
    /// of 0 mean "unlimited" for that dimension. Returns `None` (rejected) if
    /// either cap is already reached. The per-IP shard entry is held across the
    /// global check so two concurrent acquires for the same IP can't both slip
    /// past the per-IP cap.
    pub fn try_acquire(
        self: &Arc<Self>,
        client_ip: &str,
        max_total: u64,
        max_per_ip: u64,
    ) -> Option<ConnectionGuard> {
        if max_total == 0 && max_per_ip == 0 {
            // Nothing to enforce, so skip the per-IP map, but still count the
            // connection so `active` reports every open connection.
            self.global.fetch_add(1, Ordering::AcqRel);
            return Some(ConnectionGuard {
                held: Some(HeldConnection {
                    limiter: self.clone(),
                    ip: None,
                }),
            });
        }
        let ip = dos_ip_key(client_ip);
        let mut entry = self.per_ip.entry(ip.clone()).or_insert(0);
        if max_per_ip != 0 && *entry >= max_per_ip {
            return None;
        }
        loop {
            let current = self.global.load(Ordering::Acquire);
            if max_total != 0 && current >= max_total {
                return None;
            }
            if self
                .global
                .compare_exchange_weak(
                    current,
                    current.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }
        *entry += 1;
        Some(ConnectionGuard {
            held: Some(HeldConnection {
                limiter: self.clone(),
                ip: Some(ip),
            }),
        })
    }

    fn release(&self, ip: Option<&str>) {
        if let Some(ip) = ip {
            if let Some(mut e) = self.per_ip.get_mut(ip) {
                *e = e.saturating_sub(1);
                let empty = *e == 0;
                drop(e);
                if empty {
                    self.per_ip.remove_if(ip, |_, v| *v == 0);
                }
            }
        }
        self.global.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Drop-guard returned by [`ConnectionLimiter::try_acquire`]. Releases the
/// connection's slot on drop.
pub struct ConnectionGuard {
    held: Option<HeldConnection>,
}

struct HeldConnection {
    limiter: Arc<ConnectionLimiter>,
    /// The per-IP key this connection was counted under, or `None` when it was
    /// admitted with no caps and only the global count was touched.
    ip: Option<String>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(held) = self.held.as_ref() {
            held.limiter.release(held.ip.as_deref());
        }
    }
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
    let global_limit = options.max_connection_starts_per_minute;
    let ip_limit = options.max_connection_starts_per_ip_per_minute;
    if global_limit == UNLIMITED && ip_limit == UNLIMITED {
        return true;
    }
    if ip_limit == UNLIMITED {
        return store.consume(&[ConsumeRequest::new(
            "connection:start:global",
            global_limit,
            MINUTE_MS,
        )]);
    }
    let ip = dos_ip_key(client_ip);
    if global_limit == UNLIMITED {
        return store.consume(&[ConsumeRequest::new(
            format!("connection:start:ip:{ip}"),
            ip_limit,
            MINUTE_MS,
        )]);
    }
    store.consume(&[
        ConsumeRequest::new("connection:start:global", global_limit, MINUTE_MS),
        ConsumeRequest::new(format!("connection:start:ip:{ip}"), ip_limit, MINUTE_MS),
    ])
}

pub fn is_control_message_allowed(
    client_ip: &str,
    conn: &ConnectionDosGuard,
    options: &WispServerOptions,
    store: &DosGuard,
) -> bool {
    let connection_limit = options.max_control_messages_per_connection_per_minute;
    let ip_limit = options.max_control_messages_per_ip_per_minute;
    if connection_limit != UNLIMITED
        && !conn.consume(&[ConsumeRequest::new(
            "control:connection",
            connection_limit,
            MINUTE_MS,
        )])
    {
        return false;
    }
    if ip_limit == UNLIMITED {
        return true;
    }
    store.consume(&[ConsumeRequest::new(
        format!("control:ip:{}", dos_ip_key(client_ip)),
        ip_limit,
        MINUTE_MS,
    )])
}

pub fn is_tcp_stream_open_allowed(
    client_ip: &str,
    conn: &ConnectionDosGuard,
    options: &WispServerOptions,
    store: &DosGuard,
) -> bool {
    let connection_limit = options.max_tcp_stream_opens_per_connection_per_minute;
    let ip_limit = options.max_tcp_stream_opens_per_ip_per_minute;
    if connection_limit != UNLIMITED
        && !conn.consume(&[ConsumeRequest::new(
            "tcp:stream_open:connection",
            connection_limit,
            MINUTE_MS,
        )])
    {
        return false;
    }
    if ip_limit == UNLIMITED {
        return true;
    }
    store.consume(&[ConsumeRequest::new(
        format!("tcp:stream_open:ip:{}", dos_ip_key(client_ip)),
        ip_limit,
        MINUTE_MS,
    )])
}

/// `true` when at least one TCP byte limit is finite. Stream pumps hoist this
/// once so an unlimited configuration never enters [`is_tcp_bytes_allowed`].
#[inline]
pub fn tcp_byte_limits_active(options: &WispServerOptions) -> bool {
    options.max_tcp_bytes_per_connection_per_second != UNLIMITED
        || options.max_tcp_bytes_per_ip_per_second != UNLIMITED
}

/// `true` when at least one datagram limit is finite. UDP pumps hoist this
/// so the unlimited path never enters [`datagram_limit_decision`].
#[inline]
pub fn datagram_limits_active(options: &WispServerOptions) -> bool {
    options.max_datagrams_per_connection_per_second != UNLIMITED
        || options.max_datagram_bytes_per_connection_per_second != UNLIMITED
        || options.max_datagrams_per_ip_per_second != UNLIMITED
        || options.max_datagram_bytes_per_ip_per_second != UNLIMITED
}

/// Hot path: called on every relayed TCP chunk. Both limits set to
/// [`UNLIMITED`] short-circuits with zero allocation and no bucket lookup — the
/// per-IP key is only built when the per-IP limit is actually finite.
pub fn is_tcp_bytes_allowed(
    client_ip: &str,
    conn: &ConnectionDosGuard,
    options: &WispServerOptions,
    bytes: u64,
    store: &DosGuard,
) -> bool {
    let conn_lim = options.max_tcp_bytes_per_connection_per_second;
    if conn_lim != UNLIMITED
        && !conn.consume(&[
            ConsumeRequest::new("tcp:bytes:connection", conn_lim, SECOND_MS).with_amount(bytes),
        ])
    {
        return false;
    }
    let ip_lim = options.max_tcp_bytes_per_ip_per_second;
    if ip_lim == UNLIMITED {
        return true;
    }
    store.consume(&[ConsumeRequest::new(
        format!("tcp:bytes:ip:{}", dos_ip_key(client_ip)),
        ip_lim,
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
    if options.max_datagrams_per_connection_per_second == UNLIMITED
        && options.max_datagram_bytes_per_connection_per_second == UNLIMITED
        && options.max_datagrams_per_ip_per_second == UNLIMITED
        && options.max_datagram_bytes_per_ip_per_second == UNLIMITED
    {
        return DatagramDecision::Allow;
    }
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
    let global_limit = options.max_dns_resolutions_per_minute;
    let ip_limit = options.max_dns_resolutions_per_ip_per_minute;
    let unique_limit = options.max_unique_hostnames_per_ip_per_minute;
    if global_limit == UNLIMITED && ip_limit == UNLIMITED && unique_limit == UNLIMITED {
        return true;
    }
    let ip = dos_ip_key(client_ip);
    let rate_allowed = match (global_limit != UNLIMITED, ip_limit != UNLIMITED) {
        (true, true) => store.consume(&[
            ConsumeRequest::new("dns:global", global_limit, MINUTE_MS),
            ConsumeRequest::new(format!("dns:ip:{ip}"), ip_limit, MINUTE_MS),
        ]),
        (true, false) => {
            store.consume(&[ConsumeRequest::new("dns:global", global_limit, MINUTE_MS)])
        }
        (false, true) => store.consume(&[ConsumeRequest::new(
            format!("dns:ip:{ip}"),
            ip_limit,
            MINUTE_MS,
        )]),
        (false, false) => true,
    };
    if !rate_allowed {
        return false;
    }
    if unique_limit == UNLIMITED {
        return true;
    }
    store.consume_unique(
        &format!("dns:unique:{ip}"),
        hostname,
        unique_limit,
        MINUTE_MS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_tcp_limiter_reuses_finite_buckets() {
        let options = WispServerOptions {
            max_tcp_bytes_per_connection_per_second: 10,
            max_tcp_bytes_per_ip_per_second: UNLIMITED,
            ..WispServerOptions::default()
        };
        let connection = ConnectionDosGuard::new();
        let store = DosGuard::new();
        let limiter = TcpByteLimiter::new("192.0.2.1", &connection, &options, &store);
        assert!(limiter.is_active());
        assert!(limiter.is_allowed(6));
        assert!(!limiter.is_allowed(5));
    }

    fn redis_options(url: &str) -> WispServerOptions {
        WispServerOptions {
            rate_limit_backend: RateLimitBackend::Redis,
            redis_rate_limit_url: Some(url.to_owned()),
            redis_rate_limit_key_prefix: "wisp-test".to_owned(),
            redis_rate_limit_hash_tag: "limits".to_owned(),
            ..WispServerOptions::default()
        }
    }

    #[test]
    fn redis_keys_share_cluster_hash_tag() {
        let backend = RedisGuard::from_options(&redis_options("redis://127.0.0.1:0/"))
            .expect("valid Redis options");
        let first = backend.key("bucket", "global");
        let second = backend.key("bucket", "ip:203.0.113.7");
        assert!(first.contains("{limits}"));
        assert!(second.contains("{limits}"));
        assert_ne!(first, second);
        assert_eq!(backend.pool.inner.max_size, 1);
    }

    #[test]
    fn redis_batch_script_validates_before_mutation() {
        let validation = REDIS_CONSUME_SCRIPT
            .find("if amount > tokens")
            .expect("validation branch");
        let mutation = REDIS_CONSUME_SCRIPT
            .find("redis.call('HSET'")
            .expect("atomic mutation");
        assert!(validation < mutation);
        assert!(REDIS_CONSUME_SCRIPT.contains("return 0"));
        assert!(REDIS_CONSUME_SCRIPT.contains("redis.call('PEXPIRE'"));
    }

    #[test]
    fn redis_connection_failure_denies_batch() {
        let guard = DosGuard::from_options(&redis_options("redis://127.0.0.1:0/"))
            .expect("valid Redis options");
        assert!(!guard.consume(&[ConsumeRequest::new("global", 10, MINUTE_MS)]));
        assert!(!guard.consume_unique("hosts", "example.com", 10, MINUTE_MS));
    }

    #[test]
    fn redis_denies_values_lua_cannot_represent_exactly() {
        let backend = RedisGuard::from_options(&redis_options("redis://127.0.0.1:0/"))
            .expect("valid Redis options");
        let request = NormalizedConsume {
            key: "global",
            limit: REDIS_MAX_EXACT_INTEGER + 1,
            window_ms: MINUTE_MS,
            amount: 1,
        };
        assert!(!backend.consume(&[request], 0));
        assert!(!backend.consume_unique(
            "hosts",
            "example.com",
            REDIS_MAX_EXACT_INTEGER + 1,
            MINUTE_MS,
            0,
        ));
    }

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
        assert!(g.buckets.is_empty());
        assert_eq!(g.ops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn batch_normalization_orders_keys_and_coalesces_duplicates() {
        let reqs = [
            ConsumeRequest::new("z", 8, MINUTE_MS).with_amount(2),
            ConsumeRequest::new("a", 4, 0).with_amount(3),
            ConsumeRequest::new("z", 5, MINUTE_MS).with_amount(4),
            ConsumeRequest::new("ignored", UNLIMITED, MINUTE_MS),
        ];
        let batch = normalize_batch(&reqs).unwrap();

        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].key, "a");
        assert_eq!(batch[0].window_ms, 1);
        assert_eq!(batch[0].limit, 4);
        assert_eq!(batch[0].amount, 3);
        assert_eq!(batch[1].key, "z");
        assert_eq!(batch[1].window_ms, MINUTE_MS);
        assert_eq!(batch[1].limit, 5);
        assert_eq!(batch[1].amount, 6);
    }

    #[test]
    fn incompatible_duplicate_windows_fail_before_bucket_creation() {
        let g = DosGuard::new();
        assert!(!g.consume(&[
            ConsumeRequest::new("same", 10, SECOND_MS),
            ConsumeRequest::new("same", 10, MINUTE_MS),
        ]));
        assert!(g.buckets.is_empty());
    }

    #[test]
    fn consume_all_or_nothing() {
        let g = DosGuard::new();
        g.consume(&[ConsumeRequest::new("b", 1, MINUTE_MS)]);
        assert!(!g.consume(&[
            ConsumeRequest::new("a", 100, MINUTE_MS),
            ConsumeRequest::new("b", 1, MINUTE_MS),
        ]));
        assert!(g.consume(&[ConsumeRequest::new("a", 1, MINUTE_MS)]));
    }

    #[test]
    fn consume_coalesces_duplicate_keys_without_partial_commit() {
        let g = DosGuard::new();
        assert!(g.consume(&[
            ConsumeRequest::new("same", 3, MINUTE_MS),
            ConsumeRequest::new("same", 3, MINUTE_MS),
        ]));
        assert!(!g.consume(&[
            ConsumeRequest::new("other", 1, MINUTE_MS),
            ConsumeRequest::new("same", 3, MINUTE_MS),
            ConsumeRequest::new("same", 3, MINUTE_MS),
        ]));
        assert!(g.consume(&[ConsumeRequest::new("other", 1, MINUTE_MS)]));
        assert!(g.consume(&[ConsumeRequest::new("same", 3, MINUTE_MS)]));
    }

    #[test]
    fn concurrent_batches_lock_keys_in_stable_order() {
        let guard = Arc::new(DosGuard::new());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let threads: Vec<_> = [("a", "b"), ("b", "a")]
            .into_iter()
            .map(|(first, second)| {
                let guard = guard.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..1_000 {
                        assert!(guard.consume(&[
                            ConsumeRequest::new(first, 10_000, MINUTE_MS),
                            ConsumeRequest::new(second, 10_000, MINUTE_MS),
                        ]));
                    }
                })
            })
            .collect();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn unique_caps_distinct_values() {
        let g = DosGuard::new();
        assert!(g.consume_unique("k", "host1", 2, MINUTE_MS));
        assert!(g.consume_unique("k", "host2", 2, MINUTE_MS));
        assert!(g.consume_unique("k", "host1", 2, MINUTE_MS));
        assert!(!g.consume_unique("k", "host3", 2, MINUTE_MS));
        assert!(g.consume_unique("k", "host2", 2, MINUTE_MS));
    }

    #[test]
    fn datagram_strike_escalation() {
        let c = ConnectionDosGuard::new();
        assert!(!c.record_datagram_limit(3, MINUTE_MS));
    }

    #[test]
    fn unlimited_limits_short_circuit_hot_paths() {
        let store = DosGuard::new();
        let conn = ConnectionDosGuard::new();
        let opts = WispServerOptions {
            max_connection_starts_per_minute: UNLIMITED,
            max_connection_starts_per_ip_per_minute: UNLIMITED,
            max_control_messages_per_connection_per_minute: UNLIMITED,
            max_control_messages_per_ip_per_minute: UNLIMITED,
            max_tcp_stream_opens_per_connection_per_minute: UNLIMITED,
            max_tcp_stream_opens_per_ip_per_minute: UNLIMITED,
            max_tcp_bytes_per_connection_per_second: UNLIMITED,
            max_tcp_bytes_per_ip_per_second: UNLIMITED,
            max_datagrams_per_connection_per_second: UNLIMITED,
            max_datagram_bytes_per_connection_per_second: UNLIMITED,
            max_datagrams_per_ip_per_second: UNLIMITED,
            max_datagram_bytes_per_ip_per_second: UNLIMITED,
            max_dns_resolutions_per_minute: UNLIMITED,
            max_dns_resolutions_per_ip_per_minute: UNLIMITED,
            max_unique_hostnames_per_ip_per_minute: UNLIMITED,
            ..WispServerOptions::default()
        };
        assert!(!tcp_byte_limits_active(&opts));
        assert!(!datagram_limits_active(&opts));
        let tcp_limiter = TcpByteLimiter::new("not-an-ip", &conn, &opts, &store);
        assert!(!tcp_limiter.is_active());
        for _ in 0..100_000 {
            assert!(is_connection_start_allowed("not-an-ip", &opts, &store));
            assert!(is_control_message_allowed(
                "not-an-ip",
                &conn,
                &opts,
                &store
            ));
            assert!(is_tcp_stream_open_allowed(
                "not-an-ip",
                &conn,
                &opts,
                &store
            ));
            assert!(is_tcp_bytes_allowed(
                "not-an-ip",
                &conn,
                &opts,
                65_536,
                &store
            ));
            assert_eq!(
                datagram_limit_decision("not-an-ip", &conn, &opts, 1200, &store),
                DatagramDecision::Allow
            );
            assert!(is_dns_resolution_allowed(
                "not-an-ip",
                "example.com",
                &opts,
                &store
            ));
        }
        assert_eq!(store.buckets.len(), 0);
        assert_eq!(store.unique.len(), 0);
        assert_eq!(store.ops.load(Ordering::Relaxed), 0);
        assert_eq!(conn.guard.buckets.len(), 0);
        assert_eq!(conn.guard.unique.len(), 0);
        assert_eq!(conn.guard.ops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connection_limiter_caps_and_releases() {
        let lim = Arc::new(ConnectionLimiter::new());
        let g1 = lim.try_acquire("1.2.3.4", 0, 2);
        let g2 = lim.try_acquire("1.2.3.4", 0, 2);
        assert!(g1.is_some() && g2.is_some());
        assert!(lim.try_acquire("1.2.3.4", 0, 2).is_none());
        assert!(lim.try_acquire("5.6.7.8", 0, 2).is_some());
        drop(g1);
        assert!(lim.try_acquire("1.2.3.4", 0, 2).is_some());
        let l2 = Arc::new(ConnectionLimiter::new());
        let _a = l2.try_acquire("a", 1, 0).unwrap();
        assert!(l2.try_acquire("b", 1, 0).is_none());
    }

    #[test]
    fn unlimited_connection_caps_skip_the_per_ip_map() {
        let limiter = Arc::new(ConnectionLimiter::new());
        for _ in 0..100_000 {
            let guard = limiter
                .try_acquire("not-an-ip", 0, 0)
                .expect("uncapped connection admitted");
            assert_eq!(limiter.active(), 1);
            drop(guard);
        }
        assert_eq!(limiter.active(), 0);
        assert!(limiter.per_ip.is_empty());
    }

    #[test]
    fn uncapped_connections_are_counted_while_open() {
        let limiter = Arc::new(ConnectionLimiter::new());
        let first = limiter.try_acquire("203.0.113.5", 0, 0).unwrap();
        let second = limiter.try_acquire("203.0.113.6", 0, 0).unwrap();
        assert_eq!(limiter.active(), 2);
        // A capped acquire for the same IP must not see the uncapped ones in
        // its per-IP tally, and releasing them must not underflow it.
        let capped = limiter.try_acquire("203.0.113.5", 0, 1).unwrap();
        assert!(limiter.try_acquire("203.0.113.5", 0, 1).is_none());
        drop(first);
        drop(second);
        assert_eq!(limiter.active(), 1);
        drop(capped);
        assert_eq!(limiter.active(), 0);
        assert!(limiter.per_ip.is_empty());
    }

    #[test]
    fn unidentifiable_ips_share_one_strict_bucket() {
        let store = DosGuard::new();
        let opts = WispServerOptions {
            max_connection_starts_per_minute: UNLIMITED,
            max_connection_starts_per_ip_per_minute: 2,
            ..WispServerOptions::default()
        };
        assert!(is_connection_start_allowed("not-an-ip", &opts, &store));
        assert!(is_connection_start_allowed("also-garbage", &opts, &store));
        assert!(!is_connection_start_allowed("yet-more-junk", &opts, &store));
        assert!(is_connection_start_allowed("203.0.113.5", &opts, &store));
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

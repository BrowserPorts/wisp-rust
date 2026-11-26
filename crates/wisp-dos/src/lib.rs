//! Token-bucket DoS guard with explicit memory and Redis backends.
//!
//! Buckets are stored in sharded maps and the public decision helpers layer
//! per-connection, per-IP, and global limits on top of them. Redis batches are
//! checked and committed atomically through Lua and deny on backend errors.
//!
//! Sentinel: a limit of [`UNLIMITED`] (`u64::MAX`, produced from the `-1` TOML
//! convention) means "no cap". The helpers treat it as unbounded and avoid
//! overflow. A finite limit of `0` is the opposite extreme: it denies every
//! request (`WispServerOptions::validate` rejects it so a typo cannot silently
//! close a gate). The one exception is the concurrent-connection pair handled
//! by [`ConnectionLimiter`], where `0` means "no cap" for that dimension.

#![forbid(unsafe_code)]

use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use wisp_config::{ConfigError, RateLimitBackend, WispServerOptions};

pub const SECOND_MS: u64 = 1_000;
pub const MINUTE_MS: u64 = 60_000;
pub const UNLIMITED: u64 = u64::MAX;

/// Upper bound on live entries in each bucket map. Bounds attacker-driven key
/// churn (e.g. IP rotation) so the maps can't grow without limit between the
/// coarse time-based sweeps. When exceeded, the least recently used idle
/// entries are evicted in a batch of `MAX_BUCKETS / EVICT_DIVISOR`. A bucket
/// that a live connection still holds is never evicted, and if every entry is
/// held the new key gets a detached bucket that is not stored: a full map
/// never denies a new client, it only costs that client its remembered state.
const MAX_BUCKETS: usize = 65_536;
const EVICT_DIVISOR: usize = 16;

/// IPv6 per-IP keys are aggregated to this many leading bits (the /56 a
/// home broadband ISP typically delegates), so one subscriber cannot mint a
/// fresh bucket per /64. Set from `rate_limit_ipv6_prefix` by
/// [`DosGuard::from_options`]; the helpers and [`ConnectionLimiter`] read it
/// when they build a key. It is process-wide because those helpers have no
/// handle to the options.
pub const DEFAULT_IPV6_PREFIX: u8 = 56;
static IPV6_PREFIX: AtomicU8 = AtomicU8::new(DEFAULT_IPV6_PREFIX);

/// Redis leases cover one twentieth of the limit (at most 1 MiB worth), but
/// never less than the single request being admitted.
const REDIS_LEASE_DIVISOR: u64 = 20;
/// Connect and per-command deadlines for the Redis backend. The limiter has a
/// single worker thread, so a stalled server would otherwise wedge every
/// limiter until the OS gave up on the socket.
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_000);
const REDIS_IO_TIMEOUT: Duration = Duration::from_millis(500);

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
        match self
            .inner
            .client
            .get_connection_with_timeout(REDIS_CONNECT_TIMEOUT)
            .and_then(|connection| {
                connection.set_read_timeout(Some(REDIS_IO_TIMEOUT))?;
                connection.set_write_timeout(Some(REDIS_IO_TIMEOUT))?;
                Ok(connection)
            }) {
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
    /// Account for tokens a fresh local bucket was seeded with before Redis
    /// was asked. A denial (or a dead Redis) takes the seed back.
    Debit {
        seeds: Vec<(Arc<Mutex<Bucket>>, ConsumeRequest)>,
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
                        bucket.lease_expires = Some(now + redis_lease_ttl(window_ms));
                    }
                }
            }
            RedisWork::Debit { seeds } => {
                for (bucket, request) in seeds {
                    let allowed = normalize_batch(std::slice::from_ref(&request))
                        .is_some_and(|batch| guard.consume(&batch, DosGuard::now_ms()));
                    if !allowed {
                        revoke_seed(&bucket, request.amount);
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
                } else {
                    // Admitted optimistically but refused by Redis (or Redis
                    // was unreachable): remember the refusal so repeats are
                    // denied and the slot stays counted.
                    bucket.denied.insert(value);
                }
            }
        }
    }
}

/// Local lease for one Redis refill: a twentieth of the limit (at most 1 MiB
/// worth), raised to the request being admitted so a single chunk always fits,
/// and capped at the limit.
fn redis_lease(limit: u64, amount: u64) -> u64 {
    let base = limit
        .saturating_div(REDIS_LEASE_DIVISOR)
        .clamp(1, 1024 * 1024);
    base.max(amount).min(limit)
}

/// How long unspent leased tokens stay usable locally. Never shorter than a
/// second: a per-second byte bucket would otherwise expire its lease after
/// 50 ms and throttle a steady stream that Redis would have admitted.
fn redis_lease_ttl(window_ms: u64) -> Duration {
    Duration::from_millis(window_ms.saturating_div(20).max(SECOND_MS))
}

fn revoke_seed(bucket: &Mutex<Bucket>, amount: u64) {
    let mut bucket = bucket.lock();
    bucket.tokens = bucket.tokens.saturating_sub(amount);
}

/// Set the IPv6 aggregation prefix used by per-IP keys. Clamped to 16..=64:
/// normalization already masks to /64, so a longer prefix adds nothing.
pub fn set_ipv6_prefix(bits: u8) {
    IPV6_PREFIX.store(bits.clamp(16, 64), Ordering::Relaxed);
}

/// Normalize a client IP for use as a per-IP rate-limit key. IPv6 is masked to
/// the configured prefix (default /56, see [`DEFAULT_IPV6_PREFIX`]), so an
/// attacker holding a routed /56 can't mint unlimited distinct keys by
/// rotating the low bits. IPv4 passes through unchanged. Input that
/// does not parse as an IP is unidentifiable and collapses to a single shared
/// [`UNIDENTIFIED_KEY`] bucket, so malformed header text can never be treated as
/// a distinct per-IP identity and instead shares the strictest limit.
fn dos_ip_key(client_ip: &str) -> String {
    let prefix = IPV6_PREFIX.load(Ordering::Relaxed);
    wisp_iphash::normalize_client_ip(client_ip)
        .and_then(|key| aggregate_ip_key(&key, prefix))
        .unwrap_or_else(|| UNIDENTIFIED_KEY.to_owned())
}

/// A normalized key is a real identity only if it is an IPv4 literal or a
/// masked IPv6 /64 (re-masked here to `prefix`). Anything else is treated as
/// unidentifiable so it cannot mint a distinct per-IP bucket.
fn aggregate_ip_key(key: &str, prefix: u8) -> Option<String> {
    if key.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(key.to_owned());
    }
    let net = key
        .strip_suffix("/64")?
        .parse::<std::net::Ipv6Addr>()
        .ok()?;
    let prefix = prefix.clamp(16, 64);
    let masked = u128::from(net) & (u128::MAX << (128 - u32::from(prefix)));
    Some(format!("{}/{prefix}", std::net::Ipv6Addr::from(masked)))
}

/// One token-bucket charge. `limit` is the bucket capacity per `window_ms`
/// (0 is a valid "deny everything" bucket, [`UNLIMITED`] skips the bucket) and
/// `amount` the tokens to take.
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
    /// Last time any request touched this bucket, admitted or not. Drives the
    /// idle sweep and LRU eviction.
    last_seen: Instant,
    lease_pending: bool,
    lease_expires: Option<Instant>,
    /// Redis only: whether the local lease cache has been seeded yet.
    seeded: bool,
}

impl Bucket {
    fn new(limit: u64, window_ms: u64, now: Instant) -> Self {
        Self {
            // The memory backend starts full. A Redis bucket is seeded from
            // the first request that touches it (see `seeded`).
            tokens: limit,
            capacity: limit,
            remainder: 0,
            last_refill: now,
            window_ms,
            last_seen: now,
            lease_pending: false,
            lease_expires: None,
            seeded: false,
        }
    }

    /// Credit the tokens earned since the last refill at this bucket's own
    /// rate.
    fn refill(&mut self, now: Instant) {
        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos();
        let denominator = u128::from(self.window_ms).saturating_mul(1_000_000);
        let numerator = elapsed_ns
            .saturating_mul(u128::from(self.capacity))
            .saturating_add(self.remainder);
        let refill = numerator / denominator;
        self.remainder = numerator % denominator;
        self.tokens = self
            .tokens
            .saturating_add(refill.min(u128::from(u64::MAX)) as u64)
            .min(self.capacity);
        self.last_refill = now;
    }

    /// Adopt a new limit or window for a shared key. The tokens already held
    /// are kept and clamped to the new capacity: resetting to full would let
    /// two profiles with different limits refill each other's bucket on every
    /// alternating request. `local_refill` is false for Redis leases, which
    /// only grow through grants.
    fn retune(&mut self, limit: u64, window_ms: u64, now: Instant, local_refill: bool) {
        if self.capacity == limit && self.window_ms == window_ms {
            return;
        }
        if local_refill {
            self.refill(now);
        }
        self.capacity = limit;
        self.window_ms = window_ms;
        self.remainder = 0;
        self.last_refill = now;
        self.tokens = self.tokens.min(limit);
    }
}

/// Entries the eviction pass can rank by recency.
trait Idle {
    fn last_seen(&self) -> Instant;
}

impl Idle for Bucket {
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
}

/// Look up `key`, creating it when absent. At [`MAX_BUCKETS`] the least
/// recently used idle entries are evicted first; if the map is still full the
/// caller gets a detached entry that is simply not stored. Either way a new
/// key is never refused. Insertion is serialized by `admission`, which is
/// never taken while an entry's own mutex is held.
fn get_or_insert<T: Idle>(
    map: &DashMap<String, Arc<Mutex<T>>>,
    admission: &Mutex<()>,
    key: &str,
    make: impl FnOnce() -> T,
) -> Arc<Mutex<T>> {
    if let Some(entry) = map.get(key) {
        return entry.value().clone();
    }
    let _admission = admission.lock();
    if let Some(entry) = map.get(key) {
        return entry.value().clone();
    }
    if map.len() >= MAX_BUCKETS {
        evict_idle(map);
    }
    let handle = Arc::new(Mutex::new(make()));
    if map.len() < MAX_BUCKETS {
        map.insert(key.to_owned(), handle.clone());
    }
    handle
}

/// Drop the oldest `MAX_BUCKETS / EVICT_DIVISOR` entries by last use. Entries
/// something else still holds (a live connection's prepared bucket) are
/// skipped, and the holder check runs under the shard lock, so a handle cannot
/// be cloned out of the map between the check and the removal.
fn evict_idle<T: Idle>(map: &DashMap<String, Arc<Mutex<T>>>) {
    let target = MAX_BUCKETS / EVICT_DIVISOR;
    let mut seen: Vec<Instant> = map
        .iter()
        .filter(|entry| Arc::strong_count(entry.value()) == 1)
        .map(|entry| entry.value().lock().last_seen())
        .collect();
    if seen.is_empty() {
        return;
    }
    let rank = target.min(seen.len()) - 1;
    let (_, cutoff, _) = seen.select_nth_unstable(rank);
    let cutoff = *cutoff;
    let mut removed = 0;
    map.retain(|_, entry| {
        if removed >= target || Arc::strong_count(entry) > 1 {
            return true;
        }
        if entry.lock().last_seen() <= cutoff {
            removed += 1;
            return false;
        }
        true
    });
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
        bucket.last_seen = now;
        bucket.retune(self.limit, self.window_ms, now, self.redis.is_none());

        let Some(redis) = self.redis.as_ref() else {
            bucket.refill(now);
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
        let lease = redis_lease(self.limit, amount);
        let mut seed = None;
        if !bucket.seeded {
            // A new bucket starts full like the shared one in Redis does,
            // instead of denying its first request while a lease is fetched.
            // The seed is debited from Redis right after and taken back if
            // that fails.
            bucket.seeded = true;
            if amount <= self.limit {
                bucket.tokens = lease;
                bucket.lease_expires = Some(now + redis_lease_ttl(self.window_ms));
                seed = Some(lease);
            }
        }
        let admitted = amount <= bucket.tokens;
        if admitted {
            bucket.tokens -= amount;
        }
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
        } else {
            drop(bucket);
        }
        if let Some(seed) = seed {
            submit_debits(
                redis,
                vec![(
                    self.bucket.clone(),
                    ConsumeRequest::new(self.key.as_ref(), self.limit, self.window_ms)
                        .with_amount(seed),
                )],
            );
        }
        admitted
    }
}

fn submit_debits(redis: &RedisLeaseClient, seeds: Vec<(Arc<Mutex<Bucket>>, ConsumeRequest)>) {
    if redis.submit(RedisWork::Debit {
        seeds: seeds.clone(),
    }) {
        return;
    }
    for (bucket, request) in seeds {
        revoke_seed(&bucket, request.amount);
    }
}

/// Per-connection TCP byte limiter with normalized keys and bucket handles
/// prepared once. The relay hot path only locks the two token buckets.
pub struct TcpByteLimiter {
    connection: Option<PreparedBucket>,
    client: Option<PreparedBucket>,
}

impl TcpByteLimiter {
    pub fn new(
        client_ip: &str,
        connection: &ConnectionDosGuard,
        options: &WispServerOptions,
        store: &DosGuard,
    ) -> Self {
        // A full store no longer fails a limiter: `prepare_bucket` evicts or
        // hands back a detached bucket, so a new stream is never throttled
        // just because the map is busy.
        let connection = if options.max_tcp_bytes_per_connection_per_second == UNLIMITED {
            None
        } else {
            connection.guard.prepare_bucket(
                "tcp:bytes:connection".to_owned(),
                options.max_tcp_bytes_per_connection_per_second,
                SECOND_MS,
            )
        };
        let client = if options.max_tcp_bytes_per_ip_per_second == UNLIMITED {
            None
        } else {
            store.prepare_bucket(
                format!("tcp:bytes:ip:{}", dos_ip_key(client_ip)),
                options.max_tcp_bytes_per_ip_per_second,
                SECOND_MS,
            )
        };
        Self { connection, client }
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.connection.is_some() || self.client.is_some()
    }

    #[inline]
    pub fn is_allowed(&self, bytes: u64) -> bool {
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
    /// Redis only: values admitted locally whose Redis check is in flight.
    pending: HashSet<String>,
    /// Redis only: values Redis refused, or could not be asked about.
    denied: HashSet<String>,
    window_start: u64,
    window_ms: u64,
    last_seen: Instant,
}

impl Idle for UniqueBucket {
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
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
        set_ipv6_prefix(options.rate_limit_ipv6_prefix);
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

    /// Bucket handle for one limit, or `None` when the limit is [`UNLIMITED`].
    fn prepare_bucket(&self, key: String, limit: u64, window_ms: u64) -> Option<PreparedBucket> {
        if limit == UNLIMITED {
            return None;
        }
        self.maybe_cleanup();
        let monotonic_now = Instant::now();
        let window_ms = window_ms.max(1);
        let bucket = get_or_insert(&self.buckets, &self.bucket_admission, &key, || {
            Bucket::new(limit, window_ms, monotonic_now)
        });
        Some(PreparedBucket {
            key: Arc::from(key),
            limit,
            window_ms,
            bucket,
            redis: self.redis.clone(),
        })
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
        let monotonic_now = Instant::now();
        if let Some(redis) = &self.redis {
            return self.consume_redis(redis, &batch, monotonic_now);
        }
        self.maybe_cleanup();
        let handles: Vec<_> = batch
            .iter()
            .map(|request| {
                get_or_insert(&self.buckets, &self.bucket_admission, request.key, || {
                    Bucket::new(request.limit, request.window_ms.max(1), monotonic_now)
                })
            })
            .collect();
        let mut buckets: Vec<_> = handles.iter().map(|bucket| bucket.lock()).collect();
        let mut admitted = true;
        for (request, bucket) in batch.iter().zip(buckets.iter_mut()) {
            bucket.last_seen = monotonic_now;
            bucket.retune(request.limit, request.window_ms, monotonic_now, true);
            bucket.refill(monotonic_now);
            if request.amount > bucket.tokens {
                admitted = false;
            }
        }
        if admitted {
            for (request, bucket) in batch.iter().zip(buckets.iter_mut()) {
                bucket.tokens -= request.amount;
            }
        }
        admitted
    }

    pub fn consume_unique(&self, key: &str, val: &str, limit: u64, window_ms: u64) -> bool {
        if limit == UNLIMITED {
            return true;
        }
        let now = Self::now_ms();
        let seen = Instant::now();
        self.maybe_cleanup();
        let window_ms = window_ms.max(1);
        let start = (now / window_ms) * window_ms;
        let bucket = get_or_insert(&self.unique, &self.unique_admission, key, || UniqueBucket {
            values: HashSet::new(),
            pending: HashSet::new(),
            denied: HashSet::new(),
            window_start: start,
            window_ms,
            last_seen: seen,
        });
        let mut b = bucket.lock();
        b.last_seen = seen;
        if b.window_start != start || b.window_ms != window_ms {
            b.values.clear();
            b.pending.clear();
            b.denied.clear();
            b.window_start = start;
            b.window_ms = window_ms;
        }
        if let Some(redis) = &self.redis {
            // A first sighting is admitted while there is room locally and
            // checked against Redis in the background, instead of being
            // denied until a later request finds it confirmed.
            if b.values.contains(val) || b.pending.contains(val) {
                return true;
            }
            let known = b
                .values
                .len()
                .saturating_add(b.pending.len())
                .saturating_add(b.denied.len());
            if b.denied.contains(val) || known as u64 >= limit {
                return false;
            }
            b.pending.insert(val.to_owned());
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
            return submitted;
        }
        if !b.values.contains(val) && b.values.len() as u64 >= limit {
            return false;
        }
        b.values.insert(val.to_owned());
        b.window_ms = window_ms;
        (b.values.len() as u64) <= limit
    }

    pub fn clear(&self) {
        self.buckets.clear();
        self.unique.clear();
    }

    fn maybe_cleanup(&self) {
        let ops = self.ops.fetch_add(1, Ordering::Relaxed);
        if !ops.is_multiple_of(4096) {
            return;
        }
        let now = Instant::now();
        let retained = |last_seen: Instant, window_ms: u64| {
            now.saturating_duration_since(last_seen)
                <= Duration::from_millis(window_ms.saturating_mul(2).max(MINUTE_MS))
        };
        self.buckets.retain(|_, bucket| {
            Arc::strong_count(bucket) > 1 || {
                let bucket = bucket.lock();
                retained(bucket.last_seen, bucket.window_ms)
            }
        });
        self.unique.retain(|_, bucket| {
            Arc::strong_count(bucket) > 1 || {
                let bucket = bucket.lock();
                retained(bucket.last_seen, bucket.window_ms)
            }
        });
    }

    fn consume_redis(
        &self,
        redis: &RedisLeaseClient,
        batch: &[NormalizedConsume<'_>],
        monotonic_now: Instant,
    ) -> bool {
        self.maybe_cleanup();
        if batch.iter().any(|request| request.amount > request.limit) {
            return false;
        }
        let handles: Vec<_> = batch
            .iter()
            .map(|request| {
                get_or_insert(&self.buckets, &self.bucket_admission, request.key, || {
                    Bucket::new(request.limit, request.window_ms, monotonic_now)
                })
            })
            .collect();
        let mut buckets: Vec<_> = handles.iter().map(|bucket| bucket.lock()).collect();
        let mut admitted = true;
        let mut seeds = Vec::new();
        for ((request, bucket), handle) in batch.iter().zip(buckets.iter_mut()).zip(&handles) {
            bucket.last_seen = monotonic_now;
            bucket.retune(request.limit, request.window_ms, monotonic_now, false);
            if bucket
                .lease_expires
                .is_some_and(|expires| expires <= monotonic_now)
            {
                bucket.tokens = 0;
                bucket.lease_expires = None;
            }
            if !bucket.seeded {
                // See `PreparedBucket::consume`: seed a new bucket full and
                // debit Redis afterwards instead of denying the first request.
                bucket.seeded = true;
                let lease = redis_lease(request.limit, request.amount);
                bucket.tokens = lease;
                bucket.lease_expires = Some(monotonic_now + redis_lease_ttl(request.window_ms));
                seeds.push((
                    handle.clone(),
                    ConsumeRequest::new(request.key, request.limit, request.window_ms)
                        .with_amount(lease),
                ));
            }
            if bucket.tokens < request.amount {
                admitted = false;
            }
        }
        if admitted {
            for (request, bucket) in batch.iter().zip(buckets.iter_mut()) {
                bucket.tokens -= request.amount;
            }
        }

        let mut requests = Vec::new();
        let mut grants = Vec::new();
        for ((request, bucket), handle) in batch.iter().zip(buckets.iter_mut()).zip(&handles) {
            let lease = redis_lease(request.limit, request.amount);
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
        if !seeds.is_empty() {
            submit_debits(redis, seeds);
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
    /// of 0 mean "unlimited" for that dimension (the opposite of the rate
    /// limiters, where a limit of 0 denies everything). Returns `None` (rejected) if
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
        let admitted = if max_per_ip != 0 && *entry >= max_per_ip {
            false
        } else {
            loop {
                let current = self.global.load(Ordering::Acquire);
                if max_total != 0 && current >= max_total {
                    break false;
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
                    break true;
                }
            }
        };
        if !admitted {
            // `or_insert(0)` may have just created this entry. Drop it again
            // so rejected connections from many addresses cannot grow the map.
            let empty = *entry == 0;
            drop(entry);
            if empty {
                self.per_ip.remove_if(&ip, |_, count| *count == 0);
            }
            return None;
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

/// Spends one operation from the client IP's shared budget for `class`: at
/// most `limit` operations, refilled evenly over `window_ms`. Per-connection
/// limiters multiply by the number of connections an IP opens; this does not.
pub fn is_ip_budget_allowed(
    client_ip: &str,
    class: &str,
    limit: u64,
    window_ms: u64,
    store: &DosGuard,
) -> bool {
    if limit == UNLIMITED {
        return true;
    }
    store.consume(&[ConsumeRequest::new(
        format!("{class}:ip:{}", dos_ip_key(client_ip)),
        limit,
        window_ms,
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

/// Limits of the IP_TUNNEL extension, from `[ip_tunnel]`. A tunnel carries
/// a whole network stack's traffic, so it is metered by packets and bytes
/// rather than by streams, and a packet over a limit is dropped as a
/// congested router would drop it: the client's own TCP backs off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelLimits {
    pub packets_per_tunnel_per_second: u64,
    pub bytes_per_tunnel_per_second: u64,
    pub packets_per_ip_per_second: u64,
    pub bytes_per_ip_per_second: u64,
    pub new_flows_per_tunnel_per_minute: u64,
}

impl TunnelLimits {
    pub const UNLIMITED: Self = Self {
        packets_per_tunnel_per_second: UNLIMITED,
        bytes_per_tunnel_per_second: UNLIMITED,
        packets_per_ip_per_second: UNLIMITED,
        bytes_per_ip_per_second: UNLIMITED,
        new_flows_per_tunnel_per_minute: UNLIMITED,
    };
}

/// Charges one tunnel packet of `bytes` to its tunnel (`tunnel`, one guard
/// per tunnel) and to the client address the tunnel's connection came
/// from. `false` means drop it.
pub fn is_tunnel_packet_allowed(
    client_ip: &str,
    tunnel: &ConnectionDosGuard,
    limits: &TunnelLimits,
    bytes: u64,
    store: &DosGuard,
) -> bool {
    let tunnel_ok = (limits.packets_per_tunnel_per_second == UNLIMITED
        && limits.bytes_per_tunnel_per_second == UNLIMITED)
        || tunnel.consume(&[
            ConsumeRequest::new(
                "tunnel:packets:tunnel",
                limits.packets_per_tunnel_per_second,
                SECOND_MS,
            ),
            ConsumeRequest::new(
                "tunnel:bytes:tunnel",
                limits.bytes_per_tunnel_per_second,
                SECOND_MS,
            )
            .with_amount(bytes),
        ]);
    if !tunnel_ok {
        return false;
    }
    if limits.packets_per_ip_per_second == UNLIMITED && limits.bytes_per_ip_per_second == UNLIMITED
    {
        return true;
    }
    let ip = dos_ip_key(client_ip);
    store.consume(&[
        ConsumeRequest::new(
            format!("tunnel:packets:ip:{ip}"),
            limits.packets_per_ip_per_second,
            SECOND_MS,
        ),
        ConsumeRequest::new(
            format!("tunnel:bytes:ip:{ip}"),
            limits.bytes_per_ip_per_second,
            SECOND_MS,
        )
        .with_amount(bytes),
    ])
}

/// Charges the start of one new flow (a first packet of a 5-tuple the tunnel
/// has not seen) to its tunnel.
pub fn is_tunnel_flow_open_allowed(tunnel: &ConnectionDosGuard, limits: &TunnelLimits) -> bool {
    limits.new_flows_per_tunnel_per_minute == UNLIMITED
        || tunnel.consume(&[ConsumeRequest::new(
            "tunnel:flows:tunnel",
            limits.new_flows_per_tunnel_per_minute,
            MINUTE_MS,
        )])
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
    fn redis_connection_failure_denies_after_the_seed() {
        let guard = DosGuard::from_options(&redis_options("redis://127.0.0.1:0/"))
            .expect("valid Redis options");
        // A new key is seeded with one lease so its first request is not
        // denied while Redis is consulted; with Redis down nothing refills it.
        assert!(guard.consume(&[ConsumeRequest::new("global", 10, MINUTE_MS)]));
        assert!(!guard.consume(&[ConsumeRequest::new("global", 10, MINUTE_MS)]));
        // Same for a first-seen value, which is then remembered as refused
        // once the failed Redis check lands.
        assert!(guard.consume_unique("hosts", "example.com", 10, MINUTE_MS));
        for _ in 0..200 {
            if !guard.consume_unique("hosts", "example.com", 10, MINUTE_MS) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("failed Redis check was never recorded as a refusal");
    }

    #[test]
    fn redis_lease_covers_one_chunk_and_outlives_a_second() {
        // A 64 KiB chunk against a 1 MiB/s limit: the 5% lease alone (51 KiB)
        // would never admit it.
        assert!(redis_lease(1024 * 1024, 64 * 1024) >= 64 * 1024);
        assert_eq!(redis_lease(100, 1), 5);
        assert_eq!(redis_lease(10, 1), 1);
        assert!(redis_lease_ttl(SECOND_MS) >= Duration::from_secs(1));
        assert_eq!(redis_lease_ttl(MINUTE_MS), Duration::from_secs(3));
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

    #[test]
    fn ip_budget_is_shared_per_class_and_ip() {
        let store = DosGuard::new();
        let spend = |ip: &str, class: &str| is_ip_budget_allowed(ip, class, 2, 60_000, &store);
        assert!(spend("203.0.113.9", "demo"));
        assert!(spend("203.0.113.9", "demo"));
        assert!(!spend("203.0.113.9", "demo"));
        assert!(spend("203.0.113.10", "demo"));
        assert!(spend("203.0.113.9", "other"));
        for _ in 0..10 {
            assert!(is_ip_budget_allowed(
                "203.0.113.9",
                "free",
                UNLIMITED,
                60_000,
                &store
            ));
        }
    }

    fn fill(guard: &DosGuard, count: usize) {
        for index in 0..count {
            assert!(guard.consume(&[ConsumeRequest::new(format!("fill:{index}"), 5, MINUTE_MS)]));
        }
    }

    #[test]
    fn full_map_evicts_the_oldest_instead_of_denying() {
        let guard = DosGuard::new();
        fill(&guard, MAX_BUCKETS);
        assert_eq!(guard.buckets.len(), MAX_BUCKETS);
        assert!(guard.consume(&[ConsumeRequest::new("new-client", 5, MINUTE_MS)]));
        assert!(guard.buckets.len() <= MAX_BUCKETS);
        assert!(guard.buckets.contains_key("new-client"));
        assert!(!guard.buckets.contains_key("fill:0"));
        assert!(guard
            .buckets
            .contains_key(format!("fill:{}", MAX_BUCKETS - 1).as_str()));
    }

    #[test]
    fn recently_used_buckets_survive_eviction() {
        let guard = DosGuard::new();
        fill(&guard, MAX_BUCKETS);
        // Touch the oldest key, denied or not, so it is no longer the oldest.
        for _ in 0..6 {
            guard.consume(&[ConsumeRequest::new("fill:0", 5, MINUTE_MS)]);
        }
        assert!(guard.consume(&[ConsumeRequest::new("new-client", 5, MINUTE_MS)]));
        assert!(guard.buckets.contains_key("fill:0"));
        assert!(!guard.buckets.contains_key("fill:1"));
    }

    #[test]
    fn saturated_store_does_not_throttle_new_tcp_streams() {
        let store = DosGuard::new();
        let conn = ConnectionDosGuard::new();
        let options = WispServerOptions {
            max_tcp_bytes_per_connection_per_second: UNLIMITED,
            max_tcp_bytes_per_ip_per_second: 1_000_000,
            ..WispServerOptions::default()
        };
        fill(&store, MAX_BUCKETS);
        let limiter = TcpByteLimiter::new("203.0.113.9", &conn, &options, &store);
        assert!(limiter.is_allowed(1024));
        assert!(store.buckets.len() <= MAX_BUCKETS);
    }

    #[test]
    fn held_buckets_are_never_evicted_and_new_keys_get_a_detached_bucket() {
        let store = DosGuard::new();
        let held: Vec<_> = (0..MAX_BUCKETS)
            .map(|index| {
                store
                    .prepare_bucket(format!("held:{index}"), 1000, SECOND_MS)
                    .expect("finite limit")
            })
            .collect();
        assert_eq!(store.buckets.len(), MAX_BUCKETS);
        let fresh = store
            .prepare_bucket("fresh".to_owned(), 1000, SECOND_MS)
            .expect("finite limit");
        assert!(fresh.consume(1000));
        assert!(!fresh.consume(1000));
        assert_eq!(store.buckets.len(), MAX_BUCKETS);
        assert!(!store.buckets.contains_key("fresh"));
        assert!(held[0].consume(1));
    }

    #[test]
    fn eviction_applies_to_unique_buckets_too() {
        let guard = DosGuard::new();
        for index in 0..MAX_BUCKETS {
            assert!(guard.consume_unique(&format!("u:{index}"), "a", 2, MINUTE_MS));
        }
        assert!(guard.consume_unique("u:new", "a", 2, MINUTE_MS));
        assert!(guard.unique.len() <= MAX_BUCKETS);
        assert!(guard.unique.contains_key("u:new"));
    }

    #[test]
    fn rejected_connections_leave_no_zero_entries() {
        let limiter = Arc::new(ConnectionLimiter::new());
        let held = limiter.try_acquire("198.51.100.1", 1, 0).unwrap();
        for index in 0..1000 {
            assert!(limiter
                .try_acquire(&format!("203.0.113.{}", index % 250), 1, 4)
                .is_none());
        }
        assert_eq!(limiter.per_ip.len(), 1);
        let per_ip = Arc::new(ConnectionLimiter::new());
        let first = per_ip.try_acquire("192.0.2.1", 0, 1).unwrap();
        assert!(per_ip.try_acquire("192.0.2.1", 0, 1).is_none());
        assert_eq!(per_ip.per_ip.len(), 1);
        drop(first);
        assert!(per_ip.per_ip.is_empty());
        drop(held);
        assert!(limiter.per_ip.is_empty());
    }

    #[test]
    fn changing_a_shared_key_limit_clamps_instead_of_refilling() {
        let guard = DosGuard::new();
        assert!(guard.consume(&[ConsumeRequest::new("shared", 10, MINUTE_MS).with_amount(10)]));
        // A different limit on the same key must not hand back a full bucket.
        assert!(!guard.consume(&[ConsumeRequest::new("shared", 1000, MINUTE_MS)]));
        assert!(!guard.consume(&[ConsumeRequest::new("shared", 10, MINUTE_MS)]));
        // Lowering the limit clamps what is held.
        let other = DosGuard::new();
        assert!(other.consume(&[ConsumeRequest::new("k", 100, MINUTE_MS)]));
        assert!(other.consume(&[ConsumeRequest::new("k", 2, MINUTE_MS).with_amount(2)]));
        assert!(!other.consume(&[ConsumeRequest::new("k", 2, MINUTE_MS)]));
    }

    #[test]
    fn prepared_bucket_clamps_on_retune() {
        let store = DosGuard::new();
        let wide = store
            .prepare_bucket("tcp:bytes:ip:x".to_owned(), 100, SECOND_MS)
            .unwrap();
        assert!(wide.consume(100));
        let narrow = store
            .prepare_bucket("tcp:bytes:ip:x".to_owned(), 200, SECOND_MS)
            .unwrap();
        assert!(!narrow.consume(150));
    }

    #[test]
    fn ipv6_keys_aggregate_to_the_configured_prefix() {
        let a = aggregate_ip_key("2001:0db8:1234:5600:0000:0000:0000:0000/64", 56).unwrap();
        let b = aggregate_ip_key("2001:0db8:1234:56ff:0000:0000:0000:0000/64", 56).unwrap();
        let c = aggregate_ip_key("2001:0db8:1234:5700:0000:0000:0000:0000/64", 56).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, "2001:db8:1234:5600::/56");
        let narrow = aggregate_ip_key("2001:0db8:1234:56ff:0000:0000:0000:0000/64", 64).unwrap();
        assert_ne!(narrow, a);
        let wide = aggregate_ip_key("2001:0db8:1234:5700:0000:0000:0000:0000/64", 48).unwrap();
        assert_eq!(
            wide,
            aggregate_ip_key("2001:0db8:1234:9900:0000:0000:0000:0000/64", 48).unwrap()
        );
        assert_eq!(
            aggregate_ip_key("203.0.113.5", 56).as_deref(),
            Some("203.0.113.5")
        );
        assert!(aggregate_ip_key("garbage", 56).is_none());
        // Default prefix: addresses in one /56 share a key.
        assert_eq!(
            dos_ip_key("2001:db8:1234:5600::1"),
            dos_ip_key("2001:db8:1234:56ab::2")
        );
    }
}

#[cfg(test)]
mod tunnel_limit_tests {
    use super::*;

    fn limits() -> TunnelLimits {
        TunnelLimits {
            packets_per_tunnel_per_second: 3,
            bytes_per_tunnel_per_second: 10_000,
            packets_per_ip_per_second: 5,
            bytes_per_ip_per_second: UNLIMITED,
            new_flows_per_tunnel_per_minute: 2,
        }
    }

    #[test]
    fn tunnel_packets_are_bounded_per_tunnel_and_per_address() {
        let store = DosGuard::new();
        let a = ConnectionDosGuard::new();
        let b = ConnectionDosGuard::new();
        for _ in 0..3 {
            assert!(is_tunnel_packet_allowed(
                "1.2.3.4",
                &a,
                &limits(),
                100,
                &store
            ));
        }
        assert!(!is_tunnel_packet_allowed(
            "1.2.3.4",
            &a,
            &limits(),
            100,
            &store
        ));
        // Another tunnel from the same address shares the address budget.
        assert!(is_tunnel_packet_allowed(
            "1.2.3.4",
            &b,
            &limits(),
            100,
            &store
        ));
        assert!(is_tunnel_packet_allowed(
            "1.2.3.4",
            &b,
            &limits(),
            100,
            &store
        ));
        assert!(!is_tunnel_packet_allowed(
            "1.2.3.4",
            &b,
            &limits(),
            100,
            &store
        ));
        let big = ConnectionDosGuard::new();
        assert!(!is_tunnel_packet_allowed(
            "5.6.7.8",
            &big,
            &limits(),
            20_000,
            &store
        ));
    }

    #[test]
    fn tunnel_flow_opens_are_bounded() {
        let t = ConnectionDosGuard::new();
        assert!(is_tunnel_flow_open_allowed(&t, &limits()));
        assert!(is_tunnel_flow_open_allowed(&t, &limits()));
        assert!(!is_tunnel_flow_open_allowed(&t, &limits()));
        assert!(is_tunnel_flow_open_allowed(&t, &TunnelLimits::UNLIMITED));
        let store = DosGuard::new();
        for _ in 0..100 {
            assert!(is_tunnel_packet_allowed(
                "1.2.3.4",
                &t,
                &TunnelLimits::UNLIMITED,
                1500,
                &store
            ));
        }
    }
}

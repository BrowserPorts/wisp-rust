# Security & Safety Audit — wisp-rust

Date: 2026-07-03. Scope: full workspace safety review (unsafe/FFI, remote-input
parsing, panic reachability), rate-limit / DoS-guard correctness, and clippy.

`cargo clippy --workspace --all-targets` (default and `--all-features`) is
**clean — zero warnings**. The crates are disciplined: every crate except the
msquic FFI adapter declares `#![forbid(unsafe_code)]`, and no remote-reachable
`unwrap`/`expect`/`panic!` was found in the parsing paths (`wisp-wire`,
`wisp-wisp`, `wisp-ws-h3`), which consistently use `checked_add` + explicit
bounds checks and length caps. Release builds use `panic = "abort"`, so the
panic-reachability review mattered; it came back clean for network input.

## Fixed in this pass

- **Unbounded WT control-frame length (pre-auth memory-exhaustion / slowloris).**
  `WtControlIo`/`WtControlReader::read_frame` in `wisp-server/src/serve.rs` trusted
  a raw 4-byte `u32` length (up to ~4 GiB) and grew `rx_buf` without bound. Added
  a 16 MiB cap (`MAX_CONTROL_FRAME_BYTES`, mirroring `wisp-ws-h3`'s
  `MAX_FRAME_PAYLOAD`) enforced before buffering.
- **msquic datagram send: leaked payload box on every successful send.**
  `send_datagram_inner` leaks a `Box<Bytes>` as the FFI client-context and only
  freed it on synchronous error. Added the `DatagramSendStateChanged` handler in
  `on_connection_event`, freeing the box exactly once on a terminal send state
  (`Acknowledged`/`AcknowledgedSpurious`/`LostDiscarded`/`Canceled`) — never on a
  non-final state, which would be a use-after-free.
- **msquic stream: leaked send box after peer half-close.** `PeerSendShutdown`
  removed the whole per-stream registry entry, so later `SendComplete` events
  (still possible while our send side flushes) hit the early-return guard and
  leaked their boxed payload. Now signals EOF with an empty chunk and defers
  registry removal to the terminal `ShutdownComplete`.
- **DoS guard division-by-zero hardening.** `DosGuard::consume`/`consume_unique`
  divided by a caller-supplied `window_ms`; guarded with `.max(1)` so a future
  `0` (e.g. via `patch_limits`) can't abort the process.
- **Dead code removed.** `StreamState` / `TcpStreamResult` placeholder `()` aliases
  in `wisp-wisp-server` and their re-export.

## Second pass — previously-open findings now fixed

All of the findings below were addressed in a follow-up pass.

### Critical

1. **SSRF on the WS transport's no-proxy fallback — FIXED.** `wisp-wisp-server`
   `stream.rs`/`udp.rs` no longer connect by hostname. A new `resolve_checked`
   helper resolves via `tokio::net::lookup_host`, gates **every** resolved
   address through `HostPolicy::check_ip`, and rejects the whole connection if
   any address is disallowed (closing the DNS-rebinding public+private mix), then
   connects to the checked address.

2. **TCP/UDP/DNS rate limiters wired on both transports — FIXED.**
   `is_tcp_stream_open_allowed` + `is_dns_resolution_allowed` gate stream opens
   (WS `connection.rs`; WT `bridge_one_stream` via `SessionLimits`).
   `is_tcp_bytes_allowed` meters both byte-pump directions (WS `stream.rs`; WT
   `bridge_one_stream`) — on sustained over-budget the stream is closed (dropping
   TCP bytes would corrupt the stream; a sleep-shaper is disallowed by project
   rules). `datagram_limit_decision` now runs on both UDP directions on both
   transports.

3. **`max_connections` / `max_connections_per_ip` enforced as concurrency caps —
   FIXED.** New `wisp_dos::ConnectionLimiter` (+ `global_connection_limiter()`)
   tracks live connections globally and per normalized IP and returns an RAII
   `ConnectionGuard` that releases on every exit path. Acquired at admission on
   ws-h2, ws-plain, and WT. ws-plain also gained the **Origin** check it was
   missing, and both WS listeners now gate the connection-start rate.

4. **Per-IP DoS keys masked to /64 — FIXED.** All per-IP keys in `wisp-dos` now
   run through `dos_ip_key` (→ `wisp_iphash::normalize_client_ip`), so IPv6 /64
   rotation no longer mints unlimited buckets. A `MAX_BUCKETS` LRU cap also bounds
   total map growth.

5. **Redis backend + `parse_real_ip` — FIXED.** `WispServerOptions::validate`
   now rejects `rate_limit.backend = "redis"` (not implemented) instead of
   silently falling back; the shipped production config was switched to `memory`.
   `wisp_config::resolve_client_ip` implements trusted-hop `X-Forwarded-For`
   resolution (only trusts the header when the direct peer is within
   `parse_real_ip_from`, walking the chain right-to-left), wired into ws-h2,
   ws-plain (WT already resolves the peer directly).

### High

- **WT timeouts — FIXED.** `bridge_one_stream` bounds the header read by
  `handshake_timeout_ms` and both TCP pumps by `stream_idle_timeout_ms`.
- **WT concurrent UDP-flow cap — FIXED.** `on_udp_open` rejects once live flows
  reach `stream_limit_total`.
- **Client→upstream UDP metering — FIXED** on both transports.

### Medium / defensive

- **`catch_unwind` around msquic callbacks — FIXED** (connection + stream
  callbacks); panics are logged and swallowed instead of crossing the FFI
  boundary.
- **msquic stream registry keyed by QUIC stream id — FIXED** (was the raw
  `HQUIC` pointer; ids are never reused within a connection).
- **`DosGuard` LRU cap — FIXED** (`MAX_BUCKETS`).
- **`redis_fail_open` — FIXED** in the shipped production config (now `false`;
  moot anyway since `redis` is rejected at validation).
- **Port `0` explicitly rejected — FIXED** in `HostPolicy::check`.

### Remaining follow-up (deliberately not done)

- **Distributed Redis rate-limit backend is still unimplemented** — it now fails
  loud at config validation rather than silently under-protecting. Implementing
  the shared limiter (atomic Lua token buckets, connection pooling) is a feature,
  not a safety fix, and is left for when horizontal scaling is actually needed.

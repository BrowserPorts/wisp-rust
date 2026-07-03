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

## Open findings — prioritized (need design decisions, not yet changed)

These are real but touch core networking behavior or advertise config surface
that isn't implemented; they warrant deliberate fixes rather than an autonomous
rewrite.

### Critical

1. **SSRF on the WS transport's no-proxy fallback.** `wisp-wisp-server`
   `stream.rs`/`udp.rs` call `TcpStream::connect((host, port))` /
   `UdpSocket::connect((host, port))` directly. `HostPolicy::check` only runs
   `check_ip` when `host` parses as a literal IP, so a **hostname** resolving to
   `127.0.0.1` / `169.254.169.254` / RFC-1918 bypasses `allow_private_ips` /
   `allow_loopback_ips`. The WT/QUIC path is safe (it goes through
   `TcpConnector`/`UdpConnector`, which resolve and `check_ip` every address).
   Fix: route the WS fallback through the same resolver + per-address `check_ip`
   (and consider DNS-rebinding TOCTOU: check the exact IP you then connect to).

2. **TCP/UDP/DNS rate limiters are never called on the WT/QUIC path.**
   `is_tcp_stream_open_allowed`, `is_tcp_bytes_allowed`, `datagram_limit_decision`,
   and `is_dns_resolution_allowed` are wired only in `wisp-wisp-server` (WS). On
   the WT path (`serve.rs` `bridge_one_stream` / `open_udp_flow`) a single
   connection can open unlimited TCP streams and push unlimited bytes. Only
   `is_connection_start_allowed` and `is_control_message_allowed` are enforced.

3. **`max_connections` / `max_connections_per_ip` are not enforced as concurrency
   caps.** No live-connection counter exists; `max_connections` only maps to h3's
   per-connection `max_webtransport_sessions`. ws-h2 / ws-plain accept loops
   `tokio::spawn` a handler per TCP accept with no admission control (ws-h2 pays a
   full TLS handshake first; ws-plain also skips the Origin check that the other
   transports enforce).

4. **Per-IP DoS keys use the unmasked /128 IPv6 address.** `wisp-iphash` already
   masks IPv6 to /64 for the client hash, but DoS bucket keys use the raw address,
   so /64 rotation defeats every per-IP limit. Route the DoS key through the same
   /64 normalization.

5. **`rate_limit.backend = "redis"` and `parse_real_ip*` are parsed but not
   implemented.** The shipped `configs/wispd.production.toml` sets `backend =
   "redis"` (implying shared limits across instances) and the example advertises
   `parse_real_ip` / `parse_real_ip_from`. Neither is wired: every instance uses a
   private in-memory limiter, and `client_ip` is always the raw socket peer (so a
   reverse-proxied deployment collapses all clients to the proxy IP). Either
   implement them or fail config validation and drop the dead surface.

### High

- **No idle/read timeouts on the WT path.** `handshake_timeout_ms` and
  `stream_idle_timeout_ms` are unused for WT control/handshake and TCP bridge
  streams; `bridge_one_stream`'s header read has no timeout. Slow-resource-pinning.
- **Unbounded concurrent UDP flows per WT connection.** `serve.rs`
  `UdpFlowRegistry` has no cap; the WS side's `StreamCaps` does. Add an equivalent.
- **Client→upstream UDP is unmetered by the datagram limiter** (WS `udp.rs`);
  `datagram_limit_decision` runs only on the reply direction.

### Medium / defensive

- No `catch_unwind` around msquic callback closures. `panic = "abort"` makes this
  a clean process abort today, but debug/test builds unwind across the `extern "C"`
  trampoline. Wrap callback bodies in `catch_unwind(AssertUnwindSafe(..))` to turn
  a per-connection panic into a per-connection failure.
- Raw msquic `HQUIC` pointer used as an eternal `DashMap` key (ABA/handle-reuse
  hazard under high stream churn). Prefer keying by the msquic stream id.
- `DosGuard` bucket map is bounded only by a coarse periodic sweep; add an LRU cap.
- `redis_fail_open = true` in shipped configs will fail-open once Redis is wired.
- Port `0` is not explicitly rejected by policy (OS rejects at connect time).

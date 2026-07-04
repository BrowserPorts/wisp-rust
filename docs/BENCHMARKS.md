# Benchmarks (WispMark)

This document records how `wispd` is benchmarked against other Wisp server
implementations, the most recent measured results, and an assessment of where
it stands.

## Harness

The benchmark harness is not in this repo (`bench/docker` is an empty
placeholder). It is a local fork of
[MercuryWorkshop/wispmark](https://github.com/MercuryWorkshop/wispmark) checked
out as a sibling of this repo:

- `../wispmark` — the main suite. Its `server.xsh` contains a `WispRustServer`
  class that builds this repo's `wispd` (WS-only:
  `cargo build --release -p wispd --no-default-features --features ws`) and
  runs it as the `wisp-rust-ws` row.
- `../wispmark-wt` — a WebTransport-aware variant with a `wisp-rust-wt` row
  (features `ws,quic`). WT servers are only paired with WT-capable clients, so
  without a WebTransport client installed that row reports `N/A`.

### Methodology

- A Python threaded TCP echo server listens on `127.0.0.1:6002` and counts
  every byte it receives into a counter file (flushed every 100 ms).
- For each (server, client) cell, the Wisp server under test is started on
  `127.0.0.1:6001`, then the client(s) open Wisp streams to the echo server
  through it and pump data as fast as possible.
- The harness sleeps for the test duration (default 10 s) and reports the
  counter delta as MiB/s. This measures client-to-upstream application payload
  actually relayed by the server, end to end.

### Compared servers

| Row | Implementation | Language/runtime |
|---|---|---|
| `wisp-rust-ws` | this repo's `wispd` (WS-only build) | Rust / tokio |
| `wisp-js` | MercuryWorkshop wisp-js | Node |
| `wisp-server-python` | MercuryWorkshop wisp-server-python | Python |
| `epoxy-server (singlethread/multithread)` | MercuryWorkshop epoxy-tls | Rust / tokio |
| `mrrowisp` | starlightdevgroup mrrowisp | Go |

### Clients (columns)

- `wisp-js (10)` / `wisp-js (5x10)` — Node wisp-js client with 10 streams, 1
  or 5 processes.
- `wisp-mux (10)` / `wisp-mux (5x10)` — Rust `simple-wisp-client` from
  epoxy-tls (`-s 10 -p 50 --wisp-v2`), 1 or 5 processes.

The harness generates a bench config for `wispd`
(`target/wispmark-wisp-rust-ws.toml`): plain (no-TLS) WebSocket listener,
protocol inspection disabled, blank origins allowed, destination port 6002
whitelisted, loopback/private destinations allowed, TCP byte rate limits
effectively removed, `idle_timeout_ms = 2000` so the drain after SIGTERM is
short. All servers are benchmarked in comparably permissive configurations, so
the suite measures the raw mux/relay path.

### Environment caveats

- Apple M4 (10 cores), macOS. All servers and clients share the same machine,
  so every cell is a whole-system CPU contest, and run-to-run variance is
  high; differences under roughly 15-20 % are noise.
- `/usr/local/bin/node` on this machine is an x86_64 binary running under
  Rosetta. This penalizes both the `wisp-js` server row and the `wisp-js`
  client columns for every server.
- The harness caches the `wispd` build with `target/.wispd-ws.built`; it does
  NOT rebuild when source changes. Always check the binary mtime against the
  tree before trusting a row.

## Results

### 2026-07-04 (wispd binary built 2026-06-05, Apple M4, 10 s cells)

The working tree was mid-refactor and did not compile on the benchmark date
(`wisp-router` had unresolved `wisp_dos`/`wisp_origin` imports), so the run
used the last good release binary from 2026-06-05.

Two defaults in that binary initially zeroed the `wisp-rust-ws` row until the
harness config was fixed to account for them:

- `wisp.destination.port_whitelist` defaults to `[80, 443]`, so streams to the
  echo port were rejected (`port 6002 not in allowlist`) and the row measured
  0.0 MiB/s while the clients happily pumped bytes into rejected streams.
- `idle_timeout_ms` defaults to 120 000 ms and doubles as the graceful-drain
  window, so each killed `wispd` lingered two minutes and starved the next
  cells. The bench config now sets it to 2 000 ms.

IMPORTANT: this run executed while a Chromium build and other workloads had
the machine at load average ~137 on 10 cores at the start (falling to ~60 by
the end). Absolute numbers are heavily depressed and the earlier rows
(wisp-rust ran first) were hit hardest. Treat this table as ordering-only
evidence at best; the 2026-05-31 tables below are the cleaner references.

|                             | wisp-js (10) | wisp-js (5x10) | wisp-mux (10) | wisp-mux (5x10) |
|-----------------------------|--------------|----------------|---------------|-----------------|
| wisp-rust-ws                | 38.56        | 95.11          | 239.52        | 137.17          |
| wisp-js                     | DNF          | 11.1           | 66.82         | 48.48           |
| wisp-server-python          | 3.27         | 13.71          | 51.38         | 35.34           |
| epoxy-server (singlethread) | 110.17       | 89.49          | 231.68        | 149.68          |
| epoxy-server (multithread)  | 114.57       | 172.41         | 322.9         | 344.17          |
| mrrowisp                    | 124.75       | 191.84         | 543.19        | 615.04          |

Manual re-measurement of the two `wisp-rust-ws` wisp-mux cells immediately
after the run, under the same (late-run) load conditions mrrowisp enjoyed:

- `wisp-mux (10)`: 572 MiB/s (vs mrrowisp's in-suite 543.19)
- `wisp-mux (5x10)`: 366 MiB/s (vs mrrowisp's in-suite 615.04, epoxy-mt 344.17)

### Earlier reference runs (same machine, 10 s cells)

2026-05-31 (`../wispmark/wisp-rust-ws.md`):

|                             | wisp-js (10) | wisp-js (5x10) | wisp-mux (10) | wisp-mux (5x10) |
|-----------------------------|--------------|----------------|---------------|-----------------|
| wisp-rust-ws                | 203.21       | 292.14         | 677.69        | 756.4           |
| wisp-js                     | 254.48       | 78.98          | 87.42         | 265.25          |
| wisp-server-python          | 2.22         | 106.34         | 143.05        | 110.65          |
| epoxy-server (singlethread) | 418.35       | 431.75         | 604.34        | 650.3           |
| epoxy-server (multithread)  | 293.85       | 223.54         | 0.0           | 554.57          |
| mrrowisp                    | 356.87       | 331.35         | 585.09        | 635.18          |

2026-05-31 (`../wispmark/wispmark-run.log`, later run):

|                             | wisp-js (10) | wisp-js (5x10) | wisp-mux (10) | wisp-mux (5x10) |
|-----------------------------|--------------|----------------|---------------|-----------------|
| wisp-rust-ws                | 472.89       | 491.45         | 670.05        | 1002.37         |
| wisp-js                     | 368.01       | 230.0          | 389.87        | 411.7           |
| wisp-server-python          | 0.0          | 126.47         | 161.45        | 165.03          |
| epoxy-server (singlethread) | 510.02       | 501.5          | 809.46        | 724.84          |
| epoxy-server (multithread)  | 459.09       | 621.54         | 548.29        | 661.33          |
| mrrowisp                    | 523.25       | 752.35         | 1036.54       | 1275.07         |

2026-05-31 (`../wispmark-wt/wispmark-wt-results.md`):

|                             | wisp-js (10) | wisp-js (5x10) | wisp-mux (10) | wisp-mux (5x10) |
|-----------------------------|--------------|----------------|---------------|-----------------|
| wisp-rust-ws                | 460.57       | 494.7          | 1074.38       | 906.5           |
| wisp-rust-wt                | N/A          | N/A            | N/A           | N/A             |
| wisp-js                     | 363.72       | 356.92         | 454.31        | 409.84          |
| wisp-server-python          | 1.36         | 131.85         | 166.13        | 148.53          |
| epoxy-server (singlethread) | 518.78       | 596.43         | 910.73        | 744.45          |
| epoxy-server (multithread)  | 551.9        | 556.52         | 657.63        | 573.42          |
| mrrowisp                    | 536.96       | 724.68         | 1046.76       | 1270.97         |

(All values MiB/s. The 2026-06-01 `wispmark-results.md` run recorded
`wisp-rust-ws` at 0.0 across the board — that was the port-whitelist default
described above, not a performance result.)

## Assessment: is wisp-rust the fastest?

Not conclusively — it is in the top tier but does not consistently win.

Across all clean runs, three servers form the top tier: `wisp-rust-ws`,
`epoxy-server`, and `mrrowisp`. `wisp-js` and `wisp-server-python` are far
behind everywhere. Within the top tier:

- Single-client relay (`wisp-mux (10)`): `wisp-rust-ws` is competitive with or
  ahead of everything — 1074 vs mrrowisp's 1046 in the best clean run, and
  572 vs 543 in today's like-for-like recheck.
- Multi-process high concurrency (`wisp-mux (5x10)`): `mrrowisp` usually
  leads — 1275 vs wisp-rust's 1002 and 1270 vs 906 in the two clean runs where
  both completed, and it led today as well. One 2026-05-31 run had wisp-rust
  ahead (756 vs 635), so the gap is within observed run-to-run variance, but
  the direction is consistent: mrrowisp wins `5x10` more often than not.

Verdict: `wisp-rust-ws` is roughly tied for fastest at single-connection relay
throughput and typically second to `mrrowisp` (Go) under multi-process load on
this machine.

### Why the gap at high concurrency (likely causes)

- Per-frame bookkeeping on the hot path. Even with the bench config's
  effectively-unlimited rate limits, DoS byte/stream accounting
  (`wisp-dos`), stream policy checks, and tracing hooks still execute per
  event. mrrowisp's bench config disables its equivalents outright
  (`enableStreamConfirm=false`, no deflate, empty lists).
- Buffering: the relay reads in 64 KiB chunks (`READ_CHUNK` in
  `wisp-wisp-server/src/stream.rs`); mrrowisp's bench config uses 128 KiB TCP
  buffers. Larger chunks mean fewer syscalls and WS frames per byte at
  saturation.
- Scheduling: Go's netpoller plus goroutine-per-stream spreads 50 clients
  across 10 cores with very low per-task overhead; tokio does the same in
  principle, but the observed epoxy numbers (same runtime) suggest the Rust
  WS servers lose slightly more to task wakeup/frame overhead at this
  concurrency on macOS.
- Not build flags: the release profile is already maximal (opt-level 3,
  `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, mimalloc as the
  global allocator).

### Benchmarking pitfalls that look like slowness (but are policy)

- `wisp.destination.port_whitelist` defaults to `[80, 443]` — a bench that
  forgets to whitelist the echo port measures 0.0 MiB/s while everything
  "works". This is what zeroed the 2026-06-01 recorded run.
- Production rate-limit defaults (`max_tcp_bytes_per_connection_per_second =
  64 MiB`, `max_tcp_bytes_per_ip_per_second = 256 MiB`) would cap any
  benchmark run with defaults left in place.
- `idle_timeout_ms` (default 120 000) doubles as the SIGTERM drain window;
  harnesses that restart servers between cells must lower it or the previous
  `wispd` lingers for two minutes.
- Protocol inspection defers upstream connects until protocol bytes are
  validated; the harness disables it, production keeps it on.

### Not yet measured

- `wisp-rust-wt` (WebTransport/QUIC over msquic with BBR, MaxThroughput bench
  profile): the `../wispmark-wt` harness has the server row, but no
  WebTransport-capable client is installed, so it has only ever recorded
  `N/A`/`DNF`. The QUIC path's throughput is unverified by wispmark.

### Reproducing

See `.claude/skills/wispmark/SKILL.md` (local, gitignored) for the full
runbook, or in short: build the WS-only binary with
`arch -arm64 cargo build --release -p wispd --no-default-features --features ws`
(Rosetta shell caveat), then
`cd ../wispmark && ./wispmark.sh --duration 10 --output wispmark-results-$(date +%F).md`
on an otherwise idle machine.

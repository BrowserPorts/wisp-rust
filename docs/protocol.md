# wisp-wt — A WebTransport-Native Multiplexing Proxy Protocol

## About

wisp-wt is the WebTransport binding of the Wisp proxy family. It reuses Wisp's
goals — low overhead, easy to implement, a single proxy connection that
multiplexes many TCP and UDP flows — but rebuilds the protocol around the
primitives WebTransport already provides: bidirectional streams, unidirectional
streams, unreliable datagrams, per-stream flow control, and QUIC-level stream
priority.

Wisp itself is a WebSocket protocol. To carry multiple streams over a single
WebSocket, it had to invent an in-band framing layer (`Stream ID` on every
packet, `CONNECT` / `CONTINUE` / `DATA` / `CLOSE` packet types) on top of the
single byte-pipe WebSocket gives you. wisp-wt does not. A new bidi stream is a
new stream. A UDP packet is a QUIC datagram. Per-flow backpressure is the QUIC
stream's own flow-control window. The control bidi only carries events the
transport itself cannot express (open this UDP flow, close that upstream
session, exchange capability info).

The result is a smaller frame catalog (10 control frames, not 5 packet types
with stream IDs threaded through every byte) and a much shorter hot path —
data bytes are never re-wrapped, they ride the WebTransport stream raw.

This document specifies the protocol. The Rust reference implementation lives
in `wisp-wt-rust/`.

## Transport Assumptions

wisp-wt requires a WebTransport session, which in practice means HTTP/3 over
QUIC. The protocol depends on:

- **Bidirectional streams** with FIN and RESET semantics.
- **Unidirectional streams** in both directions.
- **Unreliable datagrams** (RFC 9221 QUIC datagrams).
- **Per-stream QUIC flow control.**
- **QUIC stream priority** (`QUIC_PARAM_STREAM_PRIORITY` in msquic; equivalent
  send-order knobs in other stacks).
- **QUIC datagram priority** (`QUIC_SEND_FLAG_DGRAM_PRIORITY` in msquic).

Implementations on a transport that does not expose stream priority or
datagram priority MAY ignore those fields without violating the protocol —
the bytes are always present, they simply have no effect.

All multi-byte integers are little-endian. Strings are never null-terminated.

## Endianness and Numeric Types

| Type     | Width | Encoding             |
|----------|-------|----------------------|
| `u8`     | 1 B   | raw                  |
| `u16`    | 2 B   | little-endian        |
| `u32`    | 4 B   | little-endian        |
| `i32`    | 4 B   | little-endian, two's complement |

`char[]` always means raw UTF-8 bytes with an externally-known length.

## Frame Format

The control bidi (see [Session Lifecycle](#session-lifecycle)) carries a
stream of length-prefixed frames:

| Field Name | Field Type | Notes                                          |
|------------|------------|------------------------------------------------|
| Body Length | `u32` | Number of bytes in `Frame Type + Payload`. |
| Frame Type  | `u8`  | Frame type byte, covered in the next section. |
| Payload     | `char[]` | Payload occupies the remaining `Body Length - 1` bytes. |

The 4-byte length prefix delimits each frame inside the byte stream — readers
must read exactly `Body Length` bytes before parsing the type and payload.
There is no `Stream ID` field; new flows are opened by either a new
WebTransport stream or a control frame, not by inventing IDs in-band.

## Frame Types

### `0x01` - INFO

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Extension Data | `char[]` | A sequence of negotiable extension entries. |

#### Behavior

INFO is the first frame on the control bidi in both directions. The client
sends INFO; the server replies with INFO. Each side advertises the list of
negotiable extensions it is willing to use. The negotiated set is the
intersection of the two lists.

Extension Data is encoded as a sequence of entries:

| Field Name | Field Type | Notes |
|------------|------------|-------|
| Extension ID | `u8`  | The id of the extension. |
| Payload Length | `u32` | Length of `Extension Payload` in bytes. |
| Extension Payload | `char[]` | Extension-defined data; may be empty. |

Entries are read until the end of the INFO payload. An empty extension list is
valid and means the peer advertises no negotiable extensions; only the
baked-in transport features are available.

### `0x02` - READY

#### Payload Format
The READY payload is empty.

#### Behavior

Sent by the server immediately after its INFO. Marks the end of the handshake.
After receiving READY the client may open data streams, send datagrams, and
send any control frame other than INFO.

The server MUST NOT accept data streams or process datagrams from the client
until it has both sent its own INFO and READY frames. Implementations MAY
allow the client to send those bytes optimistically before READY arrives — the
server simply buffers them until READY has been written — but observable
behavior MUST be as if data is processed only after READY.

### `0x03` - CLOSE

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Close Reason | `u8` | The reason for closing the session. |

#### Behavior

CLOSE is the session-level shutdown frame. Either side MAY send CLOSE at any
time after the handshake; the receiver SHOULD treat it as a request to wind
down and close the WebTransport session. Individual flow closures use
flow-specific frames (`UDP_CLOSE`, `WT_PROXY_CLOSE`) or transport-level
signals (TCP bridge: stream FIN/RESET), not CLOSE.

Close reasons mirror Wisp where they have a one-to-one analogue:

- `0x01` — Reason unspecified or unknown.
- `0x02` — Voluntary closure.
- `0x03` — Unexpected closure due to a network error.
- `0x04` — Incompatible extensions.
- `0x41` — Stream creation failed due to invalid information.
- `0x42` — Stream creation failed due to an unreachable destination host.
- `0x43` — Stream creation timed out.
- `0x44` — Stream creation refused by the destination server.
- `0x47` — TCP data transfer timed out.
- `0x48` — Stream destination is intentionally blocked by the proxy.
- `0x49` — Connection throttled by the server.
- `0x81` — The client has encountered an unexpected error.

### `0x04` - CONTROL

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Text | `char[]` | UTF-8 text payload. |

#### Behavior

CONTROL carries free-form UTF-8 text from server to client. It is the wisp-wt
analogue of the server MOTD that older Wisp implementations advertised as an
extension. The server MAY send CONTROL at any time after sending READY. The
client SHOULD surface the text to the user where appropriate but MUST NOT
parse it as machine-readable data.

A peer MAY send CONTROL frames in the reverse direction; implementations that
do not handle them MUST ignore them rather than treat them as an error.

### `0x05` - UDP_OPEN

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Port | `u16` | Destination UDP port. |
| Hostname Length | `u16` | Length of `Hostname` in bytes. |
| Hostname | `char[]` | UTF-8 destination hostname. |

#### Behavior

Sent by the client to ask the server to open a new UDP flow to the named
hostname and port. The UDP extension (`0x01`) MUST have been negotiated; if
it was not, the server MUST close the session with a CLOSE reason of `0x04`.

On success the server resolves the hostname, opens an upstream UDP socket
honoring any configured destination policy (blocklists, port whitelists,
private-IP rules), and replies with `UDP_OPENED` containing the server-chosen
`flow_id`. On failure the server replies with `UDP_CLOSE` carrying the
appropriate reason byte (typically `0x41`, `0x42`, or `0x48`).

Flow ids are server-assigned 32-bit identifiers, unique per session and
opaque to the client. They are reused across the datagram and per-flow uni
carriers (see [Per-Flow UDP Uni Streams](#per-flow-udp-uni-streams)).

### `0x06` - UDP_OPENED

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Flow Id | `u32` | The server-assigned flow id. |

#### Behavior

Sent by the server in response to a successful `UDP_OPEN`. Once the client
sees `UDP_OPENED` it may begin sending datagrams (or per-flow uni chunks)
tagged with this flow id. The server may also begin emitting downstream UDP
packets on this flow id before the client sends anything.

### `0x07` - UDP_CLOSE

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Flow Id | `u32` | The flow to tear down. |
| Reason | `u8` | Close reason byte (see [CLOSE](#0x03---close)). |

#### Behavior

Either side may send `UDP_CLOSE` to tear down an active UDP flow. The
receiver MUST immediately stop forwarding packets for the flow and free any
state associated with it. Subsequent datagrams or uni chunks tagged with that
flow id MUST be dropped silently.

`UDP_CLOSE` is also how the server reports failure to open a flow — sending
it in response to `UDP_OPEN` before any `UDP_OPENED` has been emitted.

### `0x08` - WT_PROXY_OPEN

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| URL Length | `u16` | Length of `URL` in bytes. |
| URL | `char[]` | UTF-8 WebTransport URL of the upstream proxy. |

#### Behavior

Sent by the client to ask the server to open an upstream WebTransport
session and bridge its streams and datagrams back through the wisp-wt
session. The WEBTRANSPORT_PROXY extension (`0x02`) MUST have been
negotiated; if it was not, the server MUST CLOSE with `0x04`.

The server validates the URL against any configured upstream-proxy policy,
opens an upstream WebTransport session, and replies with `WT_PROXY_OPENED`
carrying a server-chosen `session_id`. On failure the server replies with
`WT_PROXY_CLOSE` carrying the upstream error code and an explanatory reason
string.

### `0x09` - WT_PROXY_OPENED

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Session Id | `u32` | The server-assigned upstream-session id. |

#### Behavior

Acknowledges a successful `WT_PROXY_OPEN`. After receiving this frame the
client may open `WT_PROXY_SUB` bidirectional streams (see
[Bidirectional Streams](#bidirectional-streams)) tagged with this `session_id`
to multiplex its data over the upstream WebTransport session.

### `0x0a` - WT_PROXY_CLOSE

#### Payload Format
| Field Name | Field Type | Notes |
|------------|------------|-------|
| Session Id | `u32` | The upstream session to tear down. |
| Code | `u32` | Application close code from the upstream session. |
| Reason Length | `u16` | Length of `Reason` in bytes. |
| Reason | `char[]` | UTF-8 close reason from the upstream session. |

#### Behavior

Reports closure of an upstream WebTransport session. Either side may send it;
the receiver MUST stop forwarding any further streams or datagrams tagged
with the session id and free the local state. `Code` and `Reason` are passed
through from the underlying WebTransport `CLOSE_WEBTRANSPORT_SESSION` capsule
so the client can surface them to the application.

## Bidirectional Streams

Every bidirectional WebTransport stream other than the control bidi carries a
priority-prefixed header that selects its purpose.

### Header Format

| Field Name | Field Type | Notes |
|------------|------------|-------|
| Priority | `i32` | Send order hint for the underlying QUIC stream. |
| Kind | `u8` | Stream kind discriminator, see below. |

`Priority` is signed; higher values send earlier. msquic-backed
implementations pass this value into `QUIC_PARAM_STREAM_PRIORITY` directly.
Stacks that do not expose stream priority MUST still parse the field — they
simply do not act on it.

The current kinds are:

- `0x01` — TCP bridge.
- `0x02` — WT_PROXY sub-stream.

Unknown kinds MUST cause the stream to be closed with a RESET.

### `0x01` - TCP

The header tail for a TCP bridge stream is:

| Field Name | Field Type | Notes |
|------------|------------|-------|
| Port | `u16` | Destination TCP port. |
| Hostname Length | `u16` | Length of `Hostname` in bytes. |
| Hostname | `char[]` | UTF-8 destination hostname. |

After the header, the stream is a raw byte pipe to the destination TCP
socket. Bytes from the client are forwarded to the destination; bytes from
the destination are forwarded back to the client. No additional framing is
added — there is no `DATA` packet, no buffer accounting, no `CONTINUE`. QUIC
stream flow control supplies backpressure in both directions.

Close semantics:

- Clean destination EOF → the server `FIN`s its half of the WebTransport
  stream (equivalent to Wisp `CLOSE 0x02`).
- Destination error → the server `RESET`s the stream with the Wisp close
  reason as the QUIC application error code.
- Client `FIN` → the server closes the destination TCP socket cleanly.
- Client `RESET` → the server closes the destination TCP socket and surfaces
  the QUIC application error code where possible.

### `0x02` - WT_PROXY_SUB

The header tail is:

| Field Name | Field Type | Notes |
|------------|------------|-------|
| Session Id | `u32` | The upstream WT-proxy session this sub-stream belongs to. |

After the header the stream is bridged byte-for-byte onto a new
bidirectional stream of the named upstream WebTransport session. The session
must have been previously opened with `WT_PROXY_OPEN` / `WT_PROXY_OPENED`.
If the session id is unknown the server MUST `RESET` the sub-stream.

### Unidirectional Server Replies

The server uses unidirectional streams (in the server-to-client direction)
for one-shot frames that would otherwise have to share head-of-line with the
control bidi. Specifically:

- The reply to `WT_PROXY_OPEN` — either `WT_PROXY_OPENED` or
  `WT_PROXY_CLOSE` — is written to a fresh server-opened uni stream and the
  stream is FIN-closed.
- Out-of-band `CONTROL` text frames MAY also ride a server-opened uni stream
  rather than the control bidi.

These uni streams carry exactly one length-prefixed frame in the same format
as the control bidi. Recipients MUST read the 4-byte length prefix, then
exactly that many bytes, then expect EOF.

## Datagrams

UDP packets and bridged upstream WT-proxy datagrams ride QUIC datagrams. Every
datagram carries a 6-byte header so the receiver can demultiplex without any
session state beyond the flow id table.

| Field Name | Field Type | Notes |
|------------|------------|-------|
| Class | `u8` | Priority class. |
| Kind | `u8` | Datagram kind discriminator. |
| Flow Id | `u32` | UDP flow or upstream WT-proxy session id. |
| Payload | `char[]` | Datagram payload — rest of the QUIC datagram. |

`Class` values:

| Value | Name | Behavior |
|-------|------|----------|
| `0` | BULK | Best-effort. May be deprioritized behind interactive traffic. |
| `1` | NORMAL | Default for any flow that hasn't been classified. |
| `2` | INTERACTIVE | Latency-sensitive. msquic-backed servers send these with `QUIC_SEND_FLAG_DGRAM_PRIORITY`. |

A peer that does not implement priority classes MUST still emit a valid byte
(typically `NORMAL = 1`) and MUST accept any class value from its peer
without error.

`Kind` values:

| Value | Name | Description |
|-------|------|-------------|
| `0x00` | UDP | UDP flow — `Flow Id` is a `UDP_OPENED` flow id. |
| `0x01` | WT_PROXY | Bridged upstream datagram — `Flow Id` is a `WT_PROXY_OPENED` session id. |

Datagrams with unknown kinds MUST be dropped silently.

Datagrams are unreliable. Implementations SHOULD drop server-side datagrams
that have aged past `WISP_WT_PROXY_UPSTREAM_DATAGRAM_MAX_AGE_MS` (1000 ms) in
the egress queue.

## Per-Flow UDP Uni Streams

A noisy UDP flow can starve every other flow that shares the connection-wide
datagram queue. To bound that interference, wisp-wt allows each UDP flow to
ride a dedicated unidirectional stream in each direction. Each peer MAY open
a uni stream the first time it sends UDP data for a flow; once opened, all
subsequent UDP data for that flow MUST ride the uni stream rather than the
datagram path, until the flow is closed.

The uni stream begins with a 4-byte prelude:

| Field Name | Field Type | Notes |
|------------|------------|-------|
| Flow Id | `u32` | The UDP flow this stream carries. |

Followed by a sequence of length-prefixed chunks:

| Field Name | Field Type | Notes |
|------------|------------|-------|
| Length | `u16` | Length of `Payload` in bytes. |
| Payload | `char[]` | One UDP packet. |

Each chunk corresponds to exactly one UDP datagram. The stream is closed by
sending `UDP_CLOSE` on the control bidi for the flow id and FIN-ing the uni
stream. The receiver MUST stop reading chunks once it has seen `UDP_CLOSE`
for the flow, even if more bytes are pending.

Because the uni stream gets its own QUIC flow-control window, a hot UDP flow
can backpressure naturally without consuming the shared datagram budget.

## Negotiable Extensions

Most of the transport-flavored features above (stream priority, datagram
priority classes, server uni replies, per-flow UDP uni streams) are baked
into the protocol unconditionally — every spec-compliant WebTransport server
can implement them, so negotiation is unnecessary. The extension list in
INFO is reserved for features that genuinely vary between implementations.

The negotiable extensions are:

### `0x01` - UDP

The presence of this extension indicates the implementation supports UDP
proxying — the `UDP_OPEN` / `UDP_OPENED` / `UDP_CLOSE` frames, UDP datagrams,
and per-flow UDP uni streams. There is no payload.

If a client sends `UDP_OPEN` to a server that did not advertise UDP, the
server MUST close the session with reason `0x04`.

### `0x02` - WEBTRANSPORT_PROXY

The presence of this extension indicates the server is willing to bridge
upstream WebTransport sessions on the client's behalf — the `WT_PROXY_OPEN`
/ `WT_PROXY_OPENED` / `WT_PROXY_CLOSE` frames and `WT_PROXY_SUB` bidi
streams. There is no payload.

If a client sends `WT_PROXY_OPEN` to a server that did not advertise this
extension, the server MUST close the session with reason `0x04`.

### `0x03` - STELLITE_PROXY_CONTROL

A Stellite-specific control channel used by deployments that pair wisp-wt
with the Stellite proxy fabric. The exact semantics are deployment-defined
and out of scope for this document. There is no payload.

Implementations that do not understand this extension MUST simply not
advertise it; servers that do not advertise it MUST close the session with
reason `0x04` if the client unilaterally invokes a Stellite-only feature.

### Adding New Extensions

Future extensions are assigned ids `0x04` and above. Each extension is
defined by:

- A numeric id, unique within the extension namespace.
- An optional INFO payload (default: empty).
- A specification of which frames, stream kinds, or datagram kinds it
  unlocks, and how the peer behaves when those primitives are used without
  the extension being negotiated.

Reference implementations expose this via the `Extension` trait in the
`wisp-wire` crate — each extension is a zero-sized type with `const ID`
and `const NAME`, registered into the server's `ExtensionRegistry` during
startup.

## Session Lifecycle

1. The client establishes a WebTransport session against the server's
   configured endpoint (see [WebTransport Entry](#webtransport-entry)).
2. The client opens the **control bidi** — the first bidirectional stream of
   the session. Implementations SHOULD raise its QUIC stream priority to the
   maximum so control frames preempt bulk data.
3. The client writes an `INFO` frame on the control bidi.
4. The server reads `INFO`, computes the negotiated extension set, and
   replies with its own `INFO` followed immediately by `READY`.
5. The session is now active. Data streams, datagrams, and any non-INFO
   control frames may flow in either direction.
6. To wind the session down, either side sends `CLOSE` on the control bidi
   and then closes the WebTransport session. Mid-session per-flow closures
   use the flow-specific frames (`UDP_CLOSE`, `WT_PROXY_CLOSE`) or
   transport-level signals (`FIN` / `RESET` on a TCP bridge stream).

The handshake never round-trips for authentication or MOTD. Deployments that
need authentication MUST gate the WebTransport upgrade itself (TLS client
certificates, signed URLs, an authenticating proxy in front of the server,
etc.).

## WebTransport Entry

The server listens on an HTTP/3 endpoint and accepts WebTransport sessions
via the standard extended-CONNECT handshake:

- HTTP method: `CONNECT`.
- `:protocol` pseudo-header: `webtransport`.
- `:path`: matches the server's configured wisp-wt endpoint path (defaults
  vary by deployment; the reference Rust server's default is `/`).

The server MUST enforce its configured `Origin` policy on the upgrade
request itself, before responding to the CONNECT. WebTransport always
includes the `Origin` header; servers MUST NOT skip this check.

Requests that do not match the configured wisp-wt path are out of scope for
this protocol; the server typically returns `404 Not Found`.

## Reference Implementations

- **Rust** — `wisp-wt-rust/` (this repository). msquic-backed.

Golden round-trip vectors for every frame, bidi header, datagram, and
uni-stream framing in this document live under `#[cfg(test)]` in
`wisp-wt-rust/crates/wisp-wire/src/lib.rs`.

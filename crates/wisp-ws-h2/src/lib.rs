//! HTTP/2 transport for the Wisp v2 WebSocket server.
//!
//! Listens on TCP, terminates TLS, runs hyper's HTTP/2 server with
//! `enable_connect_protocol`, and dispatches extended-CONNECT
//! `:protocol = websocket` requests through `tokio-websockets`'
//! `ServerBuilder::serve` (handshake-skipping mode for post-H2-CONNECT).
//! The resulting WS stream is handed to [`wisp_wisp_server::serve_connection`].
//!
//! Policy ordering mirrors the legacy bun server:
//!  1. path matches the configured wisp endpoint
//!  2. extended-CONNECT method + `:protocol = websocket`
//!  3. Origin header policy via [`wisp_origin`]
//!  4. (Future) DoS connection-start allowance — wired once a per-connection
//!     IP is known. The client IP comes from the underlying TCP peer.
//!
//! Anything that fails policy returns the appropriate HTTP status before
//! the upgrade is attempted, so the WS handshake never completes for a
//! rejected request.

#![forbid(unsafe_code)]

pub mod listener;
pub mod service;

pub use listener::{accept_h2_connection, H2ServeContext};

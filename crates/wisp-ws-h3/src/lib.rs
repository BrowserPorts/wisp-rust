//! HTTP/3 transport for the Wisp v2 WebSocket server, sharing the same
//! msquic listener as wisp-wt's WebTransport endpoint.
//!
//! With the workspace `[patch.crates-io]` pinning `h3` to the master
//! revision that ships `Protocol::WEBSOCKET`, callers can dispatch on
//! the typed enum directly; legacy raw-string comparison is no longer
//! required.

#![forbid(unsafe_code)]

pub mod dispatch;
pub mod frame;

pub use dispatch::{serve_h3_websocket, H3WsContext, H3WsError, MsQuicBidi};
pub use frame::{Decoder, FrameError, InboundFrame};

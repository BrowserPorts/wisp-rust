//! HTTP/3 transport for the Wisp v2 WebSocket server, sharing the same
//! msquic listener as the WebTransport endpoint.
//!
//! The workspace pins `h3` to a revision that ships `Protocol::WEBSOCKET`,
//! so callers dispatch on the typed protocol enum directly rather than
//! comparing the raw `:protocol` header string.

#![forbid(unsafe_code)]

pub mod dispatch;
pub mod frame;

pub use dispatch::{serve_h3_websocket, H3WsContext, H3WsError, MsQuicBidi};
pub use frame::{Decoder, FrameError, InboundFrame};

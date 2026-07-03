//! Single-process router that owns the TCP+UDP :443 listeners and
//! dispatches extended-CONNECT requests to either the WebTransport
//! handler ([`wisp_server`]) or the Wisp WebSocket handler
//! ([`wisp_wisp_server`]) depending on the negotiated `:protocol`.
//!
//! Today the router exposes the TCP/H2/WS side. UDP/H3 multiplexing
//! (WT + future WS-over-H3) lives in [`wisp_server`] for now and the
//! router is the seam where the two are unified once the H3 crate
//! grows a `:protocol = websocket` variant (see task #46).

#![forbid(unsafe_code)]

pub mod tls;
pub mod ws_h2;
pub mod ws_plain;

pub use ws_h2::{serve_ws_h2_listener, WsH2ListenerConfig, WsH2ListenerError};
pub use ws_plain::{serve_ws_plain_listener, WsPlainListenerConfig, WsPlainListenerError};

//! Single-process router that owns the TCP `:443` listeners and dispatches
//! extended-CONNECT requests to the Wisp WebSocket handler
//! ([`wisp_wisp_server`]) based on the negotiated `:protocol`.
//!
//! The router exposes the TCP/H2/WS side. UDP/H3 multiplexing lives in the
//! H3 transport and the router is the seam where the two are unified once
//! that transport grows a `:protocol = websocket` variant.

#![forbid(unsafe_code)]

mod accept;
pub mod tls;
pub mod ws_h2;
mod ws_http1;
pub mod ws_plain;

pub use ws_h2::{
    bind_ws_h2_listener, serve_bound_ws_h2_listener, serve_ws_h2_listener, WsH2ListenerConfig,
    WsH2ListenerError,
};
pub use ws_plain::{
    bind_ws_plain_listener, serve_bound_ws_plain_listener, serve_ws_plain_listener,
    WsPlainListenerConfig, WsPlainListenerError,
};

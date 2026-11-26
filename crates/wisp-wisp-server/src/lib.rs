//! Wisp v2 server: protocol-level connection handling that drives
//! [`wisp-wisp`] codec, the egress extension point in [`ProxyControllerTemplate`],
//! and the shared [`wisp-inspect`] / [`wisp-origin`] / [`wisp-dos`] subsystems.
//!
//! Transport-agnostic: the entry point [`serve_connection`] takes a
//! message-oriented sink+stream of [`bytes::Bytes`] payloads. Each payload
//! is one Wisp v2 packet (one WebSocket message). The H2 and H3 transports
//! in [`wisp-ws-h2`] / [`wisp-ws-h3`] adapt their WS-message streams to
//! this interface after the extended CONNECT upgrade succeeds.

#![forbid(unsafe_code)]

mod budget;
mod connection;
mod proxy_control;
mod stream;
mod tunnel;
mod udp;

pub use budget::{buffered_bytes_total, set_max_buffered_bytes_total};
pub use connection::{
    serve_connection, ServerContext, ServerError, ServerOptions, TransportError, WispMessage,
};
pub use proxy_control::{
    handle_proxy_control_text, EgressDialer, EgressIpBudget, EgressPlugin, EgressReport,
    EgressReportKind, EgressRoute, EgressSession, EgressSessionInit, ProxyConnectError,
    ProxyControlLimits, ProxyController, ProxyControllerTemplate,
};
pub use stream::ConnectError;
pub use wisp_tun::TunnelService;

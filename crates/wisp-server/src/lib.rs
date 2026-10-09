//! Wisp-WT session lifecycle.
//!
//! QUIC-impl-agnostic on its upper surface: it speaks to the
//! [`wisp_quic_msquic::adapter`] stream types via small traits, so the same
//! session core can be exercised in unit tests with in-memory channels.
//!
//! Public surface:
//!
//! - [`SessionContext`] — per-connection state (client IP, DoS guard,
//!   negotiated extensions).
//! - [`negotiate_handshake`] — exchange INFO frames over the control bidi,
//!   intersect the offered set with implemented extensions, send READY.
//! - [`PreUpgradePolicy`] — origin/IP/DoS gates run before responding to
//!   the H3 extended CONNECT, returning the 403 body + headers on reject.
//! - [`SessionDispatch`] — frame-loop driver over the control stream.

pub mod control;
pub mod handshake;
pub mod policy;
pub mod serve;
pub mod session;
pub mod udp_flow;
pub mod wt_proxy;

pub use control::{ControlOutcome, SessionDispatch};
pub use handshake::{negotiate_handshake, HandshakeError, HandshakeOutcome};
pub use policy::{PreUpgradePolicy, PreUpgradeRejection};
pub use serve::{serve, ServeError, ServeExtras, ServeHandle};
pub use session::SessionContext;
pub use wisp_ws_h3::H3WsContext;

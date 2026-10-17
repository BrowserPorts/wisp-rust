//! `h3::quic::Connection<Bytes>` adapter over msquic. Bridges msquic's
//! callback API to async via per-stream mpsc channels and exposes a
//! `set_priority(u16)` shim on send streams.
//!
//! This crate is split into two layers:
//!
//! 1. [`engine`] — synchronous bootstrap of the msquic registration,
//!    configuration, and listener with the transport settings (BBR,
//!    RFC 9221 datagrams, msquic's default flow-control windows, Retry for
//!    every new address, no resumption).
//!
//! 2. [`adapter`] — the `h3::quic::Connection<Bytes>` impl plus stream
//!    pumps that turn the msquic callback model into async streams.
//!
//! ## macOS dev build note
//!
//! The bundled msquic source build invokes the quictls submodule via cmake.
//! On macOS with command-line tools 21+, the bundled clang's `inttypes.h`
//! does an `#include_next <inttypes.h>` that requires the macOS SDK to be
//! on the include path. Set `SDKROOT=$(xcrun --sdk macosx --show-sdk-path)`
//! before `cargo build` and the build succeeds. Linux and Docker (the
//! deployment platform) need no env changes.

#![deny(unsafe_code)]

pub mod adapter;
pub mod engine;

pub use engine::{EngineConfig, MsQuicEngine};

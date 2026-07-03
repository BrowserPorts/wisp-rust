//! `h3::quic::Connection<Bytes>` adapter over msquic. Bridges msquic's
//! callback API to async via per-stream mpsc channels and exposes a
//! `set_priority(u16)` shim mirroring `web-transport-quinn::SendStream`.
//!
//! ## Status
//!
//! This crate is intentionally split into two layers:
//!
//! 1. [`engine`] — synchronous bootstrap of the msquic registration,
//!    configuration, and listener with the Wispmark-tuned settings (BBR,
//!    RFC 9221 datagrams, 64 MiB connection flow-control window).
//!    Compiles and exercised by unit tests.
//!
//! 2. *Async adapter* — the `h3::quic::Connection<Bytes>` impl plus stream
//!    pumps that turn the msquic callback model into async streams. Staged
//!    in [`adapter`] (skeletal) for follow-up; the trait surface is
//!    exposed so [`wisp-server`] can be built against it before the
//!    pump bodies are filled in.
//!
//! ## macOS dev build note
//!
//! The bundled msquic source build invokes the quictls submodule via cmake.
//! On macOS with command-line tools 21+, the bundled clang's `inttypes.h`
//! does an `#include_next <inttypes.h>` that requires the macOS SDK to be
//! on the include path. Set `SDKROOT=$(xcrun --sdk macosx --show-sdk-path)`
//! before `cargo build` and the build succeeds. Linux and Docker (the
//! deployment platform) need no env changes.

// `adapter` invokes msquic's set_param / send / from_raw FFI shims behind
// safety comments; the rest of the crate stays safe-only by review.

pub mod adapter;
pub mod engine;

pub use engine::{EngineConfig, MsQuicEngine};

//! Wisp-WT control-bidi handshake.
//!
//! Sequence:
//!   1. read client INFO
//!   2. intersect the client set with implemented server extensions
//!   3. send server INFO and READY
//!
//! There is no extra round trip — KEY_AUTH / MOTD / PASSWORD_AUTH are gone.
//! The transport plumbing is abstracted behind [`ControlIo`] so tests drive
//! the handshake over in-memory channels without standing up h3-webtransport.

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashSet;
use thiserror::Error;
use wisp_wire::{
    decode_frame_body, encode_info_frame, encode_ready_frame, frame_type, parse_extensions,
    parse_info_payload, ExtensionRegistry, Udp, WireError,
};

use crate::session::SessionContext;

/// Minimal transport surface the handshake needs over the control bidi.
#[async_trait]
pub trait ControlIo: Send {
    async fn read_frame(&mut self) -> Result<Bytes, ControlIoError>;
    async fn write_frame(&mut self, frame: Bytes) -> Result<(), ControlIoError>;
}

#[derive(Debug, Error)]
pub enum ControlIoError {
    #[error("control stream closed")]
    Closed,
    #[error("control io error: {0}")]
    Io(String),
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("control io: {0}")]
    Io(#[from] ControlIoError),
    #[error("frame: {0}")]
    Frame(#[from] WireError),
    #[error("first frame must be INFO, got {0:#x}")]
    NotInfo(u8),
}

#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    /// Extension ids intersection of client INFO and server INFO.
    pub negotiated: HashSet<u8>,
}

/// Build the default registry with only fully implemented extensions.
pub fn default_server_registry() -> ExtensionRegistry {
    let mut reg = ExtensionRegistry::new();
    reg.register::<Udp>();
    reg
}

/// Run the handshake on `io` advertising the default registry. Mutates
/// `ctx.negotiated` on success.
pub async fn negotiate_handshake(
    io: &mut dyn ControlIo,
    ctx: &mut SessionContext,
) -> Result<HandshakeOutcome, HandshakeError> {
    let registry = if ctx.options.allow_udp_streams {
        default_server_registry()
    } else {
        ExtensionRegistry::new()
    };
    negotiate_handshake_with(io, ctx, &registry).await
}

/// Run the handshake on `io` advertising a caller-supplied registry.
pub async fn negotiate_handshake_with(
    io: &mut dyn ControlIo,
    ctx: &mut SessionContext,
    registry: &ExtensionRegistry,
) -> Result<HandshakeOutcome, HandshakeError> {
    let frame = io.read_frame().await?;
    let parsed = decode_frame_body(&frame)?;
    if parsed.frame_type != frame_type::INFO {
        return Err(HandshakeError::NotInfo(parsed.frame_type));
    }
    let info = parse_info_payload(&parsed.payload)?;
    let client_exts = parse_extensions(&info.extensions)?;
    let client_ids: HashSet<u8> = client_exts.iter().map(|e| e.id).collect();
    let negotiated = registry.intersect_ids(&client_ids);

    io.write_frame(encode_info_frame(registry.entries()))
        .await?;
    io.write_frame(encode_ready_frame()).await?;
    ctx.negotiated = negotiated.clone();
    Ok(HandshakeOutcome { negotiated })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use wisp_config::WispServerOptions;
    use wisp_dos::DosGuard;
    use wisp_wire::{
        encode_frame, encode_info_frame, Extension, ExtensionEntry, WebTransportProxy,
    };

    struct ChanIo {
        rx: mpsc::UnboundedReceiver<Bytes>,
        tx: mpsc::UnboundedSender<Bytes>,
    }

    #[async_trait::async_trait]
    impl ControlIo for ChanIo {
        async fn read_frame(&mut self) -> Result<Bytes, ControlIoError> {
            self.rx.recv().await.ok_or(ControlIoError::Closed)
        }
        async fn write_frame(&mut self, frame: Bytes) -> Result<(), ControlIoError> {
            self.tx
                .send(frame)
                .map_err(|e| ControlIoError::Io(e.to_string()))
        }
    }

    fn pair() -> (ChanIo, ChanIo) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        (ChanIo { rx: a_rx, tx: b_tx }, ChanIo { rx: b_rx, tx: a_tx })
    }

    fn make_ctx() -> SessionContext {
        SessionContext::new(
            "1.2.3.4".to_owned(),
            Arc::new(WispServerOptions::default()),
            Arc::new(DosGuard::new()),
        )
    }

    fn strip_len(frame_with_prefix: &[u8]) -> Bytes {
        Bytes::copy_from_slice(&frame_with_prefix[4..])
    }

    #[tokio::test]
    async fn happy_path() {
        let (mut server_io, mut client_io) = pair();
        let mut ctx = make_ctx();

        let client_info = encode_info_frame(&[
            ExtensionEntry {
                id: Udp::ID,
                payload: Bytes::new(),
            },
            ExtensionEntry {
                id: WebTransportProxy::ID,
                payload: Bytes::new(),
            },
        ]);
        client_io
            .write_frame(strip_len(&client_info))
            .await
            .unwrap();

        let outcome = negotiate_handshake(&mut server_io, &mut ctx).await.unwrap();
        assert!(outcome.negotiated.contains(&Udp::ID));
        assert!(!outcome.negotiated.contains(&WebTransportProxy::ID));
        assert!(ctx.has::<Udp>());

        let server_info = client_io.read_frame().await.unwrap();
        let parsed = decode_frame_body(&server_info[4..]).unwrap();
        assert_eq!(parsed.frame_type, frame_type::INFO);
        let ready = client_io.read_frame().await.unwrap();
        let parsed_ready = decode_frame_body(&ready[4..]).unwrap();
        assert_eq!(parsed_ready.frame_type, frame_type::READY);
    }

    #[tokio::test]
    async fn rejects_wrong_first_frame() {
        let (mut server_io, mut client_io) = pair();
        let mut ctx = make_ctx();
        let bad = encode_frame(frame_type::READY, &[]);
        client_io.write_frame(strip_len(&bad)).await.unwrap();
        let err = negotiate_handshake(&mut server_io, &mut ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, HandshakeError::NotInfo(_)));
    }

    #[tokio::test]
    async fn custom_registry_suppresses_extension() {
        let (mut server_io, mut client_io) = pair();
        let mut ctx = make_ctx();
        let mut registry = ExtensionRegistry::new();
        registry.register::<Udp>();

        let client_info = encode_info_frame(&[
            ExtensionEntry {
                id: Udp::ID,
                payload: Bytes::new(),
            },
            ExtensionEntry {
                id: WebTransportProxy::ID,
                payload: Bytes::new(),
            },
        ]);
        client_io
            .write_frame(strip_len(&client_info))
            .await
            .unwrap();
        let outcome = negotiate_handshake_with(&mut server_io, &mut ctx, &registry)
            .await
            .unwrap();
        assert!(outcome.negotiated.contains(&Udp::ID));
        assert!(!outcome.negotiated.contains(&WebTransportProxy::ID));
    }

    #[tokio::test]
    async fn configured_registry_negotiates_wt_proxy() {
        let (mut server_io, mut client_io) = pair();
        let mut ctx = make_ctx();
        let mut registry = ExtensionRegistry::new();
        registry.register::<WebTransportProxy>();

        let client_info = encode_info_frame(&[ExtensionEntry {
            id: WebTransportProxy::ID,
            payload: Bytes::new(),
        }]);
        client_io
            .write_frame(strip_len(&client_info))
            .await
            .unwrap();
        let outcome = negotiate_handshake_with(&mut server_io, &mut ctx, &registry)
            .await
            .unwrap();
        assert!(outcome.negotiated.contains(&WebTransportProxy::ID));
        assert!(ctx.has::<WebTransportProxy>());
    }
}

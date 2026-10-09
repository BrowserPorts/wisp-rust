//! Per-connection session state. Shared by the handshake, control loop, and
//! per-stream/datagram pumps.

use std::collections::HashSet;
use std::sync::Arc;
use wisp_config::WispServerOptions;
use wisp_dos::{ConnectionDosGuard, DosGuard};
use wisp_wire::Extension;

/// Carries everything a session task needs that isn't the WT session itself.
/// Cloned across the handshake and the control / stream / datagram pumps.
#[derive(Clone)]
pub struct SessionContext {
    pub client_ip: String,
    pub client_hash: Option<String>,
    pub options: Arc<WispServerOptions>,
    pub dos: Arc<DosGuard>,
    pub conn_dos: Arc<ConnectionDosGuard>,
    /// Set of extension IDs advertised by both peers (0x01 UDP, 0x02
    /// WEBTRANSPORT_PROXY, 0x03 WISP_PROXY_CONTROL). All other
    /// features are baked-in and are not represented here.
    pub negotiated: HashSet<u8>,
}

impl SessionContext {
    pub fn new(client_ip: String, options: Arc<WispServerOptions>, dos: Arc<DosGuard>) -> Self {
        Self {
            client_ip,
            client_hash: None,
            options,
            dos,
            conn_dos: Arc::new(ConnectionDosGuard::new()),
            negotiated: HashSet::new(),
        }
    }

    pub fn with_client_hash(mut self, hash: Option<String>) -> Self {
        self.client_hash = hash;
        self
    }

    /// `true` if the named extension id was advertised by both peers in INFO.
    /// Prefer the typed [`SessionContext::has`] for known extensions.
    pub fn has_extension(&self, id: u8) -> bool {
        self.negotiated.contains(&id)
    }

    /// `true` if the typed extension was negotiated. Preferred over
    /// [`has_extension`](Self::has_extension) for known extensions because
    /// the type system catches typos in extension references.
    pub fn has<E: Extension>(&self) -> bool {
        self.negotiated.contains(&E::ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_wire::{Extension, Udp, WebTransportProxy};

    #[test]
    fn has_extension_round_trips() {
        let mut ctx = SessionContext::new(
            "1.2.3.4".to_owned(),
            Arc::new(WispServerOptions::default()),
            Arc::new(DosGuard::new()),
        );
        assert!(!ctx.has::<Udp>());
        assert!(!ctx.has_extension(Udp::ID));
        ctx.negotiated.insert(Udp::ID);
        assert!(ctx.has::<Udp>());
        assert!(ctx.has_extension(Udp::ID));
        assert!(!ctx.has::<WebTransportProxy>());
    }
}

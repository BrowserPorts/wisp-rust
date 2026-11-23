//! Post-handshake control-stream dispatch loop.
//!
//! Reads frames from the control bidi, dispatches CONTROL / UDP_OPEN /
//! UDP_CLOSE / WT_PROXY_OPEN / WT_PROXY_CLOSE / CLOSE, fires the appropriate
//! actions in [`SessionContext`], and returns when the peer closes the
//! control stream or the runtime cancels.
//!
//! The actual side effects (open a UDP flow, open a WT-proxy session, etc.)
//! are pushed onto a [`ControlSink`] trait so this module stays unit-testable
//! against a recording sink.

use async_trait::async_trait;
use thiserror::Error;
use wisp_dos::is_control_message_allowed;
use wisp_wire::{
    decode_frame_body, frame_type, parse_close_payload, parse_control_payload,
    parse_tunnel_close_payload, parse_tunnel_payload, parse_udp_close_payload,
    parse_udp_open_payload, parse_wt_proxy_close_payload, parse_wt_proxy_open_payload,
    ProxyControl, TunnelClose, TunnelFrame, Udp, UdpClose, UdpOpenFrame, WebTransportProxy,
    WireError, WtProxyClose,
};

use crate::handshake::{ControlIo, ControlIoError};
use crate::session::SessionContext;

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("control io: {0}")]
    Io(#[from] ControlIoError),
    #[error("frame: {0}")]
    Frame(#[from] WireError),
    #[error("rate limited")]
    RateLimited,
}

/// Why the control loop returned: one of the three terminal cases for a
/// control bidi.
#[derive(Debug, Clone)]
pub enum ControlOutcome {
    /// Peer sent a CLOSE frame with the given reason byte.
    PeerClose { reason: u8 },
    /// Peer FIN'd the control stream without an explicit CLOSE.
    PeerEof,
    /// Local error closed the loop.
    Error(String),
}

/// Side-effect surface. The session task installs this; tests use a recorder.
#[async_trait]
pub trait ControlSink: Send {
    async fn on_control_text(&mut self, text: String);
    async fn on_udp_open(&mut self, frame: UdpOpenFrame);
    async fn on_udp_close(&mut self, frame: UdpClose);
    async fn on_wt_proxy_open(&mut self, url: String);
    async fn on_wt_proxy_close(&mut self, frame: WtProxyClose);
    async fn on_tunnel_open(&mut self, frame: TunnelFrame);
    async fn on_tunnel_close(&mut self, frame: TunnelClose);
    async fn on_tunnel_capsules(&mut self, frame: TunnelFrame);
}

/// Drives a single post-handshake control bidi.
pub struct SessionDispatch<'a> {
    pub ctx: &'a SessionContext,
}

impl<'a> SessionDispatch<'a> {
    pub fn new(ctx: &'a SessionContext) -> Self {
        Self { ctx }
    }

    /// Read frames until the peer closes or an error occurs.
    pub async fn run(&self, io: &mut dyn ControlIo, sink: &mut dyn ControlSink) -> ControlOutcome {
        loop {
            let frame = match io.read_frame().await {
                Ok(f) => f,
                Err(ControlIoError::Closed) => return ControlOutcome::PeerEof,
                Err(e) => return ControlOutcome::Error(e.to_string()),
            };
            let parsed = match decode_frame_body(&frame) {
                Ok(p) => p,
                Err(e) => return ControlOutcome::Error(e.to_string()),
            };
            // UDP_OPEN spends the stream-open budget in the sink and UDP_CLOSE
            // only frees a flow, so neither counts against the control-message
            // budget, whose overflow ends the whole session (and whose per-IP
            // share is common to every client behind one address).
            // TUNNEL_OPEN and TUNNEL_CLOSE likewise spend the tunnel limits.
            let udp_flow_frame = matches!(
                parsed.frame_type,
                frame_type::UDP_OPEN
                    | frame_type::UDP_CLOSE
                    | frame_type::TUNNEL_OPEN
                    | frame_type::TUNNEL_CLOSE
            );
            if !udp_flow_frame
                && !is_control_message_allowed(
                    &self.ctx.client_ip,
                    &self.ctx.conn_dos,
                    &self.ctx.options,
                    &self.ctx.dos,
                )
            {
                return ControlOutcome::Error("control rate limit".to_owned());
            }
            match parsed.frame_type {
                frame_type::CLOSE => {
                    let reason = parse_close_payload(&parsed.payload).unwrap_or(0);
                    return ControlOutcome::PeerClose { reason };
                }
                frame_type::CONTROL => {
                    if !self.ctx.has::<ProxyControl>() {
                        return ControlOutcome::Error(
                            "proxy control extension was not negotiated".to_owned(),
                        );
                    }
                    if let Ok(text) = parse_control_payload(&parsed.payload) {
                        sink.on_control_text(text).await;
                    }
                }
                frame_type::UDP_OPEN if !self.ctx.has::<Udp>() => {
                    return ControlOutcome::Error("UDP extension was not negotiated".to_owned());
                }
                frame_type::UDP_OPEN => match parse_udp_open_payload(&parsed.payload) {
                    Ok(frame) => sink.on_udp_open(frame).await,
                    Err(e) => return ControlOutcome::Error(e.to_string()),
                },
                frame_type::UDP_CLOSE if !self.ctx.has::<Udp>() => {
                    return ControlOutcome::Error("UDP extension was not negotiated".to_owned());
                }
                frame_type::UDP_CLOSE => match parse_udp_close_payload(&parsed.payload) {
                    Ok(frame) => sink.on_udp_close(frame).await,
                    Err(e) => return ControlOutcome::Error(e.to_string()),
                },
                frame_type::WT_PROXY_OPEN if !self.ctx.has::<WebTransportProxy>() => {
                    return ControlOutcome::Error(
                        "WebTransport proxy extension was not negotiated".to_owned(),
                    );
                }
                frame_type::WT_PROXY_OPEN => match parse_wt_proxy_open_payload(&parsed.payload) {
                    Ok(url) => sink.on_wt_proxy_open(url).await,
                    Err(e) => return ControlOutcome::Error(e.to_string()),
                },
                frame_type::WT_PROXY_CLOSE if !self.ctx.has::<WebTransportProxy>() => {
                    return ControlOutcome::Error(
                        "WebTransport proxy extension was not negotiated".to_owned(),
                    );
                }
                frame_type::WT_PROXY_CLOSE => match parse_wt_proxy_close_payload(&parsed.payload) {
                    Ok(frame) => sink.on_wt_proxy_close(frame).await,
                    Err(e) => return ControlOutcome::Error(e.to_string()),
                },
                frame_type::TUNNEL_OPEN
                | frame_type::TUNNEL_OPENED
                | frame_type::TUNNEL_CLOSE
                | frame_type::TUNNEL_CAPSULES
                    if self.ctx.ip_tunnel.is_none() =>
                {
                    return ControlOutcome::Error(
                        "IP tunnel extension was not negotiated".to_owned(),
                    );
                }
                frame_type::TUNNEL_OPENED => {
                    return ControlOutcome::Error("TUNNEL_OPENED is the server's".to_owned());
                }
                frame_type::TUNNEL_OPEN => match parse_tunnel_payload(&parsed.payload) {
                    Ok(frame) => sink.on_tunnel_open(frame).await,
                    Err(e) => return ControlOutcome::Error(e.to_string()),
                },
                frame_type::TUNNEL_CLOSE => match parse_tunnel_close_payload(&parsed.payload) {
                    Ok(frame) => sink.on_tunnel_close(frame).await,
                    Err(e) => return ControlOutcome::Error(e.to_string()),
                },
                frame_type::TUNNEL_CAPSULES => match parse_tunnel_payload(&parsed.payload) {
                    Ok(frame) => sink.on_tunnel_capsules(frame).await,
                    Err(e) => return ControlOutcome::Error(e.to_string()),
                },
                _ => {}
            }
        }
    }
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
        encode_close_frame, encode_control_frame, encode_frame, encode_udp_close_frame,
        encode_udp_open_frame, encode_wt_proxy_open_frame, Extension,
    };

    struct ChanIo {
        rx: mpsc::UnboundedReceiver<Bytes>,
    }
    #[async_trait::async_trait]
    impl ControlIo for ChanIo {
        async fn read_frame(&mut self) -> Result<Bytes, ControlIoError> {
            self.rx.recv().await.ok_or(ControlIoError::Closed)
        }
        async fn write_frame(&mut self, _: Bytes) -> Result<(), ControlIoError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Recorder {
        controls: Vec<String>,
        udp_opens: Vec<UdpOpenFrame>,
        udp_closes: Vec<UdpClose>,
        wt_opens: Vec<String>,
        wt_closes: Vec<WtProxyClose>,
        tunnel_opens: Vec<TunnelFrame>,
        tunnel_closes: Vec<TunnelClose>,
        tunnel_capsules: Vec<TunnelFrame>,
    }
    #[async_trait::async_trait]
    impl ControlSink for Recorder {
        async fn on_control_text(&mut self, text: String) {
            self.controls.push(text);
        }
        async fn on_udp_open(&mut self, frame: UdpOpenFrame) {
            self.udp_opens.push(frame);
        }
        async fn on_udp_close(&mut self, frame: UdpClose) {
            self.udp_closes.push(frame);
        }
        async fn on_wt_proxy_open(&mut self, url: String) {
            self.wt_opens.push(url);
        }
        async fn on_wt_proxy_close(&mut self, frame: WtProxyClose) {
            self.wt_closes.push(frame);
        }
        async fn on_tunnel_open(&mut self, frame: TunnelFrame) {
            self.tunnel_opens.push(frame);
        }
        async fn on_tunnel_close(&mut self, frame: TunnelClose) {
            self.tunnel_closes.push(frame);
        }
        async fn on_tunnel_capsules(&mut self, frame: TunnelFrame) {
            self.tunnel_capsules.push(frame);
        }
    }

    fn make_ctx() -> SessionContext {
        SessionContext::new(
            "1.2.3.4".to_owned(),
            Arc::new(WispServerOptions::default()),
            Arc::new(DosGuard::new()),
        )
    }

    fn body(framed: &[u8]) -> Bytes {
        Bytes::copy_from_slice(&framed[4..])
    }

    #[tokio::test]
    async fn dispatches_control_udp_then_close() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(body(&encode_control_frame("ping"))).unwrap();
        tx.send(body(&encode_udp_open_frame("example.com", 53)))
            .unwrap();
        tx.send(body(&encode_udp_close_frame(7, 3))).unwrap();
        tx.send(body(&encode_close_frame(0x42))).unwrap();
        let mut io = ChanIo { rx };
        let mut rec = Recorder::default();
        let mut ctx = make_ctx();
        ctx.negotiated.insert(ProxyControl::ID);
        ctx.negotiated.insert(Udp::ID);
        let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
        assert!(matches!(
            outcome,
            ControlOutcome::PeerClose { reason: 0x42 }
        ));
        assert_eq!(rec.controls, vec!["ping".to_owned()]);
        assert_eq!(rec.udp_opens.len(), 1);
        assert_eq!(rec.udp_opens[0].port, 53);
        assert_eq!(rec.udp_closes.len(), 1);
        assert_eq!(rec.udp_closes[0].flow_id, 7);
    }

    #[tokio::test]
    async fn udp_flow_frames_do_not_spend_the_control_budget() {
        let options = WispServerOptions {
            max_control_messages_per_connection_per_minute: 2,
            ..WispServerOptions::default()
        };
        let mut ctx = SessionContext::new(
            "1.2.3.4".to_owned(),
            Arc::new(options),
            Arc::new(DosGuard::new()),
        );
        ctx.negotiated.insert(Udp::ID);
        ctx.negotiated.insert(ProxyControl::ID);
        let (tx, rx) = mpsc::unbounded_channel();
        for flow in 0..50 {
            tx.send(body(&encode_udp_open_frame("example.com", 53)))
                .unwrap();
            tx.send(body(&encode_udp_close_frame(flow, 0))).unwrap();
        }
        // The control budget still applies to everything else.
        for _ in 0..3 {
            tx.send(body(&encode_control_frame("ping"))).unwrap();
        }
        tx.send(body(&encode_close_frame(0x02))).unwrap();
        let mut io = ChanIo { rx };
        let mut rec = Recorder::default();
        let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
        assert_eq!(rec.udp_opens.len(), 50);
        assert_eq!(rec.udp_closes.len(), 50);
        assert_eq!(rec.controls.len(), 2);
        assert!(matches!(outcome, ControlOutcome::Error(ref e) if e == "control rate limit"));
    }

    fn tunnel_ctx() -> SessionContext {
        let mut ctx = make_ctx();
        ctx.negotiated.insert(wisp_wire::IpTunnel::ID);
        ctx.ip_tunnel = Some(wisp_ip::Negotiated {
            version: 1,
            flags: 0x3f,
            max_tunnels: 1,
            link_mtu: 1500,
            max_packet: 1500,
        });
        ctx
    }

    #[tokio::test]
    async fn dispatches_the_tunnel_frames() {
        use wisp_wire::{encode_tunnel_close_frame, encode_tunnel_frame};
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(body(&encode_tunnel_frame(
            frame_type::TUNNEL_OPEN,
            7,
            &[0x01, 0x00, 0x02, 0x00, 0x05, 0x00],
        )))
        .unwrap();
        tx.send(body(&encode_tunnel_frame(
            frame_type::TUNNEL_CAPSULES,
            7,
            &[],
        )))
        .unwrap();
        tx.send(body(&encode_tunnel_close_frame(7, 0x02))).unwrap();
        tx.send(body(&encode_close_frame(0x02))).unwrap();
        let mut io = ChanIo { rx };
        let mut rec = Recorder::default();
        let ctx = tunnel_ctx();
        let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
        assert!(matches!(
            outcome,
            ControlOutcome::PeerClose { reason: 0x02 }
        ));
        assert_eq!(rec.tunnel_opens.len(), 1);
        assert_eq!(rec.tunnel_opens[0].tunnel_id, 7);
        assert_eq!(
            rec.tunnel_opens[0].capsules.as_ref(),
            &[0x01, 0x00, 0x02, 0x00, 0x05, 0x00]
        );
        assert_eq!(rec.tunnel_capsules.len(), 1);
        assert_eq!(rec.tunnel_closes.len(), 1);
        assert_eq!(rec.tunnel_closes[0].reason, 0x02);
    }

    #[tokio::test]
    async fn tunnel_frames_need_the_extension_and_the_right_direction() {
        use wisp_wire::encode_tunnel_frame;
        for (frame, ctx) in [
            (
                encode_tunnel_frame(frame_type::TUNNEL_OPEN, 1, &[]),
                make_ctx(),
            ),
            (
                encode_tunnel_frame(frame_type::TUNNEL_OPENED, 1, &[]),
                tunnel_ctx(),
            ),
            (encode_frame(frame_type::TUNNEL_OPEN, &[1, 2]), tunnel_ctx()),
            (
                encode_frame(frame_type::TUNNEL_CLOSE, &[1, 0, 0, 0]),
                tunnel_ctx(),
            ),
        ] {
            let (tx, rx) = mpsc::unbounded_channel();
            tx.send(body(&frame)).unwrap();
            let mut io = ChanIo { rx };
            let mut rec = Recorder::default();
            let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
            assert!(matches!(outcome, ControlOutcome::Error(_)), "{frame:?}");
            assert!(rec.tunnel_opens.is_empty());
        }
    }

    #[tokio::test]
    async fn tunnel_opens_do_not_spend_the_control_budget() {
        use wisp_wire::{encode_tunnel_close_frame, encode_tunnel_frame};
        let options = WispServerOptions {
            max_control_messages_per_connection_per_minute: 2,
            ..WispServerOptions::default()
        };
        let mut ctx = SessionContext::new(
            "1.2.3.4".to_owned(),
            Arc::new(options),
            Arc::new(DosGuard::new()),
        );
        ctx.negotiated.insert(wisp_wire::IpTunnel::ID);
        ctx.ip_tunnel = tunnel_ctx().ip_tunnel;
        let (tx, rx) = mpsc::unbounded_channel();
        for id in 0..20 {
            tx.send(body(&encode_tunnel_frame(frame_type::TUNNEL_OPEN, id, &[])))
                .unwrap();
            tx.send(body(&encode_tunnel_close_frame(id, 2))).unwrap();
        }
        tx.send(body(&encode_close_frame(0x02))).unwrap();
        let mut io = ChanIo { rx };
        let mut rec = Recorder::default();
        let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
        assert_eq!(rec.tunnel_opens.len(), 20);
        assert!(matches!(outcome, ControlOutcome::PeerClose { .. }));
    }

    #[tokio::test]
    async fn returns_peer_eof_when_channel_closes() {
        let (_tx, rx) = mpsc::unbounded_channel();
        drop(_tx);
        let mut io = ChanIo { rx };
        let mut rec = Recorder::default();
        let ctx = make_ctx();
        let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
        assert!(matches!(outcome, ControlOutcome::PeerEof));
    }

    #[tokio::test]
    async fn rejects_unnegotiated_wt_proxy_open() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(body(&encode_wt_proxy_open_frame(
            "https://upstream.example/wisp-wt",
        )))
        .unwrap();
        tx.send(body(&encode_close_frame(0x02))).unwrap();
        let mut io = ChanIo { rx };
        let mut rec = Recorder::default();
        let ctx = make_ctx();
        let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
        assert!(matches!(outcome, ControlOutcome::Error(_)));
    }

    #[tokio::test]
    async fn dispatches_negotiated_wt_proxy_frames() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(body(&encode_wt_proxy_open_frame(
            "https://upstream.example/wisp-wt/token",
        )))
        .unwrap();
        tx.send(body(&wisp_wire::encode_wt_proxy_close_frame(9, 4, "bye")))
            .unwrap();
        tx.send(body(&encode_close_frame(0x02))).unwrap();
        let mut io = ChanIo { rx };
        let mut rec = Recorder::default();
        let mut ctx = make_ctx();
        ctx.negotiated.insert(WebTransportProxy::ID);
        let outcome = SessionDispatch::new(&ctx).run(&mut io, &mut rec).await;
        assert!(matches!(outcome, ControlOutcome::PeerClose { .. }));
        assert_eq!(rec.wt_opens, vec!["https://upstream.example/wisp-wt/token"]);
        assert_eq!(rec.wt_closes.len(), 1);
        assert_eq!(rec.wt_closes[0].session_id, 9);
    }
}

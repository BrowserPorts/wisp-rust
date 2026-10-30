//! IP tunnels on the WebSocket binding (extension 0xF3).
//!
//! A tunnel lives on a stream id. The client opens it with a TUNNEL packet
//! whose first capsule is OPEN; the server answers on the same stream id with
//! a TUNNEL carrying the open confirmation (addresses, routes, link, and when
//! available resolvers and a resume token), or refuses it with a CLOSE. From
//! then on each DATA on that stream id is one IP packet either way. DATA on a
//! tunnel is not counted against CONTINUE credit and draws no CONTINUE, as
//! for UDP: a packet that cannot be forwarded at once is dropped. CLOSE from
//! either side ends the tunnel; FIN on a tunnel is a protocol error.
//!
//! Opening runs in its own task, since building the tunnel's network takes
//! a while; its outcome comes back to the connection loop as a
//! [`TunnelEvent`]. Each open tunnel has a pump task that writes the packets
//! the tunnel delivers as DATA frames. When the connection ends, its tunnels
//! are detached: a tunnel with a resume token waits for the client to come
//! back.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wisp_ip::capsule::error_code;
use wisp_ip::{close_reason, encode_capsules, parse_capsules, Capsule, Negotiated};
use wisp_tun::{credential_may_open, OpenError, OpenRequest, Opened, TunnelHandle, TunnelService};
use wisp_wisp::{encode_close, encode_data, encode_tunnel};

use crate::connection::{EgressSender, ServerContext, ServerError, WispMessage};

/// What the connection loop hears back from tunnel tasks.
pub(crate) enum TunnelEvent {
    Opened {
        stream_id: u32,
        generation: u64,
        opened: Box<Opened>,
    },
    Failed {
        stream_id: u32,
        generation: u64,
        error: OpenError,
    },
    /// The pump ended on its own: the tunnel was resumed elsewhere, or its
    /// network went away.
    Ended {
        stream_id: u32,
        generation: u64,
        reason: u8,
    },
}

enum Slot {
    Opening {
        generation: u64,
        cancel: CancellationToken,
    },
    Open {
        generation: u64,
        handle: TunnelHandle,
        close: CancellationToken,
        detach: CancellationToken,
    },
}

impl Slot {
    fn generation(&self) -> u64 {
        match self {
            Slot::Opening { generation, .. } | Slot::Open { generation, .. } => *generation,
        }
    }
}

/// A connection's tunnels, by stream id.
pub(crate) struct Tunnels {
    service: Option<Arc<TunnelService>>,
    negotiated: Option<Negotiated>,
    slots: HashMap<u32, Slot>,
    next_generation: u64,
    events: mpsc::Sender<TunnelEvent>,
}

impl Tunnels {
    pub(crate) fn new(
        service: Option<Arc<TunnelService>>,
        negotiated: Option<Negotiated>,
        events: mpsc::Sender<TunnelEvent>,
    ) -> Self {
        Self {
            service,
            negotiated,
            slots: HashMap::new(),
            next_generation: 1,
            events,
        }
    }

    pub(crate) fn contains(&self, stream_id: u32) -> bool {
        self.slots.contains_key(&stream_id)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// One IP packet from the client. Dropped while the tunnel is opening:
    /// the client must wait for the confirmation.
    pub(crate) fn data(&self, stream_id: u32, payload: Bytes) {
        if let Some(Slot::Open { handle, .. }) = self.slots.get(&stream_id) {
            let outcome = handle.forward(payload);
            tracing::trace!(stream_id, ?outcome, "wisp: tunnel packet");
        }
    }

    /// A TUNNEL packet from the client. `taken` says the stream id belongs
    /// to a TCP or UDP stream.
    pub(crate) async fn on_tunnel(
        &mut self,
        stream_id: u32,
        capsules: Bytes,
        taken: bool,
        ctx: &ServerContext,
        egress: &EgressSender,
    ) -> Result<(), ServerError> {
        let (Some(service), Some(negotiated)) = (self.service.clone(), self.negotiated) else {
            return Err(ServerError::ProtocolViolation(
                "TUNNEL without negotiated IP_TUNNEL",
            ));
        };
        if stream_id == 0 {
            return Err(ServerError::ProtocolViolation(
                "stream_id 0 reserved for control channel",
            ));
        }
        if taken {
            return Err(ServerError::StreamCollision(stream_id));
        }
        let parsed = parse_capsules(&capsules);
        if let Some(slot) = self.slots.get(&stream_id) {
            // Later control on a tunnel: nothing the client sends later
            // changes it in version 1, but a bad capsule or a second OPEN
            // ends it.
            let bad = match &parsed {
                Err(_) => true,
                Ok(list) => list.iter().any(|c| matches!(c, Capsule::Open { .. })),
            };
            if bad {
                let generation = slot.generation();
                return self
                    .close_with(stream_id, generation, close_reason::INVALID_INFO, egress)
                    .await;
            }
            return Ok(());
        }
        let capsules = match parsed {
            Ok(list) => list,
            Err(e) => {
                tracing::debug!(stream_id, error = %e, "wisp: tunnel open with bad capsules");
                return send_close(stream_id, close_reason::INVALID_INFO, egress).await;
            }
        };
        let Some(Capsule::Open { want }) = capsules.first().cloned() else {
            return send_close(stream_id, close_reason::INVALID_INFO, egress).await;
        };
        if !credential_may_open(&ctx.options) {
            return send_close(stream_id, close_reason::BLOCKED, egress).await;
        }
        if self.slots.len() >= usize::from(negotiated.max_tunnels) {
            let refusal = encode_capsules(&[Capsule::Error {
                code: error_code::TOO_MANY_TUNNELS,
                message: "too many tunnels on this connection".to_owned(),
            }]);
            send(egress, encode_tunnel(stream_id, &refusal)).await?;
            return send_close(stream_id, close_reason::THROTTLED, egress).await;
        }
        let resume = capsules.iter().find_map(|c| match c {
            Capsule::Resume { token } => Some(*token),
            _ => None,
        });
        let request = OpenRequest {
            want,
            resume,
            principal: ctx.principal.clone(),
            client_ip: ctx.client_ip.clone(),
            policy: ctx.policy.clone(),
            negotiated,
            max_datagram_payload: 0,
        };
        let generation = self.next_generation;
        self.next_generation += 1;
        let cancel = CancellationToken::new();
        self.slots.insert(
            stream_id,
            Slot::Opening {
                generation,
                cancel: cancel.clone(),
            },
        );
        let events = self.events.clone();
        tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancel.cancelled() => return,
                result = service.open(request) => result,
            };
            let event = match result {
                Ok(opened) => TunnelEvent::Opened {
                    stream_id,
                    generation,
                    opened: Box::new(opened),
                },
                Err(error) => TunnelEvent::Failed {
                    stream_id,
                    generation,
                    error,
                },
            };
            if let Err(mpsc::error::SendError(TunnelEvent::Opened { opened, .. })) =
                events.send(event).await
            {
                // The connection is gone; the client never saw the token.
                opened.tunnel.close();
            }
        });
        Ok(())
    }

    /// A CLOSE from the client on a tunnel's stream id.
    pub(crate) fn on_close(&mut self, stream_id: u32) {
        match self.slots.remove(&stream_id) {
            Some(Slot::Opening { cancel, .. }) => cancel.cancel(),
            Some(Slot::Open { close, .. }) => close.cancel(),
            None => {}
        }
    }

    pub(crate) async fn on_event(
        &mut self,
        event: TunnelEvent,
        egress: &EgressSender,
    ) -> Result<(), ServerError> {
        match event {
            TunnelEvent::Opened {
                stream_id,
                generation,
                opened,
            } => {
                let current = matches!(
                    self.slots.get(&stream_id),
                    Some(Slot::Opening { generation: g, .. }) if *g == generation
                );
                if !current {
                    opened.tunnel.close();
                    return Ok(());
                }
                let Opened {
                    tunnel,
                    confirmation,
                    resumed,
                } = *opened;
                tracing::debug!(
                    stream_id,
                    tunnel = tunnel.id(),
                    resumed,
                    "wisp: tunnel open"
                );
                // The confirmation is queued ahead of every packet.
                send(
                    egress,
                    encode_tunnel(stream_id, &encode_capsules(&confirmation)),
                )
                .await?;
                let close = CancellationToken::new();
                let detach = CancellationToken::new();
                self.slots.insert(
                    stream_id,
                    Slot::Open {
                        generation,
                        handle: tunnel.handle(),
                        close: close.clone(),
                        detach: detach.clone(),
                    },
                );
                tokio::spawn(pump(
                    tunnel,
                    stream_id,
                    generation,
                    egress.clone(),
                    close,
                    detach,
                    self.events.clone(),
                ));
                Ok(())
            }
            TunnelEvent::Failed {
                stream_id,
                generation,
                error,
            } => {
                if self.slots.get(&stream_id).map(Slot::generation) != Some(generation) {
                    return Ok(());
                }
                self.slots.remove(&stream_id);
                tracing::debug!(stream_id, error = %error, "wisp: tunnel open refused");
                if let Some(capsule) = error.error_capsule() {
                    send(
                        egress,
                        encode_tunnel(stream_id, &encode_capsules(&[capsule])),
                    )
                    .await?;
                }
                send_close(stream_id, error.close_reason(), egress).await
            }
            TunnelEvent::Ended {
                stream_id,
                generation,
                reason,
            } => {
                if self.slots.get(&stream_id).map(Slot::generation) != Some(generation) {
                    return Ok(());
                }
                self.slots.remove(&stream_id);
                send_close(stream_id, reason, egress).await
            }
        }
    }

    async fn close_with(
        &mut self,
        stream_id: u32,
        generation: u64,
        reason: u8,
        egress: &EgressSender,
    ) -> Result<(), ServerError> {
        if self.slots.get(&stream_id).map(Slot::generation) == Some(generation) {
            self.on_close(stream_id);
        }
        send_close(stream_id, reason, egress).await
    }

    /// The connection is ending: open tunnels wait for a resume, opening
    /// ones are abandoned.
    pub(crate) fn detach_all(&mut self) {
        for (_, slot) in self.slots.drain() {
            match slot {
                Slot::Opening { cancel, .. } => cancel.cancel(),
                Slot::Open { detach, .. } => detach.cancel(),
            }
        }
    }
}

async fn send(egress: &EgressSender, frame: Bytes) -> Result<(), ServerError> {
    egress
        .send(WispMessage::Binary(frame))
        .await
        .map_err(|()| ServerError::ClientClosed)
}

async fn send_close(stream_id: u32, reason: u8, egress: &EgressSender) -> Result<(), ServerError> {
    send(egress, encode_close(stream_id, reason)).await
}

/// Delivers a tunnel's packets to the client until the tunnel or the
/// connection ends.
async fn pump(
    mut tunnel: wisp_tun::Tunnel,
    stream_id: u32,
    generation: u64,
    egress: EgressSender,
    close: CancellationToken,
    detach: CancellationToken,
    events: mpsc::Sender<TunnelEvent>,
) {
    let stolen = tunnel.stolen();
    tokio::pin!(stolen);
    loop {
        tokio::select! {
            biased;
            _ = close.cancelled() => {
                tunnel.close();
                return;
            }
            _ = detach.cancelled() => {
                tunnel.detach();
                return;
            }
            _ = &mut stolen => {
                tracing::debug!(stream_id, "wisp: tunnel resumed on another connection");
                tunnel.detach();
                let _ = events
                    .send(TunnelEvent::Ended { stream_id, generation, reason: close_reason::VOLUNTARY })
                    .await;
                return;
            }
            packet = tunnel.recv() => match packet {
                Some(packet) => {
                    // A full egress drops the packet, as a congested link does.
                    let _ = egress.try_send(WispMessage::Binary(encode_data(stream_id, &packet)));
                }
                None => {
                    tunnel.close();
                    let _ = events
                        .send(TunnelEvent::Ended { stream_id, generation, reason: close_reason::NETWORK_ERROR })
                        .await;
                    return;
                }
            },
        }
    }
}

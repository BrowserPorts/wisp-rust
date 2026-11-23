//! The machine's uplink: one tunnel for the machine's one Ethernet link,
//! across carrier connections.
//!
//! [`Uplink`] owns a [`Mux`] and a [`Router`]. When a carrier comes up it
//! negotiates the extension and opens the tunnel; the confirmation becomes a
//! [`LinkConfig`] for the machine manager and the router. Frames from the
//! wire go through the router into the tunnel, and the tunnel's packets back
//! out as frames.
//!
//! **Resume (decision LD13).** When the carrier drops with the tunnel open
//! and the relay gave a resume token, the uplink keeps the machine's
//! configuration and waits: a carrier that comes back before the grace
//! period ends reopens with `RESUME`, the relay hands back the same
//! addresses and NAT state, and the machine's TCP connections retransmit
//! through the gap and go on. Frames that arrive meanwhile are dropped, as a
//! cable pulled for a moment drops them. If the relay rejects the token, it
//! opens a new tunnel and says so with `ERROR` 0x0004 inside the
//! confirmation (LS-5 finding 3); the uplink then reports
//! [`Event::LinkUp`] with `flows_lost`, since the addresses can be the same
//! while every NAT mapping is new. Past the grace period the token is not
//! sent at all.

use std::collections::VecDeque;

use wisp_ip::capsule::error_code;
use wisp_ip::info::flags;
use wisp_ip::{close_reason, Capsule, ResumeToken};

use crate::manager::LinkConfig;
use crate::mux::{Carrier, Mux, MuxEvent, MuxStats, Transmit, Unsupported, Wants};
use crate::router::{FromWire, Router, RouterConfig, RouterStats};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UplinkConfig {
    pub wants: Wants,
    pub router: RouterConfig,
    /// How long to wait for the open confirmation before giving the
    /// connection up. The relay builds a network for each tunnel.
    pub open_timeout_ms: u64,
}

impl Default for UplinkConfig {
    fn default() -> Self {
        Self {
            wants: Wants::default(),
            router: RouterConfig::default(),
            open_timeout_ms: 15_000,
        }
    }
}

/// Why the machine's link lost its tunnel for good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkDownReason {
    /// The relay refused the open: a Wisp close reason and the `ERROR`
    /// capsule that came with it.
    Refused {
        reason: u8,
        error: Option<(u16, String)>,
    },
    /// The relay, or this side, closed an open tunnel.
    Closed {
        reason: u8,
        error: Option<(u16, String)>,
    },
    /// The carrier dropped and the tunnel cannot be resumed.
    CarrierLost,
    /// The carrier stayed away past the grace period.
    ResumeExpired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The relay cannot carry tunnels (decision LD4: gex keeps its stream
    /// mode for such a relay). The carrier is being closed.
    Unsupported(Unsupported),
    /// The tunnel is open; `config` is the machine's link. `resumed`: the
    /// relay took the resume token and the machine's flows go on.
    /// `flows_lost`: the machine had a tunnel before and this one is new,
    /// so every NAT mapping is gone even if the addresses are the same.
    LinkUp {
        config: LinkConfig,
        resumed: bool,
        flows_lost: bool,
    },
    /// The relay changed the configuration (a new `ADDRESS_ASSIGN`, ...).
    LinkChanged { config: LinkConfig },
    /// The carrier dropped; reconnect before `resume_until_ms` to resume.
    Detached { resume_until_ms: u64 },
    /// No confirmation in time; the carrier is being closed.
    OpenTimedOut,
    /// The tunnel is gone; its configuration should come off the machine.
    LinkDown { reason: LinkDownReason },
    /// The relay broke the protocol or ended the connection. The carrier is
    /// being closed; [`Uplink::disconnected`] follows.
    ConnectionFailed(String),
}

/// What the uplink wants done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Carrier(Transmit),
    /// One Ethernet frame for the machine's wire device.
    Wire(Vec<u8>),
    Event(Event),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UplinkStats {
    pub mux: MuxStats,
    pub router: RouterStats,
    /// Packets from the machine while the tunnel was not open.
    pub dropped_not_up: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Link {
    Idle,
    Opening { id: u32, since: u64, resuming: bool },
    Up { id: u32 },
    Detached,
}

pub struct Uplink {
    cfg: UplinkConfig,
    mux: Mux,
    router: Router,
    link: Link,
    config: Option<LinkConfig>,
    /// The latest resume token and its grace period in seconds.
    token: Option<(ResumeToken, u32)>,
    /// While detached: the end of the grace period.
    resume_until: Option<u64>,
    /// Whether a tunnel was ever open on this machine.
    had_tunnel: bool,
    out: VecDeque<Output>,
    dropped_not_up: u64,
}

impl Uplink {
    pub fn new(cfg: UplinkConfig) -> Self {
        Self {
            cfg,
            mux: Mux::new(cfg.wants),
            router: Router::new(cfg.router),
            link: Link::Idle,
            config: None,
            token: None,
            resume_until: None,
            had_tunnel: false,
            out: VecDeque::new(),
            dropped_not_up: 0,
        }
    }

    pub fn stats(&self) -> UplinkStats {
        UplinkStats {
            mux: self.mux.stats(),
            router: self.router.stats(),
            dropped_not_up: self.dropped_not_up,
        }
    }

    pub fn mux(&self) -> &Mux {
        &self.mux
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    /// The configuration the tunnel gave the machine, while it holds.
    pub fn config(&self) -> Option<&LinkConfig> {
        self.config.as_ref()
    }

    pub fn is_up(&self) -> bool {
        matches!(self.link, Link::Up { .. })
    }

    /// The id of the open tunnel on the current connection.
    pub fn tunnel_id(&self) -> Option<u32> {
        match self.link {
            Link::Up { id } => Some(id),
            _ => None,
        }
    }

    pub fn poll_output(&mut self) -> Option<Output> {
        self.out.pop_front()
    }

    // ---- carrier ----------------------------------------------------------

    pub fn connected(&mut self, now_ms: u64, carrier: Carrier) {
        if matches!(self.link, Link::Opening { .. } | Link::Up { .. }) {
            // A second connection without a disconnect in between: the
            // old one is gone.
            self.disconnected(now_ms);
        }
        self.mux.connected(carrier);
        self.pump(now_ms);
    }

    pub fn ws_message(&mut self, now_ms: u64, message: &[u8]) {
        self.mux.ws_message(now_ms, message);
        self.pump(now_ms);
    }

    pub fn wt_control(&mut self, now_ms: u64, bytes: &[u8]) {
        self.mux.wt_control(now_ms, bytes);
        self.pump(now_ms);
    }

    pub fn wt_datagram(&mut self, now_ms: u64, datagram: &[u8]) {
        self.mux.wt_datagram(now_ms, datagram);
        self.pump(now_ms);
    }

    pub fn wt_uni(&mut self, now_ms: u64, stream: u64, bytes: &[u8]) {
        self.mux.wt_uni(stream, bytes);
        self.pump(now_ms);
    }

    pub fn wt_uni_end(&mut self, stream: u64) {
        self.mux.wt_uni_end(stream);
    }

    /// The WebTransport session's `maxDatagramSize` changed.
    pub fn set_max_datagram_size(&mut self, size: usize) {
        self.mux.set_max_datagram_size(size);
    }

    /// The carrier connection ended (after a [`Transmit::Close`] too).
    pub fn disconnected(&mut self, now_ms: u64) {
        let resumable =
            self.token.is_some() && self.mux.negotiated().is_none_or(|n| n.has(flags::RESUME));
        self.mux.disconnected();
        match self.link {
            Link::Up { .. } if resumable => {
                let (_, grace_s) = self.token.expect("resumable");
                let until = now_ms + u64::from(grace_s) * 1000;
                self.resume_until = Some(until);
                self.link = Link::Detached;
                self.emit(Event::Detached {
                    resume_until_ms: until,
                });
            }
            Link::Up { .. } => self.link_down(now_ms, LinkDownReason::CarrierLost),
            Link::Opening { resuming: true, .. } => self.link = Link::Detached,
            Link::Opening { .. } => self.link = Link::Idle,
            Link::Idle | Link::Detached => {}
        }
        self.pump(now_ms);
    }

    /// Closes the tunnel and the carrier from this side.
    pub fn close(&mut self, now_ms: u64) {
        if let Link::Up { id } | Link::Opening { id, .. } = self.link {
            self.mux.close(id, close_reason::VOLUNTARY);
            while self.mux.poll_event().is_some() {}
        }
        self.mux_out();
        self.out.push_back(Output::Carrier(Transmit::Close));
        if self.link != Link::Idle {
            self.link_down(
                now_ms,
                LinkDownReason::Closed {
                    reason: close_reason::VOLUNTARY,
                    error: None,
                },
            );
        }
        self.pump(now_ms);
    }

    // ---- wire -------------------------------------------------------------

    /// One Ethernet frame from the machine's wire device.
    pub fn wire_frame(&mut self, now_ms: u64, frame: &[u8]) {
        match self.router.from_wire(frame, now_ms) {
            FromWire::Forward(packet) => match self.link {
                Link::Up { id } => {
                    self.mux.send_packet(now_ms, id, &packet);
                }
                _ => self.dropped_not_up += 1,
            },
            FromWire::Reply(f) => self.out.push_back(Output::Wire(f)),
            FromWire::Drop(_) => {}
        }
        self.pump(now_ms);
    }

    // ---- time -------------------------------------------------------------

    pub fn poll_timeout(&self) -> Option<u64> {
        let open = match self.link {
            Link::Opening { since, .. } => Some(since + self.cfg.open_timeout_ms),
            _ => None,
        };
        let resume = match self.link {
            Link::Detached => self.resume_until,
            _ => None,
        };
        [
            self.mux.poll_timeout(),
            self.router.poll_timeout(),
            open,
            resume,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn handle_timeout(&mut self, now_ms: u64) {
        self.mux.handle_timeout(now_ms);
        self.router.handle_timeout(now_ms);
        if let Link::Opening {
            since, resuming, ..
        } = self.link
        {
            if now_ms >= since + self.cfg.open_timeout_ms {
                // Forget the connection now; the carrier's disconnect that
                // follows the close finds nothing left to do.
                self.mux.disconnected();
                self.link = if resuming { Link::Detached } else { Link::Idle };
                self.emit(Event::OpenTimedOut);
                self.out.push_back(Output::Carrier(Transmit::Close));
            }
        }
        if self.link == Link::Detached && self.resume_until.is_some_and(|t| now_ms >= t) {
            self.link_down(now_ms, LinkDownReason::ResumeExpired);
        }
        self.pump(now_ms);
    }

    // ---- internals --------------------------------------------------------

    fn emit(&mut self, e: Event) {
        self.out.push_back(Output::Event(e));
    }

    fn link_down(&mut self, now_ms: u64, reason: LinkDownReason) {
        self.link = Link::Idle;
        self.token = None;
        self.resume_until = None;
        self.config = None;
        self.router.deconfigure(now_ms);
        self.emit(Event::LinkDown { reason });
    }

    fn mux_out(&mut self) {
        while let Some(t) = self.mux.poll_transmit() {
            self.out.push_back(Output::Carrier(t));
        }
    }

    fn pump(&mut self, now_ms: u64) {
        while let Some(ev) = self.mux.poll_event() {
            self.on_mux(now_ms, ev);
        }
        self.mux_out();
        while let Some(f) = self.router.poll_frame() {
            self.out.push_back(Output::Wire(f));
        }
    }

    fn on_mux(&mut self, now_ms: u64, ev: MuxEvent) {
        match ev {
            MuxEvent::Ready(_) => self.open(now_ms),
            MuxEvent::Unsupported(why) => self.emit(Event::Unsupported(why)),
            MuxEvent::Opened { id, capsules } => self.opened(now_ms, id, &capsules),
            MuxEvent::Control { id, capsules } => {
                if self.link != (Link::Up { id }) {
                    return;
                }
                self.take_token(&capsules);
                if let Some(cfg) = self.config.as_mut() {
                    if cfg.update(&capsules) {
                        let cfg = cfg.clone();
                        self.router.configure(&cfg, now_ms);
                        self.emit(Event::LinkChanged { config: cfg });
                    }
                }
            }
            MuxEvent::Packet { id, packet } => {
                if self.link == (Link::Up { id }) {
                    if let Some(frame) = self.router.to_wire(&packet) {
                        self.out.push_back(Output::Wire(frame));
                    }
                }
            }
            MuxEvent::Closed { id, reason, error } => match self.link {
                Link::Opening { id: open, .. } if open == id => {
                    self.link_down(now_ms, LinkDownReason::Refused { reason, error });
                }
                Link::Up { id: up } if up == id => {
                    self.link_down(now_ms, LinkDownReason::Closed { reason, error });
                }
                _ => {}
            },
            MuxEvent::ConnectionFailed(why) => self.emit(Event::ConnectionFailed(why)),
        }
    }

    fn open(&mut self, now_ms: u64) {
        let token = match self.link {
            Link::Detached if self.resume_until.is_some_and(|t| now_ms < t) => {
                self.token.map(|(t, _)| t)
            }
            _ => None,
        };
        let wants = self.cfg.wants;
        match self.mux.open(wants.ipv4, wants.ipv6, token) {
            Some(id) => {
                self.link = Link::Opening {
                    id,
                    since: now_ms,
                    resuming: token.is_some(),
                };
            }
            None => {
                self.emit(Event::ConnectionFailed(
                    "the relay offers no tunnel this machine can use".to_owned(),
                ));
                self.out.push_back(Output::Carrier(Transmit::Close));
            }
        }
    }

    fn take_token(&mut self, capsules: &[Capsule]) {
        for c in capsules {
            if let Capsule::ResumeToken { grace_s, token } = c {
                self.token = (*grace_s > 0).then_some((*token, *grace_s));
            }
        }
    }

    fn opened(&mut self, now_ms: u64, id: u32, capsules: &[Capsule]) {
        let Link::Opening {
            id: open, resuming, ..
        } = self.link
        else {
            return;
        };
        if open != id {
            return;
        }
        let Some(config) = LinkConfig::from_capsules(capsules) else {
            return;
        };
        let rejected = capsules.iter().any(
            |c| matches!(c, Capsule::Error { code, .. } if *code == error_code::RESUME_REJECTED),
        );
        self.token = None;
        self.take_token(capsules);
        let resumed = resuming && !rejected;
        let flows_lost = self.had_tunnel && !resumed;
        self.had_tunnel = true;
        self.resume_until = None;
        self.link = Link::Up { id };
        self.router.configure(&config, now_ms);
        self.config = Some(config.clone());
        self.emit(Event::LinkUp {
            config,
            resumed,
            flows_lost,
        });
    }
}

#[cfg(test)]
mod tests;

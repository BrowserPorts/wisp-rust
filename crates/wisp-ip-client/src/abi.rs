//! The module's boundary with JavaScript: the uplink Worker's
//! `wisp-ip-carrier` package drives an [`Engine`] through a handful of
//! exports, passing every input and output as bytes in two buffers inside
//! the module's memory. No bindings generator is involved.
//!
//! ```text
//! wipc_reset() -> u32                        new engine from the defaults
//! wipc_input(len) -> *mut u8                 room for one input of len bytes
//! wipc_push(kind, len, now_ms: f64) -> u32   process it (0 ok, else an error code)
//! wipc_next() -> u32                         move the next output into the output
//!                                            buffer; its length, 0 for none
//! wipc_output() -> *const u8                 the output buffer
//! wipc_timeout() -> f64                      next timer in ms, or -1
//! ```
//!
//! Inputs (`kind`, then the bytes in the input buffer):
//!
//! | kind | input | bytes |
//! |---|---|---|
//! | 1 | configure | `[ipv4][ipv6][resume][icmp_echo][gateway_mac:6][has_host_mac][host_mac:6][router_lifetime_s:u16][ra_interval_ms:u32][open_timeout_ms:u32]` |
//! | 2 | connected | `[carrier: 1 WebSocket, 2 WebTransport][datagrams][max_datagram_size:u32]` |
//! | 3 | disconnected | none |
//! | 4 | WebSocket message | the message |
//! | 5 | WebTransport control bytes | the bytes |
//! | 6 | WebTransport datagram | the datagram |
//! | 7 | uni stream bytes | `[stream:u32][bytes]` |
//! | 8 | uni stream end | `[stream:u32]` |
//! | 9 | wire frame | the Ethernet frame |
//! | 10 | datagram limit | `[max_datagram_size:u32]` |
//! | 11 | timer | none |
//! | 12 | close | none |
//!
//! Outputs (`[kind][body]`):
//!
//! | kind | output | body |
//! |---|---|---|
//! | 1 | WebSocket send | the message |
//! | 2 | control bidi write | frames |
//! | 3 | datagram | the datagram |
//! | 4 | open uni stream | `[tunnel_id:u32][prelude:4]`: write the prelude alone |
//! | 5 | uni stream write | `[tunnel_id:u32][chunk]` |
//! | 6 | finish uni stream | `[tunnel_id:u32]` |
//! | 7 | close the carrier | none |
//! | 8 | wire frame | the Ethernet frame |
//! | 9 | event | `[event kind][...]`, see [`encode_event`] |
//!
//! Integers are little-endian. Configuration and messages inside events are
//! JSON text, which the Worker parses once per event.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::manager::{LinkConfig, ResolverConfig};
use crate::mux::{Carrier, Transmit, Unsupported, Wants};
use crate::router::RouterConfig;
use crate::uplink::{Event, LinkDownReason, Output, Uplink, UplinkConfig};

pub mod input {
    pub const CONFIGURE: u32 = 1;
    pub const CONNECTED: u32 = 2;
    pub const DISCONNECTED: u32 = 3;
    pub const WS_MESSAGE: u32 = 4;
    pub const WT_CONTROL: u32 = 5;
    pub const WT_DATAGRAM: u32 = 6;
    pub const WT_UNI: u32 = 7;
    pub const WT_UNI_END: u32 = 8;
    pub const WIRE_FRAME: u32 = 9;
    pub const MAX_DATAGRAM: u32 = 10;
    pub const TIMER: u32 = 11;
    pub const CLOSE: u32 = 12;
}

pub mod output {
    pub const WS_SEND: u8 = 1;
    pub const WT_CONTROL: u8 = 2;
    pub const WT_DATAGRAM: u8 = 3;
    pub const WT_UNI_OPEN: u8 = 4;
    pub const WT_UNI_CHUNK: u8 = 5;
    pub const WT_UNI_FINISH: u8 = 6;
    pub const CLOSE: u8 = 7;
    pub const WIRE: u8 = 8;
    pub const EVENT: u8 = 9;
}

pub mod event {
    pub const UNSUPPORTED: u8 = 1;
    pub const LINK_UP: u8 = 2;
    pub const LINK_CHANGED: u8 = 3;
    pub const DETACHED: u8 = 4;
    pub const OPEN_TIMED_OUT: u8 = 5;
    pub const LINK_DOWN: u8 = 6;
    pub const CONNECTION_FAILED: u8 = 7;
}

/// Error codes of `wipc_push`.
pub mod status {
    pub const OK: u32 = 0;
    pub const UNKNOWN_KIND: u32 = 1;
    pub const SHORT_INPUT: u32 = 2;
    pub const BAD_CARRIER: u32 = 3;
}

/// An [`Uplink`] behind the byte interface.
pub struct Engine {
    uplink: Uplink,
    pending: VecDeque<Vec<u8>>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(UplinkConfig::default())
    }
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn mac_at(b: &[u8], at: usize) -> Option<[u8; 6]> {
    let s = b.get(at..at + 6)?;
    let mut m = [0u8; 6];
    m.copy_from_slice(s);
    Some(m)
}

/// Parses the `configure` input.
pub fn parse_config(b: &[u8]) -> Option<UplinkConfig> {
    if b.len() < 27 {
        return None;
    }
    let host_mac = (b[10] != 0).then(|| mac_at(b, 11)).flatten();
    Some(UplinkConfig {
        wants: Wants {
            ipv4: b[0] != 0,
            ipv6: b[1] != 0,
            resume: b[2] != 0,
            icmp_echo: b[3] != 0,
        },
        router: RouterConfig {
            gateway_mac: mac_at(b, 4)?,
            host_mac,
            router_lifetime_s: u16::from_le_bytes([b[17], b[18]]),
            ra_interval_ms: u64::from(u32_at(b, 19)?),
        },
        open_timeout_ms: u64::from(u32_at(b, 23)?),
    })
}

impl Engine {
    pub fn new(cfg: UplinkConfig) -> Self {
        Self {
            uplink: Uplink::new(cfg),
            pending: VecDeque::new(),
        }
    }

    pub fn uplink(&self) -> &Uplink {
        &self.uplink
    }

    /// One input; see the module documentation for the kinds.
    pub fn push(&mut self, kind: u32, b: &[u8], now_ms: u64) -> u32 {
        let u = &mut self.uplink;
        match kind {
            input::CONFIGURE => match parse_config(b) {
                Some(cfg) => {
                    *self = Engine::new(cfg);
                    return status::OK;
                }
                None => return status::SHORT_INPUT,
            },
            input::CONNECTED => {
                if b.len() < 6 {
                    return status::SHORT_INPUT;
                }
                let carrier = match b[0] {
                    1 => Carrier::WebSocket,
                    2 => Carrier::WebTransport {
                        datagrams: b[1] != 0,
                        max_datagram_size: u32_at(b, 2).unwrap_or(0) as usize,
                    },
                    _ => return status::BAD_CARRIER,
                };
                u.connected(now_ms, carrier);
            }
            input::DISCONNECTED => u.disconnected(now_ms),
            input::WS_MESSAGE => u.ws_message(now_ms, b),
            input::WT_CONTROL => u.wt_control(now_ms, b),
            input::WT_DATAGRAM => u.wt_datagram(now_ms, b),
            input::WT_UNI => {
                let Some(stream) = u32_at(b, 0) else {
                    return status::SHORT_INPUT;
                };
                u.wt_uni(now_ms, u64::from(stream), &b[4..]);
            }
            input::WT_UNI_END => {
                let Some(stream) = u32_at(b, 0) else {
                    return status::SHORT_INPUT;
                };
                u.wt_uni_end(u64::from(stream));
            }
            input::WIRE_FRAME => u.wire_frame(now_ms, b),
            input::MAX_DATAGRAM => {
                let Some(size) = u32_at(b, 0) else {
                    return status::SHORT_INPUT;
                };
                u.set_max_datagram_size(size as usize);
            }
            input::TIMER => u.handle_timeout(now_ms),
            input::CLOSE => u.close(now_ms),
            _ => return status::UNKNOWN_KIND,
        }
        while let Some(o) = self.uplink.poll_output() {
            self.pending.push_back(encode_output(&o));
        }
        status::OK
    }

    /// The next output, encoded.
    pub fn next_output(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    pub fn timeout(&self) -> Option<u64> {
        self.uplink.poll_timeout()
    }
}

pub fn encode_output(o: &Output) -> Vec<u8> {
    let with = |kind: u8, body: &[u8]| {
        let mut v = Vec::with_capacity(1 + body.len());
        v.push(kind);
        v.extend_from_slice(body);
        v
    };
    let id_and = |kind: u8, id: u32, body: &[u8]| {
        let mut v = Vec::with_capacity(5 + body.len());
        v.push(kind);
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(body);
        v
    };
    match o {
        Output::Carrier(t) => match t {
            Transmit::Ws(b) => with(output::WS_SEND, b),
            Transmit::WtControl(b) => with(output::WT_CONTROL, b),
            Transmit::WtDatagram(b) => with(output::WT_DATAGRAM, b),
            Transmit::WtUniOpen { tunnel_id, prelude } => {
                id_and(output::WT_UNI_OPEN, *tunnel_id, prelude)
            }
            Transmit::WtUniChunk { tunnel_id, chunk } => {
                id_and(output::WT_UNI_CHUNK, *tunnel_id, chunk)
            }
            Transmit::WtUniFinish { tunnel_id } => id_and(output::WT_UNI_FINISH, *tunnel_id, &[]),
            Transmit::Close => vec![output::CLOSE],
        },
        Output::Wire(f) => with(output::WIRE, f),
        Output::Event(e) => {
            let mut v = vec![output::EVENT];
            v.extend_from_slice(&encode_event(e));
            v
        }
    }
}

/// `[event kind][body]`:
///
/// | kind | body |
/// |---|---|
/// | 1 unsupported | JSON `{"why": "..."}` |
/// | 2 link up | `[resumed][flows_lost]` then the configuration as JSON |
/// | 3 link changed | the configuration as JSON |
/// | 4 detached | `[resume_until_ms: f64]` |
/// | 5 open timed out | none |
/// | 6 link down | JSON `{"reason": "...", "close": n, "error": n, "message": "..."}` |
/// | 7 connection failed | JSON `{"why": "..."}` |
pub fn encode_event(e: &Event) -> Vec<u8> {
    match e {
        Event::Unsupported(why) => {
            let why = match why {
                Unsupported::WispV1 => "wisp-v1".to_owned(),
                Unsupported::NoExtension => "no-extension".to_owned(),
                Unsupported::BadEntry(err) => format!("bad-entry: {err}"),
                Unsupported::Version { min, max } => format!("version {min}..{max}"),
                Unsupported::NoFamily => "no-family".to_owned(),
            };
            let mut v = vec![event::UNSUPPORTED];
            v.extend_from_slice(format!("{{\"why\":{}}}", json_str(&why)).as_bytes());
            v
        }
        Event::LinkUp {
            config,
            resumed,
            flows_lost,
        } => {
            let mut v = vec![event::LINK_UP, u8::from(*resumed), u8::from(*flows_lost)];
            v.extend_from_slice(config_json(config).as_bytes());
            v
        }
        Event::LinkChanged { config } => {
            let mut v = vec![event::LINK_CHANGED];
            v.extend_from_slice(config_json(config).as_bytes());
            v
        }
        Event::Detached { resume_until_ms } => {
            let mut v = vec![event::DETACHED];
            v.extend_from_slice(&(*resume_until_ms as f64).to_le_bytes());
            v
        }
        Event::OpenTimedOut => vec![event::OPEN_TIMED_OUT],
        Event::LinkDown { reason } => {
            let (name, close, error) = match reason {
                LinkDownReason::Refused { reason, error } => ("refused", *reason, error.as_ref()),
                LinkDownReason::Closed { reason, error } => ("closed", *reason, error.as_ref()),
                LinkDownReason::CarrierLost => ("carrier-lost", 0, None),
                LinkDownReason::ResumeExpired => ("resume-expired", 0, None),
            };
            let (code, message) = error.map(|(c, m)| (*c, m.as_str())).unwrap_or((0, ""));
            let mut v = vec![event::LINK_DOWN];
            v.extend_from_slice(
                format!(
                    "{{\"reason\":{},\"close\":{close},\"error\":{code},\"message\":{}}}",
                    json_str(name),
                    json_str(message)
                )
                .as_bytes(),
            );
            v
        }
        Event::ConnectionFailed(why) => {
            let mut v = vec![event::CONNECTION_FAILED];
            v.extend_from_slice(format!("{{\"why\":{}}}", json_str(why)).as_bytes());
            v
        }
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn ip_json(a: IpAddr) -> String {
    json_str(&a.to_string())
}

/// The configuration as the Worker reads it.
pub fn config_json(c: &LinkConfig) -> String {
    let addresses: Vec<String> = c
        .addresses
        .iter()
        .map(|a| {
            format!(
                "{{\"address\":{},\"prefix\":{},\"valid\":{},\"preferred\":{}}}",
                ip_json(a.prefix.addr()),
                a.prefix.len(),
                a.valid_lft,
                a.preferred_lft
            )
        })
        .collect();
    let routes: Vec<String> = c
        .routes
        .iter()
        .map(|r| {
            format!(
                "{{\"dest\":{},\"prefix\":{},\"gateway\":{},\"metric\":{}}}",
                ip_json(r.dest.addr()),
                r.dest.len(),
                ip_json(r.gateway),
                r.metric
            )
        })
        .collect();
    let dns = match &c.dns {
        Some(d) => {
            let servers: Vec<String> = d.servers.iter().map(|s| ip_json(*s)).collect();
            format!(
                "{{\"servers\":[{}],\"search\":{},\"resolvConf\":{}}}",
                servers.join(","),
                json_str(&d.search),
                json_str(&ResolverConfig::from_dns(d).resolv_conf())
            )
        }
        None => "null".to_owned(),
    };
    format!(
        "{{\"addresses\":[{}],\"routes\":[{}],\"mtu\":{},\"maxPacket\":{},\"maxDatagramPayload\":{},\"dns\":{dns}}}",
        addresses.join(","),
        routes.join(","),
        c.link.link_mtu,
        c.link.max_packet,
        c.link.max_datagram_payload
    )
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod exports {
    //! The exports. `#[no_mangle]` is what the `unsafe_code` lint objects
    //! to here; no raw pointer is dereferenced: JavaScript writes into and
    //! reads from vectors this module owns.

    use std::cell::RefCell;

    use super::Engine;

    thread_local! {
        static ENGINE: RefCell<Engine> = RefCell::new(Engine::default());
        static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    #[no_mangle]
    pub extern "C" fn wipc_reset() -> u32 {
        ENGINE.with(|e| *e.borrow_mut() = Engine::default());
        0
    }

    #[no_mangle]
    pub extern "C" fn wipc_input(len: u32) -> *mut u8 {
        INPUT.with(|b| {
            let mut b = b.borrow_mut();
            b.clear();
            b.resize(len as usize, 0);
            b.as_mut_ptr()
        })
    }

    #[no_mangle]
    pub extern "C" fn wipc_push(kind: u32, len: u32, now_ms: f64) -> u32 {
        INPUT.with(|b| {
            let b = b.borrow();
            let len = (len as usize).min(b.len());
            let now = if now_ms.is_finite() && now_ms > 0.0 {
                now_ms as u64
            } else {
                0
            };
            ENGINE.with(|e| e.borrow_mut().push(kind, &b[..len], now))
        })
    }

    #[no_mangle]
    pub extern "C" fn wipc_next() -> u32 {
        let next = ENGINE.with(|e| e.borrow_mut().next_output());
        OUTPUT.with(|o| {
            let mut o = o.borrow_mut();
            o.clear();
            if let Some(next) = next {
                o.extend_from_slice(&next);
            }
            o.len() as u32
        })
    }

    #[no_mangle]
    pub extern "C" fn wipc_output() -> *const u8 {
        OUTPUT.with(|o| o.borrow().as_ptr())
    }

    #[no_mangle]
    pub extern "C" fn wipc_timeout() -> f64 {
        ENGINE.with(|e| e.borrow().timeout().map(|t| t as f64).unwrap_or(-1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_bytes() -> Vec<u8> {
        let mut b = vec![1, 0, 1, 1];
        b.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        b.push(1);
        b.extend_from_slice(&[0x52, 0x54, 0, 1, 2, 3]);
        b.extend_from_slice(&900u16.to_le_bytes());
        b.extend_from_slice(&60_000u32.to_le_bytes());
        b.extend_from_slice(&5_000u32.to_le_bytes());
        b
    }

    #[test]
    fn configuration_bytes_parse() {
        let cfg = parse_config(&config_bytes()).unwrap();
        assert!(cfg.wants.ipv4 && !cfg.wants.ipv6 && cfg.wants.resume);
        assert_eq!(cfg.router.gateway_mac, [0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(cfg.router.host_mac, Some([0x52, 0x54, 0, 1, 2, 3]));
        assert_eq!(cfg.router.router_lifetime_s, 900);
        assert_eq!(cfg.router.ra_interval_ms, 60_000);
        assert_eq!(cfg.open_timeout_ms, 5_000);
        assert!(parse_config(&config_bytes()[..26]).is_none());
    }

    #[test]
    fn a_webtransport_connect_writes_info_on_the_control_stream() {
        let mut e = Engine::default();
        assert_eq!(e.push(input::CONFIGURE, &config_bytes(), 0), status::OK);
        let mut c = vec![2, 1];
        c.extend_from_slice(&1024u32.to_le_bytes());
        assert_eq!(e.push(input::CONNECTED, &c, 10), status::OK);
        let out = e.next_output().unwrap();
        assert_eq!(out[0], output::WT_CONTROL);
        // [bodyLen][INFO=0x01][0xF3][len=7]["WIPT"][1][flags]
        assert_eq!(out[5], 0x01);
        assert_eq!(out[6], 0xf3);
        assert_eq!(&out[11..15], b"WIPT");
        assert!(e.next_output().is_none());
        assert_eq!(e.push(99, &[], 0), status::UNKNOWN_KIND);
        assert_eq!(
            e.push(input::CONNECTED, &[3, 0, 0, 0, 0, 0], 0),
            status::BAD_CARRIER
        );
    }

    #[test]
    fn json_escapes_quotes_and_controls() {
        assert_eq!(json_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }
}

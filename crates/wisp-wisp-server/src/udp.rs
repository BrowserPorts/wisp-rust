//! Per-flow UDP bridge. Mirrors the UDP path of the legacy
//! `stellite-wisp/src/wisp/server.ts`. UDP is supported only when the
//! UDP extension (0x01) is negotiated.

use bytes::Bytes;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use wisp_dos::{datagram_limit_decision, DatagramDecision};
use wisp_wisp::{close_reason, encode_close, encode_data};

use crate::connection::{ServerContext, WispMessage};

#[derive(Debug)]
pub enum UdpStreamMsg {
    Data(Bytes),
    Close,
}

pub(crate) fn spawn_udp_stream(
    stream_id: u32,
    hostname: String,
    port: u16,
    ctx: ServerContext,
    egress: mpsc::Sender<WispMessage>,
    done_tx: mpsc::Sender<u32>,
) -> mpsc::Sender<UdpStreamMsg> {
    let (tx, rx) = mpsc::channel::<UdpStreamMsg>(2048);
    tokio::spawn(async move {
        run_udp(stream_id, hostname, port, ctx, egress, rx).await;
        let _ = done_tx.send(stream_id).await;
    });
    tx
}

async fn run_udp(
    stream_id: u32,
    hostname: String,
    port: u16,
    ctx: ServerContext,
    egress: mpsc::Sender<WispMessage>,
    mut rx: mpsc::Receiver<UdpStreamMsg>,
) {
    if let Err(e) = ctx.policy.check(&hostname, port) {
        warn!(stream_id, %hostname, port, error = %e, "wisp udp host policy reject");
        let _ = tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => Ok(()),
            r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::HOST_BLOCKED))) => r.map_err(|_| ()),
        };
        return;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(stream_id, error = %e, "wisp udp bind failed");
            let _ = tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => Ok(()),
                r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::NETWORK_ERROR))) => r.map_err(|_| ()),
            };
            return;
        }
    };
    if let Err(e) = socket.connect((hostname.as_str(), port)).await {
        warn!(stream_id, %hostname, port, error = %e, "wisp udp connect failed");
        let _ = tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => Ok(()),
            r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::UNREACHABLE_HOST))) => r.map_err(|_| ()),
        };
        return;
    }

    let recv_socket = Arc::clone(&socket);
    let recv_egress = egress.clone();
    let recv_cancel = ctx.cancel.clone();
    let recv_ctx = ctx.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        loop {
            tokio::select! {
                _ = recv_cancel.cancelled() => break,
                res = recv_socket.recv(&mut buf) => match res {
                    Ok(n) => {
                        let decision = datagram_limit_decision(
                            &recv_ctx.client_ip,
                            &recv_ctx.conn_dos,
                            &recv_ctx.options,
                            n as u64,
                            &recv_ctx.dos_store,
                        );
                        match decision {
                            DatagramDecision::Allow => {
                                let send_res = tokio::select! {
                                    biased;
                                    _ = recv_cancel.cancelled() => break,
                                    r = recv_egress.send(WispMessage::Binary(encode_data(stream_id, &buf[..n]))) => r,
                                };
                                if send_res.is_err() {
                                    break;
                                }
                            }
                            DatagramDecision::Drop => {
                                debug!(
                                    stream_id,
                                    bytes = n,
                                    "wisp udp datagram dropped: rate limit (WISP_DATAGRAM_DROPPED)",
                                );
                                continue;
                            }
                            DatagramDecision::Close => {
                                warn!(
                                    stream_id,
                                    "wisp: closing connection: sustained datagram rate exceeded (WISP_DATAGRAM_RATE_LIMITED)",
                                );
                                let _ = tokio::select! {
                                    biased;
                                    _ = recv_cancel.cancelled() => Ok(()),
                                    r = recv_egress.send(WispMessage::Binary(encode_close(0, close_reason::CONN_THROTTLED))) => r.map_err(|_| ()),
                                };
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(stream_id, error = %e, "wisp udp recv error");
                        let _ = tokio::select! {
                            biased;
                            _ = recv_cancel.cancelled() => Ok(()),
                            r = recv_egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::NETWORK_ERROR))) => r.map_err(|_| ()),
                        };
                        break;
                    }
                }
            }
        }
    });

    loop {
        let msg = tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            recv = rx.recv() => match recv {
                Some(m) => m,
                None => break,
            },
        };
        match msg {
            UdpStreamMsg::Data(payload) => {
                let send_res = tokio::select! {
                    biased;
                    _ = ctx.cancel.cancelled() => break,
                    r = socket.send(&payload) => r,
                };
                if let Err(e) = send_res {
                    warn!(stream_id, error = %e, "wisp udp send error");
                    let _ = tokio::select! {
                        biased;
                        _ = ctx.cancel.cancelled() => Ok(()),
                        r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::NETWORK_ERROR))) => r.map_err(|_| ()),
                    };
                    break;
                }
            }
            UdpStreamMsg::Close => {
                break;
            }
        }
    }
    drop(socket);
    recv_task.abort();
    let _ = recv_task.await;
}

//! Per-flow UDP bridge. UDP is supported only when the UDP extension
//! (0x01) is negotiated.

use bytes::BytesMut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use wisp_dos::{datagram_limit_decision, datagram_limits_active, DatagramDecision};
use wisp_wisp::{
    close_reason, encode_close, encode_continue, write_data_header, PACKET_HEADER_LEN,
};

use crate::connection::{EgressSender, ServerContext, WispMessage};

#[derive(Debug)]
pub enum UdpStreamMsg {
    Data(bytes::Bytes),
    Close,
}

pub(crate) fn spawn_udp_stream(
    stream_id: u32,
    hostname: String,
    port: u16,
    ctx: ServerContext,
    egress: EgressSender,
    done_tx: mpsc::Sender<u32>,
) -> mpsc::Sender<UdpStreamMsg> {
    let (tx, rx) = mpsc::channel::<UdpStreamMsg>(2048);
    tokio::spawn(async move {
        run_udp(stream_id, hostname, port, ctx, egress, rx).await;
        let _ = done_tx.send(stream_id).await;
    });
    tx
}

async fn send_close(
    egress: &EgressSender,
    cancel: &tokio_util::sync::CancellationToken,
    stream_id: u32,
    reason: u8,
) {
    let _ = tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(()),
        r = egress.send(WispMessage::Binary(encode_close(stream_id, reason))) => r.map_err(|_| ()),
    };
}

async fn run_udp(
    stream_id: u32,
    hostname: String,
    port: u16,
    ctx: ServerContext,
    egress: EgressSender,
    mut rx: mpsc::Receiver<UdpStreamMsg>,
) {
    if let Err(e) = ctx.policy.check(&hostname, port) {
        warn!(stream_id, %hostname, port, error = %e, "wisp udp host policy reject");
        send_close(&egress, &ctx.cancel, stream_id, close_reason::HOST_BLOCKED).await;
        return;
    }

    let peer = match crate::stream::resolve_checked(&hostname, port, &ctx.policy).await {
        Ok(addrs) => addrs[0],
        Err(e) => {
            warn!(stream_id, %hostname, port, error = %e, "wisp udp connect rejected");
            send_close(
                &egress,
                &ctx.cancel,
                stream_id,
                close_reason::UNREACHABLE_HOST,
            )
            .await;
            return;
        }
    };
    let bind_addr = if peer.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(stream_id, error = %e, "wisp udp bind failed");
            send_close(&egress, &ctx.cancel, stream_id, close_reason::NETWORK_ERROR).await;
            return;
        }
    };
    if let Err(e) = socket.connect(peer).await {
        warn!(stream_id, %hostname, port, error = %e, "wisp udp connect failed");
        send_close(
            &egress,
            &ctx.cancel,
            stream_id,
            close_reason::UNREACHABLE_HOST,
        )
        .await;
        return;
    }

    let buffer_size = ctx.server_options.buffer_size;
    let _ = tokio::select! {
        biased;
        _ = ctx.cancel.cancelled() => Ok(()),
        r = egress.send(WispMessage::Binary(encode_continue(stream_id, buffer_size))) => r.map_err(|_| ()),
    };

    let meter_udp = datagram_limits_active(&ctx.options);
    let idle = ctx
        .options
        .stream_idle_timeout_ms
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis);
    let start = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));

    let recv_socket = Arc::clone(&socket);
    let recv_egress = egress.clone();
    let recv_cancel = ctx.cancel.clone();
    let recv_ctx = ctx.clone();
    let recv_last = Arc::clone(&last_activity);
    let recv_idle = idle;
    let recv_task = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(PACKET_HEADER_LEN + 65_536);
        loop {
            buf.resize(PACKET_HEADER_LEN + 65_536, 0);
            tokio::select! {
                _ = recv_cancel.cancelled() => break,
                _ = idle_wait(recv_idle) => {
                    if idle_exceeded(&recv_last, start, recv_idle) {
                        send_close(&recv_egress, &recv_cancel, stream_id, close_reason::TRANSFER_TIMEOUT).await;
                        break;
                    }
                }
                res = recv_socket.recv(&mut buf[PACKET_HEADER_LEN..]) => match res {
                    Ok(n) => {
                        touch(&recv_last, start);
                        if meter_udp {
                            let decision = datagram_limit_decision(
                                &recv_ctx.client_ip,
                                &recv_ctx.conn_dos,
                                &recv_ctx.options,
                                n as u64,
                                &recv_ctx.dos_store,
                            );
                            match decision {
                                DatagramDecision::Allow => {}
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
                                    send_close(&recv_egress, &recv_cancel, 0, close_reason::CONN_THROTTLED).await;
                                    break;
                                }
                            }
                        }
                        buf.truncate(PACKET_HEADER_LEN + n);
                        write_data_header(stream_id, &mut buf);
                        let frame = buf.split().freeze();
                        let send_res = tokio::select! {
                            biased;
                            _ = recv_cancel.cancelled() => break,
                            r = recv_egress.send(WispMessage::Binary(frame)) => r,
                        };
                        if send_res.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(stream_id, error = %e, "wisp udp recv error");
                        send_close(&recv_egress, &recv_cancel, stream_id, close_reason::NETWORK_ERROR).await;
                        break;
                    }
                }
            }
        }
    });

    loop {
        let msg = tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            _ = idle_wait(idle) => {
                if idle_exceeded(&last_activity, start, idle) {
                    send_close(&egress, &ctx.cancel, stream_id, close_reason::TRANSFER_TIMEOUT).await;
                    break;
                }
                continue;
            }
            recv = rx.recv() => match recv {
                Some(m) => m,
                None => break,
            },
        };
        match msg {
            UdpStreamMsg::Data(payload) => {
                touch(&last_activity, start);
                if meter_udp {
                    match datagram_limit_decision(
                        &ctx.client_ip,
                        &ctx.conn_dos,
                        &ctx.options,
                        payload.len() as u64,
                        &ctx.dos_store,
                    ) {
                        DatagramDecision::Allow => {}
                        DatagramDecision::Drop => {
                            debug!(
                                stream_id,
                                bytes = payload.len(),
                                "wisp udp outbound datagram dropped: rate limit",
                            );
                            continue;
                        }
                        DatagramDecision::Close => {
                            warn!(
                                stream_id,
                                "wisp: closing connection: sustained outbound datagram rate exceeded",
                            );
                            send_close(&egress, &ctx.cancel, 0, close_reason::CONN_THROTTLED).await;
                            break;
                        }
                    }
                }
                let send_res = tokio::select! {
                    biased;
                    _ = ctx.cancel.cancelled() => break,
                    r = socket.send(&payload) => r,
                };
                if let Err(e) = send_res {
                    warn!(stream_id, error = %e, "wisp udp send error");
                    send_close(&egress, &ctx.cancel, stream_id, close_reason::NETWORK_ERROR).await;
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

fn touch(last: &AtomicU64, start: Instant) {
    last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
}

fn idle_exceeded(last: &AtomicU64, start: Instant, idle: Option<Duration>) -> bool {
    let Some(idle) = idle else {
        return false;
    };
    let elapsed = start.elapsed().as_millis() as u64;
    elapsed.saturating_sub(last.load(Ordering::Relaxed)) >= idle.as_millis() as u64
}

async fn idle_wait(idle: Option<Duration>) {
    match idle {
        Some(d) => tokio::time::sleep(d / 2).await,
        None => std::future::pending::<()>().await,
    }
}

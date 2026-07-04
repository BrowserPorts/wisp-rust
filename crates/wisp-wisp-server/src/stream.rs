//! Per-stream TCP bridge. Mirrors the legacy `TcpWispStream` in
//! `stellite-wisp/src/wisp/server.ts`. Each accepted CONNECT (TCP) packet
//! spawns one bridge task; the task owns the upstream socket and the two
//! pumps (client→upstream and upstream→client).
//!
//! Protocol inspection runs on the first
//! `protocol_inspection_max_bytes` (via [`wisp_inspect::inspect`]) before
//! any byte reaches the upstream, mirroring the existing WT path. Per the
//! user's directive: "make all of the protocol inspection stuff work
//! inside of wisp-wisp as well."

use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::warn;
use wisp_dos::is_tcp_bytes_allowed;
use wisp_inspect::{inspect, BlockReason, InspectionDecision};
use wisp_proxy::HostPolicy;
use wisp_wisp::{close_reason, encode_close, encode_continue, encode_data_owned};

use crate::connection::{ServerContext, WispMessage};

/// Resolve `host:port` and gate every resolved address through the connection
/// policy. Returns the allowed addresses, or an error string if resolution
/// fails or *any* resolved address is disallowed. Rejecting when any address
/// fails (rather than filtering) closes the DNS-rebinding hole where a hostname
/// returns a mix of a public and a private/loopback record: the WS transport
/// used to connect by hostname and never re-checked the resolved IP, so a name
/// pointing at `127.0.0.1` / `169.254.169.254` / RFC-1918 bypassed
/// `allow_private_ips` / `allow_loopback_ips`.
pub(crate) async fn resolve_checked(
    host: &str,
    port: u16,
    policy: &HostPolicy,
) -> Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|e| e.to_string())?
        .collect();
    if addrs.is_empty() {
        return Err(format!("no addresses resolved for {host}"));
    }
    for sa in &addrs {
        policy.check_ip(sa.ip()).map_err(|e| e.to_string())?;
    }
    Ok(addrs)
}

async fn connect_checked_tcp(
    host: &str,
    port: u16,
    policy: &HostPolicy,
) -> Result<TcpStream, String> {
    let addrs = resolve_checked(host, port, policy).await?;
    let mut last = String::from("no address connected");
    for sa in addrs {
        match TcpStream::connect(sa).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

#[derive(Debug)]
pub enum TcpStreamMsg {
    Data(Bytes),
    Close(u8),
}

pub(crate) struct StreamHandle {
    pub tx: mpsc::Sender<TcpStreamMsg>,
    pub _task: JoinHandle<()>,
}

pub(crate) fn spawn_tcp_stream(
    stream_id: u32,
    hostname: String,
    port: u16,
    ctx: ServerContext,
    egress: mpsc::Sender<WispMessage>,
    done_tx: mpsc::Sender<u32>,
) -> StreamHandle {
    let (tx, rx) = mpsc::channel::<TcpStreamMsg>(2048);
    let task = tokio::spawn(async move {
        run_stream(stream_id, hostname, port, ctx, egress, rx).await;
        let _ = done_tx.send(stream_id).await;
    });
    StreamHandle { tx, _task: task }
}

async fn run_stream(
    stream_id: u32,
    hostname: String,
    port: u16,
    ctx: ServerContext,
    egress: mpsc::Sender<WispMessage>,
    mut rx: mpsc::Receiver<TcpStreamMsg>,
) {
    if let Err(e) = ctx.policy.check(&hostname, port) {
        warn!(stream_id, %hostname, port, error = %e, "wisp tcp host policy reject");
        let _ = tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => Ok(()),
            r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::HOST_BLOCKED))) => r.map_err(|_| ()),
        };
        return;
    }

    let connect_timeout =
        Duration::from_millis(ctx.options.connect_timeout_ms.unwrap_or(10_000).max(1));

    let upstream = match timeout(connect_timeout, async {
        if let Some(controller) = ctx.proxy_controller.as_ref() {
            controller
                .connect_tcp(&hostname, port, ctx.options.force_proxy)
                .await
                .map(|(stream, _active)| stream)
                .map_err(|e| e.to_string())
        } else if ctx.options.force_proxy {
            Err("force_proxy is enabled but no proxy controller is active".to_owned())
        } else {
            connect_checked_tcp(&hostname, port, &ctx.policy).await
        }
    })
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(stream_id, %hostname, port, error = %e, "wisp tcp connect failed");
            let _ = tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => Ok(()),
                r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::CONN_REFUSED))) => r.map_err(|_| ()),
            };
            return;
        }
        Err(_) => {
            let _ = tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => Ok(()),
                r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::NO_RESPONSE))) => r.map_err(|_| ()),
            };
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    let (mut up_read, mut up_write) = upstream.into_split();

    // Inspection state: per the legacy server, we buffer up to
    // `protocol_inspection_max_bytes` of the *first* client→upstream
    // payload, then run a single decision and either flush or block.
    let inspection_enabled = ctx.options.protocol_inspection;
    let inspection_max =
        usize::try_from(ctx.options.protocol_inspection_max_bytes).unwrap_or(usize::MAX);
    let mut inspection_buf: Option<BytesMut> = if inspection_enabled {
        Some(BytesMut::new())
    } else {
        None
    };

    // Spawn upstream→client reader.
    let egress_for_reader = egress.clone();
    let stream_id_for_reader = stream_id;
    let buffer_size = ctx.server_options.buffer_size as usize;
    let continue_threshold = ctx.server_options.continue_threshold as usize;
    let reader_cancel = ctx.cancel.clone();
    let reader_ctx = ctx.clone();
    let reader_task = tokio::spawn(async move {
        const READ_CHUNK: usize = 64 * 1024;
        let mut buf = BytesMut::with_capacity(READ_CHUNK);
        let mut bytes_since_continue = 0usize;
        loop {
            if buf.capacity() - buf.len() < READ_CHUNK {
                buf.reserve(READ_CHUNK);
            }
            tokio::select! {
                _ = reader_cancel.cancelled() => break,
                res = up_read.read_buf(&mut buf) => match res {
                    Ok(0) => {
                        let _ = tokio::select! {
                            biased;
                            _ = reader_cancel.cancelled() => Ok(()),
                            r = egress_for_reader
                                .send(WispMessage::Binary(encode_close(stream_id_for_reader, close_reason::VOLUNTARY))) => r.map_err(|_| ()),
                        };
                        break;
                    }
                    Ok(n) => {
                        if !is_tcp_bytes_allowed(
                            &reader_ctx.client_ip,
                            &reader_ctx.conn_dos,
                            &reader_ctx.options,
                            n as u64,
                            &reader_ctx.dos_store,
                        ) {
                            warn!(stream_id_for_reader, "wisp tcp upstream->client byte rate exceeded, closing stream");
                            let _ = tokio::select! {
                                biased;
                                _ = reader_cancel.cancelled() => Ok(()),
                                r = egress_for_reader
                                    .send(WispMessage::Binary(encode_close(stream_id_for_reader, close_reason::CONN_THROTTLED))) => r.map_err(|_| ()),
                            };
                            break;
                        }
                        bytes_since_continue = bytes_since_continue.saturating_add(n);
                        let payload = buf.split().freeze();
                        let frame = encode_data_owned(stream_id_for_reader, payload);
                        let send_res = tokio::select! {
                            biased;
                            _ = reader_cancel.cancelled() => break,
                            r = egress_for_reader
                                .send(WispMessage::Binary(frame)) => r,
                        };
                        if send_res.is_err() {
                            break;
                        }
                        if buffer_size > 0 && bytes_since_continue >= continue_threshold {
                            let cont_res = tokio::select! {
                                biased;
                                _ = reader_cancel.cancelled() => break,
                                r = egress_for_reader
                                    .send(WispMessage::Binary(encode_continue(stream_id_for_reader, buffer_size as u32))) => r,
                            };
                            let _ = cont_res;
                            bytes_since_continue = 0;
                        }
                    }
                    Err(e) => {
                        warn!(stream_id_for_reader, error = %e, "wisp tcp upstream read error");
                        let _ = tokio::select! {
                            biased;
                            _ = reader_cancel.cancelled() => Ok(()),
                            r = egress_for_reader
                                .send(WispMessage::Binary(encode_close(stream_id_for_reader, close_reason::NETWORK_ERROR))) => r.map_err(|_| ()),
                        };
                        break;
                    }
                }
            }
        }
    });

    // Drive the client→upstream half from the channel. Wrapping in select
    // against ctx.cancel lets us abandon a hung `up_write.write_all` when
    // the connection ends — without it an unresponsive upstream would
    // pin the task even after the wisp side closed.
    loop {
        let msg = tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            recv = rx.recv() => match recv {
                Some(m) => m,
                None => break,
            },
        };
        match msg {
            TcpStreamMsg::Data(payload) => {
                if !is_tcp_bytes_allowed(
                    &ctx.client_ip,
                    &ctx.conn_dos,
                    &ctx.options,
                    payload.len() as u64,
                    &ctx.dos_store,
                ) {
                    warn!(stream_id, "wisp tcp client->upstream byte rate exceeded, closing stream");
                    let _ = tokio::select! {
                        biased;
                        _ = ctx.cancel.cancelled() => Ok(()),
                        r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::CONN_THROTTLED))) => r.map_err(|_| ()),
                    };
                    break;
                }
                if let Some(ibuf) = inspection_buf.as_mut() {
                    let remaining = inspection_max.saturating_sub(ibuf.len());
                    let take = remaining.min(payload.len());
                    ibuf.extend_from_slice(&payload[..take]);
                    let decision = inspect(ibuf.as_ref(), &ctx.options);
                    match decision {
                        InspectionDecision::Allow(_) => {
                            let flushed = ibuf.split().freeze();
                            inspection_buf = None;
                            let write_res = tokio::select! {
                                biased;
                                _ = ctx.cancel.cancelled() => {
                                    break;
                                }
                                r = up_write.write_all(&flushed) => r,
                            };
                            if write_res.is_err() {
                                let _ = tokio::select! {
                                    biased;
                                    _ = ctx.cancel.cancelled() => Ok(()),
                                    r = egress.send(WispMessage::Binary(encode_close(
                                        stream_id,
                                        close_reason::NETWORK_ERROR,
                                    ))) => r.map_err(|_| ()),
                                };
                                break;
                            }
                            if take < payload.len() {
                                let tail = payload.slice(take..);
                                let tail_res = tokio::select! {
                                    biased;
                                    _ = ctx.cancel.cancelled() => break,
                                    r = up_write.write_all(&tail) => r,
                                };
                                if tail_res.is_err() {
                                    let _ = tokio::select! {
                                        biased;
                                        _ = ctx.cancel.cancelled() => Ok(()),
                                        r = egress.send(WispMessage::Binary(encode_close(
                                            stream_id,
                                            close_reason::NETWORK_ERROR,
                                        ))) => r.map_err(|_| ()),
                                    };
                                    break;
                                }
                            }
                        }
                        InspectionDecision::NeedMore => {
                            if ibuf.len() >= inspection_max {
                                let _ = tokio::select! {
                                    biased;
                                    _ = ctx.cancel.cancelled() => Ok(()),
                                    r = egress.send(WispMessage::Binary(encode_close(
                                        stream_id,
                                        close_reason::HOST_BLOCKED,
                                    ))) => r.map_err(|_| ()),
                                };
                                break;
                            }
                        }
                        InspectionDecision::Block { reason } => {
                            warn!(
                                stream_id,
                                ?reason,
                                "wisp tcp protocol inspection blocked stream",
                            );
                            let close_code = match reason {
                                BlockReason::ProtocolNotAllowed
                                | BlockReason::H2cDisallowed
                                | BlockReason::TlsWithoutAlpnDisallowed
                                | BlockReason::QuicInitialDisallowed => close_reason::HOST_BLOCKED,
                                BlockReason::BufferExhausted => close_reason::CLIENT_ERROR,
                            };
                            let _ = tokio::select! {
                                biased;
                                _ = ctx.cancel.cancelled() => Ok(()),
                                r = egress.send(WispMessage::Binary(encode_close(stream_id, close_code))) => r.map_err(|_| ()),
                            };
                            break;
                        }
                    }
                } else {
                    let write_res = tokio::select! {
                        biased;
                        _ = ctx.cancel.cancelled() => break,
                        r = up_write.write_all(&payload) => r,
                    };
                    if write_res.is_err() {
                        let _ = tokio::select! {
                            biased;
                            _ = ctx.cancel.cancelled() => Ok(()),
                            r = egress.send(WispMessage::Binary(encode_close(stream_id, close_reason::NETWORK_ERROR))) => r.map_err(|_| ()),
                        };
                        break;
                    }
                }
            }
            TcpStreamMsg::Close(_reason) => {
                // Half-close the upstream send side; the upstream→client
                // reader task will naturally exit when the upstream
                // closes.
                let _ = up_write.shutdown().await;
                break;
            }
        }
    }
    drop(up_write);
    reader_task.abort();
    let _ = reader_task.await;
}

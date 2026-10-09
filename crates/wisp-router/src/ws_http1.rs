//! HTTP/1.1 WebSocket upgrade handling for the plain `ws://` listener.
//!
//! Admission policy runs between request parsing and the `101` response. Frame
//! processing is delegated to `tokio-websockets`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Uri};
use sha1_smol::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

const WS_MAGIC: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HTTP_HEADER: usize = 8 * 1024;

pub struct UpgradeInfo {
    pub path: String,
    pub headers: HeaderMap,
    pub advertises_v2: bool,
    accept_key: String,
}

pub struct PendingUpgrade {
    tcp: TcpStream,
    prefix: Bytes,
    pub info: UpgradeInfo,
}

pub async fn read_upgrade(mut tcp: TcpStream) -> io::Result<PendingUpgrade> {
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        if buf.len() > MAX_HTTP_HEADER {
            let _ = write_rejection(&mut tcp, "431 Request Header Fields Too Large").await;
            return Err(invalid("http upgrade header too large"));
        }
        if let Some(pos) = find_double_crlf(&buf) {
            let header_bytes = buf.split_to(pos + 4);
            let prefix = buf.freeze();
            let info = match parse_upgrade(&header_bytes) {
                Ok(info) => info,
                Err(error) => {
                    let _ = write_rejection(&mut tcp, "400 Bad Request").await;
                    return Err(error);
                }
            };
            return Ok(PendingUpgrade { tcp, prefix, info });
        }
        let read = tcp.read_buf(&mut buf).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof during websocket upgrade",
            ));
        }
    }
}

pub async fn accept_upgrade(mut pending: PendingUpgrade) -> io::Result<PrefixedIo> {
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n",
        pending.info.accept_key
    );
    if pending.info.advertises_v2 {
        response.push_str("Sec-WebSocket-Protocol: wisp-v2\r\n");
    }
    response.push_str("\r\n");
    pending.tcp.write_all(response.as_bytes()).await?;
    Ok(PrefixedIo {
        prefix: pending.prefix,
        tcp: pending.tcp,
    })
}

pub async fn reject_upgrade(mut pending: PendingUpgrade, status: &str) -> io::Result<()> {
    write_rejection(&mut pending.tcp, status).await
}

async fn write_rejection(tcp: &mut TcpStream, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    tcp.write_all(response.as_bytes()).await
}

fn parse_upgrade(raw: &[u8]) -> io::Result<UpgradeInfo> {
    let text = std::str::from_utf8(raw).map_err(|_| invalid("upgrade request is not utf-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid("missing request line"))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || method != "GET"
        || !target.starts_with('/')
        || version != "HTTP/1.1"
    {
        return Err(invalid("invalid websocket request line"));
    }

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed websocket header"))?;
        let name = name
            .parse::<http::HeaderName>()
            .map_err(|_| invalid("invalid websocket header name"))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| invalid("invalid websocket header value"))?;
        headers.append(name, value);
    }

    if !header_has_token(&headers, http::header::UPGRADE, "websocket")
        || !header_has_token(&headers, http::header::CONNECTION, "upgrade")
    {
        return Err(invalid("missing websocket upgrade headers"));
    }
    if single_header(&headers, http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_none_or(str::is_empty)
    {
        return Err(invalid("missing or duplicate host header"));
    }
    if single_header(&headers, http::header::SEC_WEBSOCKET_VERSION)
        .and_then(|value| value.to_str().ok())
        != Some("13")
    {
        return Err(invalid("unsupported websocket version"));
    }
    let key = single_header(&headers, http::header::SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| invalid("missing or duplicate websocket key"))?;
    let decoded = B64
        .decode(key)
        .map_err(|_| invalid("invalid websocket key"))?;
    if decoded.len() != 16 {
        return Err(invalid("invalid websocket key length"));
    }
    if headers.contains_key(http::header::TRANSFER_ENCODING) {
        return Err(invalid("transfer encoding is not valid on an upgrade"));
    }
    if let Some(length) = single_header(&headers, http::header::CONTENT_LENGTH) {
        if length.as_bytes() != b"0" {
            return Err(invalid("upgrade request body is not supported"));
        }
    } else if headers.get_all(http::header::CONTENT_LENGTH).iter().count() > 1 {
        return Err(invalid("duplicate content length"));
    }

    let uri = target
        .parse::<Uri>()
        .map_err(|_| invalid("invalid websocket request target"))?;
    let advertises_v2 = header_has_token(&headers, http::header::SEC_WEBSOCKET_PROTOCOL, "wisp-v2");
    let accept_key = websocket_accept_key(key);
    Ok(UpgradeInfo {
        path: uri.path().to_owned(),
        headers,
        advertises_v2,
        accept_key,
    })
}

fn single_header(headers: &HeaderMap, name: http::HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn header_has_token(headers: &HeaderMap, name: http::HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|raw| {
            raw.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn websocket_accept_key(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(WS_MAGIC);
    B64.encode(sha.digest().bytes())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub struct PrefixedIo {
    prefix: Bytes,
    tcp: TcpStream,
}

impl AsyncRead for PrefixedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let count = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..count]);
            self.prefix.advance(count);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.tcp.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_rfc_example() {
        let request = b"GET /wisp HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: wisp-v2\r\n\r\n";
        let parsed = parse_upgrade(request).expect("valid upgrade request");
        assert_eq!(parsed.path, "/wisp");
        assert!(parsed.advertises_v2);
        assert_eq!(parsed.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn rejects_missing_upgrade_headers() {
        let request = b"GET /wisp HTTP/1.1\r\nHost: example.test\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert!(parse_upgrade(request).is_err());
    }

    #[tokio::test]
    async fn replies_to_non_upgrade_http_requests() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("read listener address");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept test client");
            assert!(read_upgrade(tcp).await.is_err());
        });

        let mut client = TcpStream::connect(address)
            .await
            .expect("connect test client");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write HTTP request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read HTTP rejection");

        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        server.await.expect("server task completes");
    }
}

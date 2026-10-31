//! Bounded WebSocket upgrade handshake, rejection and duplex byte relay.
use std::time::Duration;

/// Relay an upgraded WebSocket byte stream while preserving the count of
/// successfully forwarded bytes on partial I/O failures or unclean TLS EOF.
pub(super) async fn relay_ws_counted<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> (u64, std::io::Result<()>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut total = 0_u64;
    let mut buf = [0_u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return (total, writer.flush().await),
            Ok(n) => match writer.write_all(&buf[..n]).await {
                Ok(()) => total = total.saturating_add(n as u64),
                Err(err) => return (total, Err(err)),
            },
            Err(err) => return (total, Err(err)),
        }
    }
}

/// A failed HTTP Upgrade is a normal HTTP response, not an arbitrary stream.
/// Read exactly Content-Length when supplied so upstream keep-alive cannot
/// hang the browser; bounded EOF fallback for close-delimited responses.
pub(super) async fn relay_upgrade_rejection_body<R, W>(
    head: &str,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const MAX_BODY: u64 = 4 * 1024 * 1024;
    let mut content_length = None;
    let mut transfer_encoding = false;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err(std::io::Error::other(
                        "duplicate upgrade rejection Content-Length",
                    ));
                }
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(std::io::Error::other(
                        "invalid upgrade rejection Content-Length",
                    ));
                }
                let parsed = value.parse::<u64>().map_err(|_| {
                    std::io::Error::other("invalid upgrade rejection Content-Length")
                })?;
                if parsed > MAX_BODY {
                    return Err(std::io::Error::other(
                        "upgrade rejection body exceeds limit",
                    ));
                }
                content_length = Some(parsed);
            }
            if key.eq_ignore_ascii_case("transfer-encoding") {
                transfer_encoding = true;
            }
        }
    }
    if transfer_encoding {
        // Chunked upgrade rejection is not yet supported; do not reinterpret
        // a chunked body or mix content-length and transfer-encoding.
        return Err(std::io::Error::other(
            "upgrade rejection transfer encoding unsupported",
        ));
    }
    if let Some(length) = content_length {
        let copied = tokio::io::copy(&mut (&mut *reader).take(length), &mut *writer).await?;
        if copied != length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated upgrade rejection body",
            ));
        }
    } else {
        let copied = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::io::copy(&mut (&mut *reader).take(MAX_BODY + 1), &mut *writer),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upgrade rejection body timed out",
            )
        })??;
        if copied > MAX_BODY {
            return Err(std::io::Error::other(
                "upgrade rejection body exceeds limit",
            ));
        }
    }
    writer.flush().await
}

/// Read only the HTTP response header for WebSocket upgrade handling.
pub(super) async fn read_http_response_head<R>(stream: &mut R) -> std::io::Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    const MAX_HEADERS: usize = 32 * 1024;
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if head.len() >= MAX_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ws response headers too large",
            ));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete ws response",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(head)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF8 ws response"))
}

pub(super) fn is_websocket_switching_protocols(head: &str) -> bool {
    let mut lines = head.split("\r\n");
    let Some(status) = lines.next() else {
        return false;
    };
    let mut status_parts = status.split_whitespace();
    if status_parts.next() != Some("HTTP/1.1") || status_parts.next() != Some("101") {
        return false;
    }
    let mut upgrade = false;
    let mut connection = false;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case("upgrade") {
            upgrade |= value.trim().eq_ignore_ascii_case("websocket");
        }
        if key.eq_ignore_ascii_case("connection") {
            connection |= value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"));
        }
    }
    upgrade && connection
}

/// Verify the RFC 6455 Sec-WebSocket-Accept challenge-response before
/// treating an HTTP 101 as an authenticated WebSocket upgrade.
pub(super) fn websocket_accept_matches(request: &str, response: &str) -> bool {
    use base64::Engine as _;
    if !is_websocket_switching_protocols(response) {
        return false;
    }
    let mut browser_key = None;
    for line in request.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("sec-websocket-key") {
                if browser_key.replace(value.trim()).is_some() {
                    return false;
                }
            }
        }
    }
    let Some(key) = browser_key else {
        return false;
    };
    let Ok(key_bytes) = base64::engine::general_purpose::STANDARD.decode(key) else {
        return false;
    };
    if key_bytes.len() != 16 {
        return false;
    }
    let challenge = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let Ok(digest) = cyberdeck_crypto::apply_op("sha1", challenge.as_bytes(), None) else {
        return false;
    };
    let expected = base64::engine::general_purpose::STANDARD.encode(digest);
    let mut accepted = None;
    for line in response.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("sec-websocket-accept") {
                if accepted.replace(value.trim()).is_some() {
                    return false;
                }
            }
        }
    }
    accepted == Some(expected.as_str())
}

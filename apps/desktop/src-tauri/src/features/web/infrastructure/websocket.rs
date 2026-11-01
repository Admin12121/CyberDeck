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
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(std::io::Error::other("folded upgrade rejection header"));
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(std::io::Error::other("malformed upgrade rejection header"));
        };
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(std::io::Error::other(
                "invalid upgrade rejection header name",
            ));
        }
        {
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
                if transfer_encoding || !value.trim().eq_ignore_ascii_case("chunked") {
                    return Err(std::io::Error::other(
                        "unsupported or duplicate upgrade rejection Transfer-Encoding",
                    ));
                }
                transfer_encoding = true;
            }
        }
    }
    if transfer_encoding {
        if content_length.is_some() {
            return Err(std::io::Error::other(
                "ambiguous upgrade rejection Content-Length and Transfer-Encoding",
            ));
        }
        // Preserve the original chunk-size lines, binary payloads and
        // terminating chunk instead of relaying unbounded EOF-delimited data.
        relay_chunked_rejection(reader, writer, MAX_BODY).await?;
        return writer.flush().await;
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

/// Read exactly one CRLF-terminated chunk metadata/trailer line.
async fn rejection_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut line = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= max {
            return Err(std::io::Error::other(
                "upgrade rejection chunk metadata limit exceeded",
            ));
        }
        reader.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}

/// Byte-for-byte relay of chunked HTTP/1.1 rejection bodies with a decoded
/// payload cap, bounded metadata/trailers and strict CRLF framing.
async fn relay_chunked_rejection<R, W>(
    reader: &mut R,
    writer: &mut W,
    max_body: u64,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut decoded = 0_u64;
    let mut framing_overhead = 0usize;
    const MAX_FRAMING_OVERHEAD: usize = 64 * 1024;
    loop {
        let line = rejection_line(reader, 2048).await?;
        framing_overhead = framing_overhead.saturating_add(line.len());
        if framing_overhead > MAX_FRAMING_OVERHEAD {
            return Err(std::io::Error::other(
                "upgrade rejection chunk overhead exceeded",
            ));
        }
        let token = line[..line.len() - 2]
            .split(|b| *b == b';')
            .next()
            .unwrap_or_default();
        if token.is_empty() || !token.iter().all(u8::is_ascii_hexdigit) {
            return Err(std::io::Error::other(
                "invalid upgrade rejection chunk size",
            ));
        }
        let token = std::str::from_utf8(token)
            .map_err(|_| std::io::Error::other("invalid chunk size encoding"))?;
        let size = u64::from_str_radix(token, 16)
            .map_err(|_| std::io::Error::other("chunk size overflow"))?;
        if size > max_body.saturating_sub(decoded) {
            return Err(std::io::Error::other(
                "upgrade rejection body exceeds limit",
            ));
        }
        writer.write_all(&line).await?;
        if size == 0 {
            let mut trailer_bytes = 0usize;
            for _ in 0..32 {
                let trailer = rejection_line(reader, 2048).await?;
                trailer_bytes = trailer_bytes.saturating_add(trailer.len());
                framing_overhead = framing_overhead.saturating_add(trailer.len());
                if framing_overhead > MAX_FRAMING_OVERHEAD {
                    return Err(std::io::Error::other(
                        "upgrade rejection chunk overhead exceeded",
                    ));
                }
                if trailer_bytes > 8192 {
                    return Err(std::io::Error::other(
                        "upgrade rejection trailers too large",
                    ));
                }
                if trailer != b"\r\n" {
                    let raw = &trailer[..trailer.len() - 2];
                    let Some(colon) = raw.iter().position(|b| *b == b':') else {
                        return Err(std::io::Error::other("malformed upgrade rejection trailer"));
                    };
                    let name = &raw[..colon];
                    if name.is_empty()
                        || !name
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
                        || name.eq_ignore_ascii_case(b"content-length")
                        || name.eq_ignore_ascii_case(b"transfer-encoding")
                    {
                        return Err(std::io::Error::other("forbidden upgrade rejection trailer"));
                    }
                }
                writer.write_all(&trailer).await?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
            return Err(std::io::Error::other("too many upgrade rejection trailers"));
        }
        let copied = tokio::io::copy(&mut (&mut *reader).take(size), &mut *writer).await?;
        if copied != size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated upgrade rejection chunk",
            ));
        }
        framing_overhead = framing_overhead.saturating_add(2);
        if framing_overhead > MAX_FRAMING_OVERHEAD {
            return Err(std::io::Error::other(
                "upgrade rejection chunk overhead exceeded",
            ));
        }
        let mut delimiter = [0u8; 2];
        reader.read_exact(&mut delimiter).await?;
        if delimiter != *b"\r\n" {
            return Err(std::io::Error::other(
                "invalid upgrade rejection chunk delimiter",
            ));
        }
        writer.write_all(&delimiter).await?;
        decoded += size;
    }
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

#[cfg(test)]
mod rejection_framing_tests {
    use super::relay_upgrade_rejection_body;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn chunked_rejection_keeps_binary_framing_and_extensions_exact() {
        let body = b"3;tag=a\r\n\xff\x00\x7f\r\n2\r\nOK\r\n0\r\nX-Trace: yes\r\n\r\n";
        let (mut input_tx, mut input_rx) = duplex(128);
        input_tx.write_all(body).await.unwrap();
        drop(input_tx);
        let (mut output_tx, mut output_rx) = duplex(128);
        relay_upgrade_rejection_body(
            "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n",
            &mut input_rx,
            &mut output_tx,
        )
        .await
        .unwrap();
        drop(output_tx);
        let mut actual = Vec::new();
        output_rx.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, body);
    }

    #[tokio::test]
    async fn rejection_refuses_ambiguous_or_malformed_chunked_responses() {
        for head in [
            "HTTP/1.1 403\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 403\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "HTTP/1.1 403\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            let (mut input_tx, mut input_rx) = duplex(128);
            input_tx.write_all(b"0\r\n\r\n").await.unwrap();
            drop(input_tx);
            let (mut output_tx, _) = duplex(128);
            assert!(
                relay_upgrade_rejection_body(head, &mut input_rx, &mut output_tx)
                    .await
                    .is_err()
            );
        }
        for body in [
            &b"x\r\n0\r\n\r\n"[..],
            &b"2\r\nA!\n0\r\n\r\n"[..],
            &b"0\r\nContent-Length: 2\r\n\r\n"[..],
        ] {
            let (mut input_tx, mut input_rx) = duplex(128);
            input_tx.write_all(body).await.unwrap();
            drop(input_tx);
            let (mut output_tx, _) = duplex(128);
            assert!(relay_upgrade_rejection_body(
                "HTTP/1.1 403\r\nTransfer-Encoding: chunked\r\n\r\n",
                &mut input_rx,
                &mut output_tx,
            )
            .await
            .is_err());
        }
    }
}

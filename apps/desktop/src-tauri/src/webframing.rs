//! Defensive HTTP/1.1 request-body framing shared by plaintext and TLS proxy paths.
//! We normalize incoming chunked bodies to raw bytes; downstream reqwest
//! generates an unambiguous Content-Length. Do not forward original framing.

use std::io::{Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BodyFraming {
    Fixed(usize),
    Chunked,
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

/// Reject request-smuggling ambiguity: repeated CL, CL + TE, folding,
/// unsupported transfer codings and malformed header names.
pub fn parse_framing(head: &str, max_body: usize) -> std::io::Result<BodyFraming> {
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(invalid("ambiguous framing: folded header"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed HTTP header"))?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(invalid("invalid HTTP header name"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(invalid("ambiguous framing: duplicate Content-Length"));
            }
            let v = value.trim();
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("invalid Content-Length"));
            }
            length = Some(v.parse().map_err(|_| invalid("invalid Content-Length"))?);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(invalid("unsupported or duplicate Transfer-Encoding"));
            }
            chunked = true;
        }
    }
    if chunked && length.is_some() {
        return Err(invalid("ambiguous framing: Content-Length and Transfer-Encoding"));
    }
    if chunked {
        return Ok(BodyFraming::Chunked);
    }
    let n = length.unwrap_or(0);
    if n > max_body {
        return Err(invalid("HTTP body limit exceeded"));
    }
    Ok(BodyFraming::Fixed(n))
}

async fn line_crlf<R: AsyncRead + Unpin>(reader: &mut R, max: usize) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(32);
    let mut byte = [0_u8; 1];
    loop {
        if line.len() >= max {
            return Err(invalid("chunk metadata limit exceeded"));
        }
        reader.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
}

/// Decode one transfer-encoded body, never buffering more than max_body.
/// Reject trailers for now instead of silently losing semantically relevant
/// headers; reject chunk extensions beyond the bounded line limit.
pub async fn read_chunked<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_body: usize,
) -> std::io::Result<Vec<u8>> {
    const MAX_CHUNK_LINE: usize = 2048;
    let mut result = Vec::new();
    loop {
        let line = line_crlf(reader, MAX_CHUNK_LINE).await?;
        let size_token = line.split(|b| *b == b';').next().unwrap_or(&[]);
        if size_token.is_empty() || !size_token.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid("invalid HTTP chunk size"));
        }
        let token = std::str::from_utf8(size_token)
            .map_err(|_| invalid("invalid HTTP chunk size"))?;
        let size = usize::from_str_radix(token, 16)
            .map_err(|_| invalid("HTTP chunk size overflow"))?;
        if size == 0 {
            let trailer = line_crlf(reader, MAX_CHUNK_LINE).await?;
            if !trailer.is_empty() {
                return Err(invalid("HTTP chunked request trailers unsupported"));
            }
            return Ok(result);
        }
        let remaining = max_body.saturating_sub(result.len());
        if size > remaining {
            return Err(invalid("HTTP chunked body limit exceeded"));
        }
        let start = result.len();
        result.resize(start + size, 0);
        reader.read_exact(&mut result[start..]).await?;
        let mut terminator = [0_u8; 2];
        reader.read_exact(&mut terminator).await?;
        if terminator != *b"\r\n" {
            return Err(invalid("HTTP chunk data missing CRLF"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    #[test]
    fn validates_framing_and_ambiguity() {
        assert_eq!(parse_framing("POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\n", 4).unwrap(), BodyFraming::Fixed(3));
        assert_eq!(parse_framing("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 4).unwrap(), BodyFraming::Chunked);
        for bad in [
            "Transfer-Encoding: gzip, chunked",
            "Transfer-Encoding: identity",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nContent-Length: 5",
            "Content-Length: 5\r\nContent-Length: 5",
            "Content-Length: +5",
            "Content-Length: 1, 2",
            "BrokenHeader",
            "X-A: ok\r\n continued",
        ] {
            let msg = format!("POST / HTTP/1.1\r\nHost: localhost\r\n{bad}\r\n\r\n");
            assert!(parse_framing(&msg, 1024).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn decodes_chunked_binary_without_loss() {
        let (mut tx, mut rx) = duplex(128);
        tx.write_all(b"3\r\n\xff\x00\x7f\r\n2;label=a\r\nOK\r\n0\r\n\r\n").await.unwrap();
        let value = read_chunked(&mut rx, 10).await.unwrap();
        assert_eq!(value, [0xff, 0x00, 0x7f, b'O', b'K']);
    }

    #[tokio::test]
    async fn rejects_malformed_chunk_delimiter_and_trailer() {
        for bytes in [
            &b"2\r\nABxx0\r\n\r\n"[..],
            &b"0\r\nAuthorization: test\r\n\r\n"[..],
            &b"x\r\n0\r\n\r\n"[..],
            &b"5\r\nABC\r\n"[..],
        ] {
            let (mut tx, mut rx) = duplex(128);
            tx.write_all(bytes).await.unwrap();
            drop(tx);
            assert!(read_chunked(&mut rx, 64).await.is_err());
        }
    }

    #[tokio::test]
    async fn refuses_expansion_over_limit() {
        let (mut tx, mut rx) = duplex(128);
        tx.write_all(b"5\r\nHELLO\r\n0\r\n\r\n").await.unwrap();
        assert!(read_chunked(&mut rx, 4).await.is_err());
    }
}

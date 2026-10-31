//! Passive, bounded single-record TLS hello and HTTP start-line inspection.
//! No network I/O, TLS decryption, or assumption about TCP reassembly.

const MAX_TLS_RECORD: usize = 18_432;
const MAX_EXTENSIONS: usize = 128;

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn field8<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let count = *data.get(*pos)? as usize;
    *pos = pos.checked_add(1)?;
    let end = pos.checked_add(count)?;
    let value = data.get(*pos..end)?;
    *pos = end;
    Some(value)
}
fn field16<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let count = be16(data, *pos)? as usize;
    *pos = pos.checked_add(2)?;
    let end = pos.checked_add(count)?;
    let value = data.get(*pos..end)?;
    *pos = end;
    Some(value)
}
pub fn http_start_line(data: &[u8]) -> Option<String> {
    let end = data.iter().take(2049).position(|b| *b == b'\n')?;
    if end == 0 || end > 2048 || data[end - 1] != b'\r' {
        return None;
    }
    let bytes = &data[..end - 1];
    if !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return None;
    }
    let line = std::str::from_utf8(bytes).ok()?;
    if line.starts_with("HTTP/1.1 ") || line.starts_with("HTTP/1.0 ") {
        let status = line.split_whitespace().nth(1)?;
        if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    } else {
        let (method, remaining) = line.split_once(' ')?;
        if !matches!(
            method,
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
        ) {
            return None;
        }
        let (uri, version) = remaining.rsplit_once(' ')?;
        if uri.is_empty() || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
            return None;
        }
    }
    Some(line.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHello {
    pub client: bool,
    pub legacy_version: u16,
    /// For ClientHello this is a supported version offered by the client;
    /// for ServerHello it is the selected version.
    pub version: Option<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher: Option<u16>,
}

fn sni(ext: &[u8]) -> Option<String> {
    if be16(ext, 0)? as usize != ext.len().checked_sub(2)? {
        return None;
    }
    let mut at = 2usize;
    for _ in 0..8 {
        if at == ext.len() {
            return None;
        }
        let kind = *ext.get(at)?;
        let count = be16(ext, at + 1)? as usize;
        at += 3;
        let end = at.checked_add(count)?;
        let name = ext.get(at..end)?;
        if kind == 0 {
            if name.is_empty()
                || name.len() > 253
                || !name
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
            {
                return None;
            }
            return Some(std::str::from_utf8(name).ok()?.to_owned());
        }
        at = end;
    }
    None
}

fn alpn(ext: &[u8]) -> Option<Vec<String>> {
    if be16(ext, 0)? as usize != ext.len().checked_sub(2)? {
        return None;
    }
    let mut protocols = Vec::new();
    let mut at = 2;
    while at < ext.len() {
        if protocols.len() >= 8 {
            return None;
        }
        let protocol = field8(ext, &mut at)?;
        if protocol.is_empty() || !protocol.iter().all(|c| (0x21..=0x7e).contains(c)) {
            return None;
        }
        protocols.push(std::str::from_utf8(protocol).ok()?.to_owned());
    }
    Some(protocols)
}

pub fn tls_hello(data: &[u8]) -> Option<TlsHello> {
    if data.len() < 9 || data[0] != 22 || data[1] != 3 {
        return None;
    }
    let record_len = be16(data, 3)? as usize;
    if !(4..=MAX_TLS_RECORD).contains(&record_len) || data.len() < record_len + 5 {
        return None;
    }
    let record = &data[5..5 + record_len];
    let kind = record[0];
    if kind != 1 && kind != 2 {
        return None;
    }
    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    if handshake_len > MAX_TLS_RECORD || handshake_len + 4 > record.len() {
        return None;
    }
    let hello = &record[4..4 + handshake_len];
    if hello.len() < 35 || hello[0] != 3 {
        return None;
    }
    let legacy_version = be16(hello, 0)?;
    let mut cursor = 34; // legacy version + 32-byte random
    field8(hello, &mut cursor)?; // session ID
    let mut cipher = None;
    if kind == 1 {
        let suites = field16(hello, &mut cursor)?;
        if suites.is_empty() || suites.len() % 2 != 0 {
            return None;
        }
        if field8(hello, &mut cursor)?.is_empty() {
            return None;
        }
    } else {
        cipher = Some(be16(hello, cursor)?);
        cursor += 2;
        *hello.get(cursor)?; // compression
        cursor += 1;
    }
    let mut out = TlsHello {
        client: kind == 1,
        legacy_version,
        version: None,
        sni: None,
        alpn: Vec::new(),
        cipher,
    };
    if cursor == hello.len() {
        return Some(out);
    }
    let extensions = field16(hello, &mut cursor)?;
    if cursor != hello.len() {
        return None;
    }
    let mut at = 0;
    let mut seen = 0;
    while at < extensions.len() {
        if seen >= MAX_EXTENSIONS {
            return None;
        }
        let kind = be16(extensions, at)?;
        let count = be16(extensions, at + 2)? as usize;
        at += 4;
        let end = at.checked_add(count)?;
        let ext = extensions.get(at..end)?;
        at = end;
        seen += 1;
        match kind {
            0 if out.client => out.sni = Some(sni(ext)?),
            16 => out.alpn = alpn(ext)?,
            43 if !out.client && ext.len() == 2 => out.version = Some(be16(ext, 0)?),
            43 if out.client => {
                if ext.len() < 3 || ext[0] as usize + 1 != ext.len() || ext.len() % 2 != 1 {
                    return None;
                }
                if ext[1..].chunks_exact(2).any(|x| x == [3, 4]) {
                    out.version = Some(0x0304);
                }
            }
            _ => {}
        }
    }
    Some(out)
}

fn version(version: u16) -> String {
    match version {
        0x0301 => "TLS1.0".into(),
        0x0302 => "TLS1.1".into(),
        0x0303 => "TLS1.2".into(),
        0x0304 => "TLS1.3".into(),
        v => format!("0x{v:04x}"),
    }
}
pub fn tls_description(tls: &TlsHello) -> String {
    let role = if tls.client {
        "ClientHello"
    } else {
        "ServerHello"
    };
    let v = tls
        .version
        .map(version)
        .unwrap_or_else(|| version(tls.legacy_version));
    let mut value = format!("TLS {role} {v}");
    if tls.client && tls.version.is_some() {
        value.push_str(" (offered)");
    }
    if let Some(host) = &tls.sni {
        value.push_str(" SNI=");
        value.push_str(host);
    }
    if !tls.alpn.is_empty() {
        value.push_str(" ALPN=");
        value.push_str(&tls.alpn.join(","));
    }
    if let Some(cipher) = tls.cipher {
        value.push_str(&format!(" cipher=0x{cipher:04x}"));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Vec<u8> {
        let mut h = vec![3, 3];
        h.extend([7; 32]);
        h.push(0); // session ID
        h.extend([0, 2, 0x13, 0x01]); // ciphers
        h.extend([1, 0]); // compressions
        let host = b"example.com";
        let mut sn = vec![0, (host.len() + 3) as u8, 0, 0, host.len() as u8];
        sn.extend(host);
        let mut extensions = vec![0, 0, 0, sn.len() as u8];
        extensions.extend(sn);
        let mut alpn = vec![0, 12, 2, b'h', b'2', 8];
        alpn.extend(b"http/1.1");
        extensions.extend([0, 16, 0, alpn.len() as u8]);
        extensions.extend(alpn);
        extensions.extend([0, 43, 0, 3, 2, 3, 4]);
        h.extend((extensions.len() as u16).to_be_bytes());
        h.extend(extensions);
        let mut message = vec![1, 0, 0, h.len() as u8];
        message.extend(h);
        let mut record = vec![22, 3, 3];
        record.extend((message.len() as u16).to_be_bytes());
        record.extend(message);
        record
    }

    #[test]
    fn recognizes_http_startline_but_rejects_malformed() {
        assert_eq!(
            http_start_line(b"GET / HTTP/1.1\r\nHost: example.org\r\n").unwrap(),
            "GET / HTTP/1.1"
        );
        assert_eq!(
            http_start_line(b"HTTP/1.1 404 Not Found\r\n").unwrap(),
            "HTTP/1.1 404 Not Found"
        );
        assert!(http_start_line(b"GET / HTTP/1.1\n").is_none());
        assert!(http_start_line(b"GET / HTTP/1.1\r").is_none());
        assert!(http_start_line(b"BANANA / HTTP/1.1\r\n").is_none());
    }
    #[test]
    fn clienthello_parses_sni_alpn_and_offered_version() {
        let hello = tls_hello(&client()).unwrap();
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, ["h2", "http/1.1"]);
        assert_eq!(hello.version, Some(0x0304));
        assert!(tls_description(&hello).contains("offered"));
    }
    #[test]
    fn rejects_truncated_or_inconsistent_tls() {
        let mut data = client();
        data.pop();
        assert!(tls_hello(&data).is_none());
        data = client();
        data[3] = 0xff;
        assert!(tls_hello(&data).is_none());
        assert!(tls_hello(b"not tls").is_none());
    }
    #[test]
    fn server_hello_exposes_cipher_and_selected_version() {
        let mut h = vec![3, 3];
        h.extend([0x25; 32]);
        h.extend([0, 0x13, 0x01, 0]);
        h.extend([0, 6, 0, 43, 0, 2, 3, 4]);
        let mut record = vec![22, 3, 3, 0, (h.len() + 4) as u8, 2, 0, 0, h.len() as u8];
        record.extend(h);
        let hello = tls_hello(&record).unwrap();
        assert!(!hello.client);
        assert_eq!(hello.cipher, Some(0x1301));
        assert_eq!(hello.version, Some(0x0304));
    }
}

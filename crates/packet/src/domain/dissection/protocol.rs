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

const MAX_HTTP_HEADERS: usize = 32;
const MAX_HTTP_HEADER_BLOCK: usize = 4096;
const MAX_HTTP_HEADER_LINE: usize = 512;

/// Bounded HTTP/1.x header fields from a single captured segment, starting
/// at a validated start line. Only complete header lines within the captured
/// bytes are read; a segment boundary silently ends the block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpFields {
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub location: Option<String>,
}

fn header_value(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_HTTP_HEADER_LINE {
        return None;
    }
    // Visible ASCII only; the dissector never guesses encodings.
    if !raw.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?.trim().to_owned();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

pub fn http_fields(data: &[u8]) -> Option<HttpFields> {
    let start = http_start_line(data)?;
    let mut fields = HttpFields::default();
    if let Some(status) = start.split_whitespace().nth(1) {
        fields.status_code = status.parse::<u16>().ok();
    }
    let mut cursor = data
        .iter()
        .take(MAX_HTTP_HEADER_BLOCK)
        .position(|b| *b == b'\n')?
        + 1;
    let block_end = (cursor + MAX_HTTP_HEADER_BLOCK).min(data.len());
    for _ in 0..MAX_HTTP_HEADERS {
        let line_end = data
            .get(cursor..block_end)?
            .iter()
            .position(|b| *b == b'\n')?
            + cursor;
        let line = &data[cursor..line_end];
        cursor = line_end + 1;
        // Strip the carriage return; a bare CRLF line ends the header block.
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        // Stable Rust has no slice split_once; find the first ": " separator.
        let separator =
            (0..line.len().saturating_sub(1)).find(|i| line[*i] == b':' && line[*i + 1] == b' ');
        let Some(separator) = separator else { break };
        let name = &line[..separator];
        // An unusable name or value skips that header; extraction of the
        // remaining block continues — one bad line never erases the rest.
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        let Some(value) = header_value(&line[separator + 2..]) else {
            continue;
        };
        match name.to_ascii_lowercase().as_str() {
            "host" => fields.host = Some(value),
            "user-agent" => fields.user_agent = Some(value),
            "content-type" => fields.content_type = Some(value),
            "location" => fields.location = Some(value),
            _ => {}
        }
    }
    Some(fields)
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
    /// The captured first record, bounded by MAX_TLS_RECORD. Carried so the
    /// depth pass in tls_description can re-walk the extensions without
    /// re-validating transport framing; nothing beyond the captured bytes is
    /// ever read.
    pub payload: Vec<u8>,
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
        // Keep exactly the dissected record; trailing captured bytes after
        // the first record belong to other messages and are not claimed.
        payload: data[..record_len + 5].to_vec(),
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
    // Depth suffix from the same captured record: the named cipher suite
    // replaces the raw code when the IANA table knows it, and up to four
    // named extensions summarize the inventory. Everything stays bounded and
    // honest — a hello the depth pass cannot accept keeps the raw form.
    let depth = super::tls_depth::hello_depth(&tls.payload);
    match depth.as_ref().and_then(|d| d.cipher_name.clone()) {
        Some(name) => value.push_str(&format!(" cipher={name}")),
        None => {
            if let Some(cipher) = tls.cipher {
                value.push_str(&format!(" cipher=0x{cipher:04x}"));
            }
        }
    }
    if let Some(depth) = depth {
        let named: Vec<&str> = depth.extensions.iter().take(4).map(String::as_str).collect();
        if !named.is_empty() {
            value.push_str(" ext=");
            value.push_str(&named.join(","));
        }
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
    fn http_fields_extract_request_and_response_headers_bounded() {
        let request =
            b"GET /api/evidence HTTP/1.1\r\nHost: lab.test\r\nUser-Agent: CyberDeck/1\r\n\r\nbody";
        let fields = http_fields(request).unwrap();
        assert_eq!(fields.host.as_deref(), Some("lab.test"));
        assert_eq!(fields.user_agent.as_deref(), Some("CyberDeck/1"));
        assert_eq!(fields.status_code, None);

        let response = b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Type: text/html\r\n\r\n";
        let fields = http_fields(response).unwrap();
        assert_eq!(fields.status_code, Some(302));
        assert_eq!(fields.location.as_deref(), Some("/login"));
        assert_eq!(fields.content_type.as_deref(), Some("text/html"));

        // Non-ASCII values are refused, not guessed: the header is skipped
        // while extraction continues.
        let bad = http_fields(b"GET / HTTP/1.1\r\nHost: \xff\xfe\r\n\r\n").unwrap();
        assert_eq!(bad.host, None);
        // A header line beyond the line cap ends extraction without a panic.
        let mut oversized = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
        oversized.extend(vec![b'a'; MAX_HTTP_HEADER_LINE + 64]);
        oversized.extend(b"\r\n\r\n");
        let fields = http_fields(&oversized);
        assert!(fields.is_some());
        assert_eq!(fields.unwrap().host, None);
    }
    #[test]
    fn description_appends_named_cipher_and_extension_depth() {
        // The existing ClientHello fixture offers SNI, ALPN and versions;
        // the depth suffix names them and claims no single cipher suite.
        let hello = tls_hello(&client()).unwrap();
        let description = tls_description(&hello);
        assert!(description.contains(" ext=server_name,alpn,supported_versions"));
        assert!(!description.contains("cipher"));

        // A TLS 1.3 ServerHello selecting AES-256-GCM names the suite and
        // the share group's extension set.
        let mut server = vec![3, 3];
        server.extend([9; 32]);
        server.push(0); // session ID
        server.extend(0x1302u16.to_be_bytes());
        server.push(0); // compression
        let mut key_share = vec![0x00, 0x1D, 0, 32];
        key_share.extend([6; 32]);
        let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51];
        extensions.extend((key_share.len() as u16).to_be_bytes());
        extensions.extend(key_share);
        server.extend((extensions.len() as u16).to_be_bytes());
        server.extend(extensions);
        let mut message = vec![2, 0, 0, server.len() as u8];
        message.extend(server);
        let mut record = vec![22, 3, 3];
        record.extend((message.len() as u16).to_be_bytes());
        record.extend(message);
        let hello = tls_hello(&record).unwrap();
        let description = tls_description(&hello);
        assert!(description.contains("TLS ServerHello TLS1.3"));
        assert!(description.contains(" cipher=TLS_AES_256_GCM_SHA384"));
        assert!(description.contains(" ext=supported_versions,key_share"));
    }
    #[test]
    fn description_falls_back_to_raw_code_when_depth_has_no_name() {
        // A minimal ServerHello with an unnamed suite keeps the raw hex form;
        // nothing outside the name tables is invented.
        let mut server = vec![3, 3];
        server.extend([9; 32]);
        server.push(0);
        server.extend(0xABCDu16.to_be_bytes());
        server.push(0);
        let mut message = vec![2, 0, 0, server.len() as u8];
        message.extend(server);
        let mut record = vec![22, 3, 3];
        record.extend((message.len() as u16).to_be_bytes());
        record.extend(message);
        let hello = tls_hello(&record).unwrap();
        assert_eq!(
            tls_description(&hello),
            "TLS ServerHello TLS1.2 cipher=0xabcd"
        );
    }
}

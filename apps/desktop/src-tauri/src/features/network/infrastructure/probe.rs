//! Platform TCP connect and bounded banner probing. Active scanning only after
//! the legacy IPC command performs explicit authorization checks.
use super::ScanObservation;
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(900);
const BANNER_TIMEOUT: Duration = Duration::from_millis(400);
// DNS over TCP (RFC 1035 §4.2.2): one small, fixed root NS question. No
// recursive target expansion, version.bind query, authentication or DB reuse.
const DNS_RESPONSE_LIMIT: usize = 4096;
const DNS_QUESTION: [u8; 5] = [0, 0, 2, 0, 1]; // "." NS IN

/// Validate a received DNS reply *against our question*, never against a port
/// number or an arbitrary DNS-looking prefix. Returns the actual RCODE.
fn dns_tcp_response_rcode(reply: &[u8], expected_id: u16) -> Option<u8> {
    if reply.len() < 12 + DNS_QUESTION.len()
        || reply.len() > DNS_RESPONSE_LIMIT
        || u16::from_be_bytes([reply[0], reply[1]]) != expected_id
        || (reply[2] & 0x80) == 0 // QR: server response
        || (reply[2] & 0x78) != 0 // opcode: standard query
        || u16::from_be_bytes([reply[4], reply[5]]) != 1
        || reply[12..17] != DNS_QUESTION
    {
        return None;
    }
    Some(reply[3] & 0x0f)
}

/// Total wall-clock deadline (rather than 400ms *per byte*) prevents a TCP
/// peer from keeping a scan worker alive indefinitely by dripping DNS bytes.
fn read_dns_exact(stream: &mut TcpStream, out: &mut [u8], until: Instant) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < out.len() {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "DNS read deadline",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        match std::io::Read::read(stream, &mut out[offset..]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => offset += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Exactly one application-level query on an explicitly authorized open TCP
/// socket. It does not contact any name returned by the DNS server.
fn dns_tcp_probe(stream: &mut TcpStream) -> Option<u8> {
    let request_id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as u16)
        ^ 0x8a6d;
    let mut request = [0u8; 19];
    request[..2].copy_from_slice(&(17u16).to_be_bytes());
    request[2..4].copy_from_slice(&request_id.to_be_bytes());
    request[4..6].copy_from_slice(&[0x01, 0x00]); // recursion desired
    request[6..8].copy_from_slice(&1u16.to_be_bytes()); // one root NS question
    request[14..19].copy_from_slice(&DNS_QUESTION);
    std::io::Write::write_all(stream, &request).ok()?;
    let until = Instant::now() + BANNER_TIMEOUT;
    let mut length_bytes = [0u8; 2];
    read_dns_exact(stream, &mut length_bytes, until).ok()?;
    let len = u16::from_be_bytes(length_bytes) as usize;
    if !(17..=DNS_RESPONSE_LIMIT).contains(&len) {
        return None;
    }
    let mut reply = vec![0u8; len];
    read_dns_exact(stream, &mut reply, until).ok()?;
    dns_tcp_response_rcode(&reply, request_id)
}

/// Recognize a structurally complete TLS ServerHello (RFC 5246/8446).
/// Evidence is only that the remote side spoke TLS; neither its certificate
/// nor claimed application/software is authenticated at this stage.
fn parse_tls_server_hello(record: &[u8]) -> Option<String> {
    if record.len() < 5 || record[0] != 22 || record[1] != 3 || !(0..=4).contains(&record[2]) {
        return None;
    }
    let declared = u16::from_be_bytes([record[3], record[4]]) as usize;
    if declared > DNS_RESPONSE_LIMIT || declared < 42 || record.len() != declared + 5 {
        return None;
    }
    let payload = &record[5..];
    if payload[0] != 2 {
        return None;
    }
    let length =
        (usize::from(payload[1]) << 16) | (usize::from(payload[2]) << 8) | usize::from(payload[3]);
    if length < 38 || length + 4 != payload.len() {
        return None;
    }
    let hello = &payload[4..];
    if hello[0] != 3 || !(1..=4).contains(&hello[1]) {
        return None;
    }
    let session_len = usize::from(hello[34]);
    if session_len > 32 || hello.len() < 35 + session_len + 3 {
        return None;
    }
    let suite_idx = 35 + session_len;
    let suite = u16::from_be_bytes([hello[suite_idx], hello[suite_idx + 1]]);
    if suite == 0 || hello[suite_idx + 2] != 0 {
        return None;
    }
    let ext_idx = suite_idx + 3;
    if ext_idx < hello.len() {
        if hello.len() < ext_idx + 2 {
            return None;
        }
        let ext_len = u16::from_be_bytes([hello[ext_idx], hello[ext_idx + 1]]) as usize;
        if ext_idx + 2 + ext_len != hello.len() {
            return None;
        }
    }
    Some(format!(
        "TLS ServerHello, cipher 0x{suite:04x} (identity unverified)"
    ))
}

/// Let rustls generate the ClientHello using its secure RNG and supported
/// suites. We stop after validated ServerHello; no trust bypass or certificate
/// verification is claimed, and the target is already an authorized IP.
fn active_tls_probe(stream: &mut TcpStream, host: IpAddr) -> Option<String> {
    use std::sync::{Arc, OnceLock};
    static CLIENT_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CLIENT_CONFIG.get_or_init(|| {
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
    });
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
    let mut client = rustls::ClientConnection::new(Arc::clone(config), name).ok()?;
    let mut hello = Vec::with_capacity(2048);
    client.write_tls(&mut hello).ok()?;
    if hello.is_empty() || hello.len() > DNS_RESPONSE_LIMIT {
        return None;
    }
    std::io::Write::write_all(stream, &hello).ok()?;
    let deadline = Instant::now() + BANNER_TIMEOUT;
    let mut header = [0u8; 5];
    read_dns_exact(stream, &mut header, deadline).ok()?;
    let size = u16::from_be_bytes([header[3], header[4]]) as usize;
    if !(42..=DNS_RESPONSE_LIMIT).contains(&size) {
        return None;
    }
    let mut record = Vec::with_capacity(size + 5);
    record.extend_from_slice(&header);
    record.resize(size + 5, 0);
    read_dns_exact(stream, &mut record[5..], deadline).ok()?;
    parse_tls_server_hello(&record)
}

/// Independently authored fixed safe service commands. We do not load or
/// translate Nmap's licensed service probe database.
#[derive(Clone, Copy)]
enum TextProbe {
    SmtpEhlo,
    FtpFeat,
}

impl TextProbe {
    fn request(self) -> &'static [u8] {
        match self {
            Self::SmtpEhlo => b"EHLO cyberdeck.invalid\r\n",
            Self::FtpFeat => b"FEAT\r\n",
        }
    }

    fn terminal_code(self) -> &'static [u8; 3] {
        match self {
            Self::SmtpEhlo => b"250",
            Self::FtpFeat => b"211",
        }
    }
}

/// Match only a complete reply with a terminal line. A single 250-/211-
/// continuation fragment, truncated CRLF, or arbitrary binary data is not
/// enough to establish that the target handled our command.
fn text_probe_reply_valid(raw: &[u8], code: &[u8; 3]) -> bool {
    if raw.len() > 512 || raw.len() < 6 || !raw.ends_with(b"\r\n") {
        return false;
    }
    if raw
        .iter()
        .any(|b| !matches!(*b, b'\r' | b'\n' | 0x20..=0x7e))
    {
        return false;
    }
    let mut lines = raw.split(|b| *b == b'\n').filter(|line| !line.is_empty());
    let mut seen = false;
    while let Some(line) = lines.next() {
        if line.len() < 5
            || line.last() != Some(&b'\r')
            || &line[..3] != code
            || !matches!(line[3], b' ' | b'-')
        {
            return false;
        }
        seen = true;
        if line[3] == b' ' {
            return lines.next().is_none();
        }
    }
    let _ = seen;
    false
}

/// A positive result proves a response to a fixed safe command, not a server
/// software version. Total deadline and byte cap are shared across reads.
fn active_text_probe(stream: &mut TcpStream, probe: TextProbe) -> bool {
    if std::io::Write::write_all(stream, probe.request()).is_err() {
        return false;
    }
    let deadline = Instant::now() + BANNER_TIMEOUT;
    let mut buffer = [0u8; 512];
    let mut size = 0usize;
    while size < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return false;
        }
        let count = match std::io::Read::read(stream, &mut buffer[size..]) {
            Ok(0) | Err(_) => return false,
            Ok(count) => count,
        };
        size += count;
        if text_probe_reply_valid(&buffer[..size], probe.terminal_code()) {
            return true;
        }
        if buffer[size.saturating_sub(2)..size] == *b"\r\n" {
            // Completed invalid reply; do not wait through unsolicited chatter.
            if buffer[size.saturating_sub(5)..].starts_with(probe.terminal_code()) {
                return false;
            }
        }
    }
    false
}

pub(super) fn well_known_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        1433 => "ms-sql",
        3306 => "mysql",
        3389 => "ms-wbt",
        5432 => "postgresql",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "",
    }
}

/// Report only a remote system's self-asserted SSH software token or HTTP
/// Server header. It is *not* independently verified product/version evidence.
pub(super) fn remote_software_claim(raw: &str) -> Option<String> {
    fn safe_token(text: &str) -> Option<String> {
        let token = text.split_ascii_whitespace().next()?;
        if token.is_empty()
            || token.len() > 64
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'/'))
        {
            return None;
        }
        Some(token.to_string())
    }
    let first = raw.lines().next()?.trim_end_matches('\r');
    for tag in ["SSH-2.0-", "SSH-1.99-", "SSH-1.5-"] {
        if let Some(claim) = first.strip_prefix(tag) {
            return safe_token(claim);
        }
    }
    if first.starts_with("HTTP/1.0 ") || first.starts_with("HTTP/1.1 ") {
        for line in raw.lines().skip(1).take(24) {
            let line = line.trim_end_matches('\r');
            if line
                .get(..7)
                .is_some_and(|header| header.eq_ignore_ascii_case("Server:"))
            {
                return line.get(7..).and_then(|rest| safe_token(rest.trim_start()));
            }
        }
    }
    None
}

/// Strict, bounded first-read binary/text service identification. Each
/// protocol is recognized from a full structural greeting, not its port or
/// partially decoded text. No third-party Nmap signatures are copied.
pub(super) fn observed_service_bytes(data: &[u8]) -> Option<&'static str> {
    if data.is_empty() || data.len() > 512 {
        return None;
    }
    // MySQL initial handshake: 3-byte little-endian payload length, server
    // sequence 0, protocol 10 and a NUL-terminated printable version token.
    if data.len() >= 12 && data[3] == 0 && data[4] == 10 {
        let length =
            usize::from(data[0]) | (usize::from(data[1]) << 8) | (usize::from(data[2]) << 16);
        if length >= 8 && length + 4 <= data.len() {
            let version = &data[5..(data.len().min(5 + 64))];
            if let Some(end) = version.iter().position(|b| *b == 0) {
                if (3..=63).contains(&end) && version[..end].iter().all(|b| b.is_ascii_graphic()) {
                    return Some("mysql");
                }
            }
        }
    }
    // RFB greeting has a fixed 12-byte printable version and trailing LF.
    if data.len() >= 12
        && &data[..4] == b"RFB "
        && &data[4..7] == b"003"
        && data[7] == b'.'
        && data[8..11].iter().all(u8::is_ascii_digit)
        && data[11] == b'\n'
    {
        return Some("vnc");
    }
    // The server-side rsync daemon's initial protocol message.
    if data.starts_with(b"@RSYNCD: ") && data.contains(&b'\n') {
        let first = data.split(|b| *b == b'\n').next()?;
        if (10..=24).contains(&first.len())
            && first[9..]
                .iter()
                .all(|b| b.is_ascii_digit() || *b == b'.' || *b == b'\r')
        {
            return Some("rsync");
        }
    }
    // IMAP requires the server's explicitly marked initial OK greeting.
    if data.starts_with(b"* OK ") && data.windows(2).any(|part| part == b"\r\n") {
        return Some("imap");
    }
    // POP3 ready message must be framed by a complete CRLF-terminated line.
    if data.starts_with(b"+OK ") && data.windows(2).any(|part| part == b"\r\n") {
        return Some("pop3");
    }
    None
}

/// Return a protocol only when actual response bytes provide recognizable
/// evidence, including services listening on unexpected TCP ports. Unlike the
/// fallback port table, this is not a claim about the remote software version.
/// Independently authored from common protocol greeting formats.
pub(super) fn observed_service(banner: &str) -> Option<&'static str> {
    let first = banner.lines().next()?.trim();
    if first.starts_with("SSH-2.0-")
        || first.starts_with("SSH-1.99-")
        || first.starts_with("SSH-1.5-")
    {
        return Some("ssh");
    }
    if first.starts_with("HTTP/1.0 ")
        || first.starts_with("HTTP/1.1 ")
        || first.starts_with("HTTP/2 ")
    {
        return Some("http");
    }
    if first.starts_with("220 ") || first.starts_with("220-") {
        let lower = first.to_ascii_lowercase();
        if lower.contains("esmtp") || lower.contains("smtp") {
            return Some("smtp");
        }
        if lower.contains("ftp") {
            return Some("ftp");
        }
    }
    None
}

/// Condense a raw service banner to the informative first line / header.
pub(super) fn summarize_banner(raw: &str) -> String {
    let first_line = raw.lines().next().unwrap_or("").trim().to_string();
    if first_line.to_lowercase().starts_with("http/") {
        let server = raw
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .map(|l| l.trim().to_string())
            .unwrap_or_default();
        if server.is_empty() {
            first_line
        } else {
            format!("{first_line} · {server}")
        }
    } else {
        first_line.chars().take(120).collect()
    }
}

/// Do not mistake a timeout for a refused TCP connection.
pub(super) fn classify_connect_error(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionRefused => "closed",
        ErrorKind::TimedOut | ErrorKind::WouldBlock => "no-response",
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => "unreachable",
        _ => "unknown",
    }
}

/// Original TCP-connect observation: refusal is closed; timeout is uncertain.
pub(super) fn probe_observation(host: IpAddr, port: u16) -> ScanObservation {
    probe_observation_inner(host, port, port == 53)
}

/// Adaptive per-host deadline applies to the OS TCP connect call. Existing
/// public/internal probe signatures retain their previous fixed budget.
pub(super) fn probe_observation_timed(
    host: IpAddr,
    port: u16,
    connect_budget: Duration,
) -> ScanObservation {
    probe_observation_bounded(host, port, port == 53, connect_budget)
}

/// The injectable service-probe policy allows an unprivileged local DNS
/// fixture on an ephemeral port without scanning the machine's TCP/53.
fn probe_observation_inner(host: IpAddr, port: u16, dns_probe: bool) -> ScanObservation {
    probe_observation_bounded(host, port, dns_probe, CONNECT_TIMEOUT)
}

fn probe_observation_bounded(
    host: IpAddr,
    port: u16,
    dns_probe: bool,
    connect_budget: Duration,
) -> ScanObservation {
    let started_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    let began = Instant::now();
    let address = std::net::SocketAddr::new(host, port);
    let mut obs = ScanObservation {
        host: host.to_string(),
        port,
        protocol: "tcp".into(),
        state: "inconclusive".into(),
        reason: "unknown_error".into(),
        method: "tcp_connect".into(),
        service: "unknown".into(),
        service_basis: "none".into(),
        remote_software_claim: None,
        banner: String::new(),
        started_at_ms,
        elapsed_ms: 0,
        attempts: 1,
        retries: 0,
        os_error_code: None,
    };
    match TcpStream::connect_timeout(
        &address,
        connect_budget.clamp(Duration::from_millis(300), Duration::from_millis(1800)),
    ) {
        Err(error) => {
            let (state, reason) = classify_observation_error(error.kind());
            obs.state = state.into();
            obs.reason = reason.into();
            obs.os_error_code = error.raw_os_error();
        }
        Ok(mut stream) => {
            obs.state = "open".into();
            obs.reason = "tcp_connect_accepted".into();
            // Give unsolicited SSH/SMTP/FTP/etc greetings priority, including
            // when a non-DNS service is deliberately running on port 53.
            let tls_probe = matches!(port, 443 | 8443 | 993 | 995 | 465 | 990 | 636);
            let _ = stream.set_read_timeout(Some(if dns_probe || tls_probe {
                Duration::from_millis(80)
            } else {
                BANNER_TIMEOUT
            }));
            let _ = stream.set_write_timeout(Some(BANNER_TIMEOUT));
            if matches!(port, 80 | 8080 | 8000 | 8888) {
                let request =
                    format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                let _ = std::io::Write::write_all(&mut stream, request.as_bytes());
            }
            let mut buffer = [0u8; 512];
            let mut verified_initial_service = None;
            let received_greeting = match std::io::Read::read(&mut stream, &mut buffer) {
                Ok(length) if length > 0 => {
                    verified_initial_service = observed_service_bytes(&buffer[..length]);
                    let raw = String::from_utf8_lossy(&buffer[..length]);
                    obs.remote_software_claim = remote_software_claim(&raw);
                    obs.banner = summarize_banner(&raw);
                    true
                }
                _ => false,
            };
            // Only TCP/53 is actively queried in production. A failed, short,
            // mismatched, or silent response never upgrades a service hint.
            let dns_rcode = if dns_probe && !received_greeting {
                dns_tcp_probe(&mut stream)
            } else {
                None
            };
            // Text protocols often start with an ambiguous 220 greeting. A
            // follow-up command is permitted only for explicitly selected
            // SMTP/FTP ports and only after receiving that greeting.
            let text_probe = if obs.banner.starts_with("220 ") || obs.banner.starts_with("220-") {
                match port {
                    21 => Some(TextProbe::FtpFeat),
                    25 | 587 | 2525 => Some(TextProbe::SmtpEhlo),
                    _ => None,
                }
            } else {
                None
            };
            let verified_text = text_probe.filter(|probe| active_text_probe(&mut stream, *probe));
            let tls_hello = if tls_probe && !received_greeting {
                active_tls_probe(&mut stream, host)
            } else {
                None
            };
            if let Some(probe) = verified_text {
                obs.service = match probe {
                    TextProbe::SmtpEhlo => "smtp",
                    TextProbe::FtpFeat => "ftp",
                }
                .into();
                obs.service_basis = "observed_response".into();
                obs.banner = match probe {
                    TextProbe::SmtpEhlo => "SMTP EHLO verified 250 reply",
                    TextProbe::FtpFeat => "FTP FEAT verified 211 reply",
                }
                .into();
            } else if let Some(hello) = tls_hello {
                obs.service = "tls".into();
                obs.service_basis = "observed_response".into();
                obs.banner = hello;
            } else if let Some(rcode) = dns_rcode {
                obs.service = "dns".into();
                obs.service_basis = "observed_response".into();
                obs.banner = format!("DNS/TCP response to root NS query (RCODE {rcode})");
            } else if let Some(name) =
                verified_initial_service.or_else(|| observed_service(&obs.banner))
            {
                obs.service = name.into();
                obs.service_basis = "observed_response".into();
            } else {
                let guessed = well_known_service(port);
                if !guessed.is_empty() {
                    obs.service = guessed.into();
                    obs.service_basis = "port_hint_only".into();
                }
            }
        }
    }
    obs.elapsed_ms = began.elapsed().as_millis().min(u64::MAX as u128) as u64;
    obs
}

pub(super) fn classify_observation_error(kind: std::io::ErrorKind) -> (&'static str, &'static str) {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionRefused => ("closed", "tcp_connect_refused"),
        ErrorKind::NetworkUnreachable => ("unreachable", "network_unreachable"),
        ErrorKind::HostUnreachable => ("unreachable", "host_unreachable"),
        ErrorKind::TimedOut => ("inconclusive", "connect_timeout_no_response"),
        ErrorKind::WouldBlock => ("inconclusive", "connect_would_block"),
        ErrorKind::PermissionDenied => ("inconclusive", "local_or_network_permission_denied"),
        ErrorKind::ConnectionAborted => ("inconclusive", "connection_aborted"),
        ErrorKind::Interrupted => ("inconclusive", "interrupted"),
        _ => ("inconclusive", "connect_error_unclassified"),
    }
}

/// Preserve original open-port caller wire.
#[allow(dead_code)]
pub(super) fn probe(host: IpAddr, port: u16) -> (String, String) {
    let value = probe_observation(host, port);
    (value.state, value.banner)
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn passive_service_greeting_identification_requires_structural_evidence() {
        let mysql: &[u8] = &[10, 0, 0, 0, 10, b'8', b'.', b'0', b'.', b'3', b'5', 0, 0, 0];
        assert_eq!(observed_service_bytes(mysql), Some("mysql"));
        assert_eq!(observed_service_bytes(&mysql[..11]), None);
        let mut corrupt = mysql.to_vec();
        corrupt[3] = 1;
        assert_eq!(observed_service_bytes(&corrupt), None);
        corrupt = mysql.to_vec();
        corrupt[4] = 9;
        assert_eq!(observed_service_bytes(&corrupt), None);
        assert_eq!(observed_service_bytes(b"RFB 003.008\n"), Some("vnc"));
        assert_eq!(observed_service_bytes(b"RFB 003.008"), None);
        assert_eq!(observed_service_bytes(b"RFB 004.008\n"), None);
        assert_eq!(observed_service_bytes(b"@RSYNCD: 31.0\n"), Some("rsync"));
        assert_eq!(observed_service_bytes(b"@RSYNCD: invalid\n"), None);
        assert_eq!(
            observed_service_bytes(b"* OK IMAP service ready\r\n"),
            Some("imap")
        );
        assert_eq!(observed_service_bytes(b"* OK incomplete greeting"), None);
        assert_eq!(
            observed_service_bytes(b"+OK POP3 service ready\r\n"),
            Some("pop3")
        );
        assert_eq!(observed_service_bytes(b"+OK partial"), None);
        assert_eq!(observed_service_bytes(&vec![b'x'; 513]), None);
        assert_eq!(observed_service_bytes(&[]), None);
    }

    #[test]
    fn tls_serverhello_parser_requires_complete_structural_record() {
        let mut record = vec![0u8; 49]; // 5 record + 4 handshake + 40 body
        record[0] = 22;
        record[1..3].copy_from_slice(&[3, 3]);
        record[3..5].copy_from_slice(&(44u16).to_be_bytes());
        record[5] = 2;
        record[6..9].copy_from_slice(&[0, 0, 40]);
        record[9..11].copy_from_slice(&[3, 3]);
        record[43] = 0; // session id length
        record[44..46].copy_from_slice(&[0xc0, 0x2f]);
        record[46] = 0; // compression
        record[47..49].copy_from_slice(&[0, 0]); // zero extensions
        assert!(parse_tls_server_hello(&record).unwrap().contains("c02f"));
        let mut bad = record.clone();
        bad[0] = 23; // application-data is not a ServerHello
        assert!(parse_tls_server_hello(&bad).is_none());
        let mut bad = record.clone();
        bad[43] = 33; // session id cannot exceed 32 bytes
        assert!(parse_tls_server_hello(&bad).is_none());
        let mut bad = record.clone();
        bad[44] = 0;
        bad[45] = 0;
        assert!(parse_tls_server_hello(&bad).is_none());
        assert!(parse_tls_server_hello(&record[..48]).is_none());
        assert!(parse_tls_server_hello(&vec![0; 4097]).is_none());
    }

    #[test]
    fn smtp_and_ftp_text_probe_rejects_truncated_or_unrelated_responses() {
        assert!(text_probe_reply_valid(b"250 SMTP ready\r\n", b"250"));
        assert!(text_probe_reply_valid(
            b"250-extensions\r\n250 SIZE 1024\r\n",
            b"250"
        ));
        assert!(text_probe_reply_valid(
            b"211-extensions\r\n211 End\r\n",
            b"211"
        ));
        assert!(!text_probe_reply_valid(b"250-extensions\r\n", b"250"));
        assert!(!text_probe_reply_valid(b"250 Reply", b"250"));
        assert!(!text_probe_reply_valid(b"220 greeting\r\n", b"250"));
        assert!(!text_probe_reply_valid(b"250 OK\r\n250-bad\r\n", b"250"));
        assert!(!text_probe_reply_valid(b"250 OK\x00\r\n", b"250"));
        assert!(!text_probe_reply_valid(&vec![b'x'; 513], b"250"));
    }

    #[test]
    fn local_smtp_ehlo_reply_requires_command_correlated_status() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut input = [0u8; 24];
            socket.read_exact(&mut input).unwrap();
            assert_eq!(&input[..], b"EHLO cyberdeck.invalid\r\n");
            socket.write_all(b"250-test\r\n250 SIZE 4096\r\n").unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        assert!(active_text_probe(&mut client, TextProbe::SmtpEhlo));
        server.join().unwrap();
    }

    #[test]
    fn local_ftp_feat_wrong_status_does_not_claim_ftp() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut input = [0u8; 6];
            socket.read_exact(&mut input).unwrap();
            assert_eq!(&input, b"FEAT\r\n");
            socket.write_all(b"500 Unknown command\r\n").unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        assert!(!active_text_probe(&mut client, TextProbe::FtpFeat));
        server.join().unwrap();
    }

    #[test]
    fn dns_reply_parser_requires_matched_id_question_response_and_bounds() {
        let mut reply = [0u8; 17];
        reply[..2].copy_from_slice(&0x5ac3u16.to_be_bytes());
        reply[2..4].copy_from_slice(&[0x81, 0x83]); // QR, RD, RA, NXDOMAIN
        reply[4..6].copy_from_slice(&1u16.to_be_bytes());
        reply[12..17].copy_from_slice(&DNS_QUESTION);
        assert_eq!(dns_tcp_response_rcode(&reply, 0x5ac3), Some(3));
        assert_eq!(dns_tcp_response_rcode(&reply, 0x5ac4), None);
        reply[2] &= !0x80;
        assert_eq!(dns_tcp_response_rcode(&reply, 0x5ac3), None);
        reply[2] |= 0x80;
        reply[4] = 1;
        assert_eq!(dns_tcp_response_rcode(&reply, 0x5ac3), None);
        reply[4] = 0;
        reply[15] = 15;
        assert_eq!(dns_tcp_response_rcode(&reply, 0x5ac3), None);
        assert_eq!(dns_tcp_response_rcode(&reply[..16], 0x5ac3), None);
        assert_eq!(
            dns_tcp_response_rcode(&vec![0; DNS_RESPONSE_LIMIT + 1], 0),
            None
        );
    }

    #[test]
    fn local_dns_tcp_exchange_is_classified_only_on_correlated_response() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut question = [0; 19];
            stream.read_exact(&mut question).unwrap();
            assert_eq!(question[..2], (17u16).to_be_bytes());
            assert_eq!(question[6..8], 1u16.to_be_bytes());
            assert_eq!(question[14..19], DNS_QUESTION);
            let mut response = [0u8; 19];
            response[..2].copy_from_slice(&17u16.to_be_bytes());
            response[2..4].copy_from_slice(&question[2..4]);
            response[4..6].copy_from_slice(&[0x81, 0x80]);
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[14..19].copy_from_slice(&DNS_QUESTION);
            stream.write_all(&response).unwrap();
        });
        let obs = probe_observation_inner("127.0.0.1".parse().unwrap(), port, true);
        server.join().unwrap();
        assert_eq!(obs.state, "open");
        assert_eq!(obs.reason, "tcp_connect_accepted");
        assert_eq!(obs.service, "dns");
        assert_eq!(obs.service_basis, "observed_response");
        assert!(obs.banner.contains("DNS/TCP"));
        assert_eq!(obs.remote_software_claim, None);
    }

    #[test]
    fn invalid_dns_tcp_exchange_does_not_invent_a_service() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut question = [0; 19];
            stream.read_exact(&mut question).unwrap();
            let mut invalid = [0u8; 19];
            invalid[..2].copy_from_slice(&17u16.to_be_bytes());
            let mismatched_id = u16::from_be_bytes([question[2], question[3]]) ^ 1;
            invalid[2..4].copy_from_slice(&mismatched_id.to_be_bytes());
            invalid[4..6].copy_from_slice(&[0x81, 0x80]);
            invalid[6..8].copy_from_slice(&1u16.to_be_bytes());
            invalid[14..19].copy_from_slice(&DNS_QUESTION);
            stream.write_all(&invalid).unwrap();
        });
        let obs = probe_observation_inner("127.0.0.1".parse().unwrap(), port, true);
        server.join().unwrap();
        assert_eq!(obs.state, "open"); // TCP accepted even though DNS failed
        assert_eq!(obs.service, "unknown");
        assert_eq!(obs.service_basis, "none");
    }

    #[test]
    fn unverified_software_claim_requires_actual_response_token() {
        assert_eq!(
            remote_software_claim("SSH-2.0-OpenSSH_9.6\r\n"),
            Some("OpenSSH_9.6".into())
        );
        assert_eq!(
            remote_software_claim("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n"),
            Some("nginx/1.25.3".into())
        );
        assert_eq!(
            remote_software_claim("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"),
            None
        );
        assert_eq!(remote_software_claim("SSH-2.0-\r\n"), None);
        assert_eq!(
            remote_software_claim(&format!("SSH-2.0-{}\r\n", "x".repeat(75))),
            None
        );
        assert_eq!(remote_software_claim("220 service ready\r\n"), None);
        assert_eq!(
            remote_software_claim("HTTP/1.1 200 OK\r\nSérver: spoofed/1.0\r\n"),
            None
        );
    }

    #[test]
    fn actual_loopback_ssh_greeting_appears_as_unverified_response_claim() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection.write_all(b"SSH-2.0-ExampleSSH_3.2\r\n").unwrap();
        });
        let observed = probe_observation("127.0.0.1".parse().unwrap(), port);
        server.join().unwrap();
        assert_eq!(observed.state, "open");
        assert_eq!(observed.service, "ssh");
        assert_eq!(observed.service_basis, "observed_response");
        assert_eq!(
            observed.remote_software_claim.as_deref(),
            Some("ExampleSSH_3.2")
        );
    }

    #[test]
    fn error_kind_mapping_keeps_refusal_and_uncertain_timeout_distinct() {
        use std::io::ErrorKind;
        assert_eq!(
            classify_observation_error(ErrorKind::ConnectionRefused),
            ("closed", "tcp_connect_refused")
        );
        assert_eq!(
            classify_observation_error(ErrorKind::TimedOut),
            ("inconclusive", "connect_timeout_no_response")
        );
        assert_eq!(
            classify_observation_error(ErrorKind::PermissionDenied),
            ("inconclusive", "local_or_network_permission_denied")
        );
        assert_eq!(
            classify_observation_error(ErrorKind::HostUnreachable),
            ("unreachable", "host_unreachable")
        );
        assert_eq!(
            classify_observation_error(ErrorKind::NetworkUnreachable),
            ("unreachable", "network_unreachable")
        );
    }

    #[test]
    fn real_loopback_listener_and_refusal_have_distinct_grounded_states() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let opened = probe_observation("127.0.0.1".parse().unwrap(), port);
        assert_eq!(opened.state, "open");
        assert_eq!(opened.reason, "tcp_connect_accepted");
        assert_eq!(opened.attempts, 1);
        drop(socket);
        let refused = probe_observation("127.0.0.1".parse().unwrap(), port);
        assert_eq!(refused.state, "closed");
        assert_eq!(refused.reason, "tcp_connect_refused");
        assert_eq!(refused.retries, 0);
    }

    #[test]
    fn observed_protocol_recognizes_responses_on_unexpected_ports() {
        assert_eq!(observed_service("SSH-2.0-OpenSSH_9.6\r\n"), Some("ssh"));
        assert_eq!(
            observed_service("HTTP/1.1 200 OK\r\nServer: test\r\n"),
            Some("http")
        );
        assert_eq!(
            observed_service("220 smtp.example ESMTP ready\r\n"),
            Some("smtp")
        );
        assert_eq!(
            observed_service("220 ftp.example FTP server ready\r\n"),
            Some("ftp")
        );
    }

    #[test]
    fn observed_protocol_refuses_unsupported_or_ambiguous_banners() {
        assert_eq!(observed_service("220 ready\r\n"), None);
        assert_eq!(observed_service("error: SSH-2.0 spoofed\r\n"), None);
        assert_eq!(observed_service("HTTP/1.1x not-a-status\r\n"), None);
        assert_eq!(observed_service(""), None);
    }

    #[test]
    fn observed_protocol_does_not_invent_a_product_version() {
        assert_eq!(observed_service("SSH-2.0-vendor_1.2\r\n"), Some("ssh"));
        assert_eq!(observed_service("some unknown service\r\n"), None);
    }
}

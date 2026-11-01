//! Platform TCP connect and bounded banner probing. Active scanning only after
//! the legacy IPC command performs explicit authorization checks.
use super::ScanObservation;
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(900);
const BANNER_TIMEOUT: Duration = Duration::from_millis(400);

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
        banner: String::new(),
        started_at_ms,
        elapsed_ms: 0,
        attempts: 1,
        retries: 0,
        os_error_code: None,
    };
    match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
        Err(error) => {
            let (state, reason) = classify_observation_error(error.kind());
            obs.state = state.into();
            obs.reason = reason.into();
            obs.os_error_code = error.raw_os_error();
        }
        Ok(mut stream) => {
            obs.state = "open".into();
            obs.reason = "tcp_connect_accepted".into();
            let _ = stream.set_read_timeout(Some(BANNER_TIMEOUT));
            let _ = stream.set_write_timeout(Some(BANNER_TIMEOUT));
            if matches!(port, 80 | 8080 | 8000 | 8888) {
                let request =
                    format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                let _ = std::io::Write::write_all(&mut stream, request.as_bytes());
            }
            let mut buffer = [0u8; 512];
            if let Ok(length) = std::io::Read::read(&mut stream, &mut buffer) {
                if length > 0 {
                    obs.banner = summarize_banner(&String::from_utf8_lossy(&buffer[..length]));
                }
            }
            if let Some(name) = observed_service(&obs.banner) {
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

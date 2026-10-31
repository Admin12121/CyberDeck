//! Platform TCP connect and bounded banner probing. Active scanning only after
//! the legacy IPC command performs explicit authorization checks.
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

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

/// Connect + optional banner grab for one host:port.
pub(super) fn probe(host: IpAddr, port: u16) -> (String, String) {
    let addr = std::net::SocketAddr::new(host, port);
    match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Err(error) => (
            classify_connect_error(error.kind()).to_string(),
            String::new(),
        ),
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(BANNER_TIMEOUT));
            let _ = stream.set_write_timeout(Some(BANNER_TIMEOUT));
            let mut banner = String::new();
            // light service probes: HTTP HEAD on web ports, SSH announces itself
            if matches!(port, 80 | 8080 | 8000 | 8888) {
                let probe = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                let _ = std::io::Write::write_all(&mut stream, probe.as_bytes());
            }
            let mut buf = [0u8; 512];
            if let Ok(n) = std::io::Read::read(&mut stream, &mut buf) {
                if n > 0 {
                    banner = summarize_banner(&String::from_utf8_lossy(&buf[..n]));
                }
            }
            ("open".to_string(), banner)
        }
    }
}

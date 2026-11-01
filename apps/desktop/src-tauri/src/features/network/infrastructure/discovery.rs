//! TCP host reachability pre-pass. The caller must verify authorization.
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

const DISCOVERY_PORTS: &[u16] = &[80, 443, 22, 445, 3389];

fn refusal_is_response(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::ConnectionRefused
}

pub(super) fn responding_hosts(hosts: Vec<IpAddr>) -> Vec<String> {
    let mut up = Vec::new();
    for host in hosts {
        let alive = DISCOVERY_PORTS.iter().any(|port| {
            match TcpStream::connect_timeout(
                &SocketAddr::new(host, *port),
                Duration::from_millis(500),
            ) {
                Ok(_) => true,
                // A TCP refusal is evidence of a response (usually a RST).
                // A host with no open common ports should not be discarded.
                // This does not imply that any scanned port is open.
                Err(error) => refusal_is_response(&error),
            }
        });
        if alive {
            up.push(host.to_string());
        }
    }
    up
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_refusal_is_a_response_but_timeout_is_not() {
        use std::io::{Error, ErrorKind};
        assert!(refusal_is_response(&Error::from(ErrorKind::ConnectionRefused)));
        assert!(!refusal_is_response(&Error::from(ErrorKind::TimedOut)));
        assert!(!refusal_is_response(&Error::from(ErrorKind::NetworkUnreachable)));
    }

    #[test]
    fn no_targets_produces_no_discovery() {
        assert!(responding_hosts(Vec::new()).is_empty());
    }
}

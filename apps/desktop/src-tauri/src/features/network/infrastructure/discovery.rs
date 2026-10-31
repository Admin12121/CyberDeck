//! TCP host reachability pre-pass. The caller must verify authorization.
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

const DISCOVERY_PORTS: &[u16] = &[80, 443, 22, 445, 3389];

pub(super) fn responding_hosts(hosts: Vec<IpAddr>) -> Vec<String> {
    let mut up = Vec::new();
    for host in hosts {
        let alive = DISCOVERY_PORTS.iter().any(|port| {
            TcpStream::connect_timeout(&SocketAddr::new(host, *port), Duration::from_millis(500))
                .is_ok()
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
    fn no_targets_produces_no_discovery() {
        assert!(responding_hosts(Vec::new()).is_empty());
    }
}

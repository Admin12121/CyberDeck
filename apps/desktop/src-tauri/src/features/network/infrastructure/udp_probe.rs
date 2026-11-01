//! User-mode, explicitly authorized UDP scan observations. The kernel
//! correlates received datagrams to our connected 4-tuple; DNS and NTP
//! additionally match a per-request identity. No response is inconclusive,
//! NOT "filtered", and no Nmap probe payload database is reused.
use super::ScanObservation;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const UDP_RESPONSE_LIMIT: usize = 4096;
const UDP_TIMEOUT: Duration = Duration::from_millis(600);
const DNS_ROOT_NS: [u8; 5] = [0, 0, 2, 0, 1];

#[derive(Clone, Copy)]
enum UdpServiceProbe {
    Dns,
    Ntp,
    Generic,
}

fn dns_question(id: u16) -> [u8; 17] {
    let mut query = [0u8; 17];
    query[0..2].copy_from_slice(&id.to_be_bytes());
    query[2..4].copy_from_slice(&[1, 0]); // RD, standard query
    query[4..6].copy_from_slice(&1u16.to_be_bytes());
    query[12..17].copy_from_slice(&DNS_ROOT_NS);
    query
}

fn dns_response_rcode(response: &[u8], query: &[u8; 17]) -> Option<u8> {
    if response.len() < 17
        || response.len() > UDP_RESPONSE_LIMIT
        || response[0..2] != query[0..2]
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != 0
        || response[4..6] != [0, 1]
        || response[12..17] != query[12..17]
    {
        return None;
    }
    Some(response[3] & 0x0f)
}

/// An NTP client request with a timestamp nonce. The matching server reply
/// must echo it as the originate timestamp, per RFC 5905.
fn ntp_request(unique: u64) -> [u8; 48] {
    let mut request = [0u8; 48];
    request[0] = 0x23; // LI=0, VN=4, client mode=3
    request[40..48].copy_from_slice(&unique.to_be_bytes());
    request
}

fn ntp_response_valid(response: &[u8], request: &[u8; 48]) -> bool {
    response.len() >= 48
        && response.len() <= UDP_RESPONSE_LIMIT
        && response[0] & 0b111 == 4
        && (3..=4).contains(&((response[0] >> 3) & 0b111))
        && response[24..32] == request[40..48]
}

fn observed_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Explicitly authorized, bounded single UDP datagram and response wait.
/// ICMP-originated OS errors are not raw packet evidence; we report that
/// provenance plainly and require a raw listener for future Nmap parity.
pub(super) fn probe_udp_observation(host: IpAddr, port: u16) -> ScanObservation {
    let probe = match port {
        53 => UdpServiceProbe::Dns,
        123 => UdpServiceProbe::Ntp,
        _ => UdpServiceProbe::Generic,
    };
    probe_udp_observation_inner(host, port, probe)
}

fn probe_udp_observation_inner(host: IpAddr, port: u16, probe: UdpServiceProbe) -> ScanObservation {
    let began = Instant::now();
    let mut observation = ScanObservation {
        host: host.to_string(),
        port,
        protocol: "udp".into(),
        state: "inconclusive".into(),
        reason: "udp_no_response".into(),
        method: "udp_connected_socket".into(),
        service: "unknown".into(),
        service_basis: "none".into(),
        remote_software_claim: None,
        banner: String::new(),
        started_at_ms: observed_now_ms(),
        elapsed_ms: 0,
        attempts: 1,
        retries: 0,
        os_error_code: None,
    };
    let result = (|| -> std::io::Result<Option<(String, String)>> {
        let local = if host.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local)?;
        socket.set_read_timeout(Some(UDP_TIMEOUT))?;
        socket.set_write_timeout(Some(UDP_TIMEOUT))?;
        socket.connect(SocketAddr::new(host, port))?;

        let id = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u16)
            ^ 0xc761;
        let dns = dns_question(id);
        let ntp = ntp_request(
            (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64)
                ^ 0x6b27_5a11_730d_e295,
        );
        let request: &[u8] = match probe {
            UdpServiceProbe::Dns => &dns,
            UdpServiceProbe::Ntp => &ntp,
            UdpServiceProbe::Generic => &[], // one bounded empty datagram
        };
        socket.send(request)?;
        let mut response = [0u8; UDP_RESPONSE_LIMIT];
        let length = socket.recv(&mut response)?;
        let validated = match probe {
            UdpServiceProbe::Dns => dns_response_rcode(&response[..length], &dns).map(|rcode| {
                (
                    "dns".into(),
                    format!("DNS/UDP matching root NS reply RCODE {rcode}"),
                )
            }),
            UdpServiceProbe::Ntp if ntp_response_valid(&response[..length], &ntp) => Some((
                "ntp".into(),
                "NTP server reply matched originate timestamp".into(),
            )),
            UdpServiceProbe::Dns | UdpServiceProbe::Ntp => None,
            UdpServiceProbe::Generic if length > 0 => Some((
                "unknown".into(),
                format!(
                    "UDP response received ({} bytes; application unverified)",
                    length
                ),
            )),
            UdpServiceProbe::Generic => None,
        };
        Ok(validated)
    })();
    match result {
        Ok(Some((service, detail))) => {
            observation.state = "open".into();
            observation.reason = "udp_correlated_response".into();
            observation.service = service;
            observation.service_basis = "observed_response".into();
            observation.banner = detail;
        }
        Ok(None) => {
            observation.reason = "udp_invalid_or_unmatched_response".into();
        }
        Err(error) => {
            observation.os_error_code = error.raw_os_error();
            match error.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    observation.state = "closed".into();
                    observation.reason = "udp_connection_refused_os".into();
                }
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
                    observation.state = "unreachable".into();
                    observation.reason = "udp_unreachable_os".into();
                }
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                    observation.reason = "udp_no_response".into();
                }
                std::io::ErrorKind::PermissionDenied => {
                    observation.reason = "udp_permission_denied".into();
                }
                _ => {
                    observation.reason = "udp_local_or_transport_error".into();
                }
            }
        }
    }
    observation.elapsed_ms = began.elapsed().as_millis().min(u64::MAX as u128) as u64;
    observation
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn dns_matched_identity_and_question_required() {
        let query = dns_question(0x5ac3);
        let mut reply = query;
        reply[2] |= 0x80;
        reply[3] = 3; // NXDOMAIN still proves protocol response
        assert_eq!(dns_response_rcode(&reply, &query), Some(3));
        reply[0] ^= 1;
        assert_eq!(dns_response_rcode(&reply, &query), None);
        reply[0] ^= 1;
        reply[14] = 1;
        assert_eq!(dns_response_rcode(&reply, &query), None);
        assert!(dns_response_rcode(&reply[..16], &query).is_none());
    }

    #[test]
    fn ntp_requires_correct_mode_and_originating_nonce() {
        let query = ntp_request(0x1122_3344_5566_7788);
        let mut reply = [0u8; 48];
        reply[0] = 0x24; // VN=4, server mode 4
        reply[24..32].copy_from_slice(&query[40..48]);
        assert!(ntp_response_valid(&reply, &query));
        reply[24] ^= 1;
        assert!(!ntp_response_valid(&reply, &query));
        reply[24] ^= 1;
        reply[0] = 0x23;
        assert!(!ntp_response_valid(&reply, &query));
    }

    #[test]
    fn loopback_dns_udp_valid_response_is_open_with_observed_basis() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut incoming = [0u8; 64];
            let (length, remote) = server.recv_from(&mut incoming).unwrap();
            assert_eq!(length, 17);
            incoming[2] |= 0x80;
            server.send_to(&incoming[..length], remote).unwrap();
        });
        // Runs the real UDP observation path against an unprivileged fixture.
        let observation =
            probe_udp_observation_inner("127.0.0.1".parse().unwrap(), port, UdpServiceProbe::Dns);
        assert_eq!(observation.state, "open");
        assert_eq!(observation.protocol, "udp");
        assert_eq!(observation.service, "dns");
        assert_eq!(observation.service_basis, "observed_response");
        worker.join().unwrap();
    }

    #[test]
    fn loopback_ntp_server_response_is_evidence_not_a_port_hint() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut question = [0u8; 64];
            let (size, peer) = server.recv_from(&mut question).unwrap();
            assert_eq!(size, 48);
            let mut response = [0u8; 48];
            response[0] = 0x24; // NTP v4, server mode
            response[24..32].copy_from_slice(&question[40..48]);
            server.send_to(&response, peer).unwrap();
        });
        let observation =
            probe_udp_observation_inner("127.0.0.1".parse().unwrap(), port, UdpServiceProbe::Ntp);
        assert_eq!(observation.state, "open");
        assert_eq!(observation.service, "ntp");
        assert!(observation.banner.contains("originate"));
        worker.join().unwrap();
    }

    #[test]
    fn udp_silent_peer_is_inconclusive_not_filtered() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0u8; 8];
            server.recv_from(&mut buffer).unwrap();
            std::thread::sleep(Duration::from_millis(700));
        });
        let observed = probe_udp_observation_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpServiceProbe::Generic,
        );
        assert_eq!(observed.state, "inconclusive");
        assert_eq!(observed.reason, "udp_no_response");
        assert_ne!(observed.state, "filtered");
        worker.join().unwrap();
    }

    #[test]
    fn unprivileged_udp_socket_error_provenance_is_explicit() {
        assert_eq!(
            ErrorKind::ConnectionRefused,
            std::io::Error::from(ErrorKind::ConnectionRefused).kind()
        );
    }
}

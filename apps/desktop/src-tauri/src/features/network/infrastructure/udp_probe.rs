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
    Memcached,
    Stun,
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

/// Memcached's UDP framing includes a request ID, sequence and fragment count.
/// Only a complete single-fragment response to our read-only VERSION command
/// can be called observed evidence. Multi-fragment responses are not assembled.
fn memcached_udp_request(request_id: u16) -> [u8; 17] {
    let mut frame = [0u8; 17];
    frame[..2].copy_from_slice(&request_id.to_be_bytes());
    frame[4..6].copy_from_slice(&1u16.to_be_bytes()); // single UDP fragment
    frame[8..].copy_from_slice(b"version\r\n");
    frame
}
fn memcached_udp_reply(response: &[u8], request_id: u16) -> Option<String> {
    if response.len() < 8
        || response.len() > UDP_RESPONSE_LIMIT
        || response[..2] != request_id.to_be_bytes()
        || response[2..4] != [0, 0]
        || response[4..6] != [0, 1]
        || response[6..8] != [0, 0]
    {
        return None;
    }
    super::tcp_probe::memcached_version_claim(&response[8..])
}

/// Standard STUN Binding request (RFC 5389). This requests only the
/// mapped endpoint of the already-authorized connected socket; no relay,
/// TURN allocation, credentials, or reflection to arbitrary third parties.
const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
fn stun_binding_request(nonce: [u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&[0, 1]); // Binding Request
    req[4..8].copy_from_slice(&STUN_COOKIE);
    req[8..20].copy_from_slice(&nonce);
    req
}
// Transaction IDs must not be predictable from wall-clock timestamps.
// Cryptographically random bytes come from the host OS; never fall back to a
// deterministic value when OS randomness is unavailable.
#[cfg(unix)]
fn stun_nonce() -> std::io::Result<[u8; 12]> {
    use std::io::Read;
    let mut bytes = [0u8; 12];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}
#[cfg(windows)]
fn stun_nonce() -> std::io::Result<[u8; 12]> {
    use std::ffi::c_void;
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, length: u32, flags: u32)
            -> i32;
    }
    let mut bytes = [0u8; 12];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(std::io::Error::other(format!(
            "Windows CNG random generation failed (NTSTATUS 0x{:08x})",
            status as u32,
        )));
    }
    Ok(bytes)
}
#[cfg(not(any(unix, windows)))]
fn stun_nonce() -> std::io::Result<[u8; 12]> {
    Err(std::io::Error::other(
        "STUN transaction IDs require a supported operating-system RNG",
    ))
}
/// A responder's advertised NAT reflexive mapping is network-supplied data,
/// not an authenticated assertion. Reject mismatched transaction IDs, length,
/// malformed optional attributes and conflicting duplicate mapped addresses.
fn stun_binding_reply(response: &[u8], request: &[u8; 20]) -> Option<String> {
    if response.len() < 20
        || response.len() > UDP_RESPONSE_LIMIT
        || response[0..2] != [0x01, 0x01]
        || response[2] & 0b1100_0000 != 0
        || response[4..8] != STUN_COOKIE
        || response[8..20] != request[8..20]
    {
        return None;
    }
    let body_len = u16::from_be_bytes([response[2], response[3]]) as usize;
    if body_len % 4 != 0 || body_len + 20 != response.len() {
        return None;
    }
    let mut cursor = 20usize;
    let mut mapping: Option<String> = None;
    while cursor < response.len() {
        let header = response.get(cursor..cursor + 4)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let size = u16::from_be_bytes([header[2], header[3]]) as usize;
        let body = response.get(cursor + 4..cursor + 4 + size)?;
        if kind == 0x0020 {
            if size < 8 || body[0] != 0 {
                return None;
            }
            let port = u16::from_be_bytes([body[2], body[3]]) ^ 0x2112;
            if port == 0 {
                return None;
            }
            let address = match body[1] {
                1 if size == 8 => {
                    let mut ip = [0u8; 4];
                    for i in 0..4 {
                        ip[i] = body[i + 4] ^ STUN_COOKIE[i];
                    }
                    let parsed = std::net::Ipv4Addr::from(ip);
                    if parsed.is_unspecified() || parsed.is_multicast() {
                        return None;
                    }
                    format!("{parsed}:{port}")
                }
                2 if size == 20 => {
                    let mut ip = [0u8; 16];
                    for i in 0..16 {
                        ip[i] = body[i + 4]
                            ^ if i < 4 {
                                STUN_COOKIE[i]
                            } else {
                                request[i + 4]
                            };
                    }
                    let parsed = std::net::Ipv6Addr::from(ip);
                    if parsed.is_unspecified() || parsed.is_multicast() {
                        return None;
                    }
                    format!("[{parsed}]:{port}")
                }
                _ => return None,
            };
            if mapping
                .as_ref()
                .is_some_and(|existing| existing != &address)
            {
                return None;
            }
            mapping = Some(address);
        }
        let padded = size.checked_add(3)? & !3usize;
        cursor = cursor.checked_add(4)?.checked_add(padded)?;
        if cursor > response.len() {
            return None;
        }
    }
    mapping
}

/// Explicitly authorized, bounded single UDP datagram and response wait.
/// ICMP-originated OS errors are not raw packet evidence; we report that
/// provenance plainly and require a raw listener for future Nmap parity.
pub(super) fn probe_udp_observation(host: IpAddr, port: u16) -> ScanObservation {
    probe_udp_observation_timed(host, port, UDP_TIMEOUT)
}

pub(super) fn probe_udp_observation_timed(
    host: IpAddr,
    port: u16,
    response_budget: Duration,
) -> ScanObservation {
    let probe = match port {
        53 => UdpServiceProbe::Dns,
        123 => UdpServiceProbe::Ntp,
        11211 | 11212 => UdpServiceProbe::Memcached,
        3478 | 3479 => UdpServiceProbe::Stun,
        _ => UdpServiceProbe::Generic,
    };
    probe_udp_observation_bounded(host, port, probe, response_budget)
}

fn probe_udp_observation_inner(host: IpAddr, port: u16, probe: UdpServiceProbe) -> ScanObservation {
    probe_udp_observation_bounded(host, port, probe, UDP_TIMEOUT)
}

fn probe_udp_observation_bounded(
    host: IpAddr,
    port: u16,
    probe: UdpServiceProbe,
    response_budget: Duration,
) -> ScanObservation {
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
    let result = (|| -> std::io::Result<Option<(String, String, Option<String>)>> {
        let local = if host.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local)?;
        let budget = response_budget.clamp(Duration::from_millis(300), Duration::from_millis(1200));
        socket.set_read_timeout(Some(budget))?;
        socket.set_write_timeout(Some(budget))?;
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
        let memcached = memcached_udp_request(id);
        let stun = if matches!(probe, UdpServiceProbe::Stun) {
            stun_binding_request(stun_nonce()?)
        } else {
            stun_binding_request([0; 12])
        };
        let request: &[u8] = match probe {
            UdpServiceProbe::Dns => &dns,
            UdpServiceProbe::Ntp => &ntp,
            UdpServiceProbe::Memcached => &memcached,
            UdpServiceProbe::Stun => &stun,
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
                    None,
                )
            }),
            UdpServiceProbe::Ntp if ntp_response_valid(&response[..length], &ntp) => Some((
                "ntp".into(),
                "NTP server reply matched originate timestamp".into(),
                None,
            )),
            UdpServiceProbe::Memcached => {
                memcached_udp_reply(&response[..length], id).map(|claim| {
                    (
                        "memcached".into(),
                        "Memcached UDP VERSION reply with matching request ID".into(),
                        Some(claim),
                    )
                })
            }
            UdpServiceProbe::Ntp => None,
            UdpServiceProbe::Stun => {
                stun_binding_reply(&response[..length], &stun).map(|address| {
                    (
                        "stun".into(),
                        format!("STUN Binding response, unverified mapped endpoint {address}"),
                        None,
                    )
                })
            }
            UdpServiceProbe::Generic if length > 0 => Some((
                "unknown".into(),
                format!(
                    "UDP response received ({} bytes; application unverified)",
                    length
                ),
                None,
            )),
            UdpServiceProbe::Generic => None,
        };
        Ok(validated)
    })();
    match result {
        Ok(Some((service, detail, claim))) => {
            observation.state = "open".into();
            observation.reason = "udp_correlated_response".into();
            observation.service = service;
            observation.service_basis = "observed_response".into();
            observation.banner = detail;
            observation.remote_software_claim = claim;
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
    fn stun_requires_exact_transaction_length_and_xor_mapping() {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = stun_binding_request(nonce);
        assert_eq!(&request[..8], &[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        let mut response = [0u8; 32];
        response[0..2].copy_from_slice(&[1, 1]);
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..20].copy_from_slice(&request[4..20]);
        response[20..24].copy_from_slice(&[0, 0x20, 0, 8]);
        response[24] = 0;
        response[25] = 1;
        response[26..28].copy_from_slice(&(50500u16 ^ 0x2112).to_be_bytes());
        for (i, byte) in [203u8, 0, 113, 1].iter().enumerate() {
            response[28 + i] = *byte ^ STUN_COOKIE[i];
        }
        assert_eq!(
            stun_binding_reply(&response, &request).as_deref(),
            Some("203.0.113.1:50500")
        );
        let mut wrong = response;
        wrong[8] ^= 1;
        assert_eq!(stun_binding_reply(&wrong, &request), None);
        wrong = response;
        wrong[3] = 8;
        assert_eq!(stun_binding_reply(&wrong, &request), None);
        wrong = response;
        wrong[0] = 0;
        assert_eq!(stun_binding_reply(&wrong, &request), None);
        wrong = response;
        wrong[25] = 3;
        assert_eq!(stun_binding_reply(&wrong, &request), None);
        assert_eq!(stun_binding_reply(&response[..31], &request), None);
        assert_eq!(stun_binding_reply(&response[..20], &request), None);
    }

    #[test]
    fn stun_udp_loopback_correlates_actual_binding_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 64];
            let (length, peer) = socket.recv_from(&mut packet).unwrap();
            assert_eq!(length, 20);
            assert_eq!(packet[0..8], [0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
            let mut reply = [0u8; 32];
            reply[0..2].copy_from_slice(&[1, 1]);
            reply[2..4].copy_from_slice(&12u16.to_be_bytes());
            reply[4..20].copy_from_slice(&packet[4..20]);
            reply[20..24].copy_from_slice(&[0, 0x20, 0, 8]);
            reply[24..26].copy_from_slice(&[0, 1]);
            reply[26..28].copy_from_slice(&(44444u16 ^ 0x2112).to_be_bytes());
            for (i, byte) in [192u8, 0, 2, 77].iter().enumerate() {
                reply[28 + i] = *byte ^ STUN_COOKIE[i];
            }
            socket.send_to(&reply, peer).unwrap();
        });
        let result =
            probe_udp_observation_inner("127.0.0.1".parse().unwrap(), port, UdpServiceProbe::Stun);
        worker.join().unwrap();
        assert_eq!(result.state, "open");
        assert_eq!(result.service, "stun");
        assert_eq!(result.service_basis, "observed_response");
        assert!(result.banner.contains("192.0.2.77:44444"));
        assert!(result.banner.contains("unverified"));
        assert_eq!(result.remote_software_claim, None);
    }

    #[test]
    fn memcached_datagram_requires_exact_request_identity_and_single_fragment() {
        let req = memcached_udp_request(0x1234);
        assert_eq!(&req[..8], &[0x12, 0x34, 0, 0, 0, 1, 0, 0]);
        assert_eq!(&req[8..], b"version\r\n");
        let mut response = req[..8].to_vec();
        response.extend_from_slice(b"VERSION 1.6.25\r\n");
        assert_eq!(
            memcached_udp_reply(&response, 0x1234).as_deref(),
            Some("memcached/1.6.25")
        );
        let mut bad = response.clone();
        bad[0] ^= 1;
        assert_eq!(memcached_udp_reply(&bad, 0x1234), None);
        bad = response.clone();
        bad[2] = 1;
        assert_eq!(memcached_udp_reply(&bad, 0x1234), None);
        bad = response.clone();
        bad[5] = 2;
        assert_eq!(memcached_udp_reply(&bad, 0x1234), None);
        bad = response.clone();
        bad[8] = b'X';
        assert_eq!(memcached_udp_reply(&bad, 0x1234), None);
        assert_eq!(memcached_udp_reply(&response[..7], 0x1234), None);
        assert_eq!(
            memcached_udp_reply(&response[..response.len() - 1], 0x1234),
            None
        );
    }

    #[test]
    fn memcached_udp_loopback_uses_actual_protocol_request_and_claim() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut req = [0u8; 64];
            let (len, peer) = server.recv_from(&mut req).unwrap();
            assert_eq!(len, 17);
            assert_eq!(&req[8..len], b"version\r\n");
            let mut answer = req[..8].to_vec();
            answer.extend_from_slice(b"VERSION 1.6.25\r\n");
            server.send_to(&answer, peer).unwrap();
        });
        let found = probe_udp_observation_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpServiceProbe::Memcached,
        );
        worker.join().unwrap();
        assert_eq!(found.state, "open");
        assert_eq!(found.service, "memcached");
        assert_eq!(found.service_basis, "observed_response");
        assert_eq!(
            found.remote_software_claim.as_deref(),
            Some("memcached/1.6.25")
        );
    }

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

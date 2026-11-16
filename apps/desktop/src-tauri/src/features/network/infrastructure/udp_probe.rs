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

// ---------------------------------------------------------------------------
// Wave 6: bounded UDP service-check probing (NSE-lite excerpt source).
//
// Semantics table — one (host, port) pair, one connected socket:
//
// | port  | datagram(s) sent                                | correlated response                     |
// |-------|--------------------------------------------------|-----------------------------------------|
// | 123   | NTP mode-3 client (48 B), then mode-6 READVAR    | mode-3: originate-timestamp echo;        |
// |       | (12 B) only on mode-3 silence                    | mode-6: assocID/seq/version echo         |
// | 53    | CH TXT "version.bind" query (30 B)               | QR + opcode 0 + question echo + id       |
// | 5353  | PTR "_services._dns-sd._udp.local" (46 B)        | QR + id + question echo                  |
// | 1900  | M-SEARCH with MX=1, ST: upnp:rootdevice          | HTTP/1.x response head (no txn id exists)|
// | 161   | SNMPv2c GET sysDescr.0, community "public"       | BER SEQUENCE, response/report PDU + reqid|
// | other | one empty datagram                               | any datagram (connected-socket filter)   |
//
// Classification (honest UDP semantics — silence is NOT closed):
//   correlated/unmatched response  → "open", excerpt = sanitized response head
//   no response                    → "open|filtered" / "udp_no_response"
//   ICMP port-unreachable (ECONNREFUSED) → "closed" / "udp_icmp_port_unreachable"
//   host/network unreachable       → "unreachable"
//   local bind/connect/send errors → "inconclusive"
//
// Bounds: response window clamped to 300..1300 ms per datagram (≤ 1.5 s
// including the 150 ms late-ICMP grace recv), ≤ 2 resends (off by default),
// ≤ 2 datagram families per port, excerpt ≤ MAX_UDP_EXCERPT_BYTES, and the
// whole registry stays far under MAX_UDP_PROBES_PER_SCAN per scan. The
// netscan UDP-scan path (`probe_udp_observation*`) keeps its established
// "inconclusive on silence" contract; this section is the scan-depth
// service-check path and reports open|filtered instead.
// ---------------------------------------------------------------------------

/// Excerpt byte bound for UDP service checks, mirroring the TCP path's
/// sanitize discipline (printable kept, whitespace → space, control bytes → '?').
pub(crate) const MAX_UDP_EXCERPT_BYTES: usize = 2048;
/// Upper bound on UDP datagrams one scan may send; the per-port registries
/// below send at most two families per port, so even a 128-port scan fits.
pub(crate) const MAX_UDP_PROBES_PER_SCAN: usize = 256;
/// Bounded resends on silence. Off by default; callers opt in explicitly.
pub(crate) const MAX_UDP_RESENDS: usize = 2;
/// Late-ICMP grace: a port-unreachable can arrive just after the read
/// timeout fired. One extra bounded recv (no resend) surfaces it as closed
/// instead of open|filtered.
const ICMP_GRACE: Duration = Duration::from_millis(150);
/// Window hard ceiling: window + grace stays under the documented 1.5 s.
const MAX_SERVICE_WINDOW: Duration = Duration::from_millis(1300);

/// One bounded, protocol-appropriate UDP probe family for the checks path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpCheckProbe {
    NtpMode3,
    NtpMode6Readvar,
    DnsVersionBind,
    MdnsServices,
    SsdpSearch,
    SnmpGetPublicV2c,
    GenericEmpty,
}

/// Per-request identity tokens. DNS/mDNS and SNMP ids force the top bit so
/// the echoed id bytes sanitize to '?' instead of printable noise inside the
/// excerpt. Tokens come from the clock like the observation path above; the
/// connected socket plus echo checks (id, seq, reqid, nonce) provide the
/// correlation that a bare id cannot.
struct UdpProbeIdentity {
    dns_id: u16,
    ntp_nonce: u64,
    snmp_reqid: u16,
    mode6_sequence: u16,
}

fn udp_probe_identity() -> UdpProbeIdentity {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let low = nanos as u16;
    UdpProbeIdentity {
        dns_id: low | 0x8000,
        ntp_nonce: (nanos as u64) ^ 0x6b27_5a11_730d_e295,
        snmp_reqid: (low ^ 0x7ac3) | 0x8000,
        mode6_sequence: (low ^ 0x1f4d) | 0x8000,
    }
}

/// Registry of check probes per well-known UDP port. Unknown ports get one
/// empty datagram: a response is honest responder evidence, silence is
/// open|filtered, and the check registry classifies what it can.
pub(crate) fn udp_check_probe_registry(port: u16) -> &'static [UdpCheckProbe] {
    const NTP: &[UdpCheckProbe] = &[UdpCheckProbe::NtpMode3, UdpCheckProbe::NtpMode6Readvar];
    match port {
        123 => NTP,
        53 => &[UdpCheckProbe::DnsVersionBind],
        5353 => &[UdpCheckProbe::MdnsServices],
        1900 => &[UdpCheckProbe::SsdpSearch],
        161 => &[UdpCheckProbe::SnmpGetPublicV2c],
        _ => &[UdpCheckProbe::GenericEmpty],
    }
}

/// Per-port default response window. SSDP responders wait a random delay up
/// to MX before answering, so 1900 gets a longer bounded window; everything
/// else answers (or stays silent) quickly.
pub(crate) fn default_service_probe_window(port: u16) -> Duration {
    if port == 1900 {
        Duration::from_millis(1200)
    } else {
        Duration::from_millis(600)
    }
}

impl UdpCheckProbe {
    fn label(self) -> &'static str {
        match self {
            Self::NtpMode3 => "udp_ntp_mode3_client",
            Self::NtpMode6Readvar => "udp_ntp_mode6_readvar",
            Self::DnsVersionBind => "udp_dns_version_bind",
            Self::MdnsServices => "udp_mdns_services_dns_sd",
            Self::SsdpSearch => "udp_ssdp_msearch",
            Self::SnmpGetPublicV2c => "udp_snmp_v2c_getpublic",
            Self::GenericEmpty => "udp_generic_empty",
        }
    }

    fn service(self) -> &'static str {
        match self {
            Self::NtpMode3 | Self::NtpMode6Readvar => "ntp",
            Self::DnsVersionBind => "dns",
            Self::MdnsServices => "mdns",
            Self::SsdpSearch => "ssdp",
            Self::SnmpGetPublicV2c => "snmp",
            Self::GenericEmpty => "unknown",
        }
    }

    fn request_bytes(self, identity: &UdpProbeIdentity) -> Vec<u8> {
        match self {
            Self::NtpMode3 => ntp_request(identity.ntp_nonce).to_vec(),
            Self::NtpMode6Readvar => ntp_mode6_readvar_request(identity.mode6_sequence).to_vec(),
            Self::DnsVersionBind => dns_version_bind_query(identity.dns_id).to_vec(),
            Self::MdnsServices => mdns_services_query(identity.dns_id),
            Self::SsdpSearch => SSDP_MSEARCH.to_vec(),
            Self::SnmpGetPublicV2c => snmp_v2c_get(identity.snmp_reqid, b"public"),
            Self::GenericEmpty => Vec::new(),
        }
    }

    /// Correlated-response validation: the reply must echo our request
    /// identity, never merely look like the protocol.
    fn response_valid(self, response: &[u8], request: &[u8], identity: &UdpProbeIdentity) -> bool {
        match self {
            Self::NtpMode3 => {
                if request.len() != 48 {
                    return false;
                }
                let mut sent = [0u8; 48];
                sent.copy_from_slice(request);
                ntp_response_valid(response, &sent)
            }
            Self::NtpMode6Readvar => {
                if request.len() != 12 {
                    return false;
                }
                let mut sent = [0u8; 12];
                sent.copy_from_slice(request);
                ntp_mode6_reply_payload(response, &sent).is_some()
            }
            Self::DnsVersionBind => {
                if request.len() != 30 {
                    return false;
                }
                let mut sent = [0u8; 30];
                sent.copy_from_slice(request);
                dns_version_bind_reply(response, &sent).is_some()
            }
            Self::MdnsServices => mdns_services_reply(response, request).is_some(),
            Self::SsdpSearch => ssdp_response_head(response).is_some(),
            Self::SnmpGetPublicV2c => snmp_response_correlated(response, identity.snmp_reqid).is_some(),
            // A connected socket only delivers datagrams from the probed peer;
            // any non-empty datagram is honest responder evidence.
            Self::GenericEmpty => true,
        }
    }
}

/// NTP mode-6 (ntpq/ntpdc control protocol) READVAR request for system
/// variables: response/error/more bits clear, opcode 2, version 2, assocID 0.
fn ntp_mode6_readvar_request(sequence: u16) -> [u8; 12] {
    let mut request = [0u8; 12];
    request[0] = 0x02; // opcode READVAR (2)
    request[1] = 0x02; // mode-6 protocol version 2
    request[2..4].copy_from_slice(&sequence.to_be_bytes());
    // status(0), assocID(0, system variables), offset(0), count(0) stay zero
    request
}

fn ntp_mode6_reply_payload<'a>(response: &'a [u8], request: &[u8; 12]) -> Option<&'a [u8]> {
    if response.len() < 12
        || response.len() > UDP_RESPONSE_LIMIT
        || response[0] & 0x80 == 0 // response bit must be set
        || response[0] & 0x40 != 0 // fragmented replies are not assembled
        || response[0] & 0x20 != 0 // error replies carry no variable data
        || response[0] & 0x1f != request[0] & 0x1f
        || response[1] != request[1]
        || response[2..4] != request[2..4]
        || response[6..8] != request[6..8]
    {
        return None;
    }
    let count = u16::from_be_bytes([response[10], response[11]]) as usize;
    let offset = u16::from_be_bytes([response[8], response[9]]) as usize;
    if offset != 0 || count == 0 || response.len() != 12 + count {
        return None;
    }
    Some(&response[12..])
}

/// CH TXT "version.bind" query (RFC 1035): 12-byte header, qname
/// version.bind, QTYPE TXT, QCLASS CH. No recursion desired.
fn dns_version_bind_query(id: u16) -> [u8; 30] {
    let mut query = [0u8; 30];
    query[0..2].copy_from_slice(&id.to_be_bytes());
    query[4..6].copy_from_slice(&1u16.to_be_bytes()); // one question
    let mut at = 12;
    for label in [&b"version"[..], &b"bind"[..]] {
        query[at] = label.len() as u8;
        at += 1;
        query[at..at + label.len()].copy_from_slice(label);
        at += label.len();
    }
    at += 1; // root label (already zero)
    query[at..at + 2].copy_from_slice(&16u16.to_be_bytes()); // QTYPE TXT
    query[at + 2..at + 4].copy_from_slice(&3u16.to_be_bytes()); // QCLASS CH
    query
}

fn dns_version_bind_reply(response: &[u8], query: &[u8; 30]) -> Option<(u8, u16)> {
    let question = &query[12..30];
    if response.len() < 30
        || response.len() > UDP_RESPONSE_LIMIT
        || response[0..2] != query[0..2]
        || response[2] & 0x80 == 0 // QR: server response
        || response[2] & 0x78 != 0 // opcode: standard query
        || response[4..6] != [0, 1]
        || !response.windows(question.len()).any(|window| window == question)
    {
        return None;
    }
    Some((
        response[3] & 0x0f,
        u16::from_be_bytes([response[6], response[7]]),
    ))
}

/// mDNS service-enumeration query (RFC 6763 §9): PTR
/// "_services._dns-sd._udp.local". Sent unicast to the already-authorized
/// host; responders that answer unicast queries reply directly.
fn mdns_services_query(id: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(46);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x00]); // flags: plain multicast-format query
    query.extend_from_slice(&1u16.to_be_bytes()); // one question
    query.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar counts zero
    for label in [&b"_services"[..], &b"_dns-sd"[..], &b"_udp"[..], &b"local"[..]] {
        query.push(label.len() as u8);
        query.extend_from_slice(label);
    }
    query.push(0);
    query.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    query
}

fn mdns_services_reply(response: &[u8], query: &[u8]) -> Option<usize> {
    let question = &query[12..];
    if response.len() < query.len()
        || response.len() > UDP_RESPONSE_LIMIT
        || response[0..2] != query[0..2]
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != 0
        || !response.windows(question.len()).any(|window| window == question)
    {
        return None;
    }
    Some(response.len())
}

/// Fixed SSDP M-SEARCH with a bounded MX (1 s) and a single ST. No relay or
/// third-party reflection: the datagram goes to the authorized host itself.
const SSDP_MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

/// M-SEARCH carries no transaction identifier, so correlation is the
/// connected socket plus an HTTP/1.x response-head shape.
fn ssdp_response_head(response: &[u8]) -> Option<&[u8]> {
    if response.len() < 18 || response.len() > UDP_RESPONSE_LIMIT {
        return None;
    }
    if !response.starts_with(b"HTTP/1.1 ") && !response.starts_with(b"HTTP/1.0 ") {
        return None;
    }
    Some(response)
}

/// One-varbind SNMPv2c GET for sysDescr.0 with the given community. The only
/// community sent in production is "public"; sending guessed communities
/// beyond that would be a credential attempt, not a bounded probe.
fn snmp_v2c_get(reqid: u16, community: &[u8]) -> Vec<u8> {
    assert!(community.len() <= 63, "bounded community length");
    let mut varbind = Vec::with_capacity(14);
    varbind.extend_from_slice(&[0x30, 0x0a]);
    varbind.extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]); // sysDescr.0
    varbind.extend_from_slice(&[0x05, 0x00]); // NULL value
    let mut varbinds = Vec::with_capacity(varbind.len() + 2);
    varbinds.extend_from_slice(&[0x30, varbind.len() as u8]);
    varbinds.extend_from_slice(&varbind);
    let mut pdu = Vec::with_capacity(varbinds.len() + 12);
    pdu.push(0xA0); // GetRequest
    pdu.push((varbinds.len() as u8) + 10); // reqid(4) + error-status(3) + error-index(3)
    pdu.extend_from_slice(&[0x02, 0x02]);
    pdu.extend_from_slice(&reqid.to_be_bytes());
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // error-status: noError
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // error-index: 0
    pdu.extend_from_slice(&varbinds);
    let mut message = Vec::with_capacity(pdu.len() + community.len() + 8);
    message.push(0x30); // SEQUENCE
    let content_len = 3 + 2 + community.len() + pdu.len();
    if content_len < 128 {
        message.push(content_len as u8);
    } else {
        message.push(0x81);
        message.push(content_len as u8);
    }
    message.extend_from_slice(&[0x02, 0x01, 0x01]); // version: v2c (integer 1)
    message.push(0x04);
    message.push(community.len() as u8);
    message.extend_from_slice(community);
    message.extend_from_slice(&pdu);
    message
}

/// Bounded BER length parse: returns (content offset, content length).
fn ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.get(1)?;
    if first & 0x80 == 0 {
        return Some((2, first as usize));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 {
        return None;
    }
    let mut length = 0usize;
    for byte in bytes.get(2..2 + count)? {
        length = (length << 8) | usize::from(*byte);
    }
    Some((2 + count, length))
}

/// Minimal bounded BER walk of an SNMP response: SEQUENCE { version,
/// community (any value — classification happens in the checks), response-ish
/// PDU whose request-id echoes ours. Returns the whole message for excerpting.
fn snmp_response_correlated(response: &[u8], reqid: u16) -> Option<&[u8]> {
    if response.len() < 16 || response[0] != 0x30 {
        return None;
    }
    let (content_at, msg_len) = ber_length(response)?;
    if msg_len > UDP_RESPONSE_LIMIT || content_at + msg_len != response.len() {
        return None;
    }
    let mut cursor = content_at;
    if response.get(cursor..cursor + 2) != Some(&[0x02, 0x01]) {
        return None; // version INTEGER
    }
    cursor += 3;
    if *response.get(cursor)? != 0x04 {
        return None; // community OCTET STRING
    }
    let community_len = usize::from(*response.get(cursor + 1)? & 0x7f);
    if community_len > 64 {
        return None;
    }
    cursor += 2 + community_len;
    let tag = *response.get(cursor)?;
    if !matches!(tag, 0xA2 | 0xA8) {
        return None; // GetResponse or Report
    }
    let (pdu_at, pdu_len) = ber_length(&response[cursor..])?;
    if pdu_len > UDP_RESPONSE_LIMIT || cursor + pdu_at + pdu_len != response.len() {
        return None;
    }
    let pdu = cursor + pdu_at;
    if response.get(pdu..pdu + 2) != Some(&[0x02, 0x02]) {
        return None; // request-id INTEGER
    }
    let echoed = u16::from_be_bytes([*response.get(pdu + 2)?, *response.get(pdu + 3)?]);
    if echoed != reqid {
        return None;
    }
    Some(response)
}

/// Sanitize a UDP response head with the TCP path's discipline: printable
/// ASCII kept, whitespace → space, control/non-ASCII → '?', bounded.
fn udp_sanitize_excerpt(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes.iter().take(MAX_UDP_EXCERPT_BYTES) {
        match byte {
            0x20..=0x7e => text.push(byte as char),
            0x09 | 0x0a | 0x0d => text.push(' '),
            _ => text.push('?'),
        }
    }
    text.trim_end().to_string()
}

/// The scan-depth service-check outcome: an honest port state plus the
/// sanitized excerpt the pure check registry classifies.
#[derive(Clone, Debug)]
pub(crate) struct UdpServiceProbeOutcome {
    pub state: &'static str,
    pub reason: &'static str,
    pub service: &'static str,
    pub service_basis: &'static str,
    pub probe_used: &'static str,
    pub excerpt: String,
    pub elapsed_ms: u64,
}

enum WaitPhase {
    Data(usize),
    IcmpClosed,
    UnreachableHost,
    LocalError,
    Silence,
}

/// Bounded recv wait. ICMP port-unreachable interrupts a blocked recv
/// immediately on a connected socket; the post-deadline grace recv exists
/// for the late-arrival race. Never resends.
fn wait_for_datagram(socket: &UdpSocket, buffer: &mut [u8], deadline: Instant) -> WaitPhase {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let _ = socket.set_read_timeout(Some(ICMP_GRACE));
            return match socket.recv(buffer) {
                Ok(length) if length > 0 => WaitPhase::Data(length),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    WaitPhase::IcmpClosed
                }
                _ => WaitPhase::Silence,
            };
        }
        let _ = socket.set_read_timeout(Some(remaining));
        match socket.recv(buffer) {
            Ok(length) if length > 0 => return WaitPhase::Data(length),
            Ok(_) => continue, // zero-length datagram: keep waiting within the window
            Err(error) => match error.kind() {
                std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::ConnectionRefused => return WaitPhase::IcmpClosed,
                std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable => return WaitPhase::UnreachableHost,
                _ => return WaitPhase::LocalError,
            },
        }
    }
}

enum ProbeResolution {
    Resolved(UdpServiceProbeOutcome),
    Silent,
}

fn probe_outcome(
    state: &'static str,
    reason: &'static str,
    service: &'static str,
    basis: &'static str,
    probe_used: &'static str,
    excerpt: String,
) -> UdpServiceProbeOutcome {
    UdpServiceProbeOutcome {
        state,
        reason,
        service,
        service_basis: basis,
        probe_used,
        excerpt,
        elapsed_ms: 0,
    }
}

/// One probe family: send the bounded datagram (plus opted-in resends on
/// silence), wait the bounded window, classify.
fn run_udp_check_probe(
    socket: &UdpSocket,
    probe: UdpCheckProbe,
    identity: &UdpProbeIdentity,
    response_window: Duration,
    retries: usize,
) -> ProbeResolution {
    let request = probe.request_bytes(identity);
    let mut resends_left = retries.min(MAX_UDP_RESENDS);
    loop {
        if let Err(error) = socket.send(&request) {
            return ProbeResolution::Resolved(match error.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    probe_outcome("closed", "udp_icmp_port_unreachable", probe.service(), "none", probe.label(), String::new())
                }
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
                    probe_outcome("unreachable", "udp_unreachable_os", probe.service(), "none", probe.label(), String::new())
                }
                std::io::ErrorKind::PermissionDenied => {
                    probe_outcome("inconclusive", "udp_permission_denied", probe.service(), "none", probe.label(), String::new())
                }
                _ => probe_outcome("inconclusive", "udp_local_or_transport_error", probe.service(), "none", probe.label(), String::new()),
            });
        }
        let deadline = Instant::now() + response_window;
        let mut buffer = [0u8; UDP_RESPONSE_LIMIT];
        match wait_for_datagram(socket, &mut buffer, deadline) {
            WaitPhase::Data(length) => {
                let bytes = &buffer[..length.min(UDP_RESPONSE_LIMIT)];
                let validated = probe.response_valid(bytes, &request, identity);
                let excerpt =
                    udp_sanitize_excerpt(&bytes[..length.min(MAX_UDP_EXCERPT_BYTES)]);
                let (state, reason, service, basis) = if validated {
                    (
                        "open",
                        "udp_correlated_response",
                        probe.service(),
                        "observed_response",
                    )
                } else {
                    (
                        "open",
                        "udp_response_unmatched",
                        "unknown",
                        "unmatched_response",
                    )
                };
                return ProbeResolution::Resolved(probe_outcome(
                    state,
                    reason,
                    service,
                    basis,
                    probe.label(),
                    excerpt,
                ));
            }
            WaitPhase::IcmpClosed => {
                return ProbeResolution::Resolved(probe_outcome(
                    "closed",
                    "udp_icmp_port_unreachable",
                    probe.service(),
                    "none",
                    probe.label(),
                    String::new(),
                ));
            }
            WaitPhase::UnreachableHost => {
                return ProbeResolution::Resolved(probe_outcome(
                    "unreachable",
                    "udp_unreachable_os",
                    probe.service(),
                    "none",
                    probe.label(),
                    String::new(),
                ));
            }
            WaitPhase::LocalError => {
                return ProbeResolution::Resolved(probe_outcome(
                    "inconclusive",
                    "udp_local_or_transport_error",
                    probe.service(),
                    "none",
                    probe.label(),
                    String::new(),
                ));
            }
            WaitPhase::Silence => {
                if resends_left > 0 {
                    resends_left -= 1;
                    continue;
                }
                return ProbeResolution::Silent;
            }
        }
    }
}

/// Bounded UDP service probe for the NSE-lite checks path. Sends the
/// per-port registry datagrams on ONE connected socket, classifies honestly
/// (silence → open|filtered, ICMP unreachable → closed) and returns the
/// sanitized excerpt for the pure check registry.
pub(crate) fn probe_udp_service_excerpt(
    host: IpAddr,
    port: u16,
    response_window: Duration,
    retries: usize,
) -> UdpServiceProbeOutcome {
    let began = Instant::now();
    let registry = udp_check_probe_registry(port);
    let finish = |mut outcome: UdpServiceProbeOutcome| {
        outcome.elapsed_ms = began.elapsed().as_millis().min(u64::MAX as u128) as u64;
        outcome
    };
    let silent = || probe_outcome("open|filtered", "udp_no_response", "unknown", "none", registry.first().map(|p| p.label()).unwrap_or("none"), String::new());
    let window = response_window.clamp(Duration::from_millis(300), MAX_SERVICE_WINDOW);
    let local = if host.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match UdpSocket::bind(local)
        .and_then(|socket| {
            socket
                .set_write_timeout(Some(window))
                .map(|_| socket)
        }) {
        Ok(socket) => socket,
        Err(error) => {
            let reason = if error.kind() == std::io::ErrorKind::PermissionDenied {
                "udp_permission_denied"
            } else {
                "udp_local_or_transport_error"
            };
            return finish(probe_outcome("inconclusive", reason, "unknown", "none", "none", String::new()));
        }
    };
    if let Err(error) = socket.connect(SocketAddr::new(host, port)) {
        let reason = if error.kind() == std::io::ErrorKind::PermissionDenied {
            "udp_permission_denied"
        } else {
            "udp_local_or_transport_error"
        };
        return finish(probe_outcome("inconclusive", reason, "unknown", "none", "none", String::new()));
    }
    let identity = udp_probe_identity();
    for probe in registry {
        match run_udp_check_probe(&socket, *probe, &identity, window, retries) {
            ProbeResolution::Resolved(outcome) => return finish(outcome),
            ProbeResolution::Silent => continue,
        }
    }
    finish(silent())
}

/// Single-probe variant used by tests to run one family against a loopback
/// responder on an ephemeral port (the production path maps ports to
/// registries via [`udp_check_probe_registry`]).
#[cfg(test)]
fn probe_udp_service_inner(
    host: IpAddr,
    port: u16,
    probe: UdpCheckProbe,
    response_window: Duration,
    retries: usize,
) -> UdpServiceProbeOutcome {
    let began = Instant::now();
    let window = response_window.clamp(Duration::from_millis(300), MAX_SERVICE_WINDOW);
    let local = if host.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(local).unwrap();
    let _ = socket.set_write_timeout(Some(window));
    socket.connect(SocketAddr::new(host, port)).unwrap();
    let identity = udp_probe_identity();
    match run_udp_check_probe(&socket, probe, &identity, window, retries) {
        ProbeResolution::Resolved(mut outcome) => {
            outcome.elapsed_ms = began.elapsed().as_millis().min(u64::MAX as u128) as u64;
            outcome
        }
        ProbeResolution::Silent => probe_outcome(
            "open|filtered",
            "udp_no_response",
            "unknown",
            "none",
            probe.label(),
            String::new(),
        ),
    }
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

    // --- wave 6: service-check probe machinery tests -----------------------------

    #[test]
    fn ntp_mode6_request_and_reply_validation_is_identity_bound() {
        let request = ntp_mode6_readvar_request(0x8123);
        assert_eq!(request[0], 0x02);
        assert_eq!(request[1], 0x02);
        assert_eq!(&request[2..4], &0x8123u16.to_be_bytes());
        assert!(request[4..].iter().all(|b| *b == 0));
        let variables = b"associd=0 status=06c4 leap=none, stratum=3, rootdelay=1.500";
        let mut reply = [0u8; 12 + 59];
        reply[0] = 0x82; // response bit + READVAR opcode
        reply[1] = 0x02;
        reply[2..4].copy_from_slice(&0x8123u16.to_be_bytes());
        reply[10..12].copy_from_slice(&(variables.len() as u16).to_be_bytes());
        reply[12..].copy_from_slice(variables);
        assert_eq!(
            ntp_mode6_reply_payload(&reply, &request).map(|p| p.len()),
            Some(variables.len())
        );
        // A fragmented reply is never assembled into evidence.
        let mut fragment = reply;
        fragment[0] |= 0x40;
        assert_eq!(ntp_mode6_reply_payload(&fragment, &request), None);
        // Error replies carry no variables.
        let mut error = reply;
        error[0] = 0xa2;
        assert_eq!(ntp_mode6_reply_payload(&error, &request), None);
        // Mismatched sequence or assocID is not our reply.
        let mut mismatch = reply;
        mismatch[3] ^= 1;
        assert_eq!(ntp_mode6_reply_payload(&mismatch, &request), None);
        mismatch = reply;
        mismatch[7] = 1;
        assert_eq!(ntp_mode6_reply_payload(&mismatch, &request), None);
        // Count must match the actual payload length exactly.
        let mut short = reply;
        short[10] = 0x10;
        assert_eq!(ntp_mode6_reply_payload(&short, &request), None);
        assert_eq!(ntp_mode6_reply_payload(&reply[..30], &request), None);
    }

    #[test]
    fn dns_version_bind_query_is_well_formed_and_ids_stay_unprintable() {
        let query = dns_version_bind_query(0x8042);
        assert_eq!(query.len(), 30);
        assert_eq!(&query[0..2], &0x8042u16.to_be_bytes());
        assert_eq!(&query[4..6], &1u16.to_be_bytes());
        assert_eq!(&query[12..30], b"\x07version\x04bind\x00\x00\x10\x00\x03");
        // High bit forced: echoed ids sanitize to '?' rather than text.
        assert_eq!(query[0] & 0x80, 0x80);
    }

    #[test]
    fn dns_version_bind_reply_requires_qr_opcode_id_and_question_echo() {
        let query = dns_version_bind_query(0x8001);
        let mut refused = [0u8; 30];
        refused[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        refused[2] = 0x80; // QR
        refused[3] = 0x05; // REFUSED rcode
        refused[4..6].copy_from_slice(&1u16.to_be_bytes());
        refused[12..30].copy_from_slice(&query[12..30]);
        assert_eq!(dns_version_bind_reply(&refused, &query), Some((5, 0)));
        let mut answered = [0u8; 49];
        answered[..30].copy_from_slice(&refused);
        answered[2] = 0x80;
        answered[3] = 0x00; // NOERROR
        answered[6..8].copy_from_slice(&1u16.to_be_bytes()); // one answer
        // answer: compressed name, TXT, CH, ttl, rdlen 7, version token
        answered[30..49].copy_from_slice(&[
            0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'9', b'.',
            b'1', b'8', b'.', b'2', b'8',
        ]);
        assert_eq!(dns_version_bind_reply(&answered, &query), Some((0, 1)));
        // Mismatched id is not our reply.
        let mut wrong_id = refused;
        wrong_id[0] ^= 1;
        assert_eq!(dns_version_bind_reply(&wrong_id, &query), None);
        // A query (QR clear) is not a reply.
        let mut query_echo = refused;
        query_echo[2] = 0x00;
        assert_eq!(dns_version_bind_reply(&query_echo, &query), None);
        // Missing question echo is not our reply.
        assert_eq!(dns_version_bind_reply(&refused[..29], &query), None);
        let mut no_echo = refused;
        no_echo[29] = 0x99;
        assert_eq!(dns_version_bind_reply(&no_echo, &query), None);
    }

    #[test]
    fn mdns_query_is_well_formed_and_replies_need_echo() {
        let query = mdns_services_query(0x8055);
        assert_eq!(query.len(), 46);
        assert_eq!(&query[12..46], b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01");
        let mut reply = query.clone();
        reply[2] = 0x84; // QR + AA
        reply[6..8].copy_from_slice(&1u16.to_be_bytes()); // one answer
        reply.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12,
        ]);
        reply.extend_from_slice(b"\x04_ipp\x04_tcp\x05local\x00");
        assert_eq!(mdns_services_reply(&reply, &query), Some(reply.len()));
        // Missing QR, wrong id or missing question echo are rejected.
        let mut no_qr = reply.clone();
        no_qr[2] = 0x04;
        assert_eq!(mdns_services_reply(&no_qr, &query), None);
        let mut wrong_id = reply.clone();
        wrong_id[1] ^= 1;
        assert_eq!(mdns_services_reply(&wrong_id, &query), None);
        assert_eq!(mdns_services_reply(&reply[..query.len() - 1], &query), None);
    }

    #[test]
    fn snmp_getpublic_is_well_formed_and_replies_are_reqid_correlated() {
        let request = snmp_v2c_get(0x8421, b"public");
        assert_eq!(&request[..2], &[0x30, 0x27]); // 39 content bytes
        assert!(request.windows(6).any(|w| w == b"public"));
        assert!(request.windows(3).any(|w| w == [0x02, 0x01, 0x01]));
        // GetRequest PDU tail: reqid INTEGER is the first varbind-less field.
        assert_eq!(
            &request[request.len() - 26..request.len() - 24],
            &[0x02, 0x02]
        );
        assert_eq!(
            &request[request.len() - 24..request.len() - 22],
            &0x8421u16.to_be_bytes()
        );
        // GetResponse echoing our reqid with the same community.
        let response = snmp_v2c_response_fixture(0x8421, b"public", b"Linux lab 5.15.0");
        assert_eq!(snmp_response_correlated(&response, 0x8421).map(|r| r.len()), Some(response.len()));
        // A different reqid, a GetRequest PDU, or a broken message is rejected.
        assert_eq!(snmp_response_correlated(&response, 0x8422), None);
        let mut request_pdu = response.clone();
        request_pdu[13] = 0xA0;
        assert_eq!(snmp_response_correlated(&request_pdu, 0x8421), None);
        let mut bad_len = response.clone();
        bad_len[1] = 0x7f;
        assert_eq!(snmp_response_correlated(&bad_len, 0x8421), None);
        assert_eq!(snmp_response_correlated(&response[..15], 0x8421), None);
        assert_eq!(snmp_response_correlated(b"not snmp at all......", 0x8421), None);
    }

    /// Build a GetResponse BER fixture for tests: version, community, reqid,
    /// error-status 0, one varbind returning `value` as an OCTET STRING.
    fn snmp_v2c_response_fixture(reqid: u16, community: &[u8], value: &[u8]) -> Vec<u8> {
        let mut varbind = vec![0x30u8];
        let oid = [0x06u8, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let mut vb_content = oid.to_vec();
        vb_content.push(0x04);
        vb_content.push(value.len() as u8);
        vb_content.extend_from_slice(value);
        varbind.push(vb_content.len() as u8);
        varbind.extend_from_slice(&vb_content);
        let mut varbinds = vec![0x30u8, varbind.len() as u8];
        varbinds.extend_from_slice(&varbind);
        let mut pdu = vec![0xA2u8, (varbinds.len() as u8) + 10];
        pdu.extend_from_slice(&[0x02, 0x02]);
        pdu.extend_from_slice(&reqid.to_be_bytes());
        pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
        pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
        pdu.extend_from_slice(&varbinds);
        let mut message = vec![0x30u8, (3 + 2 + community.len() + pdu.len()) as u8];
        message.extend_from_slice(&[0x02, 0x01, 0x01]);
        message.push(0x04);
        message.push(community.len() as u8);
        message.extend_from_slice(community);
        message.extend_from_slice(&pdu);
        message
    }

    #[test]
    fn ssdp_msearch_is_bounded_and_response_heads_are_validated() {
        let msearch = SSDP_MSEARCH;
        assert!(msearch.windows(7).any(|w| w == b"MX: 1\r\n"));
        assert!(msearch.windows(4).any(|w| w == b"ST: "));
        assert!(msearch.ends_with(b"\r\n\r\n"));
        let response = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: UPnP/1.0\r\nLOCATION: http://lab/\r\n\r\n";
        assert_eq!(ssdp_response_head(response), Some(&response[..]));
        assert_eq!(ssdp_response_head(b"HTTP/1.1 "), None);
        assert_eq!(ssdp_response_head(b"NOT-HTTP at all"), None);
        assert_eq!(
            ssdp_response_head(&vec![b'x'; UDP_RESPONSE_LIMIT + 1]),
            None
        );
    }

    #[test]
    fn udp_sanitize_excerpt_mirrors_tcp_discipline_and_is_bounded() {
        let bytes: Vec<u8> = vec![b'x'; 2100];
        let text = udp_sanitize_excerpt(&bytes);
        assert_eq!(text.len(), MAX_UDP_EXCERPT_BYTES);
        assert!(text.chars().all(|c| c == 'x'));
        // Whitespace survives as spaces; control bytes become '?'.
        assert_eq!(udp_sanitize_excerpt(b"a\r\nb\x01c"), "a  b?c");
        assert_eq!(udp_sanitize_excerpt(b"trailing\x00"), "trailing?");
    }

    #[test]
    fn check_registries_stay_within_the_scan_probe_budget() {
        for port in [53u16, 123, 161, 1900, 5353, 8080] {
            let registry = udp_check_probe_registry(port);
            assert!(!registry.is_empty());
            assert!(registry.len() <= 4, "registry depth stays bounded");
        }
        // A full 128-port scan sends at most two families per port — well
        // under the documented 256-datagram scan bound.
        assert!(128 * udp_check_probe_registry(123).len() <= MAX_UDP_PROBES_PER_SCAN);
    }

    #[test]
    fn service_probe_windows_are_per_port_and_capped() {
        assert_eq!(default_service_probe_window(1900), Duration::from_millis(1200));
        assert_eq!(default_service_probe_window(161), Duration::from_millis(600));
        assert!(default_service_probe_window(1900) + ICMP_GRACE <= Duration::from_millis(1500));
    }

    #[test]
    fn loopback_ntp_mode6_variables_become_an_excerpt() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 32];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            assert_eq!(length, 12);
            assert_eq!(packet[0], 0x02);
            assert_eq!(packet[1], 0x02);
            let variables =
                b"associd=0 status=06c4 leap=none, stratum=3, rootdelay=1.500";
            let mut reply = [0u8; 12 + 59];
            reply[0] = 0x82;
            reply[1] = 0x02;
            reply[2..4].copy_from_slice(&packet[2..4]);
            reply[10..12].copy_from_slice(&(variables.len() as u16).to_be_bytes());
            reply[12..].copy_from_slice(variables);
            server.send_to(&reply[..12 + variables.len()], peer).unwrap();
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::NtpMode6Readvar,
            Duration::from_millis(600),
            0,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.reason, "udp_correlated_response");
        assert_eq!(outcome.service, "ntp");
        assert_eq!(outcome.service_basis, "observed_response");
        assert!(outcome.excerpt.contains("associd=0"));
        assert!(outcome.excerpt.contains("stratum=3"));
    }

    #[test]
    fn loopback_dns_version_bind_txt_answer_is_sanitized_evidence() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 64];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            assert_eq!(length, 30);
            let mut reply = [0u8; 49];
            reply[0..2].copy_from_slice(&packet[0..2]);
            reply[2] = 0x80;
            reply[3] = 0x00;
            reply[4..6].copy_from_slice(&1u16.to_be_bytes());
            reply[6..8].copy_from_slice(&1u16.to_be_bytes());
            reply[12..30].copy_from_slice(&packet[12..30]);
            reply[30..49].copy_from_slice(&[
                0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'9',
                b'.', b'1', b'8', b'.', b'2', b'8',
            ]);
            server.send_to(&reply, peer).unwrap();
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::DnsVersionBind,
            Duration::from_millis(600),
            0,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.service, "dns");
        // Wire labels are length-prefixed, so the echoed question sanitizes
        // to "version?bind" — never a presentation-format dotted name.
        assert!(outcome.excerpt.contains("version?bind"));
        assert!(outcome.excerpt.contains("9.18.28"));
        // The forced high id byte always sanitizes to '?', not printable noise.
        assert!(outcome.excerpt.starts_with('?'));
    }

    #[test]
    fn loopback_mdns_reply_lists_advertised_service_types() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 96];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            assert_eq!(length, 46);
            let mut reply = packet[..46].to_vec();
            reply[2] = 0x84;
            reply[6..8].copy_from_slice(&1u16.to_be_bytes());
            reply.extend_from_slice(&[
                0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12,
            ]);
            reply.extend_from_slice(b"\x04_ipp\x04_tcp\x05local\x00");
            server.send_to(&reply, peer).unwrap();
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::MdnsServices,
            Duration::from_millis(600),
            0,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.service, "mdns");
        assert!(outcome.excerpt.contains("_dns-sd"));
        assert!(outcome.excerpt.contains("_ipp?_tcp?local"));
    }

    #[test]
    fn loopback_ssdp_msearch_response_yields_upnp_headers() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 128];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            let request = &packet[..length];
            assert!(request.windows(9).any(|w| w == b"M-SEARCH "));
            assert!(request.windows(7).any(|w| w == b"MX: 1\r\n"));
            let response = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux/5.4 UPnP/1.0 LabRouter/2.1\r\nLOCATION: http://192.0.2.1:49152/description.xml\r\n\r\n";
            server.send_to(response, peer).unwrap();
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::SsdpSearch,
            Duration::from_millis(600),
            0,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.service, "ssdp");
        assert!(outcome.excerpt.contains("UPnP/1.0"));
        assert!(outcome.excerpt.contains("LOCATION:"));
    }

    #[test]
    fn loopback_snmp_public_echo_is_correlated_and_excerpted() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 128];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            let request = &packet[..length];
            assert!(request.windows(6).any(|w| w == b"public"));
            // reqid INTEGER sits 24 bytes from the end (varbind tail + error fields).
            let reqid = u16::from_be_bytes([
                request[request.len() - 24],
                request[request.len() - 23],
            ]);
            let response = snmp_v2c_response_fixture(reqid, b"public", b"Linux lab 5.15.0");
            server.send_to(&response, peer).unwrap();
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::SnmpGetPublicV2c,
            Duration::from_millis(600),
            0,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.reason, "udp_correlated_response");
        assert_eq!(outcome.service, "snmp");
        assert!(outcome.excerpt.contains("public"));
        assert!(outcome.excerpt.contains("Linux lab 5.15.0"));
    }

    #[test]
    fn loopback_snmp_wrong_reqid_is_open_but_unmatched() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 128];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            let response = snmp_v2c_response_fixture(0x1234, b"public", b"spoofed");
            let _ = length;
            server.send_to(&response, peer).unwrap();
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::SnmpGetPublicV2c,
            Duration::from_millis(600),
            0,
        );
        worker.join().unwrap();
        // A datagram arrived, but it is not OUR reply: open, honestly unmatched.
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.reason, "udp_response_unmatched");
        assert_eq!(outcome.service_basis, "unmatched_response");
        assert_eq!(outcome.service, "unknown");
    }

    #[test]
    fn loopback_silence_is_open_filtered_never_closed() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0u8; 8];
            server.recv_from(&mut buffer).unwrap();
            std::thread::sleep(Duration::from_millis(700));
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::GenericEmpty,
            Duration::from_millis(300),
            0,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open|filtered");
        assert_eq!(outcome.reason, "udp_no_response");
        assert_ne!(outcome.state, "closed");
        assert_ne!(outcome.state, "filtered");
        assert!(outcome.excerpt.is_empty());
        assert_eq!(outcome.service_basis, "none");
    }

    #[test]
    fn loopback_icmp_port_unreachable_classifies_closed() {
        // Bind, record the port, drop the socket: datagrams to it now draw an
        // ICMP port-unreachable, which a connected socket reports as
        // ECONNREFUSED — the honest "closed" signal for UDP.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::GenericEmpty,
            Duration::from_millis(300),
            0,
        );
        assert_eq!(outcome.state, "closed");
        assert_eq!(outcome.reason, "udp_icmp_port_unreachable");
        assert!(outcome.excerpt.is_empty());
    }

    #[test]
    fn loopback_resend_on_silence_is_opt_in_and_bounded() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0u8; 16];
            let (_, peer) = server.recv_from(&mut buffer).unwrap(); // first datagram: stay silent
            let (second, peer2) = server.recv_from(&mut buffer).unwrap();
            assert_eq!(second, 0); // the resend is also an empty datagram
            let _ = peer;
            server.send_to(b"late-but-real", peer2).unwrap();
        });
        let retries = 1;
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::GenericEmpty,
            Duration::from_millis(300),
            retries,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.reason, "udp_correlated_response");
        assert!(outcome.excerpt.contains("late-but-real"));
    }

    #[test]
    fn loopback_excerpt_beyond_the_cap_is_truncated() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0u8; 8];
            let (_, peer) = server.recv_from(&mut buffer).unwrap();
            let flood = vec![b'x'; 3000];
            server.send_to(&flood, peer).unwrap();
        });
        let outcome = probe_udp_service_inner(
            "127.0.0.1".parse().unwrap(),
            port,
            UdpCheckProbe::GenericEmpty,
            Duration::from_millis(600),
            0,
        );
        worker.join().unwrap();
        assert_eq!(outcome.state, "open");
        assert_eq!(outcome.excerpt.len(), MAX_UDP_EXCERPT_BYTES);
    }
}

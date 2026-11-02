//! Native Linux IPv4 ICMP echo discovery, independently authored.
//! One operator-authorized selected NIC, true kernel source IPv4 address,
//! bounded raw probes, explicit cancellation and matched echo identities.
//! Silence means inconclusive, never proof that a host is down.
use crate::scan_replies::{
    correlate_ethernet_response, ProbeIdentity, ProbeTransport, ReplyEvidence,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MAX_ECHO_HOSTS: usize = 32;
const WAIT_PER_HOST: Duration = Duration::from_millis(600);
const MIN_SEND_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoState {
    Responded,
    Unreachable,
    Inconclusive,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoObservation {
    pub target: Ipv4Addr,
    pub state: EchoState,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoErrorCode {
    Unsupported,
    InvalidScope,
    Permission,
    Device,
    Io,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoError {
    pub code: EchoErrorCode,
    pub message: String,
}
impl EchoError {
    fn new(code: EchoErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
fn validate_hosts(hosts: &[Ipv4Addr]) -> Result<(), EchoError> {
    if hosts.is_empty() || hosts.len() > MAX_ECHO_HOSTS {
        return Err(EchoError::new(
            EchoErrorCode::InvalidScope,
            "ICMP echo discovery supports 1..=32 IPv4 hosts",
        ));
    }
    if hosts
        .iter()
        .any(|host| host.is_unspecified() || host.is_multicast() || host.is_broadcast())
    {
        return Err(EchoError::new(
            EchoErrorCode::InvalidScope,
            "ICMP echo targets must be unicast IPv4 hosts",
        ));
    }
    Ok(())
}
pub fn discover_ipv4_echo(
    interface_name: &str,
    hosts: &[Ipv4Addr],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
) -> Result<Vec<EchoObservation>, EchoError> {
    validate_hosts(hosts)?;
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(EchoError::new(
            EchoErrorCode::Cancelled,
            "ICMP echo scope revoked",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::discover(interface_name, hosts, stop, scope_active)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface_name, stop, scope_active);
        Err(EchoError::new(
            EchoErrorCode::Unsupported,
            "native raw ICMPv4 echo currently requires Linux CAP_NET_RAW",
        ))
    }
}

/// Result of one bounded IPv4 TTL-limited ICMP Echo probe.
/// Router identities are observed claims and never authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceHop {
    pub ttl: u8,
    pub responder: Option<Ipv4Addr>,
    pub reached: bool,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}
pub const MAX_TRACE_HOPS: u8 = 16;

/// Traces one explicitly approved IPv4 target without external tools.
/// Each hop uses a backend-random echo identifier, 600ms deadline and
/// <=50ms cancellation polling. A timeout does not prove a missing route.
pub fn trace_ipv4_echo(
    interface_name: &str,
    target: Ipv4Addr,
    max_hops: u8,
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
) -> Result<Vec<TraceHop>, EchoError> {
    validate_hosts(&[target])?;
    if max_hops == 0 || max_hops > MAX_TRACE_HOPS {
        return Err(EchoError::new(
            EchoErrorCode::InvalidScope,
            "trace hop limit must be 1..=16",
        ));
    }
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(EchoError::new(
            EchoErrorCode::Cancelled,
            "traceroute authorization revoked",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::trace(interface_name, target, max_hops, stop, scope_active)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface_name;
        Err(EchoError::new(
            EchoErrorCode::Unsupported,
            "native ICMP traceroute requires Linux CAP_NET_RAW",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::live::{discover_interfaces, select_interface};
    use std::ffi::{c_int, c_ulong, c_void};
    use std::io;
    use std::io::Read;
    const AF_INET: c_int = 2;
    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_DGRAM: c_int = 2;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const SOL_SOCKET: c_int = 1;
    const SO_BINDTODEVICE: c_int = 25;
    const IPPROTO_RAW: c_int = 255;
    const ETH_P_IP: u16 = 0x0800;
    const SIOCGIFADDR: c_ulong = 0x8915;
    const POLLIN: i16 = 1;
    #[repr(C)]
    struct SockAddrIn {
        family: u16,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
    }
    #[repr(C)]
    struct SockAddrLl {
        family: u16,
        protocol: u16,
        ifindex: c_int,
        hatype: u16,
        pkttype: u8,
        halen: u8,
        addr: [u8; 8],
    }
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        payload: [u8; 24],
    }
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }
    unsafe extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            len: u32,
        ) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
        fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const c_void,
            alen: u32,
        ) -> isize;
        fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }
    struct Fd(c_int);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                close(self.0);
            }
        }
    }
    fn io_err(task: &str) -> EchoError {
        let error = io::Error::last_os_error();
        let kind = if error.kind() == io::ErrorKind::PermissionDenied {
            EchoErrorCode::Permission
        } else {
            EchoErrorCode::Io
        };
        EchoError::new(kind, format!("{task}: {error}"))
    }
    fn source_ipv4(interface: &str) -> Result<Ipv4Addr, EchoError> {
        if interface.is_empty()
            || interface.len() >= 16
            || interface.contains('/')
            || interface.contains('\\')
        {
            return Err(EchoError::new(
                EchoErrorCode::InvalidScope,
                "invalid selected IPv4 NIC name",
            ));
        }
        let fd = Fd(unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) });
        if fd.0 < 0 {
            return Err(io_err("open selected interface IPv4 configuration"));
        }
        let mut req = Ifreq {
            name: [0; 16],
            payload: [0; 24],
        };
        req.name[..interface.len()].copy_from_slice(interface.as_bytes());
        if unsafe { ioctl(fd.0, SIOCGIFADDR, (&raw mut req).cast()) } < 0 {
            return Err(io_err("verify selected kernel IPv4 source"));
        }
        let address =
            Ipv4Addr::from(<[u8; 4]>::try_from(&req.payload[4..8]).expect("fixed IPv4 bytes"));
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            return Err(EchoError::new(
                EchoErrorCode::InvalidScope,
                "interface lacks usable unicast IPv4",
            ));
        }
        Ok(address)
    }
    fn random_echo_identity() -> Result<(u16, u16, u16), EchoError> {
        let mut bytes = [0u8; 6];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(|e| {
                EchoError::new(
                    EchoErrorCode::Io,
                    format!("OS random identity unavailable: {e}"),
                )
            })?;
        Ok((
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
        ))
    }
    fn cancelled(stop: &AtomicBool, scope: &(impl Fn() -> bool + Sync)) -> bool {
        stop.load(Ordering::Acquire) || !scope()
    }
    pub(super) fn discover(
        name: &str,
        targets: &[Ipv4Addr],
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
    ) -> Result<Vec<EchoObservation>, EchoError> {
        let list =
            discover_interfaces().map_err(|e| EchoError::new(EchoErrorCode::Device, e.message))?;
        let selected = select_interface(&list, name)
            .map_err(|e| EchoError::new(EchoErrorCode::Device, e.message))?;
        let source = source_ipv4(&selected.name)?;
        let tx = Fd(unsafe { socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW) });
        if tx.0 < 0 {
            return Err(io_err("open native ICMP raw IPv4 sender"));
        }
        let mut device = selected.name.as_bytes().to_vec();
        device.push(0);
        if unsafe {
            setsockopt(
                tx.0,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.len() as u32,
            )
        } < 0
        {
            return Err(io_err("bind selected IPv4 NIC for echo transmission"));
        }
        let proto = ETH_P_IP.to_be();
        let rx = Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(proto)) });
        if rx.0 < 0 {
            return Err(io_err("open native ICMP response receiver"));
        }
        let index = c_int::try_from(selected.index)
            .map_err(|_| EchoError::new(EchoErrorCode::Device, "interface index overflow"))?;
        let addr = SockAddrLl {
            family: AF_PACKET as u16,
            protocol: proto,
            ifindex: index,
            hatype: 0,
            pkttype: 0,
            halen: 0,
            addr: [0; 8],
        };
        if unsafe {
            bind(
                rx.0,
                (&raw const addr).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(io_err("bind selected native IPv4 receive interface"));
        }
        let mut report = Vec::with_capacity(targets.len());
        let mut last: Option<Instant> = None;
        for &target in targets {
            if cancelled(stop, scope) {
                return Err(EchoError::new(
                    EchoErrorCode::Cancelled,
                    "ICMP echo revoked",
                ));
            }
            if let Some(previous) = last {
                while previous.elapsed() < MIN_SEND_INTERVAL {
                    if cancelled(stop, scope) {
                        return Err(EchoError::new(
                            EchoErrorCode::Cancelled,
                            "ICMP echo revoked",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            let (identifier, sequence, ip_id) = random_echo_identity()?;
            let packet = crate::scan_packets::ipv4_icmp_echo(
                source, target, identifier, sequence, ip_id, 64,
            )
            .map_err(|_| {
                EchoError::new(
                    EchoErrorCode::InvalidScope,
                    "invalid ICMP echo source or target",
                )
            })?;
            let target_sock = SockAddrIn {
                family: AF_INET as u16,
                port: 0,
                addr: target.octets(),
                zero: [0; 8],
            };
            if cancelled(stop, scope) {
                return Err(EchoError::new(
                    EchoErrorCode::Cancelled,
                    "ICMP echo revoked",
                ));
            }
            let began = Instant::now();
            if unsafe {
                sendto(
                    tx.0,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&raw const target_sock).cast(),
                    std::mem::size_of::<SockAddrIn>() as u32,
                )
            } != packet.len() as isize
            {
                return Err(io_err("transmit native IPv4 ICMP echo request"));
            }
            last = Some(began);
            let identity = ProbeIdentity {
                local: IpAddr::V4(source),
                target: IpAddr::V4(target),
                transport: ProbeTransport::IcmpEcho,
                local_port: 0,
                target_port: 0,
                syn_sequence: None,
                echo_key: Some((identifier, sequence)),
            };
            let mut state = EchoState::Inconclusive;
            let mut reason = "icmp_echo_no_response";
            let mut buffer = [0u8; 4096];
            while began.elapsed() < WAIT_PER_HOST {
                if cancelled(stop, scope) {
                    return Err(EchoError::new(
                        EchoErrorCode::Cancelled,
                        "ICMP echo revoked",
                    ));
                }
                let time = WAIT_PER_HOST.saturating_sub(began.elapsed());
                let mut pfd = PollFd {
                    fd: rx.0,
                    events: POLLIN,
                    revents: 0,
                };
                let ready =
                    unsafe { poll(&raw mut pfd, 1, time.as_millis().min(50).max(1) as c_int) };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("poll scoped ICMP echo reply"));
                }
                if ready == 0 || pfd.revents & POLLIN == 0 {
                    continue;
                }
                let len = unsafe { recv(rx.0, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
                if len < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("receive scoped IPv4 ICMP frame"));
                }
                match correlate_ethernet_response(&buffer[..len as usize], &identity) {
                    Some(ReplyEvidence::IcmpEcho) => {
                        state = EchoState::Responded;
                        reason = "icmp_echo_reply_matching_id";
                        break;
                    }
                    Some(ReplyEvidence::IcmpV4Error { kind: 3, .. }) => {
                        state = EchoState::Unreachable;
                        reason = "matched_icmp_destination_unreachable";
                        break;
                    }
                    Some(ReplyEvidence::IcmpV4Error { kind: 11, .. }) => {
                        reason = "matched_icmp_time_exceeded";
                        break;
                    }
                    _ => {}
                }
            }
            if cancelled(stop, scope) {
                return Err(EchoError::new(
                    EchoErrorCode::Cancelled,
                    "ICMP echo revoked",
                ));
            }
            report.push(EchoObservation {
                target,
                state,
                reason,
                elapsed_ms: began.elapsed().as_millis().min(u64::MAX as u128) as u64,
            });
        }
        Ok(report)
    }

    pub(super) fn trace(
        interface: &str,
        target: Ipv4Addr,
        max_hops: u8,
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
    ) -> Result<Vec<TraceHop>, EchoError> {
        let interfaces =
            discover_interfaces().map_err(|e| EchoError::new(EchoErrorCode::Device, e.message))?;
        let selected = select_interface(&interfaces, interface)
            .map_err(|e| EchoError::new(EchoErrorCode::Device, e.message))?;
        let source = source_ipv4(&selected.name)?;
        if source == target {
            return Err(EchoError::new(
                EchoErrorCode::InvalidScope,
                "traceroute target must differ from the selected source address",
            ));
        }
        let tx = Fd(unsafe { socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW) });
        if tx.0 < 0 {
            return Err(io_err("open raw ICMP trace transmitter"));
        }
        let mut device = selected.name.as_bytes().to_vec();
        device.push(0);
        if unsafe {
            setsockopt(
                tx.0,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.len() as u32,
            )
        } < 0
        {
            return Err(io_err("bind authorized trace transmitter to interface"));
        }
        let proto = ETH_P_IP.to_be();
        let rx = Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(proto)) });
        if rx.0 < 0 {
            return Err(io_err("open trace response receiver"));
        }
        let index = c_int::try_from(selected.index)
            .map_err(|_| EchoError::new(EchoErrorCode::Device, "interface index overflow"))?;
        let addr = SockAddrLl {
            family: AF_PACKET as u16,
            protocol: proto,
            ifindex: index,
            hatype: 0,
            pkttype: 0,
            halen: 0,
            addr: [0; 8],
        };
        if unsafe {
            bind(
                rx.0,
                (&raw const addr).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(io_err("bind selected IPv4 trace capture"));
        }
        let destination = SockAddrIn {
            family: AF_INET as u16,
            port: 0,
            addr: target.octets(),
            zero: [0; 8],
        };
        let mut hops = Vec::with_capacity(usize::from(max_hops));
        for ttl in 1..=max_hops {
            if cancelled(stop, scope) {
                return Err(EchoError::new(
                    EchoErrorCode::Cancelled,
                    "traceroute scope revoked",
                ));
            }
            let (id, sequence, ip_id) = random_echo_identity()?;
            let packet =
                crate::scan_packets::ipv4_icmp_echo(source, target, id, sequence, ip_id, ttl)
                    .map_err(|_| {
                        EchoError::new(EchoErrorCode::InvalidScope, "invalid scoped trace packet")
                    })?;
            let identity = ProbeIdentity {
                local: IpAddr::V4(source),
                target: IpAddr::V4(target),
                transport: ProbeTransport::IcmpEcho,
                local_port: 0,
                target_port: 0,
                syn_sequence: None,
                echo_key: Some((id, sequence)),
            };
            let began = Instant::now();
            let sent = unsafe {
                sendto(
                    tx.0,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&raw const destination).cast(),
                    std::mem::size_of::<SockAddrIn>() as u32,
                )
            };
            if sent != packet.len() as isize {
                return Err(io_err("send one bounded TTL-limited ICMP echo"));
            }
            let mut result = TraceHop {
                ttl,
                responder: None,
                reached: false,
                reason: "no_matching_response",
                elapsed_ms: 0,
            };
            let mut buffer = [0u8; 4096];
            while began.elapsed() < WAIT_PER_HOST {
                if cancelled(stop, scope) {
                    return Err(EchoError::new(
                        EchoErrorCode::Cancelled,
                        "traceroute scope revoked",
                    ));
                }
                let remaining = WAIT_PER_HOST.saturating_sub(began.elapsed());
                let mut fd = PollFd {
                    fd: rx.0,
                    events: POLLIN,
                    revents: 0,
                };
                let ready = unsafe {
                    poll(
                        &raw mut fd,
                        1,
                        remaining.as_millis().min(50).max(1) as c_int,
                    )
                };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("receive matched ICMP trace response"));
                }
                if ready == 0 || fd.revents & POLLIN == 0 {
                    continue;
                }
                let len = unsafe { recv(rx.0, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
                if len < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("read native trace frame"));
                }
                let Some((origin, evidence)) =
                    crate::scan_replies::correlate_ethernet_response_with_origin(
                        &buffer[..len as usize],
                        &identity,
                    )
                else {
                    continue;
                };
                let IpAddr::V4(hop) = origin else { continue };
                match evidence {
                    ReplyEvidence::IcmpEcho if hop == target => {
                        result.responder = Some(hop);
                        result.reached = true;
                        result.reason = "matching_echo_reply";
                        break;
                    }
                    ReplyEvidence::IcmpV4Error { kind: 11, code: 0 } => {
                        result.responder = Some(hop);
                        result.reason = "matching_time_exceeded";
                        break;
                    }
                    ReplyEvidence::IcmpV4Error { kind: 3, .. } => {
                        result.responder = Some(hop);
                        result.reason = "matching_destination_unreachable";
                        break;
                    }
                    _ => {}
                }
            }
            if cancelled(stop, scope) {
                return Err(EchoError::new(
                    EchoErrorCode::Cancelled,
                    "traceroute scope revoked",
                ));
            }
            result.elapsed_ms = began.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let done = result.reached || result.reason == "matching_destination_unreachable";
            hops.push(result);
            if done {
                break;
            }
        }
        Ok(hops)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn echo_plan_is_bounded_and_unicast_only() {
        let host: Ipv4Addr = "192.0.2.5".parse().unwrap();
        assert!(validate_hosts(&[host]).is_ok());
        assert!(validate_hosts(&[]).is_err());
        assert!(validate_hosts(&vec![host; 33]).is_err());
        assert!(validate_hosts(&[Ipv4Addr::BROADCAST]).is_err());
        assert!(validate_hosts(&["224.0.0.1".parse().unwrap()]).is_err());
    }
    #[test]
    fn trace_enforces_exact_hop_cap_and_revocation_before_sockets() {
        let target: Ipv4Addr = "192.0.2.5".parse().unwrap();
        let active = AtomicBool::new(false);
        for max in [0u8, 17u8, 255u8] {
            assert_eq!(
                trace_ipv4_echo("none", target, max, &active, &|| true)
                    .unwrap_err()
                    .code,
                EchoErrorCode::InvalidScope
            );
        }
        for invalid in [Ipv4Addr::BROADCAST, Ipv4Addr::UNSPECIFIED] {
            assert_eq!(
                trace_ipv4_echo("none", invalid, 3, &active, &|| true)
                    .unwrap_err()
                    .code,
                EchoErrorCode::InvalidScope
            );
        }
        let stopped = AtomicBool::new(true);
        assert_eq!(
            trace_ipv4_echo("none", target, 3, &stopped, &|| true)
                .unwrap_err()
                .code,
            EchoErrorCode::Cancelled
        );
        assert_eq!(
            trace_ipv4_echo("none", target, 3, &active, &|| false)
                .unwrap_err()
                .code,
            EchoErrorCode::Cancelled
        );
    }

    #[test]
    fn cancelled_scope_rejects_before_raw_socket() {
        let stop = AtomicBool::new(true);
        let err = discover_ipv4_echo(
            "does-not-exist",
            &["192.0.2.5".parse().unwrap()],
            &stop,
            &|| true,
        )
        .unwrap_err();
        assert_eq!(err.code, EchoErrorCode::Cancelled);
    }
}

//! Bounded native Linux ICMPv6 Echo discovery over the selected Ethernet NIC.
//! Link-local destinations only: no implicit target expansion or interface guess.
//! Host permission, case authority and native operator confirmation belong to
//! the caller; this module never escalates privilege or invokes external tools.
use crate::scan_replies::{
    correlate_ethernet_response, ProbeIdentity, ProbeTransport, ReplyEvidence,
};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MAX_ICMP6_HOSTS: usize = 32;
const MAX_WAIT: Duration = Duration::from_millis(600);
const SEND_GAP: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Echo6State {
    Responded,
    Inconclusive,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Echo6Observation {
    pub target: Ipv6Addr,
    pub state: Echo6State,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Echo6ErrorCode {
    InvalidScope,
    Unsupported,
    Permission,
    Device,
    Io,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Echo6Error {
    pub code: Echo6ErrorCode,
    pub message: String,
}
impl Echo6Error {
    fn new(code: Echo6ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
pub fn validate_hosts(hosts: &[Ipv6Addr]) -> Result<(), Echo6Error> {
    if hosts.is_empty() || hosts.len() > MAX_ICMP6_HOSTS {
        return Err(Echo6Error::new(
            Echo6ErrorCode::InvalidScope,
            "native ICMPv6 supports 1..=32 distinct link-local targets",
        ));
    }
    if hosts.iter().any(|ip| !ip.is_unicast_link_local()) {
        return Err(Echo6Error::new(
            Echo6ErrorCode::InvalidScope,
            "native ICMPv6 accepts only unicast link-local fe80::/10 addresses",
        ));
    }
    let mut unique = hosts.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != hosts.len() {
        return Err(Echo6Error::new(
            Echo6ErrorCode::InvalidScope,
            "repeated ICMPv6 target addresses are not permitted",
        ));
    }
    Ok(())
}
/// Only kernel-configured link-local address on the selected NIC is allowed.
/// /proc/net/if_inet6 rows: hex-address, index, prefixlen, scope, flags, name.
pub(crate) fn parse_kernel_link_local(source: &str, name: &str, index: u32) -> Option<Ipv6Addr> {
    if name.is_empty() || name.len() >= 16 {
        return None;
    }
    for row in source.lines().take(4096) {
        let parts: Vec<_> = row.split_whitespace().collect();
        if parts.len() != 6
            || parts[5] != name
            || parts[0].len() != 32
            || u32::from_str_radix(parts[1], 16).ok() != Some(index)
            || parts[3] != "20"
        {
            continue;
        }
        let mut octets = [0u8; 16];
        let mut valid = true;
        for (i, b) in octets.iter_mut().enumerate() {
            match u8::from_str_radix(&parts[0][2 * i..2 * i + 2], 16) {
                Ok(v) => *b = v,
                Err(_) => {
                    valid = false;
                    break;
                }
            }
        }
        let ip = Ipv6Addr::from(octets);
        if valid && ip.is_unicast_link_local() {
            return Some(ip);
        }
    }
    None
}
/// One traceroute hop: which router answered, whether the target was
/// reached, and how long the round trip took. Inconclusive hops are honest:
/// silence or non-matching replies never invent a responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceHop6 {
    pub hop: u8,
    pub responder: Option<Ipv6Addr>,
    pub reached: bool,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}

/// Scoped, operator-confirmed ICMPv6 traceroute over the same raw-socket
/// machinery as the echo sweep, one hop limit per probe. Linux only: raw
/// ICMPv6 and AF_PACKET require CAP_NET_RAW.
pub fn trace_ipv6_echo(
    interface_name: &str,
    target: Ipv6Addr,
    max_hops: u8,
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
) -> Result<Vec<TraceHop6>, Echo6Error> {
    validate_hosts(&[target])?;
    if max_hops == 0 || max_hops > 16 {
        return Err(Echo6Error::new(
            Echo6ErrorCode::InvalidScope,
            "trace hop limit must be 1..=16",
        ));
    }
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(Echo6Error::new(
            Echo6ErrorCode::Cancelled,
            "IPv6 trace scope revoked",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::trace(interface_name, target, max_hops, stop, scope_active)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface_name;
        Err(Echo6Error::new(
            Echo6ErrorCode::Unsupported,
            "native ICMPv6 traceroute currently requires Linux CAP_NET_RAW",
        ))
    }
}

pub fn discover_ipv6_echo(
    interface_name: &str,
    targets: &[Ipv6Addr],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
) -> Result<Vec<Echo6Observation>, Echo6Error> {
    validate_hosts(targets)?;
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(Echo6Error::new(
            Echo6ErrorCode::Cancelled,
            "IPv6 scan scope revoked",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::discover(interface_name, targets, stop, scope_active)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface_name;
        Err(Echo6Error::new(
            Echo6ErrorCode::Unsupported,
            "native raw ICMPv6 echo currently requires Linux CAP_NET_RAW",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::live::{discover_interfaces, select_interface};
    use std::ffi::{c_int, c_void};
    use std::io::{self, Read};
    const AF_INET6: c_int = 10;
    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const SOL_SOCKET: c_int = 1;
    const SO_BINDTODEVICE: c_int = 25;
    const IPPROTO_ICMPV6: c_int = 58;
    const IPPROTO_IPV6: c_int = 41;
    const IPV6_UNICAST_HOPS: c_int = 16;
    const ETH_P_IPV6: u16 = 0x86dd;
    const POLLIN: i16 = 1;
    #[repr(C)]
    struct SockAddrIn6 {
        family: u16,
        port: u16,
        flowinfo: u32,
        addr: [u8; 16],
        scope_id: u32,
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
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }
    unsafe extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        fn setsockopt(fd: c_int, level: c_int, opt: c_int, value: *const c_void, len: u32)
            -> c_int;
        fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const c_void,
            addr_len: u32,
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
    fn last_error(task: &str) -> Echo6Error {
        let err = io::Error::last_os_error();
        Echo6Error::new(
            if err.kind() == io::ErrorKind::PermissionDenied {
                Echo6ErrorCode::Permission
            } else {
                Echo6ErrorCode::Io
            },
            format!("{task}: {err}"),
        )
    }
    fn random_request_id() -> Result<(u16, u16), Echo6Error> {
        let mut bytes = [0u8; 4];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(|e| {
                Echo6Error::new(
                    Echo6ErrorCode::Io,
                    format!("OS random echo identity unavailable: {e}"),
                )
            })?;
        Ok((
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        ))
    }
    fn cancelled(stop: &AtomicBool, scope: &(impl Fn() -> bool + Sync)) -> bool {
        stop.load(Ordering::Acquire) || !scope()
    }
    /// ICMPv6 traceroute: one hop limit per probe, replies correlated by the
    /// echo identity. Echo replies mean the target was reached; ICMPv6
    /// time-exceeded (kind 3) means an intermediate router answered and its
    /// address is the frame's IPv6 source. Silence stays inconclusive.
    pub(super) fn trace(
        interface: &str,
        target: Ipv6Addr,
        max_hops: u8,
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
    ) -> Result<Vec<TraceHop6>, Echo6Error> {
        let known = discover_interfaces()
            .map_err(|e| Echo6Error::new(Echo6ErrorCode::Device, e.message))?;
        let nic = select_interface(&known, interface)
            .map_err(|e| Echo6Error::new(Echo6ErrorCode::Device, e.message))?;
        let meta = std::fs::read_to_string("/proc/net/if_inet6").map_err(|e| {
            Echo6Error::new(
                Echo6ErrorCode::Device,
                format!("read selected Linux IPv6 interface addresses: {e}"),
            )
        })?;
        let source = parse_kernel_link_local(&meta, &nic.name, nic.index).ok_or_else(|| {
            Echo6Error::new(
                Echo6ErrorCode::InvalidScope,
                "selected NIC does not have a kernel-configured IPv6 link-local source",
            )
        })?;
        let index = c_int::try_from(nic.index).map_err(|_| {
            Echo6Error::new(Echo6ErrorCode::Device, "selected interface index overflow")
        })?;
        let sender = Fd(unsafe { socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6) });
        if sender.0 < 0 {
            return Err(last_error("open native ICMPv6 raw transmitter"));
        }
        let mut device = nic.name.as_bytes().to_vec();
        device.push(0);
        if unsafe {
            setsockopt(
                sender.0,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.len() as u32,
            )
        } < 0
        {
            return Err(last_error("bind ICMPv6 transmitter to selected NIC"));
        }
        let local = SockAddrIn6 {
            family: AF_INET6 as u16,
            port: 0,
            flowinfo: 0,
            addr: source.octets(),
            scope_id: nic.index,
        };
        if unsafe {
            bind(
                sender.0,
                (&raw const local).cast(),
                std::mem::size_of::<SockAddrIn6>() as u32,
            )
        } < 0
        {
            return Err(last_error("bind actual link-local IPv6 source"));
        }
        let protocol = ETH_P_IPV6.to_be();
        let receiver =
            Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) });
        if receiver.0 < 0 {
            return Err(last_error("open native ICMPv6 Ethernet receiver"));
        }
        let local_link = SockAddrLl {
            family: AF_PACKET as u16,
            protocol,
            ifindex: index,
            hatype: 0,
            pkttype: 0,
            halen: 0,
            addr: [0; 8],
        };
        if unsafe {
            bind(
                receiver.0,
                (&raw const local_link).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(last_error("bind selected ICMPv6 response interface"));
        }

        let mut hops = Vec::with_capacity(usize::from(max_hops));
        for hop in 1..=u16::from(max_hops) {
            if cancelled(stop, scope) {
                return Err(Echo6Error::new(
                    Echo6ErrorCode::Cancelled,
                    "IPv6 trace scope revoked",
                ));
            }
            let hop_c = c_int::from(hop);
            if unsafe {
                setsockopt(
                    sender.0,
                    IPPROTO_IPV6,
                    IPV6_UNICAST_HOPS,
                    (&raw const hop_c).cast(),
                    std::mem::size_of::<c_int>() as u32,
                )
            } < 0
            {
                return Err(last_error("set per-hop IPv6 unicast hop limit"));
            }
            let (identifier, sequence) = random_request_id()?;
            let datagram = crate::scan_packets::ipv6_icmp_echo(
                source,
                target,
                identifier,
                sequence,
                hop as u8,
            )
            .map_err(|_| {
                Echo6Error::new(Echo6ErrorCode::InvalidScope, "invalid scoped ICMPv6 echo bytes")
            })?;
            let dst = SockAddrIn6 {
                family: AF_INET6 as u16,
                port: 0,
                flowinfo: 0,
                addr: target.octets(),
                scope_id: nic.index,
            };
            let started = Instant::now();
            let payload = &datagram[40..];
            let wrote = unsafe {
                sendto(
                    sender.0,
                    payload.as_ptr().cast(),
                    payload.len(),
                    0,
                    (&raw const dst).cast(),
                    std::mem::size_of::<SockAddrIn6>() as u32,
                )
            };
            if wrote != payload.len() as isize {
                return Err(last_error("send one bounded ICMPv6 trace probe"));
            }
            let outstanding = ProbeIdentity {
                local: IpAddr::V6(source),
                target: IpAddr::V6(target),
                transport: ProbeTransport::IcmpEcho,
                local_port: 0,
                target_port: 0,
                syn_sequence: None,
                echo_key: Some((identifier, sequence)),
            };
            let mut hop = TraceHop6 {
                hop: hop as u8,
                responder: None,
                reached: false,
                reason: "icmpv6_trace_no_matching_response",
                elapsed_ms: 0,
            };
            let mut frame = [0u8; 4096];
            while started.elapsed() < MAX_WAIT {
                if cancelled(stop, scope) {
                    return Err(Echo6Error::new(
                        Echo6ErrorCode::Cancelled,
                        "IPv6 trace scope revoked",
                    ));
                }
                let remaining = MAX_WAIT.saturating_sub(started.elapsed());
                let mut fds = PollFd {
                    fd: receiver.0,
                    events: POLLIN,
                    revents: 0,
                };
                let ready = unsafe {
                    poll(&raw mut fds, 1, remaining.as_millis().min(50).max(1) as c_int)
                };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(last_error("poll native ICMPv6 trace replies"));
                }
                if ready == 0 || fds.revents & POLLIN == 0 {
                    continue;
                }
                let length = unsafe { recv(receiver.0, frame.as_mut_ptr().cast(), frame.len(), 0) };
                if length < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(last_error("read native ICMPv6 Ethernet reply"));
                }
                match correlate_ethernet_response(&frame[..length as usize], &outstanding) {
                    Some(ReplyEvidence::IcmpEcho) => {
                        hop.reached = true;
                        hop.responder = Some(target);
                        hop.reason = "icmpv6_echo_reply_matching_identifier";
                        hop.elapsed_ms = started.elapsed().as_millis() as u64;
                        break;
                    }
                    Some(ReplyEvidence::IcmpV6Error { kind: 3, .. }) => {
                        // Time exceeded: the frame's IPv6 source is the
                        // intermediate router that dropped the probe.
                        if length as usize >= 38 {
                            let octets: [u8; 16] = frame[22..38]
                                .try_into()
                                .expect("bounded frame slice is 16 bytes");
                            hop.responder = Some(Ipv6Addr::from(octets));
                        }
                        hop.reason = "icmpv6_time_exceeded_from_intermediate_hop";
                        hop.elapsed_ms = started.elapsed().as_millis() as u64;
                        break;
                    }
                    _ => continue,
                }
            }
            let reached = hop.reached;
            hops.push(hop);
            if reached {
                break;
            }
        }
        Ok(hops)
    }

    pub(super) fn discover(
        interface: &str,
        targets: &[Ipv6Addr],
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
    ) -> Result<Vec<Echo6Observation>, Echo6Error> {
        let known = discover_interfaces()
            .map_err(|e| Echo6Error::new(Echo6ErrorCode::Device, e.message))?;
        let nic = select_interface(&known, interface)
            .map_err(|e| Echo6Error::new(Echo6ErrorCode::Device, e.message))?;
        let meta = std::fs::read_to_string("/proc/net/if_inet6").map_err(|e| {
            Echo6Error::new(
                Echo6ErrorCode::Device,
                format!("read selected Linux IPv6 interface addresses: {e}"),
            )
        })?;
        let source = parse_kernel_link_local(&meta, &nic.name, nic.index).ok_or_else(|| {
            Echo6Error::new(
                Echo6ErrorCode::InvalidScope,
                "selected NIC does not have a kernel-configured IPv6 link-local source",
            )
        })?;
        if targets.contains(&source) {
            return Err(Echo6Error::new(
                Echo6ErrorCode::InvalidScope,
                "ICMPv6 scan cannot target its own selected interface address",
            ));
        }
        let index = c_int::try_from(nic.index).map_err(|_| {
            Echo6Error::new(Echo6ErrorCode::Device, "selected interface index overflow")
        })?;
        // AF_INET6 raw socket supplies an IPv6 header in the kernel and
        // calculates the mandatory ICMPv6 checksum; user bytes are ICMP only.
        let sender = Fd(unsafe { socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6) });
        if sender.0 < 0 {
            return Err(last_error("open native ICMPv6 raw transmitter"));
        }
        let mut device = nic.name.as_bytes().to_vec();
        device.push(0);
        if unsafe {
            setsockopt(
                sender.0,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.len() as u32,
            )
        } < 0
        {
            return Err(last_error("bind ICMPv6 transmitter to selected NIC"));
        }
        let local = SockAddrIn6 {
            family: AF_INET6 as u16,
            port: 0,
            flowinfo: 0,
            addr: source.octets(),
            scope_id: nic.index,
        };
        if unsafe {
            bind(
                sender.0,
                (&raw const local).cast(),
                std::mem::size_of::<SockAddrIn6>() as u32,
            )
        } < 0
        {
            return Err(last_error("bind actual link-local IPv6 source"));
        }
        let protocol = ETH_P_IPV6.to_be();
        let receiver =
            Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) });
        if receiver.0 < 0 {
            return Err(last_error("open native ICMPv6 Ethernet receiver"));
        }
        let local_link = SockAddrLl {
            family: AF_PACKET as u16,
            protocol,
            ifindex: index,
            hatype: 0,
            pkttype: 0,
            halen: 0,
            addr: [0; 8],
        };
        if unsafe {
            bind(
                receiver.0,
                (&raw const local_link).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(last_error("bind selected ICMPv6 response interface"));
        }
        let mut rows = Vec::with_capacity(targets.len());
        let mut last: Option<Instant> = None;
        for &target in targets {
            if cancelled(stop, scope) {
                return Err(Echo6Error::new(
                    Echo6ErrorCode::Cancelled,
                    "IPv6 echo scope revoked",
                ));
            }
            if let Some(previous) = last {
                while previous.elapsed() < SEND_GAP {
                    if cancelled(stop, scope) {
                        return Err(Echo6Error::new(
                            Echo6ErrorCode::Cancelled,
                            "IPv6 echo scope revoked",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            let (identifier, sequence) = random_request_id()?;
            let datagram =
                crate::scan_packets::ipv6_icmp_echo(source, target, identifier, sequence, 64)
                    .map_err(|_| {
                        Echo6Error::new(
                            Echo6ErrorCode::InvalidScope,
                            "invalid scoped ICMPv6 echo bytes",
                        )
                    })?;
            let dst = SockAddrIn6 {
                family: AF_INET6 as u16,
                port: 0,
                flowinfo: 0,
                addr: target.octets(),
                scope_id: nic.index,
            };
            if cancelled(stop, scope) {
                return Err(Echo6Error::new(
                    Echo6ErrorCode::Cancelled,
                    "IPv6 echo scope revoked",
                ));
            }
            let started = Instant::now();
            let payload = &datagram[40..];
            let wrote = unsafe {
                sendto(
                    sender.0,
                    payload.as_ptr().cast(),
                    payload.len(),
                    0,
                    (&raw const dst).cast(),
                    std::mem::size_of::<SockAddrIn6>() as u32,
                )
            };
            if wrote != payload.len() as isize {
                return Err(last_error("send one bounded IPv6 echo request"));
            }
            last = Some(started);
            let outstanding = ProbeIdentity {
                local: IpAddr::V6(source),
                target: IpAddr::V6(target),
                transport: ProbeTransport::IcmpEcho,
                local_port: 0,
                target_port: 0,
                syn_sequence: None,
                echo_key: Some((identifier, sequence)),
            };
            let mut status = Echo6State::Inconclusive;
            let mut reason = "icmpv6_echo_no_matching_response";
            let mut frame = [0u8; 4096];
            while started.elapsed() < MAX_WAIT {
                if cancelled(stop, scope) {
                    return Err(Echo6Error::new(
                        Echo6ErrorCode::Cancelled,
                        "IPv6 echo scope revoked",
                    ));
                }
                let remaining = MAX_WAIT.saturating_sub(started.elapsed());
                let mut fds = PollFd {
                    fd: receiver.0,
                    events: POLLIN,
                    revents: 0,
                };
                let ready = unsafe {
                    poll(
                        &raw mut fds,
                        1,
                        remaining.as_millis().min(50).max(1) as c_int,
                    )
                };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(last_error("poll native IPv6 echo replies"));
                }
                if ready == 0 || fds.revents & POLLIN == 0 {
                    continue;
                }
                let length = unsafe { recv(receiver.0, frame.as_mut_ptr().cast(), frame.len(), 0) };
                if length < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(last_error("read native IPv6 Ethernet reply"));
                }
                match correlate_ethernet_response(&frame[..length as usize], &outstanding) {
                    Some(ReplyEvidence::IcmpEcho) => {
                        status = Echo6State::Responded;
                        reason = "icmpv6_echo_reply_matching_identifier";
                        break;
                    }
                    Some(ReplyEvidence::IcmpV6Error { kind: 1, .. }) => {
                        reason = "matched_icmpv6_destination_unreachable";
                        break;
                    }
                    Some(ReplyEvidence::IcmpV6Error { kind: 3, .. }) => {
                        reason = "matched_icmpv6_time_exceeded";
                        break;
                    }
                    _ => {}
                }
            }
            if cancelled(stop, scope) {
                return Err(Echo6Error::new(
                    Echo6ErrorCode::Cancelled,
                    "IPv6 echo scope revoked",
                ));
            }
            rows.push(Echo6Observation {
                target,
                state: status,
                reason,
                elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            });
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_distinct_bounded_link_local_hosts_are_accepted() {
        let one: Ipv6Addr = "fe80::2".parse().unwrap();
        assert!(validate_hosts(&[one]).is_ok());
        assert!(validate_hosts(&[]).is_err());
        assert!(validate_hosts(&[one, one]).is_err());
        assert!(validate_hosts(&vec![one; 33]).is_err());
        assert!(validate_hosts(&["ff02::1".parse().unwrap()]).is_err());
        assert!(validate_hosts(&["2001:db8::1".parse().unwrap()]).is_err());
    }
    #[test]
    fn interface_source_parser_never_uses_another_nic() {
        let meta="fe800000000000000000000000000001 02 40 20 80 eth0\nfe800000000000000000000000000002 03 40 20 80 eth1\n";
        assert_eq!(
            parse_kernel_link_local(meta, "eth0", 2),
            Some("fe80::1".parse().unwrap())
        );
        assert_eq!(parse_kernel_link_local(meta, "eth0", 3), None);
        assert_eq!(
            parse_kernel_link_local(meta, "eth1", 3),
            Some("fe80::2".parse().unwrap())
        );
        assert_eq!(parse_kernel_link_local(meta, "eth2", 3), None);
    }
    #[test]
    fn cancellation_precedes_interface_or_privileged_socket_access() {
        let cancel = AtomicBool::new(true);
        let target = "fe80::1".parse().unwrap();
        assert_eq!(
            discover_ipv6_echo("invalid", &[target], &cancel, &|| true)
                .unwrap_err()
                .code,
            Echo6ErrorCode::Cancelled
        );
        let live = AtomicBool::new(false);
        assert_eq!(
            discover_ipv6_echo("invalid", &[target], &live, &|| false)
                .unwrap_err()
                .code,
            Echo6ErrorCode::Cancelled
        );
    }
}

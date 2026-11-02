//! Native Linux IPv6 link-local TCP SYN scanner. A bounded receive window
//! correlates responses with backend-random source ports and SYN sequences.
//! Authorization, selected saved case and explicit native consent are enforced
//! by the Tauri caller. Silence is inconclusive, never a filtered claim.
use crate::scan_replies::{
    correlate_ethernet_response, ProbeIdentity, ProbeTransport, ReplyEvidence,
};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MAX_SYN6_HOSTS: usize = 16;
pub const MAX_SYN6_PORTS: usize = 64;
pub const MAX_SYN6_PROBES: usize = 512;
const WINDOW: usize = 8;
const SEND_GAP: Duration = Duration::from_millis(40);
const REPLY_DEADLINE: Duration = Duration::from_millis(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syn6State {
    Open,
    Closed,
    Unreachable,
    Inconclusive,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syn6Finding {
    pub host: Ipv6Addr,
    pub port: u16,
    pub state: Syn6State,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syn6ErrorCode {
    InvalidScope,
    Unsupported,
    Permission,
    Device,
    Io,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syn6Error {
    pub code: Syn6ErrorCode,
    pub message: String,
}
impl Syn6Error {
    fn new(code: Syn6ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
pub fn validate_plan(hosts: &[Ipv6Addr], ports: &[u16]) -> Result<(), Syn6Error> {
    if hosts.is_empty()
        || hosts.len() > MAX_SYN6_HOSTS
        || ports.is_empty()
        || ports.len() > MAX_SYN6_PORTS
        || hosts
            .len()
            .checked_mul(ports.len())
            .is_none_or(|n| n > MAX_SYN6_PROBES)
    {
        return Err(Syn6Error::new(
            Syn6ErrorCode::InvalidScope,
            "IPv6 SYN scan caps: 16 link-local hosts, 64 ports and 512 probes",
        ));
    }
    if hosts.iter().any(|h| !h.is_unicast_link_local()) || ports.contains(&0) {
        return Err(Syn6Error::new(
            Syn6ErrorCode::InvalidScope,
            "IPv6 SYN requires fe80::/10 unicast hosts and nonzero TCP ports",
        ));
    }
    let mut h = hosts.to_vec();
    h.sort_unstable();
    h.dedup();
    let mut p = ports.to_vec();
    p.sort_unstable();
    p.dedup();
    if h.len() != hosts.len() || p.len() != ports.len() {
        return Err(Syn6Error::new(
            Syn6ErrorCode::InvalidScope,
            "duplicate IPv6 SYN hosts/ports are disallowed",
        ));
    }
    Ok(())
}
pub fn scan_ipv6_syn(
    interface: &str,
    hosts: &[Ipv6Addr],
    ports: &[u16],
    stop: &AtomicBool,
    active: &(impl Fn() -> bool + Sync),
    progress: &(impl Fn(usize, usize) + Sync),
) -> Result<Vec<Syn6Finding>, Syn6Error> {
    validate_plan(hosts, ports)?;
    if stop.load(Ordering::Acquire) || !active() {
        return Err(Syn6Error::new(
            Syn6ErrorCode::Cancelled,
            "native IPv6 scan revoked",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::run(interface, hosts, ports, stop, active, progress)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        Err(Syn6Error::new(
            Syn6ErrorCode::Unsupported,
            "native IPv6 SYN currently requires Linux CAP_NET_RAW",
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
    const IPPROTO_TCP: c_int = 6;
    const IPPROTO_IPV6: c_int = 41;
    const IPV6_CHECKSUM: c_int = 7;
    const SOL_SOCKET: c_int = 1;
    const SO_BINDTODEVICE: c_int = 25;
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
        fn setsockopt(fd: c_int, level: c_int, opt: c_int, data: *const c_void, len: u32) -> c_int;
        fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const c_void,
            addr_len: u32,
        ) -> isize;
        fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, n: usize, timeout: c_int) -> c_int;
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
    fn io_err(task: &str) -> Syn6Error {
        let e = io::Error::last_os_error();
        let code = if e.kind() == io::ErrorKind::PermissionDenied {
            Syn6ErrorCode::Permission
        } else {
            Syn6ErrorCode::Io
        };
        Syn6Error::new(code, format!("{task}: {e}"))
    }
    fn random_identity() -> Result<(u16, u32), Syn6Error> {
        let mut random = [0u8; 6];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut random))
            .map_err(|e| {
                Syn6Error::new(
                    Syn6ErrorCode::Io,
                    format!("OS random probe identity unavailable: {e}"),
                )
            })?;
        Ok((
            49152 + (u16::from_be_bytes([random[0], random[1]]) % 16384),
            u32::from_be_bytes(random[2..6].try_into().expect("six bytes")),
        ))
    }
    fn cancelled(stop: &AtomicBool, scope: &(impl Fn() -> bool + Sync)) -> bool {
        stop.load(Ordering::Acquire) || !scope()
    }
    struct Pending {
        index: usize,
        identity: ProbeIdentity,
        sent: Instant,
    }
    fn entry(p: &Pending, state: Syn6State, reason: &'static str) -> Syn6Finding {
        Syn6Finding {
            host: match p.identity.target {
                IpAddr::V6(ip) => ip,
                _ => unreachable!("IPv6 plan"),
            },
            port: p.identity.target_port,
            state,
            reason,
            elapsed_ms: p.sent.elapsed().as_millis().min(u64::MAX as u128) as u64,
        }
    }
    pub(super) fn run(
        interface: &str,
        hosts: &[Ipv6Addr],
        ports: &[u16],
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
        progress: &(impl Fn(usize, usize) + Sync),
    ) -> Result<Vec<Syn6Finding>, Syn6Error> {
        let all =
            discover_interfaces().map_err(|e| Syn6Error::new(Syn6ErrorCode::Device, e.message))?;
        let nic = select_interface(&all, interface)
            .map_err(|e| Syn6Error::new(Syn6ErrorCode::Device, e.message))?;
        let metadata = std::fs::read_to_string("/proc/net/if_inet6").map_err(|e| {
            Syn6Error::new(
                Syn6ErrorCode::Device,
                format!("read kernel IPv6 addresses: {e}"),
            )
        })?;
        let source = crate::active_echo6::parse_kernel_link_local(&metadata, &nic.name, nic.index)
            .ok_or_else(|| {
                Syn6Error::new(
                    Syn6ErrorCode::InvalidScope,
                    "selected NIC has no kernel IPv6 link-local address",
                )
            })?;
        if hosts.contains(&source) {
            return Err(Syn6Error::new(
                Syn6ErrorCode::InvalidScope,
                "cannot SYN scan own NIC address",
            ));
        }
        let index = c_int::try_from(nic.index)
            .map_err(|_| Syn6Error::new(Syn6ErrorCode::Device, "NIC index exceeds native range"))?;
        let sender = Fd(unsafe { socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_TCP) });
        if sender.0 < 0 {
            return Err(io_err("open Linux IPv6 raw TCP socket"));
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
            return Err(io_err("bind raw IPv6 sender to selected NIC"));
        }
        let checksum_offset: c_int = 16;
        if unsafe {
            setsockopt(
                sender.0,
                IPPROTO_IPV6,
                IPV6_CHECKSUM,
                (&raw const checksum_offset).cast(),
                std::mem::size_of::<c_int>() as u32,
            )
        } < 0
        {
            return Err(io_err("configure raw IPv6 TCP checksum"));
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
            return Err(io_err("bind kernel-configured IPv6 source"));
        }
        let proto = ETH_P_IPV6.to_be();
        let receiver =
            Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(proto)) });
        if receiver.0 < 0 {
            return Err(io_err("open native IPv6 frame receiver"));
        }
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
                receiver.0,
                (&raw const addr).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(io_err("bind selected IPv6 Ethernet receiver"));
        }
        let total = hosts.len() * ports.len();
        let mut results = vec![None; total];
        let mut active: Vec<Pending> = Vec::with_capacity(WINDOW);
        let mut next = 0usize;
        let mut done = 0usize;
        let mut last: Option<Instant> = None;
        let mut frame = [0u8; 4096];
        while done < total {
            if cancelled(stop, scope) {
                return Err(Syn6Error::new(
                    Syn6ErrorCode::Cancelled,
                    "IPv6 SYN operation revoked",
                ));
            }
            let mut i = 0;
            while i < active.len() {
                if active[i].sent.elapsed() >= REPLY_DEADLINE {
                    let pending = active.swap_remove(i);
                    results[pending.index] = Some(entry(
                        &pending,
                        Syn6State::Inconclusive,
                        "tcp_syn_no_matching_response",
                    ));
                    done += 1;
                    progress(done, total);
                } else {
                    i += 1;
                }
            }
            if next < total
                && active.len() < WINDOW
                && last.is_none_or(|when| when.elapsed() >= SEND_GAP)
            {
                let host = hosts[next / ports.len()];
                let port = ports[next % ports.len()];
                let (local_port, sequence) = random_identity()?;
                let datagram =
                    crate::scan_packets::ipv6_tcp_syn(source, host, local_port, port, sequence, 64)
                        .map_err(|_| {
                            Syn6Error::new(
                                Syn6ErrorCode::InvalidScope,
                                "unable to build selected IPv6 TCP SYN",
                            )
                        })?;
                let destination = SockAddrIn6 {
                    family: AF_INET6 as u16,
                    port: 0,
                    flowinfo: 0,
                    addr: host.octets(),
                    scope_id: nic.index,
                };
                if cancelled(stop, scope) {
                    return Err(Syn6Error::new(
                        Syn6ErrorCode::Cancelled,
                        "IPv6 SYN operation revoked",
                    ));
                }
                let began = Instant::now();
                let tcp = &datagram[40..60];
                if unsafe {
                    sendto(
                        sender.0,
                        tcp.as_ptr().cast(),
                        tcp.len(),
                        0,
                        (&raw const destination).cast(),
                        std::mem::size_of::<SockAddrIn6>() as u32,
                    )
                } != tcp.len() as isize
                {
                    return Err(io_err("send bounded IPv6 TCP SYN"));
                }
                active.push(Pending {
                    index: next,
                    sent: began,
                    identity: ProbeIdentity {
                        local: IpAddr::V6(source),
                        target: IpAddr::V6(host),
                        transport: ProbeTransport::TcpSyn,
                        local_port,
                        target_port: port,
                        syn_sequence: Some(sequence),
                        echo_key: None,
                    },
                });
                last = Some(began);
                next += 1;
            }
            let mut pollfd = PollFd {
                fd: receiver.0,
                events: POLLIN,
                revents: 0,
            };
            let ready = unsafe { poll(&raw mut pollfd, 1, 20) };
            if ready < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io_err("poll scoped IPv6 SYN reply"));
            }
            if ready == 0 || pollfd.revents & POLLIN == 0 {
                continue;
            }
            let length = unsafe { recv(receiver.0, frame.as_mut_ptr().cast(), frame.len(), 0) };
            if length < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io_err("read native IPv6 reply"));
            }
            for pos in 0..active.len() {
                let outcome = match correlate_ethernet_response(
                    &frame[..length as usize],
                    &active[pos].identity,
                ) {
                    Some(ReplyEvidence::TcpSynAck) => Some((Syn6State::Open, "matched_tcp_synack")),
                    Some(ReplyEvidence::TcpReset) => Some((Syn6State::Closed, "matched_tcp_reset")),
                    Some(ReplyEvidence::IcmpV6Error { kind: 1, .. }) => {
                        Some((Syn6State::Unreachable, "matched_icmpv6_unreachable"))
                    }
                    Some(ReplyEvidence::IcmpV6Error { kind: 3, .. }) => {
                        Some((Syn6State::Inconclusive, "matched_icmpv6_time_exceeded"))
                    }
                    _ => None,
                };
                if let Some((state, reason)) = outcome {
                    let p = active.swap_remove(pos);
                    results[p.index] = Some(entry(&p, state, reason));
                    done += 1;
                    progress(done, total);
                    break;
                }
            }
        }
        if cancelled(stop, scope) {
            return Err(Syn6Error::new(
                Syn6ErrorCode::Cancelled,
                "IPv6 SYN operation revoked",
            ));
        }
        results
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Syn6Error::new(Syn6ErrorCode::Io, "IPv6 SYN results incomplete"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_scan_limits_and_duplicate_policy() {
        let host: Ipv6Addr = "fe80::42".parse().unwrap();
        assert!(validate_plan(&[host], &[22, 443]).is_ok());
        assert!(validate_plan(&[], &[22]).is_err());
        assert!(validate_plan(&[host], &[0]).is_err());
        assert!(validate_plan(&[host, host], &[22]).is_err());
        assert!(validate_plan(&[host], &[22, 22]).is_err());
        assert!(validate_plan(&["2001:db8::1".parse().unwrap()], &[22]).is_err());
        assert!(validate_plan(&vec![host; 17], &[22]).is_err());
        assert!(validate_plan(&[host], &(1..=65).collect::<Vec<_>>()).is_err());
    }
    #[test]
    fn stop_or_scope_revocation_precedes_privileged_socket() {
        let host = "fe80::42".parse().unwrap();
        let stopped = AtomicBool::new(true);
        assert_eq!(
            scan_ipv6_syn("missing", &[host], &[22], &stopped, &|| true, &|_, _| {})
                .unwrap_err()
                .code,
            Syn6ErrorCode::Cancelled
        );
        let live = AtomicBool::new(false);
        assert_eq!(
            scan_ipv6_syn("missing", &[host], &[22], &live, &|| false, &|_, _| {})
                .unwrap_err()
                .code,
            Syn6ErrorCode::Cancelled
        );
    }
}

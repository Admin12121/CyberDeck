//! Linux native IPv4 TCP SYN scanning. No subprocess or external scanner.
//! Raw socket access and explicit upstream operator/case authorization required.
//! Enforces one interface, a bounded plan, rate, cancellation, and correlated
//! response evidence. Never assumes a timeout means filtered or down.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::scan_replies::{
    correlate_ethernet_response, ProbeIdentity, ProbeTransport, ReplyEvidence,
};

pub const MAX_SYN_HOSTS: usize = 32;
pub const MAX_SYN_PORTS: usize = 128;
pub const MAX_SYN_PROBES: usize = 2048;
const RESPONSE_WAIT: Duration = Duration::from_millis(600);
const SEND_GAP: Duration = Duration::from_millis(40);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynState {
    Open,
    Closed,
    Unreachable,
    Inconclusive,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynFinding {
    pub host: Ipv4Addr,
    pub port: u16,
    pub state: SynState,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynErrorCode {
    Unsupported,
    InvalidScope,
    Permission,
    Device,
    Io,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynScanError {
    pub code: SynErrorCode,
    pub message: String,
}
impl SynScanError {
    fn new(code: SynErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn validate_plan(hosts: &[Ipv4Addr], ports: &[u16]) -> Result<(), SynScanError> {
    if hosts.is_empty()
        || hosts.len() > MAX_SYN_HOSTS
        || ports.is_empty()
        || ports.len() > MAX_SYN_PORTS
        || hosts
            .len()
            .checked_mul(ports.len())
            .is_none_or(|count| count > MAX_SYN_PROBES)
    {
        return Err(SynScanError::new(
            SynErrorCode::InvalidScope,
            "raw TCP SYN scan exceeds 32 hosts, 128 ports, or 2048 probes",
        ));
    }
    if hosts
        .iter()
        .any(|host| host.is_unspecified() || host.is_multicast() || host.is_broadcast())
        || ports.contains(&0)
    {
        return Err(SynScanError::new(
            SynErrorCode::InvalidScope,
            "SYN scanning requires unicast IPv4 targets and nonzero ports",
        ));
    }
    Ok(())
}

pub fn scan_ipv4_syn(
    interface_name: &str,
    hosts: &[Ipv4Addr],
    ports: &[u16],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    progress: &(impl Fn(usize, usize) + Sync),
) -> Result<Vec<SynFinding>, SynScanError> {
    validate_plan(hosts, ports)?;
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(SynScanError::new(
            SynErrorCode::Cancelled,
            "raw scan scope revoked",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::scan(interface_name, hosts, ports, stop, scope_active, progress)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface_name, progress);
        Err(SynScanError::new(
            SynErrorCode::Unsupported,
            "Linux native IPv4 SYN scanning requires CAP_NET_RAW",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::live::{discover_interfaces, select_interface};
    use std::ffi::{c_int, c_ulong, c_void};
    use std::io;
    use std::os::fd::RawFd;

    const AF_INET: c_int = 2;
    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_DGRAM: c_int = 2;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_IP: u16 = 0x0800;
    const IPPROTO_RAW: c_int = 255;
    const SOL_SOCKET: c_int = 1;
    const SO_BINDTODEVICE: c_int = 25;
    const SIOCGIFADDR: c_ulong = 0x8915;
    const POLLIN: i16 = 1;

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
    struct SockAddrIn {
        family: u16,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
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
        fn setsockopt(fd: c_int, level: c_int, opt: c_int, val: *const c_void, len: u32) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
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
    struct Fd(RawFd);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                close(self.0);
            }
        }
    }
    fn err(context: &str) -> SynScanError {
        let e = io::Error::last_os_error();
        let code = if e.kind() == io::ErrorKind::PermissionDenied {
            SynErrorCode::Permission
        } else {
            SynErrorCode::Io
        };
        SynScanError::new(code, format!("{context}: {e}"))
    }
    fn random_identity() -> Result<(u16, u32, u16), SynScanError> {
        use std::io::Read;
        let mut bytes = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut r| r.read_exact(&mut bytes))
            .map_err(|e| {
                SynScanError::new(
                    SynErrorCode::Io,
                    format!("OS random identity unavailable: {e}"),
                )
            })?;
        let port = 49152 + (u16::from_be_bytes([bytes[0], bytes[1]]) % 16384);
        let seq = u32::from_be_bytes(bytes[2..6].try_into().expect("fixed random array"));
        let id = u16::from_be_bytes([bytes[6], bytes[7]]);
        Ok((port, seq, id))
    }
    fn selected_source(device: &str) -> Result<Ipv4Addr, SynScanError> {
        if device.is_empty()
            || device.len() >= 16
            || !device
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
        {
            return Err(SynScanError::new(
                SynErrorCode::InvalidScope,
                "invalid interface name",
            ));
        }
        let fd = Fd(unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) });
        if fd.0 < 0 {
            return Err(err("read local interface IPv4"));
        }
        let mut request = Ifreq {
            name: [0; 16],
            payload: [0; 24],
        };
        request.name[..device.len()].copy_from_slice(device.as_bytes());
        if unsafe { ioctl(fd.0, SIOCGIFADDR, (&raw mut request).cast()) } < 0 {
            return Err(err("verify selected interface IPv4"));
        }
        let octets: [u8; 4] = request.payload[4..8].try_into().expect("fixed ifreq");
        let address = Ipv4Addr::from(octets);
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            return Err(SynScanError::new(
                SynErrorCode::InvalidScope,
                "interface has no usable IPv4",
            ));
        }
        Ok(address)
    }
    fn bind_interface(fd: c_int, interface: &str) -> Result<(), SynScanError> {
        let mut device = interface.as_bytes().to_vec();
        device.push(0);
        if unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.len() as u32,
            )
        } < 0
        {
            return Err(err("bind raw scan to explicitly selected interface"));
        }
        Ok(())
    }
    fn cancelled(stop: &AtomicBool, scope: &(impl Fn() -> bool + Sync)) -> bool {
        stop.load(Ordering::Acquire) || !scope()
    }

    pub(super) fn scan(
        interface_name: &str,
        hosts: &[Ipv4Addr],
        ports: &[u16],
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
        progress: &(impl Fn(usize, usize) + Sync),
    ) -> Result<Vec<SynFinding>, SynScanError> {
        let interfaces = discover_interfaces()
            .map_err(|e| SynScanError::new(SynErrorCode::Device, e.message))?;
        let selected = select_interface(&interfaces, interface_name)
            .map_err(|e| SynScanError::new(SynErrorCode::Device, e.message))?;
        let local = selected_source(&selected.name)?;
        let send_fd = Fd(unsafe { socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW) });
        if send_fd.0 < 0 {
            return Err(err("open native raw IPv4 SYN transmitter"));
        }
        bind_interface(send_fd.0, &selected.name)?;
        let protocol = ETH_P_IP.to_be();
        let receive_fd =
            Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) });
        if receive_fd.0 < 0 {
            return Err(err("open native Ethernet IPv4 response receiver"));
        }
        let index = c_int::try_from(selected.index)
            .map_err(|_| SynScanError::new(SynErrorCode::Device, "interface index overflow"))?;
        let address = SockAddrLl {
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
                receive_fd.0,
                (&raw const address).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(err("bind raw IPv4 response receiver to selected interface"));
        }
        let total = hosts.len() * ports.len();
        let mut found = Vec::with_capacity(total);
        let mut sent: Option<Instant> = None;
        for &target in hosts {
            for &port in ports {
                if cancelled(stop, scope) {
                    return Err(SynScanError::new(
                        SynErrorCode::Cancelled,
                        "raw TCP scan revoked",
                    ));
                }
                if let Some(last) = sent {
                    while last.elapsed() < SEND_GAP {
                        if cancelled(stop, scope) {
                            return Err(SynScanError::new(
                                SynErrorCode::Cancelled,
                                "raw TCP scan revoked",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                let (local_port, sequence, identification) = random_identity()?;
                let bytes = crate::scan_packets::ipv4_tcp_syn(
                    local,
                    target,
                    local_port,
                    port,
                    sequence,
                    identification,
                    64,
                )
                .map_err(|_| {
                    SynScanError::new(
                        SynErrorCode::InvalidScope,
                        "invalid native TCP SYN source or destination",
                    )
                })?;
                let destination = SockAddrIn {
                    family: AF_INET as u16,
                    port: 0,
                    addr: target.octets(),
                    zero: [0; 8],
                };
                if cancelled(stop, scope) {
                    return Err(SynScanError::new(
                        SynErrorCode::Cancelled,
                        "raw TCP scan revoked",
                    ));
                }
                let started = Instant::now();
                let wrote = unsafe {
                    sendto(
                        send_fd.0,
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        0,
                        (&raw const destination).cast(),
                        std::mem::size_of::<SockAddrIn>() as u32,
                    )
                };
                if wrote != bytes.len() as isize {
                    return Err(err("send bounded native TCP SYN"));
                }
                sent = Some(started);
                let outstanding = ProbeIdentity {
                    local: IpAddr::V4(local),
                    target: IpAddr::V4(target),
                    transport: ProbeTransport::TcpSyn,
                    local_port,
                    target_port: port,
                    syn_sequence: Some(sequence),
                    echo_key: None,
                };
                let mut buffer = [0u8; 4096];
                let mut state = SynState::Inconclusive;
                let mut reason = "syn_no_response";
                while started.elapsed() < RESPONSE_WAIT {
                    if cancelled(stop, scope) {
                        return Err(SynScanError::new(
                            SynErrorCode::Cancelled,
                            "raw TCP scan revoked",
                        ));
                    }
                    let remaining = RESPONSE_WAIT.saturating_sub(started.elapsed());
                    let mut pfd = PollFd {
                        fd: receive_fd.0,
                        events: POLLIN,
                        revents: 0,
                    };
                    let wait = (remaining.as_millis().min(50) as c_int).max(1);
                    let ready = unsafe { poll(&raw mut pfd, 1, wait) };
                    if ready < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(err("poll native SYN responses"));
                    }
                    if ready == 0 || pfd.revents & POLLIN == 0 {
                        continue;
                    }
                    let received =
                        unsafe { recv(receive_fd.0, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
                    if received < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(err("read native SYN response"));
                    }
                    let reply =
                        correlate_ethernet_response(&buffer[..received as usize], &outstanding);
                    match reply {
                        Some(ReplyEvidence::TcpSynAck) => {
                            state = SynState::Open;
                            reason = "syn_ack_matching_sequence";
                            break;
                        }
                        Some(ReplyEvidence::TcpReset) => {
                            state = SynState::Closed;
                            reason = "tcp_rst_matching_sequence";
                            break;
                        }
                        Some(ReplyEvidence::IcmpV4Error { kind: 3, code })
                            if code == 0 || code == 1 =>
                        {
                            state = SynState::Unreachable;
                            reason = "icmp_ipv4_destination_unreachable";
                            break;
                        }
                        Some(ReplyEvidence::IcmpV4Error { kind: 3, .. }) => {
                            state = SynState::Inconclusive;
                            reason = "icmp_ipv4_network_policy";
                            break;
                        }
                        _ => {}
                    }
                }
                if cancelled(stop, scope) {
                    return Err(SynScanError::new(
                        SynErrorCode::Cancelled,
                        "raw TCP scan revoked",
                    ));
                }
                found.push(SynFinding {
                    host: target,
                    port,
                    state,
                    reason,
                    elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                });
                progress(found.len(), total);
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_plan_rejects_oversize_empty_multicast_and_zero_port() {
        let host: Ipv4Addr = "192.0.2.5".parse().unwrap();
        assert!(validate_plan(&[host], &[80]).is_ok());
        assert!(validate_plan(&[], &[80]).is_err());
        assert!(validate_plan(&[host], &[]).is_err());
        assert!(validate_plan(&vec![host; 33], &[80]).is_err());
        assert!(validate_plan(&vec![host; 32], &vec![80; 128]).is_err());
        assert!(validate_plan(&["224.0.0.1".parse().unwrap()], &[80]).is_err());
        assert!(validate_plan(&[host], &[0]).is_err());
    }
    #[test]
    fn revoked_case_never_attempts_native_socket() {
        let stopped = AtomicBool::new(true);
        let err = scan_ipv4_syn(
            "no-device",
            &["192.0.2.5".parse().unwrap()],
            &[80],
            &stopped,
            &|| true,
            &|_, _| {},
        )
        .unwrap_err();
        assert_eq!(err.code, SynErrorCode::Cancelled);
    }
}

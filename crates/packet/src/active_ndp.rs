//! Native Linux IPv6 link-local Neighbor Discovery; no external tools.
//! The sending application must enforce saved-case authority, native operator
//! consent and interface ownership. This module performs only bounded
//! solicited-node Neighbor Solicitation on one explicitly chosen Ethernet NIC.
use crate::scan_replies::{
    correlate_ethernet_response, ProbeIdentity, ProbeTransport, ReplyEvidence,
};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MAX_NDP_TARGETS: usize = 16;
const RESPONSE_WAIT: Duration = Duration::from_millis(600);
const MIN_GAP: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpNeighbor {
    pub address: Ipv6Addr,
    pub mac: [u8; 6],
    pub elapsed_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpErrorCode {
    Unsupported,
    InvalidScope,
    Permission,
    Device,
    Io,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpError {
    pub code: NdpErrorCode,
    pub message: String,
}
impl NdpError {
    fn new(code: NdpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
fn validate_targets(targets: &[Ipv6Addr]) -> Result<(), NdpError> {
    if targets.is_empty() || targets.len() > MAX_NDP_TARGETS {
        return Err(NdpError::new(
            NdpErrorCode::InvalidScope,
            "IPv6 Neighbor Discovery requires 1..=16 link-local IPv6 targets",
        ));
    }
    if targets
        .iter()
        .any(|address| !address.is_unicast_link_local())
    {
        return Err(NdpError::new(
            NdpErrorCode::InvalidScope,
            "Neighbor Discovery is limited to unicast link-local IPv6 targets on the selected NIC",
        ));
    }
    Ok(())
}

pub fn discover_ndp(
    interface_name: &str,
    targets: &[Ipv6Addr],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
) -> Result<Vec<NdpNeighbor>, NdpError> {
    validate_targets(targets)?;
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(NdpError::new(
            NdpErrorCode::Cancelled,
            "IPv6 neighbor scope revoked",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::discover(interface_name, targets, stop, scope_active)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface_name, stop, scope_active);
        Err(NdpError::new(
            NdpErrorCode::Unsupported,
            "native IPv6 Neighbor Discovery requires Linux CAP_NET_RAW",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::live::{discover_interfaces, select_interface};
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::path::Path;

    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_IPV6: u16 = 0x86dd;
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
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }
    unsafe extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, addr: *const c_void, length: u32) -> c_int;
        fn send(fd: c_int, buf: *const c_void, length: usize, flags: c_int) -> isize;
        fn recv(fd: c_int, buf: *mut c_void, length: usize, flags: c_int) -> isize;
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
    fn io_err(context: &str) -> NdpError {
        let e = io::Error::last_os_error();
        let code = if e.kind() == io::ErrorKind::PermissionDenied {
            NdpErrorCode::Permission
        } else {
            NdpErrorCode::Io
        };
        NdpError::new(code, format!("{context}: {e}"))
    }
    fn selected_mac(name: &str) -> Result<[u8; 6], NdpError> {
        if name.is_empty() || name.len() >= 16 || name.contains('/') || name.contains('\\') {
            return Err(NdpError::new(
                NdpErrorCode::InvalidScope,
                "invalid interface name",
            ));
        }
        let path = Path::new("/sys/class/net").join(name).join("address");
        let content = std::fs::read_to_string(path).map_err(|e| {
            NdpError::new(
                NdpErrorCode::Device,
                format!("selected NIC MAC unavailable: {e}"),
            )
        })?;
        let components: Vec<_> = content.trim().split(':').collect();
        if components.len() != 6 {
            return Err(NdpError::new(
                NdpErrorCode::Device,
                "malformed selected NIC MAC",
            ));
        }
        let mut mac = [0u8; 6];
        for (b, part) in mac.iter_mut().zip(components) {
            *b = u8::from_str_radix(part, 16)
                .map_err(|_| NdpError::new(NdpErrorCode::Device, "invalid selected NIC MAC"))?;
        }
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(NdpError::new(
                NdpErrorCode::Device,
                "selected NIC MAC must be unicast",
            ));
        }
        Ok(mac)
    }
    /// Linux proc interface metadata: address[32 hex] ifindex[hex]
    /// prefixlen[hex] scope[hex] flags[hex] ifname. Reject foreign interfaces.
    fn selected_link_local(name: &str, index: u32) -> Result<Ipv6Addr, NdpError> {
        let text = std::fs::read_to_string("/proc/net/if_inet6").map_err(|e| {
            NdpError::new(
                NdpErrorCode::Device,
                format!("IPv6 interface metadata unavailable: {e}"),
            )
        })?;
        for row in text.lines().take(4096) {
            let cols: Vec<_> = row.split_whitespace().collect();
            if cols.len() != 6 || cols[5] != name || cols[0].len() != 32 {
                continue;
            }
            if u32::from_str_radix(cols[1], 16).ok() != Some(index) || cols[3] != "20" {
                continue;
            }
            let mut bytes = [0u8; 16];
            let mut valid = true;
            for (i, slot) in bytes.iter_mut().enumerate() {
                match u8::from_str_radix(&cols[0][i * 2..i * 2 + 2], 16) {
                    Ok(b) => *slot = b,
                    Err(_) => {
                        valid = false;
                        break;
                    }
                }
            }
            let candidate = Ipv6Addr::from(bytes);
            if valid && candidate.is_unicast_link_local() {
                return Ok(candidate);
            }
        }
        Err(NdpError::new(
            NdpErrorCode::InvalidScope,
            "selected NIC has no kernel-configured IPv6 link-local source address",
        ))
    }
    fn cancelled(stop: &AtomicBool, scope: &(impl Fn() -> bool + Sync)) -> bool {
        stop.load(Ordering::Acquire) || !scope()
    }
    pub(super) fn discover(
        interface_name: &str,
        targets: &[Ipv6Addr],
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
    ) -> Result<Vec<NdpNeighbor>, NdpError> {
        let interfaces =
            discover_interfaces().map_err(|e| NdpError::new(NdpErrorCode::Device, e.message))?;
        let selected = select_interface(&interfaces, interface_name)
            .map_err(|e| NdpError::new(NdpErrorCode::Device, e.message))?;
        let mac = selected_mac(&selected.name)?;
        let source = selected_link_local(&selected.name, selected.index)?;
        if targets.contains(&source) {
            return Err(NdpError::new(
                NdpErrorCode::InvalidScope,
                "self-target IPv6 Neighbor Discovery is disallowed",
            ));
        }
        let protocol = ETH_P_IPV6.to_be();
        let fd = Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) });
        if fd.0 < 0 {
            return Err(io_err("open selected IPv6 AF_PACKET interface"));
        }
        let index = c_int::try_from(selected.index)
            .map_err(|_| NdpError::new(NdpErrorCode::Device, "NIC index overflow"))?;
        let sock_addr = SockAddrLl {
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
                fd.0,
                (&raw const sock_addr).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(io_err("bind selected IPv6 Ethernet interface"));
        }
        let mut results = Vec::new();
        let mut last: Option<Instant> = None;
        for &target in targets {
            if cancelled(stop, scope) {
                return Err(NdpError::new(NdpErrorCode::Cancelled, "NDP scan revoked"));
            }
            if let Some(previous) = last {
                while previous.elapsed() < MIN_GAP {
                    if cancelled(stop, scope) {
                        return Err(NdpError::new(NdpErrorCode::Cancelled, "NDP scan revoked"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let packet =
                crate::scan_packets::ethernet_ipv6_neighbor_solicitation(mac, source, target)
                    .map_err(|_| {
                        NdpError::new(
                            NdpErrorCode::InvalidScope,
                            "invalid source or target for NDP",
                        )
                    })?;
            if cancelled(stop, scope) {
                return Err(NdpError::new(NdpErrorCode::Cancelled, "NDP scan revoked"));
            }
            let started = Instant::now();
            if unsafe { send(fd.0, packet.as_ptr().cast(), packet.len(), 0) }
                != packet.len() as isize
            {
                return Err(io_err("send bounded IPv6 Neighbor Solicitation"));
            }
            last = Some(started);
            let identity = ProbeIdentity {
                local: IpAddr::V6(source),
                target: IpAddr::V6(target),
                transport: ProbeTransport::NeighborDiscovery,
                local_port: 0,
                target_port: 0,
                syn_sequence: None,
                echo_key: None,
            };
            let mut frame = [0u8; 2048];
            while started.elapsed() < RESPONSE_WAIT {
                if cancelled(stop, scope) {
                    return Err(NdpError::new(NdpErrorCode::Cancelled, "NDP scan revoked"));
                }
                let remaining = RESPONSE_WAIT.saturating_sub(started.elapsed());
                let mut pfd = PollFd {
                    fd: fd.0,
                    events: POLLIN,
                    revents: 0,
                };
                let ready = unsafe {
                    poll(
                        &raw mut pfd,
                        1,
                        remaining.as_millis().min(50).max(1) as c_int,
                    )
                };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("poll IPv6 Neighbor Advertisement"));
                }
                if ready == 0 || pfd.revents & POLLIN == 0 {
                    continue;
                }
                let n = unsafe { recv(fd.0, frame.as_mut_ptr().cast(), frame.len(), 0) };
                if n < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("read IPv6 Neighbor Advertisement"));
                }
                if let Some(ReplyEvidence::NeighborAdvertisement { hardware_address }) =
                    correlate_ethernet_response(&frame[..n as usize], &identity)
                {
                    results.push(NdpNeighbor {
                        address: target,
                        mac: hardware_address,
                        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    });
                    break;
                }
            }
        }
        if cancelled(stop, scope) {
            return Err(NdpError::new(NdpErrorCode::Cancelled, "NDP scan revoked"));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ndp_plan_accepts_only_bounded_link_local_unicast() {
        let link: Ipv6Addr = "fe80::42".parse().unwrap();
        assert!(validate_targets(&[link]).is_ok());
        assert!(validate_targets(&[]).is_err());
        assert!(validate_targets(&vec![link; 17]).is_err());
        assert!(validate_targets(&["2001:db8::1".parse().unwrap()]).is_err());
        assert!(validate_targets(&["ff02::1".parse().unwrap()]).is_err());
        assert!(validate_targets(&[Ipv6Addr::UNSPECIFIED]).is_err());
    }
    #[test]
    fn cancelled_ndp_returns_before_opening_raw_socket() {
        let stopped = AtomicBool::new(true);
        let err =
            discover_ndp("lo", &["fe80::42".parse().unwrap()], &stopped, &|| true).unwrap_err();
        assert_eq!(err.code, NdpErrorCode::Cancelled);
    }
}

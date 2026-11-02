//! Explicitly authorized Linux on-link ARP discovery. Never prompts for or
//! impersonates a source MAC/IP: both are read from the selected kernel
//! interface. Does not modify interface flags or enable promiscuous capture.
//! The embedding application MUST bind scope checks to its backend case ID
//! and obtain human approval before calling this entry point.
use crate::scan_replies::{
    correlate_ethernet_response, ProbeIdentity, ProbeTransport, ReplyEvidence,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const MAX_ARP_TARGETS: usize = 32;
const RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);
const MIN_SEND_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpNeighbor {
    pub address: Ipv4Addr,
    pub mac: [u8; 6],
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpErrorCode {
    Unsupported,
    InvalidScope,
    Permission,
    Device,
    Io,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpDiscoveryError {
    pub code: ArpErrorCode,
    pub message: String,
}
impl ArpDiscoveryError {
    fn new(code: ArpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn valid_on_link_targets(
    local: Ipv4Addr,
    mask: Ipv4Addr,
    targets: &[Ipv4Addr],
) -> Result<(), ArpDiscoveryError> {
    if targets.is_empty() || targets.len() > MAX_ARP_TARGETS {
        return Err(ArpDiscoveryError::new(
            ArpErrorCode::InvalidScope,
            format!("ARP discovery supports 1..={MAX_ARP_TARGETS} targets"),
        ));
    }
    let addr = u32::from(local);
    let network_mask = u32::from(mask);
    if network_mask == 0 || addr & !network_mask == 0 || addr & !network_mask == !network_mask {
        return Err(ArpDiscoveryError::new(
            ArpErrorCode::InvalidScope,
            "selected interface has no usable unicast IPv4 subnet",
        ));
    }
    let subnet = addr & network_mask;
    for &target in targets {
        let address = u32::from(target);
        if target.is_multicast()
            || target.is_unspecified()
            || target.is_broadcast()
            || address == addr
            || address & network_mask != subnet
            || address & !network_mask == 0
            || address & !network_mask == !network_mask
        {
            return Err(ArpDiscoveryError::new(
                ArpErrorCode::InvalidScope,
                format!("ARP target {target} is not a distinct on-link unicast host"),
            ));
        }
    }
    Ok(())
}

pub fn discover_on_link_arp(
    interface_name: &str,
    targets: &[Ipv4Addr],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
) -> Result<Vec<ArpNeighbor>, ArpDiscoveryError> {
    #[cfg(target_os = "linux")]
    {
        linux::discover(interface_name, targets, stop, scope_active)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface_name, targets, stop, scope_active);
        Err(ArpDiscoveryError::new(
            ArpErrorCode::Unsupported,
            "native ARP injection currently requires Linux AF_PACKET and CAP_NET_RAW",
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
    use std::path::Path;

    const AF_PACKET: c_int = 17;
    const AF_INET: c_int = 2;
    const SOCK_RAW: c_int = 3;
    const SOCK_DGRAM: c_int = 2;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_ARP: u16 = 0x0806;
    const POLLIN: i16 = 1;
    const SIOCGIFADDR: c_ulong = 0x8915;
    const SIOCGIFNETMASK: c_ulong = 0x891b;

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

    // Linux ifreq has IFNAMSIZ=16 with 24 bytes for its union on supported
    // 64-bit ABIs. Do not extend this implementation to non-Linux targets.
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        payload: [u8; 24],
    }

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn send(fd: c_int, data: *const c_void, length: usize, flags: c_int) -> isize;
        fn recv(fd: c_int, data: *mut c_void, length: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
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

    fn io_err(context: &str) -> ArpDiscoveryError {
        let err = io::Error::last_os_error();
        let code = if err.kind() == io::ErrorKind::PermissionDenied {
            ArpErrorCode::Permission
        } else {
            ArpErrorCode::Io
        };
        ArpDiscoveryError::new(code, format!("{context}: {err}"))
    }

    fn interface_ipv4(
        fd: c_int,
        name: &str,
        request: c_ulong,
    ) -> Result<Ipv4Addr, ArpDiscoveryError> {
        if name.is_empty() || name.len() >= 16 {
            return Err(ArpDiscoveryError::new(
                ArpErrorCode::InvalidScope,
                "invalid selected network interface name",
            ));
        }
        let mut req = Ifreq {
            name: [0; 16],
            payload: [0; 24],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        if unsafe { ioctl(fd, request, (&raw mut req).cast()) } < 0 {
            return Err(io_err("verify selected interface IPv4 configuration"));
        }
        // Linux sockaddr_in: sa_family(2), sin_port(2), sin_addr(4).
        let addr: [u8; 4] = req.payload[4..8].try_into().expect("fixed-size ifreq");
        Ok(Ipv4Addr::from(addr))
    }
    fn source_mac(name: &str) -> Result<[u8; 6], ArpDiscoveryError> {
        let path = Path::new("/sys/class/net").join(name).join("address");
        let value = std::fs::read_to_string(path).map_err(|e| {
            ArpDiscoveryError::new(ArpErrorCode::Device, format!("read interface MAC: {e}"))
        })?;
        let parts: Vec<_> = value.trim().split(':').collect();
        if parts.len() != 6 {
            return Err(ArpDiscoveryError::new(
                ArpErrorCode::Device,
                "selected interface hardware address invalid",
            ));
        }
        let mut mac = [0; 6];
        for (slot, piece) in mac.iter_mut().zip(parts) {
            *slot = u8::from_str_radix(piece, 16).map_err(|_| {
                ArpDiscoveryError::new(ArpErrorCode::Device, "selected interface MAC malformed")
            })?;
        }
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(ArpDiscoveryError::new(
                ArpErrorCode::Device,
                "selected interface does not have a unicast MAC",
            ));
        }
        Ok(mac)
    }

    pub(super) fn discover(
        interface_name: &str,
        targets: &[Ipv4Addr],
        stop: &AtomicBool,
        scope_active: &(impl Fn() -> bool + Sync),
    ) -> Result<Vec<ArpNeighbor>, ArpDiscoveryError> {
        if stop.load(Ordering::Acquire) || !scope_active() {
            return Err(ArpDiscoveryError::new(
                ArpErrorCode::Cancelled,
                "ARP scope was revoked",
            ));
        }
        let all = discover_interfaces()
            .map_err(|e| ArpDiscoveryError::new(ArpErrorCode::Device, e.message))?;
        let selected = select_interface(&all, interface_name)
            .map_err(|e| ArpDiscoveryError::new(ArpErrorCode::Device, e.message))?;
        let mac = source_mac(&selected.name)?;
        let ip_fd = Fd(unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) });
        if ip_fd.0 < 0 {
            return Err(io_err("open interface address verification socket"));
        }
        let local = interface_ipv4(ip_fd.0, &selected.name, SIOCGIFADDR)?;
        let mask = interface_ipv4(ip_fd.0, &selected.name, SIOCGIFNETMASK)?;
        valid_on_link_targets(local, mask, targets)?;
        let protocol = ETH_P_ARP.to_be();
        let fd = Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) });
        if fd.0 < 0 {
            return Err(io_err("open authorized ARP raw interface"));
        }
        let index = c_int::try_from(selected.index).map_err(|_| {
            ArpDiscoveryError::new(
                ArpErrorCode::Device,
                "network interface index exceeds native range",
            )
        })?;
        let addr = SockAddrLl {
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
                (&raw const addr).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(io_err("bind selected Ethernet interface for ARP"));
        }
        let mut found = Vec::new();
        let mut last_sent: Option<Instant> = None;
        for &target in targets {
            if stop.load(Ordering::Acquire) || !scope_active() {
                return Err(ArpDiscoveryError::new(
                    ArpErrorCode::Cancelled,
                    "ARP scope was revoked",
                ));
            }
            if let Some(last) = last_sent {
                // Rate limit even when a peer replies immediately.
                while last.elapsed() < MIN_SEND_INTERVAL {
                    if stop.load(Ordering::Acquire) || !scope_active() {
                        return Err(ArpDiscoveryError::new(
                            ArpErrorCode::Cancelled,
                            "ARP scope was revoked",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let packet =
                crate::scan_packets::ethernet_arp_request(mac, local, target).map_err(|_| {
                    ArpDiscoveryError::new(ArpErrorCode::InvalidScope, "invalid ARP request")
                })?;
            let started = Instant::now();
            if unsafe { send(fd.0, packet.as_ptr().cast(), packet.len(), 0) }
                != packet.len() as isize
            {
                return Err(io_err("send one ARP request on selected interface"));
            }
            last_sent = Some(started);
            let id = ProbeIdentity {
                local: IpAddr::V4(local),
                target: IpAddr::V4(target),
                transport: ProbeTransport::Arp,
                local_port: 0,
                target_port: 0,
                syn_sequence: None,
                echo_key: None,
            };
            let mut frame = [0u8; 2048];
            while started.elapsed() < RESPONSE_TIMEOUT {
                if stop.load(Ordering::Acquire) || !scope_active() {
                    return Err(ArpDiscoveryError::new(
                        ArpErrorCode::Cancelled,
                        "ARP scope was revoked",
                    ));
                }
                let remaining = RESPONSE_TIMEOUT.saturating_sub(started.elapsed());
                let mut pfd = PollFd {
                    fd: fd.0,
                    events: POLLIN,
                    revents: 0,
                };
                let milliseconds = (remaining.as_millis().min(50) as c_int).max(1);
                let polled = unsafe { poll(&raw mut pfd, 1, milliseconds) };
                if polled < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("receive selected-interface ARP reply"));
                }
                if polled == 0 || pfd.revents & POLLIN == 0 {
                    continue;
                }
                let size = unsafe { recv(fd.0, frame.as_mut_ptr().cast(), frame.len(), 0) };
                if size < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("read ARP frame"));
                }
                if let Some(ReplyEvidence::ArpReply { hardware_address }) =
                    correlate_ethernet_response(&frame[..size as usize], &id)
                {
                    found.push(ArpNeighbor {
                        address: target,
                        mac: hardware_address,
                        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    });
                    break;
                }
            }
        }
        if stop.load(Ordering::Acquire) || !scope_active() {
            return Err(ArpDiscoveryError::new(
                ArpErrorCode::Cancelled,
                "ARP scope was revoked",
            ));
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_network_policy_blocks_offlink_broadcast_and_excessive_scope() {
        let local: Ipv4Addr = "192.0.2.10".parse().unwrap();
        let mask: Ipv4Addr = "255.255.255.0".parse().unwrap();
        assert!(valid_on_link_targets(local, mask, &["192.0.2.11".parse().unwrap()]).is_ok());
        for forbidden in [
            "192.0.3.11",
            "192.0.2.255",
            "192.0.2.0",
            "192.0.2.10",
            "224.0.0.1",
        ] {
            assert!(
                valid_on_link_targets(local, mask, &[forbidden.parse().unwrap()]).is_err(),
                "{forbidden}"
            );
        }
        assert!(valid_on_link_targets(local, mask, &[]).is_err());
        assert!(valid_on_link_targets(local, mask, &vec![local; MAX_ARP_TARGETS + 1]).is_err());
    }
    #[test]
    fn invalid_interface_scope_aborts_without_any_raw_transmission() {
        let stopped = AtomicBool::new(true);
        let result =
            discover_on_link_arp("lo", &["192.0.2.11".parse().unwrap()], &stopped, &|| true);
        assert!(matches!(
            result,
            Err(ArpDiscoveryError {
                code: ArpErrorCode::Cancelled,
                ..
            })
        ));
    }
}

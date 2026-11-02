//! Windows native, read-only adapter discovery through the IP Helper API.
//! Listing a NIC does not imply an Ethernet frame capture driver is installed.
#![cfg(target_os = "windows")]
use crate::live::{CaptureError, CaptureErrorCode, CaptureInterface};
use std::{
    ffi::{c_char, c_void},
    mem, ptr,
};

const AF_UNSPEC: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const MAX_BUFFER: usize = 2 * 1024 * 1024;
const IF_TYPE_ETHERNET: u32 = 6;
const IF_TYPE_WIFI: u32 = 71;
const IF_TYPE_LOOPBACK: u32 = 24;

#[repr(C)]
struct AdapterAddress {
    length: u32,
    if_index: u32,
    next: *const AdapterAddress,
    adapter_name: *const c_char,
    first_unicast: *const c_void,
    first_anycast: *const c_void,
    first_multicast: *const c_void,
    first_dns: *const c_void,
    dns_suffix: *const u16,
    description: *const u16,
    friendly_name: *const u16,
    physical_address: [u8; 8],
    physical_length: u32,
    flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: u32,
}

#[link(name = "Iphlpapi")]
unsafe extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *const c_void,
        addresses: *mut AdapterAddress,
        bytes: *mut u32,
    ) -> u32;
}

fn flags(if_type: u32, status: u32) -> (bool, bool, bool) {
    (
        matches!(if_type, IF_TYPE_ETHERNET | IF_TYPE_WIFI),
        status == 1,
        if_type == IF_TYPE_LOOPBACK,
    )
}

/// A real OS-discovered interface identifier. Does not enable capture by itself.
pub fn discover() -> Result<Vec<CaptureInterface>, CaptureError> {
    let mut size = 16 * 1024usize;
    for _ in 0..5 {
        if size > MAX_BUFFER {
            break;
        }
        let words = size.div_ceil(mem::size_of::<usize>());
        let mut buffer = vec![0usize; words];
        let mut needed = (words * mem::size_of::<usize>()) as u32;
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                0,
                ptr::null(),
                buffer.as_mut_ptr().cast::<AdapterAddress>(),
                &raw mut needed,
            )
        };
        if code == ERROR_BUFFER_OVERFLOW {
            size = (needed as usize).max(size.saturating_mul(2));
            continue;
        }
        if code != 0 {
            return Err(CaptureError {
                code: CaptureErrorCode::Io,
                message: format!("Windows adapter enumeration failed (Win32 {code})"),
            });
        }
        let begin = buffer.as_ptr() as usize;
        let end = begin + words * mem::size_of::<usize>();
        let mut current = buffer.as_ptr().cast::<AdapterAddress>();
        let mut out = Vec::new();
        while !current.is_null() && out.len() < 256 {
            let at = current as usize;
            if at < begin
                || at
                    .checked_add(mem::size_of::<AdapterAddress>())
                    .is_none_or(|next| next > end)
            {
                return Err(CaptureError {
                    code: CaptureErrorCode::Io,
                    message: "Windows adapter API returned invalid record bounds".into(),
                });
            }
            let item = unsafe { &*current };
            if item.length as usize >= mem::size_of::<AdapterAddress>() && item.if_index != 0 {
                let name = format!("win{}", item.if_index);
                let (ethernet, up, loopback) = flags(item.if_type, item.oper_status);
                if name.len() <= 15
                    && !out
                        .iter()
                        .any(|nic: &CaptureInterface| nic.index == item.if_index)
                {
                    out.push(CaptureInterface {
                        name,
                        index: item.if_index,
                        ethernet,
                        up,
                        loopback,
                    });
                }
            }
            current = item.next;
        }
        out.sort_by_key(|nic| nic.index);
        return Ok(out);
    }
    Err(CaptureError {
        code: CaptureErrorCode::Io,
        message: "Windows adapter inventory exceeded bounded memory".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interface_type_state_are_correctly_classified() {
        assert_eq!(flags(IF_TYPE_ETHERNET, 1), (true, true, false));
        assert_eq!(flags(IF_TYPE_WIFI, 1), (true, true, false));
        assert_eq!(flags(IF_TYPE_LOOPBACK, 1), (false, true, true));
        assert_eq!(flags(IF_TYPE_ETHERNET, 2), (true, false, false));
    }
}

#[repr(C)]
struct SocketAddress {
    sockaddr: *const c_void,
    len: i32,
}
#[repr(C)]
struct AdapterUnicast {
    alignment: u64,
    next: *const AdapterUnicast,
    address: SocketAddress,
}
/// Resolve the *actual* Windows IPv4 source assigned to an OS-listed
/// interface. This prevents a scan request naming one NIC while Windows
/// silently originates ICMP traffic from an unrelated adapter.
pub fn selected_ipv4_source(index: u32) -> Result<std::net::Ipv4Addr, CaptureError> {
    if index == 0 {
        return Err(CaptureError {
            code: CaptureErrorCode::InterfaceNotFound,
            message: "zero Windows interface index is not valid".into(),
        });
    }
    const AF_INET: u32 = 2;
    let mut size = 16384usize;
    for _ in 0..5 {
        if size > MAX_BUFFER {
            break;
        }
        let words = size.div_ceil(mem::size_of::<usize>());
        let mut buffer = vec![0usize; words];
        let begin = buffer.as_ptr() as usize;
        let end = begin.saturating_add(words * mem::size_of::<usize>());
        let mut needed = (words * mem::size_of::<usize>()) as u32;
        let code = unsafe {
            GetAdaptersAddresses(
                AF_INET,
                0,
                ptr::null(),
                buffer.as_mut_ptr().cast::<AdapterAddress>(),
                &raw mut needed,
            )
        };
        if code == ERROR_BUFFER_OVERFLOW {
            size = (needed as usize).max(size.saturating_mul(2));
            continue;
        }
        if code != 0 {
            return Err(CaptureError {
                code: CaptureErrorCode::Io,
                message: format!("Windows IPv4 adapter address lookup failed ({code})"),
            });
        }
        let in_range = |pointer: usize, length: usize| {
            pointer >= begin && pointer.checked_add(length).is_some_and(|v| v <= end)
        };
        let mut adapter = buffer.as_ptr().cast::<AdapterAddress>();
        let mut visited = 0;
        while !adapter.is_null() && visited < 256 {
            visited += 1;
            if !in_range(adapter as usize, mem::size_of::<AdapterAddress>()) {
                return Err(CaptureError {
                    code: CaptureErrorCode::Io,
                    message: "Windows adapter address record outside OS-owned result".into(),
                });
            }
            let entry = unsafe { &*adapter };
            if entry.if_index == index {
                let (ethernet, up, loopback) = flags(entry.if_type, entry.oper_status);
                if !ethernet || !up || loopback {
                    return Err(CaptureError {
                        code: CaptureErrorCode::UnsupportedLinkLayer,
                        message: "selected Windows NIC is not an active Ethernet/Wi-Fi interface"
                            .into(),
                    });
                }
                let mut unicast = entry.first_unicast.cast::<AdapterUnicast>();
                let mut examined = 0;
                while !unicast.is_null() && examined < 64 {
                    examined += 1;
                    if !in_range(unicast as usize, mem::size_of::<AdapterUnicast>()) {
                        return Err(CaptureError {
                            code: CaptureErrorCode::Io,
                            message: "Windows unicast record outside OS-owned adapter buffer"
                                .into(),
                        });
                    }
                    let u = unsafe { &*unicast };
                    let address = u.address.sockaddr as usize;
                    // sockaddr_in includes family, port and the 4-byte IPv4 address.
                    if u.address.len >= 16 && in_range(address, 8) {
                        let raw = unsafe { std::slice::from_raw_parts(address as *const u8, 8) };
                        if u16::from_ne_bytes([raw[0], raw[1]]) == 2 {
                            let ip = std::net::Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
                            if !ip.is_unspecified()
                                && !ip.is_multicast()
                                && !ip.is_broadcast()
                                && !ip.is_loopback()
                            {
                                return Ok(ip);
                            }
                        }
                    }
                    unicast = u.next;
                }
                return Err(CaptureError {
                    code: CaptureErrorCode::InterfaceNotFound,
                    message: "selected Windows NIC has no usable configured IPv4 address".into(),
                });
            }
            adapter = entry.next;
        }
        return Err(CaptureError {
            code: CaptureErrorCode::InterfaceNotFound,
            message: "selected Windows interface index was not found".into(),
        });
    }
    Err(CaptureError {
        code: CaptureErrorCode::Io,
        message: "Windows IPv4 interface lookup exceeded bounded OS buffer".into(),
    })
}

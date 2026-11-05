//! macOS BPF (/dev/bpf) live capture backend.
//!
//! Owned by the live-capture slice. Zero-dependency like the rest of the
//! packet crate: `std` only, plus direct `extern "C"` declarations against the
//! system C library that `std` already links on macOS (`ioctl`, `poll`,
//! `getifaddrs`, `freeifaddrs`). Device open/close uses `std::fs::File`, so no
//! raw `open`/`close` declarations are needed. The ioctl sequence and the
//! kernel record layout mirror libpcap's `pcap-bpf.c` behavior (see
//! reference/nmap/libpcap); the Rust implementation here is original.
//!
//! Privileges: BPF device nodes are root-owned, so opening /dev/bpf* requires
//! root or read/write access (e.g. the `access_bpf` group created by the
//! ChmodBPF package). Every permission failure surfaces as
//! `CaptureErrorCode::PermissionDenied` with that explanation instead of a
//! generic I/O error, and interface discovery itself stays unprivileged.
//!
//! Bounds: identical session caps as the Linux AF_PACKET backend (same
//! `CaptureLimits`, 20k packets / 16 MiB / 600 s), enforced by the shared
//! bounded engine in `live::capture_from_with_progress`. No frames are ever
//! sent or injected; the device is opened read-only whenever permitted.
#![cfg(target_os = "macos")]

use crate::live::{
    capture_from_with_progress, select_interface, CaptureError, CaptureErrorCode,
    CaptureInterface, CaptureLimits, CaptureProgress, CaptureResult, FrameSource, ReceivedFrame,
    MAX_FRAME_BYTES,
};
use std::ffi::{c_char, c_int, c_short, c_uint, c_ulong, c_void, CStr};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// --- Darwin constants (mirrored from the macOS SDK; no libc crate) ---------

const AF_LINK: u8 = 18;
const IFT_ETHER: u8 = 0x06;
const IFT_LOOP: u8 = 0x18;
const IFF_UP: c_uint = 0x1;
const IFF_LOOPBACK: c_uint = 0x8;
const DLT_EN10MB: u32 = 1;
const O_CLOEXEC: c_int = 0x0100_0000;
const POLLIN: c_short = 0x1;
const POLLERR: c_short = 0x8;
const POLLHUP: c_short = 0x10;
const POLLNVAL: c_short = 0x20;

/// BPF minors are created contiguously (/dev/bpf0..3 on a stock macOS), so
/// probing stops at the first missing node; the bound keeps a corrupt devfs
/// from walking forever.
const BPF_DEVICE_PROBE_LIMIT: u32 = 64;
/// Requested kernel store buffer. 256 KiB batches many packets per read()
/// (fewer wakeups) while staying well under the kernel's BPF_MAXBUFSIZE and
/// far below the 16 MiB session byte budget.
const BPF_BUFFER_REQUEST: u32 = 256 * 1024;
const BPF_BUFFER_MIN: u32 = 4096;
/// Buffer negotiation must terminate: each attempt halves the request.
const BPF_BUFFER_ATTEMPTS: usize = 12;

// --- ioctl request codes (mirrors sys/ioccom.h; BPF group 'B') --------------

const IOC_VOID: c_ulong = 0x2000_0000;
const IOC_OUT: c_ulong = 0x4000_0000;
const IOC_IN: c_ulong = 0x8000_0000;
const IOCPARM_MASK: c_ulong = 0x1fff;

const fn ioc(inout: c_ulong, group: u8, num: u8, len: usize) -> c_ulong {
    inout | ((len as c_ulong & IOCPARM_MASK) << 16) | ((group as c_ulong) << 8) | num as c_ulong
}
const fn ior<T>(group: u8, num: u8) -> c_ulong {
    ioc(IOC_OUT, group, num, std::mem::size_of::<T>())
}
const fn iow<T>(group: u8, num: u8) -> c_ulong {
    ioc(IOC_IN, group, num, std::mem::size_of::<T>())
}
const fn iowr<T>(group: u8, num: u8) -> c_ulong {
    ioc(IOC_IN | IOC_OUT, group, num, std::mem::size_of::<T>())
}

const BIOCSBLEN: c_ulong = iowr::<u32>(b'B', 102);
const BIOCGBLEN: c_ulong = ior::<u32>(b'B', 102);
const BIOCGDLT: c_ulong = ior::<u32>(b'B', 106);
const BIOCSETIF: c_ulong = iow::<IfReq>(b'B', 108);
const BIOCIMMEDIATE: c_ulong = iow::<u32>(b'B', 112);
const FIONREAD: c_ulong = ior::<c_int>(b'f', 127);

// Darwin errno values, kept local so this backend never needs a libc crate.
const EINVAL: i32 = 22;
const ENXIO: i32 = 6;
const ENOBUFS: i32 = 55;
const EACCES: i32 = 13;
const ENETDOWN: i32 = 50;

/// `struct ifreq` is exactly 32 bytes on darwin (16-byte name + 16-byte
/// union); BIOCSETIF reads only `ifr_name`. The assert pins the layout so a
/// future SDK change fails the build instead of sending a wrong ioctl size.
#[repr(C)]
#[derive(Debug)]
struct IfReq {
    name: [c_char; 16],
    data: [u8; 16],
}
const _: () = assert!(std::mem::size_of::<IfReq>() == 32);

/// Build an `ifr_name` the way the kernel expects: copied bytes, zero filled,
/// always NUL terminated. Names of 16 bytes would lose the terminator, so
/// they are rejected exactly like libpcap rejects them before BIOCSETIF.
fn build_ifreq(interface_name: &str) -> Result<IfReq, CaptureError> {
    if interface_name.len() >= 16 {
        return Err(CaptureError::new(
            CaptureErrorCode::InvalidConfig,
            format!(
                "interface name '{interface_name}' is too long for the kernel ifreq layout"
            ),
        ));
    }
    let mut request = IfReq {
        name: [0; 16],
        data: [0; 16],
    };
    for (slot, byte) in request.name.iter_mut().zip(interface_name.bytes()) {
        *slot = byte as c_char;
    }
    Ok(request)
}

// --- Kernel record layout (LP64 darwin) -------------------------------------
//
// `struct bpf_hdr` on 64-bit macOS uses `BPF_TIMEVAL = timeval32`
// (two i32 fields, see net/bpf.h under __LP64__) and BPF_ALIGNMENT is
// sizeof(int32_t) = 4:
//
//   offset 0  i32 bh_tstamp.tv_sec
//   offset 4  i32 bh_tstamp.tv_usec
//   offset 8  u32 bh_caplen
//   offset 12 u32 bh_datalen
//   offset 16 u16 bh_hdrlen   (18 bytes of fields, kernel reports 20 = padded)
//
// This layout only holds because this backend never issues BIOCSTSTAMP:
// libpcap switches its own descriptors to the wider `bpf_xhdr` (bintime)
// header that way, while the per-descriptor default stays BPF_T_NONE and
// yields the bpf_hdr above. Records are separated by
// BPF_WORDALIGN(hdrlen + caplen) and the final record may be unpadded, so
// parsing must never assume whole alignment units. Field offsets are read
// manually (never via a struct cast) because the read buffer is a byte
// vector with no alignment guarantee and the data is kernel-controlled and
// therefore untrusted; a descriptor whose header layout we do not
// understand fails the invariant checks below and is discarded, never
// misparsed.
const BPF_HDR_MIN: usize = 18;
const BPF_ALIGNMENT: usize = 4;

/// Mirrors the kernel `BPF_WORDALIGN` macro used to space records.
fn bpf_word_align(value: usize) -> usize {
    (value + (BPF_ALIGNMENT - 1)) & !(BPF_ALIGNMENT - 1)
}

/// One defensive parse step over the front of a kernel buffer.
enum Stepped {
    /// A frame copied into the caller's buffer plus the consumed length.
    Frame(ReceivedFrame, usize),
    /// A structurally valid record that must not be surfaced (truncated by a
    /// kernel snaplen or unusable timestamp); skip exactly `advance` bytes.
    Skipped(usize),
    /// The record violates kernel invariants, so the remaining batch cannot
    /// be trusted at any offset and must be discarded whole.
    Untrusted,
}

/// Parse the next BPF record at the front of `kernel` and copy its frame into
/// `out`. Never panics on hostile bytes: every field is validated against the
/// remaining buffer length and against kernel invariants before use, and no
/// field is unwrapped.
fn step_kernel_record(kernel: &[u8], out: &mut [u8]) -> Stepped {
    if kernel.len() < BPF_HDR_MIN {
        // Not even the fixed fields fit; the tail cannot contain a record.
        return Stepped::Untrusted;
    }
    let secs = i32::from_ne_bytes([kernel[0], kernel[1], kernel[2], kernel[3]]);
    let micros = i32::from_ne_bytes([kernel[4], kernel[5], kernel[6], kernel[7]]);
    let caplen = u32::from_ne_bytes([kernel[8], kernel[9], kernel[10], kernel[11]]) as usize;
    let datalen = u32::from_ne_bytes([kernel[12], kernel[13], kernel[14], kernel[15]]);
    let hdrlen = u16::from_ne_bytes([kernel[16], kernel[17]]) as usize;
    // bh_hdrlen covers the (possibly padded) header and is the only reliable
    // data offset; a kernel reporting a shorter or overflowing header has a
    // layout we do not understand.
    if hdrlen < BPF_HDR_MIN || hdrlen > kernel.len() {
        return Stepped::Untrusted;
    }
    let data_len = match hdrlen.checked_add(caplen) {
        Some(len) if len <= kernel.len() => len,
        // Captured bytes claim to extend past the actual read; torn or
        // hostile buffer, so the rest of the batch is meaningless.
        _ => return Stepped::Untrusted,
    };
    // Kernel invariant: the captured portion never exceeds the wire length.
    // A violation means our field offsets are wrong for this kernel.
    if caplen as u64 > u64::from(datalen) {
        return Stepped::Untrusted;
    }
    let advance = bpf_word_align(hdrlen + caplen);
    // BPF timestamps are `timeval32`: whole seconds and microseconds.
    // Pre-epoch or out-of-range stamps would either fail the shared engine's
    // PCAP conversion or fabricate sub-second precision, so skip the record.
    if secs < 0 || !(0..1_000_000).contains(&micros) {
        return Stepped::Skipped(advance);
    }
    // Same honesty rule as the Linux engine's MSG_TRUNC handling: a frame the
    // kernel snaplen truncated is not an original frame and must never be
    // stored with fabricated provenance. macOS BPF captures full frames by
    // default, so this only guards non-default configurations.
    if caplen < datalen as usize {
        return Stepped::Skipped(advance);
    }
    // The shared engine bound; larger frames are dropped, never truncated,
    // because a copy would misrepresent the original bytes.
    if caplen > MAX_FRAME_BYTES || caplen > out.len() {
        return Stepped::Skipped(advance);
    }
    out[..caplen].copy_from_slice(&kernel[hdrlen..data_len]);
    Stepped::Frame(
        ReceivedFrame {
            length: caplen,
            timestamp: UNIX_EPOCH + Duration::new(secs as u64, (micros as u32) * 1000),
        },
        advance,
    )
}

// --- Direct libc declarations (std links the system libc on macOS) ----------

unsafe extern "C" {
    /// Variadic in C, but every call site here passes exactly the pointer
    /// argument; fixed-register ABI is identical for that shape.
    fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
    fn getifaddrs(ifap: *mut *mut IfAddrs) -> c_int;
    fn freeifaddrs(ifa: *mut IfAddrs);
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

// --- Interface discovery (unprivileged, like Linux /sys/class/net) ----------

#[repr(C)]
struct IfAddrs {
    next: *mut IfAddrs,
    name: *const c_char,
    flags: c_uint,
    addr: *const SockAddr,
    netmask: *const SockAddr,
    dstaddr: *const SockAddr,
    data: *mut c_void,
}

/// Darwin `struct sockaddr`: length-prefixed with a one-byte family.
#[repr(C)]
struct SockAddr {
    len: u8,
    family: u8,
    data: [u8; 14],
}

/// Darwin `struct sockaddr_dl` as returned for AF_LINK records.
#[repr(C)]
struct SockAddrDl {
    len: u8,
    family: u8,
    index: u16,
    link_type: u8,
    name_len: u8,
    addr_len: u8,
    selector_len: u8,
    data: [u8; 12],
}
const _: () = assert!(std::mem::size_of::<SockAddrDl>() == 20);

/// Enumerates real macOS interfaces through getifaddrs, mapped to the same
/// strict capture-eligibility shape as the Windows backend: only IFT_ETHER
/// link types count as Ethernet, loopback is excluded by flag or link type,
/// and the kernel interface index must be resolved. Listing never opens a
/// BPF device and therefore never requires privileges.
pub fn discover_interfaces() -> Result<Vec<CaptureInterface>, CaptureError> {
    let mut head: *mut IfAddrs = std::ptr::null_mut();
    if unsafe { getifaddrs(&raw mut head) } != 0 {
        return Err(io_error("enumerate network interfaces", io::Error::last_os_error()));
    }
    // Raw per-name observations merged below; getifaddrs yields several
    // records per interface (AF_LINK, AF_INET, ...) sharing one name.
    struct Observed {
        name: String,
        up: bool,
        loopback: bool,
        link: Option<(u32, u8)>,
    }
    let mut observed: Vec<Observed> = Vec::new();
    let mut cursor = head;
    // Bound the kernel-provided list so a corrupt chain cannot loop forever.
    for _ in 0..1024 {
        if cursor.is_null() {
            break;
        }
        let record = unsafe { &*cursor };
        cursor = record.next;
        let name = if record.name.is_null() {
            continue;
        } else {
            unsafe { CStr::from_ptr(record.name) }
                .to_string_lossy()
                .into_owned()
        };
        if !crate::live::valid_name(&name) {
            continue;
        }
        let up = record.flags & IFF_UP != 0;
        let flag_loopback = record.flags & IFF_LOOPBACK != 0;
        let mut link = None;
        if !record.addr.is_null() {
            // Darwin sockaddr starts with a one-byte length and family.
            let head_bytes = unsafe { std::slice::from_raw_parts(record.addr.cast::<u8>(), 2) };
            if head_bytes[1] == AF_LINK
                && head_bytes[0] as usize >= std::mem::size_of::<SockAddrDl>()
            {
                let dl = unsafe {
                    std::slice::from_raw_parts(record.addr.cast::<u8>(), head_bytes[0] as usize)
                };
                let index = u16::from_ne_bytes([dl[2], dl[3]]) as u32;
                // Index 0 is never a real kernel interface (mirrors Windows).
                if index != 0 {
                    link = Some((index, dl[4]));
                }
            }
        }
        if let Some(entry) = observed.iter_mut().find(|entry| entry.name == name) {
            entry.up |= up;
            entry.loopback |= flag_loopback;
            if entry.link.is_none() {
                entry.link = link;
            }
        } else if observed.len() < 256 {
            observed.push(Observed {
                name,
                up,
                loopback: flag_loopback,
                link,
            });
        }
    }
    unsafe { freeifaddrs(head) };
    let mut interfaces = Vec::new();
    for entry in observed {
        let Some((index, link_type)) = entry.link else {
            continue;
        };
        interfaces.push(CaptureInterface {
            name: entry.name,
            index,
            ethernet: link_type == IFT_ETHER,
            up: entry.up,
            loopback: entry.loopback || link_type == IFT_LOOP,
        });
    }
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

// --- BPF device acquisition and configuration -------------------------------

/// Errors carry honest macOS privilege guidance instead of the Linux
/// capability wording used by the shared helper in live.rs.
fn io_error(context: &str, error: io::Error) -> CaptureError {
    let code = if error.kind() == io::ErrorKind::PermissionDenied {
        CaptureErrorCode::PermissionDenied
    } else {
        CaptureErrorCode::Io
    };
    let message = if code == CaptureErrorCode::PermissionDenied {
        format!(
            "{context}: capture permission denied (macOS BPF requires root privileges or read/write access to /dev/bpf*, e.g. access_bpf membership): {error}"
        )
    } else {
        format!("{context}: {error}")
    };
    CaptureError::new(code, message)
}

fn privileges_error(path: &str, error: io::Error) -> CaptureError {
    CaptureError::new(
        CaptureErrorCode::PermissionDenied,
        format!(
            "open BPF device at {path}: live capture requires BPF access — run with appropriate privileges (root, or read/write access to /dev/bpf* via the access_bpf group): {error}"
        ),
    )
}

/// Opens the first available /dev/bpfN. Read/write is preferred for parity
/// with libpcap, falling back to read-only so group-authorized (access_bpf)
/// users can still capture; this backend never injects frames.
fn open_bpf_device() -> Result<(File, String), CaptureError> {
    let mut denied: Option<io::Error> = None;
    for unit in 0..BPF_DEVICE_PROBE_LIMIT {
        let path = format!("/dev/bpf{unit}");
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    // BPF nodes are contiguous: nothing further can exist.
                    break;
                }
                if error.kind() == io::ErrorKind::PermissionDenied {
                    // Read-only still supports every operation used here
                    // (BIOCSETIF, BIOCIMMEDIATE, reads) on macOS.
                    match OpenOptions::new()
                        .read(true)
                        .custom_flags(O_CLOEXEC)
                        .open(&path)
                    {
                        Ok(file) => return Ok((file, path)),
                        Err(second) => {
                            if denied.is_none() {
                                denied = Some(second);
                            }
                        }
                    }
                }
                // EBUSY (device bound by another process) and any other
                // transient error: keep probing the remaining minors.
            }
        }
    }
    match denied {
        Some(error) => Err(privileges_error("/dev/bpf*", error)),
        None => Err(CaptureError::new(
            CaptureErrorCode::UnsupportedPlatform,
            format!(
                "no BPF capture device is available at /dev/bpf0..{}; macOS BPF live capture is unusable on this system",
                BPF_DEVICE_PROBE_LIMIT - 1
            ),
        )),
    }
}

/// One configured BPF device ready for bounded reads.
struct BpfDevice {
    device: File,
    /// Mirror of the kernel store buffer, sized exactly to the negotiated
    /// BPF buffer length: macOS rejects reads with smaller buffers (EINVAL).
    kernel: Vec<u8>,
    /// Bytes of `kernel` that the last read() populated.
    fill: usize,
    /// Parse cursor into `kernel`; always reaches `fill` before a new read.
    cursor: usize,
}

impl BpfDevice {
    /// Full libpcap-equivalent configuration sequence: probe a device node,
    /// negotiate the buffer size (BIOCSBLEN must precede BIOCSETIF because
    /// binding allocates the buffer), bind to the interface (BIOCSETIF),
    /// verify the data link type (BIOCGDLT) and enable immediate mode
    /// (BIOCIMMEDIATE) so reads return as soon as one packet is buffered
    /// instead of waiting for a full store buffer.
    fn open(interface_name: &str) -> Result<Self, CaptureError> {
        let (device, path) = open_bpf_device()?;
        let fd = device.as_raw_fd();
        let mut request = BPF_BUFFER_REQUEST;
        let mut bound = false;
        for _ in 0..BPF_BUFFER_ATTEMPTS {
            let mut value = request;
            if unsafe { ioctl(fd, BIOCSBLEN, (&raw mut value).cast()) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(EINVAL) && request > BPF_BUFFER_MIN {
                    request /= 2;
                    continue;
                }
                return Err(io_error("set BPF buffer size (BIOCSBLEN)", error));
            }
            // The kernel writes the clamped size back through the same word.
            request = value;
            let mut ifreq = build_ifreq(interface_name)?;
            let bound_rc =
                unsafe { ioctl(fd, BIOCSETIF, (&raw mut ifreq).cast()) };
            if bound_rc == 0 {
                bound = true;
                break;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                // Darwin reports unknown interfaces as ENXIO (libpcap: the
                // BSDs "return ENXIO for unknown devices").
                Some(ENXIO) => {
                    return Err(CaptureError::new(
                        CaptureErrorCode::InterfaceNotFound,
                        format!("interface '{interface_name}' was rejected by BPF (BIOCSETIF): no such device"),
                    ));
                }
                Some(code) if code == EACCES => {
                    return Err(privileges_error(&path, error));
                }
                Some(code) if code == ENETDOWN => {
                    return Err(CaptureError::new(
                        CaptureErrorCode::InvalidConfig,
                        format!("interface '{interface_name}' is reported down by BIOCSETIF"),
                    ));
                }
                // A buffer too large for this kernel is retried halved, the
                // same bounded fallback libpcap applies.
                Some(code) if code == EINVAL || code == ENOBUFS => {
                    if request > BPF_BUFFER_MIN {
                        request /= 2;
                        continue;
                    }
                    return Err(io_error("bind BPF to selected interface (BIOCSETIF)", error));
                }
                _ => {
                    return Err(io_error("bind BPF to selected interface (BIOCSETIF)", error));
                }
            }
        }
        if !bound {
            return Err(CaptureError::new(
                CaptureErrorCode::Io,
                format!(
                    "BPF buffer negotiation failed for '{interface_name}' after {BPF_BUFFER_ATTEMPTS} bounded attempts"
                ),
            ));
        }
        // Read back the size the kernel actually allocated (BIOCGBLEN after
        // BIOCSETIF) exactly like libpcap sizes its read buffer; a read with
        // a smaller buffer is rejected by the kernel.
        let mut buffer_size = 0u32;
        if unsafe { ioctl(fd, BIOCGBLEN, (&raw mut buffer_size).cast()) } != 0 {
            return Err(io_error(
                "read BPF buffer size (BIOCGBLEN)",
                io::Error::last_os_error(),
            ));
        }
        let mut dlt = 0u32;
        if unsafe { ioctl(fd, BIOCGDLT, (&raw mut dlt).cast()) } != 0 {
            return Err(io_error("read BPF data link type (BIOCGDLT)", io::Error::last_os_error()));
        }
        // The shared engine stamps every PCAP record as DLT_EN10MB, so a
        // non-Ethernet link type would silently fabricate false evidence.
        if dlt != DLT_EN10MB {
            return Err(CaptureError::new(
                CaptureErrorCode::UnsupportedLinkLayer,
                format!(
                    "BPF interface '{interface_name}' reports link type {dlt}; only exact DLT_EN10MB Ethernet capture is supported"
                ),
            ));
        }
        let mut immediate = 1u32;
        if unsafe { ioctl(fd, BIOCIMMEDIATE, (&raw mut immediate).cast()) } != 0 {
            return Err(io_error(
                "enable BPF immediate mode (BIOCIMMEDIATE)",
                io::Error::last_os_error(),
            ));
        }
        Ok(Self {
            device,
            kernel: vec![0u8; buffer_size as usize],
            fill: 0,
            cursor: 0,
        })
    }

    /// One poll(+FIONREAD+read) cycle. Mirrors the Linux socket's poll loop;
    /// immediate mode guarantees read() returns a whole batch instead of
    /// blocking for a full store buffer.
    fn read_batch(&mut self, timeout: Duration) -> Result<(), CaptureError> {
        self.fill = 0;
        self.cursor = 0;
        let mut descriptor = PollFd {
            fd: self.device.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.as_millis().max(1).min(c_int::MAX as u128) as c_int;
        let polled = unsafe { poll(&raw mut descriptor, 1, timeout_ms) };
        if polled == 0 {
            return Ok(()); // idle timeout
        }
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(io_error("poll selected BPF capture device", error));
        }
        if descriptor.revents & (POLLERR | POLLHUP | POLLNVAL) != 0 {
            return Err(CaptureError::new(
                CaptureErrorCode::Io,
                "selected BPF capture device reported an error or hung up",
            ));
        }
        if descriptor.revents & POLLIN == 0 {
            return Ok(());
        }
        // FIONREAD guards against spurious readability before committing a
        // read; zero available bytes means nothing is actually buffered.
        let mut available: c_int = 0;
        if unsafe { ioctl(self.device.as_raw_fd(), FIONREAD, (&raw mut available).cast()) } == 0
            && available <= 0
        {
            return Ok(());
        }
        let received = self.device.read(&mut self.kernel);
        match received {
            Ok(0) => Ok(()), // defensive: BPF never returns EOF; treat as idle
            Ok(size) => {
                self.fill = size;
                Ok(())
            }
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                Ok(())
            }
            Err(error) => Err(io_error("read BPF kernel packet buffer", error)),
        }
    }

    /// Surface the next staged frame, if any. A record that fails kernel
    /// invariants discards the remainder of the batch: its successors cannot
    /// be located at trustworthy offsets.
    fn next_staged(&mut self, out: &mut [u8]) -> Option<ReceivedFrame> {
        while self.cursor < self.fill {
            let cursor = self.cursor;
            match step_kernel_record(&self.kernel[cursor..self.fill], out) {
                Stepped::Frame(frame, advance) => {
                    self.cursor = cursor + advance;
                    return Some(frame);
                }
                Stepped::Skipped(advance) => self.cursor = cursor + advance,
                Stepped::Untrusted => {
                    self.cursor = self.fill;
                    return None;
                }
            }
        }
        None
    }
}

impl FrameSource for BpfDevice {
    fn receive(
        &mut self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> Result<Option<ReceivedFrame>, CaptureError> {
        // Drain packets already staged from a previous read before blocking.
        if let Some(frame) = self.next_staged(buffer) {
            return Ok(Some(frame));
        }
        self.read_batch(timeout)?;
        Ok(self.next_staged(buffer))
    }
}

/// Bounded, passive macOS capture through the shared engine. Same contract
/// as `capture_linux_with_progress`: one synchronous run, caller-owned
/// cancellation flag, identical caps and progress events.
pub fn capture_with_progress(
    interface_name: &str,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    limits.validate()?;
    let selected = select_interface(&discover_interfaces()?, interface_name)?;
    let mut device = BpfDevice::open(&selected.name)?;
    capture_from_with_progress(&mut device, selected, limits, cancel, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Well-known darwin ioctl request encodings; pins the const-fn mirror of
    // sys/ioccom.h against accidental group/size changes.
    #[test]
    fn ioctl_request_codes_match_darwin_abi() {
        assert_eq!(BIOCSBLEN, 0xC004_4266);
        assert_eq!(BIOCGBLEN, 0x4004_4266);
        assert_eq!(BIOCGDLT, 0x4004_426A);
        assert_eq!(BIOCSETIF, 0x8020_426C);
        assert_eq!(BIOCIMMEDIATE, 0x8004_4270);
        assert_eq!(FIONREAD, 0x4004_667F);
    }

    #[test]
    fn word_align_matches_kernel_bpf_wordalign() {
        assert_eq!(bpf_word_align(0), 0);
        assert_eq!(bpf_word_align(1), 4);
        assert_eq!(bpf_word_align(4), 4);
        assert_eq!(bpf_word_align(18), 20);
        assert_eq!(bpf_word_align(33), 36);
        assert_eq!(bpf_word_align(34), 36);
        assert_eq!(bpf_word_align(65_536), 65_536);
    }

    #[test]
    fn ifreq_builder_zero_fills_and_rejects_oversize_names() {
        let request = build_ifreq("en0").unwrap();
        let name: Vec<u8> = request.name.iter().map(|b| *b as u8).collect();
        assert_eq!(&name[..4], b"en0\0");
        assert!(name[4..].iter().all(|b| *b == 0));
        assert!(request.data.iter().all(|b| *b == 0));
        assert!(build_ifreq(&"a".repeat(15)).is_ok());
        assert_eq!(
            build_ifreq(&"a".repeat(16)).unwrap_err().code,
            CaptureErrorCode::InvalidConfig
        );
    }

    /// Builds one realistic LP64-darwin kernel record: 18 bytes of fields,
    /// padded header (bh_hdrlen = 20), packet bytes, then word alignment.
    fn push_record(
        kernel: &mut Vec<u8>,
        secs: i32,
        micros: i32,
        caplen: u32,
        datalen: u32,
        hdrlen: u16,
        data: &[u8],
    ) {
        let start = kernel.len();
        kernel.extend_from_slice(&secs.to_ne_bytes());
        kernel.extend_from_slice(&micros.to_ne_bytes());
        kernel.extend_from_slice(&caplen.to_ne_bytes());
        kernel.extend_from_slice(&datalen.to_ne_bytes());
        kernel.extend_from_slice(&hdrlen.to_ne_bytes());
        assert!(hdrlen as usize >= BPF_HDR_MIN);
        kernel.resize(start + hdrlen as usize, 0);
        kernel.extend_from_slice(data);
        let padded = bpf_word_align(hdrlen as usize + caplen as usize);
        kernel.resize(start + padded, 0);
    }

    fn frame(length: usize, fill: u8) -> Vec<u8> {
        vec![fill; length]
    }

    #[test]
    fn parser_yields_aligned_records_with_kernel_padding() {
        let mut kernel = Vec::new();
        let a = frame(14, 0xAA);
        let b = frame(60, 0xBB);
        push_record(&mut kernel, 1_700_000_000, 123_456, 14, 14, 20, &a);
        push_record(&mut kernel, 1_700_000_100, 7, 60, 60, 20, &b);
        let mut out = [0u8; MAX_FRAME_BYTES];
        // First record: header padding puts data at offset 20; record spans
        // align(20 + 14) = 36 bytes including two alignment bytes.
        let Stepped::Frame(first, advance_a) = step_kernel_record(&kernel, &mut out) else {
            panic!("first record must parse");
        };
        assert_eq!(first.length, 14);
        assert_eq!(&out[..14], &a[..]);
        assert_eq!(advance_a, 36);
        assert_eq!(
            first.timestamp,
            UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000)
        );
        // Second record parses from the aligned cursor, not from raw offset.
        let Stepped::Frame(second, advance_b) = step_kernel_record(&kernel[advance_a..], &mut out)
        else {
            panic!("second record must parse");
        };
        assert_eq!(second.length, 60);
        assert_eq!(&out[..60], &b[..]);
        assert_eq!(advance_b, bpf_word_align(20 + 60));
        assert_eq!(advance_a + advance_b, kernel.len());
    }

    #[test]
    fn parser_accepts_final_record_without_trailing_padding() {
        // 20 + 14 = 34 rounds to 36, but the kernel may end the batch at 34.
        let mut kernel = Vec::new();
        let only = frame(14, 0x11);
        push_record(&mut kernel, 1_700_000_000, 0, 14, 14, 20, &only);
        kernel.truncate(34);
        let mut out = [0u8; MAX_FRAME_BYTES];
        let Stepped::Frame(record, advance) = step_kernel_record(&kernel, &mut out) else {
            panic!("unpadded final record must parse");
        };
        assert_eq!(record.length, 14);
        assert_eq!(advance, 36); // advance may exceed the buffer end safely
    }

    #[test]
    fn zero_hdrlen_and_short_hdrlen_records_are_rejected() {
        let mut out = [0u8; MAX_FRAME_BYTES];
        for hdrlen in [0u16, 10, 17] {
            let mut kernel = Vec::new();
            kernel.extend_from_slice(&1_700_000_000i32.to_ne_bytes());
            kernel.extend_from_slice(&0i32.to_ne_bytes());
            kernel.extend_from_slice(&14u32.to_ne_bytes());
            kernel.extend_from_slice(&14u32.to_ne_bytes());
            kernel.extend_from_slice(&hdrlen.to_ne_bytes());
            kernel.extend_from_slice(&frame(64, 0x22));
            assert!(
                matches!(step_kernel_record(&kernel, &mut out), Stepped::Untrusted),
                "hdrlen {hdrlen} must be rejected"
            );
        }
    }

    #[test]
    fn malformed_caplen_discards_the_whole_remaining_batch() {
        let mut out = [0u8; MAX_FRAME_BYTES];
        // caplen claims 200 captured bytes but the buffer ends 10 bytes into
        // the data area: a torn or hostile batch that must poison the rest.
        let mut kernel = Vec::new();
        kernel.extend_from_slice(&1_700_000_000i32.to_ne_bytes());
        kernel.extend_from_slice(&0i32.to_ne_bytes());
        kernel.extend_from_slice(&200u32.to_ne_bytes());
        kernel.extend_from_slice(&200u32.to_ne_bytes());
        kernel.extend_from_slice(&20u16.to_ne_bytes());
        kernel.extend_from_slice(&frame(10, 0x33));
        // A valid record afterwards is unreachable once untrusted; parsing
        // must report Untrusted at the front, never skip ahead blindly.
        push_record(&mut kernel, 1_700_000_001, 0, 14, 14, 20, &frame(14, 0x34));
        assert!(matches!(step_kernel_record(&kernel, &mut out), Stepped::Untrusted));
        // caplen exceeding the wire length breaks a kernel invariant.
        let mut kernel = Vec::new();
        push_record(&mut kernel, 1_700_000_000, 0, 20, 10, 20, &frame(20, 0x35));
        assert!(matches!(step_kernel_record(&kernel, &mut out), Stepped::Untrusted));
        // A short tail cannot contain the fixed fields at all.
        assert!(matches!(step_kernel_record(&kernel[..8], &mut out), Stepped::Untrusted));
    }

    #[test]
    fn oversize_record_is_skipped_without_stalling_the_stream() {
        let mut out = [0u8; MAX_FRAME_BYTES];
        let mut kernel = Vec::new();
        let oversize = MAX_FRAME_BYTES as u32 + 1;
        let big = frame(oversize as usize, 0x44);
        push_record(&mut kernel, 1_700_000_000, 0, oversize, oversize, 20, &big);
        let next_start = kernel.len();
        let follow = frame(14, 0x55);
        push_record(&mut kernel, 1_700_000_001, 5, 14, 14, 20, &follow);
        let Stepped::Skipped(advance) = step_kernel_record(&kernel, &mut out) else {
            panic!("oversize record must be skipped, not surfaced or fatal");
        };
        assert_eq!(advance, bpf_word_align(20 + oversize as usize));
        let Stepped::Frame(record, _) = step_kernel_record(&kernel[advance..], &mut out) else {
            panic!("successor record must still parse");
        };
        assert_eq!(record.length, 14);
        assert_eq!(&out[..14], &follow[..]);
        assert_eq!(next_start, bpf_word_align(20 + oversize as usize));
    }

    #[test]
    fn pre_epoch_and_bogus_timestamps_are_skipped_not_surfaced() {
        let mut out = [0u8; MAX_FRAME_BYTES];
        let data = frame(14, 0x66);
        let mut kernel = Vec::new();
        push_record(&mut kernel, -5, 0, 14, 14, 20, &data);
        assert!(matches!(step_kernel_record(&kernel, &mut out), Stepped::Skipped(_)));
        let mut kernel = Vec::new();
        push_record(&mut kernel, 1_700_000_000, 1_000_000, 14, 14, 20, &data);
        assert!(matches!(step_kernel_record(&kernel, &mut out), Stepped::Skipped(_)));
        let mut kernel = Vec::new();
        push_record(&mut kernel, 1_700_000_000, -1, 14, 14, 20, &data);
        assert!(matches!(step_kernel_record(&kernel, &mut out), Stepped::Skipped(_)));
    }

    #[test]
    fn snaplen_truncated_records_are_dropped_like_linux_msg_trunc() {
        let mut out = [0u8; MAX_FRAME_BYTES];
        let mut kernel = Vec::new();
        push_record(&mut kernel, 1_700_000_000, 0, 20, 1_500, 20, &frame(20, 0x77));
        assert!(matches!(step_kernel_record(&kernel, &mut out), Stepped::Skipped(40)));
    }

    #[test]
    fn unprivileged_discovery_lists_only_kernel_valid_interfaces() {
        let list = discover_interfaces().unwrap();
        assert!(!list.is_empty(), "macOS always exposes kernel interfaces");
        for interface in &list {
            assert!(crate::live::valid_name(&interface.name));
            assert!(interface.index > 0);
            if interface.loopback {
                assert!(!interface.ethernet || !interface.loopback);
            }
        }
        let lo0 = list.iter().find(|entry| entry.name == "lo0");
        if let Some(loopback) = lo0 {
            assert!(loopback.loopback);
            assert!(!loopback.ethernet);
        }
    }
}

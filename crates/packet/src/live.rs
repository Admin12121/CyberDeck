//! N2 Linux-first passive Ethernet capture.
//! Never opens an interface without an explicit selection and caller action.
//! Frames are serialized once into a bounded classic PCAP; original frame spans
//! are tracked in that immutable byte source for later evidence integration.

use crate::{inventory, parse_capture};
use serde::Serialize;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_LIVE_PACKETS: usize = 20_000;
pub const MAX_LIVE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LIVE_DURATION: Duration = Duration::from_secs(600);
pub const MAX_POLL_INTERVAL: Duration = Duration::from_millis(250);
pub const MAX_FRAME_BYTES: usize = 65_535;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureErrorCode {
    UnsupportedPlatform,
    InterfaceNotFound,
    UnsupportedLinkLayer,
    PermissionDenied,
    InvalidConfig,
    Io,
    Parse,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureError {
    pub code: CaptureErrorCode,
    pub message: String,
}

impl CaptureError {
    fn new(code: CaptureErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn io(context: &str, error: io::Error) -> Self {
        let code = if error.kind() == io::ErrorKind::PermissionDenied {
            CaptureErrorCode::PermissionDenied
        } else {
            CaptureErrorCode::Io
        };
        let message = if code == CaptureErrorCode::PermissionDenied {
            format!("{context}: capture permission denied (Linux requires CAP_NET_RAW or equivalent authorization): {error}")
        } else {
            format!("{context}: {error}")
        };
        Self::new(code, message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureInterface {
    pub name: String,
    pub index: u32,
    pub ethernet: bool,
    pub up: bool,
    pub loopback: bool,
}

/// Enumerates native Linux kernel interfaces, not synthetic application profiles.
/// Discovery does not require opening a raw socket and is safe when unprivileged.
#[cfg(target_os = "linux")]
pub fn discover_interfaces() -> Result<Vec<CaptureInterface>, CaptureError> {
    discover_from(std::path::Path::new("/sys/class/net"))
}

#[cfg(not(target_os = "linux"))]
pub fn discover_interfaces() -> Result<Vec<CaptureInterface>, CaptureError> {
    Err(CaptureError::new(
        CaptureErrorCode::UnsupportedPlatform,
        "native live capture is currently supported only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn discover_from(root: &std::path::Path) -> Result<Vec<CaptureInterface>, CaptureError> {
    let entries =
        std::fs::read_dir(root).map_err(|e| CaptureError::io("enumerate network interfaces", e))?;
    let mut interfaces = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| CaptureError::io("read interface directory", e))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !valid_name(&name) {
            continue;
        }
        let root = entry.path();
        let parse = |key: &str| -> Option<String> {
            std::fs::read_to_string(root.join(key))
                .ok()
                .map(|s| s.trim().to_string())
        };
        let Some(index) = parse("ifindex")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|n| *n > 0)
        else {
            continue;
        };
        let kind = parse("type")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let flags = parse("flags")
            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        interfaces.push(CaptureInterface {
            name,
            index,
            ethernet: kind == 1,
            loopback: kind == 772 || flags & 0x8 != 0,
            up: flags & 0x1 != 0,
        });
    }
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b':'))
}

pub fn select_interface(
    interfaces: &[CaptureInterface],
    name: &str,
) -> Result<CaptureInterface, CaptureError> {
    if !valid_name(name) {
        return Err(CaptureError::new(
            CaptureErrorCode::InterfaceNotFound,
            "invalid interface name",
        ));
    }
    let interface = interfaces
        .iter()
        .find(|interface| interface.name == name)
        .ok_or_else(|| {
            CaptureError::new(
                CaptureErrorCode::InterfaceNotFound,
                format!("interface '{name}' is not available"),
            )
        })?;
    if !interface.ethernet || interface.loopback {
        return Err(CaptureError::new(
            CaptureErrorCode::UnsupportedLinkLayer,
            format!("interface '{name}' is not Ethernet: only exact DLT_EN10MB frame capture is supported"),
        ));
    }
    if !interface.up {
        return Err(CaptureError::new(
            CaptureErrorCode::InvalidConfig,
            format!("interface '{name}' is down"),
        ));
    }
    Ok(interface.clone())
}

#[derive(Clone, Debug)]
pub struct CaptureLimits {
    pub max_packets: usize,
    /// Includes 24-byte PCAP header and 16-byte per-frame records.
    pub max_bytes: usize,
    pub duration: Duration,
    pub poll_interval: Duration,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_packets: 4_000,
            max_bytes: 8 * 1024 * 1024,
            duration: Duration::from_secs(60),
            poll_interval: Duration::from_millis(100),
        }
    }
}

impl CaptureLimits {
    pub fn validate(&self) -> Result<(), CaptureError> {
        if self.max_packets == 0
            || self.max_packets > MAX_LIVE_PACKETS
            || self.max_bytes < 40
            || self.max_bytes > MAX_LIVE_BYTES
            || self.duration.is_zero()
            || self.duration > MAX_LIVE_DURATION
            || self.poll_interval.is_zero()
            || self.poll_interval > MAX_POLL_INTERVAL
        {
            return Err(CaptureError::new(CaptureErrorCode::InvalidConfig,
                "capture limits exceed bounds (1..=20000 packets, 40..=16MiB, duration <=600s, poll <=250ms)"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Cancelled,
    PacketLimit,
    ByteLimit,
    DurationLimit,
}

#[derive(Clone, Copy, Debug)]
pub struct ReceivedFrame {
    pub length: usize,
    pub timestamp: SystemTime,
}

pub trait FrameSource {
    /// Return None on an idle timeout. A reported oversize length is discarded.
    fn receive(
        &mut self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> Result<Option<ReceivedFrame>, CaptureError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FrameProvenance {
    pub packet_index: usize,
    pub pcap_frame_offset: usize,
    pub captured_length: usize,
    pub wire_length: usize,
    /// The dissection index is derived from this exact PCAP frame, not synthesized.
    pub source: Option<String>,
    pub destination: Option<String>,
    pub stream_id: Option<String>,
}

#[derive(Debug)]
pub struct CaptureResult {
    pub interface: CaptureInterface,
    /// Original captured Ethernet frame bytes are stored only here, in original order.
    pub pcap_bytes: Vec<u8>,
    pub frame_provenance: Vec<FrameProvenance>,
    pub inventory: inventory::PassiveInventory,
    pub stop_reason: StopReason,
    pub oversized_frames_discarded: usize,
    pub duration_ms: u64,
}

/// Read the identical frame bytes that will be preserved in a future case artifact.
impl CaptureResult {
    pub fn original_frame(&self, index: usize) -> Option<&[u8]> {
        let entry = self.frame_provenance.get(index)?;
        let end = entry.pcap_frame_offset.checked_add(entry.captured_length)?;
        self.pcap_bytes.get(entry.pcap_frame_offset..end)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureProgress {
    pub packets: usize,
    pub stored_pcap_bytes: usize,
    pub oversized_frames_discarded: usize,
}

/// One bounded synchronous capture run; the caller owns its cancellation flag
/// and may invoke this on a worker thread. No frames are sent or injected.
pub fn capture_from<S: FrameSource>(
    source: &mut S,
    interface: CaptureInterface,
    limits: &CaptureLimits,
    stop: &AtomicBool,
) -> Result<CaptureResult, CaptureError> {
    capture_from_with_progress(source, interface, limits, stop, |_| {})
}

/// Identical capture engine with monotonic bounded progress events for a future
/// Tauri Channel. No UI dependency or mandatory long-lived background task.
pub fn capture_from_with_progress<S: FrameSource>(
    source: &mut S,
    interface: CaptureInterface,
    limits: &CaptureLimits,
    stop: &AtomicBool,
    mut on_progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    limits.validate()?;
    if !interface.ethernet || interface.loopback {
        return Err(CaptureError::new(
            CaptureErrorCode::UnsupportedLinkLayer,
            "capture requires an Ethernet device",
        ));
    }
    let start = Instant::now();
    let mut pcap_bytes = Vec::with_capacity(limits.max_bytes.min(64 * 1024));
    pcap_bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap_bytes.extend_from_slice(&2u16.to_le_bytes());
    pcap_bytes.extend_from_slice(&4u16.to_le_bytes());
    pcap_bytes.extend_from_slice(&0i32.to_le_bytes());
    pcap_bytes.extend_from_slice(&0u32.to_le_bytes());
    pcap_bytes.extend_from_slice(&(MAX_FRAME_BYTES as u32).to_le_bytes());
    pcap_bytes.extend_from_slice(&1u32.to_le_bytes()); // exact Ethernet frames (DLT_EN10MB)
    let mut frames = Vec::new();
    let mut oversized = 0usize;
    let mut buffer = [0u8; MAX_FRAME_BYTES];
    let reason = loop {
        if stop.load(Ordering::Acquire) {
            break StopReason::Cancelled;
        }
        if frames.len() >= limits.max_packets {
            break StopReason::PacketLimit;
        }
        if start.elapsed() >= limits.duration {
            break StopReason::DurationLimit;
        }
        let remaining = limits.max_bytes.saturating_sub(pcap_bytes.len());
        if remaining <= 16 {
            break StopReason::ByteLimit;
        }
        let timeout = limits
            .poll_interval
            .min(limits.duration.saturating_sub(start.elapsed()));
        if timeout.is_zero() {
            break StopReason::DurationLimit;
        }
        let received = source.receive(&mut buffer, timeout)?;
        if stop.load(Ordering::Acquire) {
            break StopReason::Cancelled;
        }
        let Some(frame) = received else { continue };
        if frame.length > MAX_FRAME_BYTES {
            oversized = oversized.saturating_add(1);
            continue;
        }
        if frame.length == 0 {
            continue;
        }
        let record_size = 16usize.saturating_add(frame.length);
        if record_size > remaining {
            break StopReason::ByteLimit;
        }
        let since_epoch = frame.timestamp.duration_since(UNIX_EPOCH).map_err(|_| {
            CaptureError::new(
                CaptureErrorCode::Io,
                "capture timestamp predates Unix epoch",
            )
        })?;
        let secs = u32::try_from(since_epoch.as_secs()).map_err(|_| {
            CaptureError::new(
                CaptureErrorCode::Io,
                "capture timestamp exceeds classic PCAP timestamp range",
            )
        })?;
        let offset = pcap_bytes.len().saturating_add(16);
        pcap_bytes.extend_from_slice(&secs.to_le_bytes());
        pcap_bytes.extend_from_slice(&since_epoch.subsec_micros().to_le_bytes());
        pcap_bytes.extend_from_slice(&(frame.length as u32).to_le_bytes());
        pcap_bytes.extend_from_slice(&(frame.length as u32).to_le_bytes());
        pcap_bytes.extend_from_slice(&buffer[..frame.length]);
        frames.push(FrameProvenance {
            packet_index: frames.len(),
            pcap_frame_offset: offset,
            captured_length: frame.length,
            wire_length: frame.length,
            source: None,
            destination: None,
            stream_id: None,
        });
        on_progress(CaptureProgress {
            packets: frames.len(),
            stored_pcap_bytes: pcap_bytes.len(),
            oversized_frames_discarded: oversized,
        });
    };
    let parsed =
        parse_capture(&pcap_bytes).map_err(|e| CaptureError::new(CaptureErrorCode::Parse, e))?;
    if parsed.malformed_tail || parsed.packets.len() != frames.len() {
        return Err(CaptureError::new(
            CaptureErrorCode::Parse,
            "captured PCAP failed exact frame identity validation",
        ));
    }
    for (packet, span) in parsed.packets.iter().zip(&mut frames) {
        if packet.offset != span.pcap_frame_offset || packet.incl_len != span.captured_length {
            return Err(CaptureError::new(
                CaptureErrorCode::Parse,
                "captured packet offset differs from original bytes",
            ));
        }
        if packet.dissected.source.parse::<std::net::IpAddr>().is_ok()
            && packet
                .dissected
                .destination
                .parse::<std::net::IpAddr>()
                .is_ok()
        {
            span.source = Some(packet.dissected.source.clone());
            span.destination = Some(packet.dissected.destination.clone());
        }
        span.stream_id = packet.dissected.stream_id.clone();
    }
    Ok(CaptureResult {
        interface,
        inventory: inventory::observe(&parsed.packets),
        pcap_bytes,
        frame_provenance: frames,
        stop_reason: reason,
        oversized_frames_discarded: oversized,
        duration_ms: start.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

/// Linux AF_PACKET, non-promiscuous Ethernet receive. No shell commands,
/// third-party utilities, implicit privilege escalation or interface changes.
pub fn capture_linux(
    interface_name: &str,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
) -> Result<CaptureResult, CaptureError> {
    capture_linux_with_progress(interface_name, limits, cancel, |_| {})
}

/// Report only bounded counts during the run. The original capture is returned
/// once, after its offsets and inventory have been validated.
#[cfg(target_os = "linux")]
pub fn capture_linux_with_progress(
    interface_name: &str,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    limits.validate()?;
    let selected = select_interface(&discover_interfaces()?, interface_name)?;
    let mut source = linux_socket::LinuxSocket::open(selected.index)?;
    capture_from_with_progress(&mut source, selected, limits, cancel, progress)
}

#[cfg(not(target_os = "linux"))]
pub fn capture_linux_with_progress(
    _interface_name: &str,
    _limits: &CaptureLimits,
    _cancel: &AtomicBool,
    _progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    Err(CaptureError::new(
        CaptureErrorCode::UnsupportedPlatform,
        "native live capture is currently supported only on Linux (Windows Npcap/macOS BPF not implemented)",
    ))
}

#[cfg(target_os = "linux")]
mod linux_socket {
    use super::*;
    use std::ffi::c_void;
    use std::os::raw::{c_int, c_short};

    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_ALL: u16 = 3;
    const POLLIN: c_short = 1;
    const POLLERR: c_short = 8;
    const POLLHUP: c_short = 16;
    const MSG_TRUNC: c_int = 0x20;

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
        events: c_short,
        revents: c_short,
    }

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }

    pub(super) struct LinuxSocket {
        fd: c_int,
    }
    impl Drop for LinuxSocket {
        fn drop(&mut self) {
            unsafe {
                close(self.fd);
            }
        }
    }
    impl LinuxSocket {
        pub(super) fn open(index: u32) -> Result<Self, CaptureError> {
            let protocol = ETH_P_ALL.to_be();
            let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) };
            if fd < 0 {
                return Err(CaptureError::io(
                    "open AF_PACKET raw capture socket",
                    io::Error::last_os_error(),
                ));
            }
            let source = Self { fd };
            let address = SockAddrLl {
                family: AF_PACKET as u16,
                protocol,
                ifindex: c_int::try_from(index).map_err(|_| {
                    CaptureError::new(CaptureErrorCode::InvalidConfig, "interface index overflow")
                })?,
                hatype: 0,
                pkttype: 0,
                halen: 0,
                addr: [0; 8],
            };
            let rc = unsafe {
                bind(
                    fd,
                    (&raw const address).cast(),
                    std::mem::size_of::<SockAddrLl>() as u32,
                )
            };
            if rc != 0 {
                return Err(CaptureError::io(
                    "bind AF_PACKET to selected interface",
                    io::Error::last_os_error(),
                ));
            }
            Ok(source)
        }
    }
    impl FrameSource for LinuxSocket {
        fn receive(
            &mut self,
            buffer: &mut [u8],
            timeout: Duration,
        ) -> Result<Option<ReceivedFrame>, CaptureError> {
            let mut descriptor = PollFd {
                fd: self.fd,
                events: POLLIN,
                revents: 0,
            };
            let timeout_ms = timeout.as_millis().max(1).min(c_int::MAX as u128) as c_int;
            let polled = unsafe { poll(&raw mut descriptor, 1, timeout_ms) };
            if polled == 0 {
                return Ok(None);
            }
            if polled < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(CaptureError::io("poll selected capture interface", e));
            }
            if descriptor.revents & (POLLERR | POLLHUP) != 0 {
                return Err(CaptureError::new(
                    CaptureErrorCode::Io,
                    "selected capture interface closed or reported an error",
                ));
            }
            if descriptor.revents & POLLIN == 0 {
                return Ok(None);
            }
            // MSG_TRUNC returns the full wire length so snaplen truncations
            // are discarded rather than falsely labeled as original frames.
            let size =
                unsafe { recv(self.fd, buffer.as_mut_ptr().cast(), buffer.len(), MSG_TRUNC) };
            if size < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted || e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(CaptureError::io("receive native Ethernet frame", e));
            }
            Ok(Some(ReceivedFrame {
                length: size as usize,
                timestamp: SystemTime::now(),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;

    struct Fixture {
        frames: VecDeque<Vec<u8>>,
        stop_after: Option<usize>,
        received: usize,
        stop_ptr: Option<Arc<AtomicBool>>,
    }
    impl FrameSource for Fixture {
        fn receive(
            &mut self,
            out: &mut [u8],
            _timeout: Duration,
        ) -> Result<Option<ReceivedFrame>, CaptureError> {
            let Some(frame) = self.frames.pop_front() else {
                return Ok(None);
            };
            let n = frame.len();
            let copied = n.min(out.len());
            out[..copied].copy_from_slice(&frame[..copied]);
            self.received += 1;
            if self.stop_after == Some(self.received) {
                if let Some(flag) = self.stop_ptr.as_ref() {
                    flag.store(true, Ordering::Release);
                }
            }
            Ok(Some(ReceivedFrame {
                length: n,
                timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            }))
        }
    }
    fn ethernet_ipv4() -> Vec<u8> {
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 10, 198, 51, 100, 7,
        ]);
        frame
    }
    fn selected() -> CaptureInterface {
        CaptureInterface {
            name: "fixture0".into(),
            index: 2,
            ethernet: true,
            up: true,
            loopback: false,
        }
    }
    fn fixture(frames: Vec<Vec<u8>>) -> Fixture {
        Fixture {
            frames: frames.into(),
            stop_after: None,
            received: 0,
            stop_ptr: None,
        }
    }
    #[test]
    fn captured_frames_roundtrip_from_original_pcap_and_observe_hosts() {
        let frame = ethernet_ipv4();
        let mut src = fixture(vec![frame.clone()]);
        let limits = CaptureLimits {
            max_packets: 1,
            ..Default::default()
        };
        let result = capture_from(&mut src, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.stop_reason, StopReason::PacketLimit);
        assert_eq!(result.frame_provenance.len(), 1);
        assert_eq!(result.frame_provenance[0].pcap_frame_offset, 40);
        assert_eq!(&result.pcap_bytes[40..], frame.as_slice());
        assert_eq!(result.inventory.hosts.len(), 2);
        assert_eq!(result.inventory.packets_scanned, 1);
        assert_eq!(result.inventory.hosts[0].first_packet_index, 0);
    }
    fn ethernet_udp(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());
        bytes.extend_from_slice(&[0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0]);
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        bytes.extend_from_slice(&source_port.to_be_bytes());
        bytes.extend_from_slice(&destination_port.to_be_bytes());
        bytes.extend_from_slice(&8u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    #[test]
    fn bidirectional_udp_flow_links_each_original_frame_to_inventory() {
        let a = ethernet_udp([192, 0, 2, 1], [198, 51, 100, 2], 43210, 53);
        let b = ethernet_udp([198, 51, 100, 2], [192, 0, 2, 1], 53, 43210);
        let mut source = fixture(vec![a.clone(), b.clone()]);
        let limits = CaptureLimits {
            max_packets: 2,
            ..Default::default()
        };
        let mut progress = Vec::new();
        let result = capture_from_with_progress(
            &mut source,
            selected(),
            &limits,
            &AtomicBool::new(false),
            |event| progress.push(event),
        )
        .unwrap();
        assert_eq!(result.inventory.hosts.len(), 2);
        assert_eq!(result.inventory.flows.len(), 1);
        assert_eq!(result.inventory.flows[0].packet_count, 2);
        assert_eq!(result.inventory.flows[0].first_packet_index, 0);
        assert_eq!(result.inventory.flows[0].last_packet_index, 1);
        assert_eq!(result.original_frame(0), Some(a.as_slice()));
        assert_eq!(result.original_frame(1), Some(b.as_slice()));
        assert_eq!(result.original_frame(2), None);
        assert_eq!(
            result.frame_provenance[0].source.as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(
            result.frame_provenance[1].destination.as_deref(),
            Some("192.0.2.1")
        );
        let stream = result.frame_provenance[0].stream_id.as_deref();
        assert!(stream.is_some());
        assert_eq!(stream, result.frame_provenance[1].stream_id.as_deref());
        assert_eq!(progress.len(), 2);
        assert_eq!((progress[0].packets, progress[1].packets), (1, 2));
        assert!(progress[1].stored_pcap_bytes > progress[0].stored_pcap_bytes);
        assert_eq!(progress[1].stored_pcap_bytes, result.pcap_bytes.len());
    }

    #[test]
    fn stop_before_start_does_not_consume_frames() {
        let stop = AtomicBool::new(true);
        let mut src = fixture(vec![ethernet_ipv4()]);
        let result = capture_from(&mut src, selected(), &CaptureLimits::default(), &stop).unwrap();
        assert_eq!(result.stop_reason, StopReason::Cancelled);
        assert_eq!(src.received, 0);
        assert_eq!(result.pcap_bytes.len(), 24);
    }
    #[test]
    fn cancellation_mid_stream_is_terminal_without_promoting_inflight_frame() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut src = fixture(vec![ethernet_ipv4(), ethernet_ipv4()]);
        src.stop_after = Some(1);
        src.stop_ptr = Some(Arc::clone(&stop));
        let result = capture_from(&mut src, selected(), &CaptureLimits::default(), &stop).unwrap();
        assert_eq!(result.stop_reason, StopReason::Cancelled);
        assert!(result.frame_provenance.is_empty());
        assert_eq!(src.received, 1);
    }
    #[test]
    fn byte_budget_never_keeps_half_record_and_reports_limit() {
        let mut src = fixture(vec![ethernet_ipv4()]);
        let limits = CaptureLimits {
            max_bytes: 40,
            ..Default::default()
        };
        let result = capture_from(&mut src, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.stop_reason, StopReason::ByteLimit);
        assert_eq!(result.pcap_bytes.len(), 24);
        assert!(result.frame_provenance.is_empty());
    }
    #[test]
    fn oversized_frame_is_not_misrepresented_as_original_bytes() {
        let mut source = fixture(vec![vec![0u8; MAX_FRAME_BYTES + 1], ethernet_ipv4()]);
        let limits = CaptureLimits {
            max_packets: 1,
            ..Default::default()
        };
        let result =
            capture_from(&mut source, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.oversized_frames_discarded, 1);
        assert_eq!(result.frame_provenance.len(), 1);
        assert_eq!(result.original_frame(0), Some(ethernet_ipv4().as_slice()));
        assert_eq!(result.stop_reason, StopReason::PacketLimit);
    }

    #[test]
    fn cancellation_after_first_stored_frame_retains_only_that_frame() {
        let cancel = AtomicBool::new(false);
        let original = ethernet_ipv4();
        let mut source = fixture(vec![original.clone(), original.clone()]);
        let mut progress_count = 0;
        let result = capture_from_with_progress(
            &mut source,
            selected(),
            &CaptureLimits::default(),
            &cancel,
            |progress| {
                progress_count += 1;
                assert_eq!(progress.packets, 1);
                cancel.store(true, Ordering::Release);
            },
        )
        .unwrap();
        assert_eq!(result.stop_reason, StopReason::Cancelled);
        assert_eq!(progress_count, 1);
        assert_eq!(source.received, 1);
        assert_eq!(result.original_frame(0), Some(original.as_slice()));
        assert_eq!(result.original_frame(1), None);
    }

    #[test]
    fn permission_denied_is_structured_and_explains_linux_capability() {
        let error = CaptureError::io("open AF_PACKET", io::Error::from_raw_os_error(1));
        assert_eq!(error.code, CaptureErrorCode::PermissionDenied);
        assert!(error.message.contains("CAP_NET_RAW"));
    }

    #[test]
    fn idle_capture_stops_at_duration_limit_without_creating_fake_packets() {
        struct Idle;
        impl FrameSource for Idle {
            fn receive(
                &mut self,
                _buf: &mut [u8],
                timeout: Duration,
            ) -> Result<Option<ReceivedFrame>, CaptureError> {
                std::thread::sleep(timeout);
                Ok(None)
            }
        }
        let limits = CaptureLimits {
            duration: Duration::from_millis(3),
            poll_interval: Duration::from_millis(1),
            ..Default::default()
        };
        let result = capture_from(&mut Idle, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.stop_reason, StopReason::DurationLimit);
        assert!(result.frame_provenance.is_empty());
        assert_eq!(result.pcap_bytes.len(), 24);
        assert_eq!(result.inventory.packets_scanned, 0);
    }

    #[test]
    fn strict_limits_reject_bad_config_before_receiving() {
        let mut src = fixture(vec![ethernet_ipv4()]);
        let limits = CaptureLimits {
            max_packets: MAX_LIVE_PACKETS + 1,
            ..Default::default()
        };
        assert_eq!(
            capture_from(&mut src, selected(), &limits, &AtomicBool::new(false))
                .unwrap_err()
                .code,
            CaptureErrorCode::InvalidConfig
        );
        assert_eq!(src.received, 0);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn interface_discovery_and_selection_use_kernel_metadata() {
        let temp = tempfile_directory();
        std::fs::create_dir_all(temp.join("eth-test")).unwrap();
        std::fs::write(temp.join("eth-test/ifindex"), "7\n").unwrap();
        std::fs::write(temp.join("eth-test/type"), "1\n").unwrap();
        std::fs::write(temp.join("eth-test/flags"), "0x1003\n").unwrap();
        std::fs::create_dir_all(temp.join("lo")).unwrap();
        std::fs::write(temp.join("lo/ifindex"), "1\n").unwrap();
        std::fs::write(temp.join("lo/type"), "772\n").unwrap();
        std::fs::write(temp.join("lo/flags"), "0x9\n").unwrap();
        let list = discover_from(&temp).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(select_interface(&list, "eth-test").unwrap().index, 7);
        assert_eq!(
            select_interface(&list, "lo").unwrap_err().code,
            CaptureErrorCode::UnsupportedLinkLayer
        );
        assert_eq!(
            select_interface(&list, "../eth-test").unwrap_err().code,
            CaptureErrorCode::InterfaceNotFound
        );
        std::fs::remove_dir_all(&temp).unwrap();
    }
    #[cfg(target_os = "linux")]
    fn tempfile_directory() -> std::path::PathBuf {
        use std::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "cyberdeck-live-iface-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

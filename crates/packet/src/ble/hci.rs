//! Hand-rolled HCI command/event framing for BLE advertising scans
//! (Bettercap `ble.recon` parity at the capture level).
//!
//! The packet crate is zero-dependency, so everything here is built on raw
//! byte frames and — on Linux — a hand-rolled `AF_BLUETOOTH`/`BTPROTO_HCI`
//! raw socket (the `active_arp` pattern: hand-declared libc externs, RAII
//! fd, poll-paced bounded reads). The command builders and the event
//! parser are platform-independent and pinned against spec fixtures in
//! tests that run anywhere; only the socket door is cfg-Linux, and every
//! constructor off Linux returns the honest `Unsupported` before touching
//! the OS.
//!
//! Framing (Bluetooth Core Spec 5.x Vol 4 Part E):
//! - command frames: `0x01 | opcode(2, LE) | plen(1) | params`;
//!   this slice builds LE Set Scan Parameters (OCF 0x0012) and
//!   LE Set Scan Enable (OCF 0x001A) in the LE Control Commands OGF 0x08;
//! - event frames: `0x04 | event code(1) | plen(1) | params`;
//!   Command Complete (0x0E) carries the status the controller answered
//!   with, and LE Meta events (0x3E) carry advertising reports.
//!
//! Bounds: event reads ≤ [`MAX_EVENT_BYTES`] (64 KiB) with malformed frames
//! refused (callers skip+count), ≤ [`MAX_REPORTS_PER_EVENT`] reports per
//! event, legacy report data ≤ [`MAX_LEGACY_REPORT_DATA`] bytes, commands
//! ≤ [`MAX_COMMAND_FRAME_BYTES`], and the command-complete wait is bounded
//! in both time (2 s) and events (128). Nothing panics on malformed input.
//!
//! Honesty: the raw-HCI door exists only on Linux and requires
//! CAP_NET_ADMIN (typically root); unsupported platforms and permission
//! failures surface as coded errors, never as silent degradation. The scan
//! is passive: LE Set Scan Parameters with the passive scan type, LE Set
//! Scan Enable with duplicate filtering — this module has no connect, no
//! write and no active-probe path by construction.
use super::{BleError, BleErrorCode};

/// Read-bound for one HCI event frame (task bound; larger reads refused).
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
/// Reports per LE Advertising Report event (spec allows at most 0x0F+1; the
/// honest local bound is tighter).
pub const MAX_REPORTS_PER_EVENT: usize = 16;
/// Legacy advertising report data cap (spec: ≤ 31 octets).
pub const MAX_LEGACY_REPORT_DATA: usize = 31;
/// Command frame cap: preamble + opcode + plen + up to 255 parameter bytes.
pub const MAX_COMMAND_FRAME_BYTES: usize = 3 + 255;

pub const HCI_COMMAND_PREAMBLE: u8 = 0x01;
pub const HCI_EVENT_PREAMBLE: u8 = 0x04;

pub const EVENT_COMMAND_COMPLETE: u8 = 0x0E;
pub const EVENT_LE_META: u8 = 0x3E;
pub const LE_META_ADVERTISING_REPORT: u8 = 0x02;
pub const LE_META_EXTENDED_ADVERTISING_REPORT: u8 = 0x07;

/// LE Control Commands OGF.
pub const OGF_LE_CONTROL: u16 = 0x08;
pub const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x0012;
pub const OCF_LE_SET_SCAN_ENABLE: u16 = 0x001A;

/// HCI controller status byte for success.
pub const HCI_STATUS_SUCCESS: u8 = 0x00;

/// Scan type from LE Set Scan Parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeScanType {
    /// 0x00: passive — the controller only listens. This slice uses only
    /// this type; Active (0x01, sends SCAN_REQ probes) is not offered.
    Passive,
}

impl LeScanType {
    pub fn code(self) -> u8 {
        match self {
            LeScanType::Passive => 0x00,
        }
    }
}

/// Parameters for LE Set Scan Parameters (Vol 4 Part E, §7.8.10). All
/// fields are validated against the spec ranges before any frame is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeScanParams {
    pub scan_type: LeScanType,
    /// LE scan interval in 0.625 ms slots (spec: 0x0004..=0xFFFF).
    pub interval_slots: u16,
    /// LE scan window in slots; must be ≤ the interval.
    pub window_slots: u16,
    /// Own address type: 0x00 public, 0x01 random.
    pub own_address_type: u8,
    /// Scanning filter policy: 0x00 accept all, 0x01 whitelist only.
    pub filter_policy: u8,
}

impl LeScanParams {
    /// Spec minimum: 4 slots = 2.5 ms.
    pub const MIN_INTERVAL_SLOTS: u16 = 0x0004;
    /// Spec maximum: 0xFFFF slots ≈ 10.24 s.
    pub const MAX_INTERVAL_SLOTS: u16 = 0xFFFF;

    /// Full-duty passive scan: 10 ms interval, 10 ms window, public own
    /// address, accept all advertisers, duplicate filtering applied by
    /// LE Set Scan Enable.
    pub fn passive_default() -> Self {
        Self {
            scan_type: LeScanType::Passive,
            interval_slots: 0x0010, // 16 slots = 10 ms
            window_slots: 0x0010,   // 10 ms: 100% duty, passive
            own_address_type: 0x00,
            filter_policy: 0x00,
        }
    }

    /// Validate every field against the spec range; every violation states
    /// its reason.
    pub fn validate(&self) -> Result<(), BleError> {
        if self.interval_slots < Self::MIN_INTERVAL_SLOTS
            || self.interval_slots > Self::MAX_INTERVAL_SLOTS
        {
            return Err(BleError::new(
                BleErrorCode::Protocol,
                format!(
                    "scan interval {} slots is outside the spec range {}..={} (2.5 ms..10.24 s)",
                    self.interval_slots,
                    Self::MIN_INTERVAL_SLOTS,
                    Self::MAX_INTERVAL_SLOTS
                ),
            ));
        }
        if self.window_slots < Self::MIN_INTERVAL_SLOTS || self.window_slots > self.interval_slots
        {
            return Err(BleError::new(
                BleErrorCode::Protocol,
                format!(
                    "scan window {} slots is outside the spec range {}..={} (window must not \
                     exceed the {}-slot interval)",
                    self.window_slots,
                    Self::MIN_INTERVAL_SLOTS,
                    self.interval_slots,
                    self.interval_slots
                ),
            ));
        }
        if self.own_address_type > 0x01 {
            return Err(BleError::new(
                BleErrorCode::Protocol,
                format!(
                    "own address type 0x{:02X} is outside the report set (0x00 public / \
                     0x01 random)",
                    self.own_address_type
                ),
            ));
        }
        if self.filter_policy > 0x01 {
            return Err(BleError::new(
                BleErrorCode::Protocol,
                format!(
                    "scanning filter policy 0x{:02X} is outside the report set (0x00 accept \
                     all / 0x01 whitelist)",
                    self.filter_policy
                ),
            ));
        }
        Ok(())
    }
}

/// HCI command opcode: OGF in the upper 6 bits, OCF in the lower 10.
pub fn le_opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | ocf
}

/// Build the exact `LE Set Scan Parameters` command frame:
/// `0x01 | 0x12 0x20 | 0x07 | type | interval(2 LE) | window(2 LE) | own | filter`.
pub fn build_le_set_scan_parameters(params: &LeScanParams) -> Result<[u8; 11], BleError> {
    params.validate()?;
    let opcode = le_opcode(OGF_LE_CONTROL, OCF_LE_SET_SCAN_PARAMETERS).to_le_bytes();
    Ok([
        HCI_COMMAND_PREAMBLE,
        opcode[0],
        opcode[1],
        0x07, // parameter total length
        params.scan_type.code(),
        params.interval_slots.to_le_bytes()[0],
        params.interval_slots.to_le_bytes()[1],
        params.window_slots.to_le_bytes()[0],
        params.window_slots.to_le_bytes()[1],
        params.own_address_type,
        params.filter_policy,
    ])
}

/// Build the exact `LE Set Scan Enable` command frame:
/// `0x01 | 0x1A 0x20 | 0x02 | enable | filter_duplicates`.
pub fn build_le_set_scan_enable(enabled: bool, filter_duplicates: bool) -> [u8; 6] {
    let opcode = le_opcode(OGF_LE_CONTROL, OCF_LE_SET_SCAN_ENABLE).to_le_bytes();
    [
        HCI_COMMAND_PREAMBLE,
        opcode[0],
        opcode[1],
        0x02, // parameter total length
        enabled as u8,
        filter_duplicates as u8,
    ]
}

/// One raw advertising report entry as carried by the LE Advertising
/// Report event (fields exactly as transmitted; semantics live in
/// `super::advertising`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawReport {
    pub event_type: u8,
    pub address_type: u8,
    /// HCI order (LSB first).
    pub address: [u8; 6],
    /// Advertising data as transmitted (legacy reports: ≤ 31 bytes).
    pub data: Vec<u8>,
    /// Signed dBm as transmitted; 0x7F (127) means "unavailable".
    pub rssi: i8,
}

/// The classified subset of HCI events this slice understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HciEvent {
    /// Command Complete (0x0E) for one of this slice's commands.
    CommandComplete { opcode: u16, status: u8 },
    /// LE Advertising Report (LE meta subevent 0x02): the scan payload.
    LeAdvertisingReports(Vec<RawReport>),
    /// LE Extended Advertising Report (subevent 0x07): named-not-decoded —
    /// this slice reports the event honestly without dissecting it.
    LeExtendedAdvertisingReports,
    /// Other LE meta subevents (connection complete, etc.): skipped.
    LeMetaOther { subevent: u8 },
    /// Any other event code: skipped.
    Other { code: u8 },
}

fn protocol(message: impl Into<String>) -> BleError {
    BleError::new(BleErrorCode::Protocol, message)
}

/// Parse one full HCI event frame exactly as read from a raw HCI socket
/// (`0x04 | code | plen | params`). Every structural problem is refused
/// with a stated reason; callers skip+count the refusals.
pub fn parse_hci_event(frame: &[u8]) -> Result<HciEvent, BleError> {
    if frame.len() < 3 {
        return Err(protocol(format!(
            "HCI event frame truncated: {} bytes, need at least the 3-byte header",
            frame.len()
        )));
    }
    if frame[0] != HCI_EVENT_PREAMBLE {
        return Err(protocol(format!(
            "frame preamble 0x{:02X} is not an HCI event (0x{:02X})",
            frame[0], HCI_EVENT_PREAMBLE
        )));
    }
    let param_len = frame[2] as usize;
    let params = &frame[3..];
    if params.len() != param_len {
        return Err(protocol(format!(
            "event parameter length field says {param_len} but {} bytes followed",
            params.len()
        )));
    }
    match frame[1] {
        EVENT_COMMAND_COMPLETE => {
            if params.len() < 4 {
                return Err(protocol(format!(
                    "Command Complete truncated: {} parameter bytes, need at least 4",
                    params.len()
                )));
            }
            Ok(HciEvent::CommandComplete {
                opcode: u16::from_le_bytes([params[1], params[2]]),
                status: params[3],
            })
        }
        EVENT_LE_META => {
            if params.is_empty() {
                return Err(protocol("LE meta event carries no subevent byte"));
            }
            match params[0] {
                LE_META_ADVERTISING_REPORT => {
                    Ok(HciEvent::LeAdvertisingReports(parse_le_advertising_report(
                        params,
                    )?))
                }
                LE_META_EXTENDED_ADVERTISING_REPORT => Ok(HciEvent::LeExtendedAdvertisingReports),
                subevent => Ok(HciEvent::LeMetaOther { subevent }),
            }
        }
        code => Ok(HciEvent::Other { code }),
    }
}

/// Parse the parameters of a LE Advertising Report (subevent 0x02): a
/// subevent byte, a report count, then per report `event_type(1) |
/// addr_type(1) | addr(6) | data_len(1) | data | rssi(1)`. Every bounds
/// violation states the report index and offset it failed at.
pub fn parse_le_advertising_report(params: &[u8]) -> Result<Vec<RawReport>, BleError> {
    if params.len() < 2 {
        return Err(protocol(format!(
            "LE advertising report truncated: {} bytes, need the subevent and report count",
            params.len()
        )));
    }
    if params[0] != LE_META_ADVERTISING_REPORT {
        return Err(protocol(format!(
            "LE meta subevent 0x{:02X} is not the advertising report (0x{:02X})",
            params[0], LE_META_ADVERTISING_REPORT
        )));
    }
    let count = params[1] as usize;
    if count == 0 {
        return Err(protocol("LE advertising report carries zero reports"));
    }
    if count > MAX_REPORTS_PER_EVENT {
        return Err(protocol(format!(
            "LE advertising report carries {count} reports, over the \
             {MAX_REPORTS_PER_EVENT}-report event bound"
        )));
    }
    let mut reports = Vec::with_capacity(count);
    let mut pos = 2usize;
    for index in 0..count {
        // event_type(1) + addr_type(1) + addr(6) + data_len(1)
        if pos + 9 > params.len() {
            return Err(protocol(format!(
                "report #{index} header truncated at offset {pos}"
            )));
        }
        let event_type = params[pos];
        let address_type = params[pos + 1];
        let mut address = [0u8; 6];
        address.copy_from_slice(&params[pos + 2..pos + 8]);
        let data_len = params[pos + 8] as usize;
        if data_len > MAX_LEGACY_REPORT_DATA {
            return Err(protocol(format!(
                "report #{index} carries {data_len} bytes of advertising data, over the \
                 {MAX_LEGACY_REPORT_DATA}-byte legacy report bound"
            )));
        }
        if pos + 9 + data_len + 1 > params.len() {
            return Err(protocol(format!(
                "report #{index} data or RSSI truncated at offset {pos}"
            )));
        }
        let data = params[pos + 9..pos + 9 + data_len].to_vec();
        let rssi = params[pos + 9 + data_len] as i8;
        reports.push(RawReport {
            event_type,
            address_type,
            address,
            data,
            rssi,
        });
        pos += 9 + data_len + 1;
    }
    if pos != params.len() {
        return Err(protocol(format!(
            "LE advertising report carries {} trailing bytes after the last report",
            params.len() - pos
        )));
    }
    Ok(reports)
}

/// Describe a controller status byte for the wire, honestly: known codes
/// name the spec meaning, unknown codes say so instead of guessing.
pub fn controller_status_description(status: u8) -> String {
    let name = match status {
        0x00 => "success",
        0x01 => "unknown HCI command",
        0x02 => "unknown connection identifier",
        0x03 => "hardware failure",
        0x04 => "page timeout",
        0x05 => "authentication failure",
        0x06 => "PIN or key missing",
        0x07 => "memory capacity exceeded",
        0x08 => "connection timeout",
        0x09 => "connection limit exceeded",
        0x0A => "synchronous connection limit exceeded",
        0x0B => "connection already exists",
        0x0C => "command disallowed",
        0x0D => "connection rejected due to limited resources",
        0x0E => "connection rejected due to security reasons",
        0x0F => "connection rejected due to unacceptable BD_ADDR",
        0x10 => "connection accept timeout exceeded",
        0x11 => "unsupported feature or parameter value",
        0x12 => "invalid HCI command parameters",
        0x13 => "remote user terminated connection",
        0x16 => "connection terminated by local host",
        0x22 => "LL response timeout",
        0x2F => "insufficient security",
        _ => return format!("controller status 0x{status:02X} (not in the local status table)"),
    };
    format!("controller status 0x{status:02X} ({name})")
}

/// The raw-HCI socket door. Exists on every platform so callers get the
/// honest `Unsupported` from the constructor off Linux instead of a
/// compile-time dead end; the real body is cfg-Linux.
pub struct HciSocket {
    #[cfg(target_os = "linux")]
    fd: linux::Fd,
}

impl HciSocket {
    /// Open a raw HCI socket bound to the given device index (the classic
    /// `HCI_CHANNEL_RAW` door). Linux-only: requires CAP_NET_ADMIN
    /// (typically root). Every other platform reports `Unsupported`
    /// before any OS call.
    pub fn open(device_index: u16) -> Result<Self, BleError> {
        #[cfg(target_os = "linux")]
        {
            linux::open(device_index)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = device_index;
            Err(BleError::new(
                BleErrorCode::Unsupported,
                "BLE advertising scanning uses the Linux raw-HCI socket door and currently \
                 requires Linux",
            ))
        }
    }

    /// Send LE Set Scan Parameters (passive) and LE Set Scan Enable (with
    /// duplicate filtering), awaiting each Command Complete and refusing on
    /// any nonzero controller status with its spec meaning named.
    #[cfg(target_os = "linux")]
    pub fn configure_le_passive_scan(&self, params: &LeScanParams) -> Result<(), BleError> {
        let frame = build_le_set_scan_parameters(params)?;
        self.send_command(&frame)?;
        let status = self.await_command_complete(le_opcode(
            OGF_LE_CONTROL,
            OCF_LE_SET_SCAN_PARAMETERS,
        ))?;
        if status != HCI_STATUS_SUCCESS {
            return Err(BleError::new(
                BleErrorCode::Device,
                format!(
                    "controller refused LE Set Scan Parameters: {}",
                    controller_status_description(status)
                ),
            ));
        }
        let frame = build_le_set_scan_enable(true, true);
        self.send_command(&frame)?;
        let status = self.await_command_complete(le_opcode(
            OGF_LE_CONTROL,
            OCF_LE_SET_SCAN_ENABLE,
        ))?;
        if status != HCI_STATUS_SUCCESS {
            return Err(BleError::new(
                BleErrorCode::Device,
                format!(
                    "controller refused LE Set Scan Enable: {}",
                    controller_status_description(status)
                ),
            ));
        }
        Ok(())
    }

    /// Best-effort scan disable (LE Set Scan Enable with enable = 0).
    /// Callers drain the result; stopping must never be refused hard.
    #[cfg(target_os = "linux")]
    pub fn disable_le_scan(&self) -> Result<(), BleError> {
        let frame = build_le_set_scan_enable(false, false);
        self.send_command(&frame)?;
        let status = self.await_command_complete(le_opcode(
            OGF_LE_CONTROL,
            OCF_LE_SET_SCAN_ENABLE,
        ))?;
        if status != HCI_STATUS_SUCCESS {
            return Err(BleError::new(
                BleErrorCode::Device,
                format!(
                    "controller refused LE Set Scan Enable (disable): {}",
                    controller_status_description(status)
                ),
            ));
        }
        Ok(())
    }

    /// Send one command frame (bounded, retried on EINTR, partial sends
    /// completed). Linux-only: unreachable off Linux since `open` refuses.
    #[cfg(target_os = "linux")]
    fn send_command(&self, frame: &[u8]) -> Result<(), BleError> {
        if frame.len() < 4 || frame.len() > MAX_COMMAND_FRAME_BYTES {
            return Err(protocol(format!(
                "command frame is {} bytes, outside the bounded {}-byte command range",
                frame.len(),
                MAX_COMMAND_FRAME_BYTES
            )));
        }
        let param_len = frame[3] as usize;
        if param_len != frame.len() - 4 {
            return Err(protocol(format!(
                "command parameter length field says {param_len} but the frame carries {}",
                frame.len() - 4
            )));
        }
        linux::send_all(self.fd.0, frame).map_err(|err| linux::io_err2(&err, "send HCI command"))
    }

    /// One poll-paced bounded read. `Ok(None)` is the idle tick (timeout or
    /// signal), `Ok(Some(frame))` hands over one full event frame, refusals
    /// (oversized buffers, IO errors) are honest errors. Linux-only.
    #[cfg(target_os = "linux")]
    pub fn read_event<'a>(&self, buffer: &'a mut [u8]) -> Result<Option<&'a [u8]>, BleError> {
        if buffer.len() < 3 || buffer.len() > MAX_EVENT_BYTES {
            return Err(protocol(format!(
                "event read buffer is {} bytes, outside the bounded 3..={} range",
                buffer.len(),
                MAX_EVENT_BYTES
            )));
        }
        match linux::read_event(self.fd.0, buffer, linux::READ_POLL_TIMEOUT_MS) {
            Ok(0) => Ok(None),
            Ok(size) => Ok(Some(&buffer[..size])),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                Err(linux::io_err2(&err, "read HCI event"))
            }
        }
    }

    /// Bounded wait for the Command Complete of `opcode`: at most 2 s and
    /// 128 events; unrelated events (including advertising reports already
    /// in flight) are skipped. Returns the controller status byte.
    #[cfg(target_os = "linux")]
    fn await_command_complete(&self, opcode: u16) -> Result<u8, BleError> {
        let started = std::time::Instant::now();
        let mut buffer = vec![0u8; MAX_EVENT_BYTES];
        let mut seen = 0usize;
        loop {
            if seen >= 128 {
                return Err(BleError::new(
                    BleErrorCode::Io,
                    format!(
                        "no Command Complete for opcode 0x{opcode:04X} within 128 events"
                    ),
                ));
            }
            if started.elapsed() > std::time::Duration::from_secs(2) {
                return Err(BleError::new(
                    BleErrorCode::Io,
                    format!(
                        "no Command Complete for opcode 0x{opcode:04X} within the 2 s deadline"
                    ),
                ));
            }
            seen += 1;
            match self.read_event(&mut buffer)? {
                None => continue,
                Some(frame) => match parse_hci_event(frame)? {
                    HciEvent::CommandComplete {
                        opcode: completed,
                        status,
                    } if completed == opcode => return Ok(status),
                    _ => continue,
                },
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::os::fd::RawFd;

    // Hand-rolled constants (zero-dependency crate, the `active_arp` way):
    // AF_BLUETOOTH 31, BTPROTO_HCI 1, SOCK_RAW 3, SOCK_CLOEXEC.
    const AF_BLUETOOTH: c_int = 31;
    const BTPROTO_HCI: c_int = 1;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const POLLIN: i16 = 1;
    /// The classic raw HCI channel (requires CAP_NET_ADMIN).
    const HCI_CHANNEL_RAW: u16 = 0;
    /// Raw errno ENODEV: the bound device index does not exist.
    const ENODEV: i32 = 19;
    /// Poll timeout per read: bounds idle CPU and stop latency (~100 ms).
    pub(super) const READ_POLL_TIMEOUT_MS: c_int = 100;

    #[repr(C)]
    struct SockAddrHci {
        family: u16,
        dev: u16,
        channel: u16,
    }
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn send(fd: c_int, data: *const c_void, length: usize, flags: c_int) -> isize;
        fn recv(fd: c_int, data: *mut c_void, length: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }

    pub(super) struct Fd(pub(super) RawFd);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                close(self.0);
            }
        }
    }

    /// Map an OS error to the honest BLE taxonomy: a missing device index
    /// is `Device`, refusal is `Permission`, everything else `Io`.
    fn io_code(err: &io::Error) -> BleErrorCode {
        if err.raw_os_error() == Some(ENODEV) {
            BleErrorCode::Device
        } else if err.kind() == io::ErrorKind::PermissionDenied {
            BleErrorCode::Permission
        } else {
            BleErrorCode::Io
        }
    }

    pub(super) fn io_err2(err: &io::Error, context: &str) -> BleError {
        let mapped = io_code(err);
        BleError::new(mapped, format!("{context}: {err}"))
    }

    fn io_err(context: &str) -> BleError {
        io_err2(&io::Error::last_os_error(), context)
    }

    pub(super) fn open(device_index: u16) -> Result<HciSocket, BleError> {
        let fd = unsafe { socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI) };
        if fd < 0 {
            return Err(io_err("open raw HCI socket for BLE scanning"));
        }
        let fd = Fd(fd);
        let address = SockAddrHci {
            family: AF_BLUETOOTH as u16,
            dev: device_index,
            channel: HCI_CHANNEL_RAW,
        };
        if unsafe {
            bind(
                fd.0,
                (&raw const address).cast(),
                std::mem::size_of::<SockAddrHci>() as u32,
            )
        } < 0
        {
            let err = io_err(&format!(
                "bind raw HCI socket to device index {device_index} (a missing adapter is \
                 Device; without CAP_NET_ADMIN the refusal is Permission)"
            ));
            return Err(err);
        }
        Ok(HciSocket { fd })
    }

    /// Full bounded send with EINTR retry and partial-send completion.
    pub(super) fn send_all(fd: RawFd, frame: &[u8]) -> io::Result<()> {
        let mut sent = 0usize;
        while sent < frame.len() {
            let n = unsafe {
                send(
                    fd,
                    frame[sent..].as_ptr().cast(),
                    frame.len() - sent,
                    0,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            sent += n as usize;
        }
        Ok(())
    }

    /// One poll-paced read: `Ok(0)` is the no-frame tick (timeout or
    /// signal), `Ok(n)` hands over one full event frame.
    pub(super) fn read_event(
        fd: RawFd,
        buffer: &mut [u8],
        timeout_ms: c_int,
    ) -> io::Result<usize> {
        let mut pfd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        let polled = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if polled < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(err);
        }
        if polled == 0 || pfd.revents & POLLIN == 0 {
            return Ok(0);
        }
        let size = unsafe { recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if size < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(size as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_set_scan_enable_frame_matches_the_spec_layout() {
        // Vol 4 Part E §7.8.18: opcode 0x201A little-endian, plen 2,
        // enable + filter_duplicates.
        assert_eq!(
            build_le_set_scan_enable(true, false),
            [0x01, 0x1A, 0x20, 0x02, 0x01, 0x00]
        );
        assert_eq!(
            build_le_set_scan_enable(false, false),
            [0x01, 0x1A, 0x20, 0x02, 0x00, 0x00]
        );
        assert_eq!(
            build_le_set_scan_enable(true, true),
            [0x01, 0x1A, 0x20, 0x02, 0x01, 0x01]
        );
    }

    #[test]
    fn le_set_scan_parameters_frame_matches_the_spec_layout() {
        // Vol 4 Part E §7.8.10: opcode 0x2012 little-endian, plen 7,
        // passive type, interval/window 0x0010 slots (10 ms), public own
        // address, accept-all policy.
        assert_eq!(
            build_le_set_scan_parameters(&LeScanParams::passive_default()).expect("valid"),
            [
                0x01, 0x12, 0x20, 0x07, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn opcode_encoding_puts_ogf_above_ocf() {
        assert_eq!(le_opcode(OGF_LE_CONTROL, OCF_LE_SET_SCAN_PARAMETERS), 0x2012);
        assert_eq!(le_opcode(OGF_LE_CONTROL, OCF_LE_SET_SCAN_ENABLE), 0x201A);
        let bytes = 0x2012u16.to_le_bytes();
        assert_eq!(bytes, [0x12, 0x20]);
    }

    #[test]
    fn scan_parameter_violations_refuse_with_reasons() {
        let mut params = LeScanParams::passive_default();
        params.interval_slots = 0x0003;
        assert!(build_le_set_scan_parameters(&params)
            .unwrap_err()
            .message
            .contains("scan interval"));
        let mut params = LeScanParams::passive_default();
        params.window_slots = 0x0020; // window > interval (0x0010)
        let err = build_le_set_scan_parameters(&params).unwrap_err();
        assert!(err.message.contains("window"), "{}", err.message);
        let mut params = LeScanParams::passive_default();
        params.own_address_type = 0x02;
        assert!(build_le_set_scan_parameters(&params)
            .unwrap_err()
            .message
            .contains("own address type"));
        let mut params = LeScanParams::passive_default();
        params.filter_policy = 0x02;
        assert!(build_le_set_scan_parameters(&params)
            .unwrap_err()
            .message
            .contains("filter policy"));
    }

    #[test]
    fn command_complete_fixture_parses_to_opcode_and_status() {
        // 0x04 | 0x0E | 0x04 | num(1) | opcode(2 LE) | status(1)
        let frame = [0x04, 0x0E, 0x04, 0x01, 0x12, 0x20, 0x00];
        let event = parse_hci_event(&frame).expect("fixture parses");
        assert_eq!(
            event,
            HciEvent::CommandComplete {
                opcode: 0x2012,
                status: 0x00
            }
        );
    }

    #[test]
    fn le_advertising_report_fixture_parses_two_reports() {
        let mut params = vec![LE_META_ADVERTISING_REPORT, 0x02];
        // Report 1: ADV_IND, random address, 3 data bytes, RSSI -71.
        params.extend_from_slice(&[
            0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x03, 0x02, 0x01, 0x06, 0xB9,
        ]);
        // Report 2: SCAN_RSP, public address, no data, RSSI -60.
        params.extend_from_slice(&[0x04, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0xC4]);
        let mut frame = vec![HCI_EVENT_PREAMBLE, EVENT_LE_META, params.len() as u8];
        frame.extend_from_slice(&params);
        let event = parse_hci_event(&frame).expect("fixture parses");
        match event {
            HciEvent::LeAdvertisingReports(reports) => {
                assert_eq!(reports.len(), 2);
                assert_eq!(reports[0].event_type, 0x00);
                assert_eq!(reports[0].address_type, 0x01);
                assert_eq!(reports[0].address, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
                assert_eq!(reports[0].data, vec![0x02, 0x01, 0x06]);
                assert_eq!(reports[0].rssi, -71);
                assert_eq!(reports[1].event_type, 0x04);
                assert_eq!(reports[1].data, Vec::<u8>::new());
                assert_eq!(reports[1].rssi, -60);
            }
            other => panic!("expected advertising reports, got {other:?}"),
        }
    }

    #[test]
    fn extended_advertising_reports_are_named_not_decoded() {
        let frame = [0x04, 0x3E, 0x01, LE_META_EXTENDED_ADVERTISING_REPORT];
        assert_eq!(
            parse_hci_event(&frame).expect("parses"),
            HciEvent::LeExtendedAdvertisingReports
        );
    }

    #[test]
    fn other_event_codes_and_subevents_pass_through_honestly() {
        assert_eq!(
            parse_hci_event(&[0x04, 0x08, 0x00]).expect("parses"),
            HciEvent::Other { code: 0x08 }
        );
        assert_eq!(
            parse_hci_event(&[0x04, 0x3E, 0x02, 0x01, 0x00]).expect("parses"),
            HciEvent::LeMetaOther { subevent: 0x01 }
        );
    }

    #[test]
    fn malformed_event_frames_refuse_with_reasons() {
        // Wrong preamble.
        let err = parse_hci_event(&[0x02, 0x0E, 0x00]).unwrap_err();
        assert!(err.message.contains("preamble"), "{}", err.message);
        // Truncated header.
        assert!(parse_hci_event(&[0x04, 0x0E]).is_err());
        // plen mismatch.
        let err = parse_hci_event(&[0x04, 0x0E, 0x04, 0x01, 0x12]).unwrap_err();
        assert!(err.message.contains("length field"), "{}", err.message);
        // Empty LE meta.
        assert!(parse_hci_event(&[0x04, 0x3E, 0x00]).is_err());
    }

    #[test]
    fn malformed_advertising_reports_refuse_with_indexed_reasons() {
        let base: Vec<u8> = [
            0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x03, 0x02, 0x01, 0x06, 0xB9,
        ]
        .to_vec();
        let frame = |mut params: Vec<u8>| {
            let mut out = vec![HCI_EVENT_PREAMBLE, EVENT_LE_META, params.len() as u8];
            out.append(&mut params);
            out
        };
        // Zero reports.
        let err = parse_hci_event(&frame(vec![0x02, 0x00])).unwrap_err();
        assert!(err.message.contains("zero reports"), "{}", err.message);
        // Over the report bound.
        let mut params = vec![0x02, (MAX_REPORTS_PER_EVENT + 1) as u8];
        params.extend_from_slice(&base);
        let err = parse_hci_event(&frame(params)).unwrap_err();
        assert!(err.message.contains("report event bound"), "{}", err.message);
        // Report data over the legacy bound.
        let mut over_data = [0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x20].to_vec();
        over_data.extend_from_slice(&[0u8; MAX_LEGACY_REPORT_DATA + 1]);
        over_data.push(0xC8);
        let mut params = vec![0x02, 0x01];
        params.extend_from_slice(&over_data);
        let err = parse_hci_event(&frame(params)).unwrap_err();
        assert!(err.message.contains("legacy report bound"), "{}", err.message);
        // Data + RSSI truncated.
        let mut params = vec![0x02, 0x01];
        params.extend_from_slice(&base[..base.len() - 1]);
        let err = parse_hci_event(&frame(params)).unwrap_err();
        assert!(err.message.contains("truncated"), "{}", err.message);
        // Trailing bytes after the last report.
        let mut params = vec![0x02, 0x01];
        params.extend_from_slice(&base);
        params.push(0x00);
        let err = parse_hci_event(&frame(params)).unwrap_err();
        assert!(err.message.contains("trailing bytes"), "{}", err.message);
    }

    #[test]
    fn controller_status_descriptions_name_the_common_codes_honestly() {
        assert!(controller_status_description(0x00).contains("success"));
        assert!(controller_status_description(0x0C).contains("command disallowed"));
        assert!(controller_status_description(0x12).contains("invalid HCI command parameters"));
        assert!(controller_status_description(0x77).contains("not in the local status table"));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn socket_constructor_reports_unsupported_off_linux() {
        let err = match HciSocket::open(0) {
            Ok(_) => panic!("the socket door must not exist off Linux"),
            Err(err) => err,
        };
        assert_eq!(err.code, BleErrorCode::Unsupported);
        assert!(err.message.contains("Linux"), "{}", err.message);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn event_read_buffer_bounds_are_enforced_before_any_syscall() {
        // Constructing a socket may fail without root; the bound check runs
        // before any read, so probe it through the error of a refused
        // buffer size against an (possibly absent) device.
        let socket = match HciSocket::open(0xFFFF) {
            Ok(socket) => socket,
            Err(_) => return, // no adapter / no privileges on this host
        };
        let mut small = [0u8; 2];
        assert_eq!(
            socket.read_event(&mut small).unwrap_err().code,
            BleErrorCode::Protocol
        );
        let mut big = vec![0u8; MAX_EVENT_BYTES + 1];
        assert_eq!(
            socket.read_event(&mut big).unwrap_err().code,
            BleErrorCode::Protocol
        );
    }
}

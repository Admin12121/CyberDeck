//! Windows native capture client for the CyberDeck-owned kernel capture device.
//! This module does not contain/install a driver. Open fails closed unless a
//! compatible independently implemented, OS-authorized device is present.
//! Device producer must emit complete Ethernet bytes, not IP reconstructions.
#![cfg(target_os = "windows")]
use super::windows_capture_wire::{decode_original_frame, HEADER_LEN, MAX_RECORD_LEN};
use crate::live::{
    self, CaptureError, CaptureErrorCode, CaptureInterface, FrameSource, ReceivedFrame,
    MAX_FRAME_BYTES,
};
use std::{ffi::c_void, ptr, time::Duration};

type Handle = *mut c_void;
const DEVICE: &str = r"\\.\CyberDeckCapture";
const INVALID_HANDLE_VALUE: Handle = (-1isize) as Handle;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const ERROR_IO_PENDING: u32 = 997;
const ERROR_OPERATION_ABORTED: u32 = 995;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const IOCTL_GET_ABI: u32 = 0x222_000;
const IOCTL_SELECT: u32 = 0x222_004;
const ABI_V1: u16 = 1;
const DLT_ETHERNET: u32 = 1;

#[repr(C)]
#[derive(Default)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: Handle,
}

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        attrs: u32,
        template: Handle,
    ) -> Handle;
    fn CreateEventW(
        attrs: *mut c_void,
        manual_reset: i32,
        initial: i32,
        name: *const u16,
    ) -> Handle;
    fn ResetEvent(event: Handle) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn ReadFile(
        handle: Handle,
        buffer: *mut c_void,
        length: u32,
        bytes: *mut u32,
        pending: *mut Overlapped,
    ) -> i32;
    fn DeviceIoControl(
        handle: Handle,
        code: u32,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        bytes: *mut u32,
        pending: *mut Overlapped,
    ) -> i32;
    fn WaitForSingleObject(handle: Handle, timeout: u32) -> u32;
    fn GetOverlappedResult(
        handle: Handle,
        pending: *mut Overlapped,
        bytes: *mut u32,
        wait: i32,
    ) -> i32;
    fn CancelIoEx(handle: Handle, pending: *mut Overlapped) -> i32;
}

#[link(name = "Iphlpapi")]
unsafe extern "system" {
    fn ConvertInterfaceIndexToLuid(index: u32, luid: *mut u64) -> u32;
    fn ConvertInterfaceLuidToAlias(luid: *const u64, alias: *mut u16, length: usize) -> u32;
}

/// Get the real user-visible adapter alias from the Windows IP Helper API.
/// The stable win{index} identifier remains the backend selection key, so
/// display names cannot redirect capture/ICMP to another interface.
pub fn interface_alias(index: u32) -> Option<String> {
    let luid = interface_luid(index).ok()?;
    // IF_MAX_STRING_SIZE is 256 WCHAR; reserve an extra NUL unit.
    let mut alias = [0u16; 257];
    let result = unsafe { ConvertInterfaceLuidToAlias(&luid, alias.as_mut_ptr(), alias.len()) };
    if result != 0 {
        return None;
    }
    let end = alias.iter().position(|unit| *unit == 0)?;
    if end == 0 {
        return None;
    }
    String::from_utf16(&alias[..end]).ok()
}

fn error(context: &str, code: u32) -> CaptureError {
    let kind = match code {
        ERROR_ACCESS_DENIED => CaptureErrorCode::PermissionDenied,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => CaptureErrorCode::UnsupportedPlatform,
        ERROR_DEVICE_NOT_CONNECTED => CaptureErrorCode::InterfaceNotFound,
        _ => CaptureErrorCode::Io,
    };
    let detail = match kind {
        CaptureErrorCode::PermissionDenied => {
            "administrator-authorized capture device access required"
        }
        CaptureErrorCode::UnsupportedPlatform => {
            "CyberDeck-signed native capture component is not installed"
        }
        CaptureErrorCode::InterfaceNotFound => "selected adapter disconnected",
        _ => "Windows kernel capture operation failed",
    };
    CaptureError {
        code: kind,
        message: format!("{context}: {detail} (Win32 {code})"),
    }
}

fn failed(context: &str) -> CaptureError {
    error(context, unsafe { GetLastError() })
}

struct OwnedHandle(Handle);
impl OwnedHandle {
    fn valid(handle: Handle, context: &str) -> Result<Self, CaptureError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(failed(context))
        } else {
            Ok(Self(handle))
        }
    }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub fn interface_luid(index: u32) -> Result<u64, CaptureError> {
    if index == 0 {
        return Err(error(
            "invalid selected adapter",
            ERROR_DEVICE_NOT_CONNECTED,
        ));
    }
    let mut luid = 0u64;
    let result = unsafe { ConvertInterfaceIndexToLuid(index, &raw mut luid) };
    if result != 0 {
        return Err(error("resolve selected Windows interface LUID", result));
    }
    if luid == 0 {
        return Err(error(
            "empty selected adapter identity",
            ERROR_DEVICE_NOT_CONNECTED,
        ));
    }
    Ok(luid)
}

pub struct NativeSource {
    device: OwnedHandle,
    event: OwnedHandle,
    overlapped: Box<Overlapped>,
    buffer: Vec<u8>,
    pending: bool,
    index: u32,
    luid: u64,
}
impl NativeSource {
    fn connect() -> Result<Self, CaptureError> {
        let mut name: Vec<u16> = DEVICE.encode_utf16().collect();
        name.push(0);
        let device = OwnedHandle::valid(
            unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                )
            },
            "open CyberDeck native capture device",
        )?;
        let event = OwnedHandle::valid(
            unsafe { CreateEventW(ptr::null_mut(), 1, 0, ptr::null()) },
            "create capture operation event",
        )?;
        let mut source = Self {
            device,
            event,
            overlapped: Box::new(Overlapped::default()),
            buffer: vec![0; MAX_RECORD_LEN],
            pending: false,
            index: 0,
            luid: 0,
        };
        source.overlapped.event = source.event.0;
        let abi = source.control(IOCTL_GET_ABI, &[], 16)?;
        if abi.len() != 16
            || &abi[..4] != b"CDC1"
            || u16::from_le_bytes(abi[4..6].try_into().unwrap()) != ABI_V1
            || u16::from_le_bytes(abi[6..8].try_into().unwrap()) as usize != HEADER_LEN
            || u32::from_le_bytes(abi[8..12].try_into().unwrap()) != DLT_ETHERNET
            || u32::from_le_bytes(abi[12..16].try_into().unwrap()) != MAX_FRAME_BYTES as u32
        {
            return Err(CaptureError {
                code: CaptureErrorCode::UnsupportedPlatform,
                message:
                    "native driver ABI/linktype does not match exact CyberDeck Ethernet capture"
                        .into(),
            });
        }
        Ok(source)
    }

    fn await_result(&mut self, timeout: u32) -> Result<Option<usize>, CaptureError> {
        let result = unsafe { WaitForSingleObject(self.event.0, timeout) };
        if result == WAIT_TIMEOUT {
            return Ok(None);
        }
        if result != WAIT_OBJECT_0 {
            return Err(failed("wait for native capture operation"));
        }
        let mut bytes = 0u32;
        let ok =
            unsafe { GetOverlappedResult(self.device.0, &mut *self.overlapped, &raw mut bytes, 0) };
        self.pending = false;
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_OPERATION_ABORTED {
                return Ok(None);
            }
            return Err(error("read native capture frame", code));
        }
        Ok(Some(bytes as usize))
    }

    fn control(
        &mut self,
        code: u32,
        request: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, CaptureError> {
        if self.pending {
            return Err(error("capture driver operation already pending", 87));
        }
        self.overlapped.internal = 0;
        self.overlapped.internal_high = 0;
        unsafe {
            ResetEvent(self.event.0);
        }
        let mut response = vec![0; output_size];
        let mut bytes = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                self.device.0,
                code,
                request.as_ptr().cast(),
                request.len() as u32,
                response.as_mut_ptr().cast(),
                output_size as u32,
                &raw mut bytes,
                &mut *self.overlapped,
            )
        };
        if ok == 0 {
            let reason = unsafe { GetLastError() };
            if reason != ERROR_IO_PENDING {
                return Err(error("query/select native capture driver", reason));
            }
            self.pending = true;
            if let Some(received) = self.await_result(1_000)? {
                bytes = received as u32;
            } else {
                unsafe {
                    CancelIoEx(self.device.0, &mut *self.overlapped);
                }
                // Driver must implement cancel-safe IRPs. The owned in/out
                // buffers and OVERLAPPED must remain valid until completion.
                let _ = self.await_result(u32::MAX)?;
                return Err(CaptureError {
                    code: CaptureErrorCode::Io,
                    message: "native capture driver did not answer handshake within 1 second"
                        .into(),
                });
            }
        }
        if bytes as usize > response.len() {
            return Err(CaptureError {
                code: CaptureErrorCode::Io,
                message: "driver returned oversized control response".into(),
            });
        }
        response.truncate(bytes as usize);
        Ok(response)
    }

    pub fn open(selected: &CaptureInterface, expected_luid: u64) -> Result<Self, CaptureError> {
        let luid = interface_luid(selected.index)?;
        if luid != expected_luid || expected_luid == 0 {
            return Err(CaptureError {
                code: CaptureErrorCode::InterfaceNotFound,
                message: "selected Windows adapter changed since operator authorization".into(),
            });
        }
        let mut source = Self::connect()?;
        let mut request = Vec::with_capacity(24);
        request.extend_from_slice(&ABI_V1.to_le_bytes());
        request.extend_from_slice(&0u16.to_le_bytes());
        request.extend_from_slice(&selected.index.to_le_bytes());
        request.extend_from_slice(&luid.to_le_bytes());
        request.extend_from_slice(&(MAX_FRAME_BYTES as u32).to_le_bytes());
        request.extend_from_slice(&0u32.to_le_bytes()); // no promisc/injection
        let accepted = source.control(IOCTL_SELECT, &request, request.len())?;
        if accepted != request {
            return Err(CaptureError {
                code: CaptureErrorCode::InterfaceNotFound,
                message: "driver did not bind to exact selected interface index and LUID".into(),
            });
        }
        source.index = selected.index;
        source.luid = luid;
        Ok(source)
    }
}

impl FrameSource for NativeSource {
    fn receive(
        &mut self,
        output: &mut [u8],
        timeout: Duration,
    ) -> Result<Option<ReceivedFrame>, CaptureError> {
        if !self.pending {
            self.overlapped.internal = 0;
            self.overlapped.internal_high = 0;
            unsafe {
                ResetEvent(self.event.0);
            }
            let mut received = 0u32;
            let ok = unsafe {
                ReadFile(
                    self.device.0,
                    self.buffer.as_mut_ptr().cast(),
                    self.buffer.len() as u32,
                    &raw mut received,
                    &mut *self.overlapped,
                )
            };
            if ok != 0 {
                return self.copy_frame(received as usize, output);
            }
            let code = unsafe { GetLastError() };
            if code != ERROR_IO_PENDING {
                return Err(error("receive exact Ethernet frame", code));
            }
            self.pending = true;
        }
        let timeout = timeout.as_millis().min(250).max(1) as u32;
        match self.await_result(timeout)? {
            Some(length) => self.copy_frame(length, output),
            None => Ok(None),
        }
    }
}
impl NativeSource {
    fn copy_frame(
        &self,
        length: usize,
        output: &mut [u8],
    ) -> Result<Option<ReceivedFrame>, CaptureError> {
        let data = self.buffer.get(..length).ok_or(CaptureError {
            code: CaptureErrorCode::Io,
            message: "driver returned an out-of-bounds frame".into(),
        })?;
        let original = decode_original_frame(data, self.index, self.luid)?;
        if original.bytes.len() > output.len() {
            return Err(CaptureError {
                code: CaptureErrorCode::InvalidConfig,
                message: "capture output buffer cannot fit original frame".into(),
            });
        }
        output[..original.bytes.len()].copy_from_slice(original.bytes);
        Ok(Some(ReceivedFrame {
            length: original.bytes.len(),
            timestamp: original.timestamp,
        }))
    }
}
impl Drop for NativeSource {
    fn drop(&mut self) {
        if self.pending {
            unsafe {
                CancelIoEx(self.device.0, &mut *self.overlapped);
            }
            // The kernel producer must complete canceled read IRPs before the
            // OVERLAPPED memory/buffer can be freed. This is a driver contract.
            let _ = self.await_result(u32::MAX);
        }
    }
}

/// Presence/ABI probe only. Never marks a NIC supported merely because the
/// adapter can be enumerated with GetAdaptersAddresses.
pub fn probe_driver() -> Result<(), CaptureError> {
    NativeSource::connect().map(|_| ())
}

pub fn capture_with_progress(
    interface_name: &str,
    expected_luid: u64,
    limits: &live::CaptureLimits,
    cancel: &std::sync::atomic::AtomicBool,
    progress: impl FnMut(live::CaptureProgress),
) -> Result<live::CaptureResult, CaptureError> {
    limits.validate()?;
    let selected = live::select_interface(&live::discover_interfaces()?, interface_name)?;
    let mut source = NativeSource::open(&selected, expected_luid)?;
    live::capture_from_with_progress(&mut source, selected, limits, cancel, progress)
}

//! Optional native OpenCL GPU execution. CyberDeck owns the kernel and host
//! dispatch; OpenCL is a hardware API, not a subprocess or hashcat adapter.
//! OpenCL SHA-256, MD5 and SHA-1 kernels accept <=55-byte candidates;
//! the NTLM kernel is ASCII-only up to 27 bytes. Hardware verification remains separate.
use serde::Serialize;
pub const MAX_GPU_BATCH: usize = 65_536;
pub const MAX_GPU_CANDIDATE_BYTES: usize = 55;

#[derive(Debug, Clone, Serialize)]
pub struct GpuDevice {
    pub name: String,
    pub vendor: String,
    pub driver: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct GpuProbe {
    pub available: bool,
    pub backend: &'static str,
    pub devices: Vec<GpuDevice>,
    pub detail: String,
}
/// Probe real OpenCL GPU devices; software/CPU OpenCL is not misreported as a GPU.
pub fn probe() -> GpuProbe {
    #[cfg(feature = "gpu")]
    {
        match native::devices() {
            Ok(devices) => GpuProbe {
                available: !devices.is_empty(),
                backend: "opencl",
                detail: if devices.is_empty() {
                    "No OpenCL GPU device detected".into()
                } else {
                    "OpenCL GPU detected; kernel validation requires a hardware test".into()
                },
                devices,
            },
            Err(err) => GpuProbe {
                available: false,
                backend: "opencl",
                detail: err,
                devices: Vec::new(),
            },
        }
    }
    #[cfg(not(feature = "gpu"))]
    {
        GpuProbe {
            available: false,
            backend: "opencl",
            devices: Vec::new(),
            detail: "GPU backend not built (enable the gpu Cargo feature)".into(),
        }
    }
}
/// Return matching zero-based batch indices. Reject unsupported inputs rather
/// than silently falling back or losing work; caller can choose CPU explicitly.
/// GPU positives are verified again using Rust SHA-256 before being returned.
pub fn recover_sha256(target_hex: &str, candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
    let target = hex::decode(target_hex).map_err(|_| "SHA-256 target must be hex")?;
    if target.len() != 32 {
        return Err("SHA-256 target must be 32 bytes".into());
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    if candidates.len() > MAX_GPU_BATCH {
        return Err("GPU batch exceeds bound".into());
    }
    if candidates.iter().any(|c| c.len() > MAX_GPU_CANDIDATE_BYTES) {
        return Err("GPU SHA-256 supports 0..=55-byte candidates only".into());
    }
    #[cfg(feature = "gpu")]
    {
        native::execute(&target, candidates)
    }
    #[cfg(not(feature = "gpu"))]
    {
        Err("GPU feature not enabled; use the native CPU recovery path".into())
    }
}

/// Native OpenCL MD5 matching. Positive GPU results are rechecked with Rust MD5.
pub fn recover_md5(target_hex: &str, candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
    let target = hex::decode(target_hex).map_err(|_| "MD5 target must be hex")?;
    if target.len() != 16 {
        return Err("MD5 target must be 16 bytes".into());
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    if candidates.len() > MAX_GPU_BATCH {
        return Err("GPU batch exceeds bound".into());
    }
    if candidates.iter().any(|c| c.len() > MAX_GPU_CANDIDATE_BYTES) {
        return Err("GPU MD5 supports only 0..=55-byte candidates".into());
    }
    #[cfg(feature = "gpu")]
    {
        native::execute_md5(&target, candidates)
    }
    #[cfg(not(feature = "gpu"))]
    {
        Err("GPU feature not enabled; use native CPU recovery".into())
    }
}

/// Native OpenCL SHA-1 matching. Positive GPU results are rechecked with Rust SHA-1.
pub fn recover_sha1(target_hex: &str, candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
    let target = hex::decode(target_hex).map_err(|_| "SHA-1 target must be hex")?;
    if target.len() != 20 {
        return Err("SHA-1 target must be 20 bytes".into());
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    if candidates.len() > MAX_GPU_BATCH {
        return Err("GPU batch exceeds bound".into());
    }
    if candidates.iter().any(|c| c.len() > MAX_GPU_CANDIDATE_BYTES) {
        return Err("GPU SHA-1 supports only 0..=55-byte candidates".into());
    }
    #[cfg(feature = "gpu")]
    {
        native::execute_sha1(&target, candidates)
    }
    #[cfg(not(feature = "gpu"))]
    {
        Err("GPU feature not enabled; use native CPU recovery".into())
    }
}

/// Supported native OpenCL digest formats for explicit GPU device selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GpuHash {
    Sha256,
    Md5,
    Sha1,
    Ntlm,
}
impl GpuHash {
    fn digest_bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Ntlm => 16,
        }
    }
    fn engine(self) -> &'static str {
        match self {
            Self::Sha256 => "cyberdeck-crypto-opencl-sha256",
            Self::Md5 => "cyberdeck-crypto-opencl-md5",
            Self::Sha1 => "cyberdeck-crypto-opencl-sha1",
            Self::Ntlm => "cyberdeck-crypto-opencl-ntlm",
        }
    }
    #[cfg(feature = "gpu")]
    fn native(self) -> native::Algorithm {
        match self {
            Self::Sha256 => native::Algorithm::Sha256,
            Self::Md5 => native::Algorithm::Md5,
            Self::Sha1 => native::Algorithm::Sha1,
            Self::Ntlm => native::Algorithm::Ntlm,
        }
    }
}

/// Stream synthetic or user-supplied candidate bytes to a chosen OpenCL GPU.
/// The zero-based device index refers to probe().devices and may change after
/// GPU driver updates or when OpenCL platforms are re-enumerated.
/// Existing recover_*_stream APIs intentionally retain the first-GPU default.
pub fn recover_stream_on_device<I, B, F>(
    algorithm: GpuHash,
    device_index: usize,
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    recover_stream_on_device_with_batch(
        algorithm,
        device_index,
        GPU_STREAM_BATCH,
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        cancel,
    )
}

/// Like recover_stream_on_device but allows bounded per-job batch tuning.
/// This is not a hardware performance claim: benchmark both size and device.
pub fn recover_stream_on_device_with_batch<I, B, F>(
    algorithm: GpuHash,
    device_index: usize,
    batch_size: usize,
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    #[cfg(feature = "gpu")]
    {
        let mut session: Option<native::Session> = None;
        stream_with_batch(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            batch_size,
            algorithm.digest_bytes(),
            algorithm.engine(),
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid GPU target hex")?;
                if session.is_none() {
                    session = Some(native::Session::new_for_device(
                        batch_size,
                        algorithm.native(),
                        device_index,
                    )?);
                }
                session
                    .as_mut()
                    .expect("GPU session initialized")
                    .execute(&target, batch)
            },
        )
    }
    #[cfg(not(feature = "gpu"))]
    {
        let _ = device_index;
        stream_with_batch(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            batch_size,
            algorithm.digest_bytes(),
            algorithm.engine(),
            cancel,
            |_, _| Err("GPU feature not enabled; no OpenCL work was performed".into()),
        )
    }
}

/// Recover a bounded wordlist on an explicitly selected OpenCL GPU,
/// propagating file-read and overlength-line failures without materializing
/// the wordlist. Only the algorithms and candidate lengths supported by the
/// native GPU session can be used; no silent CPU fallback is performed.
/// Fallible candidate API for reproducible GPU rule/wordlist streams.
/// OpenCL failure is returned, not disguised as CPU execution.
pub fn recover_results_on_device_with_batch<I, B, F>(
    algorithm: GpuHash,
    device_index: usize,
    batch_size: usize,
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = Result<B, String>>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    recover_results_on_device_with_batch_progress(
        algorithm,
        device_index,
        batch_size,
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        cancel,
        |_| {},
    )
}

/// Execute selected-device OpenCL batches with completed-check progress.
/// Does not silently fall back to CPU or serialize recovered passwords in events.
pub fn recover_results_on_device_with_batch_progress<I, B, F, P>(
    algorithm: GpuHash,
    device_index: usize,
    batch_size: usize,
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
    on_progress: P,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = Result<B, String>>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    P: FnMut(GpuStreamProgress),
{
    // Reject unsupported NTLM inputs even without an OpenCL loader. A
    // candidate validation error must not be disguised as a driver failure.
    let candidates = candidates.into_iter().map(|entry| {
        entry.and_then(|candidate| {
            if algorithm == GpuHash::Ntlm
                && (candidate.as_ref().len() > 27 || !candidate.as_ref().is_ascii())
            {
                Err("GPU NTLM supports only ASCII candidates of length 0..=27".into())
            } else {
                Ok(candidate)
            }
        })
    });
    #[cfg(feature = "gpu")]
    {
        let mut session: Option<native::Session> = None;
        streaming::stream_with_batch_results_progress(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            batch_size,
            algorithm.digest_bytes(),
            algorithm.engine(),
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid GPU target hex")?;
                if session.is_none() {
                    session = Some(native::Session::new_for_device(
                        batch_size,
                        algorithm.native(),
                        device_index,
                    )?);
                }
                session
                    .as_mut()
                    .expect("GPU session initialized")
                    .execute(&target, batch)
            },
            on_progress,
        )
    }
    #[cfg(not(feature = "gpu"))]
    {
        let _ = device_index;
        streaming::stream_with_batch_results_progress(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            batch_size,
            algorithm.digest_bytes(),
            algorithm.engine(),
            cancel,
            |_, _| Err("GPU feature not enabled; no OpenCL work was performed".into()),
            on_progress,
        )
    }
}

/// Streams binary/CRLF-safe wordlists directly to the selected GPU.
pub fn recover_wordlist_on_device_with_batch<R, F>(
    algorithm: GpuHash,
    device_index: usize,
    batch_size: usize,
    target_hex: &str,
    reader: R,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    R: std::io::BufRead,
    F: FnMut() -> bool,
{
    recover_results_on_device_with_batch(
        algorithm,
        device_index,
        batch_size,
        target_hex,
        crate::candidates::WordlistCandidates::new(reader),
        max_attempts,
        max_matches,
        cancel,
    )
}

/// Streams bounded compiled-rule variants directly into OpenCL, without
/// collecting a generated dictionary or silently falling back to CPU.
pub fn recover_rule_wordlist_on_device_with_batch<R, F>(
    algorithm: GpuHash,
    device_index: usize,
    batch_size: usize,
    target_hex: &str,
    reader: R,
    rules: Vec<crate::recovery::CompiledRule>,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    R: std::io::BufRead,
    F: FnMut() -> bool,
{
    let source = crate::candidates::WordlistCandidates::new(reader);
    let stream = crate::candidates::RuleCandidates::new(source, rules)?;
    recover_results_on_device_with_batch(
        algorithm,
        device_index,
        batch_size,
        target_hex,
        stream,
        max_attempts,
        max_matches,
        cancel,
    )
}

/// Native GPU NTLM matching (MD4 of UTF-16LE).
/// This optimized single-block implementation is intentionally ASCII-only:
/// 0..=27 bytes. Use native CPU recovery for Unicode or longer candidates.
pub fn recover_ntlm(target_hex: &str, candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
    let target = hex::decode(target_hex).map_err(|_| "NTLM target must be hex")?;
    if target.len() != 16 {
        return Err("NTLM target must be 16 bytes".into());
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    if candidates.len() > MAX_GPU_BATCH {
        return Err("GPU batch exceeds bound".into());
    }
    if candidates.iter().any(|c| c.len() > 27 || !c.is_ascii()) {
        return Err("GPU NTLM supports only ASCII candidates of length 0..=27".into());
    }
    #[cfg(feature = "gpu")]
    {
        native::execute_ntlm(&target, candidates)
    }
    #[cfg(not(feature = "gpu"))]
    {
        Err("GPU feature not enabled; use native CPU NTLM recovery".into())
    }
}

#[path = "gpu_stream.rs"]
mod streaming;
pub use streaming::{
    recover_md5_stream, recover_ntlm_stream, recover_sha1_stream, recover_sha256_stream,
    GpuStreamHit, GpuStreamProgress, GpuStreamResult, GPU_STREAM_BATCH, MAX_GPU_STREAM_CANDIDATES,
    MAX_GPU_STREAM_MATCHES,
};
#[cfg(test)]
use streaming::{stream_with, stream_with_checked};
use streaming::{stream_with_batch, stream_with_batch_results};

#[cfg(feature = "gpu")]
mod native {
    use super::*;
    use libloading::Library;
    use sha2::{Digest, Sha256};
    use std::ffi::{c_char, c_void, CString};
    use std::ptr;
    type Handle = *mut c_void;
    type FPlatform = unsafe extern "system" fn(u32, *mut Handle, *mut u32) -> i32;
    type FDevices = unsafe extern "system" fn(Handle, u64, u32, *mut Handle, *mut u32) -> i32;
    type FInfo = unsafe extern "system" fn(Handle, u32, usize, *mut c_void, *mut usize) -> i32;
    type FContext = unsafe extern "system" fn(
        *const isize,
        u32,
        *const Handle,
        *mut c_void,
        *mut c_void,
        *mut i32,
    ) -> Handle;
    type FQueue = unsafe extern "system" fn(Handle, Handle, u64, *mut i32) -> Handle;
    type FProgram = unsafe extern "system" fn(
        Handle,
        u32,
        *const *const c_char,
        *const usize,
        *mut i32,
    ) -> Handle;
    type FBuild = unsafe extern "system" fn(
        Handle,
        u32,
        *const Handle,
        *const c_char,
        *mut c_void,
        *mut c_void,
    ) -> i32;
    type FKernel = unsafe extern "system" fn(Handle, *const c_char, *mut i32) -> Handle;
    type FBuffer = unsafe extern "system" fn(Handle, u64, usize, *mut c_void, *mut i32) -> Handle;
    type FArg = unsafe extern "system" fn(Handle, u32, usize, *const c_void) -> i32;
    type FEnqueue = unsafe extern "system" fn(
        Handle,
        Handle,
        u32,
        *const usize,
        *const usize,
        *const usize,
        u32,
        *const c_void,
        *mut c_void,
    ) -> i32;
    type FRead = unsafe extern "system" fn(
        Handle,
        Handle,
        u32,
        usize,
        usize,
        *mut c_void,
        u32,
        *const c_void,
        *mut c_void,
    ) -> i32;
    type FRelease = unsafe extern "system" fn(Handle) -> i32;

    const DEVICE_TYPE_GPU: u64 = 4;
    const DEVICE_NAME: u32 = 0x102B;
    const DEVICE_VENDOR: u32 = 0x102C;
    const DRIVER_VERSION: u32 = 0x102D;
    const MEM_READ_ONLY: u64 = 1 << 2;
    const MEM_WRITE_ONLY: u64 = 1 << 1;

    struct Api {
        library: Library,
    }
    impl Api {
        fn load() -> Result<Self, String> {
            // Resolve Windows OpenCL from the actual system directory, not the
            // current working directory or an attacker-controlled PATH entry.
            #[cfg(target_os = "windows")]
            let names: Vec<std::path::PathBuf> = {
                use std::os::windows::ffi::OsStringExt;
                #[link(name = "kernel32")]
                unsafe extern "system" {
                    fn GetSystemDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
                }
                let mut buffer = [0u16; 32768];
                let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
                if len == 0 || len as usize >= buffer.len() {
                    return Err("Windows system directory unavailable".into());
                }
                vec![std::path::PathBuf::from(std::ffi::OsString::from_wide(
                    &buffer[..len as usize],
                ))
                .join("OpenCL.dll")]
            };
            #[cfg(target_os = "linux")]
            let names: Vec<std::path::PathBuf> = ["libOpenCL.so.1", "libOpenCL.so"]
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect();
            #[cfg(target_os = "macos")]
            let names: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from(
                "/System/Library/Frameworks/OpenCL.framework/OpenCL",
            )];
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            let names: Vec<std::path::PathBuf> = vec![];
            for name in names {
                // SAFETY: loader binaries must be platform-owned; OpenCL device
                // vendors are still responsible for their installed ICD drivers.
                if let Ok(library) = unsafe { Library::new(&name) } {
                    return Ok(Self { library });
                }
            }
            Err("No system OpenCL loader is installed".into())
        }
        unsafe fn symbol<T: Copy>(&self, name: &[u8]) -> Result<T, String> {
            let sym: libloading::Symbol<'_, T> = self.library.get(name).map_err(|_| {
                format!(
                    "OpenCL entry point unavailable: {}",
                    String::from_utf8_lossy(name)
                )
            })?;
            Ok(*sym)
        }
    }
    struct Owned {
        value: Handle,
        release: FRelease,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.value.is_null() {
                // SAFETY: handles were created by the matching runtime and have not been released.
                unsafe {
                    (self.release)(self.value);
                }
            }
        }
    }
    fn status(rc: i32, operation: &str) -> Result<(), String> {
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("{operation} failed with OpenCL status {rc}"))
        }
    }
    unsafe fn select_devices(api: &Api) -> Result<Vec<(Handle, Handle)>, String> {
        let platform_ids: FPlatform = api.symbol(b"clGetPlatformIDs")?;
        let device_ids: FDevices = api.symbol(b"clGetDeviceIDs")?;
        let mut count = 0;
        let rc = platform_ids(0, ptr::null_mut(), &mut count);
        if rc == -1001 {
            return Ok(Vec::new());
        } // CL_PLATFORM_NOT_FOUND_KHR
        status(rc, "enumerating OpenCL platforms")?;
        if count > 32 {
            return Err("too many OpenCL platforms".into());
        }
        let mut platforms = vec![ptr::null_mut(); count as usize];
        status(
            platform_ids(count, platforms.as_mut_ptr(), ptr::null_mut()),
            "reading OpenCL platforms",
        )?;
        let mut out = Vec::new();
        for platform in platforms {
            let mut count = 0;
            if device_ids(platform, DEVICE_TYPE_GPU, 0, ptr::null_mut(), &mut count) != 0 {
                continue;
            }
            if count > 32 {
                return Err("too many OpenCL GPU devices".into());
            }
            let mut devices = vec![ptr::null_mut(); count as usize];
            if device_ids(
                platform,
                DEVICE_TYPE_GPU,
                count,
                devices.as_mut_ptr(),
                ptr::null_mut(),
            ) != 0
            {
                continue;
            }
            for device in devices {
                out.push((platform, device));
            }
        }
        Ok(out)
    }
    unsafe fn device_info(api: &Api, device: Handle, property: u32) -> String {
        let Ok(info): Result<FInfo, _> = api.symbol(b"clGetDeviceInfo") else {
            return "unknown".into();
        };
        let mut length = 0usize;
        if info(device, property, 0, ptr::null_mut(), &mut length) != 0
            || length == 0
            || length > 4096
        {
            return "unknown".into();
        }
        let mut bytes = vec![0u8; length];
        if info(
            device,
            property,
            bytes.len(),
            bytes.as_mut_ptr().cast(),
            ptr::null_mut(),
        ) != 0
        {
            return "unknown".into();
        }
        String::from_utf8_lossy(bytes.split(|b| *b == 0).next().unwrap_or(&[])).into_owned()
    }
    pub(super) fn devices() -> Result<Vec<GpuDevice>, String> {
        let api = Api::load()?;
        // SAFETY: clGetPlatformIDs/clGetDeviceIDs and clGetDeviceInfo are called
        // with bounded, properly allocated output buffers.
        unsafe {
            let ids = select_devices(&api)?;
            Ok(ids
                .into_iter()
                .map(|(_, d)| GpuDevice {
                    name: device_info(&api, d, DEVICE_NAME),
                    vendor: device_info(&api, d, DEVICE_VENDOR),
                    driver: device_info(&api, d, DRIVER_VERSION),
                })
                .collect())
        }
    }
    // Session keeps the OpenCL program, kernel, queue and buffers alive.
    include!("gpu_session.rs");
    pub(super) fn execute(target: &[u8], candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
        Session::new(candidates.len())?.execute(target, candidates)
    }
    pub(super) fn execute_md5(target: &[u8], candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
        Session::new_for(candidates.len(), Algorithm::Md5)?.execute(target, candidates)
    }
    pub(super) fn execute_sha1(target: &[u8], candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
        Session::new_for(candidates.len(), Algorithm::Sha1)?.execute(target, candidates)
    }
    pub(super) fn execute_ntlm(target: &[u8], candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
        Session::new_for(candidates.len(), Algorithm::Ntlm)?.execute(target, candidates)
    }
}
#[cfg(test)]
#[path = "gpu_tests.rs"]
mod tests;

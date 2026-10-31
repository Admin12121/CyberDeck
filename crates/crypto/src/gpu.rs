//! Optional native OpenCL GPU execution. CyberDeck owns the kernel and host
//! dispatch; OpenCL is a hardware API, not a subprocess or hashcat adapter.
//! Only SHA-256 candidates <=55 bytes are supported in this first GPU kernel.
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

pub const GPU_STREAM_BATCH: usize = 4096;
pub const MAX_GPU_STREAM_CANDIDATES: u64 = 10_000_000;
pub const MAX_GPU_STREAM_MATCHES: usize = 100;

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct GpuStreamHit {
    pub index: u64,
    pub candidate: Vec<u8>,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct GpuStreamResult {
    pub engine: &'static str,
    /// Number of candidates actually dispatched to the GPU and checked.
    pub tried: u64,
    pub batches: u64,
    pub hits: Vec<GpuStreamHit>,
    pub cancelled: bool,
    pub limit_reached: bool,
}
/// Lazy, bounded SHA-256 GPU candidate streaming with exact processed counts.
/// Does not silently switch to CPU when OpenCL fails.
pub fn recover_sha256_stream<I, B, F>(
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
        return stream_with(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid SHA-256 target")?;
                if session.is_none() {
                    session = Some(native::Session::new(GPU_STREAM_BATCH)?);
                }
                session
                    .as_mut()
                    .expect("initialized GPU session")
                    .execute(&target, batch)
            },
        );
    }
    #[cfg(not(feature = "gpu"))]
    {
        stream_with(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            cancel,
            recover_sha256,
        )
    }
}

/// Run bounded MD5 GPU recovery using one native OpenCL session per stream.
pub fn recover_md5_stream<I, B, F>(
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
        return stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            16,
            "cyberdeck-crypto-opencl-md5",
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid MD5 target")?;
                if session.is_none() {
                    session = Some(native::Session::new_for(
                        GPU_STREAM_BATCH,
                        native::Algorithm::Md5,
                    )?);
                }
                session
                    .as_mut()
                    .expect("MD5 session initialized")
                    .execute(&target, batch)
            },
        );
    }
    #[cfg(not(feature = "gpu"))]
    {
        stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            16,
            "cyberdeck-crypto-opencl-md5",
            cancel,
            recover_md5,
        )
    }
}

/// Run bounded SHA-1 GPU recovery using one native OpenCL session per stream.
pub fn recover_sha1_stream<I, B, F>(
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
        return stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            20,
            "cyberdeck-crypto-opencl-sha1",
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid SHA-1 target")?;
                if session.is_none() {
                    session = Some(native::Session::new_for(
                        GPU_STREAM_BATCH,
                        native::Algorithm::Sha1,
                    )?);
                }
                session
                    .as_mut()
                    .expect("SHA-1 session initialized")
                    .execute(&target, batch)
            },
        );
    }
    #[cfg(not(feature = "gpu"))]
    {
        stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            20,
            "cyberdeck-crypto-opencl-sha1",
            cancel,
            recover_sha1,
        )
    }
}

/// Stream ASCII-only NTLM candidates through native OpenCL MD4.
pub fn recover_ntlm_stream<I, B, F>(
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
    recover_stream_on_device(
        GpuHash::Ntlm,
        0,
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        cancel,
    )
}

fn dispatch_batch<E>(
    target_hex: &str,
    batch: &mut Vec<Vec<u8>>,
    result: &mut GpuStreamResult,
    max_matches: usize,
    executor: &mut E,
) -> Result<(), String>
where
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    if batch.is_empty() {
        return Ok(());
    }
    let refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
    let hits = executor(target_hex, &refs)?;
    for index in hits {
        if index >= batch.len() {
            return Err("GPU returned an invalid match index".into());
        }
        if result.hits.len() < max_matches {
            result.hits.push(GpuStreamHit {
                index: result.tried + index as u64,
                candidate: batch[index].clone(),
            });
        }
    }
    result.tried += batch.len() as u64;
    result.batches += 1;
    batch.clear();
    Ok(())
}
fn stream_with<I, B, F, E>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
    executor: E,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    stream_with_checked(
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        32,
        "cyberdeck-crypto-opencl-sha256",
        cancel,
        executor,
    )
}

fn stream_with_checked<I, B, F, E>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    digest_bytes: usize,
    engine: &'static str,
    cancel: F,
    executor: E,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    stream_with_batch(
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        GPU_STREAM_BATCH,
        digest_bytes,
        engine,
        cancel,
        executor,
    )
}

fn stream_with_batch<I, B, F, E>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    batch_size: usize,
    digest_bytes: usize,
    engine: &'static str,
    mut cancel: F,
    mut executor: E,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    if hex::decode(target_hex)
        .map_err(|_| "invalid GPU digest")?
        .len()
        != digest_bytes
    {
        return Err("GPU digest has incorrect size".into());
    }
    if batch_size == 0 || batch_size > MAX_GPU_BATCH {
        return Err("GPU batch size must be 1..=65536".into());
    }
    if max_attempts == 0
        || max_attempts > MAX_GPU_STREAM_CANDIDATES
        || max_matches == 0
        || max_matches > MAX_GPU_STREAM_MATCHES
    {
        return Err("invalid streaming GPU limits".into());
    }
    let mut result = GpuStreamResult {
        engine,
        tried: 0,
        batches: 0,
        hits: Vec::new(),
        cancelled: false,
        limit_reached: false,
    };
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_size);
    let mut generated = 0u64;
    let mut source = candidates.into_iter();
    loop {
        // Cancellation discards queued but undispatched candidates; 'tried'
        // only includes candidates actually checked on the GPU.
        if cancel() {
            result.cancelled = true;
            break;
        }
        if generated >= max_attempts {
            result.limit_reached = true;
            break;
        }
        let Some(candidate) = source.next() else {
            break;
        };
        let candidate = candidate.as_ref();
        if candidate.len() > MAX_GPU_CANDIDATE_BYTES {
            return Err("GPU streaming candidate exceeds 55-byte SHA-256 limit".into());
        }
        batch.push(candidate.to_vec());
        generated += 1;
        if batch.len() >= batch_size {
            dispatch_batch(
                target_hex,
                &mut batch,
                &mut result,
                max_matches,
                &mut executor,
            )?;
            if result.hits.len() >= max_matches {
                return Ok(result);
            }
        }
    }
    if !result.cancelled {
        dispatch_batch(
            target_hex,
            &mut batch,
            &mut result,
            max_matches,
            &mut executor,
        )?;
    }
    Ok(result)
}

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
mod tests {
    use super::*;

    #[test]
    fn lazy_gpu_stream_counts_only_verified_batches() {
        let mut batches = 0;
        let run = stream_with(
            &"00".repeat(32),
            std::iter::repeat(b"bad".to_vec())
                .take(GPU_STREAM_BATCH)
                .chain(std::iter::once(b"hit".to_vec())),
            10_000,
            1,
            || false,
            |_, list| {
                batches += 1;
                Ok(list
                    .iter()
                    .enumerate()
                    .filter_map(|(i, c)| if *c == b"hit" { Some(i) } else { None })
                    .collect())
            },
        )
        .unwrap();
        assert_eq!(batches, 2);
        assert_eq!(run.tried, (GPU_STREAM_BATCH + 1) as u64);
        assert_eq!(run.hits[0].index, GPU_STREAM_BATCH as u64);
        assert_eq!(run.hits[0].candidate, b"hit");
    }
    #[test]
    fn gpu_stream_limit_cancel_and_bad_return_indices() {
        let target = "00".repeat(32);
        let run = stream_with(
            &target,
            std::iter::repeat(b"x".to_vec()).take(9),
            3,
            1,
            || false,
            |_, _| Ok(vec![]),
        )
        .unwrap();
        assert_eq!(run.tried, 3);
        assert!(run.limit_reached);
        let mut polls = 0;
        let cancelled = stream_with(
            &target,
            [b"hello", b"world"],
            10,
            1,
            || {
                polls += 1;
                polls > 1
            },
            |_, _| Ok(vec![]),
        )
        .unwrap();
        assert!(cancelled.cancelled);
        assert_eq!(cancelled.tried, 0);
        assert!(stream_with(&target, [b"x"], 10, 1, || false, |_, _| Ok(vec![2])).is_err());
    }

    #[test]
    fn ntlm_gpu_rejects_bad_inputs_without_a_driver() {
        assert!(recover_ntlm("ab", &[b"a"]).is_err());
        assert!(recover_ntlm("zz", &[b"a"]).is_err());
        let target = "00".repeat(16);
        assert!(recover_ntlm(&target, &[&[b'a'; 28]]).is_err());
        assert!(recover_ntlm(&target, &[&[0xC3, 0xA9]]).is_err());
        assert!(recover_ntlm(&target, &vec![b"a".as_slice(); MAX_GPU_BATCH + 1]).is_err());
    }

    #[test]
    fn ntlm_native_reference_vectors_are_stable() {
        use md4::Digest;
        fn ntlm(candidate: &[u8]) -> String {
            let mut utf16le = Vec::new();
            for byte in candidate {
                utf16le.extend_from_slice(&[*byte, 0]);
            }
            hex::encode(md4::Md4::digest(&utf16le))
        }
        assert_eq!(ntlm(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(ntlm(b"password"), "8846f7eaee8fb117ad06bdd830b7586c");
        assert_eq!(ntlm(b"Password123"), "58a478135a93ac3bf058a5ea0e8fdb71");
    }

    #[test]
    fn md5_gpu_rejects_invalid_digest_and_candidate_size() {
        assert!(recover_md5("zz", &[b"x"]).is_err());
        assert!(recover_md5("ab", &[b"x"]).is_err());
        assert!(recover_md5(&"00".repeat(16), &[&[b'x'; 56]]).is_err());
        let too_many = vec![b"x".as_slice(); MAX_GPU_BATCH + 1];
        assert!(recover_md5(&"00".repeat(16), &too_many).is_err());
    }
    #[test]
    fn md5_mock_stream_preserves_global_match_index() {
        use md5::Digest;
        let target = hex::encode(md5::Md5::digest(b"found"));
        let words = std::iter::repeat(b"bad".to_vec())
            .take(GPU_STREAM_BATCH)
            .chain(std::iter::once(b"found".to_vec()));
        let result = stream_with_checked(
            &target,
            words,
            10_000,
            1,
            16,
            "cyberdeck-crypto-opencl-md5",
            || false,
            |_, items| {
                Ok(items
                    .iter()
                    .enumerate()
                    .filter_map(|(i, c)| if *c == b"found" { Some(i) } else { None })
                    .collect())
            },
        )
        .unwrap();
        assert_eq!(result.tried, (GPU_STREAM_BATCH + 1) as u64);
        assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
        assert_eq!(result.engine, "cyberdeck-crypto-opencl-md5");
    }
    #[test]
    fn md5_hardware_reference_vectors_if_available() {
        #[cfg(feature = "gpu")]
        if probe().available {
            use md5::{Digest, Md5};
            let inputs = vec![
                vec![],
                b"a".to_vec(),
                b"abc".to_vec(),
                vec![0xff, 0x00],
                vec![b'x'; 54],
                vec![b'x'; 55],
            ];
            let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
            for (index, input) in inputs.iter().enumerate() {
                let target = hex::encode(Md5::digest(input));
                assert_eq!(recover_md5(&target, &refs).unwrap(), vec![index]);
            }
            let mut words = vec![b"not-match".to_vec(); GPU_STREAM_BATCH + 2];
            words[GPU_STREAM_BATCH] = b"hello".to_vec();
            let target = hex::encode(Md5::digest(b"hello"));
            let result = recover_md5_stream(&target, words, 10_000, 1, || false).unwrap();
            assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
            assert_eq!(result.batches, 2);
        }
    }

    #[test]
    fn sha1_gpu_rejects_invalid_digest_and_candidate_size() {
        assert!(recover_sha1("zz", &[b"x"]).is_err());
        assert!(recover_sha1("ab", &[b"x"]).is_err());
        assert!(recover_sha1(&"00".repeat(20), &[&[b'x'; 56]]).is_err());
        let too_many = vec![b"x".as_slice(); MAX_GPU_BATCH + 1];
        assert!(recover_sha1(&"00".repeat(20), &too_many).is_err());
    }
    #[test]
    fn sha1_mock_stream_preserves_global_match_index() {
        use sha1::Digest;
        let target = hex::encode(sha1::Sha1::digest(b"found"));
        let words = std::iter::repeat(b"bad".to_vec())
            .take(GPU_STREAM_BATCH)
            .chain(std::iter::once(b"found".to_vec()));
        let result = stream_with_checked(
            &target,
            words,
            10_000,
            1,
            20,
            "cyberdeck-crypto-opencl-sha1",
            || false,
            |_, items| {
                Ok(items
                    .iter()
                    .enumerate()
                    .filter_map(|(i, c)| if *c == b"found" { Some(i) } else { None })
                    .collect())
            },
        )
        .unwrap();
        assert_eq!(result.tried, (GPU_STREAM_BATCH + 1) as u64);
        assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
        assert_eq!(result.engine, "cyberdeck-crypto-opencl-sha1");
    }
    #[test]
    fn sha1_hardware_reference_vectors_if_available() {
        #[cfg(feature = "gpu")]
        if probe().available {
            use sha1::{Digest, Sha1};
            let inputs = vec![
                vec![],
                b"a".to_vec(),
                b"abc".to_vec(),
                vec![0xff, 0x00],
                vec![b'x'; 54],
                vec![b'x'; 55],
            ];
            let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
            for (index, input) in inputs.iter().enumerate() {
                let target = hex::encode(Sha1::digest(input));
                assert_eq!(recover_sha1(&target, &refs).unwrap(), vec![index]);
            }
            let mut words = vec![b"not-match".to_vec(); GPU_STREAM_BATCH + 2];
            words[GPU_STREAM_BATCH] = b"hello".to_vec();
            let target = hex::encode(Sha1::digest(b"hello"));
            let result = recover_sha1_stream(&target, words, 10_000, 1, || false).unwrap();
            assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
            assert_eq!(result.batches, 2);
        }
    }

    #[test]
    fn configurable_gpu_batch_size_accounts_for_partial_final_batch() {
        let hash = "00".repeat(32);
        let mut sizes = Vec::new();
        let result = stream_with_batch(
            &hash,
            std::iter::repeat_n(b"test".to_vec(), 1_025),
            2_000,
            1,
            128,
            32,
            "cyberdeck-crypto-opencl-sha256",
            || false,
            |_, batch| {
                sizes.push(batch.len());
                Ok(Vec::new())
            },
        )
        .unwrap();
        assert_eq!(result.tried, 1_025);
        assert_eq!(result.batches, 9);
        assert_eq!(sizes, [128, 128, 128, 128, 128, 128, 128, 128, 1]);
        for invalid_size in [0, MAX_GPU_BATCH + 1] {
            assert!(stream_with_batch(
                &hash,
                [b"x"],
                1,
                1,
                invalid_size,
                32,
                "cyberdeck-crypto-opencl-sha256",
                || false,
                |_, _| Ok(vec![]),
            )
            .is_err());
        }
    }

    #[test]
    fn selected_gpu_stream_validates_target_before_device_access() {
        assert!(
            recover_stream_on_device(GpuHash::Sha256, 0, "zz", [b"test"], 5, 1, || false,).is_err()
        );
        assert!(recover_stream_on_device(
            GpuHash::Md5,
            0,
            &"00".repeat(32),
            [b"test"],
            5,
            1,
            || false,
        )
        .is_err());
        assert!(recover_stream_on_device(
            GpuHash::Sha1,
            0,
            &"00".repeat(20),
            [b"test"],
            0,
            1,
            || false,
        )
        .is_err());
    }

    #[test]
    fn explicit_device_index_parity_if_hardware_is_accessible() {
        #[cfg(feature = "gpu")]
        {
            use md4::{Digest as _, Md4};
            use md5::Md5;
            use sha1::Sha1;
            use sha2::{Digest, Sha256};

            let devices = probe().devices;
            for device_index in 0..devices.len() {
                for algorithm in [GpuHash::Sha256, GpuHash::Md5, GpuHash::Sha1, GpuHash::Ntlm] {
                    let hash = |candidate: &[u8]| -> String {
                        let digest = match algorithm {
                            GpuHash::Sha256 => Sha256::digest(candidate).to_vec(),
                            GpuHash::Md5 => Md5::digest(candidate).to_vec(),
                            GpuHash::Sha1 => Sha1::digest(candidate).to_vec(),
                            GpuHash::Ntlm => {
                                let mut utf16le = Vec::new();
                                for byte in candidate {
                                    utf16le.extend_from_slice(&[*byte, 0]);
                                }
                                Md4::digest(&utf16le).to_vec()
                            }
                        };
                        hex::encode(digest)
                    };
                    // Cover empty and maximum-size candidates on every GPU,
                    // not only the first device returned by OpenCL.
                    for candidate in [
                        Vec::new(),
                        vec![b'x'; if algorithm == GpuHash::Ntlm { 27 } else { 55 }],
                    ] {
                        let result = recover_stream_on_device_with_batch(
                            algorithm,
                            device_index,
                            64,
                            &hash(&candidate),
                            vec![b"not-a-hit".to_vec(), candidate.clone()],
                            10,
                            1,
                            || false,
                        )
                        .expect("explicit GPU device failed reference vector");
                        assert_eq!(result.tried, 2, "device {device_index} {algorithm:?}");
                        assert_eq!(result.hits.len(), 1, "device {device_index} {algorithm:?}");
                        assert_eq!(result.hits[0].index, 1);
                        assert_eq!(result.hits[0].candidate, candidate);
                    }
                    // Partial last batch and global index across multiple
                    // dispatches must work for every GPU vendor/algorithm.
                    let last = vec![b'x'; if algorithm == GpuHash::Ntlm { 27 } else { 55 }];
                    let batch = std::iter::repeat_n(b"not-a-hit".to_vec(), 257)
                        .chain(std::iter::once(last.clone()));
                    let result = recover_stream_on_device_with_batch(
                        algorithm,
                        device_index,
                        128,
                        &hash(&last),
                        batch,
                        258,
                        1,
                        || false,
                    )
                    .expect("explicit GPU device failed cross-batch validation");
                    assert_eq!(result.tried, 258);
                    assert_eq!(result.batches, 3);
                    assert_eq!(result.hits.len(), 1);
                    assert_eq!(result.hits[0].index, 257);
                    assert_eq!(result.hits[0].candidate, last);
                }
            }
            if !devices.is_empty() {
                let result = recover_stream_on_device(
                    GpuHash::Sha256,
                    devices.len(),
                    &"00".repeat(32),
                    [b"x"],
                    1,
                    1,
                    || false,
                );
                assert!(result.is_err(), "out-of-range GPU index must fail");
            }
        }
    }

    #[test]
    fn unsupported_gpu_inputs_are_rejected_before_driver_access() {
        assert!(recover_sha256("xx", &[b"abc"]).is_err());
        assert!(recover_sha256("ab", &[b"abc"]).is_err());
        assert!(recover_sha256(&"00".repeat(32), &[&[1u8; 56]]).is_err());
        let too_many = vec![b"x".as_slice(); MAX_GPU_BATCH + 1];
        assert!(recover_sha256(&"00".repeat(32), &too_many).is_err());
    }
    #[test]
    fn gpu_reference_vectors_if_hardware_is_accessible() {
        #[cfg(feature = "gpu")]
        if probe().available {
            use sha2::{Digest, Sha256};
            let candidates = vec![
                vec![],
                b"a".to_vec(),
                b"hello".to_vec(),
                vec![b'x'; 54],
                vec![b'x'; 55],
            ];
            let refs: Vec<&[u8]> = candidates.iter().map(Vec::as_slice).collect();
            for (index, candidate) in candidates.iter().enumerate() {
                let digest = hex::encode(Sha256::digest(candidate));
                assert_eq!(recover_sha256(&digest, &refs).unwrap(), vec![index]);
            }

            let mut words = vec![b"incorrect".to_vec(); GPU_STREAM_BATCH + 3];
            words[GPU_STREAM_BATCH + 1] = b"known-target".to_vec();
            let digest = hex::encode(Sha256::digest(b"known-target"));
            let run = recover_sha256_stream(&digest, words, 10_000, 1, || false).unwrap();
            assert_eq!(run.batches, 2);
            assert_eq!(run.tried, (GPU_STREAM_BATCH + 3) as u64);
            assert_eq!(run.hits[0].index, (GPU_STREAM_BATCH + 1) as u64);
            assert_eq!(run.hits[0].candidate, b"known-target");
        }
    }
    #[test]
    fn no_gpu_feature_never_claims_availability() {
        #[cfg(not(feature = "gpu"))]
        {
            let status = probe();
            assert!(!status.available);
            assert!(recover_sha256(&"00".repeat(32), &[b"x"]).is_err());
        }
    }
}

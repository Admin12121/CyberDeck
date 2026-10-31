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
    const MEM_COPY_HOST_PTR: u64 = 1 << 5;

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
    pub(super) fn execute(target: &[u8], candidates: &[&[u8]]) -> Result<Vec<usize>, String> {
        let api = Api::load()?;
        // All allocated handles are RAII-released on any early return. The
        // Api library outlives them because it is declared first.
        unsafe {
            let (_, device) = select_devices(&api)?
                .into_iter()
                .next()
                .ok_or("No OpenCL GPU device detected")?;
            let create_context: FContext = api.symbol(b"clCreateContext")?;
            let create_queue: FQueue = api.symbol(b"clCreateCommandQueue")?;
            let create_program: FProgram = api.symbol(b"clCreateProgramWithSource")?;
            let build: FBuild = api.symbol(b"clBuildProgram")?;
            let create_kernel: FKernel = api.symbol(b"clCreateKernel")?;
            let create_buffer: FBuffer = api.symbol(b"clCreateBuffer")?;
            let set_arg: FArg = api.symbol(b"clSetKernelArg")?;
            let enqueue: FEnqueue = api.symbol(b"clEnqueueNDRangeKernel")?;
            let read: FRead = api.symbol(b"clEnqueueReadBuffer")?;
            let release_context: FRelease = api.symbol(b"clReleaseContext")?;
            let release_queue: FRelease = api.symbol(b"clReleaseCommandQueue")?;
            let release_program: FRelease = api.symbol(b"clReleaseProgram")?;
            let release_kernel: FRelease = api.symbol(b"clReleaseKernel")?;
            let release_buffer: FRelease = api.symbol(b"clReleaseMemObject")?;

            let mut rc = 0i32;
            let context = Owned {
                value: create_context(
                    ptr::null(),
                    1,
                    &device,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut rc,
                ),
                release: release_context,
            };
            status(rc, "creating OpenCL context")?;
            if context.value.is_null() {
                return Err("null OpenCL context".into());
            }
            let queue = Owned {
                value: create_queue(context.value, device, 0, &mut rc),
                release: release_queue,
            };
            status(rc, "creating OpenCL queue")?;
            if queue.value.is_null() {
                return Err("null OpenCL queue".into());
            }

            let source = include_str!("sha256.cl");
            let source_ptr = source.as_ptr().cast::<c_char>();
            let source_len = source.len();
            let program = Owned {
                value: create_program(context.value, 1, &source_ptr, &source_len, &mut rc),
                release: release_program,
            };
            status(rc, "creating OpenCL program")?;
            if program.value.is_null() {
                return Err("null OpenCL program".into());
            }
            status(
                build(
                    program.value,
                    1,
                    &device,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                "compiling native SHA-256 OpenCL kernel",
            )?;
            let kernel_name = CString::new("sha256_match").expect("constant kernel name");
            let kernel = Owned {
                value: create_kernel(program.value, kernel_name.as_ptr(), &mut rc),
                release: release_kernel,
            };
            status(rc, "creating OpenCL kernel")?;
            if kernel.value.is_null() {
                return Err("null OpenCL kernel".into());
            }

            let mut packed = vec![0u8; candidates.len() * 64];
            let mut lengths = Vec::<u32>::with_capacity(candidates.len());
            for (i, candidate) in candidates.iter().enumerate() {
                packed[i * 64..i * 64 + candidate.len()].copy_from_slice(candidate);
                lengths.push(candidate.len() as u32);
            }
            let words: Vec<u32> = target
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("fixed 4 bytes")))
                .collect();
            let mut output = vec![0u32; candidates.len()];

            let buffer = |data: *mut c_void, size: usize, flags: u64| -> Result<Owned, String> {
                let mut e = 0;
                let value = create_buffer(context.value, flags, size, data, &mut e);
                status(e, "allocating OpenCL buffer")?;
                if value.is_null() {
                    return Err("null OpenCL buffer".into());
                }
                Ok(Owned {
                    value,
                    release: release_buffer,
                })
            };
            let input = buffer(
                packed.as_mut_ptr().cast(),
                packed.len(),
                MEM_READ_ONLY | MEM_COPY_HOST_PTR,
            )?;
            let len_bytes = lengths.len() * std::mem::size_of::<u32>();
            let len_buffer = buffer(
                lengths.as_mut_ptr().cast(),
                len_bytes,
                MEM_READ_ONLY | MEM_COPY_HOST_PTR,
            )?;
            let words_bytes = words.len() * std::mem::size_of::<u32>();
            let mut words = words;
            let target_buffer = buffer(
                words.as_mut_ptr().cast(),
                words_bytes,
                MEM_READ_ONLY | MEM_COPY_HOST_PTR,
            )?;
            let output_buffer = buffer(
                ptr::null_mut(),
                output.len() * std::mem::size_of::<u32>(),
                MEM_WRITE_ONLY,
            )?;
            for (i, mem) in [&input, &len_buffer, &target_buffer, &output_buffer]
                .iter()
                .enumerate()
            {
                status(
                    set_arg(
                        kernel.value,
                        i as u32,
                        std::mem::size_of::<Handle>(),
                        (&mem.value as *const Handle).cast(),
                    ),
                    "setting OpenCL buffer argument",
                )?;
            }
            let count = candidates.len() as u32;
            status(
                set_arg(
                    kernel.value,
                    4,
                    std::mem::size_of::<u32>(),
                    (&count as *const u32).cast(),
                ),
                "setting OpenCL count argument",
            )?;
            let global = [candidates.len()];
            status(
                enqueue(
                    queue.value,
                    kernel.value,
                    1,
                    ptr::null(),
                    global.as_ptr(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ),
                "launching OpenCL SHA-256 kernel",
            )?;
            status(
                read(
                    queue.value,
                    output_buffer.value,
                    1,
                    0,
                    output.len() * std::mem::size_of::<u32>(),
                    output.as_mut_ptr().cast(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ),
                "reading GPU results",
            )?;

            // Verify positives on the CPU; never return an unconfirmed recovery.
            Ok(output
                .iter()
                .enumerate()
                .filter_map(|(i, flag)| {
                    if *flag != 0 && Sha256::digest(candidates[i]).as_slice() == target {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
            let candidates: Vec<Vec<u8>> = vec![
                vec![],
                b"incorrect".to_vec(),
                b"hello".to_vec(),
                vec![b'x'; 55],
                vec![b'x'; 54],
            ];
            let refs: Vec<&[u8]> = candidates.iter().map(Vec::as_slice).collect();
            let hash = hex::encode(Sha256::digest(&candidates[3]));
            assert_eq!(recover_sha256(&hash, &refs).unwrap(), vec![3]);
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

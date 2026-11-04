//! Versioned, narrow Rust FFI client for CyberDeck's bundled Hashcat C shim.
//! MIT; confidential execution must happen in a separately supervised worker.
//! This module DOES NOT register Tauri IPC or select an engine automatically.
use std::ffi::{c_char, c_int, c_void, CString};
use std::path::Path;
use std::ptr::NonNull;

const ABI_VERSION: u32 = 4;
const MAX_CANDIDATES: u64 = 1_000_000;
const MAX_RUNTIME_SECONDS: u32 = 300;

// Windows MSVC does not link a MinGW-produced DLL directly without an
// import .lib. Rust raw-dylib generates its own import library from the fixed
// C ABI, so the private worker can link the bundled DLL without a separate
// MSVC/MinGW import-library conversion tool.
#[cfg_attr(target_os = "windows", link(name = "cyberdeck_hashcat_shim", kind = "raw-dylib"))]
#[cfg_attr(not(target_os = "windows"), link(name = "cyberdeck_hashcat_shim"))]
unsafe extern "C" {
    fn cd_hashcat_abi_version() -> u32;
    fn cd_hashcat_opencl_loader_available() -> u32;
    fn cd_hashcat_last_setup_stage(context: *mut c_void) -> u32;
    fn cd_hashcat_create() -> *mut c_void;
    fn cd_hashcat_prepare_mode(
        context: *mut c_void,
        install_root: *const c_char,
        shared_root: *const c_char,
        hash_file: *const c_char,
        wordlist_file: *const c_char,
        temporary_outfile: *const c_char,
        max_candidates: u64,
        runtime_seconds: u32,
        device_id: u32,
        hash_mode: u32,
    ) -> c_int;
    fn cd_hashcat_prepare_sha256(
        context: *mut c_void,
        install_root: *const c_char,
        shared_root: *const c_char,
        hash_file: *const c_char,
        wordlist_file: *const c_char,
        temporary_outfile: *const c_char,
        max_candidates: u64,
        runtime_seconds: u32,
        device_id: u32,
    ) -> c_int;
    fn cd_hashcat_execute(context: *mut c_void) -> c_int;
    fn cd_hashcat_quit(context: *mut c_void) -> c_int;
    #[link_name = "cd_hashcat_last_event"]
    fn cd_hashcat_last_event() -> *const c_char;
    #[link_name = "cd_hashcat_shim_version"]
    fn cd_hashcat_shim_version() -> i32;
    #[link_name = "cd_hashcat_event_trace"]
    fn cd_hashcat_event_trace() -> *const c_char;
    fn cd_hashcat_destroy(context: *mut c_void);
}

#[derive(Debug, PartialEq, Eq)]
pub enum NativeError {
    AbiMismatch,
    AllocationFailed,
    InvalidBound,
    InvalidPath,
    Native(i32),
}

fn checked_path(path: &Path) -> Result<CString, NativeError> {
    if !path.is_absolute() {
        return Err(NativeError::InvalidPath);
    }
    let value = path.to_str().ok_or(NativeError::InvalidPath)?;
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(NativeError::InvalidPath);
    }
    CString::new(value).map_err(|_| NativeError::InvalidPath)
}

/// RAII owner of the opaque C-allocated Hashcat context. Not Clone/Copy, and
/// deliberately neither Send nor Sync; process supervision owns cancellation.
pub struct NativeHashcat {
    handle: NonNull<c_void>,
    state: InitState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InitState {
    Fresh,
    Ready,
    Failed,
}

impl NativeHashcat {
    /// Loader check only; no device enumeration or GPU acceptance is implied.
    pub fn opencl_loader_available() -> bool {
        (unsafe { cd_hashcat_opencl_loader_available() }) == 1
    }

    pub fn new() -> Result<Self, NativeError> {
        let version = unsafe { cd_hashcat_abi_version() };
        if version != ABI_VERSION {
            return Err(NativeError::AbiMismatch);
        }
        let handle =
            NonNull::new(unsafe { cd_hashcat_create() }).ok_or(NativeError::AllocationFailed)?;
        Ok(Self {
            handle,
            state: InitState::Fresh,
        })
    }

    /// Called only with worker-owned files and explicit operator scope.
    /// A failure leaves this context terminal; drop it rather than retrying.
    pub fn prepare_sha256(
        &mut self,
        root: &Path,
        hash_file: &Path,
        wordlist_file: &Path,
        scratch_outfile: &Path,
        max_candidates: u64,
        runtime_seconds: u32,
        device_id: u32,
    ) -> Result<(), NativeError> {
        self.prepare_mode(
            root,
            hash_file,
            wordlist_file,
            scratch_outfile,
            max_candidates,
            runtime_seconds,
            device_id,
            1400,
        )
    }

    /// Selected, bundled raw digest modes; no user-defined Hashcat flags.
    pub fn prepare_mode(
        &mut self,
        root: &Path,
        hash_file: &Path,
        wordlist_file: &Path,
        scratch_outfile: &Path,
        max_candidates: u64,
        runtime_seconds: u32,
        device_id: u32,
        hash_mode: u32,
    ) -> Result<(), NativeError> {
        if self.state != InitState::Fresh
            || max_candidates == 0
            || max_candidates > MAX_CANDIDATES
            || runtime_seconds == 0
            || runtime_seconds > MAX_RUNTIME_SECONDS
            || device_id > 128
            || !matches!(hash_mode, 0 | 10 | 20 | 50 | 60 | 100 | 110 | 120 | 132 | 400 | 1500 | 1731 | 500 | 1000 | 1400 | 1700 | 1800 | 3200 | 7400 | 1100 | 2100 | 5500 | 5600 | 11600 | 13600 | 17200 | 17210 | 9400 | 9600 | 9700 | 10400 | 10500)
        {
            return Err(NativeError::InvalidBound);
        }
        let root = checked_path(root)?;
        // Dynamic loader presence is a strict prerequisite to native OpenCL
        // execution, not hardware acceptance. Fail before upstream session
        // initialization when the system loader is unavailable.
        if unsafe { cd_hashcat_opencl_loader_available() } == 0 {
            self.state = InitState::Failed;
            return Err(NativeError::Native(-52));
        }
        let hash_file = checked_path(hash_file)?;
        let wordlist_file = checked_path(wordlist_file)?;
        let scratch_outfile = checked_path(scratch_outfile)?;
        let status = unsafe {
            cd_hashcat_prepare_mode(
                self.handle.as_ptr(),
                root.as_ptr(),
                root.as_ptr(),
                hash_file.as_ptr(),
                wordlist_file.as_ptr(),
                scratch_outfile.as_ptr(),
                max_candidates,
                runtime_seconds,
                device_id,
                hash_mode,
            )
        };
        // Regardless of success, native initialization may have allocated
        // resources and mutated upstream context; it cannot be retried.
        self.state = if status == 0 {
            InitState::Ready
        } else {
            InitState::Failed
        };
        if status == 0 {
            Ok(())
        } else if status == -5 {
            // Classify only fixed upstream initialization phase markers.
            // Never retrieve native log text: it may contain sensitive hashes.
            let stage = unsafe { cd_hashcat_last_setup_stage(self.handle.as_ptr()) };
            let error = match stage {
                0x121 | 0x120 => -51, // bridge initialization
                0x131 | 0x130 => -52, // compute runtime loading
                0x133 => -53,         // device enumeration/initialization
                0x132 => -54,         // post-device pre-execution setup
                _ => -5,
            };
            Err(NativeError::Native(error))
        } else {
            Err(NativeError::Native(status))
        }
    }

    /// Synchronous and blocking. Never call on Tauri's UI/main thread.
    /// Results stay in isolated worker scratch until independently reverified.
    pub fn execute(&mut self) -> Result<i32, NativeError> {
        if self.state != InitState::Ready {
            return Err(NativeError::InvalidBound);
        }
        Ok(unsafe { cd_hashcat_execute(self.handle.as_ptr()) })
    }

    /// Cooperative Stop only; supervising process must force-kill if hung.
    pub fn event_trace() -> String {
        unsafe {
            let ptr = cd_hashcat_event_trace();
            if ptr.is_null() {
                return String::new();
            }
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    pub fn shim_version() -> i32 {
        unsafe { cd_hashcat_shim_version() }
    }

    pub fn last_event() -> String {
        unsafe {
            let ptr = cd_hashcat_last_event();
            if ptr.is_null() {
                return String::new();
            }
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    pub fn request_quit(&mut self) -> Result<(), NativeError> {
        if self.state != InitState::Ready {
            return Err(NativeError::InvalidBound);
        }
        let status = unsafe { cd_hashcat_quit(self.handle.as_ptr()) };
        if status == 0 {
            Ok(())
        } else {
            Err(NativeError::Native(status))
        }
    }
}

impl Drop for NativeHashcat {
    fn drop(&mut self) {
        unsafe { cd_hashcat_destroy(self.handle.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_abi_lifecycle_and_boundaries() {
        let mut engine = NativeHashcat::new().expect("real pinned core loaded");
        assert_eq!(engine.execute(), Err(NativeError::InvalidBound));
        assert_eq!(engine.request_quit(), Err(NativeError::InvalidBound));
        assert_eq!(
            engine.prepare_sha256(
                Path::new("/tmp"),
                Path::new("/tmp/hash.sha256"),
                Path::new("/tmp/wordlist"),
                Path::new("/tmp/out"),
                0,
                1,
                0,
            ),
            Err(NativeError::InvalidBound)
        );
    }

    #[test]
    fn selected_hash_modes_are_explicit_and_bounded() {
        let mut engine = NativeHashcat::new().expect("real native ABI");
        let failed = engine.prepare_mode(
            Path::new("/tmp"),
            Path::new("/tmp/test.hash"),
            Path::new("/tmp/test.words"),
            Path::new("/tmp/test.out"),
            1,
            1,
            0,
            99999,
        );
        assert_eq!(failed, Err(NativeError::InvalidBound));
        // Rejected modes must not initialize any native session.
        assert_eq!(engine.execute(), Err(NativeError::InvalidBound));
    }

    #[test]
    fn loader_preflight_reports_only_boolean_availability() {
        let state = unsafe { cd_hashcat_opencl_loader_available() };
        assert!(state <= 1);
        // There is no default software fallback or fabricated device index.
        // A machine with no loader fails before upstream session creation.
        if state == 0 {
            let mut context = NativeHashcat::new().expect("valid native ABI");
            let result = context.prepare_sha256(
                Path::new("/tmp"),
                Path::new("/tmp/fixture.hash"),
                Path::new("/tmp/fixture.words"),
                Path::new("/tmp/fixture.result"),
                3,
                30,
                0,
            );
            assert_eq!(result, Err(NativeError::Native(-52)));
        }
    }

    #[test]
    fn path_validation_rejects_injection_and_ambiguous_root() {
        assert_eq!(
            checked_path(Path::new("relative/path")),
            Err(NativeError::InvalidPath)
        );
        assert_eq!(
            checked_path(Path::new("/tmp/bad\npath")),
            Err(NativeError::InvalidPath)
        );
        assert!(checked_path(Path::new("/tmp/safe")).is_ok());
    }
}

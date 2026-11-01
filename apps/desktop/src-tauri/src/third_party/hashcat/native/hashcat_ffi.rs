//! Versioned, narrow Rust FFI client for CyberDeck's bundled Hashcat C shim.
//! MIT; confidential execution must happen in a separately supervised worker.
//! This module DOES NOT register Tauri IPC or select an engine automatically.
use std::ffi::{c_char, c_int, c_void, CString};
use std::path::Path;
use std::ptr::NonNull;

const ABI_VERSION: u32 = 1;
const MAX_CANDIDATES: u64 = 1_000_000;
const MAX_RUNTIME_SECONDS: u32 = 300;

#[link(name = "cyberdeck_hashcat_shim")]
unsafe extern "C" {
    fn cd_hashcat_abi_version() -> u32;
    fn cd_hashcat_create() -> *mut c_void;
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
        if self.state != InitState::Fresh
            || max_candidates == 0
            || max_candidates > MAX_CANDIDATES
            || runtime_seconds == 0
            || runtime_seconds > MAX_RUNTIME_SECONDS
            || device_id > 128
        {
            return Err(NativeError::InvalidBound);
        }
        let root = checked_path(root)?;
        let hash_file = checked_path(hash_file)?;
        let wordlist_file = checked_path(wordlist_file)?;
        let scratch_outfile = checked_path(scratch_outfile)?;
        let status = unsafe {
            cd_hashcat_prepare_sha256(
                self.handle.as_ptr(),
                root.as_ptr(),
                root.as_ptr(),
                hash_file.as_ptr(),
                wordlist_file.as_ptr(),
                scratch_outfile.as_ptr(),
                max_candidates,
                runtime_seconds,
                device_id,
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

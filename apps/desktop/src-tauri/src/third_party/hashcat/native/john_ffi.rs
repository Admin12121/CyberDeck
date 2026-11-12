//! Versioned, narrow Rust FFI client for CyberDeck's bundled john DLL shim.
//! GPLv2 upstream (john), MIT for this glue; confidential execution must
//! happen in a separately supervised worker process (`john_worker.rs` —
//! john's `exit()` inside `cd_john_main` terminates the CALLING process, so
//! the app process must never call it in-process).
//! This module DOES NOT register Tauri IPC or select an engine automatically.
//! Compiled only as a `#[path]` module of `john_worker.rs` (the supervised
//! helper), never in the app crate's module tree: the raw-dylib import table
//! makes `john.dll` a process-load-time requirement.
use std::ffi::{c_char, c_int, CString};

/// One argv item: the worker passes at most this many strings to
/// `cd_john_main` (john.exe path + flags + operand). The recovery runner
/// constructs at most 9; the bound is deliberately generous but fixed.
pub const MAX_ARGC: usize = 64;
/// One argv item's byte bound, mirroring the hashcat worker's MAX_PATH.
pub const MAX_ARG_LENGTH: usize = 4096;

// Windows MSVC does not link a MinGW-produced DLL directly without an
// import .lib. Rust raw-dylib generates its own import library from the
// fixed C ABI (same pattern as hashcat_ffi.rs), so the supervised helper
// links the bundled john.dll without an import-library conversion tool.
// At runtime the loader finds "john.dll" in the helper's own directory.
#[cfg_attr(target_os = "windows", link(name = "john", kind = "raw-dylib"))]
#[cfg_attr(not(target_os = "windows"), link(name = "john"))]
unsafe extern "C" {
    /// john's real `main` (john.c:2002, not renamed by the shim). Returns
    /// john's exit status when it returns; any internal `exit()` terminates
    /// the calling process with that status instead — the helper treats both
    /// as the session outcome (documented exit-code-as-outcome contract).
    fn cd_john_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// JTR_GIT_VERSION from the pinned source's version.h — the exact string
    /// john.exe --list=build-info prints on its "Version:" line.
    #[link_name = "cd_john_version"]
    fn cd_john_version() -> *const c_char;
}

#[derive(Debug, PartialEq, Eq)]
pub enum NativeError {
    /// cd_john_version() returned no readable string.
    VersionUnavailable,
    /// An argv item broke the bounds: empty, oversized, or carrying a
    /// control character (flags/paths come from the supervising process).
    InvalidArgv,
    /// An argv item could not be represented as a NUL-terminated C string.
    AllocationFailed,
}

/// Validate one argv item the way hashcat_ffi.rs's checked_path validates
/// paths, minus the absolute/leading-dash rules that would wrongly reject
/// john flags (`--pot=...`) and relative resources the supervising process
/// constructs from worker-owned scratch files.
pub fn checked_arg_item(item: &str) -> Result<CString, NativeError> {
    if item.is_empty()
        || item.len() > MAX_ARG_LENGTH
        || item.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(NativeError::InvalidArgv);
    }
    CString::new(item).map_err(|_| NativeError::AllocationFailed)
}

/// Probe the pinned engine's version string. Never target data: it is the
/// exact `Version:` line john.exe --list=build-info prints.
pub fn engine_version() -> Result<String, NativeError> {
    unsafe {
        let pointer = cd_john_version();
        if pointer.is_null() {
            return Err(NativeError::VersionUnavailable);
        }
        let text = std::ffi::CStr::from_ptr(pointer)
            .to_str()
            .map_err(|_| NativeError::VersionUnavailable)?;
        if text.is_empty() {
            return Err(NativeError::VersionUnavailable);
        }
        Ok(text.to_string())
    }
}

/// Validate and stage the whole frame as writable C argv buffers. Writable
/// buffers are REQUIRED: john mutates argv[0] in place (strlwr + ".exe"
/// truncation, john.c:2032-2034; proven by C:\Dev\john-build\probe\probe-bi.c).
pub fn build_argv(items: &[String]) -> Result<(c_int, Vec<CString>), NativeError> {
    if items.is_empty() || items.len() > MAX_ARGC {
        return Err(NativeError::InvalidArgv);
    }
    let mut argv = Vec::with_capacity(items.len());
    for item in items {
        argv.push(checked_arg_item(item)?);
    }
    Ok((items.len() as c_int, argv))
}

/// Run one john CLI session with the given argv (item 0 = program path).
/// Blocking; never call on Tauri's UI/main thread. When this returns, john
/// ran to completion and the return value is its exit status; when john
/// `exit()`s first, this call never returns and the process dies with that
/// status — the helper's documented contract either way.
///
/// # Safety
/// argv must come from build_argv() so every pointer is a valid, writable,
/// NUL-terminated C string for the duration of the call; john mutates the
/// buffers and may terminate the process.
pub unsafe fn run_session(argc: c_int, argv: &mut [CString]) -> Result<i32, NativeError> {
    if argc as usize != argv.len() || argv.is_empty() {
        return Err(NativeError::InvalidArgv);
    }
    let mut pointers: Vec<*mut c_char> = argv.iter_mut().map(|item| item.as_ptr() as *mut c_char).collect();
    pointers.push(std::ptr::null_mut());
    Ok(cd_john_main(argc, pointers.as_mut_ptr()))
}

//! CyberDeck private embedded Hashcat process. Not a general command-line
//! adapter. A supervising, case-authorized Tauri backend owns every request.
//! Protocol is fixed/binary; secrets do not appear in argv or stdout.
//! SPDX-License-Identifier: MIT

#[path = "hashcat_ffi.rs"]
mod hashcat_ffi;

use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"CDHC0001";
const MAX_PATH: usize = 4096;
const MAX_CANDIDATES: u64 = 1_000_000;
const MAX_SECONDS: u32 = 300;

struct Request {
    max_candidates: u64,
    max_seconds: u32,
    device_id: u32,
    root: PathBuf,
    hash_file: PathBuf,
    wordlist_file: PathBuf,
    outfile: PathBuf,
}

fn read_exact<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut output = [0u8; N];
    reader.read_exact(&mut output)?;
    Ok(output)
}

fn checked_path(reader: &mut impl Read) -> io::Result<PathBuf> {
    let length = u16::from_le_bytes(read_exact::<2>(reader)?) as usize;
    if length == 0 || length > MAX_PATH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid path length",
        ));
    }
    let mut raw = vec![0u8; length];
    reader.read_exact(&mut raw)?;
    let string = String::from_utf8(raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 path"))?;
    if string.bytes().any(|b| b < 32 || b == 127) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control character in path",
        ));
    }
    let path = PathBuf::from(string);
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "relative path"));
    }
    Ok(path)
}

fn read_request(mut reader: impl Read) -> io::Result<Request> {
    if &read_exact::<8>(&mut reader)? != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported worker protocol",
        ));
    }
    let max_candidates = u64::from_le_bytes(read_exact::<8>(&mut reader)?);
    let max_seconds = u32::from_le_bytes(read_exact::<4>(&mut reader)?);
    let device_id = u32::from_le_bytes(read_exact::<4>(&mut reader)?);
    if !(1..=MAX_CANDIDATES).contains(&max_candidates)
        || !(1..=MAX_SECONDS).contains(&max_seconds)
        || device_id > 128
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid work bounds",
        ));
    }
    let request = Request {
        max_candidates,
        max_seconds,
        device_id,
        root: checked_path(&mut reader)?,
        hash_file: checked_path(&mut reader)?,
        wordlist_file: checked_path(&mut reader)?,
        outfile: checked_path(&mut reader)?,
    };
    // Refuse inline configuration/suffix smuggling after the four paths.
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected protocol bytes",
        ));
    }
    Ok(request)
}

fn validate_paths(req: &Request) -> io::Result<()> {
    for path in [&req.root, &req.hash_file, &req.wordlist_file] {
        if !path.is_absolute() || !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "input or runtime unavailable",
            ));
        }
    }
    if !req.root.is_dir() || !req.hash_file.is_file() || !req.wordlist_file.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wrong input file type",
        ));
    }
    if req.outfile.exists() || !req.outfile.parent().is_some_and(Path::is_dir) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "scratch output is not private",
        ));
    }
    Ok(())
}

/// Stable numeric child exit statuses: never carry hashes, plaintext,
/// paths, vendor driver strings or other sensitive data in IPC/logs.
fn native_failure(error: hashcat_ffi::NativeError) -> i32 {
    match error {
        hashcat_ffi::NativeError::AbiMismatch => 21,
        hashcat_ffi::NativeError::AllocationFailed => 22,
        hashcat_ffi::NativeError::InvalidBound => 23,
        hashcat_ffi::NativeError::InvalidPath => 24,
        hashcat_ffi::NativeError::Native(-3) => 31, // mode-options initialization
        hashcat_ffi::NativeError::Native(-41) => 32, // upstream option parsing
        hashcat_ffi::NativeError::Native(-42) => 33, // upstream option validation
        hashcat_ffi::NativeError::Native(-5) => 34, // other native session init
        hashcat_ffi::NativeError::Native(-51) => 36, // native bridge setup
        hashcat_ffi::NativeError::Native(-52) => 37, // compute runtime loader
        hashcat_ffi::NativeError::Native(-53) => 38, // compute device discovery/init
        hashcat_ffi::NativeError::Native(-54) => 39, // after device init
        hashcat_ffi::NativeError::Native(_) => 35,
    }
}

fn run() -> Result<(), i32> {
    let request = read_request(io::stdin().lock()).map_err(|_| 10)?;
    validate_paths(&request).map_err(|_| 11)?;
    let mut engine = hashcat_ffi::NativeHashcat::new().map_err(native_failure)?;
    engine
        .prepare_sha256(
            &request.root,
            &request.hash_file,
            &request.wordlist_file,
            &request.outfile,
            request.max_candidates,
            request.max_seconds,
            request.device_id,
        )
        .map_err(native_failure)?;
    match engine.execute() {
        Ok(0 | 1) => Ok(()), // completed with match or exhausted without match
        Ok(_) => Err(40),
        Err(error) => Err(native_failure(error)),
    }
}

fn main() {
    // A supervising Tauri process redirects stdout/stderr to null. Only
    // bounded numeric status is returned, never raw candidates or target data.
    if let Err(status) = run() {
        std::process::exit(status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame() -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&123u64.to_le_bytes());
        out.extend_from_slice(&30u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        for path in ["/tmp/root", "/tmp/hash", "/tmp/wordlist", "/tmp/out"] {
            out.extend_from_slice(&(path.len() as u16).to_le_bytes());
            out.extend_from_slice(path.as_bytes());
        }
        out
    }
    #[test]
    fn native_init_phase_codes_never_expose_untrusted_log_content() {
        for (raw, expected) in [(-51, 36), (-52, 37), (-53, 38), (-54, 39), (-5, 34)] {
            assert_eq!(
                native_failure(hashcat_ffi::NativeError::Native(raw)),
                expected
            );
        }
    }

    #[test]
    fn protocol_accepts_only_versioned_bounded_frames() {
        let good = read_request(Cursor::new(frame())).unwrap();
        assert_eq!(good.max_candidates, 123);
        assert_eq!(good.device_id, 0);
        let mut broken = frame();
        broken[0] = b'X';
        assert!(read_request(Cursor::new(broken)).is_err());
        let mut broken = frame();
        broken[8..16].copy_from_slice(&0u64.to_le_bytes());
        assert!(read_request(Cursor::new(broken)).is_err());
        let mut broken = frame();
        broken.push(0);
        assert!(read_request(Cursor::new(broken)).is_err());
    }
    #[test]
    fn protocol_rejects_relative_or_oversized_paths() {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&1u64.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&3u16.to_le_bytes());
        input.extend_from_slice(b"abc");
        assert!(read_request(Cursor::new(input)).is_err());
    }
}

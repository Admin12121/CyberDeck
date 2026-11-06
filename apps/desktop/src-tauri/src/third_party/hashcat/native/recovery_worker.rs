//! CyberDeck private embedded Hashcat process. Not a general command-line
//! adapter. A supervising, case-authorized Tauri backend owns every request.
//! Protocol is fixed/binary; secrets do not appear in argv or stdout.
//! SPDX-License-Identifier: MIT

#[path = "hashcat_ffi.rs"]
mod hashcat_ffi;

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAGIC: &[u8; 8] = b"CDHC0001";
const MAGIC_MULTI_MODE: &[u8; 8] = b"CDHC0002";
const MAGIC_PROGRESS: &[u8; 8] = b"CDHC0003";
const MAX_PATH: usize = 4096;
const MAX_CANDIDATES: u64 = 1_000_000;
const MAX_SECONDS: u32 = 300;
/// Progress frames are emitted at this cadence while a native session runs.
const PROGRESS_INTERVAL_MS: u32 = 500;

struct Request {
    max_candidates: u64,
    max_seconds: u32,
    device_id: u32,
    hash_mode: u32,
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
    let version = read_exact::<8>(&mut reader)?;
    if &version != MAGIC && &version != MAGIC_MULTI_MODE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported worker protocol",
        ));
    }
    let max_candidates = u64::from_le_bytes(read_exact::<8>(&mut reader)?);
    let max_seconds = u32::from_le_bytes(read_exact::<4>(&mut reader)?);
    let device_id = u32::from_le_bytes(read_exact::<4>(&mut reader)?);
    let hash_mode = if &version == MAGIC_MULTI_MODE {
        u32::from_le_bytes(read_exact::<4>(&mut reader)?)
    } else {
        1400
    };
    if !matches!(
        hash_mode,
        0 | 10 | 20 | 50 | 60 | 100 | 110 | 120 | 132 | 400 | 500 | 1000 | 1100 | 1400 | 1500
        | 1700 | 1731 | 1800 | 2100 | 3200 | 5500 | 5600 | 7400
        | 11600 | 13600 | 17200 | 17210
        | 9400 | 9600 | 9700 | 10400 | 10500
        | 11300 | 13400 | 15600 | 15700
        | 13100 | 18200 | 22100
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported hash mode",
        ));
    }
    if !(1..=MAX_CANDIDATES).contains(&max_candidates)
        || !(1..=MAX_SECONDS).contains(&max_seconds)
        || device_id > 128
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid work bounds",
        ));
    }
    eprintln!("[wk] frame parsed");
    let request = Request {
        max_candidates,
        max_seconds,
        device_id,
        hash_mode,
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

/// CDHC0003 progress frame: 8 ASCII magic bytes + u64 tried + u64 budget +
/// u32 cracked, little-endian. Aggregate counters only, never candidate,
/// hash or device data. One unbuffered write per frame; failures are
/// tolerated silently because the supervising process may run stdout=null.
fn write_progress_frame(tried: u64, budget: u64, cracked: u32) {
    let mut frame = [0u8; 28];
    frame[..8].copy_from_slice(MAGIC_PROGRESS);
    frame[8..16].copy_from_slice(&tried.to_le_bytes());
    frame[16..24].copy_from_slice(&budget.to_le_bytes());
    frame[24..28].copy_from_slice(&cracked.to_le_bytes());
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = handle.write_all(&frame);
    let _ = handle.flush();
}

fn run() -> Result<(), i32> {
    eprintln!("[wk] frame read start");
    let request = read_request(io::stdin().lock()).map_err(|_| 10)?;
    eprintln!("[wk] validating");
    validate_paths(&request).map_err(|_| 11)?;
    eprintln!("[wk] validated");
    eprintln!("[wk] calling create");
    let mut engine = hashcat_ffi::NativeHashcat::new().map_err(native_failure)?;
    eprintln!("[wk] created");
    engine
        .prepare_mode(
            &request.root,
            &request.hash_file,
            &request.wordlist_file,
            &request.outfile,
            request.max_candidates,
            request.max_seconds,
            request.device_id,
            request.hash_mode,
        )
        .map_err(native_failure)?;
    engine.execute_async().map_err(native_failure)?;
    // The bounded finish wait doubles as the poll cadence: while the session
    // still runs after each interval, report the latest self-reported
    // snapshot as a CDHC0003 frame, then wait again.
    let final_status = loop {
        match engine.execute_finish(PROGRESS_INTERVAL_MS) {
            Ok(status) => break status,
            Err(hashcat_ffi::NativeError::Native(-2)) => {
                if let Ok(Some((tried, budget, cracked))) = engine.poll_status() {
                    write_progress_frame(tried, budget, cracked);
                }
            }
            Err(hashcat_ffi::NativeError::Native(-1)) => break -1,
            Err(error) => return Err(native_failure(error)),
        }
    };
    match final_status {
        0 | 1 => Ok(()), // completed with match or exhausted without match
        other => {
            eprintln!(
                "diag: shim_version={} last_event={:?} trace={:?}",
                hashcat_ffi::NativeHashcat::shim_version(),
                hashcat_ffi::NativeHashcat::last_event(),
                hashcat_ffi::NativeHashcat::event_trace()
            );
            Err(40 + other.abs().clamp(0, 50))
        }
    }
}

fn main() {
    // The only accepted control argument is a fixed, non-secret loader probe.
    // This does not initialize a cracking session, read evidence or print
    // arbitrary driver messages. All other CLI arguments are prohibited.
    let mut args = std::env::args_os().skip(1);
    if let Some(flag) = args.next() {
        if flag == "--probe-opencl-loader" && args.next().is_none() {
            std::process::exit(if hashcat_ffi::NativeHashcat::opencl_loader_available() {
                0
            } else {
                37
            });
        }
        std::process::exit(10);
    }
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
        assert_eq!(good.hash_mode, 1400);
        for mode in [0_u32, 100, 1000, 1400, 1700] {
            let mut frame2 = frame();
            frame2[..8].copy_from_slice(MAGIC_MULTI_MODE);
            frame2.splice(24..24, mode.to_le_bytes());
            let parsed = read_request(Cursor::new(frame2)).unwrap();
            assert_eq!(parsed.hash_mode, mode);
        }
        let mut unknown = frame();
        unknown[..8].copy_from_slice(MAGIC_MULTI_MODE);
        unknown.splice(24..24, 99999_u32.to_le_bytes());
        assert!(read_request(Cursor::new(unknown)).is_err());
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

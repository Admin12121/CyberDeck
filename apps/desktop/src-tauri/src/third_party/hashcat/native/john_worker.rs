//! CyberDeck private embedded john worker. Not a general john CLI adapter.
//! A supervising, case-authorized Tauri backend owns every request. The
//! request arrives as a versioned, bounded binary frame on stdin (no
//! secrets in argv); john's own stdout/stderr pipes stay inherited so the
//! supervisor parses its status lines exactly like the john.exe sidecar.
//! SPDX-License-Identifier: MIT
//!
//! Isolation contract (same model as the hashcat recovery worker): john's
//! `exit()` inside `cd_john_main` terminates the CALLING process, so the app
//! never calls it in-process — this helper process does, and its exit status
//! IS the session outcome whether john returns or exits (documented
//! exit-code-as-outcome contract, proven by C:\Dev\john-build\probe).

#[path = "john_ffi.rs"]
mod john_ffi;

use std::io::{self, Read};
use std::path::Path;

/// Versioned worker frame: 8 ASCII magic bytes + u16 item count + per item
/// (u16 byte length + UTF-8 bytes), little-endian. Item 0 is the bundled
/// john.exe path: john dispatches on its basename (john.c:2002-2034) and
/// resolves $JOHN (john.conf, run/ resources) from it (path.c:118-134).
const MAGIC: &[u8; 8] = b"CDJW0001";
/// Stable numeric child exit statuses: never carry hashes, plaintext,
/// paths or other sensitive data in IPC/logs.
const EXIT_BAD_FRAME: i32 = 10;
/// The fixed loader probe failed: cd_john_version() yielded no string.
const EXIT_PROBE_FAILED: i32 = 39;

/// UCRT host-process compatibility for the MinGW-built john DLL.
///
/// The DLL was built and baseline-verified under MinGW host processes
/// (UCRT64 gcc probe exes: C:\Dev\john-build\probe). MinGW's CRT startup
/// installs a lenient UCRT invalid-parameter handler, so upstream's
/// `setvbuf(stdout, NULL, _IOLBF, 0)` (john.c:1616 — john's own _MSC_VER
/// comment documents that this call "fails setvbuf, but execution
/// continues") merely fails-and-continues there. A default MSVC host
/// (this worker's rustc target) leaves UCRT's default handler active and
/// the same call fail-fasts with 0xc0000409 mid-session. Installing the
/// same lenient handler in this helper process reproduces the proven
/// MinGW-host semantics; it affects UCRT validation inside this
/// supervised worker only, never the supervising app process.
#[cfg(windows)]
mod ucrt_host_compat {
    type InvalidParameterHandler = unsafe extern "C" fn(
        expression: *const u16,
        function_name: *const u16,
        file_name: *const u16,
        line_number: u32,
        reserved: usize,
    );
    extern "system" {
        fn _set_invalid_parameter_handler(
            handler: Option<InvalidParameterHandler>,
        ) -> Option<InvalidParameterHandler>;
    }
    unsafe extern "C" fn lenient_handler(
        _expression: *const u16,
        _function_name: *const u16,
        _file_name: *const u16,
        _line_number: u32,
        _reserved: usize,
    ) {
    }
    pub fn install_lenient_ucrt_validation() {
        unsafe {
            _set_invalid_parameter_handler(Some(lenient_handler));
        }
    }
}

struct Frame {
    items: Vec<String>,
}

fn read_exact<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut output = [0u8; N];
    reader.read_exact(&mut output)?;
    Ok(output)
}

fn read_frame(mut reader: impl Read) -> io::Result<Frame> {
    let magic = read_exact::<8>(&mut reader)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported worker protocol",
        ));
    }
    let count = u16::from_le_bytes(read_exact::<2>(&mut reader)?) as usize;
    if count == 0 || count > john_ffi::MAX_ARGC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid argv item count",
        ));
    }
    let mut items = Vec::with_capacity(count);
    for index in 0..count {
        let length = u16::from_le_bytes(read_exact::<2>(&mut reader)?) as usize;
        if length == 0 || length > john_ffi::MAX_ARG_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid argv item length",
            ));
        }
        let mut raw = vec![0u8; length];
        reader.read_exact(&mut raw)?;
        let string = String::from_utf8(raw).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 argv item")
        })?;
        if string.bytes().any(|b| b < 32 || b == 127) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control character in argv item",
            ));
        }
        if index == 0 && !Path::new(&string).is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relative program path",
            ));
        }
        items.push(string);
    }
    // Refuse inline frame smuggling after the declared items.
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected protocol bytes",
        ));
    }
    Ok(Frame { items })
}

fn run() -> Result<i32, i32> {
    let frame = read_frame(io::stdin().lock()).map_err(|_| EXIT_BAD_FRAME)?;
    eprintln!("[jw] frame parsed ({} items)", frame.items.len());
    #[cfg(windows)]
    ucrt_host_compat::install_lenient_ucrt_validation();
    let (argc, mut argv) = john_ffi::build_argv(&frame.items).map_err(|_| EXIT_BAD_FRAME)?;
    eprintln!("[jw] running john session; exit() inside is the documented outcome");
    // The one native call. On return, the i32 is john's exit status; on an
    // internal exit() this line never completes and the process dies with
    // john's status instead. Both are the session outcome.
    let status = unsafe { john_ffi::run_session(argc, &mut argv) }.map_err(|_| EXIT_BAD_FRAME)?;
    eprintln!("[jw] session returned {status}");
    Ok(status)
}

fn main() {
    // The only accepted control argument is a fixed, non-secret loader
    // probe. This does not initialize a cracking session, read evidence or
    // print arbitrary engine output. All other CLI arguments are prohibited.
    let mut args = std::env::args_os().skip(1);
    if let Some(flag) = args.next() {
        if flag == "--probe-john-version" && args.next().is_none() {
            std::process::exit(match john_ffi::engine_version() {
                Ok(version) if !version.is_empty() => 0,
                _ => EXIT_PROBE_FAILED,
            });
        }
        std::process::exit(EXIT_BAD_FRAME);
    }
    // The supervising Tauri process pipes stdout/stderr; john's own output
    // flows through, but only bounded numeric status is interpreted by the
    // supervisor, never raw candidates or target data.
    match run() {
        Ok(status) => std::process::exit(status),
        Err(status) => std::process::exit(status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(items: &[&str]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&(items.len() as u16).to_le_bytes());
        for item in items {
            out.extend_from_slice(&(item.len() as u16).to_le_bytes());
            out.extend_from_slice(item.as_bytes());
        }
        out
    }

    #[test]
    fn frame_accepts_a_bounded_item_list() {
        let parsed = read_frame(Cursor::new(frame(&[
            "C:\\engines\\john.exe",
            "--format=crypt",
            "--pot=C:\\scratch\\p.pot",
        ])))
        .unwrap();
        assert_eq!(parsed.items.len(), 3);
        assert_eq!(parsed.items[0], "C:\\engines\\john.exe");
    }

    #[test]
    fn frame_rejects_unknown_magic_counts_and_trailing_bytes() {
        let mut unknown = frame(&["C:\\engines\\john.exe", "--show"]);
        unknown[0] = b'X';
        assert!(read_frame(Cursor::new(unknown)).is_err());
        // Count 0
        assert!(read_frame(Cursor::new(MAGIC.to_vec())).is_err());
        let mut smuggled = frame(&["C:\\engines\\john.exe", "--show"]);
        smuggled.push(0);
        assert!(read_frame(Cursor::new(smuggled)).is_err());
    }

    #[test]
    fn frame_rejects_oversized_or_control_character_items() {
        let long = "x".repeat(john_ffi::MAX_ARG_LENGTH + 1);
        let mut oversized = frame(&["C:\\engines\\john.exe", &long]);
        let count_index = 8;
        oversized[count_index..count_index + 2].copy_from_slice(&2u16.to_le_bytes());
        assert!(read_frame(Cursor::new(oversized)).is_err());
        let injected = frame(&["C:\\engines\\john.exe", "--pot=a\nb"]);
        assert!(read_frame(Cursor::new(injected)).is_err());
    }

    #[test]
    fn frame_requires_an_absolute_program_path() {
        let relative = frame(&["john.exe", "--show"]);
        assert!(read_frame(Cursor::new(relative)).is_err());
        let absolute = frame(&["C:\\engines\\john.exe", "--show"]);
        assert!(read_frame(Cursor::new(absolute)).is_ok());
    }

    #[test]
    fn argv_staging_uses_writable_c_strings_with_bounds() {
        let items = vec![
            "C:\\engines\\john.exe".to_string(),
            "--format=crypt".to_string(),
        ];
        let (argc, argv) = john_ffi::build_argv(&items).unwrap();
        assert_eq!(argc, 2);
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[0].to_bytes(), b"C:\\engines\\john.exe");
        // Over the fixed argv bound
        let too_many: Vec<String> = (0..=john_ffi::MAX_ARGC).map(|i| format!("--flag{i}")).collect();
        assert_eq!(
            john_ffi::build_argv(&too_many),
            Err(john_ffi::NativeError::InvalidArgv)
        );
        assert_eq!(
            john_ffi::build_argv(&[]),
            Err(john_ffi::NativeError::InvalidArgv)
        );
    }

    #[test]
    fn arg_items_reject_control_characters_but_keep_john_flags() {
        assert!(john_ffi::checked_arg_item("--progress-every=2").is_ok());
        assert!(john_ffi::checked_arg_item("--pot=C:\\scratch\\p.pot").is_ok());
        assert_eq!(
            john_ffi::checked_arg_item("bad\nnewline"),
            Err(john_ffi::NativeError::InvalidArgv)
        );
        assert_eq!(
            john_ffi::checked_arg_item("bad\x7fdel"),
            Err(john_ffi::NativeError::InvalidArgv)
        );
        assert_eq!(
            john_ffi::checked_arg_item(""),
            Err(john_ffi::NativeError::InvalidArgv)
        );
    }

    #[test]
    fn program_path_must_be_absolute_filesystem_path() {
        let absolute = if cfg!(windows) {
            std::path::PathBuf::from("C:\\engines\\john.exe")
        } else {
            std::path::PathBuf::from("/opt/engines/john")
        };
        assert!(john_ffi::checked_arg_item(&absolute.to_string_lossy()).is_ok());
        assert!(!Path::new("john.exe").is_absolute());
        assert!(absolute.is_absolute());
    }
}

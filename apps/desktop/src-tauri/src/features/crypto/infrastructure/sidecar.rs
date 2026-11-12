//! Pure host-process adapters for optional Hashcat and John executables.
//! This module owns process arguments, captured output, scratch files and parsing.
//! Desktop dialogs, IPC and evidence persistence remain in the root controller.
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant};

use super::engine_formats::{parse_hashcat_outfile, parse_john_show};
use super::process::{collect_bounded, run_with_timeout};
use super::scratch::ScratchDir;
use crate::features::crypto::ipc::attack::AttackMatch;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_REPORTED_MATCHES: usize = 100;

/// Honest wall-clock bound for one recovery sidecar stage, matching the
/// Engines-panel sidecar timeout precedent above (`PROCESS_TIMEOUT`).
pub const JOHN_RECOVERY_TIMEOUT: Duration = Duration::from_secs(300);

/// Bounded diagnostic capture for one sidecar run, matching the engine
/// adapters' capture bound in `process.rs`.
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Bounded wall-clock wait for the isolated-pot `--show` extraction.
const SHOW_TIMEOUT: Duration = Duration::from_secs(30);

/// Binary name of the supervised john DLL worker helper (platform suffix is
/// appended by the resolver). It is compiled from
/// `third_party/hashcat/native/john_worker.rs` by `build-john-worker.mjs`
/// and bundled beside john.dll in the engines resource directory.
pub const JOHN_WORKER_BINARY: &str = "cyberdeck-john-worker";

/// Versioned worker frame (`john_worker.rs`, `CDJW0001`): 8-byte magic +
/// u16 item count + per item (u16 byte length + UTF-8 bytes). Item 0 is the
/// bundled john.exe path. Bounds mirror the worker's own validation; paths
/// travel as UTF-8 (john jumbo's internal encoding), not ANSI command-line
/// recoding, so non-ASCII scratch paths behave consistently.
fn worker_frame(john_exe: &Path, args: &[String]) -> Result<Vec<u8>, String> {
    const MAX_ITEMS: usize = 64;
    const MAX_ITEM_BYTES: usize = 4096;
    let program = john_exe
        .to_str()
        .ok_or("the john.exe path is not valid UTF-8")?;
    let items = std::iter::once(program).chain(args.iter().map(String::as_str));
    let count = 1 + args.len();
    if count > MAX_ITEMS {
        return Err("john worker frame exceeds the argv bound".into());
    }
    let mut frame = Vec::with_capacity(10 + count * 2);
    frame.extend_from_slice(b"CDJW0001");
    frame.extend_from_slice(&(count as u16).to_le_bytes());
    for item in items {
        if item.is_empty() || item.len() > MAX_ITEM_BYTES {
            return Err("john worker frame item exceeds the length bound".into());
        }
        frame.extend_from_slice(&(item.len() as u16).to_le_bytes());
        frame.extend_from_slice(item.as_bytes());
    }
    Ok(frame)
}

/// How one recovery sidecar stage runs john.
pub enum JohnSidecarEngine {
    /// john.exe CLI spawn — the CI stub path and the fallback when no DLL
    /// bundle is present.
    Exe(PathBuf),
    /// john.dll loaded in-process by the supervised worker helper
    /// (`JOHN_WORKER_BINARY`), the primary engine when bundled. The helper
    /// exists because john's `exit()` inside `cd_john_main` terminates the
    /// CALLING process (C:\Dev\john-build\probe\probe-bi.c contract): it
    /// kills only the helper, never the app — the same isolation model as
    /// the hashcat recovery worker. `john_exe` is the bundled john.exe whose
    /// absolute path becomes the frame's item 0 so john dispatches on its
    /// basename (john.c:2002-2034) and resolves $JOHN/john.conf exactly as
    /// the exe spawn does (path.c:118-134).
    Dll { worker: PathBuf, john_exe: PathBuf },
}

/// Spawn one sidecar session: the exe branch is a plain john.exe CLI spawn,
/// the DLL branch feeds the same argv to the worker helper as a CDJW0001
/// frame and closes stdin (EOF delimits the frame). stdout/stderr stay
/// inherited pipes in both branches so the supervision loop below parses
/// john's own status lines identically.
fn spawn_sidecar(engine: &JohnSidecarEngine, args: &[String]) -> Result<Child, String> {
    match engine {
        JohnSidecarEngine::Exe(binary) => {
            let mut command = Command::new(binary);
            command
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null());
            command
                .spawn()
                .map_err(|e| format!("cannot start john sidecar: {e}"))
        }
        JohnSidecarEngine::Dll { worker, john_exe } => {
            let frame = worker_frame(john_exe, args)?;
            let mut command = Command::new(worker);
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::piped());
            let mut child = command
                .spawn()
                .map_err(|e| format!("cannot start the john worker helper: {e}"))?;
            let mut stdin = child
                .stdin
                .take()
                .ok_or("the john worker helper stdin was unavailable")?;
            let write = stdin.write_all(&frame);
            drop(stdin);
            if let Err(e) = write {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot send the john worker frame: {e}"));
            }
            Ok(child)
        }
    }
}

/// Run the isolated-pot `--show` extraction through the same engine branch
/// as the crack session, returning (exit status, bounded stdout capture).
fn john_show_run(
    engine: &JohnSidecarEngine,
    args: &[String],
) -> Result<(ExitStatus, Vec<u8>), String> {
    match engine {
        JohnSidecarEngine::Exe(binary) => {
            let mut command = Command::new(binary);
            command.args(args);
            let (status, stdout, _) = run_with_timeout(command, SHOW_TIMEOUT)?;
            Ok((status, stdout))
        }
        JohnSidecarEngine::Dll { worker, john_exe } => {
            let frame = worker_frame(john_exe, args)?;
            let mut command = Command::new(worker);
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::piped());
            let mut child = command
                .spawn()
                .map_err(|e| format!("cannot start the john worker helper: {e}"))?;
            let mut stdin = child
                .stdin
                .take()
                .ok_or("the john worker helper stdin was unavailable")?;
            let write = stdin.write_all(&frame);
            drop(stdin);
            if let Err(e) = write {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot send the john worker frame: {e}"));
            }
            let stdout_capture = child.stdout.take().map(collect_bounded);
            let stderr_capture = child.stderr.take().map(collect_bounded);
            let started = Instant::now();
            let mut timed_out = false;
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) if started.elapsed() >= SHOW_TIMEOUT => {
                        timed_out = true;
                        let _ = child.kill();
                        break child.wait().map_err(|e| e.to_string())?;
                    }
                    Ok(None) => thread::sleep(Duration::from_millis(25)),
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!("cannot await the john worker helper: {e}"));
                    }
                }
            };
            let stdout = stdout_capture
                .and_then(|handle| handle.join().ok())
                .unwrap_or_default();
            // Bounded stderr capture of the show run: drained, never parsed.
            let _stderr = stderr_capture
                .and_then(|handle| handle.join().ok())
                .unwrap_or_default();
            if timed_out {
                return Err(format!(
                    "john --show exceeded the {}s timeout; output discarded",
                    SHOW_TIMEOUT.as_secs()
                ));
            }
            Ok((status, stdout))
        }
    }
}

pub struct EngineRun {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub matches: Vec<AttackMatch>,
}

pub fn hashcat(
    binary: &Path,
    hash_mode: u32,
    target: &str,
    mode: &str,
    mask: Option<&str>,
    wordlist: Option<&Path>,
    rules: Option<&Path>,
    scratch: &ScratchDir,
) -> Result<EngineRun, String> {
    let hash_file = scratch.write_hash_file(target)?;
    let outfile = scratch.join("hashcat.out");
    let mut command = Command::new(binary);
    command
        .arg("-m")
        .arg(hash_mode.to_string())
        .arg("--potfile-disable")
        .arg("-o")
        .arg(&outfile);
    match mode {
        "mask" => {
            let mask = mask
                .filter(|value| !value.is_empty())
                .ok_or("mask attack needs a mask pattern")?;
            command.arg("-a").arg("3").arg(&hash_file).arg(mask);
        }
        "wordlist" => {
            let path = wordlist.ok_or("wordlist mode requires a selected file")?;
            command.arg("-a").arg("0");
            if let Some(rules_path) = rules {
                command.arg("-r").arg(rules_path);
            }
            command.arg(&hash_file).arg(path);
        }
        _ => return Err("unsupported engine mode".into()),
    }
    let (status, stdout, stderr) = run_with_timeout(command, PROCESS_TIMEOUT)?;
    // The outfile contains recovered passwords. Bound its size before parsing.
    let output_text = match std::fs::metadata(&outfile) {
        Ok(meta) if meta.len() > 4 * 1024 * 1024 => {
            return Err("hashcat output exceeds the 4 MiB safety limit".into());
        }
        Ok(_) => std::fs::read_to_string(&outfile)
            .map_err(|e| format!("cannot read hashcat output: {e}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot inspect hashcat output: {error}")),
    };
    let mut matches = parse_hashcat_outfile(&output_text);
    matches.truncate(MAX_REPORTED_MATCHES);
    Ok(EngineRun {
        status,
        stdout,
        stderr,
        matches,
    })
}

pub fn john(
    binary: &Path,
    format: &str,
    target: &str,
    wordlist: &Path,
    scratch: &ScratchDir,
) -> Result<EngineRun, String> {
    let hash_file = scratch.write_hash_file(target)?;
    let potfile = scratch.join("john.pot");
    let session = scratch.join("john-session");
    let mut command = Command::new(binary);
    command
        .arg(format!("--pot={}", potfile.display()))
        .arg(format!("--session={}", session.display()))
        .arg(format!("--format={format}"))
        .arg(format!("--wordlist={}", wordlist.display()))
        .arg(&hash_file);
    let (status, stdout, stderr) = run_with_timeout(command, PROCESS_TIMEOUT)?;

    // Read the isolated pot rather than exposing or modifying the user's
    // existing John password history.
    let mut show = Command::new(binary);
    show.arg("--show")
        .arg(format!("--pot={}", potfile.display()))
        .arg(format!("--format={format}"))
        .arg(&hash_file);
    let (show_status, show_out, _) = run_with_timeout(show, Duration::from_secs(30))?;
    if !show_status.success() {
        return Err("john could not read the isolated result pot".into());
    }
    let mut matches = parse_john_show(&String::from_utf8_lossy(&show_out));
    matches.truncate(MAX_REPORTED_MATCHES);
    Ok(EngineRun {
        status,
        stdout,
        stderr,
        matches,
    })
}

pub fn capture_tail(stdout: &[u8], stderr: &[u8], max_bytes: usize) -> String {
    let mut output = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    if output.len() > max_bytes {
        let mut end = max_bytes;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
    }
    output
}

// --- recovery sidecar stage (autopilot fallback) ----------------------------
//
// The Engines-panel `john()` above runs to completion and reports afterwards.
// The autopilot ladder needs more: live progress streaming, cooperative
// cancellation and an honest timeout, while keeping the same isolated pot and
// `--show` result-extraction pattern.

/// One parsed john stderr status line (`src/status.c`, the periodic output of
/// `--progress-every=N`): `<g>g <elapsed> <progress> <g/s> <p/s> <c/s> ...`.
/// The guess count is exact; the percent is john's own keyspace progress.
#[derive(Debug, Clone, PartialEq)]
pub struct JohnStatusLine {
    pub guesses: u64,
    pub percent: Option<f64>,
}

/// Parse a john status line. Returns None for every non-status stderr line
/// (format banners, warnings, load errors) so callers only stream real ticks.
pub fn parse_john_status_line(line: &str) -> Option<JohnStatusLine> {
    let trimmed = line.trim();
    let first = trimmed.split_whitespace().next()?;
    let guesses: u64 = first.strip_suffix('g')?.parse().ok()?;
    let mut percent = None;
    for token in trimmed.split_whitespace() {
        if token == "DONE" {
            percent = Some(100.0);
            break;
        }
        if let Some(value) = token.strip_suffix('%') {
            if let Ok(parsed) = value.parse::<f64>() {
                percent = Some(parsed.clamp(0.0, 100.0));
                break;
            }
        }
    }
    Some(JohnStatusLine { guesses, percent })
}

/// Collect hash:plain pairs from `john --show`, keeping the hash so the
/// caller can map a pot entry back to its multi-target ordinal.
pub fn parse_john_show_pairs(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|line| {
            line.contains(':') && !line.contains("password hashes") && !line.starts_with('\'')
        })
        .filter_map(|line| {
            let (hash, plain) = line.split_once(':')?;
            (!hash.trim().is_empty() && !plain.trim().is_empty())
                .then(|| (hash.trim().to_string(), plain.trim().to_string()))
        })
        .collect()
}

/// One controlled recovery sidecar run.
#[derive(Debug)]
pub struct JohnRecoveryRun {
    /// false when the run was cancelled (no result pot is read then).
    pub cancelled: bool,
    /// hash:plain pairs recovered into the isolated pot (via `--show`).
    pub matches: Vec<(String, String)>,
}

enum Stop {
    Exit(ExitStatus),
    Cancelled,
    TimedOut,
}

/// Run one recovery sidecar stage: john with a wordlist (plus optional john
/// rules) against a hash file and an isolated pot/session, streaming stderr
/// status lines through `on_status` as they arrive. The child is killed when
/// `is_cancelled` fires or `timeout` elapses; the timeout is reported as an
/// honest error, never swallowed. Match extraction happens through the same
/// `--show`-on-isolated-pot pattern as the Engines-panel adapter above, run
/// through the same engine branch. The DLL branch constructs one identical
/// argv for both sessions and lets the supervised worker helper call
/// `cd_john_main` (its exit status is the session outcome whether john
/// returns or `exit()`s); the exe-spawn path stays as the fallback engine.
#[allow(clippy::too_many_arguments)]
pub fn john_recovery(
    engine: &JohnSidecarEngine,
    format: &str,
    hash_file: &Path,
    wordlist: &Path,
    rules: Option<&Path>,
    pot: &Path,
    session: &Path,
    timeout: Duration,
    is_cancelled: &dyn Fn() -> bool,
    mut on_status: impl FnMut(JohnStatusLine),
) -> Result<JohnRecoveryRun, String> {
    let mut args: Vec<String> = vec![
        format!("--pot={}", pot.display()),
        format!("--session={}", session.display()),
        format!("--format={format}"),
        // Periodic status.c lines on stderr; this is john's own documented
        // progress hook (`--progress-every`, options.c/signals.c).
        "--progress-every=2".into(),
        format!("--wordlist={}", wordlist.display()),
    ];
    if let Some(rules_path) = rules {
        args.push(format!("--rules={}", rules_path.display()));
    }
    args.push(hash_file.display().to_string());
    let mut child = spawn_sidecar(engine, &args)?;
    let stdout_capture = child.stdout.take().map(collect_bounded);
    let (status_tx, status_rx) = channel::<JohnStatusLine>();
    let stderr_capture = child.stderr.take().map(|stderr| {
        thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut captured: Vec<u8> = Vec::new();
            let mut pending: Vec<u8> = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let remaining = MAX_CAPTURE_BYTES.saturating_sub(captured.len());
                        captured.extend_from_slice(&buffer[..read.min(remaining)]);
                        pending.extend_from_slice(&buffer[..read]);
                        while let Some(pos) = pending.iter().position(|&byte| byte == b'\n') {
                            let line: Vec<u8> = pending.drain(..=pos).collect();
                            let text = String::from_utf8_lossy(&line);
                            if let Some(status) = parse_john_status_line(&text) {
                                if status_tx.send(status).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            if !pending.is_empty() {
                if let Some(status) =
                    parse_john_status_line(&String::from_utf8_lossy(&pending))
                {
                    let _ = status_tx.send(status);
                }
            }
            captured
        })
    });

    let started = Instant::now();
    let stop = loop {
        while let Ok(status) = status_rx.try_recv() {
            on_status(status);
        }
        match child.try_wait() {
            Ok(Some(status)) => break Stop::Exit(status),
            Ok(None) if is_cancelled() => {
                let _ = child.kill();
                let _ = child.wait();
                break Stop::Cancelled;
            }
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break Stop::TimedOut;
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot await john sidecar: {e}"));
            }
        }
    };
    let stdout = stdout_capture
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr_capture
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    // The reader thread has finished: drain whatever it queued after the
    // last poll so no status tick is lost to the exit race.
    while let Ok(status) = status_rx.try_recv() {
        on_status(status);
    }
    match stop {
        Stop::TimedOut => Err(format!(
            "john sidecar exceeded the {}s timeout; output discarded",
            timeout.as_secs()
        )),
        Stop::Cancelled => Ok(JohnRecoveryRun {
            cancelled: true,
            matches: Vec::new(),
        }),
        Stop::Exit(status) => {
            if !status.success() {
                return Err(format!(
                    "john sidecar did not complete cleanly: {}",
                    capture_tail(&stdout, &stderr, 2048)
                ));
            }
            // Read the isolated pot rather than exposing or modifying the
            // user's existing John password history (same pattern as john()).
            let show_args = vec![
                "--show".into(),
                format!("--pot={}", pot.display()),
                format!("--format={format}"),
                hash_file.display().to_string(),
            ];
            let (show_status, show_out) = john_show_run(engine, &show_args)?;
            if !show_status.success() {
                return Err("john could not read the isolated result pot".into());
            }
            let matches = parse_john_show_pairs(&String::from_utf8_lossy(&show_out));
            Ok(JohnRecoveryRun {
                cancelled: false,
                matches,
            })
        }
    }
}

/// Test helper (also used by the ipc/recovery ladder tests): write a stub
/// john binary emulating exactly the CLI surface the recovery runner depends
/// on — `--pot/--session/--format/--wordlist/--progress-every/--rules`, a
/// hash file, periodic stderr status lines, and `--show` reading the pot.
/// It "cracks" every hash line with the fixed plaintext "openwall": like the
/// real john, the pot stores `login:openwall` where login is the hash-file
/// line's first `:`-delimited field — so both the bare-`ciphertext` and the
/// ladder's `hash:hash` input shapes map back to the same pair.
#[cfg(test)]
pub(crate) fn stub_john_binary(dir: &Path, sleep_seconds: u32) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let script = format!(
            "@echo off\r\n\
             setlocal EnableDelayedExpansion\r\n\
             set \"POT=\"\r\n\
             set \"HASHFILE=\"\r\n\
             set \"SHOW=0\"\r\n\
             set \"SLEEP={sleep}\"\r\n\
             for %%A in (%*) do (\r\n\
             \x20 set \"ARG=%%~A\"\r\n\
             \x20 if \"!ARG:~0,6!\"==\"--pot=\" set \"POT=!ARG:~6!\"\r\n\
             \x20 if \"!ARG:~0,10!\"==\"--session=\" set \"SESSION=!ARG:~10!\"\r\n\
             \x20 if \"!ARG:~0,9!\"==\"--format=\" set \"FMT=!ARG:~9!\"\r\n\
             \x20 if \"!ARG:~0,10!\"==\"--wordlist=\" set \"WORDLIST=!ARG:~10!\"\r\n\
             \x20 if \"!ARG:~0,7!\"==\"--rules=\" set \"RULES=!ARG:~7!\"\r\n\
             \x20 if \"%%~A\"==\"--show\" set \"SHOW=1\"\r\n\
             \x20 if not \"!ARG:~0,1!\"==\"-\" set \"HASHFILE=%%~A\"\r\n\
             )\r\n\
             if \"!SHOW!\"==\"1\" (\r\n\
             \x20 if exist \"!POT!\" type \"!POT!\"\r\n\
             \x20 echo 1 password hash cracked, 0 left\r\n\
             \x20 exit /b 0\r\n\
             )\r\n\
             if exist \"!POT!\" del \"!POT!\"\r\n\
             for /f \"usebackq delims=: tokens=1\" %%H in (\"!HASHFILE!\") do (echo %%H:openwall)>>\"!POT!\"\r\n\
             >&2 echo 1g 0:00:00:01 50.00%% 0g/s 10p/s 10c/s\r\n\
             if not \"!SLEEP!\"==\"0\" ping -n {ping} 127.0.0.1 >nul\r\n\
             >&2 echo 1g 0:00:00:02 DONE 0g/s 10p/s 10c/s\r\n\
             exit /b 0\r\n",
            sleep = sleep_seconds,
            ping = sleep_seconds + 1,
        );
        let path = dir.join("john.cmd");
        std::fs::write(&path, script).unwrap();
        path
    }
    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/sh\n\
             POT=\"\"; HASHFILE=\"\"; SHOW=0; SLEEP={sleep}\n\
             for arg in \"$@\"; do\n\
             \x20case \"$arg\" in\n\
             \x20 --pot=*) POT=\"${{arg#--pot=}}\" ;;\n\
             \x20 --show) SHOW=1 ;;\n\
             \x20 -*) ;;\n\
             \x20 *) HASHFILE=\"$arg\" ;;\n\
             \x20esac\n\
             done\n\
             if [ \"$SHOW\" = \"1\" ]; then\n\
             \x20[ -f \"$POT\" ] && cat \"$POT\"\n\
             \x20echo \"1 password hash cracked, 0 left\"\n\
             \x20exit 0\n\
             fi\n\
             : > \"$POT\"\n\
             while IFS= read -r line; do printf '%s:openwall\\n' \"${{line%%:*}}\" >> \"$POT\"; done < \"$HASHFILE\"\n\
             echo \"1g 0:00:00:01 50.00% 0g/s 10p/s 10c/s\" >&2\n\
             if [ \"$SLEEP\" != \"0\" ]; then sleep \"$SLEEP\"; fi\n\
             echo \"1g 0:00:00:02 DONE 0g/s 10p/s 10c/s\" >&2\n\
             exit 0\n",
            sleep = sleep_seconds,
        );
        let path = dir.join("john.sh");
        std::fs::write(&path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn stdout_log_truncation_never_splits_utf8() {
        let output = capture_tail("é".repeat(20).as_bytes(), b"", 7);
        assert_eq!(output, "ééé");
    }

    #[test]
    fn parses_john_status_lines_and_ignores_everything_else() {
        assert_eq!(
            parse_john_status_line("0g 0:00:00:02 12.34% 0g/s 10p/s 10c/s"),
            Some(JohnStatusLine {
                guesses: 0,
                percent: Some(12.34)
            })
        );
        assert_eq!(
            parse_john_status_line("3g 0:00:00:10 DONE 0.3g/s 10p/s 10c/s"),
            Some(JohnStatusLine {
                guesses: 3,
                percent: Some(100.0)
            })
        );
        // Warnings, footers and load errors are never progress.
        assert_eq!(parse_john_status_line("Warning: crypt() returned NULL"), None);
        assert_eq!(parse_john_status_line("1 password hash cracked, 0 left"), None);
        assert_eq!(parse_john_status_line("No password hashes loaded"), None);
        assert_eq!(parse_john_status_line(""), None);
    }

    #[test]
    fn show_pairs_keep_the_hash_for_target_mapping() {
        let text = "$gy$j9T$x/y:openwall\n\n1 password hash cracked, 0 left\n";
        assert_eq!(
            parse_john_show_pairs(text),
            vec![("$gy$j9T$x/y".to_string(), "openwall".to_string())]
        );
    }

    #[test]
    fn recovery_sidecar_streams_status_and_extracts_matches() {
        let temp = tempfile::tempdir().unwrap();
        let stub = stub_john_binary(temp.path(), 0);
        let hash = "$gy$j9T$Rt9jcSbmNRUKSenPHUxJp/$4zprMvVKuU/xwoYe3gB5k6WFKfpxRv6IbTkdBfVQQu3";
        let hash_file = temp.path().join("target.hash");
        std::fs::write(&hash_file, format!("{hash}\n")).unwrap();
        let pot = temp.path().join("stage.pot");
        let session = temp.path().join("stage-session");
        let mut statuses = Vec::new();
        let run = john_recovery(
            &JohnSidecarEngine::Exe(stub),
            "crypt",
            &hash_file,
            &hash_file,
            None,
            &pot,
            &session,
            Duration::from_secs(60),
            &|| false,
            |status| statuses.push(status),
        )
        .unwrap();
        assert!(!run.cancelled);
        assert_eq!(statuses.len(), 2);
        assert_eq!(
            statuses[0],
            JohnStatusLine {
                guesses: 1,
                percent: Some(50.0)
            }
        );
        assert_eq!(statuses[1].percent, Some(100.0));
        assert_eq!(
            run.matches,
            vec![(hash.to_string(), "openwall".to_string())]
        );
    }

    #[test]
    fn recovery_sidecar_honours_cancellation_by_killing_the_child() {
        let temp = tempfile::tempdir().unwrap();
        let stub = stub_john_binary(temp.path(), 10);
        let hash_file = temp.path().join("target.hash");
        std::fs::write(&hash_file, "$gy$whatever\n").unwrap();
        let pot = temp.path().join("stage.pot");
        let session = temp.path().join("stage-session");
        let cancelled = Arc::new(AtomicBool::new(false));
        let killer_flag = cancelled.clone();
        let killer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(400));
            killer_flag.store(true, Ordering::SeqCst);
        });
        let run = john_recovery(
            &JohnSidecarEngine::Exe(stub),
            "crypt",
            &hash_file,
            &hash_file,
            None,
            &pot,
            &session,
            Duration::from_secs(60),
            &|| cancelled.load(Ordering::SeqCst),
            |_| {},
        )
        .unwrap();
        killer.join().unwrap();
        assert!(run.cancelled);
        assert!(run.matches.is_empty());
    }

    #[test]
    fn recovery_sidecar_timeout_is_reported_honestly() {
        let temp = tempfile::tempdir().unwrap();
        let stub = stub_john_binary(temp.path(), 10);
        let hash_file = temp.path().join("target.hash");
        std::fs::write(&hash_file, "$gy$whatever\n").unwrap();
        let pot = temp.path().join("stage.pot");
        let session = temp.path().join("stage-session");
        let error = john_recovery(
            &JohnSidecarEngine::Exe(stub),
            "crypt",
            &hash_file,
            &hash_file,
            None,
            &pot,
            &session,
            Duration::from_millis(800),
            &|| false,
            |_| {},
        )
        .unwrap_err();
        assert!(error.contains("timeout"), "got: {error}");
    }

    #[test]
    fn worker_frames_carry_the_same_argv_the_exe_spawn_would_pass() {
        let john_exe = std::path::PathBuf::from("C:\\engines\\john.exe");
        let args = vec![
            "--pot=C:\\scratch\\p.pot".to_string(),
            "--format=crypt".to_string(),
        ];
        let frame = worker_frame(&john_exe, &args).unwrap();
        assert_eq!(&frame[..8], b"CDJW0001");
        assert_eq!(u16::from_le_bytes([frame[8], frame[9]]), 3);
        // First item is the program path, then the flags verbatim.
        let mut cursor = 10usize;
        let mut items = Vec::new();
        for _ in 0..3 {
            let length = u16::from_le_bytes([frame[cursor], frame[cursor + 1]]) as usize;
            items.push(
                String::from_utf8(frame[cursor + 2..cursor + 2 + length].to_vec()).unwrap(),
            );
            cursor += 2 + length;
        }
        assert_eq!(items[0], "C:\\engines\\john.exe");
        assert_eq!(items[1], "--pot=C:\\scratch\\p.pot");
        assert_eq!(items[2], "--format=crypt");
        // A path over the item bound is rejected before any spawn.
        let long = "x".repeat(4097);
        let oversized_args = vec![format!("--pot={long}")];
        assert!(worker_frame(&john_exe, &oversized_args).is_err());
    }

    /// Locate a real john.dll for the DLL-branch integration test, in
    /// deployment order: explicit `CYBERDECK_JOHN_DLL`, the bundled engines
    /// resource directory (production shape), or the local mingw build's
    /// deploy directory (where john.dll and its MinGW runtime deps live).
    /// Returns None on CI machines without the DLL — the test then skips
    /// cleanly; the owner runs the real verification.
    fn locate_john_dll_for_test() -> Option<std::path::PathBuf> {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidates = [
            std::env::var_os("CYBERDECK_JOHN_DLL").map(std::path::PathBuf::from),
            Some(manifest.join("resources").join("engines").join("john.dll")),
            Some(std::path::PathBuf::from("C:\\Dev\\john-build\\run\\john.dll")),
        ];
        for candidate in candidates.into_iter().flatten() {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    /// Integration test (runs only when a real john.dll is present): compile
    /// the supervised worker helper from its pinned source with rustc, stage
    /// john.dll and its MinGW runtime deps beside it, and run the whole
    /// DLL-branch recovery flow — cd_john_main crack session, stderr status
    /// parsing, isolated pot and `--show` extraction through the helper.
    /// The known vector is md5crypt("openwall", salt "cddeck") as produced
    /// by `openssl passwd -1 -salt cddeck openwall` (verified against the
    /// bundled john.exe and the DLL in this session). The generic "crypt"
    /// format is NOT in this john build, so an existing format proves the
    /// route mechanics; the gost-yescrypt sidecar registry is unchanged.
    #[test]
    fn recovery_sidecar_dll_branch_cracks_through_the_real_john_dll() {
        let Some(dll) = locate_john_dll_for_test() else {
            eprintln!("skipping: no john.dll found (set CYBERDECK_JOHN_DLL to run)");
            return;
        };
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let john_exe = manifest
            .join("resources")
            .join("engines")
            .join(if cfg!(windows) { "john.exe" } else { "john" });
        if !john_exe.is_file() {
            eprintln!("skipping: bundled john.exe is not staged for this run");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let worker_name = if cfg!(windows) {
            format!("{JOHN_WORKER_BINARY}.exe")
        } else {
            JOHN_WORKER_BINARY.to_string()
        };
        let worker = temp.path().join(&worker_name);
        let source = manifest
            .join("src")
            .join("third_party")
            .join("hashcat")
            .join("native")
            .join("john_worker.rs");
        let build = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
            .args(["--edition=2021", "-C", "opt-level=2", "-C", "panic=abort", "-o"])
            .arg(&worker)
            .arg(&source)
            .output()
            .expect("rustc is required to build the john worker helper");
        assert!(
            build.status.success(),
            "worker helper compile failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        // The helper's import table wants john.dll in its own directory, and
        // john.dll's MinGW runtime deps must resolve beside it as well.
        std::fs::copy(&dll, temp.path().join("john.dll")).unwrap();
        for entry in dll
            .parent()
            .map(|dir| dir.read_dir().expect("john.dll directory is readable"))
            .into_iter()
            .flatten()
        {
            if let Ok(entry) = entry {
                let name = entry.file_name();
                let path = entry.path();
                if path.is_file()
                    && name
                        .to_str()
                        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".dll"))
                {
                    let _ = std::fs::copy(&path, temp.path().join(&name));
                }
            }
        }
        // Real vector, written in the ladder's `hash:hash` login shape
        // (scratch::write_john_hash_file contract, loader.c:565 rationale).
        let hash = "$1$cddeck$jdHRxTOqkfeA/5c52WcAe0";
        let hash_file = temp.path().join("target.hash");
        std::fs::write(&hash_file, format!("{hash}:{hash}\n")).unwrap();
        let wordlist = temp.path().join("candidates.words");
        std::fs::write(&wordlist, "decoy1\ndecoy2\nopenwall\ndecoy3\n").unwrap();
        let pot = temp.path().join("dll.pot");
        let session = temp.path().join("dll-session");
        let mut statuses = Vec::new();
        let run = john_recovery(
            &JohnSidecarEngine::Dll { worker, john_exe },
            // The registered sidecar format is "crypt"; this build lacks it
            // entirely (exe and DLL alike), so the route mechanics are proven
            // with a format the build does carry.
            "md5crypt",
            &hash_file,
            &wordlist,
            None,
            &pot,
            &session,
            Duration::from_secs(120),
            &|| false,
            |status| statuses.push(status),
        )
        .unwrap();
        assert!(!run.cancelled);
        assert_eq!(
            run.matches,
            vec![(hash.to_string(), "openwall".to_string())]
        );
        // Progress flowed from the helper's inherited stderr through the
        // same status-line parser the exe branch uses (final DONE tick).
        assert!(
            statuses.iter().any(|status| status.percent == Some(100.0)),
            "expected a DONE status tick, got: {statuses:?}"
        );
    }
}

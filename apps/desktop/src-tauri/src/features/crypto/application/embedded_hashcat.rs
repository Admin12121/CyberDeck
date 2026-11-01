//! Supervised, opt-in Hashcat source-compiled worker. Case and job identity
//! remain owned by RecoveryCtx. No external installed hashcat process.
//! All confidential outputs reside in a restrictive, temporary directory.
use super::recovery_backend::{
    self, RecoveryCancel, RecoveryProgressWire, RecoveryRequest, RecoveryRun,
};
use cyberdeck_crypto::recovery::RecoveryTarget;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = b"CDHC0001";
const MAX_PRIVATE_OUTPUT: u64 = 1 << 20;
const HARD_DEADLINE: Duration = Duration::from_secs(315);

/// Best-effort clearing of confidential worker output on all return paths.
struct SensitiveBytes(Vec<u8>);
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}


/// Worker exit cleanup must happen even if the supervising native thread
/// panics or the active case is revoked while the GPU runtime is busy.
struct PrivateChild(Child);
impl Drop for PrivateChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn worker_name() -> &'static str {
    if cfg!(windows) {
        "cyberdeck-recovery-worker.exe"
    } else {
        "cyberdeck-recovery-worker"
    }
}

pub fn runtime_available(root: &Path) -> Result<(), String> {
    for p in [
        root.join(worker_name()),
        root.join(if cfg!(windows) {
            "cyberdeck_hashcat_shim.dll"
        } else if cfg!(target_os = "macos") {
            "libcyberdeck_hashcat_shim.dylib"
        } else {
            "libcyberdeck_hashcat_shim.so"
        }),
        root.join(if cfg!(windows) {
            "hashcat.dll"
        } else if cfg!(target_os = "macos") {
            "libhashcat.8.dylib"
        } else {
            "libhashcat.so.8"
        }),
        root.join("modules").join(if cfg!(windows) {
            "module_01400.dll"
        } else {
            "module_01400.so"
        }),
        root.join("source-manifest.json"),
    ] {
        if !p.is_file() {
            return Err("source-built Hashcat runtime is not bundled".into());
        }
    }
    Ok(())
}

fn push_path(buffer: &mut Vec<u8>, path: &Path) -> Result<(), String> {
    let text = path.to_str().ok_or("native path is not UTF-8")?;
    if !path.is_absolute()
        || text.is_empty()
        || text.len() > 4096
        || text.bytes().any(|b| b < 32 || b == 127)
    {
        return Err("unsafe Hashcat worker input path".into());
    }
    let length = u16::try_from(text.len()).map_err(|_| "worker path too long")?;
    buffer.extend_from_slice(&length.to_le_bytes());
    buffer.extend_from_slice(text.as_bytes());
    Ok(())
}

fn frame(
    root: &Path,
    target: &Path,
    wordlist: &Path,
    outfile: &Path,
    budget: u64,
    runtime: u32,
    device_id: u32,
) -> Result<Vec<u8>, String> {
    if budget == 0 || budget > 1_000_000 || runtime == 0 || runtime > 300 || device_id > 128 {
        return Err("embedded Hashcat work limits invalid".into());
    }
    let mut packet = MAGIC.to_vec();
    packet.extend_from_slice(&budget.to_le_bytes());
    packet.extend_from_slice(&runtime.to_le_bytes());
    packet.extend_from_slice(&device_id.to_le_bytes());
    for path in [root, target, wordlist, outfile] {
        push_path(&mut packet, path)?;
    }
    Ok(packet)
}

/// Runs only the upstream 1400/SHA-256 straight-wordlist mode. This function
/// does not assume Hashcat's device identifiers match CyberDeck's Rust OpenCL
/// inventory. Automatic GPU selection must not be certified without a KAT.
pub fn execute_path<P: FnMut(RecoveryProgressWire)>(
    request: &RecoveryRequest,
    wordlist: &Path,
    runtime: &Path,
    cancel: &RecoveryCancel,
    _progress: P,
) -> Result<RecoveryRun, String> {
    recovery_backend::validate_request(request)?;
    runtime_available(runtime)?;
    if !wordlist.is_file() {
        return Err("wordlist must be an accessible regular file".into());
    }
    // No arbitrary Hashcat CLI or device flags. Only the known current mode.
    // Device choice 0 means Hashcat's own default, not verified GPU/CPU routing.
    let device_id = 0;
    let scratch = tempfile::Builder::new()
        .prefix("cyberdeck-hc-")
        .tempdir()
        .map_err(|_| "cannot create private Hashcat workspace")?;
    let hash = scratch.path().join("target.sha256");
    let output = scratch.path().join("recovered.tmp");
    let mut file = File::create(&hash).map_err(|_| "cannot create private target file")?;
    file.write_all(request.target_hash.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|_| "cannot write private target file")?;
    drop(file);

    let bytes = frame(
        runtime,
        &hash,
        wordlist,
        &output,
        request.max_candidates,
        300,
        device_id,
    )?;
    let mut child = PrivateChild(
        Command::new(runtime.join(worker_name()))
            .current_dir(scratch.path())
            .env("HOME", scratch.path())
            .env("XDG_CACHE_HOME", scratch.path())
            .env("XDG_CONFIG_HOME", scratch.path())
            .env("APPDATA", scratch.path())
            .env("LOCALAPPDATA", scratch.path())
            .env("TMP", scratch.path())
            .env("TEMP", scratch.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "could not start bundled Hashcat worker")?,
    );
    {
        let mut pipe = child
            .0
            .stdin
            .take()
            .ok_or("private worker stdin unavailable")?;
        pipe.write_all(&bytes)
            .map_err(|_| "private Hashcat worker protocol write failed")?;
    }
    let started = Instant::now();
    let cancelled = loop {
        if cancel.is_cancelled() {
            break true;
        }
        if started.elapsed() > HARD_DEADLINE {
            return Err("Hashcat worker timed out and was terminated".into());
        }
        match child.0.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err("embedded Hashcat worker exited with failure".into());
                }
                break false;
            }
            Ok(None) => thread::sleep(Duration::from_millis(75)),
            Err(_) => return Err("Hashcat worker status unavailable".into()),
        }
    };
    // Drop terminates any remaining child and waits before TempDir deletes
    // sensitive inputs/output, including on timeout and case cancellation.
    drop(child);
    if cancelled || cancel.is_cancelled() {
        return Ok(recovery_backend::embedded_result(
            request,
            Vec::new(),
            true,
            started.elapsed().as_millis() as u64,
        ));
    }
    let mut matches = Vec::new();
    if output.exists() {
        if fs::metadata(&output)
            .map_err(|_| "recovery output metadata unavailable")?
            .len()
            > MAX_PRIVATE_OUTPUT
        {
            return Err("Hashcat result output exceeded strict limit".into());
        }
        let target = RecoveryTarget::parse("sha256", &request.target_hash)?;
        let content = SensitiveBytes(fs::read(&output).map_err(|_| "cannot read bounded private output")?);
        for candidate in content.0.split(|b| *b == b'\n') {
            let candidate = candidate.strip_suffix(b"\r").unwrap_or(candidate);
            if candidate.is_empty() {
                continue;
            }
            if !target.is_match(candidate)? {
                return Err(
                    "Hashcat candidate failed independent Rust SHA-256 verification".into(),
                );
            }
            // Find the real candidate ordinal in original wordlist where
            // possible, rather than fabricating work counters.
            let file = File::open(wordlist).map_err(|_| "wordlist became unavailable")?;
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            let mut index = 0u64;
            let found_index = loop {
                line.clear();
                if reader
                    .read_until(b'\n', &mut line)
                    .map_err(|_| "cannot recheck wordlist")?
                    == 0
                {
                    break None;
                }
                if line.len() > 4096 {
                    return Err("wordlist candidate exceeds recovery bound".into());
                }
                let data = line.strip_suffix(b"\n").unwrap_or(&line);
                let data = data.strip_suffix(b"\r").unwrap_or(data);
                if data == candidate {
                    break Some(index);
                }
                index += 1;
                if index >= request.max_candidates {
                    break None;
                }
            };
            let Some(index) = found_index else {
                return Err("Hashcat output is not a verified original wordlist candidate".into());
            };
            if matches.iter().any(|(old, _)| *old == index) {
                continue;
            }
            matches.push((index, candidate.to_vec()));
            if matches.len() >= request.max_matches {
                break;
            }
        }
    }
    Ok(recovery_backend::embedded_result(
        request,
        matches,
        false,
        started.elapsed().as_millis() as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_bounds_and_path_safety() {
        let root = Path::new("/tmp/a");
        assert!(frame(root, root, root, root, 1, 20, 0).is_ok());
        assert!(frame(root, root, root, root, 0, 20, 0).is_err());
        assert!(frame(root, root, root, root, 1, 301, 0).is_err());
        assert!(frame(Path::new("relative"), root, root, root, 1, 20, 0).is_err());
    }
}

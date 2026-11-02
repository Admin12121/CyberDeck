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

/// Safe, stable diagnostics for a sealed child process. Never include the
/// worker's stdout/stderr because upstream libraries may print target data.
fn worker_failure(code: Option<i32>) -> &'static str {
    match code {
        Some(10) => "embedded worker protocol rejected request",
        Some(11) => "embedded worker input files unavailable or unsafe",
        Some(21) => "embedded Hashcat C ABI version mismatch",
        Some(22) => "embedded Hashcat could not allocate native context",
        Some(23 | 24) => "embedded Hashcat rejected bounds or file path",
        Some(31) => "Hashcat SHA-256 mode options initialization failed",
        Some(32) => "Hashcat native option parsing failed",
        Some(33) => "Hashcat native option validation failed",
        Some(34) => "Hashcat native session setup failed before compute initialization",
        Some(36) => "Hashcat native bridge initialization failed",
        Some(37) => "Hashcat native compute runtime loader failed",
        Some(38) => "Hashcat native device initialization failed; check compatible OpenCL drivers",
        Some(39) => "Hashcat native post-device setup failed",
        Some(35) => "Hashcat native session preparation failed",
        Some(40) => "Hashcat native kernel execution failed",
        _ => "embedded Hashcat worker crashed or exited unexpectedly",
    }
}

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
    // A native library without its exact SHA-256 mode, kernels and notices
    // cannot be advertised as a complete bundled recovery capability.
    let required_files = [
        worker_name(),
        if cfg!(windows) {
            "cyberdeck_hashcat_shim.dll"
        } else if cfg!(target_os = "macos") {
            "libcyberdeck_hashcat_shim.dylib"
        } else {
            "libcyberdeck_hashcat_shim.so"
        },
        if cfg!(windows) {
            "hashcat.dll"
        } else if cfg!(target_os = "macos") {
            "libhashcat.8.dylib"
        } else {
            "libhashcat.so.8"
        },
        if cfg!(windows) {
            "modules/module_00000.dll"
        } else {
            "modules/module_00000.so"
        },
        if cfg!(windows) {
            "modules/module_01400.dll"
        } else {
            "modules/module_01400.so"
        },
        // Upstream loads the generic recipe preflight kernel during startup.
        "OpenCL/m04000-pure.cl",
        "OpenCL/m01400_a0-optimized.cl",
        "OpenCL/m01400_a1-optimized.cl",
        "OpenCL/m01400_a3-optimized.cl",
        "OpenCL/amp_a0.cl",
        "source-manifest.json",
        "licenses/HASHCAT_MIT.txt",
        "licenses/OPENCL_HEADERS.txt",
    ];
    for relative in required_files {
        let path = root.join(relative);
        if !path.is_file() || path.metadata().map(|meta| meta.len() == 0).unwrap_or(true) {
            return Err("source-built Hashcat runtime is incomplete".into());
        }
    }
    // A bundled mode needs its actual module plus the optimized kernel family.
    for mode in [0u32, 100, 1400, 1700] {
        let module = if cfg!(windows) {
            format!("modules/module_{mode:05}.dll")
        } else {
            format!("modules/module_{mode:05}.so")
        };
        let path = root.join(module);
        if !path.is_file() || path.metadata().map(|m| m.len() == 0).unwrap_or(true) {
            return Err("source-built Hashcat runtime is incomplete".into());
        }
        for attack in [0, 1, 3] {
            let kernel = root.join(format!("OpenCL/m{mode:05}_a{attack}-optimized.cl"));
            if !kernel.is_file() || kernel.metadata().map(|m| m.len() == 0).unwrap_or(true) {
                return Err("source-built Hashcat runtime is incomplete".into());
            }
        }
    }
    if !root.join("capability-manifest.json").is_file() {
        return Err("source-built Hashcat runtime is incomplete".into());
    }
    if !root.join("tunings").is_dir() {
        return Err("source-built Hashcat runtime is incomplete".into());
    }
    Ok(())
}

/// Execute a fixed no-evidence loader probe using the exact bundled private
/// worker. This is not device enumeration or a kernel known-answer test.
/// The worker emits no text; all diagnostics are static and redacted.
pub fn probe_opencl_loader(root: &Path) -> Result<bool, String> {
    runtime_available(root)?;
    let child = Command::new(root.join(worker_name()))
        .arg("--probe-opencl-loader")
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "bundled Hashcat worker loader probe could not start")?;
    let mut child = PrivateChild(child);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .map_err(|_| "bundled Hashcat loader probe failed")?
        {
            return match status.code() {
                Some(0) => Ok(true),
                Some(37) => Ok(false),
                _ => Err("bundled Hashcat loader probe returned an unexpected result".into()),
            };
        }
        if Instant::now() >= deadline {
            return Err("bundled Hashcat loader probe timed out".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
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

pub(super) fn validate_embedded_request(request: &RecoveryRequest) -> Result<u32, String> {
    if !matches!(
        request.backend,
        recovery_backend::BackendSelection::HashcatManaged
    ) {
        return Err("embedded Hashcat requires Hashcat-managed device selection".into());
    }
    if request.max_candidates == 0
        || request.max_candidates > 1_000_000
        || request.max_matches == 0
        || request.max_matches > 4
    {
        return Err("embedded Hashcat candidate or result limit exceeded".into());
    }
    let mode = match request.algorithm.as_str() {
        "md5" => 0,
        "sha1" => 100,
        "sha256" => 1400,
        "sha512" => 1700,
        _ => return Err("raw hash mode not bundled for embedded Hashcat".into()),
    };
    match RecoveryTarget::parse(&request.algorithm, &request.target_hash)? {
        RecoveryTarget::Digest { .. } => Ok(mode),
        _ => Err("embedded Hashcat requires a raw hexadecimal digest".into()),
    }
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

fn frame_mode(
    root: &Path,
    target: &Path,
    wordlist: &Path,
    outfile: &Path,
    budget: u64,
    runtime: u32,
    device_id: u32,
    hash_mode: u32,
) -> Result<Vec<u8>, String> {
    if budget == 0 || budget > 1_000_000 || runtime == 0 || runtime > 300 || device_id > 128 {
        return Err("embedded Hashcat work limits invalid".into());
    }
    if !matches!(hash_mode, 0 | 100 | 1400 | 1700) {
        return Err("embedded Hashcat mode unsupported".into());
    }
    let mut packet = b"CDHC0002".to_vec();
    packet.extend_from_slice(&budget.to_le_bytes());
    packet.extend_from_slice(&runtime.to_le_bytes());
    packet.extend_from_slice(&device_id.to_le_bytes());
    packet.extend_from_slice(&hash_mode.to_le_bytes());
    for path in [root, target, wordlist, outfile] {
        push_path(&mut packet, path)?;
    }
    Ok(packet)
}

/// Executes selected bundled MD5/SHA-1/SHA-256/SHA-512 wordlist mode. This function
/// does not assume Hashcat's device identifiers match CyberDeck's Rust OpenCL
/// inventory. Automatic GPU selection must not be certified without a KAT.
pub fn execute_path<P: FnMut(RecoveryProgressWire)>(
    request: &RecoveryRequest,
    wordlist: &Path,
    runtime: &Path,
    cancel: &RecoveryCancel,
    _progress: P,
) -> Result<RecoveryRun, String> {
    let hash_mode = validate_embedded_request(request)?;
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
    let hash = scratch.path().join("target.rawhash");
    let output = scratch.path().join("recovered.tmp");
    let mut file = File::create(&hash).map_err(|_| "cannot create private target file")?;
    file.write_all(request.target_hash.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|_| "cannot write private target file")?;
    drop(file);

    let bytes = frame_mode(
        runtime,
        &hash,
        wordlist,
        &output,
        request.max_candidates,
        300,
        device_id,
        hash_mode,
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
                    return Err(worker_failure(status.code()).into());
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
        let target = RecoveryTarget::parse(&request.algorithm, &request.target_hash)?;
        let content =
            SensitiveBytes(fs::read(&output).map_err(|_| "cannot read bounded private output")?);
        for candidate in content.0.split(|b| *b == b'\n') {
            let candidate = candidate.strip_suffix(b"\r").unwrap_or(candidate);
            if candidate.is_empty() {
                continue;
            }
            if !target.is_match(candidate)? {
                return Err("Hashcat candidate failed independent Rust digest verification".into());
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
    fn digest_modes_and_worker_v2_packet_are_bounded() {
        for (algorithm, size, mode) in [
            ("md5", 32, 0),
            ("sha1", 40, 100),
            ("sha256", 64, 1400),
            ("sha512", 128, 1700),
        ] {
            let request = RecoveryRequest {
                algorithm: algorithm.into(),
                target_hash: "a".repeat(size),
                backend: recovery_backend::BackendSelection::HashcatManaged,
                max_candidates: 100,
                max_matches: 1,
            };
            assert_eq!(validate_embedded_request(&request), Ok(mode));
            let path = Path::new("/tmp/fixture");
            let packet = frame_mode(path, path, path, path, 100, 30, 0, mode).unwrap();
            assert_eq!(&packet[..8], b"CDHC0002");
            assert_eq!(u32::from_le_bytes(packet[24..28].try_into().unwrap()), mode);
            let mut bad = request.clone();
            bad.target_hash.pop();
            assert!(validate_embedded_request(&bad).is_err());
        }
        let path = Path::new("/tmp/fixture");
        assert!(frame_mode(path, path, path, path, 1, 10, 0, 999).is_err());
    }

    #[test]
    fn incomplete_bundle_must_not_claim_embedded_capability() {
        let scratch = tempfile::tempdir().unwrap();
        assert!(runtime_available(scratch.path()).is_err());
        // Merely creating a worker executable is insufficient; kernels,
        // SHA-256 mode, provenance and license notices are mandatory.
        std::fs::write(scratch.path().join(worker_name()), b"worker").unwrap();
        assert!(runtime_available(scratch.path()).is_err());
    }

    #[test]
    fn worker_failure_diagnostics_are_redacted_and_specific() {
        assert!(worker_failure(Some(34)).contains("compute runtime"));
        assert!(worker_failure(Some(21)).contains("ABI"));
        assert!(worker_failure(None).contains("crashed"));
        for code in [
            10, 11, 21, 22, 23, 24, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ] {
            assert!(!worker_failure(Some(code)).contains("/tmp/"));
        }
    }

    #[test]
    fn protocol_bounds_and_path_safety() {
        let root = Path::new("/tmp/a");
        assert!(frame(root, root, root, root, 1, 20, 0).is_ok());
        assert!(frame(root, root, root, root, 0, 20, 0).is_err());
        assert!(frame(root, root, root, root, 1, 301, 0).is_err());
        assert!(frame(Path::new("relative"), root, root, root, 1, 20, 0).is_err());
    }
}

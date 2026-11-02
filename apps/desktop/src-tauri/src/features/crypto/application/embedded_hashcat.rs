//! Supervised, opt-in Hashcat source-compiled worker. Case and job identity
//! remain owned by RecoveryCtx. No external installed hashcat process.
//! All confidential outputs reside in a restrictive, temporary directory.
use super::recovery_backend::{
    self, RecoveryCancel, RecoveryProgressWire, RecoveryRequest, RecoveryRun,
};
use cyberdeck_crypto::recovery::RecoveryTarget;
#[path = "embedded_hashcat_preset.rs"]
mod preset;
pub use preset::WordlistPreset;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
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
    for mode in [0u32, 100, 1000, 1400, 1700] {
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

/// Trusted built-in KATs use only public fixtures: zero user hashes, wordlists,
/// case context or secret output ever passes into this capability probe.
const PUBLIC_KATS: &[(u32, &str, &str)] = &[
    (1400, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (0, "abc", "900150983cd24fb0d6963f7d28e17f72"),
    (100, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (1000, "password", "8846f7eaee8fb117ad06bdd830b7586c"),
    (1700, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    // Batch-1 KDF modes: vectors verified independently by our native Rust
    // engines (pwhash / john / Openwall published bcrypt vectors).
    (500, "password", "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0"),
    (1800, "test", "$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJURCXk43.EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/"),
    (3200, "U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
    // Batch-2: salted digests + HMAC (independent Node-crypto vectors),
    // Windows auth (john the Ripper vectors) and sha256crypt (pwhash).
    (10, "cyberdeck", "c51d5447beddf60e68604ca2dbf4e6ad:4242"),
    (20, "cyberdeck", "a944dd5c9a02c5bed3a4b175ac565d7c:4242"),
    (50, "cyberdeck", "dc5b5ad28f4dd280463a5319b976bd50:4242"),
    (60, "cyberdeck", "3de2a5579621deb8357374953c6a520d4779fc8a:4242"),
    (110, "cyberdeck", "047564e24f0e65d25618c3369b98d9602219c03d:4242"),
    (120, "cyberdeck", "0c0ae97e6246815bb0426ba6cff3093561f069b3:4242"),
    (1100, "test1", "64cd29e36a8431a2b111378564a10631:test1"),
    (2100, "test1", "$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8"),
    (5500, "g3rg3g3rg3g3rg3", "a::b:1122334455667788:000000000000000000000000000000000000000000000000:BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB"),
    (5600, "password", "NTLMV2TEST::WORKGROUP:1122334455667788:07659A550D5E9D02996DFD95C87EC1D5:0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"),
    (7400, "cyberdeck-kat-2026", "$5$CyberDeckKAT$kGyqS./awuvI5h4KB95ES/o9w3pxHqKFF8aBBpvSGvD"),
];
type Readiness = Result<Vec<u32>, String>;
static READINESS_CACHE: OnceLock<Mutex<HashMap<PathBuf, Readiness>>> = OnceLock::new();

fn self_test_mode(root: &Path, mode: u32, word: &str, digest: &str) -> Result<(), String> {
    let scratch = tempfile::Builder::new()
        .prefix("cyberdeck-hc-selftest-")
        .tempdir()
        .map_err(|_| "could not create private Hashcat self-test workspace")?;
    let target_path = scratch.path().join("public.hash");
    let wordlist_path = scratch.path().join("public.words");
    let result_path = scratch.path().join("public.out");
    fs::write(&target_path, format!("{digest}\n"))
        .map_err(|_| "could not create private Hashcat self-test hash")?;
    fs::write(&wordlist_path, format!("not-the-solution\n{word}\n"))
        .map_err(|_| "could not create private Hashcat self-test dictionary")?;
    let packet = frame_mode(
        root,
        &target_path,
        &wordlist_path,
        &result_path,
        2,
        30,
        0,
        mode,
    )?;
    let mut child = PrivateChild(
        Command::new(root.join(worker_name()))
            .current_dir(scratch.path())
            .env("HOME", scratch.path())
            .env("XDG_DATA_HOME", scratch.path())
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
            .map_err(|_| "could not start bundled Hashcat self-test worker")?,
    );
    child
        .0
        .stdin
        .take()
        .ok_or("Hashcat self-test worker input unavailable")?
        .write_all(&packet)
        .map_err(|_| "could not send bounded Hashcat self-test")?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match child.0.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => return Err(worker_failure(status.code()).into()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(30)),
            Ok(None) => return Err("native Hashcat self-test timed out".into()),
            Err(_) => return Err("native Hashcat self-test worker status unavailable".into()),
        }
    }
    drop(child);
    let metadata = fs::metadata(&result_path)
        .map_err(|_| "native Hashcat self-test failed to produce a match")?;
    if metadata.len() > 4096 {
        return Err("native Hashcat self-test result limit exceeded".into());
    }
    let mut result = SensitiveBytes(Vec::with_capacity(metadata.len() as usize));
    File::open(&result_path)
        .map_err(|_| "native Hashcat self-test result inaccessible")?
        .take(4097)
        .read_to_end(&mut result.0)
        .map_err(|_| "native Hashcat self-test result unreadable")?;
    let output = result.0.strip_suffix(b"\n").unwrap_or(&result.0);
    let output = output.strip_suffix(b"\r").unwrap_or(output);
    let expected = RecoveryTarget::parse(
        match mode {
            0 => "md5",
            100 => "sha1",
            1000 => "ntlm",
            1400 => "sha256",
            1700 => "sha512",
            _ => return Err("Hashcat self-test mode unsupported".into()),
        },
        digest,
    )?;
    if output != word.as_bytes() || !expected.is_match(output)? {
        return Err(
            "native Hashcat self-test failed independent digest/candidate verification".into(),
        );
    }
    Ok(())
}

/// Only actually executed modes may be enabled in the desktop UI. A loader
/// check or enumerated GPU is insufficient. Cache exact runtime-path findings
/// for one process lifetime; after changing drivers, restart the application.
/// Real hardware/type mapping remains a separate acceptance requirement.
pub fn verified_modes(root: &Path) -> Readiness {
    let cache = READINESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(lock) => lock,
        Err(_) => return Err("Hashcat readiness cache unavailable".into()),
    };
    if let Some(stored) = guard.get(root) {
        return stored.clone();
    }
    let result = (|| {
        runtime_available(root)?;
        if !probe_opencl_loader(root)? {
            return Err("Bundled Hashcat OpenCL loader unavailable".into());
        }
        let mut verified = Vec::new();
        let mut first_failure = None;
        for &(mode, word, digest) in PUBLIC_KATS {
            match self_test_mode(root, mode, word, digest) {
                Ok(()) => verified.push(mode),
                Err(error) if first_failure.is_none() => first_failure = Some(error),
                Err(_) => {}
            }
        }
        if verified.is_empty() {
            Err(first_failure.unwrap_or_else(|| {
                "No bundled Hashcat mode passed its private known-answer test".into()
            }))
        } else {
            Ok(verified)
        }
    })();
    guard.insert(root.to_path_buf(), result.clone());
    result
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
        "md5crypt" => 500,
        "ntlm" => 1000,
        "sha256" => 1400,
        "sha512" => 1700,
        "sha512crypt" => 1800,
        "bcrypt" => 3200,
        "md5-pass-salt" => 10,
        "md5-salt-pass" => 20,
        "hmac-md5" => 50,
        "hmac-sha1" => 60,
        "sha1-pass-salt" => 110,
        "sha1-salt-pass" => 120,
        "mscash" => 1100,
        "mscash2" => 2100,
        "netntlm-v1" => 5500,
        "netntlm-v2" => 5600,
        "sha256crypt" => 7400,
        _ => return Err("hash mode not bundled for embedded Hashcat".into()),
    };
    match RecoveryTarget::parse(&request.algorithm, &request.target_hash)? {
        RecoveryTarget::Digest { .. } => Ok(mode),
        _ => Err("embedded Hashcat requires a raw hexadecimal digest".into()),
    }
}

#[cfg(test)]
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
    if !matches!(hash_mode, 0 | 100 | 1000 | 1400 | 1700) {
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

/// Executes selected bundled MD5/SHA-1/NTLM/SHA-256/SHA-512 wordlist mode. This function
/// does not assume Hashcat's device identifiers match CyberDeck's Rust OpenCL
/// inventory. Automatic GPU selection must not be certified without a KAT.
pub fn execute_path<P: FnMut(RecoveryProgressWire)>(
    request: &RecoveryRequest,
    wordlist: &Path,
    runtime: &Path,
    cancel: &RecoveryCancel,
    preset: WordlistPreset,
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
    // Bounded candidate transforms are prepared only in private job scratch.
    // The packaged Hashcat worker still executes the same native wordlist
    // attack, with no arbitrary rules/flags. Never mutate original evidence.
    let generated_path = scratch.path().join("transformed.words");
    let generated = match preset::generate(
        wordlist,
        &generated_path,
        request.max_candidates,
        preset,
        || cancel.is_cancelled(),
    ) {
        Ok(value) => value,
        Err(_error) if cancel.is_cancelled() => {
            return Ok(recovery_backend::embedded_result(
                request,
                Vec::new(),
                true,
                0,
            ));
        }
        Err(error) => return Err(error),
    };
    // A transformed empty wordlist is an exhausted operation, not a native
    // runtime/device failure. No worker or secret output is created.
    if generated == Some(0) {
        return Ok(recovery_backend::embedded_result(
            request,
            Vec::new(),
            false,
            0,
        ));
    }
    let active_wordlist = if generated.is_some() {
        generated_path.as_path()
    } else {
        wordlist
    };
    let mut file = File::create(&hash).map_err(|_| "cannot create private target file")?;
    file.write_all(request.target_hash.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|_| "cannot write private target file")?;
    drop(file);

    let bytes = frame_mode(
        runtime,
        &hash,
        active_wordlist,
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
            // Hashcat may derive its profile from passwd(5), ignoring HOME.
            // Keep potfiles, session metadata and cache under private scratch.
            .env("XDG_DATA_HOME", scratch.path())
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
            let file = File::open(active_wordlist).map_err(|_| "wordlist became unavailable")?;
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            let mut index = 0u64;
            let found_index = loop {
                line.clear();
                if !preset::read_line_bounded(&mut reader, &mut line)? {
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
    fn every_public_native_mode_fixture_is_independently_verifiable_without_gpu() {
        assert_eq!(PUBLIC_KATS.len(), 19);
        for &(mode, word, hash) in PUBLIC_KATS {
            let algorithm = match mode {
                0 => "md5",
                100 => "sha1",
                1000 => "ntlm",
                1400 => "sha256",
                1700 => "sha512",
                // KDF fixtures are verified through the KDF verifier, which
                // derives the family from the modular string itself.
                500 | 1800 | 3200 | 2100 | 5500 | 5600 | 7400 => "kdf",
                // Hint-driven composed targets: the wire shape is ambiguous.
                10 => "md5-pass-salt",
                20 => "md5-salt-pass",
                50 => "hmac-md5",
                60 => "hmac-sha1",
                110 => "sha1-pass-salt",
                120 => "sha1-salt-pass",
                1100 => "mscash",
                _ => panic!("invalid pinned Hashcat self-test mode"),
            };
            let target = if algorithm == "kdf" {
                RecoveryTarget::parse("", hash).unwrap()
            } else {
                RecoveryTarget::parse(algorithm, hash).unwrap()
            };
            assert!(
                target.is_match(word.as_bytes()).unwrap(),
                "{algorithm} fixture"
            );
            assert!(!target.is_match(b"not-the-solution").unwrap());
        }
    }

    #[test]
    fn an_unbundled_directory_never_reports_native_mode_ready() {
        let scratch = tempfile::tempdir().unwrap();
        assert!(verified_modes(scratch.path()).is_err());
    }

    #[test]
    fn digest_modes_and_worker_v2_packet_are_bounded() {
        for (algorithm, size, mode) in [
            ("md5", 32, 0),
            ("sha1", 40, 100),
            ("ntlm", 32, 1000),
            ("sha256", 64, 1400),
            ("sha512", 128, 1700),
        ] {
            let request = RecoveryRequest {
                algorithm: algorithm.into(),
                target_hash: "a".repeat(size),
                backend: recovery_backend::BackendSelection::HashcatManaged,
                max_candidates: 100,
                max_matches: 1,
                target_hashes: Vec::new(),
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
    fn ntlm_mode_1000_has_independent_utf16le_reference_verification() {
        // NTLM and MD5 are both 32 hexadecimal characters; identification
        // from digest shape alone must never silently choose the algorithm.
        let ntlm_hash = "8846f7eaee8fb117ad06bdd830b7586c";
        let target = RecoveryTarget::parse("ntlm", ntlm_hash).unwrap();
        assert!(target.is_match(b"password").unwrap());
        assert!(!target.is_match(b"Password").unwrap());
        assert!(RecoveryTarget::parse("ntlm", "a").is_err());
        let request = RecoveryRequest {
            algorithm: "ntlm".into(),
            target_hash: ntlm_hash.into(),
            backend: recovery_backend::BackendSelection::HashcatManaged,
            max_candidates: 100,
            max_matches: 1,
            target_hashes: Vec::new(),
        };
        assert_eq!(validate_embedded_request(&request), Ok(1000));
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
        assert!(worker_failure(Some(34)).contains("before compute initialization"));
        assert!(worker_failure(Some(37)).contains("compute runtime loader"));
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

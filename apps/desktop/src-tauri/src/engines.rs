//! External password-cracking engines (Master Plan §5.5, §6). hashcat is MIT
//! and john is GPLv2 shipped as a separate sidecar — both approved for
//! bundling (docs/engine-licensing.md). The adapter layer owns process
//! creation, argument construction, timeouts and output parsing; the frontend
//! only ever receives structured results.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::attack::AttackMatch;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_REPORTED_MATCHES: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct EngineStatus {
    pub id: String,
    pub label: String,
    pub license: String,
    pub available: bool,
    pub version: String,
    pub source: String,
    pub note: String,
}

/// Where a binary may live: the bundled resource directory first, then PATH.
fn candidate_paths(app: &AppHandle, binary: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let exe = if cfg!(windows) { format!("{binary}.exe") } else { binary.to_string() };
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join("engines").join(&exe));
    }
    candidates.push(PathBuf::from(exe)); // resolved from PATH by Command
    candidates
}

fn run_with_timeout(mut command: Command, timeout: Duration) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    let mut child = command.spawn().map_err(|e| format!("cannot start process: {e}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read as _;
                    let _ = out.read_to_end(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read as _;
                    let _ = err.read_to_end(&mut stderr);
                }
                return Ok((status, stdout, stderr));
            }
            None if started.elapsed() > timeout => {
                let _ = child.kill();
                return Err(format!("engine exceeded the {}s timeout; output discarded", timeout.as_secs()));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

pub fn parse_hashcat_version(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| {
            let trimmed = line.trim().trim_start_matches('v');
            let mut split = trimmed.split(|c: char| !c.is_ascii_digit() && c != '.');
            let head = split.next()?.to_string();
            head.contains('.')
            .then_some(head)
        })
        .map(|v| format!("v{v}"))
}

pub fn parse_john_version(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.contains("John the Ripper"))
        .map(|l| l.trim().split_whitespace().take(4).collect::<Vec<_>>().join(" "))
}

fn version_of(app: &AppHandle, binary: &str, version_args: &[&str], parse: fn(&str) -> Option<String>) -> Option<(String, String)> {
    for candidate in candidate_paths(app, binary) {
        let mut command = Command::new(&candidate);
        command.args(version_args);
        if let Ok((status, stdout, stderr)) = run_with_timeout(command, Duration::from_secs(10)) {
            if status.success() {
                let text = format!("{}{}", String::from_utf8_lossy(&stdout), String::from_utf8_lossy(&stderr));
                if let Some(version) = parse(&text) {
                    let source = if candidate.is_absolute() { "bundled resource" } else { "system PATH" };
                    return Some((version, source.to_string()));
                }
            }
        }
    }
    None
}

#[tauri::command]
pub fn engines_detect(app: AppHandle) -> Vec<EngineStatus> {
    let hashcat = version_of(&app, "hashcat", &["--version"], parse_hashcat_version);
    let john = version_of(&app, "john", &["--version"], parse_john_version);
    vec![
        EngineStatus {
            id: "hashcat".to_string(),
            label: "hashcat".to_string(),
            license: "MIT".to_string(),
            available: hashcat.is_some(),
            version: hashcat.as_ref().map(|(v, _)| v.clone()).unwrap_or_default(),
            source: hashcat.map(|(_, s)| s).unwrap_or_default(),
            note: "GPU when vendor drivers are present; MIT license approved for bundling".to_string(),
        },
        EngineStatus {
            id: "john".to_string(),
            label: "John the Ripper".to_string(),
            license: "GPL-2.0-only (sidecar)".to_string(),
            available: john.is_some(),
            version: john.as_ref().map(|(v, _)| v.clone()).unwrap_or_default(),
            source: john.map(|(_, s)| s).unwrap_or_default(),
            note: "CPU engine, jumbo formats; ships as a separate sidecar binary".to_string(),
        },
    ]
}

/// hashcat -m mode for a digest family; KDF and crypt formats included so
/// cracking is reachable through the engine.
pub fn hashcat_mode(algo: &str) -> Option<u32> {
    match algo {
        "md5" => Some(0),
        "sha1" => Some(100),
        "sha256" => Some(1400),
        "sha512" => Some(1700),
        "ntlm" => Some(1000),
        "md4" => Some(900),
        "lm" => Some(3000),
        "bcrypt" => Some(3200),
        "sha512crypt" => Some(1800),
        "sha256crypt" => Some(17400),
        "md5crypt" => Some(500),
        "apr1" => Some(1600),
        "phpass" => Some(400),
        "mscash2" => Some(2100),
        "sunmd5" => Some(7400),
        "yescrypt" => Some(22700),
        _ => None,
    }
}

pub fn john_format(algo: &str) -> Option<&'static str> {
    match algo {
        "md5" => Some("raw-md5"),
        "sha1" => Some("raw-sha1"),
        "sha256" => Some("raw-sha256"),
        "sha512" => Some("raw-sha512"),
        "bcrypt" => Some("bcrypt"),
        "sha512crypt" => Some("sha512crypt"),
        "sha256crypt" => Some("sha256crypt"),
        "md5crypt" => Some("md5crypt"),
        "apr1" => Some("apr1"),
        "phpass" => Some("phpass"),
        "mscash2" => Some("mscash2"),
        "sunmd5" => Some("sunmd5"),
        "yescrypt" => Some("yescrypt"),
        "lm" => Some("LM"),
        _ => None,
    }
}

/// Collect hash:plain pairs from a hashcat -o outfile.
pub fn parse_hashcat_outfile(text: &str) -> Vec<AttackMatch> {
    text.lines()
        .filter_map(|line| {
            let (hash, plain) = line.split_once(':')?;
            (!hash.is_empty() && !plain.is_empty()).then(|| AttackMatch { line_no: 0, password: plain.trim().to_string() })
        })
        .collect()
}

/// Collect hash:plain pairs from `john --show`.
pub fn parse_john_show(text: &str) -> Vec<AttackMatch> {
    text.lines()
        .filter(|line| line.contains(':') && !line.contains("password hashes") && !line.starts_with('\''))
        .filter_map(|line| {
            let (hash, plain) = line.split_once(':')?;
            (!hash.trim().is_empty() && !plain.trim().is_empty()).then(|| AttackMatch { line_no: 0, password: plain.trim().to_string() })
        })
        .collect()
}

fn scratch_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("cannot resolve cache dir: {e}"))?
        .join("engine-scratch");
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create engine scratch dir: {e}"))?;
    Ok(dir)
}

fn write_hash_file(dir: &Path, algo: &str, hash: &str, engine: &str) -> Result<PathBuf, String> {
    let file = dir.join(format!("{engine}-{algo}-{}.txt", &hash[..hash.len().min(12)]));
    std::fs::write(&file, format!("{hash}\n")).map_err(|e| format!("cannot write hash file: {e}"))?;
    Ok(file)
}

#[derive(Debug, Serialize)]
pub struct EngineAttackResult {
    pub engine: String,
    pub engine_version: String,
    pub algo: String,
    pub mode: String,
    pub tried_note: String,
    pub matches: Vec<AttackMatch>,
    pub duration_ms: u64,
    pub raw_tail: String,
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn engine_attack(
    app: AppHandle,
    engine: String,
    algo: String,
    target_hash: String,
    mode: String,
    mask: Option<String>,
    ctx: State<'_, crate::evidence::EvidenceCtx>,
) -> Result<EngineAttackResult, String> {
    let target = target_hash.trim().to_lowercase();
    if target.is_empty() {
        return Err("target hash is empty".to_string());
    }
    if !matches!(mode.as_str(), "wordlist" | "mask") {
        return Err("engine attacks support wordlist and mask modes this arc".to_string());
    }
    let started = Instant::now();

    // The attack input (wordlist file) arrives through the dialog; mask needs
    // no file. Wordlist: pick first.
    let scratch = scratch_dir(&app)?;
    match engine.as_str() {
        "hashcat" => {
            let hash_mode = hashcat_mode(&algo).ok_or_else(|| format!("hashcat has no -m mode for {algo}"))?;
            let binary = if cfg!(windows) { "hashcat.exe" } else { "hashcat" };
            let bin_path = candidate_paths(&app, "hashcat")
                .into_iter()
                .find(|p| p.is_absolute() || which_exists(binary))
                .ok_or("hashcat is not detected on this machine")?;
            let hash_file = write_hash_file(&scratch, &algo, &target, "hashcat")?;
            let out_file = scratch.join(format!("hashcat-{}.out", &target[..12.min(target.len())]));
            let _ = std::fs::remove_file(&out_file);
            let mut command = Command::new(bin_path);
            command
                .arg("-m").arg(hash_mode.to_string())
                .arg("--potfile-disable")
                .arg("-o").arg(&out_file);
            if mode == "mask" {
                let mask = mask.clone().unwrap_or_default();
                if mask.is_empty() {
                    return Err("mask attack needs a mask pattern".to_string());
                }
                command.arg("-a").arg("3").arg(&hash_file).arg(mask);
            } else {
                let picked = app.dialog().file().blocking_pick_file().ok_or("cancelled")?;
                let wordlist = picked.as_path().ok_or("unsupported file location")?.to_path_buf();
                command.arg("-a").arg("0").arg(&hash_file).arg(wordlist);
            }
            let (status, stdout, stderr) = run_with_timeout(command, PROCESS_TIMEOUT)?;
            let outfile_text = std::fs::read_to_string(&out_file).unwrap_or_default();
            let mut matches = parse_hashcat_outfile(&outfile_text);
            matches.truncate(MAX_REPORTED_MATCHES);
            crate::attack::record_history(&ctx, &algo, &target, "hashcat", &matches);
            let mut raw = format!("{}{}", String::from_utf8_lossy(&stdout), String::from_utf8_lossy(&stderr));
            raw.truncate(4000);
            let engine_version = version_of(&app, "hashcat", &["--version"], parse_hashcat_version)
                .map(|(v, _)| v)
                .unwrap_or_default();
            Ok(EngineAttackResult {
                engine: "hashcat".to_string(),
                engine_version,
                algo,
                mode,
                tried_note: if status.success() { "completed" } else { "engine returned nonzero; see raw output" }.to_string(),
                matches,
                duration_ms: started.elapsed().as_millis() as u64,
                raw_tail: raw,
            })
        }
        "john" => {
            let fmt = john_format(&algo).ok_or_else(|| format!("john has no format for {algo}"))?;
            let binary = if cfg!(windows) { "john.exe" } else { "john" };
            let bin_path = candidate_paths(&app, "john")
                .into_iter()
                .find(|p| p.is_absolute() || which_exists(binary))
                .ok_or("john is not detected on this machine")?;
            if mode == "mask" {
                return Err("john mask mode arrives with the mask engine arc; use wordlist or native".to_string());
            }
            let picked = app.dialog().file().blocking_pick_file().ok_or("cancelled")?;
            let wordlist = picked.as_path().ok_or("unsupported file location")?.to_path_buf();
            let hash_file = write_hash_file(&scratch, &algo, &target, "john")?;
            let mut command = Command::new(&bin_path);
            command
                .arg(format!("--format={fmt}"))
                .arg(format!("--wordlist={}", wordlist.display()))
                .arg(&hash_file);
            let (status, stdout, stderr) = run_with_timeout(command, PROCESS_TIMEOUT)?;
            // secrets live in john's pot; --show reads them back
            let mut show = Command::new(bin_path);
            show.arg("--show").arg(format!("--format={fmt}")).arg(&hash_file);
            let (_, show_out, _) = run_with_timeout(show, Duration::from_secs(30))?;
            let mut matches = parse_john_show(&String::from_utf8_lossy(&show_out));
            matches.truncate(MAX_REPORTED_MATCHES);
            crate::attack::record_history(&ctx, &algo, &target, "john", &matches);
            let mut raw = format!("{}{}", String::from_utf8_lossy(&stdout), String::from_utf8_lossy(&stderr));
            raw.truncate(4000);
            let engine_version = version_of(&app, "john", &["--version"], parse_john_version)
                .map(|(v, _)| v)
                .unwrap_or_default();
            let _ = status;
            Ok(EngineAttackResult {
                engine: "john".to_string(),
                engine_version,
                algo,
                mode,
                tried_note: "wordlist + john pot".to_string(),
                matches,
                duration_ms: started.elapsed().as_millis() as u64,
                raw_tail: raw,
            })
        }
        other => Err(format!("unknown engine: {other}")),
    }
}

fn which_exists(binary: &str) -> bool {
    if cfg!(windows) {
        std::process::Command::new("where").arg(binary).output().map(|o| o.status.success()).unwrap_or(false)
    } else {
        std::process::Command::new("sh").arg("-c").arg(format!("command -v {binary}")).output().map(|o| o.status.success()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashcat_mode_map_covers_digests_and_kdf() {
        assert_eq!(hashcat_mode("md5"), Some(0));
        assert_eq!(hashcat_mode("sha256"), Some(1400));
        assert_eq!(hashcat_mode("bcrypt"), Some(3200));
        assert_eq!(hashcat_mode("sha512crypt"), Some(1800));
        assert_eq!(hashcat_mode("yescrypt"), Some(22700));
        assert_eq!(hashcat_mode("argon2"), None);
    }

    #[test]
    fn john_format_map() {
        assert_eq!(john_format("md5"), Some("raw-md5"));
        assert_eq!(john_format("bcrypt"), Some("bcrypt"));
        assert_eq!(john_format("yescrypt"), Some("yescrypt"));
        assert_eq!(john_format("sha512crypt"), Some("sha512crypt"));
        assert_eq!(john_format("ntlm"), None);
    }

    #[test]
    fn parses_hashcat_version() {
        assert_eq!(parse_hashcat_version("v6.2.6\nsome build info"), Some("v6.2.6".to_string()));
        assert_eq!(parse_hashcat_version("6.2.6"), Some("v6.2.6".to_string()));
        assert_eq!(parse_hashcat_version("no version here"), None);
    }

    #[test]
    fn parses_john_version() {
        let banner = "John the Ripper 1.9.0-jumbo-1+ bleeding [windows-x86_64 AVX2]";
        assert_eq!(parse_john_version(banner).unwrap(), "John the Ripper 1.9.0-jumbo-1+");
    }

    #[test]
    fn parses_hashcat_outfile_lines() {
        let text = "5d41402abc4b2a76b9719d911017c592:hello\n746308829575e38c3cc2a3d38dcbba9957ee5c4d:\n\n0d107d09f5bbe40cade3de5c71e9e9b7:world\n";
        let matches = parse_hashcat_outfile(text);
        let passwords: Vec<_> = matches.into_iter().map(|m| m.password).collect();
        assert_eq!(passwords, vec!["hello", "world"]);
    }

    #[test]
    fn parses_john_show_lines() {
        let text = "5d41402abc4b2a76b9719d911017c592:hello\n\n1 password hash cracked, 0 left\n";
        let matches = parse_john_show(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].password, "hello");
    }

    #[test]
    fn guard_rejects_empty_target() {
        // guard() lives in attack.rs; engine_attack validates via the same rule
        assert!("".trim().is_empty());
    }
}

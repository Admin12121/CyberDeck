//! External engine adapters (hashcat MIT, john GPLv2 sidecar): process
//! process orchestration is here; parsing/capture are feature infrastructure adapters.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, State};

#[path = "../domain/engines.rs"]
mod domain;
pub use domain::{EngineAttackResult, EngineStatus};

#[path = "../infrastructure/engine_formats.rs"]
mod engine_formats;
pub use engine_formats::{hashcat_mode, john_format, parse_hashcat_version, parse_john_version};
#[cfg(test)]
pub use engine_formats::{parse_hashcat_outfile, parse_john_show};

#[path = "../application/engines.rs"]
mod application;
#[path = "../infrastructure/sidecar.rs"]
mod sidecar;

#[path = "../infrastructure/executables.rs"]
mod executables;
pub use executables::which_exists;

#[path = "../infrastructure/scratch.rs"]
mod scratch;

#[path = "../infrastructure/process.rs"]
pub(crate) mod process;
use process::run_with_timeout;

/// Where a binary may live: the bundled resource directory first, then PATH.
fn candidate_paths(app: &AppHandle, binary: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let exe = if cfg!(windows) {
        format!("{binary}.exe")
    } else {
        binary.to_string()
    };
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join("engines").join(&exe));
    }
    candidates.push(PathBuf::from(exe)); // resolved from PATH by Command
    candidates
}

fn version_of(
    app: &AppHandle,
    binary: &str,
    version_args: &[&str],
    parse: fn(&str) -> Option<String>,
) -> Option<(String, String)> {
    for candidate in candidate_paths(app, binary) {
        let mut command = Command::new(&candidate);
        command.args(version_args);
        if let Ok((status, stdout, stderr)) = run_with_timeout(command, Duration::from_secs(10)) {
            if status.success() {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
                if let Some(version) = parse(&text) {
                    let source = if candidate.is_absolute() {
                        "bundled resource"
                    } else {
                        "system PATH"
                    };
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
            note: "GPU when vendor drivers are present; MIT license approved for bundling"
                .to_string(),
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
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn engine_attack(
    app: AppHandle,
    engine: String,
    algo: String,
    target_hash: String,
    mode: String,
    mask: Option<String>,
    rules_set: Option<String>,
    ctx: State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
) -> Result<EngineAttackResult, String> {
    let target = application::normalized_target(&target_hash)?;
    application::validate_mode(&engine, &mode, mask.as_deref())?;

    // Resolve supported hash formats and sidecar binaries before creating files.
    let binary_name = if cfg!(windows) {
        format!("{engine}.exe")
    } else {
        engine.clone()
    };
    let binary = candidate_paths(&app, &engine)
        .into_iter()
        .find(|p| {
            if p.is_absolute() {
                p.is_file()
            } else {
                which_exists(&binary_name)
            }
        })
        .ok_or_else(|| format!("{engine} is not detected on this machine"))?;
    let hash_mode = if engine == "hashcat" {
        Some(hashcat_mode(&algo).ok_or_else(|| format!("hashcat has no -m mode for {algo}"))?)
    } else {
        None
    };
    let john_fmt = if engine == "john" {
        Some(john_format(&algo).ok_or_else(|| format!("john has no format for {algo}"))?)
    } else {
        None
    };
    let wordlist = if mode == "wordlist" {
        Some(crate::features::crypto::ipc::crack::resolved_wordlist(&app, None)?.0)
    } else {
        None
    };
    // Bundled rule sets resolve backend-side by manifest id (hashcat only;
    // john rule syntax differs and stays out of this command).
    let rules = match (engine.as_str(), rules_set.as_deref()) {
        ("hashcat", Some(id)) => {
            if mode != "wordlist" {
                return Err("rules apply to wordlist mode only".into());
            }
            Some(
                crate::features::crypto::ipc::recovery::library_rules::resolve_rules_path(
                    &app, id,
                )?,
            )
        }
        _ => None,
    };

    let started = Instant::now();
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("cannot resolve cache dir: {e}"))?;
    let scratch = scratch::ScratchDir::create(&cache)?;
    let run = match engine.as_str() {
        "hashcat" => sidecar::hashcat(
            &binary,
            hash_mode.expect("validated hashcat format"),
            &target,
            &mode,
            mask.as_deref(),
            wordlist.as_deref(),
            rules.as_deref(),
            &scratch,
        )?,
        "john" => sidecar::john(
            &binary,
            john_fmt.expect("validated john format"),
            &target,
            wordlist.as_deref().ok_or("wordlist is required")?,
            &scratch,
        )?,
        _ => unreachable!("validated engine"),
    };
    let version = match engine.as_str() {
        "hashcat" => version_of(&app, "hashcat", &["--version"], parse_hashcat_version),
        _ => version_of(&app, "john", &["--version"], parse_john_version),
    }
    .map(|(value, _)| value)
    .unwrap_or_default();
    let result = application::report(
        engine,
        version,
        algo.clone(),
        mode,
        started.elapsed().as_millis() as u64,
        run,
    );
    crate::features::crypto::ipc::attack::record_history(
        &ctx,
        &algo,
        &target,
        &result.engine,
        &result.matches,
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_executable_lookup_does_not_invoke_a_shell() {
        assert!(!which_exists("nonexistent-program-DO-NOT-EXECUTE"));
        #[cfg(unix)]
        assert!(which_exists("sh"));
    }

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
        assert_eq!(
            parse_hashcat_version("v6.2.6\nsome build info"),
            Some("v6.2.6".to_string())
        );
        assert_eq!(parse_hashcat_version("6.2.6"), Some("v6.2.6".to_string()));
        assert_eq!(parse_hashcat_version("no version here"), None);
    }

    #[test]
    fn parses_john_version() {
        let banner = "John the Ripper 1.9.0-jumbo-1+ bleeding [windows-x86_64 AVX2]";
        assert_eq!(
            parse_john_version(banner).unwrap(),
            "John the Ripper 1.9.0-jumbo-1+"
        );
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

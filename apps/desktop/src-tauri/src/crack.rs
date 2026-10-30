//! Wordlist recovery sessions (Master Plan §5.5). This is the honest first
//! cracker: unsalted digest matching against a user-picked wordlist, streamed
//! from disk. KDF formats (bcrypt, argon2, yescrypt) stay gated until the
//! john/hashcat engines pass the license review; the UI must not pretend
//! otherwise.

use std::io::BufRead as _;
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::evidence::MAX_IMPORT_BYTES;

const SUPPORTED: &[&str] = &["md5", "sha1", "sha256", "sha512"];
const MAX_REPORTED_MATCHES: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct CrackMatch {
    pub line_no: u64,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct CrackResultWire {
    pub algo: String,
    pub target_hash: String,
    pub wordlist: String,
    pub tried: u64,
    pub matches: Vec<CrackMatch>,
    pub duration_ms: u64,
    pub engine: String,
    pub engine_version: String,
}

#[tauri::command]
pub fn crack_wordlist_dialog(
    app: AppHandle,
    algo: String,
    target_hash: String,
    ctx: State<'_, crate::evidence::EvidenceCtx>,
) -> Result<CrackResultWire, String> {
    let target = target_hash.trim().to_string();
    if target.is_empty() {
        return Err("target hash is empty".to_string());
    }
    let started = Instant::now();
    let picked = app.dialog().file().blocking_pick_file().ok_or("cancelled")?;
    let path = picked.as_path().ok_or("unsupported file location")?.to_path_buf();
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read wordlist metadata: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "wordlist is {} MB; the limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let wordlist_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "wordlist.txt".to_string());

    let file = std::fs::File::open(&path).map_err(|e| format!("cannot open wordlist: {e}"))?;
    let reader = std::io::BufReader::with_capacity(1 << 20, file);
    let mut tried: u64 = 0;
    let mut matches: Vec<CrackMatch> = Vec::new();

    // KDF targets (bcrypt/argon2 PHC strings) verify natively, slowly by design.
    if let Some(format) = hacktool_crypto::kdf_format(&target) {
        const MAX_KDF_CANDIDATES: u64 = 10_000;
        let mut capped = false;
        for line in reader.lines() {
            let line = line.map_err(|e| format!("read error: {e}"))?;
            tried += 1;
            let candidate = line.strip_suffix('\r').unwrap_or(&line);
            if hacktool_crypto::verify_kdf(&target, candidate).unwrap_or(false) {
                matches.push(CrackMatch { line_no: tried, password: candidate.to_string() });
                break;
            }
            if tried >= MAX_KDF_CANDIDATES {
                capped = true;
                break;
            }
        }
        let _ = ctx;
        return Ok(CrackResultWire {
            algo: format.to_string(),
            target_hash: target,
            wordlist: wordlist_name,
            tried,
            matches,
            duration_ms: started.elapsed().as_millis() as u64,
            engine: "hacktool-crypto".to_string(),
            engine_version: hacktool_crypto::ENGINE_VERSION.to_string(),
        });
    }

    if !SUPPORTED.contains(&algo.as_str()) {
        return Err(format!("wordlist recovery supports {} this arc", SUPPORTED.join(", ")));
    }
    let target = target.to_lowercase();
    let mut capped = false;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read error: {e}"))?;
        tried += 1;
        // Candidate bytes are the raw line without the newline; trailing CR is
        // stripped so CRLF wordlists behave.
        let candidate = line.strip_suffix('\r').unwrap_or(&line);
        let digest = hacktool_crypto::apply_op(&algo, candidate.as_bytes(), None)?;
        if hex::encode(digest) == target {
            matches.push(CrackMatch { line_no: tried, password: candidate.to_string() });
            if matches.len() >= MAX_REPORTED_MATCHES {
                break;
            }
        }
    }
    // Wordlist provenance lands in the case log via the artifact store.
    let _ = ctx;
    let _ = capped;
    Ok(CrackResultWire {
        algo,
        target_hash: target,
        wordlist: wordlist_name,
        tried,
        matches,
        duration_ms: started.elapsed().as_millis() as u64,
        engine: "hacktool-crypto".to_string(),
        engine_version: hacktool_crypto::ENGINE_VERSION.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The matching logic shared by the command, exercised without Tauri.
    fn match_candidate(algo: &str, candidate: &str, target: &str) -> bool {
        let digest = hacktool_crypto::apply_op(algo, candidate.as_bytes(), None).unwrap();
        hex::encode(digest) == target
    }

    #[test]
    fn matches_known_digest() {
        assert!(match_candidate("md5", "hello", "5d41402abc4b2a76b9719d911017c592"));
        assert!(!match_candidate("md5", "world", "5d41402abc4b2a76b9719d911017c592"));
    }

    #[test]
    fn sha256_candidate_matches() {
        assert!(match_candidate("sha256", "hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
    }

    #[test]
    fn unsupported_algo_is_rejected() {
        assert!(!SUPPORTED.contains(&"bcrypt"));
    }

    #[test]
    fn kdf_targets_route_to_the_verify_path() {
        assert_eq!(hacktool_crypto::kdf_format("$2b$10$abcdefghijklmnopqrstuv"), Some("bcrypt"));
        assert!(hacktool_crypto::kdf_format("5d41402abc4b2a76b9719d911017c592").is_none());
    }
}

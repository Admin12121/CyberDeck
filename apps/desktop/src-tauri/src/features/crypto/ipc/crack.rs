//! Stable native crypto wordlist IPC entry points. Recovery streams through
//! the bounded Rust core; file dialogs stay outside the application service.
use std::path::PathBuf;
use std::time::Instant;

use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

#[path = "../application/recovery.rs"]
mod application;
#[path = "../domain/crack.rs"]
mod domain;
#[path = "../infrastructure/wordlists.rs"]
mod wordlists;

pub use domain::{CrackMatch, CrackProgress, CrackResultWire, WordlistInfoWire};

const SUPPORTED: &[&str] = &["md5", "sha1", "sha256", "sha512"];

fn choose_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.dialog()
        .file()
        .blocking_pick_file()
        .ok_or_else(|| "cancelled".to_string())?
        .as_path()
        .ok_or_else(|| "unsupported file location".to_string())
        .map(|path| path.to_path_buf())
}

#[tauri::command]
pub fn pick_wordlist(app: AppHandle) -> Result<WordlistInfoWire, String> {
    let path = choose_path(&app)?;
    let (name, size) = wordlists::inspect(&path)?;
    Ok(WordlistInfoWire {
        name,
        path: path.to_string_lossy().into_owned(),
        size,
    })
}

/// Validate a previously OS-selected file again before recovery starts.
pub(crate) fn inspect_recovery_wordlist(path: &std::path::Path) -> Result<(String, u64), String> {
    wordlists::inspect(path)
}

pub(crate) fn resolved_wordlist(
    app: &AppHandle,
    wordlist_path: Option<&str>,
) -> Result<(PathBuf, String), String> {
    let path = match wordlist_path {
        Some(path) => PathBuf::from(path),
        None => choose_path(app)?,
    };
    let (name, _) = wordlists::inspect(&path)?;
    Ok((path, name))
}

/// Read the capped candidate prefix for hybrid/combinator handlers without
/// loading the rest of the selected wordlist.
pub(crate) fn read_wordlist_prefix(
    path: &std::path::Path,
    limit: usize,
) -> Result<Vec<u8>, String> {
    wordlists::read_nonempty_prefix(path, limit)
}

#[tauri::command]
pub fn crack_wordlist_dialog(
    app: AppHandle,
    algo: String,
    target_hash: String,
    wordlist_path: Option<String>,
    on_progress: tauri::ipc::Channel<CrackProgress>,
    ctx: State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
) -> Result<CrackResultWire, String> {
    let target = target_hash.trim().to_string();
    if target.is_empty() {
        return Err("target hash is empty".into());
    }
    let kdf = cyberdeck_crypto::kdf_format(&target).is_some();
    if !kdf && !SUPPORTED.contains(&algo.as_str()) {
        return Err(format!(
            "wordlist recovery supports {} this arc",
            SUPPORTED.join(", ")
        ));
    }

    let started = Instant::now();
    let (wordlist, wordlist_name) = resolved_wordlist(&app, wordlist_path.as_deref())?;
    let total = wordlists::count_lines(&wordlist)?;
    let file = std::fs::File::open(&wordlist).map_err(|e| format!("cannot open wordlist: {e}"))?;
    let reader = std::io::BufReader::with_capacity(1 << 20, file);
    let result = application::execute(reader, &algo, &target, total, |progress| {
        let _ = on_progress.send(progress);
    })?;
    crate::features::crypto::ipc::history::persist(
        ctx.inner(),
        &result.format,
        &target,
        "cyberdeck-crypto",
        Some(&wordlist_name),
        result.matches.iter().map(|hit| hit.password.as_str()),
    );
    Ok(CrackResultWire {
        algo: result.format,
        target_hash: if kdf { target } else { target.to_lowercase() },
        wordlist: wordlist_name,
        tried: result.tried,
        matches: result.matches,
        duration_ms: started.elapsed().as_millis() as u64,
        // The native streaming CPU core runs one verifier; avoid falsely
        // reporting available CPU cores as the number of active workers.
        threads: 1,
        engine: "cyberdeck-crypto".into(),
        engine_version: cyberdeck_crypto::ENGINE_VERSION.into(),
    })
}

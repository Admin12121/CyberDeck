//! Native wordlist recovery (§5.5): chunked across all cores with a shared
//! early-stop flag. KDF targets verify natively, slowly by design, capped.

use std::io::BufRead as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::evidence::MAX_IMPORT_BYTES;

const SUPPORTED: &[&str] = &["md5", "sha1", "sha256", "sha512"];
const MAX_REPORTED_MATCHES: usize = 100;
const MAX_KDF_CANDIDATES: u64 = 10_000;

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
    pub threads: usize,
    pub engine: String,
    pub engine_version: String,
}

#[derive(Debug, Serialize)]
pub struct WordlistInfoWire {
    pub name: String,
    pub path: String,
    pub size: u64,
}

/// Pick a wordlist once; the path round-trips into the attack commands, which
/// re-validate it (paths originate from our own dialog, never typed by the UI).
#[tauri::command]
pub fn pick_wordlist(app: AppHandle) -> Result<WordlistInfoWire, String> {
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
    Ok(WordlistInfoWire {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "wordlist.txt".to_string()),
        path: path.to_string_lossy().to_string(),
        size: meta.len(),
    })
}

pub(crate) fn resolved_wordlist(
    app: &AppHandle,
    wordlist_path: Option<&str>,
) -> Result<(PathBuf, String), String> {
    match wordlist_path {
        Some(path) => {
            let path = PathBuf::from(path);
            let meta = std::fs::metadata(&path).map_err(|e| format!("selected wordlist is unreadable: {e}"))?;
            if meta.len() > MAX_IMPORT_BYTES {
                return Err(format!(
                    "wordlist is {} MB; the limit this arc is {} MB",
                    meta.len() / (1024 * 1024),
                    MAX_IMPORT_BYTES / (1024 * 1024)
                ));
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "wordlist.txt".to_string());
            Ok((path, name))
        }
        None => {
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
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "wordlist.txt".to_string());
            Ok((path, name))
        }
    }
}

fn thread_count() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 32)
}

/// Persist recovered pairs into the crack history (deduped by the store).
fn record_history(
    ctx: &crate::evidence::EvidenceCtx,
    algo: &str,
    target: &str,
    engine: &str,
    wordlist: &str,
    matches: &[CrackMatch],
) {
    if matches.is_empty() {
        return;
    }
    let store = ctx.store.lock().expect("artifact store poisoned");
    for m in matches {
        let _ = store.add_crack_entry(algo, target, &m.password, engine, Some(wordlist));
    }
}

/// Chunk `items` across `threads` worker threads; each worker returns its
/// (tried, matches) partial, merged in chunk order so line numbers stay true.
fn run_parallel<T, F>(items: Vec<T>, worker: F) -> Vec<(u64, Vec<CrackMatch>)>
where
    T: Send + Sync,
    F: Fn(&[T], u64, &AtomicBool) -> (u64, Vec<CrackMatch>) + Send + Sync + Copy,
{
    let threads = thread_count();
    let stop = Arc::new(AtomicBool::new(false));
    let chunk_size = (items.len() + threads - 1) / threads.max(1);
    let mut partials: Vec<(u64, Vec<CrackMatch>)> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (chunk_index, chunk) in items.chunks(chunk_size.max(1)).enumerate() {
            let stop = &stop;
            let base = (chunk_index * chunk_size.max(1)) as u64;
            handles.push(scope.spawn(move || worker(chunk, base, stop)));
        }
        partials = handles.into_iter().map(|h| h.join().unwrap_or((0, Vec::new()))).collect();
    });
    partials
}

/// Streaming progress for long wordlist runs (percent of candidates tried).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CrackProgress {
    pub tried: u64,
    pub total: u64,
    pub percent: u32,
}

#[tauri::command]
pub fn crack_wordlist_dialog(
    app: AppHandle,
    algo: String,
    target_hash: String,
    wordlist_path: Option<String>,
    on_progress: tauri::ipc::Channel<CrackProgress>,
    ctx: State<'_, crate::evidence::EvidenceCtx>,
) -> Result<CrackResultWire, String> {
    let target = target_hash.trim().to_string();
    if target.is_empty() {
        return Err("target hash is empty".to_string());
    }
    let started = Instant::now();
    let (wordlist, wordlist_name) = resolved_wordlist(&app, wordlist_path.as_deref())?;
    let threads = thread_count();
    let progress = Arc::new(on_progress);

    let file = std::fs::File::open(&wordlist).map_err(|e| format!("cannot open wordlist: {e}"))?;
    let reader = std::io::BufReader::with_capacity(1 << 20, file);
    let lines: Vec<String> = reader
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read error: {e}"))?;

    // KDF targets (bcrypt/argon2 PHC strings) verify natively, slowly by design.
    if let Some(format) = cyberdeck_crypto::kdf_format(&target) {
        let total = lines.len() as u64;
        let target_ref = Arc::new(target.clone());
        let progress = Arc::clone(&progress);
        let parts = run_parallel(lines, |chunk: &[String], base, stop| {
            let mut tried: u64 = 0;
            let mut matches: Vec<CrackMatch> = Vec::new();
            for (i, line) in chunk.iter().enumerate() {
                if stop.load(Ordering::Relaxed) || tried >= MAX_KDF_CANDIDATES {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                tried += 1;
                if tried % 25 == 0 {
                    let done = (base + tried).min(total);
                    let _ = progress.send(CrackProgress { tried: done, total, percent: (done * 100 / total.max(1)) as u32 });
                }
                let candidate = line.strip_suffix('\r').unwrap_or(line);
                if cyberdeck_crypto::verify_kdf(&target_ref, candidate).unwrap_or(false) {
                    matches.push(CrackMatch { line_no: base + i as u64 + 1, password: candidate.to_string() });
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
            (tried, matches)
        });
        let tried: u64 = parts.iter().map(|(t, _)| t).sum();
        let mut matches: Vec<CrackMatch> = parts.into_iter().flat_map(|(_, m)| m).collect();
        matches.truncate(MAX_REPORTED_MATCHES);
        record_history(&ctx, &format, &target, "cyberdeck-crypto", &wordlist_name, &matches);
        return Ok(CrackResultWire {
            algo: format.to_string(),
            target_hash: target,
            wordlist: wordlist_name,
            tried,
            matches,
            duration_ms: started.elapsed().as_millis() as u64,
            threads,
            engine: "cyberdeck-crypto".to_string(),
            engine_version: cyberdeck_crypto::ENGINE_VERSION.to_string(),
        });
    }

    if !SUPPORTED.contains(&algo.as_str()) {
        return Err(format!("wordlist recovery supports {} this arc", SUPPORTED.join(", ")));
    }
    let target = target.to_lowercase();
    let total = lines.len() as u64;
    let target_ref = Arc::new(target.clone());
    let algo_ref = Arc::new(algo.clone());
    let progress = Arc::clone(&progress);
    let parts = run_parallel(lines, |chunk: &[String], base, stop: &AtomicBool| {
        let mut tried: u64 = 0;
        let mut matches: Vec<CrackMatch> = Vec::new();
        for (i, line) in chunk.iter().enumerate() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            tried += 1;
            if tried % 50_000 == 0 {
                let done = (base + tried).min(total);
                let _ = progress.send(CrackProgress { tried: done, total, percent: (done * 100 / total.max(1)) as u32 });
            }
            let candidate = line.strip_suffix('\r').unwrap_or(line);
            if let Ok(digest) = cyberdeck_crypto::apply_op(&algo_ref, candidate.as_bytes(), None) {
                if hex::encode(digest) == *target_ref {
                    matches.push(CrackMatch { line_no: base + i as u64 + 1, password: candidate.to_string() });
                    if matches.len() >= MAX_REPORTED_MATCHES {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
        (tried, matches)
    });
    let tried: u64 = parts.iter().map(|(t, _)| t).sum();
    let mut matches: Vec<CrackMatch> = parts.into_iter().flat_map(|(_, m)| m).collect();
    matches.truncate(MAX_REPORTED_MATCHES);
    record_history(&ctx, &algo, &target, "cyberdeck-crypto", &wordlist_name, &matches);
    Ok(CrackResultWire {
        algo,
        target_hash: target,
        wordlist: wordlist_name,
        tried,
        matches,
        duration_ms: started.elapsed().as_millis() as u64,
        threads,
        engine: "cyberdeck-crypto".to_string(),
        engine_version: cyberdeck_crypto::ENGINE_VERSION.to_string(),
    })
}


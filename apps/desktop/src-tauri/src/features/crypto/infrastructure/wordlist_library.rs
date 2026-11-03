//! Wordlist library: a bundled starter list plus curated downloadable sets.
//! Downloads stream into the app-data directory under a hard size cap and
//! are recorded with their actual sha256. The frontend never supplies file
//! system paths; library entries are addressed by catalog id only.
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::Manager;

use crate::features::crypto::ipc::crack::inspect_recovery_wordlist;

/// Download ceiling, matching the wordlist import policy.
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
const USER_AGENT: &str = "CyberDeck-WordlistLibrary/1";

#[derive(Serialize)]
pub struct WordlistLibraryEntry {
    pub id: String,
    pub name: String,
    /// Where the bytes come from when present.
    pub origin: WordlistOrigin,
    pub size_bytes: u64,
    pub present: bool,
    pub source_url: Option<&'static str>,
    pub license_note: &'static str,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WordlistOrigin {
    Bundled,
    Downloaded,
}

#[derive(Serialize, Clone)]
pub struct DownloadProgress {
    pub id: String,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
}

struct CatalogEntry {
    id: &'static str,
    name: &'static str,
    source_url: &'static str,
    license_note: &'static str,
    /// Minimum bytes a completed download must have; catches truncation.
    min_bytes: u64,
}

/// Curated, widely mirrored password lists. SecLists is MIT licensed; the
/// rockyou list is breach-release data redistributed by a standard mirror.
const CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        id: "seclists-top-1000000",
        name: "SecLists top 1,000,000 passwords",
        source_url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-1000000.txt",
        license_note: "MIT (SecLists)",
        min_bytes: 8_000_000,
    },
    CatalogEntry {
        id: "rockyou",
        name: "rockyou.txt (14.3 million passwords)",
        source_url: "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
        license_note: "Breach-release data; standard security-research mirror",
        min_bytes: 100_000_000,
    },
];

fn bundled_name() -> &'static str {
    "cyberdeck-common.txt"
}

fn bundled_root(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    if let Ok(packaged) = app
        .path()
        .resource_dir()
        .map_err(|_| "app resources unavailable".to_string())
        .map(|dir| dir.join("wordlists"))
    {
        if packaged.is_dir() {
            return Ok(packaged);
        }
    }
    #[cfg(debug_assertions)]
    {
        let dev = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/wordlists");
        if dev.is_dir() {
            return Ok(dev);
        }
    }
    Err("bundled wordlists are not packaged".into())
}

fn download_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|_| "app data directory unavailable".to_string())?;
    let dir = base.join("wordlists");
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create wordlist library: {e}"))?;
    Ok(dir)
}

fn catalog(id: &str) -> Result<&'static CatalogEntry, String> {
    CATALOG
        .iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| "unknown wordlist id".to_string())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Resolve a catalog id to a concrete local file path, verifying that it is
/// a regular file inside the expected size policy.
pub fn resolve(app: &tauri::AppHandle, id: &str) -> Result<std::path::PathBuf, String> {
    if id == "cyberdeck-common" {
        let path = bundled_root(app)?.join(bundled_name());
        return verify_regular(&path);
    }
    let entry = catalog(id)?;
    let path = download_dir(app)?.join(format!("{}.txt", entry.id));
    verify_regular(&path)
}

fn verify_regular(path: &std::path::PathBuf) -> Result<std::path::PathBuf, String> {
    let meta = std::fs::metadata(path).map_err(|_| "wordlist is not downloaded".to_string())?;
    if !meta.is_file() {
        return Err("wordlist path is not a regular file".into());
    }
    Ok(path.clone())
}

pub fn list(app: &tauri::AppHandle) -> Result<Vec<WordlistLibraryEntry>, String> {
    let mut entries = Vec::new();
    if let Ok(path) = resolve(app, "cyberdeck-common") {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        entries.push(WordlistLibraryEntry {
            id: "cyberdeck-common".into(),
            name: "CyberDeck common passwords (built in)".into(),
            origin: WordlistOrigin::Bundled,
            size_bytes: size,
            present: true,
            source_url: None,
            license_note: "Authored for CyberDeck",
        });
    }
    let dir = download_dir(app)?;
    for entry in CATALOG {
        let path = dir.join(format!("{}.txt", entry.id));
        let meta = std::fs::metadata(&path).ok();
        let present = meta.as_ref().is_some_and(|m| m.is_file());
        entries.push(WordlistLibraryEntry {
            id: entry.id.into(),
            name: entry.name.into(),
            origin: WordlistOrigin::Downloaded,
            size_bytes: meta.map(|m| m.len()).unwrap_or(0),
            present,
            source_url: Some(entry.source_url),
            license_note: entry.license_note,
        });
    }
    Ok(entries)
}

pub fn remove(app: &tauri::AppHandle, id: &str) -> Result<bool, String> {
    let entry = catalog(id)?;
    let path = download_dir(app)?.join(format!("{}.txt", entry.id));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot delete wordlist: {error}")),
    }
}

/// Stream a catalog download into a sibling temp file, enforcing the size cap
/// while chunks arrive, then atomically move it into place. Progress is
/// reported through the IPC channel; the sha256 of the exact bytes received
/// is returned so the operator can pin it later.
pub async fn fetch(
    app: &tauri::AppHandle,
    id: &str,
    on_progress: impl Fn(DownloadProgress) + Send,
) -> Result<String, String> {
    let entry = catalog(id)?;
    let dir = download_dir(app)?;
    let final_path = dir.join(format!("{}.txt", entry.id));
    let temp_path = dir.join(format!(".{}.part", entry.id));
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| format!("cannot start download: {e}"))?;
    let response = client
        .get(entry.source_url)
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("download failed: HTTP {}", response.status()));
    }
    if let Some(length) = response.content_length() {
        if length > MAX_DOWNLOAD_BYTES {
            return Err(format!(
                "source is {} MB; the download cap is {} MB",
                length / (1024 * 1024),
                MAX_DOWNLOAD_BYTES / (1024 * 1024)
            ));
        }
    }
    let total = response.content_length();
    use futures_util::StreamExt;
    let mut stream = response
        .bytes_stream()
        .map(|chunk| chunk.map_err(|e| format!("download interrupted: {e}")));
    let file = std::fs::File::create(&temp_path)
        .map_err(|e| format!("cannot create download file: {e}"))?;
    let mut writer = std::io::BufWriter::with_capacity(1 << 20, file);
    use std::io::Write;
    let mut downloaded: u64 = 0;
    let mut hasher = Sha256::new();
    let mut next_report = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        downloaded += chunk.len() as u64;
        if downloaded > MAX_DOWNLOAD_BYTES {
            let _ = std::fs::remove_file(&temp_path);
            return Err(format!(
                "download exceeded the {} MB cap and was aborted",
                MAX_DOWNLOAD_BYTES / (1024 * 1024)
            ));
        }
        hasher.update(&chunk);
        writer
            .write_all(&chunk)
            .map_err(|e| format!("cannot write download: {e}"))?;
        if downloaded >= next_report {
            on_progress(DownloadProgress {
                id: entry.id.into(),
                downloaded_bytes: downloaded,
                total_bytes: total,
            });
            next_report = downloaded.saturating_add(1 << 20);
        }
    }
    writer
        .flush()
        .map_err(|e| format!("cannot finish download: {e}"))?;
    drop(writer);
    if downloaded < entry.min_bytes {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!(
            "downloaded file is {} bytes; expected at least {} for this source",
            downloaded, entry.min_bytes
        ));
    }
    std::fs::rename(&temp_path, &final_path)
        .map_err(|e| format!("cannot finalize download: {e}"))?;
    on_progress(DownloadProgress {
        id: entry.id.into(),
        downloaded_bytes: downloaded,
        total_bytes: total,
    });
    Ok(sha256_hex(&std::fs::read(&final_path).map_err(|e| format!("cannot verify download: {e}"))?))
}

/// Wrap the shared wordlist inspection (regular file, size cap) for a
/// library-resolved path. Returns the display name and byte size.
pub fn inspect_resolved(path: &std::path::PathBuf) -> Result<(String, u64), String> {
    inspect_recovery_wordlist(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_constrained_and_unique() {
        let mut ids: Vec<&str> = CATALOG.iter().map(|entry| entry.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), CATALOG.len());
        for entry in CATALOG {
            assert!(!entry.id.is_empty() && entry.id.len() < 64);
            assert!(entry
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'));
            assert!(entry.source_url.starts_with("https://"));
            assert!(entry.min_bytes > 0);
        }
    }

    #[test]
    fn unknown_catalog_id_is_rejected() {
        assert!(catalog("rockyou").is_ok());
        assert!(catalog("nonexistent").is_err());
        assert!(catalog("../../etc/passwd").is_err());
    }

    #[test]
    fn bundled_wordlist_is_present_and_nonempty() {
        let dev =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/wordlists");
        let path = dev.join(bundled_name());
        let data = std::fs::read(&path).expect("bundled wordlist must exist");
        assert!(data.len() > 1024);
        let text = String::from_utf8(data).expect("wordlist must be utf-8");
        let lines = text.lines().filter(|line| !line.trim().is_empty()).count();
        assert!(lines >= 200, "bundled list should cover the common basics");
        assert_eq!(text.lines().next(), Some("123456"));
    }

    #[test]
    fn sha256_helper_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

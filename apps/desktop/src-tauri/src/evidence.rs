//! Evidence import and inspection (Master Plan §5.6). Files enter the case
//! store only through these commands: the frontend never supplies paths.
//! Originals are copied immutably into the case artifact directory; the
//! SQLite index keeps metadata with full digests for reproducibility.

use std::path::Path;
use std::sync::Mutex;

use hacktool_crypto::{apply_op, detect_signature, entropy};
use hacktool_storage::{ArtifactRecord, ArtifactStore, DEFAULT_CASE};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

/// Import size guard: hashing and hex views operate on in-memory bytes this
/// arc; streaming for multi-hundred-MB files arrives with the storage upgrade.
const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_HEX_REQUEST: i64 = 4096;
const MAX_STRINGS_SCAN: usize = 8 * 1024 * 1024;
const MAX_STRINGS_HITS: usize = 2000;

pub struct EvidenceCtx {
    pub store: Mutex<ArtifactStore>,
    pub artifacts_dir: std::path::PathBuf,
}

#[derive(Debug, Serialize)]
pub struct HexRow {
    pub offset: usize,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Serialize)]
pub struct HexResponse {
    pub rows: Vec<HexRow>,
    pub offset: i64,
    pub total_size: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringHit {
    pub offset: usize,
    pub text: String,
}

fn digest_of(op: &str, bytes: &[u8]) -> Result<String, String> {
    let out = apply_op(op, bytes, None)?;
    Ok(hex::encode(out))
}

fn sanitize_file_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect()
}

fn import_bytes(ctx: &EvidenceCtx, source: &Path, bytes: &[u8]) -> Result<ArtifactRecord, String> {
    let sha256 = digest_of("sha256", bytes)?;
    let md5 = digest_of("md5", bytes)?;
    let sha1 = digest_of("sha1", bytes)?;
    let crc32 = digest_of("crc32", bytes)?;
    let signature = detect_signature(bytes)
        .map(str::to_string)
        .or_else(|| {
            // printable-dominant content reads as text
            let printable = bytes
                .iter()
                .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
                .count();
            (!bytes.is_empty() && printable * 100 / bytes.len() >= 95).then(|| "ASCII text".to_string())
        });
    let entropy_value = entropy(bytes);
    let imported_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string());

    // content-addressed identity: re-importing identical bytes replaces the record
    let id = format!("sha256-{}", &sha256[..16]);
    let original_name = source
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "evidence.bin".to_string());
    let stored_name = format!("{sha256}_{}", sanitize_file_name(&original_name));
    let case_dir = ctx.artifacts_dir.join(DEFAULT_CASE);
    std::fs::create_dir_all(&case_dir).map_err(|e| format!("cannot create case directory: {e}"))?;
    let stored_path = case_dir.join(&stored_name);
    if !stored_path.exists() {
        std::fs::write(&stored_path, bytes).map_err(|e| format!("cannot store evidence copy: {e}"))?;
    }

    let record = ArtifactRecord {
        id: id.clone(),
        case_id: DEFAULT_CASE.to_string(),
        name: original_name,
        stored_path: stored_path.to_string_lossy().to_string(),
        original_path: Some(source.to_string_lossy().to_string()),
        size: bytes.len() as u64,
        sha256,
        md5,
        sha1,
        crc32,
        signature,
        entropy: entropy_value,
        imported_at,
    };
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.upsert_artifact(&record)?;
    Ok(record)
}

#[tauri::command]
pub fn file_import_dialog(app: AppHandle, ctx: State<'_, EvidenceCtx>) -> Result<ArtifactRecord, String> {
    let picked = app.dialog().file().blocking_pick_file().ok_or("cancelled")?;
    let path = picked.as_path().ok_or("unsupported file location")?.to_path_buf();
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read file metadata: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "file is {} MB; the import limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read file: {e}"))?;
    import_bytes(&ctx, &path, &bytes)
}

#[tauri::command]
pub fn file_list(ctx: State<'_, EvidenceCtx>, case: Option<String>) -> Result<Vec<ArtifactRecord>, String> {
    list(&ctx, case.as_deref().unwrap_or(DEFAULT_CASE))
}

fn list(ctx: &EvidenceCtx, case_id: &str) -> Result<Vec<ArtifactRecord>, String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.list_artifacts(case_id)
}

fn load_record_bytes(ctx: &EvidenceCtx, id: &str) -> Result<(ArtifactRecord, Vec<u8>), String> {
    let record = {
        let store = ctx.store.lock().expect("artifact store poisoned");
        store
            .get_artifact(id)?
            .ok_or_else(|| format!("unknown artifact id: {id}"))?
    };
    // stored_path originates from our own index, never from the frontend
    let bytes = std::fs::read(&record.stored_path).map_err(|e| format!("cannot read stored evidence: {e}"))?;
    Ok((record, bytes))
}

#[tauri::command]
pub fn file_hex(ctx: State<'_, EvidenceCtx>, id: String, offset: i64, len: i64) -> Result<HexResponse, String> {
    hex_view(&ctx, &id, offset, len)
}

fn hex_view(ctx: &EvidenceCtx, id: &str, offset: i64, len: i64) -> Result<HexResponse, String> {
    let (_, bytes) = load_record_bytes(ctx, id)?;
    let total = bytes.len() as i64;
    let start = offset.clamp(0, total.max(0)) as usize;
    let wanted = len.clamp(1, MAX_HEX_REQUEST) as usize;
    let end = (start + wanted).min(bytes.len());
    let slice = &bytes[start..end];
    let mut rows = Vec::with_capacity((slice.len() + 15) / 16);
    for (i, chunk) in slice.chunks(16).enumerate() {
        let hex_str: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect();
        rows.push(HexRow {
            offset: start + i * 16,
            hex: hex_str.trim_end().to_string(),
            ascii,
        });
    }
    Ok(HexResponse {
        complete: end >= bytes.len(),
        offset: start as i64,
        total_size: total as u64,
        rows,
    })
}

#[tauri::command]
pub fn file_strings(ctx: State<'_, EvidenceCtx>, id: String, min_len: i32, max_hits: i32) -> Result<Vec<StringHit>, String> {
    strings(&ctx, &id, min_len, max_hits)
}

fn strings(ctx: &EvidenceCtx, id: &str, min_len: i32, max_hits: i32) -> Result<Vec<StringHit>, String> {
    let (_, bytes) = load_record_bytes(ctx, id)?;
    let scan = &bytes[..bytes.len().min(MAX_STRINGS_SCAN)];
    let min_len = min_len.clamp(2, 128) as usize;
    let max_hits = max_hits.clamp(1, MAX_STRINGS_HITS as i32) as usize;
    let mut hits = Vec::new();
    let mut start: Option<usize> = None;
    let indexed = scan.iter().copied().enumerate().chain(std::iter::once((scan.len(), 0u8)));
    for (i, b) in indexed {
        let printable = i < scan.len() && (0x20..=0x7e).contains(&b);
        if printable && start.is_none() {
            start = Some(i);
        }
        if !printable {
            if let Some(s) = start {
                if i - s >= min_len {
                    hits.push(StringHit {
                        offset: s,
                        text: String::from_utf8_lossy(&scan[s..i]).to_string(),
                    });
                    if hits.len() >= max_hits {
                        break;
                    }
                }
                start = None;
            }
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx(dir: &Path) -> EvidenceCtx {
        EvidenceCtx {
            store: Mutex::new(ArtifactStore::open(&dir.join("index.db")).unwrap()),
            artifacts_dir: dir.to_path_buf(),
        }
    }

    #[test]
    fn import_computes_digests_and_signature() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let src = dir.path().join("sample.zip");
        std::fs::write(&src, b"PK\x03\x04 fake zip body").unwrap();
        let bytes = std::fs::read(&src).unwrap();
        let record = import_bytes(&ctx, &src, &bytes).unwrap();
        assert_eq!(record.signature.as_deref(), Some("ZIP archive"));
        assert_eq!(record.sha256.len(), 64);
        assert_eq!(record.md5.len(), 32);
        assert!(record.entropy > 0.0);
        assert!(record.stored_path.contains(&record.sha256));
        // content-addressed: re-import replaces, not duplicates
        let again = import_bytes(&ctx, &src, &bytes).unwrap();
        assert_eq!(again.id, record.id);
        assert_eq!(ctx.store.lock().unwrap().list_artifacts(DEFAULT_CASE).unwrap().len(), 1);
    }

    #[test]
    fn hex_view_matches_known_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let src = dir.path().join("abc.txt");
        std::fs::write(&src, b"abc").unwrap();
        let bytes = std::fs::read(&src).unwrap();
        let record = import_bytes(&ctx, &src, &bytes).unwrap();
        let view = hex_view(&ctx, &record.id, 0, 16).unwrap();
        assert_eq!(view.rows[0].hex, "61 62 63");
        assert_eq!(view.rows[0].ascii, "abc");
        assert!(view.complete);
    }

    #[test]
    fn strings_extracts_printable_runs() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let src = dir.path().join("bin.dat");
        std::fs::write(&src, b"\x00\x01\x02user=admin\x03\x04path=/bin\x00").unwrap();
        let bytes = std::fs::read(&src).unwrap();
        let record = import_bytes(&ctx, &src, &bytes).unwrap();
        let hits = strings(&ctx, &record.id, 4, 100).unwrap();
        let texts: Vec<_> = hits.into_iter().map(|h| h.text).collect();
        assert!(texts.contains(&"user=admin".to_string()));
        assert!(texts.contains(&"path=/bin".to_string()));
    }
}

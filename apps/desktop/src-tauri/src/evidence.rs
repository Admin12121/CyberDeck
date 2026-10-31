//! Evidence import and inspection (§5.6). Files enter only via these commands;
//! originals are copied immutably and indexed with full digests.

use base64::Engine as _;
use std::path::Path;
use std::sync::Mutex;

use cyberdeck_crypto::{apply_op, detect_signature, entropy};
use cyberdeck_storage::{
    validate_case_id, ArtifactRecord, ArtifactStore, NewFinding, DEFAULT_CASE,
};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

/// Import size guard: hashing and hex views operate on in-memory bytes this
/// arc; streaming for multi-hundred-MB files arrives with the storage upgrade.
pub(crate) const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_HEX_REQUEST: i64 = 4096;
const MAX_STRINGS_SCAN: usize = 8 * 1024 * 1024;
const MAX_STRINGS_HITS: usize = 2000;
const MAX_DERIVED_BYTES: usize = 8 * 1024 * 1024;

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
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn import_bytes(
    ctx: &EvidenceCtx,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
) -> Result<ArtifactRecord, String> {
    validate_case_id(case_id)?;
    if !ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .case_exists(case_id)?
    {
        return Err("selected case does not exist".into());
    }
    let sha256 = digest_of("sha256", bytes)?;
    let md5 = digest_of("md5", bytes)?;
    let sha1 = digest_of("sha1", bytes)?;
    let crc32 = digest_of("crc32", bytes)?;
    let signature = detect_signature(bytes).map(str::to_string).or_else(|| {
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
    let kind = if disk_source {
        "sha256"
    } else {
        "derived-sha256"
    };
    let id = if case_id == DEFAULT_CASE {
        format!("{kind}-{}", &sha256[..16])
    } else {
        format!("{case_id}:{kind}-{}", &sha256[..16])
    };
    let original_name = source
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "evidence.bin".to_string());
    let stored_name = format!("{sha256}_{}", sanitize_file_name(&original_name));
    let case_dir = ctx.artifacts_dir.join(case_id);
    std::fs::create_dir_all(&case_dir).map_err(|e| format!("cannot create case directory: {e}"))?;
    let stored_path = case_dir.join(&stored_name);
    if !stored_path.exists() {
        std::fs::write(&stored_path, bytes)
            .map_err(|e| format!("cannot store evidence copy: {e}"))?;
    }

    let record = ArtifactRecord {
        id: id.clone(),
        case_id: case_id.to_string(),
        name: original_name,
        stored_path: stored_path.to_string_lossy().to_string(),
        original_path: disk_source.then(|| source.to_string_lossy().to_string()),
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
    store.record_event(
        case_id,
        if disk_source {
            "forensics.import"
        } else {
            "crypto.recipes"
        },
        if disk_source { "import" } else { "derived" },
        Some(&record.id),
        &record.name,
    )?;
    Ok(record)
}

#[tauri::command]
pub fn file_import_dialog(
    app: AppHandle,
    ctx: State<'_, EvidenceCtx>,
    case_id: Option<String>,
) -> Result<ArtifactRecord, String> {
    let picked = app
        .dialog()
        .file()
        .blocking_pick_file()
        .ok_or("cancelled")?;
    let path = picked
        .as_path()
        .ok_or("unsupported file location")?
        .to_path_buf();
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read file metadata: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "file is {} MB; the import limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read file: {e}"))?;
    import_bytes(
        &ctx,
        &path,
        &bytes,
        case_id.as_deref().unwrap_or(DEFAULT_CASE),
        true,
    )
}

/// Promote an explicitly selected recipe output into immutable case evidence.
/// The untrusted IPC payload has a strict decoded-byte limit and cannot choose
/// a filesystem path. A corresponding finding links the generated artifact.
#[tauri::command]
pub fn file_import_derived(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    name: String,
    data_b64: String,
    source_description: Option<String>,
) -> Result<ArtifactRecord, String> {
    validate_case_id(&case_id)?;
    if name.trim().is_empty()
        || name.len() > 100
        || data_b64.len() > (MAX_DERIVED_BYTES + 2) / 3 * 4 + 8
    {
        return Err("invalid derived artifact name or payload size".into());
    }
    let safe_name = sanitize_file_name(name.trim());
    if safe_name.is_empty() || safe_name == "." || safe_name == ".." {
        return Err("invalid derived artifact name".into());
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(&data_b64)
        .map_err(|e| format!("invalid derived artifact encoding: {e}"))?;
    if data.len() > MAX_DERIVED_BYTES {
        return Err("derived artifact exceeds 8 MiB limit".into());
    }
    let source_description = source_description.unwrap_or_else(|| "Manual Recipes input".into());
    if source_description.len() > 512 {
        return Err("source description too long".into());
    }
    let record = import_bytes(&ctx, Path::new(&safe_name), &data, &case_id, false)?;
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable")?
        .record_event(
            &case_id,
            "crypto.recipes",
            "transformation",
            Some(&record.id),
            &source_description,
        )?;
    let note = NewFinding {
        title: format!("Derived file: {}", record.name),
        severity: "info".to_string(),
        details: format!(
            "Saved from CyberDeck Recipes into case {}\nSHA256: {}\nSize: {} bytes",
            case_id, record.sha256, record.size
        ),
    };
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable")?
        .add_findings(&case_id, "crypto.recipes", Some(&record.id), &[note])?;
    Ok(record)
}

#[tauri::command]
pub fn file_list(
    ctx: State<'_, EvidenceCtx>,
    case: Option<String>,
) -> Result<Vec<ArtifactRecord>, String> {
    list(&ctx, case.as_deref().unwrap_or(DEFAULT_CASE))
}

fn list(ctx: &EvidenceCtx, case_id: &str) -> Result<Vec<ArtifactRecord>, String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.list_artifacts(case_id)
}

fn load_record_bytes(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
) -> Result<(ArtifactRecord, Vec<u8>), String> {
    validate_case_id(case_id)?;
    let record = {
        let store = ctx.store.lock().expect("artifact store poisoned");
        store
            .get_artifact(id)?
            .filter(|item| item.case_id == case_id)
            .ok_or_else(|| "artifact not found in selected case".to_string())?
    };
    // stored_path originates from our own index, never from the frontend
    let bytes = std::fs::read(&record.stored_path)
        .map_err(|e| format!("cannot read stored evidence: {e}"))?;
    Ok((record, bytes))
}

#[derive(Debug, Serialize)]
pub struct SignatureScanResponse {
    pub hits: Vec<cyberdeck_crypto::formats::SignatureHit>,
    pub scanned_bytes: usize,
    pub file_bytes: u64,
    pub truncated: bool,
    pub integrity_checked: bool,
}

/// Offline binary format detection. No extraction or external executables.
/// Only the first 16 MiB is scanned, with a cap on returned signatures.
#[tauri::command]
pub fn file_signature_scan(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
) -> Result<SignatureScanResponse, String> {
    signature_scan(&ctx, &case_id, &id)
}

fn signature_scan(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
) -> Result<SignatureScanResponse, String> {
    use cyberdeck_crypto::formats::{scan_signatures, MAX_SIGNATURE_SCAN_BYTES};
    use std::io::Read;
    validate_case_id(case_id)?;
    let record = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(id)?
        .filter(|item| item.case_id == case_id)
        .ok_or_else(|| "artifact does not belong to the selected case".to_string())?;
    let source = std::fs::File::open(&record.stored_path)
        .map_err(|e| format!("cannot open stored evidence: {e}"))?;
    let file_bytes = source.metadata().map_err(|e| e.to_string())?.len();
    if file_bytes != record.size {
        return Err(
            "evidence integrity failure: stored file size differs from its indexed size".into(),
        );
    }
    let mut bytes = Vec::with_capacity((file_bytes as usize).min(MAX_SIGNATURE_SCAN_BYTES));
    source
        .take(MAX_SIGNATURE_SCAN_BYTES as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot scan evidence: {e}"))?;
    let integrity_checked = file_bytes <= MAX_SIGNATURE_SCAN_BYTES as u64;
    if integrity_checked && digest_of("sha256", &bytes)? != record.sha256 {
        return Err(
            "evidence integrity failure: stored SHA256 differs from its indexed hash".into(),
        );
    }
    Ok(SignatureScanResponse {
        hits: scan_signatures(&bytes, 256),
        scanned_bytes: bytes.len(),
        file_bytes,
        truncated: !integrity_checked,
        integrity_checked,
    })
}

#[tauri::command]
pub fn file_hex(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    offset: i64,
    len: i64,
) -> Result<HexResponse, String> {
    hex_view(&ctx, &case_id, &id, offset, len)
}

fn hex_view(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: i64,
    len: i64,
) -> Result<HexResponse, String> {
    let (_, bytes) = load_record_bytes(ctx, case_id, id)?;
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
            .map(|&b| {
                if (0x20..=0x7e).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
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
pub fn file_strings(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    min_len: i32,
    max_hits: i32,
) -> Result<Vec<StringHit>, String> {
    strings(&ctx, &case_id, &id, min_len, max_hits)
}

#[derive(Debug, Serialize)]
pub struct FileDigestsWire {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub crc32: String,
}

/// Digest a picked file without importing it into the case store.
#[tauri::command]
pub fn digest_file_dialog(app: AppHandle) -> Result<FileDigestsWire, String> {
    let picked = app
        .dialog()
        .file()
        .blocking_pick_file()
        .ok_or("cancelled")?;
    let path = picked
        .as_path()
        .ok_or("unsupported file location")?
        .to_path_buf();
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read file metadata: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "file is {} MB; the limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read file: {e}"))?;
    Ok(FileDigestsWire {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string()),
        size: bytes.len() as u64,
        sha256: digest_of("sha256", &bytes)?,
        sha1: digest_of("sha1", &bytes)?,
        md5: digest_of("md5", &bytes)?,
        crc32: digest_of("crc32", &bytes)?,
    })
}

fn strings(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    min_len: i32,
    max_hits: i32,
) -> Result<Vec<StringHit>, String> {
    let (_, bytes) = load_record_bytes(ctx, case_id, id)?;
    let scan = &bytes[..bytes.len().min(MAX_STRINGS_SCAN)];
    let min_len = min_len.clamp(2, 128) as usize;
    let max_hits = max_hits.clamp(1, MAX_STRINGS_HITS as i32) as usize;
    let mut hits = Vec::new();
    let mut start: Option<usize> = None;
    let indexed = scan
        .iter()
        .copied()
        .enumerate()
        .chain(std::iter::once((scan.len(), 0u8)));
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
    fn derived_artifact_is_isolated_to_selected_case() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let new_case = ctx
            .store
            .lock()
            .unwrap()
            .create_case("Analysis Lab", "")
            .unwrap();
        let source = Path::new("recipe-output.bin");
        let derived = import_bytes(&ctx, source, b"hello", &new_case.id, false).unwrap();
        assert_eq!(derived.case_id, new_case.id);
        assert!(derived.original_path.is_none());
        assert!(derived.stored_path.contains(&new_case.id));
        let scratch = import_bytes(&ctx, source, b"hello", DEFAULT_CASE, true).unwrap();
        let generated_in_scratch =
            import_bytes(&ctx, source, b"hello", DEFAULT_CASE, false).unwrap();
        assert_ne!(scratch.id, generated_in_scratch.id);
        assert_eq!(scratch.original_path.as_deref(), Some("recipe-output.bin"));
        assert!(generated_in_scratch.original_path.is_none());
        assert_ne!(derived.id, scratch.id);
        assert_eq!(
            ctx.store
                .lock()
                .unwrap()
                .list_artifacts(&new_case.id)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            ctx.store
                .lock()
                .unwrap()
                .list_artifacts(DEFAULT_CASE)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn signature_scan_is_case_scoped_and_checks_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let case = ctx
            .store
            .lock()
            .unwrap()
            .create_case("Analysis", "")
            .unwrap();
        let path = Path::new("firmware.bin");
        let mut data = b"prefix".to_vec();
        data.extend_from_slice(b"%PDF-1.7\n");
        let record = import_bytes(&ctx, path, &data, &case.id, false).unwrap();
        assert!(signature_scan(&ctx, DEFAULT_CASE, &record.id).is_err());
        let result = signature_scan(&ctx, &case.id, &record.id).unwrap();
        assert!(result.integrity_checked);
        assert!(result
            .hits
            .iter()
            .any(|h| h.format == "pdf" && h.offset == 6));
        std::fs::write(&record.stored_path, b"mismatch").unwrap();
        assert!(signature_scan(&ctx, &case.id, &record.id)
            .unwrap_err()
            .contains("integrity"));
    }

    #[test]
    fn hex_and_strings_enforce_case_isolation() {
        let temp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(temp.path());
        let private_case = ctx
            .store
            .lock()
            .unwrap()
            .create_case("Private", "")
            .unwrap();
        let record = import_bytes(
            &ctx,
            Path::new("secret.txt"),
            b"private-data",
            &private_case.id,
            true,
        )
        .unwrap();
        assert!(hex_view(&ctx, DEFAULT_CASE, &record.id, 0, 8).is_err());
        assert!(strings(&ctx, DEFAULT_CASE, &record.id, 3, 20).is_err());
        assert!(!hex_view(&ctx, &private_case.id, &record.id, 0, 16)
            .unwrap()
            .rows
            .is_empty());
    }

    #[test]
    fn import_computes_digests_and_signature() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let src = dir.path().join("sample.zip");
        std::fs::write(&src, b"PK\x03\x04 fake zip body").unwrap();
        let bytes = std::fs::read(&src).unwrap();
        let record = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
        assert_eq!(record.signature.as_deref(), Some("ZIP archive"));
        assert_eq!(record.sha256.len(), 64);
        assert_eq!(record.md5.len(), 32);
        assert!(record.entropy > 0.0);
        assert!(record.stored_path.contains(&record.sha256));
        // content-addressed: re-import replaces, not duplicates
        let again = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
        assert_eq!(again.id, record.id);
        assert_eq!(
            ctx.store
                .lock()
                .unwrap()
                .list_artifacts(DEFAULT_CASE)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn hex_view_matches_known_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let src = dir.path().join("abc.txt");
        std::fs::write(&src, b"abc").unwrap();
        let bytes = std::fs::read(&src).unwrap();
        let record = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
        let view = hex_view(&ctx, DEFAULT_CASE, &record.id, 0, 16).unwrap();
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
        let record = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
        let hits = strings(&ctx, DEFAULT_CASE, &record.id, 4, 100).unwrap();
        let texts: Vec<_> = hits.into_iter().map(|h| h.text).collect();
        assert!(texts.contains(&"user=admin".to_string()));
        assert!(texts.contains(&"path=/bin".to_string()));
    }
}

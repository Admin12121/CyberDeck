//! Evidence import and inspection (§5.6). Files enter only via these commands;
//! originals are copied immutably and indexed with full digests.

use base64::Engine as _;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use cyberdeck_crypto::{apply_op, detect_signature, entropy};
use cyberdeck_storage::{
    validate_case_id, ArtifactRecord, ArtifactStore, ImportBatchItem, ImportEvent, NewFinding,
    DEFAULT_CASE,
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

static NEXT_EVIDENCE_TEMP: AtomicU64 = AtomicU64::new(0);

/// Never trust an already-present destination merely because it exists:
/// reject symlinks/special files and compare the complete stored bytes.
fn verify_existing_evidence(path: &Path, expected: &[u8]) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat existing evidence: {e}"))?;
    if !meta.file_type().is_file() || meta.len() != expected.len() as u64 {
        return Err("existing evidence is not a regular file of the expected size".into());
    }
    let existing =
        std::fs::read(path).map_err(|e| format!("cannot verify existing evidence: {e}"))?;
    if existing != expected {
        return Err("existing evidence content integrity failure".into());
    }
    Ok(())
}

/// Write to an exclusive temporary file in the case directory, sync it, then
/// publish with an atomic no-clobber hard link. Rename alone can overwrite
/// an existing destination on some platforms and is therefore not suitable.
/// No archive-controlled filename reaches this path.
fn publish_evidence(case_dir: &Path, stored_path: &Path, bytes: &[u8]) -> Result<(), String> {
    if std::fs::symlink_metadata(stored_path).is_ok() {
        return verify_existing_evidence(stored_path, bytes);
    }
    let mut temporary = None;
    for _ in 0..16 {
        let nonce = NEXT_EVIDENCE_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = case_dir.join(format!(".evidence-{}-{nonce}.tmp", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                temporary = Some((path, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create evidence temporary file: {e}")),
        }
    }
    let (temp_path, mut file) =
        temporary.ok_or_else(|| "cannot reserve a unique evidence temporary path".to_string())?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|e| format!("cannot write evidence: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot sync evidence: {e}"))?;
        drop(file);
        match std::fs::hard_link(&temp_path, stored_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_existing_evidence(stored_path, bytes)
            }
            Err(e) => Err(format!("cannot publish immutable evidence: {e}")),
        }
    })();
    let _ = std::fs::remove_file(&temp_path);
    result
}

fn import_bytes(
    ctx: &EvidenceCtx,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
) -> Result<ArtifactRecord, String> {
    let description = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "evidence.bin".into());
    let events = [ImportEvent {
        source: if disk_source {
            "forensics.import"
        } else {
            "crypto.recipes"
        },
        action: if disk_source { "import" } else { "derived" },
        description: &description,
    }];
    import_bytes_with_events(ctx, source, bytes, case_id, disk_source, &events, &[])
}

fn import_bytes_with_events(
    ctx: &EvidenceCtx,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
    events: &[ImportEvent<'_>],
    findings: &[NewFinding],
) -> Result<ArtifactRecord, String> {
    let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
    let record = prepare_import_record(ctx, &store, source, bytes, case_id, disk_source)?;
    store.commit_artifact_import_with_events(&record, &ctx.artifacts_dir, events, findings)?;
    Ok(record)
}

/// Publish evidence safely but defer database changes to the caller. The
/// caller holds the case store lock throughout preparation and commit.
fn prepare_import_record(
    ctx: &EvidenceCtx,
    store: &ArtifactStore,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
) -> Result<ArtifactRecord, String> {
    validate_case_id(case_id)?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err("evidence exceeds the import size limit".into());
    }
    let sha256 = digest_of("sha256", bytes)?;
    let md5 = digest_of("md5", bytes)?;
    let sha1 = digest_of("sha1", bytes)?;
    let crc32 = digest_of("crc32", bytes)?;
    let signature = detect_signature(bytes).map(str::to_string).or_else(|| {
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
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "evidence.bin".into());

    if !store.case_exists(case_id)? {
        return Err("selected case does not exist".into());
    }
    let prior = store.get_artifact(&id)?;
    if let Some(old) = prior.as_ref() {
        if old.case_id != case_id || old.sha256 != sha256 || old.size != bytes.len() as u64 {
            return Err("immutable evidence identity conflict".into());
        }
    }
    let case_dir = ctx.artifacts_dir.join(case_id);
    std::fs::create_dir_all(&case_dir).map_err(|e| format!("cannot create case directory: {e}"))?;
    let case_meta = std::fs::symlink_metadata(&case_dir)
        .map_err(|e| format!("cannot inspect case directory: {e}"))?;
    if !case_meta.file_type().is_dir() || case_meta.file_type().is_symlink() {
        return Err("case evidence directory is a symlink or non-directory".into());
    }
    let root = std::fs::canonicalize(&ctx.artifacts_dir)
        .map_err(|e| format!("cannot resolve evidence root: {e}"))?;
    let resolved_case = std::fs::canonicalize(&case_dir)
        .map_err(|e| format!("cannot resolve case evidence directory: {e}"))?;
    if resolved_case == root || !resolved_case.starts_with(root) {
        return Err("case evidence directory escapes evidence root".into());
    }
    let stored_path = prior
        .as_ref()
        .map(|old| std::path::PathBuf::from(&old.stored_path))
        .unwrap_or_else(|| case_dir.join(format!("{sha256}.evidence")));
    // Existing historical names remain unchanged; new storage names are
    // digest-only, independent of the source filename.
    if let Some(old) = prior.as_ref() {
        cyberdeck_storage::verify_artifact_file(old, &ctx.artifacts_dir)?;
        verify_existing_evidence(&stored_path, bytes)?;
    } else {
        publish_evidence(&case_dir, &stored_path, bytes)?;
    }
    let record = prior.unwrap_or_else(|| ArtifactRecord {
        id,
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
    });
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
    let derived_hash = digest_of("sha256", &data)?;
    let events = [
        ImportEvent {
            source: "crypto.recipes",
            action: "derived",
            description: &safe_name,
        },
        ImportEvent {
            source: "crypto.recipes",
            action: "transformation",
            description: &source_description,
        },
    ];
    let findings = [NewFinding {
        title: format!("Derived file: {safe_name}"),
        severity: "info".into(),
        details: format!(
            "Saved from CyberDeck Recipes into case {}\nSHA256: {}\nSize: {} bytes",
            case_id,
            derived_hash,
            data.len()
        ),
    }];
    import_bytes_with_events(
        &ctx,
        Path::new(&safe_name),
        &data,
        &case_id,
        false,
        &events,
        &findings,
    )
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

/// Inspect one case artifact without executing it. Limited to 16 MiB; every
/// inspected byte is checked against the immutable evidence digest.
#[tauri::command]
pub fn file_binary_inspect(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
) -> Result<cyberdeck_crypto::formats::binary::BinaryInfo, String> {
    binary_inspect(&ctx, &case_id, &id)
}

fn binary_inspect(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
) -> Result<cyberdeck_crypto::formats::binary::BinaryInfo, String> {
    use cyberdeck_crypto::formats::binary::{inspect_binary, MAX_BINARY_BYTES};
    validate_case_id(case_id)?;
    let record = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(id)?
        .filter(|item| item.case_id == case_id)
        .ok_or("artifact not found in selected case")?;
    if record.size > MAX_BINARY_BYTES as u64 {
        return Err("binary inspection currently limited to 16 MiB evidence".into());
    }
    let bytes =
        std::fs::read(&record.stored_path).map_err(|e| format!("cannot read evidence: {e}"))?;
    if bytes.len() as u64 != record.size || digest_of("sha256", &bytes)? != record.sha256 {
        return Err("source evidence integrity failure".into());
    }
    inspect_binary(&bytes)
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

/// Extract one embedded Gzip member without executing external programs,
/// using the selected case's immutable evidence copy as input.
#[tauri::command]
pub fn file_extract_gzip(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    offset: usize,
) -> Result<ArtifactRecord, String> {
    extract_gzip_from_evidence(&ctx, &case_id, &id, offset)
}

fn extract_gzip_from_evidence(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: usize,
) -> Result<ArtifactRecord, String> {
    use cyberdeck_crypto::extraction::{
        extract_gzip_limited, MAX_GZIP_INPUT_BYTES, MAX_GZIP_OUTPUT_BYTES,
    };
    validate_case_id(case_id)?;
    let record = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(id)?
        .filter(|item| item.case_id == case_id)
        .ok_or_else(|| "source artifact not found in selected case".to_string())?;
    if record.size > MAX_GZIP_INPUT_BYTES as u64 {
        return Err("gzip extraction limited to stored files of at most 16 MiB".into());
    }
    cyberdeck_storage::verify_artifact_file(&record, &ctx.artifacts_dir)?;
    let data = std::fs::read(&record.stored_path)
        .map_err(|e| format!("cannot read stored source: {e}"))?;
    if data.len() as u64 != record.size || digest_of("sha256", &data)? != record.sha256 {
        return Err("source evidence integrity failure".into());
    }
    let output = extract_gzip_limited(&data, offset, MAX_GZIP_OUTPUT_BYTES)?;
    let name = format!("gzip-offset-{offset:x}.bin");
    let derived_hash = digest_of("sha256", &output)?;
    let description = format!("Source artifact {} gzip offset 0x{offset:x}", record.id);
    let events = [
        ImportEvent {
            source: "forensics.gzip",
            action: "derived",
            description: &name,
        },
        ImportEvent {
            source: "forensics.gzip",
            action: "extract",
            description: &description,
        },
    ];
    let findings = [NewFinding {
        title: format!("Extracted Gzip member at 0x{offset:x}"),
        severity: "info".into(),
        details: format!(
            "Source: {} (sha256 {})\nDerived SHA-256: {}\nUncompressed length: {}",
            record.id,
            record.sha256,
            derived_hash,
            output.len(),
        ),
    }];
    import_bytes_with_events(
        ctx,
        Path::new(&name),
        &output,
        case_id,
        false,
        &events,
        &findings,
    )
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

/// Extract regular files from a validated ZIP or ustar TAR into this case.
struct PlannedArchiveEntry {
    name: String,
    bytes: Vec<u8>,
    provenance: String,
    title: String,
}

/// Plan and validate every member first; publish immutable bytes under the
/// case store lock, then atomically commit all unique artifact indexes, events
/// and findings in a single storage transaction. File publication itself is
/// not part of the SQLite transaction, so a failed DB commit can leave
/// unindexed bytes for a later integrity/recovery scan.
fn import_archive_batch(
    ctx: &EvidenceCtx,
    case_id: &str,
    source_tag: &'static str,
    planned: Vec<PlannedArchiveEntry>,
) -> Result<Vec<ArtifactRecord>, String> {
    use std::collections::HashMap;
    validate_case_id(case_id)?;
    if planned.is_empty() {
        return Ok(Vec::new());
    }
    // The storage API supports up to 32 unique artifacts per atomic batch
    // and at most 32 events for any one artifact. Duplicate bytes share an
    // immutable artifact ID, so multiple archive paths aggregate lineage.
    let mut occurrences = HashMap::<String, usize>::new();
    for plan in &planned {
        if plan.name.is_empty()
            || plan.name.len() > 100
            || plan.provenance.len() > 512
            || plan.title.len() > 200
        {
            return Err("archive metadata exceeds atomic import limits".into());
        }
        let digest = digest_of("sha256", &plan.bytes)?;
        let seen = occurrences.entry(digest).or_default();
        *seen += 1;
        if *seen > 16 {
            return Err("identical archive data exceeds 16 provenance paths per artifact".into());
        }
        if occurrences.len() > 32 {
            return Err("atomic archive import supports at most 32 distinct artifacts".into());
        }
    }
    let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
    let mut all_records = Vec::with_capacity(planned.len());
    let mut unique_records = Vec::with_capacity(occurrences.len());
    let mut ids = HashMap::<String, usize>::new();
    for plan in &planned {
        let record = prepare_import_record(
            ctx,
            &store,
            Path::new(&plan.name),
            &plan.bytes,
            case_id,
            false,
        )?;
        if !ids.contains_key(&record.id) {
            ids.insert(record.id.clone(), unique_records.len());
            unique_records.push(record.clone());
        }
        all_records.push(record);
    }
    let mut event_groups = vec![Vec::new(); unique_records.len()];
    let mut finding_groups = vec![Vec::new(); unique_records.len()];
    for (plan, record) in planned.iter().zip(all_records.iter()) {
        let index = ids[&record.id];
        event_groups[index].push(ImportEvent {
            source: source_tag,
            action: "derived",
            description: &plan.name,
        });
        event_groups[index].push(ImportEvent {
            source: source_tag,
            action: "extract",
            description: &plan.provenance,
        });
        finding_groups[index].push(NewFinding {
            title: plan.title.clone(),
            severity: "info".into(),
            details: format!("{}\nDerived SHA-256: {}", plan.provenance, record.sha256,),
        });
    }
    let items: Vec<ImportBatchItem<'_>> = unique_records
        .iter()
        .enumerate()
        .map(|(index, record)| ImportBatchItem {
            record,
            events: &event_groups[index],
            findings: &finding_groups[index],
        })
        .collect();
    store
        .commit_artifact_batch(&ctx.artifacts_dir, &items)
        .map_err(|e| {
            format!(
                "archive database batch was rolled back: {e}; already-published \
             unindexed evidence bytes may require cleanup"
            )
        })?;
    Ok(all_records)
}

/// The parser never writes archive-controlled paths; imported evidence is
/// content-addressed and every output is linked back to its source artifact.
#[tauri::command]
pub fn file_extract_archive(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    format: String,
    offset: usize,
) -> Result<Vec<ArtifactRecord>, String> {
    extract_archive_from_evidence(&ctx, &case_id, &id, &format, offset)
}

fn extract_archive_from_evidence(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    format: &str,
    offset: usize,
) -> Result<Vec<ArtifactRecord>, String> {
    use cyberdeck_crypto::extraction::{
        extract_tar_limited, extract_zip_limited, MAX_ARCHIVE_INPUT_BYTES, MAX_ARCHIVE_OUTPUT_BYTES,
    };
    validate_case_id(case_id)?;
    if format != "zip" && format != "tar" {
        return Err("only ZIP and TAR native extraction is supported".into());
    }
    let record = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(id)?
        .filter(|item| item.case_id == case_id)
        .ok_or("source evidence does not belong to the selected case")?;
    if record.size > MAX_ARCHIVE_INPUT_BYTES as u64 {
        return Err("archive source is larger than the 16 MiB limit".into());
    }
    cyberdeck_storage::verify_artifact_file(&record, &ctx.artifacts_dir)?;
    let source = std::fs::read(&record.stored_path)
        .map_err(|e| format!("cannot read archive evidence: {e}"))?;
    if source.len() as u64 != record.size || digest_of("sha256", &source)? != record.sha256 {
        return Err("source archive evidence integrity failure".into());
    }
    // Parse and verify *every* entry before saving any result into the case.
    let entries = match format {
        "zip" => extract_zip_limited(&source, offset, MAX_ARCHIVE_OUTPUT_BYTES)?,
        _ => extract_tar_limited(&source, offset, MAX_ARCHIVE_OUTPUT_BYTES)?,
    };
    let mut planned = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let base = entry.path.rsplit('/').next().unwrap_or("file");
        let safe = sanitize_file_name(base);
        let short = safe.chars().take(48).collect::<String>();
        let name = format!("{format}-{index:03}-{short}");
        let provenance = format!(
            "Source: {} (sha256 {}) | Format: {} | Archive offset: 0x{:x} | \
             Entry: {} | Header offset: 0x{:x}",
            record.id, record.sha256, format, offset, entry.path, entry.source_offset,
        );
        if provenance.len() > 512 {
            return Err(format!(
                "archive entry {index} provenance exceeds 512 bytes"
            ));
        }
        planned.push(PlannedArchiveEntry {
            name,
            bytes: entry.bytes,
            provenance,
            title: format!("Extracted {format} entry {index}"),
        });
    }
    import_archive_batch(ctx, case_id, "forensics.archive", planned)
}

/// Explicit nested extraction, staged for integration-owner Tauri registration.
/// Parsing of every layer completes before importing any leaf. Each leaf
/// commits independently; a later import failure reports previously imported
/// entries rather than implying archive-wide transaction semantics.
#[tauri::command]
pub fn file_extract_nested_archive(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    format: String,
    offset: usize,
    max_depth: usize,
) -> Result<Vec<ArtifactRecord>, String> {
    extract_nested_from_evidence(&ctx, &case_id, &id, &format, offset, max_depth)
}

fn extract_nested_from_evidence(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    format: &str,
    offset: usize,
    max_depth: usize,
) -> Result<Vec<ArtifactRecord>, String> {
    use cyberdeck_crypto::extraction::{
        nested::extract_nested_limited, MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_INPUT_BYTES,
        MAX_ARCHIVE_OUTPUT_BYTES,
    };
    validate_case_id(case_id)?;
    let format = match format {
        "zip" => "zip",
        "tar" => "tar",
        "gzip" => "gzip",
        _ => return Err("unsupported nested archive format".into()),
    };
    let source_record = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(id)?
        .filter(|item| item.case_id == case_id)
        .ok_or("nested source evidence is not in the selected case")?;
    if source_record.size > MAX_ARCHIVE_INPUT_BYTES as u64 {
        return Err("nested source archive exceeds 16 MiB".into());
    }
    cyberdeck_storage::verify_artifact_file(&source_record, &ctx.artifacts_dir)?;
    let source = std::fs::read(&source_record.stored_path)
        .map_err(|e| format!("cannot read nested archive source: {e}"))?;
    if source.len() as u64 != source_record.size
        || digest_of("sha256", &source)? != source_record.sha256
    {
        return Err("nested archive source integrity failure".into());
    }
    let leafs = extract_nested_limited(
        &source,
        format,
        offset,
        max_depth,
        MAX_ARCHIVE_ENTRIES,
        MAX_ARCHIVE_OUTPUT_BYTES,
    )?;
    let mut planned = Vec::with_capacity(leafs.len());
    for (index, leaf) in leafs.into_iter().enumerate() {
        let last = leaf.lineage.last().ok_or("nested lineage is empty")?;
        let name_part = sanitize_file_name(last.item_name.rsplit('/').next().unwrap_or("member"));
        let short = name_part.chars().take(48).collect::<String>();
        let name = format!("nested-{index:03}-{short}");
        let chain = leaf
            .lineage
            .iter()
            .enumerate()
            .map(|(depth, hop)| {
                format!(
                    "{depth}:{}:{}@0x{:x}",
                    hop.format, hop.item_name, hop.source_offset,
                )
            })
            .collect::<Vec<_>>()
            .join(" -> ");
        let provenance = format!(
            "Parent: {} sha256={} | source offset 0x{:x} | {}",
            source_record.id, source_record.sha256, offset, chain,
        );
        if provenance.len() > 512 {
            return Err(format!("nested entry {index} provenance exceeds 512 bytes"));
        }
        planned.push(PlannedArchiveEntry {
            name,
            bytes: leaf.bytes,
            provenance,
            title: format!("Nested archive entry {index}"),
        });
    }
    import_archive_batch(ctx, case_id, "forensics.nested", planned)
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
    fn archive_batch_indexes_distinct_and_deduplicated_files_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let planned = vec![
            PlannedArchiveEntry {
                name: "one.bin".into(),
                bytes: b"same".to_vec(),
                provenance: "Parent: source-A > one.bin".into(),
                title: "Member one".into(),
            },
            PlannedArchiveEntry {
                name: "two.bin".into(),
                bytes: b"other".to_vec(),
                provenance: "Parent: source-A > two.bin".into(),
                title: "Member two".into(),
            },
            PlannedArchiveEntry {
                name: "duplicate.bin".into(),
                bytes: b"same".to_vec(),
                provenance: "Parent: source-A > duplicate.bin".into(),
                title: "Duplicate".into(),
            },
        ];
        let records =
            import_archive_batch(&ctx, DEFAULT_CASE, "forensics.archive", planned).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].id, records[2].id);
        let store = ctx.store.lock().unwrap();
        assert_eq!(store.list_artifacts(DEFAULT_CASE).unwrap().len(), 2);
        assert_eq!(store.list_events(DEFAULT_CASE).unwrap().len(), 6);
        assert_eq!(store.list_findings(DEFAULT_CASE).unwrap().len(), 3);
    }

    #[test]
    fn oversized_atomic_archive_batch_rejects_before_file_publication() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let planned = (0..33)
            .map(|i| PlannedArchiveEntry {
                name: format!("member-{i}.bin"),
                bytes: format!("distinct contents {i}").into_bytes(),
                provenance: format!("source member #{i}"),
                title: format!("Member {i}"),
            })
            .collect();
        assert!(
            import_archive_batch(&ctx, DEFAULT_CASE, "forensics.archive", planned)
                .unwrap_err()
                .contains("32 distinct")
        );
        let store = ctx.store.lock().unwrap();
        assert!(store.list_artifacts(DEFAULT_CASE).unwrap().is_empty());
        assert!(store.list_events(DEFAULT_CASE).unwrap().is_empty());
        assert!(!dir.path().join(DEFAULT_CASE).exists());
    }

    #[test]
    fn nested_extraction_preserves_source_chain_and_rejects_tampering() {
        use flate2::{write::GzEncoder, Compression};
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let case = ctx
            .store
            .lock()
            .unwrap()
            .create_case("Nested evidence", "")
            .unwrap();
        let mut header = [0u8; 512];
        header[..8].copy_from_slice(b"note.txt");
        header[124..136].copy_from_slice(b"00000000005\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|&b| b as usize).sum::<usize>();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut tar = header.to_vec();
        tar.extend_from_slice(b"hello");
        tar.resize(512 + 512 + 1024, 0);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&tar).unwrap();
        let compressed = gzip.finish().unwrap();
        let source =
            import_bytes(&ctx, Path::new("outer.gz"), &compressed, &case.id, true).unwrap();
        assert!(
            extract_nested_from_evidence(&ctx, DEFAULT_CASE, &source.id, "gzip", 0, 2).is_err()
        );
        let imported =
            extract_nested_from_evidence(&ctx, &case.id, &source.id, "gzip", 0, 2).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(std::fs::read(&imported[0].stored_path).unwrap(), b"hello");
        let events = ctx.store.lock().unwrap().list_events(&case.id).unwrap();
        assert!(events.iter().any(|e| e.source == "forensics.nested"
            && e.action == "extract"
            && e.source_description.contains(&source.id)
            && e.source_description.contains("note.txt")));
        std::fs::write(&source.stored_path, b"modified").unwrap();
        assert!(extract_nested_from_evidence(&ctx, &case.id, &source.id, "gzip", 0, 2).is_err());
    }

    #[test]
    fn repeat_evidence_import_keeps_identity_path_and_checks_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let first = import_bytes(
            &ctx,
            Path::new("initial.bin"),
            b"immutable sample",
            DEFAULT_CASE,
            true,
        )
        .unwrap();
        let next = import_bytes(
            &ctx,
            Path::new("renamed-copy.bin"),
            b"immutable sample",
            DEFAULT_CASE,
            true,
        )
        .unwrap();
        assert_eq!(first.id, next.id);
        assert_eq!(first.stored_path, next.stored_path);
        assert_eq!(first.name, next.name);
        assert_eq!(
            ctx.store
                .lock()
                .unwrap()
                .list_artifacts(DEFAULT_CASE)
                .unwrap()
                .len(),
            1
        );
        let copy_path = std::path::PathBuf::from(&first.stored_path);
        assert_eq!(std::fs::read(&copy_path).unwrap(), b"immutable sample");
        std::fs::write(&copy_path, b"modified evidence").unwrap();
        assert!(import_bytes(
            &ctx,
            Path::new("renamed-copy.bin"),
            b"immutable sample",
            DEFAULT_CASE,
            true
        )
        .is_err());
        assert_eq!(std::fs::read(&copy_path).unwrap(), b"modified evidence");
    }

    #[test]
    fn invalid_second_import_event_does_not_index_artifact_or_findings() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let invalid_description = "X".repeat(513);
        let events = [
            ImportEvent {
                source: "forensics.archive",
                action: "derived",
                description: "entry.bin",
            },
            ImportEvent {
                source: "forensics.archive",
                action: "extract",
                description: &invalid_description,
            },
        ];
        let findings = [NewFinding {
            title: "Archive finding".into(),
            severity: "info".into(),
            details: "should roll back".into(),
        }];
        assert!(import_bytes_with_events(
            &ctx,
            Path::new("entry.bin"),
            b"artifact",
            DEFAULT_CASE,
            false,
            &events,
            &findings,
        )
        .is_err());
        let store = ctx.store.lock().unwrap();
        assert!(store.list_artifacts(DEFAULT_CASE).unwrap().is_empty());
        assert!(store.list_events(DEFAULT_CASE).unwrap().is_empty());
        assert!(store.list_findings(DEFAULT_CASE).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_case_directory_cannot_redirect_evidence_publication() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        std::os::unix::fs::symlink(outside.path(), dir.path().join(DEFAULT_CASE)).unwrap();
        assert!(import_bytes(
            &ctx,
            Path::new("sample.bin"),
            b"blocked",
            DEFAULT_CASE,
            true
        )
        .unwrap_err()
        .contains("symlink"));
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[test]
    fn preexisting_symlink_is_not_accepted_as_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let bytes = b"symlink fixture";
        let digest = digest_of("sha256", bytes).unwrap();
        let case_dir = dir.path().join(DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let target = dir.path().join("outside.bin");
        std::fs::write(&target, bytes).unwrap();
        let stored_path = case_dir.join(format!("{digest}.evidence"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &stored_path).unwrap();
            assert!(
                import_bytes(&ctx, Path::new("sample.bin"), bytes, DEFAULT_CASE, true).is_err()
            );
            assert_eq!(std::fs::read(&target).unwrap(), bytes);
        }
        #[cfg(not(unix))]
        {
            assert!(!stored_path.exists());
        }
    }

    #[test]
    fn binary_inspection_requires_case_membership_and_intact_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(temp.path());
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4..7].copy_from_slice(&[2, 1, 1]);
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        let record = import_bytes(&ctx, Path::new("sample.elf"), &elf, DEFAULT_CASE, true).unwrap();
        assert_eq!(
            binary_inspect(&ctx, DEFAULT_CASE, &record.id)
                .unwrap()
                .architecture,
            "ARM64"
        );
        let another = ctx
            .store
            .lock()
            .unwrap()
            .create_case("Other case", "")
            .unwrap();
        assert!(binary_inspect(&ctx, &another.id, &record.id).is_err());
        std::fs::write(&record.stored_path, b"modified").unwrap();
        assert!(binary_inspect(&ctx, DEFAULT_CASE, &record.id)
            .unwrap_err()
            .contains("integrity"));
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
    fn embedded_gzip_is_bounded_and_linked_to_case() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let case = ctx
            .store
            .lock()
            .unwrap()
            .create_case("Gzip lab", "")
            .unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"decompressed sample").unwrap();
        let gz = encoder.finish().unwrap();
        let mut fixture = b"prefix".to_vec();
        fixture.extend(gz);
        let src = import_bytes(&ctx, Path::new("firmware.bin"), &fixture, &case.id, true).unwrap();
        assert!(extract_gzip_from_evidence(&ctx, DEFAULT_CASE, &src.id, 6).is_err());
        assert!(extract_gzip_from_evidence(&ctx, &case.id, &src.id, 0).is_err());
        let out = extract_gzip_from_evidence(&ctx, &case.id, &src.id, 6).unwrap();
        assert_eq!(
            std::fs::read(&out.stored_path).unwrap(),
            b"decompressed sample"
        );
        assert!(ctx
            .store
            .lock()
            .unwrap()
            .list_events(&case.id)
            .unwrap()
            .iter()
            .any(|event| event.source_description.contains(&src.id)));
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

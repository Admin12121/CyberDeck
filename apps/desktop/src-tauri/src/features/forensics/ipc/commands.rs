//! Stable Tauri command entry points. They delegate to application services.
//! This module owns IPC protocol shape, not filesystem/storage algorithms.
use super::{
    binary_inspect, carve_preview, digest_disk_file, entropy_scan, extract_archive_from_evidence,
    extract_gzip_from_evidence, extract_nested_from_evidence, hex_view, import_derived,
    import_file_from_path, list_artifacts, metadata_scan, signature_scan, strings, strings_scan,
    EvidenceCtx, FileCarveResponse, FileDigestsWire, ForensicEntropyResponse,
    ForensicMetadataResponse, ForensicStringsResponse, HexResponse, SignatureScanResponse,
    StringHit,
};
use cyberdeck_storage::{ArtifactRecord, DEFAULT_CASE};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

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
    import_file_from_path(&ctx, &path, case_id.as_deref().unwrap_or(DEFAULT_CASE))
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
    import_derived(&ctx, case_id, name, data_b64, source_description)
}

#[tauri::command]
pub fn file_list(
    ctx: State<'_, EvidenceCtx>,
    case: Option<String>,
) -> Result<Vec<ArtifactRecord>, String> {
    list_artifacts(&ctx, case.as_deref().unwrap_or(DEFAULT_CASE))
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

#[tauri::command]
pub fn file_signature_scan(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
) -> Result<SignatureScanResponse, String> {
    signature_scan(&ctx, &case_id, &id)
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
    digest_disk_file(&path)
}

#[tauri::command]
pub fn file_strings_scan(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    offset: u64,
    len: usize,
    min_len: i32,
    max_hits: i32,
) -> Result<ForensicStringsResponse, String> {
    strings_scan(&ctx, &case_id, &id, offset, len, min_len, max_hits)
}

#[tauri::command]
pub fn file_entropy_regions(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    offset: u64,
    len: usize,
    block_size: usize,
) -> Result<ForensicEntropyResponse, String> {
    entropy_scan(&ctx, &case_id, &id, offset, len, block_size)
}

#[tauri::command]
pub fn file_metadata_scan(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
) -> Result<ForensicMetadataResponse, String> {
    metadata_scan(&ctx, &case_id, &id)
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

/// Explicit nested extraction, staged for integration-owner Tauri registration.
/// Every bounded archive layer is parsed before publishing derived evidence.
/// Derived artifacts and provenance are committed as one database batch;
/// filesystem publication remains outside the SQL transaction.
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

/// Read-only native PNG carving preview of a verified, case-scoped artifact.
/// Does not extract bytes or insert artifacts/findings into the case store.
#[tauri::command]
pub fn file_carve_preview(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    id: String,
    offset: u64,
    len: usize,
) -> Result<FileCarveResponse, String> {
    carve_preview(&ctx, &case_id, &id, offset, len)
}

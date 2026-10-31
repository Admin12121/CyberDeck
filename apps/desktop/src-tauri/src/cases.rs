//! Unified case and finding IPC. Storage and validation stay in the Rust core.

use crate::evidence::EvidenceCtx;
use cyberdeck_storage::{
    CaseEvent, CaseIntegritySummary, CaseRecord, CaseReport, FindingRecord, NewFinding,
    ProvenanceVerification,
};
use tauri::State;

#[tauri::command]
pub fn case_list(ctx: State<'_, EvidenceCtx>) -> Result<Vec<CaseRecord>, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .list_cases()
}

#[tauri::command]
pub fn case_create(
    ctx: State<'_, EvidenceCtx>,
    title: String,
    description: String,
) -> Result<CaseRecord, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .create_case(&title, &description)
}

#[tauri::command]
pub fn case_findings_list(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<Vec<FindingRecord>, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .list_findings(&case_id)
}

#[tauri::command]
pub fn case_findings_add(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    source: String,
    artifact_id: Option<String>,
    findings: Vec<NewFinding>,
) -> Result<usize, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .add_findings(&case_id, &source, artifact_id.as_deref(), &findings)
}

#[tauri::command]
pub fn case_events_list(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<Vec<CaseEvent>, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .list_events(&case_id)
}

#[tauri::command]
pub fn case_report(ctx: State<'_, EvidenceCtx>, case_id: String) -> Result<CaseReport, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .export_case_report(&case_id)
}

#[tauri::command]
pub fn case_provenance_verify(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<ProvenanceVerification, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .verify_case_provenance(&case_id)
}

#[tauri::command]
pub fn case_artifact_verify(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    artifact_id: String,
) -> Result<bool, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .verify_artifact(&case_id, &artifact_id, &ctx.artifacts_dir)?;
    Ok(true)
}

#[tauri::command]
pub fn case_integrity_verify(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<CaseIntegritySummary, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .verify_case_integrity(&case_id, &ctx.artifacts_dir)
}

#[tauri::command]
pub fn case_provenance_verify_against(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    trusted_head_sha256: String,
) -> Result<ProvenanceVerification, String> {
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?
        .verify_case_provenance_against(&case_id, &trusted_head_sha256)
}

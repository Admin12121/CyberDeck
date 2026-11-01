//! Tauri command transport for the case feature. Names and JSON payloads are stable.
use super::{application, domain::*, infrastructure};
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use tauri::State;

#[tauri::command]
pub fn case_list(ctx: State<'_, EvidenceCtx>) -> Result<Vec<CaseRecord>, String> {
    infrastructure::with_store(&ctx, |store| application::list(store))
}

#[tauri::command]
pub fn case_create(
    ctx: State<'_, EvidenceCtx>,
    title: String,
    description: String,
) -> Result<CaseRecord, String> {
    infrastructure::with_store(&ctx, |store| {
        application::create(store, &title, &description)
    })
}

#[tauri::command]
pub fn case_findings_list(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<Vec<FindingRecord>, String> {
    infrastructure::with_store(&ctx, |store| application::findings(store, &case_id))
}

#[tauri::command]
pub fn case_findings_add(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    source: String,
    artifact_id: Option<String>,
    findings: Vec<NewFinding>,
) -> Result<usize, String> {
    infrastructure::with_store(&ctx, |store| {
        application::add_findings(store, &case_id, &source, artifact_id.as_deref(), &findings)
    })
}

#[tauri::command]
pub fn case_events_list(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<Vec<CaseEvent>, String> {
    infrastructure::with_store(&ctx, |store| application::events(store, &case_id))
}

#[tauri::command]
pub fn case_report(ctx: State<'_, EvidenceCtx>, case_id: String) -> Result<CaseReport, String> {
    infrastructure::with_store(&ctx, |store| application::report(store, &case_id))
}

#[tauri::command]
pub fn case_provenance_verify(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<ProvenanceVerification, String> {
    infrastructure::with_store(&ctx, |store| application::provenance(store, &case_id))
}

#[tauri::command]
pub fn case_artifact_verify(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    artifact_id: String,
) -> Result<bool, String> {
    let artifact = infrastructure::with_store(&ctx, |store| {
        application::prepare_artifact(store, &case_id, &artifact_id)
    })?;
    application::verify_prepared_artifact(
        &infrastructure::EVIDENCE_VERIFIER,
        &artifact,
        &ctx.artifacts_dir,
    )
}

#[tauri::command]
pub fn case_integrity_verify(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
) -> Result<CaseIntegritySummary, String> {
    let plan =
        infrastructure::with_store(&ctx, |store| application::prepare_case(store, &case_id))?;
    application::verify_prepared_case(&infrastructure::EVIDENCE_VERIFIER, plan, &ctx.artifacts_dir)
}

#[tauri::command]
pub fn case_provenance_verify_against(
    ctx: State<'_, EvidenceCtx>,
    case_id: String,
    trusted_head_sha256: String,
) -> Result<ProvenanceVerification, String> {
    infrastructure::with_store(&ctx, |store| {
        application::verify_against_trusted_head(store, &case_id, &trusted_head_sha256)
    })
}

#[path = "scoped.rs"]
pub mod scoped;
#[path = "temporary.rs"]
pub mod temporary;

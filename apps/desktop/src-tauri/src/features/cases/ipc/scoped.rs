//! Additive, backend-selected read-only case investigation endpoints.
//! No client-supplied case ID, filesystem root, recovery record or write action.

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::CaseSessionCtx;
use cyberdeck_storage::{CaseLineageReport, CaseSearchPage};
use tauri::State;

#[tauri::command]
pub fn case_search_scoped_v1(
    query: String,
    limit: usize,
    offset: usize,
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<CaseSearchPage, String> {
    let snapshot = session.selected()?;
    let case_id = snapshot.case_id.as_deref().ok_or("no selected case")?;
    let found = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .search_case(case_id, &query, limit, offset)?;
    session.ensure(&snapshot)?;
    Ok(found)
}

#[tauri::command]
pub fn case_lineage_scoped_v1(
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<CaseLineageReport, String> {
    let snapshot = session.selected()?;
    let case_id = snapshot.case_id.as_deref().ok_or("no selected case")?;
    let lineage = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .list_artifact_lineage(case_id)?;
    session.ensure(&snapshot)?;
    Ok(lineage)
}

/// Backend-selected investigation restoration snapshot; portable summaries
/// only, never host-local evidence paths or volatile confidential job buffers.
#[tauri::command]
pub fn case_resume_scoped_v1(
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<cyberdeck_storage::CaseReport, String> {
    let scope = session.selected()?;
    let case_id = scope.case_id.as_deref().ok_or("no selected case")?;
    if case_id == cyberdeck_storage::DEFAULT_CASE {
        return Err("temporary workspace has no saved investigation to resume".into());
    }
    let report = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .export_case_report(case_id)?;
    session.ensure(&scope)?;
    Ok(report)
}

/// Explicit read-only, case-scoped reconciliation. Never adopts, deletes,
/// repairs or exposes unknown filesystem paths to the frontend.
#[tauri::command]
pub fn case_evidence_review_scoped_v1(
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<cyberdeck_storage::CaseReconciliation, String> {
    let scope = session.selected()?;
    let case_id = scope.case_id.as_deref().ok_or("no selected case")?;
    if case_id == cyberdeck_storage::DEFAULT_CASE {
        return Err("temporary workspace has no persisted evidence".into());
    }
    let report = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .reconcile_case_artifacts(case_id, &ctx.artifacts_dir)?;
    session.ensure(&scope)?;
    Ok(report)
}

/// The typed reference has no stored path, no raw bytes and no authority on
/// its own. Consumers must revalidate the backend selected session revision
/// and indexed case ownership again at the actual read/transfer boundary.
#[derive(serde::Serialize)]
pub struct ScopedArtifactReferenceV1 {
    pub case_id: String,
    pub artifact_id: String,
    pub sha256: String,
    pub size: u64,
    pub kind: &'static str,
    pub session_revision: u64,
}

#[tauri::command]
pub fn case_artifact_reference_scoped_v1(
    artifact_id: String,
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<ScopedArtifactReferenceV1, String> {
    let scope = session.selected()?;
    let case_id = scope.case_id.as_deref().ok_or("no selected case")?;
    if case_id == cyberdeck_storage::DEFAULT_CASE {
        return Err("temporary workspace has no transferable indexed evidence".into());
    }
    let record = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(&artifact_id)?
        .filter(|record| record.case_id == case_id)
        .ok_or("artifact is not in the selected case")?;
    session.ensure(&scope)?;
    let kind = if record.signature.as_deref() == Some("Original Ethernet PCAP") {
        "packet-capture"
    } else {
        "file"
    };
    Ok(ScopedArtifactReferenceV1 {
        case_id: case_id.to_string(),
        artifact_id: record.id,
        sha256: record.sha256,
        size: record.size,
        kind,
        session_revision: scope.revision,
    })
}

/// Full-file case integrity is performed after the SQLite lock is released.
/// A case switch invalidates the result before it is exposed to the caller.
#[tauri::command]
pub fn case_integrity_scoped_v1(
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<cyberdeck_storage::CaseIntegritySummary, String> {
    let scope = session.selected()?;
    let case_id = scope.case_id.as_deref().ok_or("no selected case")?;
    if case_id == cyberdeck_storage::DEFAULT_CASE {
        return Err("temporary workspace has no persisted case integrity".into());
    }
    let plan = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .case_integrity_plan(case_id)?;
    let result = plan.verify(&ctx.artifacts_dir)?;
    session.ensure(&scope)?;
    Ok(result)
}

/// Explicit, operator-confirmed copy between two existing saved cases.
/// The source case and its revision are backend-selected. The destination
/// identifier is untrusted and must be checked against the actual case index.
#[derive(serde::Serialize)]
pub struct CaseTransferReceiptV1 {
    pub source_case_id: String,
    pub target_case_id: String,
    pub artifact_id: String,
    pub sha256: String,
    pub size: u64,
}

#[tauri::command]
pub async fn case_copy_artifact_to_existing_v1(
    artifact_id: String,
    target_case_id: String,
    app: tauri::AppHandle,
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<CaseTransferReceiptV1, String> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
    let scope = session.selected()?;
    let source = scope.case_id.as_deref().ok_or("no selected saved case")?;
    cyberdeck_storage::validate_case_id(&target_case_id)?;
    if source == cyberdeck_storage::DEFAULT_CASE
        || target_case_id == source
        || target_case_id == cyberdeck_storage::DEFAULT_CASE
    {
        return Err("cross-case transfer requires distinct saved investigations".into());
    }
    {
        let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
        if !store.case_exists(&target_case_id)?
            || !store
                .get_artifact(&artifact_id)?
                .is_some_and(|artifact| artifact.case_id == source)
        {
            return Err("source artifact or destination case unavailable".into());
        }
    }
    let prompt = format!(
        "Copy verified artifact '{}' from the selected investigation into case '{}'? The original remains unchanged and the copy receives new provenance.",
        artifact_id, target_case_id
    );
    let allowed = tokio::task::spawn_blocking(move || {
        app.dialog()
            .message(prompt)
            .title("Confirm cross-case evidence copy")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "case transfer confirmation unavailable")?;
    if !allowed {
        return Err("case transfer declined by operator".into());
    }
    session.ensure(&scope)?;
    let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
    let copied = session.with_current_publication(&scope, || {
        store.copy_verified_case_artifact(&ctx.artifacts_dir, source, &artifact_id, &target_case_id)
    })?;
    Ok(CaseTransferReceiptV1 {
        source_case_id: source.to_string(),
        target_case_id,
        artifact_id: copied.id,
        sha256: copied.sha256,
        size: copied.size,
    })
}

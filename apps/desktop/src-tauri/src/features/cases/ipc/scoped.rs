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

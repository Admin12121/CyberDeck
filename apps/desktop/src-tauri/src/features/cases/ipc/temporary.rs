//! Explicit-only volatile Quick Tools digest staging and atomic case promotion.
//! No client case-id or raw output classification grants durable storage.
use crate::features::cases::infrastructure::temp_work::{TempOutputView, TempOverview};
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::CaseSessionCtx;
use cyberdeck_storage::{CaseRecord, PromotionDestination};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

fn temporary_revision(session: &CaseSessionCtx) -> Result<u64,String> {
    let scope = session.snapshot()?;
    if scope.case_id.is_some() {
        return Err("temporary outputs require no selected saved case".into());
    }
    Ok(scope.revision)
}

#[tauri::command]
pub fn case_temp_stage_sha256_v1(
    input: String,
    session: State<'_, CaseSessionCtx>,
) -> Result<TempOutputView,String> {
    let scope = session.snapshot()?;
    let rev = temporary_revision(&session)?;
    session.with_current_publication(&scope, || {
        session.temp_work.lock().map_err(|_| "temporary workspace unavailable".to_string())?
            .stage_digest(rev, &input)
    })
}

#[tauri::command]
pub fn case_temp_overview_v1(
    session: State<'_, CaseSessionCtx>,
) -> Result<TempOverview,String> {
    let scope = session.snapshot()?;
    let rev = temporary_revision(&session)?;
    session.with_current_publication(&scope, || {
        Ok(session.temp_work.lock().map_err(|_| "temporary workspace unavailable".to_string())?
            .overview(rev))
    })
}

#[tauri::command]
pub fn case_temp_discard_v1(
    session: State<'_, CaseSessionCtx>,
) -> Result<TempOverview,String> {
    let scope = session.snapshot()?;
    let rev = temporary_revision(&session)?;
    session.with_current_publication(&scope, || {
        let mut temp = session.temp_work.lock()
            .map_err(|_| "temporary workspace unavailable".to_string())?;
        temp.clear();
        Ok(temp.overview(rev))
    })
}

#[derive(Serialize)]
pub struct PromotedArtifactView {
    id: String,
    name: String,
    sha256: String,
    size: u64,
}
#[derive(Serialize)]
pub struct TempPromotionReceipt {
    pub case: CaseRecord,
    pub artifacts: Vec<PromotedArtifactView>,
}

/// Native confirmation is mandatory. Frontend cannot supply source evidence
/// bytes, source case, stage identities, eligibility flags or generation grants.
#[tauri::command]
pub async fn case_temp_promote_v1(
    new_title: Option<String>,
    description: Option<String>,
    existing_case_id: Option<String>,
    app: AppHandle,
    ctx: State<'_,EvidenceCtx>,
    session: State<'_,CaseSessionCtx>,
) -> Result<TempPromotionReceipt,String> {
    let scope = session.snapshot()?;
    let rev = temporary_revision(&session)?;
    // Exactly one destination is allowed. Explicit saved case must exist.
    let new = new_title.as_deref().filter(|value| !value.trim().is_empty());
    let existing = existing_case_id.as_deref().filter(|value| !value.is_empty());
    if new.is_some() == existing.is_some() {
        return Err("choose exactly one new or existing saved case".into());
    }
    if let Some(id) = existing {
        cyberdeck_storage::validate_case_id(id)?;
        if id == cyberdeck_storage::DEFAULT_CASE {
            return Err("Scratchpad is not a saved investigation".into());
        }
        let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
        if !store.case_exists(id)? { return Err("target case not found".into()); }
    }
    let overview = session.temp_work.lock()
        .map_err(|_| "temporary workspace unavailable")?.overview(rev);
    if overview.outputs.is_empty() { return Err("no eligible temporary outputs to save".into()); }
    let count = overview.outputs.len();
    let destination_label = existing.or(new).unwrap_or("");
    let prompt = format!(
        "Save {count} eligible SHA-256 digest output(s) to the investigation '{destination_label}'? Original input and confidential recovery results are not included. This creates permanent case evidence."
    );
    let accepted = tokio::task::spawn_blocking(move || {
        app.dialog().message(prompt).title("Save Temporary Work as Case")
            .buttons(MessageDialogButtons::YesNo).blocking_show()
    }).await.map_err(|_| "native promotion confirmation unavailable")?;
    if !accepted { return Err("case promotion declined by operator".into()); }
    session.ensure(&scope)?;
    // Lock ordering is store -> publication -> temporary. Native selection
    // holds store -> publication; therefore this cannot deadlock on case switch.
    let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
    let result = session.with_current_publication(&scope, || {
        let mut temp = session.temp_work.lock()
            .map_err(|_| "temporary workspace unavailable".to_string())?;
        temp.promote(rev, |artifacts| {
            let destination = match existing {
                Some(id) => PromotionDestination::Existing(id),
                None => PromotionDestination::New {
                    title: new.ok_or("missing new case title")?,
                    description: description.as_deref().unwrap_or(""),
                },
            };
            store.promote_temporary_evidence(&ctx.artifacts_dir, destination, artifacts)
        })
    })?;
    Ok(TempPromotionReceipt {
        case: result.case,
        artifacts: result.artifacts.into_iter().map(|a| PromotedArtifactView {
            id:a.id, name:a.name, sha256:a.sha256, size:a.size
        }).collect(),
    })
}

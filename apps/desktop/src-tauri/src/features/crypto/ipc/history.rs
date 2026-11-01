//! Stable Tauri crack-history commands; storage access lives in infrastructure.
use cyberdeck_storage::CrackEntry;
use tauri::State;

use crate::features::forensics::ipc::evidence::EvidenceCtx;

#[path = "../infrastructure/retention.rs"]
mod retention;
#[path = "../infrastructure/history.rs"]
mod storage;
pub(crate) use retention::persist;

#[tauri::command]
pub fn crack_history_list(ctx: State<'_, EvidenceCtx>) -> Result<Vec<CrackEntry>, String> {
    storage::list(ctx.inner())
}

#[tauri::command]
pub fn crack_history_delete(ctx: State<'_, EvidenceCtx>, id: i64) -> Result<(), String> {
    storage::delete(ctx.inner(), id)
}

#[tauri::command]
pub fn crack_history_clear(ctx: State<'_, EvidenceCtx>) -> Result<(), String> {
    storage::clear(ctx.inner())
}

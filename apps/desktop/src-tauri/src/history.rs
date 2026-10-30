//! Crack history (Master Plan §5.5): recovered pairs persist in the case
//! store until the user deletes them. Recording happens automatically in the
//! attack commands; the UI lists, deletes, or clears.

use hacktool_storage::CrackEntry;
use tauri::State;

use crate::evidence::EvidenceCtx;

#[tauri::command]
pub fn crack_history_list(ctx: State<'_, EvidenceCtx>) -> Result<Vec<CrackEntry>, String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.list_crack_entries()
}

#[tauri::command]
pub fn crack_history_delete(ctx: State<'_, EvidenceCtx>, id: i64) -> Result<(), String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.delete_crack_entry(id)
}

#[tauri::command]
pub fn crack_history_clear(ctx: State<'_, EvidenceCtx>) -> Result<(), String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.clear_crack_entries()
}

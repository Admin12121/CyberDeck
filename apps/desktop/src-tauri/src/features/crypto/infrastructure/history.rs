//! Persistence adapter for the pre-existing crack-history storage interface.
//! Legacy secret-retention behavior is unchanged pending Agent 5 migration.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use cyberdeck_storage::CrackEntry;

pub fn list(ctx: &EvidenceCtx) -> Result<Vec<CrackEntry>, String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.list_crack_entries()
}

pub fn delete(ctx: &EvidenceCtx, id: i64) -> Result<(), String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.delete_crack_entry(id)
}

pub fn clear(ctx: &EvidenceCtx) -> Result<(), String> {
    let store = ctx.store.lock().expect("artifact store poisoned");
    store.clear_crack_entries()
}

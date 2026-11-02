//! Wordlist and rule library IPC. The library lives backend-side: the
//! frontend addresses entries by catalog id, never by file system path.
#[path = "../infrastructure/rules_library.rs"]
mod rules_library;
#[path = "../infrastructure/wordlist_library.rs"]
mod wordlist_library;

use super::recovery::{RecoveryCtx, RecoveryWordlistInfo, SelectedWordlist};
use tauri::ipc::Channel;
use tauri::{AppHandle, State};

use crate::features::shared::session::CaseSessionCtx;

fn valid_catalog_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[tauri::command]
pub fn wordlist_library_list_v1(
    app: AppHandle,
) -> Result<Vec<wordlist_library::WordlistLibraryEntry>, String> {
    wordlist_library::list(&app)
}

#[derive(serde::Serialize, Clone)]
pub struct WordlistFetchProgress {
    pub id: String,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
}

#[tauri::command]
pub async fn wordlist_library_fetch_v1(
    app: AppHandle,
    id: String,
    on_progress: Channel<WordlistFetchProgress>,
) -> Result<String, String> {
    if !valid_catalog_id(&id) {
        return Err("invalid wordlist id".into());
    }
    wordlist_library::fetch(&app, &id, move |progress| {
        let _ = on_progress.send(WordlistFetchProgress {
            id: progress.id,
            downloaded_bytes: progress.downloaded_bytes,
            total_bytes: progress.total_bytes,
        });
    })
    .await
}

#[tauri::command]
pub fn wordlist_library_delete_v1(app: AppHandle, id: String) -> Result<bool, String> {
    if !valid_catalog_id(&id) {
        return Err("invalid wordlist id".into());
    }
    wordlist_library::remove(&app, &id)
}

/// Authorize a library wordlist into the recovery session. Mirrors the native
/// picker flow: resolve backend-side, re-inspect, bind to the verified case.
#[tauri::command]
pub async fn wordlist_library_use_v1(
    app: AppHandle,
    id: String,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<RecoveryWordlistInfo, String> {
    if !valid_catalog_id(&id) {
        return Err("invalid wordlist id".into());
    }
    let before = session.selected()?;
    state.with_active(&session, |_, _| Ok(()))?;
    let resolved =
        tokio::task::spawn_blocking(move || wordlist_library::resolve(&app, &id))
            .await
            .map_err(|_| "library lookup failed".to_string())??;
    session.ensure(&before)?;
    let (name, size_bytes) = wordlist_library::inspect_resolved(&resolved)?;
    let info = RecoveryWordlistInfo {
        name: name.clone(),
        size_bytes,
    };
    state.with_active(&session, |registry, _| {
        registry.selected_wordlist = Some(SelectedWordlist {
            path: resolved,
            name,
            size_bytes,
        });
        Ok(())
    })?;
    Ok(info)
}

#[tauri::command]
pub fn rules_library_list_v1(app: AppHandle) -> Result<Vec<rules_library::RuleSetEntry>, String> {
    rules_library::list(&app)
}

#[tauri::command]
pub fn rules_library_inspect_v1(
    app: AppHandle,
    id: String,
) -> Result<rules_library::LoadedRuleSetSummary, String> {
    rules_library::load_summary(&app, &id)
}

// Used by the recovery IPC sibling to load a rules set for a live job.
pub(crate) use rules_library::load as load_rule_set;

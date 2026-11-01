//! Backend-selected case identity and revision for new security-sensitive IPC.
//! A caller-supplied case ID is never sufficient authorization for scoped reads.

use cyberdeck_storage::{validate_case_id, ActiveCaseHistoryPolicy, ArtifactStore};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::State;

use crate::features::forensics::ipc::evidence::EvidenceCtx;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaseSessionWire {
    pub case_id: Option<String>,
    pub revision: u64,
}

#[derive(Default)]
struct Selection {
    case_id: Option<String>,
    revision: u64,
}

/// One process-local case authority. Initially unselected. A future frontend
/// case-switch must await case_session_select before using scoped native APIs.
pub struct CaseSessionCtx {
    selection: Mutex<Selection>,
    pub history_policy: Arc<Mutex<ActiveCaseHistoryPolicy>>,
}
impl Default for CaseSessionCtx {
    fn default() -> Self {
        Self {
            selection: Mutex::new(Selection::default()),
            history_policy: Arc::new(Mutex::new(ActiveCaseHistoryPolicy::default())),
        }
    }
}
impl CaseSessionCtx {
    pub fn select(&self, store: &ArtifactStore, case_id: &str) -> Result<CaseSessionWire, String> {
        validate_case_id(case_id)?;
        if !store.case_exists(case_id)? {
            return Err("selected case does not exist".into());
        }
        let mut state = self
            .selection
            .lock()
            .map_err(|_| "case session unavailable")?;
        let next = state
            .revision
            .checked_add(1)
            .ok_or("case session exhausted")?;
        // Revokes Web consent, even on selection of the same case.
        self.history_policy
            .lock()
            .map_err(|_| "case history policy unavailable")?
            .select_case(store, case_id)?;
        state.case_id = Some(case_id.to_owned());
        state.revision = next;
        Ok(CaseSessionWire {
            case_id: state.case_id.clone(),
            revision: next,
        })
    }

    pub fn clear(&self) -> Result<CaseSessionWire, String> {
        let mut state = self
            .selection
            .lock()
            .map_err(|_| "case session unavailable")?;
        let next = state
            .revision
            .checked_add(1)
            .ok_or("case session exhausted")?;
        self.history_policy
            .lock()
            .map_err(|_| "case history policy unavailable")?
            .close_case();
        state.case_id = None;
        state.revision = next;
        Ok(CaseSessionWire {
            case_id: None,
            revision: next,
        })
    }

    pub fn snapshot(&self) -> Result<CaseSessionWire, String> {
        let state = self
            .selection
            .lock()
            .map_err(|_| "case session unavailable")?;
        Ok(CaseSessionWire {
            case_id: state.case_id.clone(),
            revision: state.revision,
        })
    }

    pub fn selected(&self) -> Result<CaseSessionWire, String> {
        let scope = self.snapshot()?;
        if scope.case_id.is_none() {
            return Err("select a case in the native desktop session first".into());
        }
        Ok(scope)
    }

    pub fn ensure(&self, prior: &CaseSessionWire) -> Result<(), String> {
        if &self.snapshot()? != prior {
            return Err("selected case changed while native work was running".into());
        }
        Ok(())
    }
}

#[tauri::command]
pub fn case_session_select_v1(
    case_id: String,
    ctx: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
    recovery: State<'_, crate::features::crypto::ipc::recovery::RecoveryCtx>,
    capture: State<'_, crate::features::network::ipc::capture::CaptureCtx>,
) -> Result<CaseSessionWire, String> {
    let result = {
        let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
        session.select(&store, &case_id)?
    };
    // No backend/policy mutex is held while Web clears volatile captures.
    crate::features::web::ipc::web::revoke_backend_case_capture();
    recovery.on_case_selected(&session)?;
    capture.on_case_changed();
    Ok(result)
}

#[tauri::command]
pub fn case_session_clear_v1(
    session: State<'_, CaseSessionCtx>,
    recovery: State<'_, crate::features::crypto::ipc::recovery::RecoveryCtx>,
    capture: State<'_, crate::features::network::ipc::capture::CaptureCtx>,
) -> Result<CaseSessionWire, String> {
    let result = session.clear()?;
    recovery.on_case_cleared();
    capture.on_case_changed();
    crate::features::web::ipc::web::revoke_backend_case_capture();
    Ok(result)
}

#[tauri::command]
pub fn case_session_status_v1(
    session: State<'_, CaseSessionCtx>,
) -> Result<CaseSessionWire, String> {
    session.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_selection_validates_store_and_invalidates_reselected_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let session = CaseSessionCtx::default();
        assert!(session.selected().is_err());
        assert!(session.select(&store, "missing").is_err());
        assert_eq!(session.snapshot().unwrap().revision, 0);
        let first = session.select(&store, "scratchpad").unwrap();
        assert_eq!(first.case_id.as_deref(), Some("scratchpad"));
        session.ensure(&first).unwrap();
        let next = session.select(&store, "scratchpad").unwrap();
        assert!(next.revision > first.revision);
        assert!(session.ensure(&first).is_err());
        assert_eq!(session.clear().unwrap().case_id, None);
        assert!(session.selected().is_err());
    }
}

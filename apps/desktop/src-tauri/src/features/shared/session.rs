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
    /// Serializes case revocation against durable publication/consent minting.
    publication: Mutex<()>,
    selection: Mutex<Selection>,
    pub history_policy: Arc<Mutex<ActiveCaseHistoryPolicy>>,
    /// Only eligible nonsecret Quick Tools outputs live here, never SQLite.
    pub(crate) temp_work: Arc<Mutex<crate::features::cases::infrastructure::temp_work::TempWork>>,
}
impl Default for CaseSessionCtx {
    fn default() -> Self {
        Self {
            publication: Mutex::new(()),
            selection: Mutex::new(Selection::default()),
            history_policy: Arc::new(Mutex::new(ActiveCaseHistoryPolicy::default())),
            temp_work: Arc::new(Mutex::new(Default::default())),
        }
    }
}
impl CaseSessionCtx {
    /// Evicts expired temporary outputs even when a user is idle. Weak ref
    /// ensures cleanup exits when desktop state is dropped; no retained bytes
    /// survive a case switch.
    pub fn start_temporary_expiry_cleanup(&self) {
        let weak = Arc::downgrade(&self.temp_work);
        tauri::async_runtime::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let Some(work) = weak.upgrade() else { break };
                if let Ok(mut state) = work.lock() {
                    state.evict_expired();
                };
            }
        });
    }

    pub fn select(&self, store: &ArtifactStore, case_id: &str) -> Result<CaseSessionWire, String> {
        let _gate = self
            .publication
            .lock()
            .map_err(|_| "case publication gate unavailable")?;
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
        self.temp_work
            .lock()
            .map_err(|_| "temporary workspace unavailable")?
            .clear();
        Ok(CaseSessionWire {
            case_id: state.case_id.clone(),
            revision: next,
        })
    }

    pub fn clear(&self) -> Result<CaseSessionWire, String> {
        let _gate = self
            .publication
            .lock()
            .map_err(|_| "case publication gate unavailable")?;
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
        self.temp_work
            .lock()
            .map_err(|_| "temporary workspace unavailable")?
            .clear();
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

    /// Synchronize short backend-only publication and consent operations with
    /// every case switch/reselection. The callback must NOT await, call select/
    /// clear, or hold a network operation. Use this at the real commit boundary.
    /// Lock order: publication -> selection -> policy, never the reverse.
    pub fn with_current_publication<T>(
        &self,
        expected: &CaseSessionWire,
        publish: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let _gate = self
            .publication
            .lock()
            .map_err(|_| "case publication gate unavailable")?;
        self.ensure(expected)?;
        let result = publish()?;
        self.ensure(expected)?;
        Ok(result)
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
    fn publication_guard_serializes_reselection_and_rejects_stale_generation() {
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let session = Arc::new(CaseSessionCtx::default());
        let old = session.select(&store, "scratchpad").unwrap();
        let (entered, observed) = mpsc::channel::<()>();
        let (release, continue_gate) = mpsc::channel::<()>();
        let held = session.clone();
        let prior = old.clone();
        let publisher = thread::spawn(move || {
            held.with_current_publication(&prior, || {
                entered.send(()).unwrap();
                continue_gate.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(42)
            })
        });
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        let (attempted, attempting) = mpsc::channel::<()>();
        let (selected, completed) = mpsc::channel::<()>();
        let changing = session.clone();
        let switch = thread::spawn(move || {
            attempted.send(()).unwrap();
            let later = changing.select(&store, "scratchpad").unwrap();
            selected.send(()).unwrap();
            later
        });
        attempting.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(completed.recv_timeout(Duration::from_millis(25)).is_err());
        release.send(()).unwrap();
        assert_eq!(publisher.join().unwrap().unwrap(), 42);
        let newer = switch.join().unwrap();
        assert_ne!(newer.revision, old.revision);
        assert!(session.with_current_publication(&old, || Ok(())).is_err());
    }

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
    #[test]
    fn temporary_staging_is_discarded_on_case_switch_and_clear() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let selected = store.create_case("Saved", "").unwrap();
        let session = CaseSessionCtx::default();
        session
            .temp_work
            .lock()
            .unwrap()
            .stage_digest(0, "volatile-only")
            .unwrap();
        assert_eq!(
            session.temp_work.lock().unwrap().overview(0).outputs.len(),
            1
        );
        let saved = session.select(&store, &selected.id).unwrap();
        assert!(session
            .temp_work
            .lock()
            .unwrap()
            .overview(saved.revision)
            .outputs
            .is_empty());
        let cleared = session.clear().unwrap();
        assert!(session
            .temp_work
            .lock()
            .unwrap()
            .overview(cleared.revision)
            .outputs
            .is_empty());
        assert!(store.list_artifacts("scratchpad").unwrap().is_empty());
    }
}

//! Thread-safe in-memory scan session state; no UI or filesystem operations.
use super::{ScanEntry, ScanHistoryItem, ScanObservation};
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex as StdMutex};

/// Compatible with the original Tauri managed state layout.
pub struct ScanCtx {
    pub results: Arc<StdMutex<Vec<ScanEntry>>>,
    pub observations: Arc<StdMutex<Vec<ScanObservation>>>,
    pub running: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    pub history: Arc<StdMutex<Vec<ScanHistoryItem>>>,
    pub next_id: Arc<AtomicU64>,
    pub last_save_error: Arc<StdMutex<Option<String>>>,
    pub saved_findings: Arc<AtomicU64>,
    pub active_scope: Arc<StdMutex<Option<CaseSessionWire>>>,
}

impl Default for ScanCtx {
    fn default() -> Self {
        Self {
            results: Arc::new(StdMutex::new(Vec::new())),
            observations: Arc::new(StdMutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            history: Arc::new(StdMutex::new(Vec::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            last_save_error: Arc::new(StdMutex::new(None)),
            saved_findings: Arc::new(AtomicU64::new(0)),
            active_scope: Arc::new(StdMutex::new(None)),
        }
    }
}

impl ScanCtx {
    pub fn visible_for(&self, selected: &CaseSessionCtx) -> bool {
        let Ok(current) = selected.selected() else {
            return false;
        };
        self.active_scope
            .lock()
            .map(|scope| scope.as_ref() == Some(&current))
            .unwrap_or(false)
    }

    /// Case changes invalidate the worker and all retained scan observations.
    /// The existing worker checks stop; persistence independently checks the
    /// authoritative selected case under the publication gate at commit.
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut scope) = self.active_scope.lock() {
            *scope = None;
        }
        if let Ok(mut rows) = self.results.lock() {
            rows.clear();
        }
        if let Ok(mut history) = self.history.lock() {
            history.clear();
        }
        self.saved_findings.store(0, Ordering::Release);
        if let Ok(mut error) = self.last_save_error.lock() {
            *error = None;
        }
    }
}

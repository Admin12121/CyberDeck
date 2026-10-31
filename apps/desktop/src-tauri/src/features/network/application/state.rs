//! Thread-safe in-memory scan session state; no UI or filesystem operations.
use super::{ScanEntry, ScanHistoryItem};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex as StdMutex};

/// Compatible with the original Tauri managed state layout.
pub struct ScanCtx {
    pub results: Arc<StdMutex<Vec<ScanEntry>>>,
    pub running: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    pub history: Arc<StdMutex<Vec<ScanHistoryItem>>>,
    pub next_id: Arc<AtomicU64>,
    pub last_save_error: Arc<StdMutex<Option<String>>>,
    pub saved_findings: Arc<AtomicU64>,
}

impl Default for ScanCtx {
    fn default() -> Self {
        Self {
            results: Arc::new(StdMutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            history: Arc::new(StdMutex::new(Vec::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            last_save_error: Arc::new(StdMutex::new(None)),
            saved_findings: Arc::new(AtomicU64::new(0)),
        }
    }
}

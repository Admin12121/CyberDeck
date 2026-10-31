//! Stable serializable desktop scanner response payloads.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NetscanStatusWire {
    pub running: bool,
    pub results: usize,
    pub saved_findings: usize,
    pub save_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanSummaryWire {
    pub id: u64,
    pub targets: String,
    pub ports: String,
    pub hosts_scanned: usize,
    pub open_ports: usize,
    pub duration_ms: u64,
    pub at_ms: u64,
}

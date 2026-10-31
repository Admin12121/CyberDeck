//! Public scanner domain records; serialized field names stay stable.
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ScanEntry {
    pub host: String,
    pub port: u16,
    pub state: String,
    pub service: String,
    pub banner: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanProgress {
    pub tried: u64,
    pub total: u64,
    pub percent: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanHistoryItem {
    pub id: u64,
    pub targets: String,
    pub ports: String,
    pub hosts_scanned: usize,
    pub open_ports: usize,
    pub duration_ms: u64,
    pub at_ms: u64,
}

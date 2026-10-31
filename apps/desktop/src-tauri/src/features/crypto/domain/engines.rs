//! External engine IPC payloads. No Tauri/process dependencies.
use serde::Serialize;
use crate::attack::AttackMatch;

#[derive(Debug, Clone, Serialize)]
pub struct EngineStatus {
    pub id: String,
    pub label: String,
    pub license: String,
    pub available: bool,
    pub version: String,
    pub source: String,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct EngineAttackResult {
    pub engine: String,
    pub engine_version: String,
    pub algo: String,
    pub mode: String,
    pub tried_note: String,
    pub matches: Vec<AttackMatch>,
    pub duration_ms: u64,
    pub raw_tail: String,
}

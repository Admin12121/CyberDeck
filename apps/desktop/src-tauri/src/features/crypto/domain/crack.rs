//! Stable native recovery IPC payloads. No Tauri dependency.
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CrackMatch {
    pub line_no: u64,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct CrackResultWire {
    pub algo: String,
    pub target_hash: String,
    pub wordlist: String,
    pub tried: u64,
    pub matches: Vec<CrackMatch>,
    pub duration_ms: u64,
    pub threads: usize,
    pub engine: String,
    pub engine_version: String,
}

#[derive(Debug, Serialize)]
pub struct WordlistInfoWire {
    pub name: String,
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrackProgress {
    pub tried: u64,
    pub total: u64,
    pub percent: u32,
}

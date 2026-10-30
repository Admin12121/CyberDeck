//! hacktool-core — shared domain types for the HackTool workbench.
//!
//! The canonical capability/artifact/job contracts (Master Plan §8) live here so
//! the Tauri shell and future engine crates share one vocabulary. Presentation
//! code never depends on this crate directly; it flows through IPC types.

use serde::{Deserialize, Serialize};

/// Artifact categories in the canonical data model (Master Plan §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Binary,
    Text,
    Capture,
    NetworkHost,
    NetworkService,
    HttpRequest,
    HttpResponse,
    ScanFinding,
    CryptoResult,
    Recipe,
    ToolExecution,
    EvidenceNote,
    Case,
}

/// Provenance attached to every produced artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub capability_id: String,
    pub engine_id: Option<String>,
    pub engine_version: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

/// Canonical artifact envelope (content addressed by hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub kind: ArtifactKind,
    pub content_hash: String,
    pub created_at: String,
    pub provenance: Provenance,
    pub warnings: Vec<String>,
}

/// Lifecycle states shared by every job class (Master Plan §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

/// Kinds of work the job manager accepts. Grows per arc as engines land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Demo,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_kind_serializes_snake_case() {
        let json = serde_json::to_string(&JobKind::Demo).unwrap();
        assert_eq!(json, r#""demo""#);
    }

    #[test]
    fn artifact_kind_round_trips() {
        let json = serde_json::to_string(&ArtifactKind::ScanFinding).unwrap();
        assert_eq!(json, r#""scan_finding""#);
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ArtifactKind::ScanFinding);
    }
}

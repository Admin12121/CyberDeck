//! SQLite artifact index (§8.4); artifact bytes live in the case directory.

use rusqlite::{params, Connection};

mod application;
mod domain;
mod infrastructure;
pub use application::lineage::{ArtifactLineageHop, CaseLineageReport};
pub use application::search::{CaseSearchPage, SearchFinding};
pub use domain::*;
#[path = "infrastructure/batch.rs"]
mod batch;
pub use batch::ImportBatchItem;
#[path = "application/case_integrity.rs"]
mod case_integrity;
#[path = "application/ingest.rs"]
mod ingest;
pub use application::active_case_policy::{
    ActiveCaseHistoryPolicy, HistoryCaptureGrant, HistoryRetentionLimits, MAX_CAPTURE_BODY_BYTES,
    MAX_CAPTURE_DURATION, MAX_CAPTURE_EVENTS, MAX_CAPTURE_TOTAL_BYTES,
};
pub use case_integrity::{CaseIntegrityPlan, CaseIntegritySummary};
pub use ingest::ImportEvent;
#[path = "infrastructure/integrity.rs"]
mod integrity;
pub use infrastructure::orphan_recovery::{
    CaseReconciliation, ExplicitRecovery, ReconciliationEntry, ReconciliationState,
};
pub use infrastructure::verified_handle::{open_verified_case_artifact, VerifiedArtifactHandle};
pub use integrity::{verify_artifact_file, GENESIS_HASH};

fn timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct ArtifactStore {
    conn: Connection,
}

#[cfg(test)]
mod tests;

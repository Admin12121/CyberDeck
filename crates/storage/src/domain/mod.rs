//! Case and evidence records and platform-independent validation.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_CASE: &str = "scratchpad";

/// One imported evidence file. The record is the index entry; `stored_path`
/// points into the case artifact directory where the original bytes live
/// immutably.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub stored_path: String,
    pub original_path: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub crc32: String,
    pub signature: Option<String>,
    pub entropy: f64,
    pub imported_at: String,
}

/// A project/case owns evidence and analysis findings; scratchpad remains the
/// default for existing imports made before case management existed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub id: String,
    pub title: String,
    pub description: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: i64,
    pub case_id: String,
    pub source: String,
    pub title: String,
    pub severity: String,
    pub details: String,
    pub artifact_id: Option<String>,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFinding {
    pub title: String,
    pub severity: String,
    pub details: String,
}

/// Structured provenance is deliberately append-only at the application API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEvent {
    pub id: i64,
    pub case_id: String,
    pub source: String,
    pub action: String,
    pub artifact_id: Option<String>,
    pub source_description: String,
    pub created_ms: i64,
}

/// A portable case report includes no host-local paths or copied evidence bytes.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportArtifact {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub signature: Option<String>,
    pub imported_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseReport {
    pub schema_version: u8,
    pub manifest_sha256: String,
    pub provenance: ProvenanceVerification,
    pub generated_ms: i64,
    pub case: CaseRecord,
    pub artifacts: Vec<ReportArtifact>,
    pub findings: Vec<FindingRecord>,
    pub events: Vec<CaseEvent>,
    pub truncated: bool,
}

/// Unkeyed integrity chain; retain its head externally to detect wholesale DB rewrites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceVerification {
    pub verified_events: usize,
    pub head_sha256: String,
}

/// Recompute a portable report's digest over all fields except the digest
/// itself. Preserve the returned digest independently.
pub fn case_report_manifest_digest(report: &CaseReport) -> Result<String, String> {
    let payload = serde_json::to_vec(&(
        report.schema_version,
        report.generated_ms,
        &report.case,
        &report.artifacts,
        &report.findings,
        &report.events,
        &report.provenance,
        report.truncated,
    ))
    .map_err(|e| format!("cannot serialize case manifest: {e}"))?;
    let mut digest = Sha256::new();
    digest.update(b"cyberdeck.case-report.v2\0");
    digest.update(payload);
    Ok(format!("{:x}", digest.finalize()))
}

pub fn verify_case_report_manifest(report: &CaseReport) -> Result<(), String> {
    let calculated = case_report_manifest_digest(report)?;
    if calculated != report.manifest_sha256 {
        return Err("case report manifest SHA-256 mismatch".into());
    }
    Ok(())
}

pub fn validate_case_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 100
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid case identifier".to_string());
    }
    Ok(())
}

/// One successfully recovered pair, kept until the user deletes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackEntry {
    pub id: i64,
    pub algo: String,
    pub hash: String,
    pub password: String,
    pub engine: String,
    pub wordlist: Option<String>,
    pub recovered_at: String,
}

/// Run-state lifecycle of a durable recovery checkpoint row.
pub const RECOVERY_CHECKPOINT_STATES: &[&str] =
    &["running", "suspended", "completed", "cancelled"];
/// Which engine shape produced the run; decides how a re-issue can honestly
/// skip already-submitted candidates.
pub const RECOVERY_CHECKPOINT_KINDS: &[&str] = &["wordlist_cpu", "wordlist_gpu", "autopilot"];
/// Resume capability: sequential ordinals, GPU 1M chunk boundaries, autopilot
/// stage boundaries, or restart-from-zero only.
pub const RECOVERY_CHECKPOINT_RESUME_KINDS: &[&str] =
    &["sequential", "chunk_boundary", "stage", "restart"];
/// Backend selection kind; device parameters are hardware-local and never persisted.
pub const RECOVERY_CHECKPOINT_BACKENDS: &[&str] = &["cpu", "hashcat_managed"];

/// Durable case-scoped resume checkpoint for one recovery run. Rows carry
/// counters and library wordlist references only — never candidates,
/// recovered secrets, or arbitrary operator file paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCheckpointRecord {
    pub id: i64,
    pub case_id: String,
    pub run_kind: String,
    pub resume_kind: String,
    pub algorithm: String,
    pub backend: String,
    /// Operator-owned target hash; case data, not a secret at rest.
    pub target_hash: String,
    pub total_budget: u64,
    pub max_matches: u64,
    /// Candidates submitted by finished work units (CPU ordinals, GPU chunk
    /// boundaries, or completed autopilot stages).
    pub submitted: u64,
    /// Autopilot only: completed stage count and the in-flight stage's
    /// submitted candidates.
    pub stage_index: u64,
    pub stage_submitted: u64,
    /// Library wordlist catalog id; absent for runs that cannot be re-issued.
    pub wordlist_id: Option<String>,
    /// Library rule preset id for rules stages.
    pub rules_set_id: Option<String>,
    /// Embedded transform preset id ("plain", "uppercase", "append_one").
    pub preset: String,
    pub state: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

/// Validated insert payload for a new checkpoint row (state always starts running).
#[derive(Debug, Clone)]
pub struct NewRecoveryCheckpoint {
    pub case_id: String,
    pub run_kind: String,
    pub resume_kind: String,
    pub algorithm: String,
    pub backend: String,
    pub target_hash: String,
    pub total_budget: u64,
    pub max_matches: u64,
    pub stage_index: u64,
    pub stage_submitted: u64,
    pub wordlist_id: Option<String>,
    pub rules_set_id: Option<String>,
    pub preset: String,
}

impl NewRecoveryCheckpoint {
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_case_id(&self.case_id)?;
        if !RECOVERY_CHECKPOINT_KINDS.contains(&self.run_kind.as_str())
            || !RECOVERY_CHECKPOINT_RESUME_KINDS.contains(&self.resume_kind.as_str())
            || !RECOVERY_CHECKPOINT_BACKENDS.contains(&self.backend.as_str())
        {
            return Err("invalid recovery checkpoint kind".into());
        }
        if self.algorithm.is_empty()
            || self.algorithm.len() > 64
            || self.target_hash.is_empty()
            || self.target_hash.len() > 8192
            || self.preset.is_empty()
            || self.preset.len() > 32
        {
            return Err("invalid recovery checkpoint metadata".into());
        }
        if let Some(id) = &self.wordlist_id {
            if id.is_empty() || id.len() > 64 {
                return Err("invalid recovery checkpoint wordlist id".into());
            }
        }
        if let Some(id) = &self.rules_set_id {
            if id.is_empty() || id.len() > 64 {
                return Err("invalid recovery checkpoint rules id".into());
            }
        }
        if self.max_matches == 0 || self.max_matches > 100 {
            return Err("invalid recovery checkpoint match cap".into());
        }
        Ok(())
    }
}

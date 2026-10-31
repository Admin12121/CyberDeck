//! Case use cases and an explicit repository port (no Tauri or SQLite).
use super::domain::*;
use std::path::Path;

/// Storage operations required by case use cases. Production uses the SQLite
/// adapter; test or future stores can implement this port independently.
pub trait CaseRepository {
    fn list_cases(&self) -> Result<Vec<CaseRecord>, String>;
    fn create_case(&self, title: &str, description: &str) -> Result<CaseRecord, String>;
    fn list_findings(&self, case_id: &str) -> Result<Vec<FindingRecord>, String>;
    fn add_findings(
        &self,
        case_id: &str,
        source: &str,
        artifact_id: Option<&str>,
        findings: &[NewFinding],
    ) -> Result<usize, String>;
    fn list_events(&self, case_id: &str) -> Result<Vec<CaseEvent>, String>;
    fn export_case_report(&self, case_id: &str) -> Result<CaseReport, String>;
    fn verify_case_provenance(&self, case_id: &str) -> Result<ProvenanceVerification, String>;
    fn artifact_for_case(&self, case_id: &str, artifact_id: &str)
        -> Result<ArtifactRecord, String>;
    fn prepare_case_integrity(&self, case_id: &str) -> Result<CaseIntegrityPlan, String>;
    fn verify_case_provenance_against(
        &self,
        case_id: &str,
        trusted_head: &str,
    ) -> Result<ProvenanceVerification, String>;
}

pub fn list(repo: &impl CaseRepository) -> Result<Vec<CaseRecord>, String> {
    repo.list_cases()
}

pub fn create(
    repo: &impl CaseRepository,
    title: &str,
    description: &str,
) -> Result<CaseRecord, String> {
    repo.create_case(title, description)
}

pub fn findings(repo: &impl CaseRepository, case_id: &str) -> Result<Vec<FindingRecord>, String> {
    repo.list_findings(case_id)
}

pub fn add_findings(
    repo: &impl CaseRepository,
    case_id: &str,
    source: &str,
    artifact_id: Option<&str>,
    findings: &[NewFinding],
) -> Result<usize, String> {
    repo.add_findings(case_id, source, artifact_id, findings)
}

pub fn events(repo: &impl CaseRepository, case_id: &str) -> Result<Vec<CaseEvent>, String> {
    repo.list_events(case_id)
}

pub fn report(repo: &impl CaseRepository, case_id: &str) -> Result<CaseReport, String> {
    repo.export_case_report(case_id)
}

pub fn provenance(
    repo: &impl CaseRepository,
    case_id: &str,
) -> Result<ProvenanceVerification, String> {
    repo.verify_case_provenance(case_id)
}

/// Snapshot the index under lock; the caller performs expensive hash work
/// outside the repository/SQLite mutex.
pub fn prepare_case(
    repo: &impl CaseRepository,
    case_id: &str,
) -> Result<CaseIntegrityPlan, String> {
    repo.prepare_case_integrity(case_id)
}

/// File-system verification port. Application orchestrates; infrastructure
/// owns the actual file open, streaming hash and containment checks.
pub trait EvidenceVerifier {
    fn verify_artifact(&self, artifact: &ArtifactRecord, root: &Path) -> Result<(), String>;
    fn verify_case(
        &self,
        plan: CaseIntegrityPlan,
        root: &Path,
    ) -> Result<CaseIntegritySummary, String>;
}

pub fn verify_prepared_case(
    verifier: &impl EvidenceVerifier,
    plan: CaseIntegrityPlan,
    root: &Path,
) -> Result<CaseIntegritySummary, String> {
    verifier.verify_case(plan, root)
}

pub fn prepare_artifact(
    repo: &impl CaseRepository,
    case_id: &str,
    artifact_id: &str,
) -> Result<ArtifactRecord, String> {
    repo.artifact_for_case(case_id, artifact_id)
}

pub fn verify_prepared_artifact(
    verifier: &impl EvidenceVerifier,
    artifact: &ArtifactRecord,
    root: &Path,
) -> Result<bool, String> {
    verifier.verify_artifact(artifact, root)?;
    Ok(true)
}

pub fn verify_against_trusted_head(
    repo: &impl CaseRepository,
    case_id: &str,
    trusted_head: &str,
) -> Result<ProvenanceVerification, String> {
    repo.verify_case_provenance_against(case_id, trusted_head)
}

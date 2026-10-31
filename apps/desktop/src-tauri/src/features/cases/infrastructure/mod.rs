//! Adapter around the existing case store shared by the evidence workspace.
use crate::evidence::EvidenceCtx;
use cyberdeck_storage::ArtifactStore;

pub mod storage_paths;

/// Hold the existing case-store lock for exactly one synchronous operation.
pub fn with_store<T>(
    ctx: &EvidenceCtx,
    operation: impl FnOnce(&ArtifactStore) -> Result<T, String>,
) -> Result<T, String> {
    let store = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable".to_string())?;
    operation(&store)
}

use super::application::CaseRepository;
use super::domain::*;

impl CaseRepository for ArtifactStore {
    fn list_cases(&self) -> Result<Vec<CaseRecord>, String> {
        ArtifactStore::list_cases(self)
    }

    fn create_case(&self, title: &str, description: &str) -> Result<CaseRecord, String> {
        ArtifactStore::create_case(self, title, description)
    }

    fn list_findings(&self, case_id: &str) -> Result<Vec<FindingRecord>, String> {
        ArtifactStore::list_findings(self, case_id)
    }

    fn add_findings(
        &self,
        case_id: &str,
        source: &str,
        artifact_id: Option<&str>,
        findings: &[NewFinding],
    ) -> Result<usize, String> {
        ArtifactStore::add_findings(self, case_id, source, artifact_id, findings)
    }

    fn list_events(&self, case_id: &str) -> Result<Vec<CaseEvent>, String> {
        ArtifactStore::list_events(self, case_id)
    }

    fn export_case_report(&self, case_id: &str) -> Result<CaseReport, String> {
        ArtifactStore::export_case_report(self, case_id)
    }

    fn verify_case_provenance(&self, case_id: &str) -> Result<ProvenanceVerification, String> {
        ArtifactStore::verify_case_provenance(self, case_id)
    }

    fn artifact_for_case(
        &self,
        case_id: &str,
        artifact_id: &str,
    ) -> Result<ArtifactRecord, String> {
        cyberdeck_storage::validate_case_id(case_id)?;
        ArtifactStore::get_artifact(self, artifact_id)?
            .filter(|record| record.case_id == case_id)
            .ok_or_else(|| "artifact not found in selected case".to_string())
    }

    fn prepare_case_integrity(&self, case_id: &str) -> Result<CaseIntegrityPlan, String> {
        ArtifactStore::case_integrity_plan(self, case_id)
    }

    fn verify_case_provenance_against(
        &self,
        case_id: &str,
        trusted_head: &str,
    ) -> Result<ProvenanceVerification, String> {
        ArtifactStore::verify_case_provenance_against(self, case_id, trusted_head)
    }
}

use super::application::EvidenceVerifier;
use std::path::Path;

/// Platform-neutral facade for existing verified filesystem operations.
pub struct FilesystemEvidenceVerifier;

pub const EVIDENCE_VERIFIER: FilesystemEvidenceVerifier = FilesystemEvidenceVerifier;

impl EvidenceVerifier for FilesystemEvidenceVerifier {
    fn verify_artifact(&self, artifact: &ArtifactRecord, root: &Path) -> Result<(), String> {
        cyberdeck_storage::verify_artifact_file(artifact, root)
    }

    fn verify_case(
        &self,
        plan: CaseIntegrityPlan,
        root: &Path,
    ) -> Result<CaseIntegritySummary, String> {
        plan.verify(root)
    }
}

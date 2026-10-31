//! Indexed case integrity planning and trusted provenance checks.
use crate::{ArtifactStore, CaseIntegrityPlan, CaseIntegritySummary, ProvenanceVerification};
use rusqlite::params;
use std::path::Path;

impl ArtifactStore {
    /// Collect metadata and validate provenance while holding the SQLite lock.
    /// Callers may release the lock before streaming evidence files.
    pub fn case_integrity_plan(&self, case_id: &str) -> Result<CaseIntegrityPlan, String> {
        let provenance = self.verify_case_provenance(case_id)?;
        let mut statement = self
            .conn
            .prepare(
                "SELECT id,case_id,name,stored_path,original_path,size,sha256,
                    md5,sha1,crc32,signature,entropy,imported_at
             FROM artifacts WHERE case_id=?1 ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map(params![case_id], crate::infrastructure::artifact_from_row)
            .map_err(|e| e.to_string())?;
        let artifacts = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        Ok(CaseIntegrityPlan {
            case_id: case_id.to_owned(),
            provenance,
            artifacts,
        })
    }

    /// Preserve the existing Rust API for non-desktop callers.
    pub fn verify_case_integrity(
        &self,
        case_id: &str,
        artifacts_root: &Path,
    ) -> Result<CaseIntegritySummary, String> {
        self.case_integrity_plan(case_id)?.verify(artifacts_root)
    }

    /// Verify the chain against a separately retained trusted head.
    /// Without an external anchor, whole-history rewriting remains undetectable.
    pub fn verify_case_provenance_against(
        &self,
        case_id: &str,
        expected_head: &str,
    ) -> Result<ProvenanceVerification, String> {
        if expected_head.len() != 64 || !expected_head.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid trusted provenance head".into());
        }
        let proof = self.verify_case_provenance(case_id)?;
        if !proof.head_sha256.eq_ignore_ascii_case(expected_head) {
            return Err("trusted provenance head mismatch".into());
        }
        Ok(proof)
    }
}

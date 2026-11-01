//! Evidence integrity case use cases.
#[cfg(not(unix))]
use crate::integrity;
use crate::{validate_case_id, ArtifactStore};

impl ArtifactStore {
    /// Check the selected case, path containment, length and actual SHA-256.
    pub fn verify_artifact(
        &self,
        case_id: &str,
        artifact_id: &str,
        artifacts_root: &std::path::Path,
    ) -> Result<(), String> {
        validate_case_id(case_id)?;
        let record = self
            .get_artifact(artifact_id)?
            .filter(|r| r.case_id == case_id)
            .ok_or_else(|| "artifact not found in selected case".to_string())?;
        #[cfg(unix)]
        return crate::open_verified_case_artifact(&record, artifacts_root).map(|_| ());
        #[cfg(not(unix))]
        integrity::verify_artifact_file(&record, artifacts_root)
    }
}

//! Whole-case verification without retaining evidence bytes in memory.
use crate::{integrity, ArtifactRecord, ProvenanceVerification};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseIntegritySummary {
    pub case_id: String,
    pub verified_artifacts: u64,
    pub verified_bytes: u64,
    pub provenance: ProvenanceVerification,
}

/// Database-derived metadata and provenance for one integrity verification.
/// This object owns no database handle; verification can run after releasing
/// the shared case-store mutex.
#[derive(Debug)]
pub struct CaseIntegrityPlan {
    pub(crate) case_id: String,
    pub(crate) provenance: ProvenanceVerification,
    pub(crate) artifacts: Vec<ArtifactRecord>,
}

impl CaseIntegrityPlan {
    /// Hash all indexed bytes using a detached, immutable metadata snapshot.
    pub fn verify(self, artifacts_root: &Path) -> Result<CaseIntegritySummary, String> {
        let mut verified_bytes = 0_u64;
        let mut verified_artifacts = 0_u64;
        for record in &self.artifacts {
            integrity::verify_artifact_file(record, artifacts_root)
                .map_err(|e| format!("artifact {} integrity failure: {e}", record.id))?;
            verified_bytes = verified_bytes
                .checked_add(record.size)
                .ok_or_else(|| "case evidence size overflow".to_string())?;
            verified_artifacts += 1;
        }
        Ok(CaseIntegritySummary {
            case_id: self.case_id,
            verified_artifacts,
            verified_bytes,
            provenance: self.provenance,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactRecord, ArtifactStore, DEFAULT_CASE};
    use sha2::{Digest, Sha256};

    fn sample(path: &Path, id: &str, bytes: &[u8]) -> ArtifactRecord {
        std::fs::write(path, bytes).unwrap();
        ArtifactRecord {
            id: id.into(),
            case_id: DEFAULT_CASE.into(),
            name: id.into(),
            stored_path: path.to_string_lossy().into(),
            original_path: None,
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            md5: "".into(),
            sha1: "".into(),
            crc32: "".into(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        }
    }

    #[test]
    fn whole_case_integrity_verifies_all_bytes_and_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("artifacts");
        let case_dir = root.join(DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let store = ArtifactStore::open(&dir.path().join("cases.db")).unwrap();
        let a = sample(&case_dir.join("a"), "a", b"hello");
        let b = sample(&case_dir.join("b"), "b", b"world!");
        store.upsert_artifact(&a).unwrap();
        store.upsert_artifact(&b).unwrap();
        store
            .record_event(DEFAULT_CASE, "test", "import", Some("a"), "a")
            .unwrap();
        let checked = store.verify_case_integrity(DEFAULT_CASE, &root).unwrap();
        assert_eq!(checked.verified_artifacts, 2);
        assert_eq!(checked.verified_bytes, 11);
        store
            .verify_case_provenance_against(DEFAULT_CASE, &checked.provenance.head_sha256)
            .unwrap();
        assert!(store
            .verify_case_provenance_against(DEFAULT_CASE, crate::GENESIS_HASH)
            .is_err());
        std::fs::write(&a.stored_path, b"tamper").unwrap();
        assert!(store.verify_case_integrity(DEFAULT_CASE, &root).is_err());
    }

    #[test]
    fn detached_plan_verifies_after_database_handle_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("artifacts");
        let case_dir = root.join(DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let file = case_dir.join("first");
        let record = sample(&file, "first", b"hello");
        let store = ArtifactStore::open(&dir.path().join("cases.db")).unwrap();
        store.upsert_artifact(&record).unwrap();
        let plan = store.case_integrity_plan(DEFAULT_CASE).unwrap();
        drop(store);
        let checked = plan.verify(&root).unwrap();
        assert_eq!(checked.case_id, DEFAULT_CASE);
        assert_eq!(checked.verified_artifacts, 1);
        assert_eq!(checked.verified_bytes, 5);

        let store = ArtifactStore::open(&dir.path().join("cases.db")).unwrap();
        let stale = store.case_integrity_plan(DEFAULT_CASE).unwrap();
        drop(store);
        std::fs::write(file, b"altered").unwrap();
        assert!(stale.verify(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_case_directory_even_inside_root() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("artifacts");
        let other = root.join("other-case");
        std::fs::create_dir_all(&other).unwrap();
        symlink(&other, root.join(DEFAULT_CASE)).unwrap();
        let artifact = sample(&other.join("a"), "a", b"hello");
        assert!(integrity::verify_artifact_file(&artifact, &root).is_err());
    }
}

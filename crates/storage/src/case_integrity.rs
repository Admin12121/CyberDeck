//! Whole-case verification without retaining evidence bytes in memory.
use crate::{integrity, ArtifactRecord, ArtifactStore, ProvenanceVerification};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseIntegritySummary {
    pub case_id: String,
    pub verified_artifacts: u64,
    pub verified_bytes: u64,
    pub provenance: ProvenanceVerification,
}

impl ArtifactStore {
    /// Verify the entire selected case. Returns an error on the first invalid
    /// artifact rather than silently reporting partially verified evidence.
    pub fn verify_case_integrity(
        &self,
        case_id: &str,
        artifacts_root: &Path,
    ) -> Result<CaseIntegritySummary, String> {
        let provenance = self.verify_case_provenance(case_id)?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,case_id,name,stored_path,original_path,size,sha256,
                    md5,sha1,crc32,signature,entropy,imported_at
             FROM artifacts WHERE case_id=?1 ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![case_id], |r| {
                Ok(ArtifactRecord {
                    id: r.get(0)?,
                    case_id: r.get(1)?,
                    name: r.get(2)?,
                    stored_path: r.get(3)?,
                    original_path: r.get(4)?,
                    size: r.get::<_, i64>(5)?.max(0) as u64,
                    sha256: r.get(6)?,
                    md5: r.get(7)?,
                    sha1: r.get(8)?,
                    crc32: r.get(9)?,
                    signature: r.get(10)?,
                    entropy: r.get(11)?,
                    imported_at: r.get(12)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut verified_artifacts = 0_u64;
        let mut verified_bytes = 0_u64;
        for row in rows {
            let record = row.map_err(|e| e.to_string())?;
            integrity::verify_artifact_file(&record, artifacts_root)
                .map_err(|e| format!("artifact {} integrity failure: {e}", record.id))?;
            verified_bytes = verified_bytes
                .checked_add(record.size)
                .ok_or_else(|| "case evidence size overflow".to_string())?;
            verified_artifacts += 1;
        }
        Ok(CaseIntegritySummary {
            case_id: case_id.to_string(),
            verified_artifacts,
            verified_bytes,
            provenance,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactRecord, DEFAULT_CASE};
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

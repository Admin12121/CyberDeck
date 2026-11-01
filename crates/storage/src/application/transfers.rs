//! Explicit backend-authorized cross-case evidence copy with immutable bytes.
//! Source/target case identity must be authorized by the Tauri case session
//! publication gate and an explicit operator confirmation.
use crate::{
    application::network_capture::{publish_no_replace, MAX_ORIGINAL_PCAP_BYTES},
    ArtifactRecord, ArtifactStore, ImportBatchItem, ImportEvent, DEFAULT_CASE,
};
use std::fs;
use std::path::Path;

/// Copy an already-indexed, verified existing artifact into a distinct saved
/// case, without browser download/reupload, raw client bytes or hard links
/// between case directories. This does not move/delete the original object.
impl ArtifactStore {
    pub fn copy_verified_case_artifact(
        &self,
        root: &Path,
        source_case: &str,
        artifact_id: &str,
        target_case: &str,
    ) -> Result<ArtifactRecord, String> {
        crate::validate_case_id(source_case)?;
        crate::validate_case_id(target_case)?;
        if source_case == DEFAULT_CASE || target_case == DEFAULT_CASE || source_case == target_case
        {
            return Err("case transfer requires two distinct saved cases".into());
        }
        if !self.case_exists(source_case)? || !self.case_exists(target_case)? {
            return Err("case transfer source or destination does not exist".into());
        }
        let source = self
            .get_artifact(artifact_id)?
            .filter(|record| record.case_id == source_case)
            .ok_or("source artifact is not indexed in the selected case")?;
        if source.size > MAX_ORIGINAL_PCAP_BYTES as u64 {
            return Err("cross-case transfer exceeds 16 MiB verified copy limit".into());
        }
        let mut verified = crate::open_verified_case_artifact(&source, root)?;
        let bytes = verified.read_window(0, source.size as usize, MAX_ORIGINAL_PCAP_BYTES)?;
        fs::create_dir_all(root).map_err(|e| e.to_string())?;
        let root_meta = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
            return Err("unsafe case evidence root".into());
        }
        let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        let target_dir = root.join(target_case);
        fs::create_dir_all(&target_dir).map_err(|e| e.to_string())?;
        let meta = fs::symlink_metadata(&target_dir).map_err(|e| e.to_string())?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || fs::canonicalize(&target_dir)
                .map_err(|e| e.to_string())?
                .parent()
                != Some(root.as_path())
        {
            return Err("unsafe target case directory".into());
        }
        let path = target_dir.join(format!("{}.evidence", source.sha256));
        if source.sha256.len() != 64 || !source.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("source evidence SHA-256 index is invalid".into());
        }
        let id = format!("{target_case}:transfer-{}", &source.sha256[..32]);
        let prior = self.get_artifact(&id)?;
        if let Some(ref old) = prior {
            if old.case_id != target_case
                || old.sha256 != source.sha256
                || old.size != source.size
                || old.stored_path != path.to_string_lossy()
            {
                return Err("target evidence identity conflict".into());
            }
        }
        publish_no_replace(&target_dir, &path, &bytes)?;
        let target = prior.unwrap_or_else(|| ArtifactRecord {
            id,
            case_id: target_case.into(),
            name: source.name.clone(),
            stored_path: path.to_string_lossy().into_owned(),
            original_path: None,
            size: source.size,
            sha256: source.sha256.clone(),
            md5: source.md5.clone(),
            sha1: source.sha1.clone(),
            crc32: source.crc32.clone(),
            signature: source.signature.clone(),
            entropy: source.entropy,
            imported_at: crate::timestamp_ms().to_string(),
        });
        let mut copy = crate::open_verified_case_artifact(&target, &root)?;
        if copy.read_window(0, bytes.len(), MAX_ORIGINAL_PCAP_BYTES)? != bytes {
            return Err("case transfer readback integrity mismatch".into());
        }
        let description = format!(
            "source_case={};source_artifact={};source_sha256={}",
            source_case, source.id, source.sha256
        );
        if description.len() > 512 {
            return Err("case transfer provenance exceeds bounded event limit".into());
        }
        let event = [ImportEvent {
            source: "cases.transfer",
            action: "copy_verified",
            description: &description,
        }];
        self.commit_artifact_batch(
            &root,
            &[ImportBatchItem {
                record: &target,
                events: &event,
                findings: &[],
            }],
        )?;
        drop(crate::open_verified_case_artifact(&target, &root)?);
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn indexed(store: &ArtifactStore, root: &Path, case: &str) -> ArtifactRecord {
        let bytes = b"verified immutable cross-case evidence";
        let dir = root.join(case);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("evidence");
        fs::write(&path, bytes).unwrap();
        let record = ArtifactRecord {
            id: "source-1".into(),
            case_id: case.into(),
            name: "original".into(),
            stored_path: path.to_string_lossy().into_owned(),
            original_path: None,
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            md5: String::new(),
            sha1: String::new(),
            crc32: String::new(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        };
        store.upsert_artifact(&record).unwrap();
        record
    }

    #[cfg(unix)]
    #[test]
    fn copies_original_bytes_to_existing_case_and_survives_restart_with_lineage_event() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("evidence");
        let db = tmp.path().join("db.sqlite");
        let store = ArtifactStore::open(&db).unwrap();
        let from = store.create_case("From", "").unwrap();
        let to = store.create_case("To", "").unwrap();
        let source = indexed(&store, &root, &from.id);
        let dest = store
            .copy_verified_case_artifact(&root, &from.id, &source.id, &to.id)
            .unwrap();
        assert_ne!(dest.stored_path, source.stored_path);
        let mut pinned = crate::open_verified_case_artifact(&dest, &root).unwrap();
        assert_eq!(
            pinned
                .read_window(0, source.size as usize, MAX_ORIGINAL_PCAP_BYTES)
                .unwrap(),
            b"verified immutable cross-case evidence"
        );
        drop(store);
        let restarted = ArtifactStore::open(&db).unwrap();
        let history = restarted.list_events(&to.id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].source, "cases.transfer");
        assert!(history[0].source_description.contains(&source.id));
        assert_eq!(
            restarted
                .verify_case_provenance(&to.id)
                .unwrap()
                .verified_events,
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn denies_missing_cross_case_and_tampered_source_without_partial_index() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("evidence");
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let from = store.create_case("From", "").unwrap();
        let to = store.create_case("To", "").unwrap();
        let source = indexed(&store, &root, &from.id);
        assert!(store
            .copy_verified_case_artifact(&root, &to.id, &source.id, &from.id)
            .is_err());
        assert!(store
            .copy_verified_case_artifact(&root, &from.id, &source.id, DEFAULT_CASE)
            .is_err());
        fs::write(&source.stored_path, b"changed bytes").unwrap();
        assert!(store
            .copy_verified_case_artifact(&root, &from.id, &source.id, &to.id)
            .is_err());
        assert!(store.list_artifacts(&to.id).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn transaction_failure_preserves_uncertain_published_copy_for_review() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("evidence");
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let from = store.create_case("From", "").unwrap();
        let to = store.create_case("To", "").unwrap();
        let source = indexed(&store, &root, &from.id);
        store.conn.execute_batch(
            "CREATE TRIGGER fail_transfer BEFORE INSERT ON case_events WHEN NEW.source='cases.transfer' BEGIN SELECT RAISE(ABORT,'test'); END;"
        ).unwrap();
        assert!(store
            .copy_verified_case_artifact(&root, &from.id, &source.id, &to.id)
            .is_err());
        assert!(store.list_artifacts(&to.id).unwrap().is_empty());
        let scan = store.reconcile_case_artifacts(&to.id, &root).unwrap();
        assert!(scan
            .entries
            .iter()
            .any(|e| e.state == crate::ReconciliationState::UnindexedPublished));
    }
}

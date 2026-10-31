//! Atomic SQLite commit for evidence records, ordered provenance events and findings.
//! Evidence bytes must be safely published inside the case directory before this call.
use crate::{ArtifactRecord, ArtifactStore, NewFinding};
use std::path::Path;

/// One ordered operation linked to a newly imported or existing case artifact.
#[derive(Debug, Clone, Copy)]
pub struct ImportEvent<'a> {
    pub source: &'a str,
    pub action: &'a str,
    pub description: &'a str,
}

impl ArtifactStore {
    /// Backward-compatible single-event evidence import.
    pub fn commit_artifact_import(
        &self,
        record: &ArtifactRecord,
        artifacts_root: &Path,
        source: &str,
        action: &str,
        description: &str,
        findings: &[NewFinding],
    ) -> Result<i64, String> {
        let events = [ImportEvent {
            source,
            action,
            description,
        }];
        let ids =
            self.commit_artifact_import_with_events(record, artifacts_root, &events, findings)?;
        ids.into_iter()
            .next()
            .ok_or_else(|| "import created no event".into())
    }

    /// A single item uses the same fully-verified, case-scoped transaction as
    /// multi-member archive imports. Retains the existing public API.
    pub fn commit_artifact_import_with_events(
        &self,
        record: &ArtifactRecord,
        artifacts_root: &Path,
        events: &[ImportEvent<'_>],
        findings: &[NewFinding],
    ) -> Result<Vec<i64>, String> {
        let items = [crate::ImportBatchItem { record, events, findings }];
        let mut committed = self.commit_artifact_batch(artifacts_root, &items)?;
        Ok(committed.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn fixture(dir: &std::path::Path) -> (ArtifactRecord, std::path::PathBuf) {
        let root = dir.join("artifacts");
        let case_dir = root.join(crate::DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let path = case_dir.join("evidence.txt");
        std::fs::write(&path, b"known evidence bytes").unwrap();
        let record = ArtifactRecord {
            id: "import-1".into(),
            case_id: crate::DEFAULT_CASE.into(),
            name: "evidence.txt".into(),
            stored_path: path.to_string_lossy().into(),
            original_path: None,
            size: 20,
            sha256: format!("{:x}", Sha256::digest(b"known evidence bytes")),
            md5: "".into(),
            sha1: "".into(),
            crc32: "".into(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        };
        (record, root)
    }

    #[test]
    fn atomic_ingest_commits_artifact_event_and_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let (record, root) = fixture(tmp.path());
        let id = store
            .commit_artifact_import(
                &record,
                &root,
                "forensics.import",
                "import",
                "evidence",
                &[NewFinding {
                    title: "Sample".into(),
                    severity: "info".into(),
                    details: "ok".into(),
                }],
            )
            .unwrap();
        assert!(id > 0);
        assert_eq!(store.list_artifacts(crate::DEFAULT_CASE).unwrap().len(), 1);
        assert_eq!(store.list_findings(crate::DEFAULT_CASE).unwrap().len(), 1);
        assert_eq!(
            store
                .verify_case_provenance(crate::DEFAULT_CASE)
                .unwrap()
                .verified_events,
            1
        );
    }

    #[test]
    fn ordered_multi_event_ingest_is_single_atomic_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let (record, root) = fixture(tmp.path());
        let events = [
            ImportEvent {
                source: "forensics.import",
                action: "import",
                description: "copied",
            },
            ImportEvent {
                source: "crypto.recipes",
                action: "transform",
                description: "decoded",
            },
        ];
        let ids = store
            .commit_artifact_import_with_events(
                &record,
                &root,
                &events,
                &[NewFinding {
                    title: "derived".into(),
                    severity: "info".into(),
                    details: "ok".into(),
                }],
            )
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids[0] < ids[1]);
        assert_eq!(
            store
                .verify_case_provenance(crate::DEFAULT_CASE)
                .unwrap()
                .verified_events,
            2
        );
        assert_eq!(store.list_findings(crate::DEFAULT_CASE).unwrap().len(), 1);
    }

    #[test]
    fn later_provenance_failure_rolls_back_all_import_records() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let (record, root) = fixture(tmp.path());
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_transform BEFORE INSERT ON case_events
             WHEN NEW.action='transform' BEGIN SELECT RAISE(ABORT,'injected'); END;",
            )
            .unwrap();
        let events = [
            ImportEvent {
                source: "forensics.import",
                action: "import",
                description: "copied",
            },
            ImportEvent {
                source: "crypto.recipes",
                action: "transform",
                description: "decoded",
            },
        ];
        assert!(store
            .commit_artifact_import_with_events(&record, &root, &events, &[])
            .is_err());
        assert!(store
            .list_artifacts(crate::DEFAULT_CASE)
            .unwrap()
            .is_empty());
        assert!(store.list_events(crate::DEFAULT_CASE).unwrap().is_empty());
        assert_eq!(
            store
                .verify_case_provenance(crate::DEFAULT_CASE)
                .unwrap()
                .verified_events,
            0
        );
    }

    #[test]
    fn failed_finding_insert_rolls_back_artifact_and_event() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let (record, root) = fixture(tmp.path());
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_ingest BEFORE INSERT ON findings
             WHEN NEW.title='reject'
             BEGIN SELECT RAISE(ABORT,'reject test'); END;",
            )
            .unwrap();
        assert!(store
            .commit_artifact_import(
                &record,
                &root,
                "forensics.import",
                "import",
                "evidence",
                &[NewFinding {
                    title: "reject".into(),
                    severity: "info".into(),
                    details: "bad".into()
                }]
            )
            .is_err());
        assert!(store
            .list_artifacts(crate::DEFAULT_CASE)
            .unwrap()
            .is_empty());
        assert!(store.list_events(crate::DEFAULT_CASE).unwrap().is_empty());
        assert_eq!(
            store
                .verify_case_provenance(crate::DEFAULT_CASE)
                .unwrap()
                .verified_events,
            0
        );
    }
}

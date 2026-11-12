//! Read-only filesystem/SQLite reconciliation and explicit verified recovery.
//! Reconciliation never deletes, moves or automatically indexes evidence.
use crate::{ArtifactRecord, ArtifactStore, ImportEvent};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_SCAN_ENTRIES: usize = 4096;
const MAX_UNKNOWN_HASH_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationState {
    IndexedVerified,
    IndexedUnverified,
    IndexedMissing,
    IndexedTampered,
    UnindexedPublished,
    StagedIncomplete,
    UnrecognizedFile,
    UnsafeEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationEntry {
    pub name: String,
    pub artifact_id: Option<String>,
    pub state: ReconciliationState,
    pub size: Option<u64>,
    /// SHA-256 only when safely read within the per-entry size bound.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseReconciliation {
    pub case_id: String,
    pub entries: Vec<ReconciliationEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplicitRecovery {
    Adopted { event_id: i64 },
    AlreadyIndexed,
}

#[cfg(unix)]
fn hash_unknown(case_dir: &Path, leaf: &std::ffi::OsStr, size: u64) -> Option<String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    if size > MAX_UNKNOWN_HASH_BYTES {
        return None;
    }
    let case_path = CString::new(case_dir.as_os_str().as_bytes()).ok()?;
    let leaf = CString::new(leaf.as_bytes()).ok()?;
    let flags = libc::O_CLOEXEC | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY;
    // SAFETY: descriptors are immediately owned by File and closed by RAII.
    let dir_fd = unsafe { libc::open(case_path.as_ptr(), flags) };
    if dir_fd < 0 {
        return None;
    }
    let dir = unsafe { std::fs::File::from_raw_fd(dir_fd) };
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    bounded_unknown_digest(&mut file, size)
}

/// On platforms without a native confined opener, do not read unknown
/// evidence paths during discovery. Indexed files retain their old verifier.
#[cfg(not(unix))]
fn hash_unknown(_case_dir: &Path, _leaf: &std::ffi::OsStr, _size: u64) -> Option<String> {
    None
}

fn bounded_unknown_digest(file: &mut std::fs::File, size: u64) -> Option<String> {
    if size > MAX_UNKNOWN_HASH_BYTES {
        return None;
    }
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() != size {
        return None;
    }
    let mut sha = Sha256::new();
    let mut counted = 0_u64;
    let mut block = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut block).ok()?;
        if n == 0 {
            break;
        }
        counted = counted.checked_add(n as u64)?;
        if counted > size {
            return None;
        }
        sha.update(&block[..n]);
    }
    (counted == size).then(|| format!("{:x}", sha.finalize()))
}

impl ArtifactStore {
    fn indexed_for_reconciliation(
        &self,
        case_id: &str,
    ) -> Result<(Vec<ArtifactRecord>, bool), String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,case_id,name,stored_path,original_path,size,sha256,
                    md5,sha1,crc32,signature,entropy,imported_at
             FROM artifacts WHERE case_id=?1 ORDER BY id LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![case_id, (MAX_SCAN_ENTRIES + 1) as i64],
                crate::infrastructure::artifact_from_row,
            )
            .map_err(|e| e.to_string())?;
        let mut indexed = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let truncated = indexed.len() > MAX_SCAN_ENTRIES;
        indexed.truncate(MAX_SCAN_ENTRIES);
        Ok((indexed, truncated))
    }

    /// Inspect a single authorized case and compare the immutable indexed
    /// records with published files. No evidence is modified or discarded.
    pub fn reconcile_case_artifacts(
        &self,
        case_id: &str,
        root: &Path,
    ) -> Result<CaseReconciliation, String> {
        crate::validate_case_id(case_id)?;
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        let (indexed, index_truncated) = self.indexed_for_reconciliation(case_id)?;
        let case_dir = root.join(case_id);
        let root_meta = std::fs::symlink_metadata(root)
            .map_err(|e| format!("cannot stat evidence root: {e}"))?;
        if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
            return Err("unsafe evidence root".into());
        }
        let case_meta = match std::fs::symlink_metadata(&case_dir) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CaseReconciliation {
                    case_id: case_id.to_string(),
                    truncated: index_truncated,
                    entries: indexed
                        .into_iter()
                        .map(|r| ReconciliationEntry {
                            name: Path::new(&r.stored_path)
                                .file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            artifact_id: Some(r.id),
                            state: ReconciliationState::IndexedMissing,
                            size: Some(r.size),
                            sha256: None,
                        })
                        .collect(),
                });
            }
            Err(e) => return Err(format!("cannot inspect case evidence: {e}")),
        };
        if !case_meta.is_dir() || case_meta.file_type().is_symlink() {
            return Err("unsafe case evidence directory".into());
        }
        let canonical_root = std::fs::canonicalize(root)
            .map_err(|e| format!("cannot resolve evidence root: {e}"))?;
        let canonical_case = std::fs::canonicalize(&case_dir)
            .map_err(|e| format!("cannot resolve case directory: {e}"))?;
        if !canonical_case.starts_with(&canonical_root) || canonical_case == canonical_root {
            return Err("case evidence escapes the configured root".into());
        }
        let mut by_name: HashMap<String, Vec<ArtifactRecord>> = HashMap::new();
        let mut entries = Vec::new();
        for record in indexed {
            let path = Path::new(&record.stored_path);
            // stored_path is published from the uncanonicalized artifacts
            // dir, which on macOS traverses /var -> /private/var; resolve it
            // before comparing so the membership check stays exact without
            // reporting valid evidence as tampered. A symlinked member
            // resolves outside the case directory and still fails here, and
            // an unresolvable path is not tampering: the presence check below
            // decides between IndexedMissing and UnindexedPublished.
            if let Ok(resolved) = std::fs::canonicalize(path) {
                if resolved.parent() != Some(canonical_case.as_path()) {
                    entries.push(ReconciliationEntry {
                        name: path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        artifact_id: Some(record.id),
                        state: ReconciliationState::IndexedTampered,
                        size: Some(record.size),
                        sha256: None,
                    });
                    continue;
                }
            }
            if let Some(leaf) = path.file_name() {
                by_name
                    .entry(leaf.to_string_lossy().into_owned())
                    .or_default()
                    .push(record);
            }
        }
        let mut seen = HashSet::new();
        let mut names = Vec::<PathBuf>::new();
        let reader = std::fs::read_dir(&case_dir)
            .map_err(|e| format!("cannot enumerate case evidence: {e}"))?;
        let mut truncated = index_truncated;
        for item in reader {
            if names.len() >= MAX_SCAN_ENTRIES {
                truncated = true;
                break;
            }
            names.push(
                item.map_err(|e| format!("cannot inspect case entry: {e}"))?
                    .path(),
            );
        }
        names.sort();
        // Hard cap on aggregate unknown-file hashing during one audit.
        let mut unknown_hash_budget = MAX_UNKNOWN_HASH_BYTES;
        let mut indexed_hash_budget = 256 * 1024 * 1024_u64;
        for path in names {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            seen.insert(name.clone());
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("cannot stat case entry: {e}"))?;
            if let Some(records) = by_name.get(&name) {
                for record in records {
                    let within_budget = record.size <= indexed_hash_budget;
                    if within_budget {
                        indexed_hash_budget -= record.size;
                    }
                    #[cfg(unix)]
                    let verified =
                        within_budget && crate::open_verified_case_artifact(record, root).is_ok();
                    #[cfg(not(unix))]
                    let verified =
                        within_budget && crate::verify_artifact_file(record, root).is_ok();
                    entries.push(ReconciliationEntry {
                        name: name.clone(),
                        artifact_id: Some(record.id.clone()),
                        state: if !within_budget {
                            ReconciliationState::IndexedUnverified
                        } else if verified {
                            ReconciliationState::IndexedVerified
                        } else {
                            ReconciliationState::IndexedTampered
                        },
                        size: Some(record.size),
                        sha256: if verified {
                            Some(record.sha256.clone())
                        } else {
                            None
                        },
                    });
                }
            } else {
                let normal = metadata.file_type().is_file() && !metadata.file_type().is_symlink();
                let state = if !normal {
                    ReconciliationState::UnsafeEntry
                } else if name.starts_with(".evidence-") && name.ends_with(".tmp") {
                    ReconciliationState::StagedIncomplete
                } else if name.ends_with(".evidence") {
                    ReconciliationState::UnindexedPublished
                } else {
                    ReconciliationState::UnrecognizedFile
                };
                let within_budget = normal && metadata.len() <= unknown_hash_budget;
                if within_budget {
                    unknown_hash_budget -= metadata.len();
                }
                let digest = if within_budget {
                    path.file_name()
                        .and_then(|leaf| hash_unknown(&case_dir, leaf, metadata.len()))
                } else {
                    None
                };
                entries.push(ReconciliationEntry {
                    name,
                    artifact_id: None,
                    state,
                    size: normal.then_some(metadata.len()),
                    sha256: digest,
                });
            }
        }
        for (name, records) in by_name {
            if !seen.contains(&name) {
                for record in records {
                    entries.push(ReconciliationEntry {
                        name: name.clone(),
                        artifact_id: Some(record.id),
                        state: ReconciliationState::IndexedMissing,
                        size: Some(record.size),
                        sha256: None,
                    });
                }
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(CaseReconciliation {
            case_id: case_id.to_string(),
            entries,
            truncated,
        })
    }

    /// Explicit operator-requested adoption of an already published file.
    /// Validates case/digest and commits index + provenance in one transaction.
    /// Repeated calls do not append duplicate recovery provenance.
    pub fn recover_published_artifact(
        &self,
        record: &ArtifactRecord,
        root: &Path,
    ) -> Result<ExplicitRecovery, String> {
        crate::validate_case_id(&record.case_id)?;
        if !self.case_exists(&record.case_id)? {
            return Err("case not found".into());
        }
        if let Some(indexed) = self.get_artifact(&record.id)? {
            if indexed.case_id == record.case_id
                && indexed.stored_path == record.stored_path
                && indexed.sha256.eq_ignore_ascii_case(&record.sha256)
                && indexed.size == record.size
            {
                #[cfg(unix)]
                drop(crate::open_verified_case_artifact(&indexed, root)?);
                #[cfg(not(unix))]
                crate::verify_artifact_file(&indexed, root)?;
                return Ok(ExplicitRecovery::AlreadyIndexed);
            }
            return Err("recovery artifact ID conflicts with existing evidence".into());
        }
        // commit_artifact_batch reopens through the confined verifier on Unix
        // and checks the expected digest before beginning its SQLite transaction.
        // Do not hash the entire file a second time here.
        let event = [ImportEvent {
            source: "cases.reconciliation",
            action: "recover",
            description: "explicitly reviewed unindexed published evidence",
        }];
        let ids = self.commit_artifact_import_with_events(record, root, &event, &[])?;
        Ok(ExplicitRecovery::Adopted { event_id: ids[0] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CASE;

    fn sample(root: &Path, name: &str, data: &[u8], id: &str) -> ArtifactRecord {
        let case_dir = root.join(DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let file = case_dir.join(name);
        std::fs::write(&file, data).unwrap();
        ArtifactRecord {
            id: id.into(),
            case_id: DEFAULT_CASE.into(),
            name: name.into(),
            stored_path: file.to_string_lossy().into_owned(),
            original_path: None,
            size: data.len() as u64,
            sha256: format!("{:x}", Sha256::digest(data)),
            md5: String::new(),
            sha1: String::new(),
            crc32: String::new(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        }
    }

    #[test]
    fn crash_after_publish_is_detected_then_explicitly_adopted_once_across_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let db = temp.path().join("cases.db");
        let record = sample(
            &root,
            "abc.evidence",
            b"published but not indexed",
            "evidence-1",
        );
        let store = ArtifactStore::open(&db).unwrap();
        let found = store.reconcile_case_artifacts(DEFAULT_CASE, &root).unwrap();
        assert_eq!(
            found.entries[0].state,
            ReconciliationState::UnindexedPublished
        );
        assert!(found.entries[0].sha256.is_some());
        drop(store);
        let reopened = ArtifactStore::open(&db).unwrap();
        let adopted = reopened.recover_published_artifact(&record, &root).unwrap();
        assert!(matches!(adopted, ExplicitRecovery::Adopted { .. }));
        assert_eq!(
            reopened.recover_published_artifact(&record, &root).unwrap(),
            ExplicitRecovery::AlreadyIndexed
        );
        drop(reopened);
        let restarted = ArtifactStore::open(&db).unwrap();
        let scan = restarted
            .reconcile_case_artifacts(DEFAULT_CASE, &root)
            .unwrap();
        assert_eq!(scan.entries[0].state, ReconciliationState::IndexedVerified);
        assert_eq!(
            restarted
                .verify_case_provenance(DEFAULT_CASE)
                .unwrap()
                .verified_events,
            1
        );
    }

    #[test]
    fn staged_unknown_and_corrupt_files_are_reported_without_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let record = sample(&root, "one.evidence", b"original", "one");
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        store.upsert_artifact(&record).unwrap();
        let case_dir = root.join(DEFAULT_CASE);
        let staged = case_dir.join(".evidence-123.tmp");
        std::fs::write(&staged, b"staged").unwrap();
        let unknown = case_dir.join("two.evidence");
        std::fs::write(&unknown, b"unknown").unwrap();
        std::fs::write(&record.stored_path, b"changed!").unwrap();
        let scan = store.reconcile_case_artifacts(DEFAULT_CASE, &root).unwrap();
        assert!(scan
            .entries
            .iter()
            .any(|e| e.state == ReconciliationState::IndexedTampered));
        assert!(scan
            .entries
            .iter()
            .any(|e| e.state == ReconciliationState::StagedIncomplete));
        assert!(scan
            .entries
            .iter()
            .any(|e| e.state == ReconciliationState::UnindexedPublished));
        assert!(staged.exists() && unknown.exists());
        assert!(store.recover_published_artifact(&record, &root).is_err());
    }

    #[test]
    fn two_index_ids_sharing_one_member_are_not_hidden_by_reconciliation() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("artifacts");
        let original = sample(&root, "shared.evidence", b"identical", "first");
        let mut second = original.clone();
        second.id = "second".into();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        store.upsert_artifact(&original).unwrap();
        store.upsert_artifact(&second).unwrap();
        let report = store.reconcile_case_artifacts(DEFAULT_CASE, &root).unwrap();
        assert_eq!(report.entries.len(), 2);
        assert!(report
            .entries
            .iter()
            .all(|entry| entry.state == ReconciliationState::IndexedVerified));
        assert_ne!(report.entries[0].artifact_id, report.entries[1].artifact_id);
    }

    #[test]
    fn massive_indexed_file_is_reported_as_unverified_without_full_scan() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let mut record = sample(&root, "huge.evidence", b"", "huge");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&record.stored_path)
            .unwrap();
        file.set_len(257 * 1024 * 1024).unwrap();
        record.size = 257 * 1024 * 1024;
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        store.upsert_artifact(&record).unwrap();
        let scan = store.reconcile_case_artifacts(DEFAULT_CASE, &root).unwrap();
        assert_eq!(
            scan.entries[0].state,
            ReconciliationState::IndexedUnverified
        );
        assert!(scan.entries[0].sha256.is_none());
        assert!(Path::new(&record.stored_path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_cross_case_recovery_fail_closed() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let mut record = sample(&root, "one.evidence", b"case1", "one");
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"case1").unwrap();
        std::fs::remove_file(&record.stored_path).unwrap();
        symlink(&outside, &record.stored_path).unwrap();
        assert!(store.recover_published_artifact(&record, &root).is_err());
        assert!(store
            .reconcile_case_artifacts(DEFAULT_CASE, &root)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.state == ReconciliationState::UnsafeEntry));
        let dangling = root.join(DEFAULT_CASE).join("unindexed.evidence");
        symlink(&outside, &dangling).unwrap();
        assert!(store
            .reconcile_case_artifacts(DEFAULT_CASE, &root)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.state == ReconciliationState::UnsafeEntry));
        record.case_id = "other".into();
        assert!(store.recover_published_artifact(&record, &root).is_err());
    }
}

//! Backend-only original network.capture PCAP evidence importer.
//! The caller must hold the authoritative case revision and capture publish
//! gates across this operation. No client-supplied bytes or paths are accepted.
use crate::{ArtifactRecord, ArtifactStore, ImportBatchItem, ImportEvent, DEFAULT_CASE};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_ORIGINAL_PCAP_BYTES: usize = 16 * 1024 * 1024;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

/// Built by the trusted native CaptureResult, never deserialized from IPC.
pub struct NetworkCaptureSource<'a> {
    pub session_id: u64,
    pub interface: &'a str,
    pub frame_offsets: &'a [usize],
    pub bytes: &'a [u8],
}

fn checked_offsets(source: &NetworkCaptureSource<'_>) -> Result<String, String> {
    let b = source.bytes;
    if b.len() < 24
        || b.len() > MAX_ORIGINAL_PCAP_BYTES
        || b[..4] != [0xd4, 0xc3, 0xb2, 0xa1]
        || b[4..8] != [2, 0, 4, 0]
        || b[20..24] != [1, 0, 0, 0]
        || source.interface.is_empty()
        || source.interface.len() > 100
        || source.interface.chars().any(char::is_control)
        || source.frame_offsets.len() > 200_000
    {
        return Err("invalid original Ethernet PCAP or capture metadata".into());
    }
    let mut cursor = 24usize;
    let mut i = 0usize;
    let mut frames = Sha256::new();
    while cursor < b.len() {
        if b.len() - cursor < 16 || i == 200_000 {
            return Err("truncated or excess original PCAP records".into());
        }
        let size = u32::from_le_bytes(b[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        let wire = u32::from_le_bytes(b[cursor + 12..cursor + 16].try_into().unwrap()) as usize;
        let start = cursor
            .checked_add(16)
            .ok_or("capture frame offset overflow")?;
        let end = start
            .checked_add(size)
            .ok_or("capture frame length overflow")?;
        if size == 0
            || size > 65_535
            || wire < size
            || end > b.len()
            || source.frame_offsets.get(i) != Some(&start)
        {
            return Err("original frame bytes differ from capture provenance".into());
        }
        frames.update((start as u64).to_le_bytes());
        frames.update((size as u64).to_le_bytes());
        i += 1;
        cursor = end;
    }
    if cursor != b.len() || i != source.frame_offsets.len() {
        return Err("original PCAP record count mismatch".into());
    }
    Ok(format!("{:x}", frames.finalize()))
}

pub(crate) fn publish_no_replace(
    dir: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    if fs::symlink_metadata(destination).is_ok() {
        // The caller MUST still verify full on-disk bytes via pinned handle.
        return Ok(());
    }
    let mut stage = None;
    for _ in 0..16 {
        let n = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(".capture-{}-{n}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => {
                stage = Some((path, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("cannot stage capture: {e}")),
        }
    }
    let (temp, mut file) = stage.ok_or("capture temporary allocation exhausted")?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|e| format!("cannot write original PCAP: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot sync original PCAP: {e}"))?;
        drop(file);
        match fs::hard_link(&temp, destination) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(format!("cannot publish original capture: {e}")),
        }
    })();
    // Our temporary is safe to unlink. Published/uncertain evidence is never
    // removed following a transaction failure; reconciliation reports it.
    let _ = fs::remove_file(&temp);
    result
}

impl ArtifactStore {
    /// SQLite index + append-only provenance commit is atomic. Case selection
    /// and capture authorization must be serialized externally by the trusted
    /// Tauri caller using CaseSessionCtx::with_current_publication.
    pub fn import_original_network_capture(
        &self,
        artifacts_root: &Path,
        case_id: &str,
        source: &NetworkCaptureSource<'_>,
    ) -> Result<ArtifactRecord, String> {
        crate::validate_case_id(case_id)?;
        if case_id == DEFAULT_CASE {
            return Err("temporary workspace is not a persistent case".into());
        }
        if !self.case_exists(case_id)? {
            return Err("selected capture case does not exist".into());
        }
        let offsets_digest = checked_offsets(source)?;
        let sha256 = format!("{:x}", Sha256::digest(source.bytes));
        let id = format!("{case_id}:capture-{}", &sha256[..32]);
        fs::create_dir_all(artifacts_root).map_err(|e| e.to_string())?;
        let root_meta = fs::symlink_metadata(artifacts_root).map_err(|e| e.to_string())?;
        if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
            return Err("unsafe capture evidence root".into());
        }
        let root = fs::canonicalize(artifacts_root).map_err(|e| e.to_string())?;
        let case_dir = root.join(case_id);
        fs::create_dir_all(&case_dir).map_err(|e| e.to_string())?;
        let case_meta = fs::symlink_metadata(&case_dir).map_err(|e| e.to_string())?;
        if !case_meta.is_dir()
            || case_meta.file_type().is_symlink()
            || fs::canonicalize(&case_dir)
                .map_err(|e| e.to_string())?
                .parent()
                != Some(root.as_path())
        {
            return Err("capture case evidence directory is unsafe".into());
        }
        let path = case_dir.join(format!("{sha256}.evidence"));
        let prior = self.get_artifact(&id)?;
        if let Some(ref old) = prior {
            if old.case_id != case_id
                || old.sha256 != sha256
                || old.size != source.bytes.len() as u64
                || old.stored_path != path.to_string_lossy()
            {
                return Err("immutable original capture identity conflict".into());
            }
        }
        publish_no_replace(&case_dir, &path, source.bytes)?;
        let record = prior.unwrap_or_else(|| ArtifactRecord {
            id,
            case_id: case_id.to_owned(),
            name: format!("Capture session {}.pcap", source.session_id),
            stored_path: path.to_string_lossy().into_owned(),
            original_path: None,
            size: source.bytes.len() as u64,
            sha256: sha256.clone(),
            md5: String::new(),
            sha1: String::new(),
            crc32: String::new(),
            signature: Some("Original Ethernet PCAP".into()),
            entropy: 0.0,
            imported_at: crate::timestamp_ms().to_string(),
        });
        // Same-descriptor verification & exact original-byte readback.
        // Windows remains explicitly disabled until the NTFS handle adapter
        // passes its native acceptance matrix.
        let mut verified = crate::open_verified_case_artifact(&record, artifacts_root)?;
        if verified.read_window(0, source.bytes.len(), MAX_ORIGINAL_PCAP_BYTES)? != source.bytes {
            return Err("original capture failed exact at-rest readback".into());
        }
        let description = format!(
            "session={};interface={};frames={};offsets_sha256={}",
            source.session_id,
            source.interface,
            source.frame_offsets.len(),
            offsets_digest
        );
        let event = [ImportEvent {
            source: "network.capture",
            action: "import_original",
            description: &description,
        }];
        self.commit_artifact_batch(
            artifacts_root,
            &[ImportBatchItem {
                record: &record,
                events: &event,
                findings: &[],
            }],
        )?;
        drop(crate::open_verified_case_artifact(&record, artifacts_root)?);
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Vec<u8>, Vec<usize>) {
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let mut offsets = Vec::new();
        for frame in [b"abc".as_slice(), b"test".as_slice()] {
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&2u32.to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            offsets.push(bytes.len());
            bytes.extend_from_slice(frame);
        }
        (bytes, offsets)
    }
    #[cfg(unix)]
    #[test]
    fn original_capture_exact_bytes_survive_restart_with_provenance() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("evidence");
        let db = tmp.path().join("cases.db");
        let store = ArtifactStore::open(&db).unwrap();
        let case = store.create_case("Capture", "").unwrap();
        let (bytes, offsets) = fixture();
        let src = NetworkCaptureSource {
            session_id: 3,
            interface: "eth0",
            frame_offsets: &offsets,
            bytes: &bytes,
        };
        let record = store
            .import_original_network_capture(&root, &case.id, &src)
            .unwrap();
        let mut fd = crate::open_verified_case_artifact(&record, &root).unwrap();
        assert_eq!(
            fd.read_window(0, bytes.len(), MAX_ORIGINAL_PCAP_BYTES)
                .unwrap(),
            bytes
        );
        drop(store);
        let reopened = ArtifactStore::open(&db).unwrap();
        assert_eq!(reopened.list_artifacts(&case.id).unwrap().len(), 1);
        let events = reopened.list_events(&case.id).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "network.capture");
        assert!(events[0].source_description.contains("frames=2"));
        assert_eq!(
            reopened
                .verify_case_provenance(&case.id)
                .unwrap()
                .verified_events,
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn scratchpad_and_false_offsets_never_publish_or_index() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("evidence");
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let case = store.create_case("Case", "").unwrap();
        let (bytes, offsets) = fixture();
        let src = NetworkCaptureSource {
            session_id: 1,
            interface: "eth0",
            frame_offsets: &offsets,
            bytes: &bytes,
        };
        assert!(store
            .import_original_network_capture(&root, DEFAULT_CASE, &src)
            .is_err());
        let mut bad = offsets.clone();
        bad[0] += 1;
        let invalid = NetworkCaptureSource {
            frame_offsets: &bad,
            ..src
        };
        assert!(store
            .import_original_network_capture(&root, &case.id, &invalid)
            .is_err());
        assert!(store.list_artifacts(&case.id).unwrap().is_empty());
        assert!(store.list_events(&case.id).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn failed_sqlite_commit_keeps_original_for_safe_reconciliation() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("evidence");
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let case = store.create_case("Case", "").unwrap();
        store.conn.execute_batch(
            "CREATE TRIGGER fail_capture BEFORE INSERT ON case_events WHEN NEW.source='network.capture' BEGIN SELECT RAISE(ABORT,'fixture'); END;"
        ).unwrap();
        let (bytes, offsets) = fixture();
        let src = NetworkCaptureSource {
            session_id: 1,
            interface: "eth0",
            frame_offsets: &offsets,
            bytes: &bytes,
        };
        assert!(store
            .import_original_network_capture(&root, &case.id, &src)
            .is_err());
        assert!(store.list_artifacts(&case.id).unwrap().is_empty());
        assert!(store.list_events(&case.id).unwrap().is_empty());
        let scan = store.reconcile_case_artifacts(&case.id, &root).unwrap();
        assert!(scan
            .entries
            .iter()
            .any(|x| x.state == crate::ReconciliationState::UnindexedPublished));
    }
}

//! Explicit all-or-nothing SQL promotion of bounded nonsecret volatile results.
//! The caller owns temporary-session generation, eligibility and OS consent.
//! New-case creation and every artifact/provenance event share ONE transaction.
use crate::{integrity, timestamp_ms, ArtifactRecord, ArtifactStore, CaseEvent, CaseRecord, DEFAULT_CASE, GENESIS_HASH};
use crate::application::network_capture::publish_no_replace;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub const TEMP_MAX_ARTIFACTS: usize = 8;
pub const TEMP_MAX_EACH_BYTES: usize = 256 * 1024;
pub const TEMP_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct TemporaryEvidence<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
    /// Backend-classified eligible source only, never frontend-defined.
    pub source: &'a str,
}

#[derive(Clone, Copy)]
pub enum PromotionDestination<'a> {
    New { title: &'a str, description: &'a str },
    Existing(&'a str),
}

pub struct PromotionReceipt {
    pub case: CaseRecord,
    pub artifacts: Vec<ArtifactRecord>,
}

impl ArtifactStore {
    /// The entire SQLite change set (including new case creation) is atomic.
    /// Files are first published immutably; any failed SQL leaves uncertain
    /// originals for case-scoped reconciliation, never silently deletes them.
    pub fn promote_temporary_evidence(
        &self,
        root: &Path,
        destination: PromotionDestination<'_>,
        artifacts: &[TemporaryEvidence<'_>],
    ) -> Result<PromotionReceipt, String> {
        if artifacts.is_empty() || artifacts.len() > TEMP_MAX_ARTIFACTS {
            return Err("temporary promotion needs 1 to 8 eligible artifacts".into());
        }
        let mut total = 0usize;
        let mut digests = HashSet::new();
        for item in artifacts {
            if item.name.is_empty() || item.name.len() > 100
                || item.name == "." || item.name == ".."
                || item.name.chars().any(|c| c.is_control() || c == '/' || c == '\\')
                || item.bytes.is_empty() || item.bytes.len() > TEMP_MAX_EACH_BYTES
                || !matches!(item.source, "temporary.sha256" | "temporary.public-diagnostic")
            {
                return Err("ineligible temporary output or invalid artifact name".into());
            }
            total = total.checked_add(item.bytes.len()).ok_or("temporary output budget overflow")?;
            if total > TEMP_MAX_TOTAL_BYTES {
                return Err("temporary promotion byte limit exceeded".into());
            }
            if !digests.insert(Sha256::digest(item.bytes).to_vec()) {
                return Err("duplicate output digests in one promotion".into());
            }
        }
        let new_case = match destination {
            PromotionDestination::New { title, description } => {
                let title = title.trim();
                let description = description.trim();
                if title.is_empty() || title.len() > 120 || description.len() > 2048 {
                    return Err("invalid case title or description".into());
                }
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?
                    .as_nanos();
                Some(CaseRecord {
                    id: format!("case-{nanos:x}-{:x}", std::process::id()),
                    title: title.into(), description: description.into(),
                    created_ms: timestamp_ms(),
                })
            }
            PromotionDestination::Existing(id) => {
                crate::validate_case_id(id)?;
                if id == DEFAULT_CASE { return Err("Scratchpad cannot be a promotion destination".into()); }
                None
            }
        };
        let case = if let Some(ref record) = new_case {
            record.clone()
        } else {
            let PromotionDestination::Existing(id) = destination else { unreachable!() };
            self.list_cases()?.into_iter().find(|c| c.id == id)
                .ok_or("promotion destination case not found")?
        };
        fs::create_dir_all(root).map_err(|e| format!("cannot initialize evidence root: {e}"))?;
        let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("unsafe temporary evidence root".into());
        }
        let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        let dir = root.join(&case.id);
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create case evidence folder: {e}"))?;
        let meta = fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.file_type().is_symlink()
            || fs::canonicalize(&dir).map_err(|e| e.to_string())?.parent() != Some(root.as_path()) {
            return Err("unsafe case evidence folder".into());
        }
        let mut records = Vec::with_capacity(artifacts.len());
        let now = timestamp_ms();
        for item in artifacts {
            let digest = format!("{:x}", Sha256::digest(item.bytes));
            let id = format!("{}:temporary-{}", case.id, &digest[..32]);
            let path = dir.join(format!("{digest}.evidence"));
            let existing = self.get_artifact(&id)?;
            if let Some(ref old) = existing {
                if old.case_id != case.id || old.sha256 != digest
                    || old.size != item.bytes.len() as u64
                    || Path::new(&old.stored_path) != path {
                    return Err("immutable promotion destination identity conflict".into());
                }
            }
            publish_no_replace(&dir, &path, item.bytes)?;
            let record = existing.unwrap_or_else(|| ArtifactRecord {
                id, case_id: case.id.clone(), name: item.name.to_owned(),
                stored_path: path.to_string_lossy().into_owned(), original_path: None,
                size: item.bytes.len() as u64, sha256: digest,
                md5: String::new(), sha1: String::new(), crc32: String::new(),
                signature: Some("Volatile verified output".into()), entropy: 0.0,
                imported_at: now.to_string(),
            });
            let mut verified = crate::open_verified_case_artifact(&record, &root)?;
            if verified.read_window(0, item.bytes.len(), TEMP_MAX_EACH_BYTES)? != item.bytes {
                return Err("promoted evidence differs from original temporary bytes".into());
            }
            records.push(record);
        }

        let tx = self.conn.unchecked_transaction()
            .map_err(|e| format!("cannot start promotion transaction: {e}"))?;
        if let Some(ref fresh) = new_case {
            tx.execute("INSERT INTO cases(id,title,description,created_ms) VALUES(?1,?2,?3,?4)",
                params![fresh.id,fresh.title,fresh.description,fresh.created_ms])
                .map_err(|e| format!("cannot create new saved case atomically: {e}"))?;
        } else {
            let exists: i64 = tx.query_row(
                "SELECT count(*) FROM cases WHERE id=?1", params![case.id], |r| r.get(0))
                .map_err(|e| e.to_string())?;
            if exists != 1 { return Err("case changed during promotion".into()); }
        }
        let tail: Option<i64> = tx.query_row(
            "SELECT id FROM case_events WHERE case_id=?1 ORDER BY id DESC LIMIT 1",
            params![case.id], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
        let head: Option<(i64,String)> = tx.query_row(
            "SELECT event_id,event_hash FROM case_event_integrity WHERE case_id=?1 ORDER BY event_id DESC LIMIT 1",
            params![case.id], |r| Ok((r.get(0)?,r.get(1)?)))
            .optional().map_err(|e| e.to_string())?;
        if tail != head.as_ref().map(|(id, _)| *id) {
            return Err("provenance history incomplete; promotion aborted".into());
        }
        let mut prior = head.map(|(_,hash)| hash).unwrap_or_else(|| GENESIS_HASH.to_owned());
        for (record, staged) in records.iter().zip(artifacts) {
            let inserted = tx.execute(
                "INSERT INTO artifacts(id,case_id,name,stored_path,original_path,size,sha256,md5,sha1,crc32,signature,entropy,imported_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                 ON CONFLICT(id) DO NOTHING",
                params![record.id,record.case_id,record.name,record.stored_path,record.original_path,
                    record.size,record.sha256,record.md5,record.sha1,record.crc32,
                    record.signature,record.entropy,record.imported_at])
                .map_err(|e| format!("cannot index promoted output: {e}"))?;
            if inserted == 0 {
                let existing: (String,String,i64,String) = tx.query_row(
                    "SELECT case_id,sha256,size,stored_path FROM artifacts WHERE id=?1",
                    params![record.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))
                    .map_err(|e| e.to_string())?;
                if existing.0 != case.id || existing.1 != record.sha256
                    || existing.2 != record.size as i64 || existing.3 != record.stored_path {
                    return Err("promoted evidence identity conflicts with existing index".into());
                }
            }
            let desc = format!("volatile-output={};sha256={}", staged.name, record.sha256);
            tx.execute(
                "INSERT INTO case_events(case_id,source,action,artifact_id,source_description,created_ms)
                 VALUES(?1,?2,'promote',?3,?4,?5)",
                params![case.id,staged.source,record.id,desc,now])
                .map_err(|e| format!("cannot append promotion event: {e}"))?;
            let id = tx.last_insert_rowid();
            let event = CaseEvent {
                id, case_id: case.id.clone(), source: staged.source.to_owned(),
                action: "promote".into(), artifact_id: Some(record.id.clone()),
                source_description: desc, created_ms: now,
            };
            let hash = integrity::event_hash(&event, &prior);
            tx.execute(
                "INSERT INTO case_event_integrity(event_id,case_id,previous_hash,event_hash)
                 VALUES(?1,?2,?3,?4)",
                params![id,case.id,prior,hash])
                .map_err(|e| format!("cannot chain promotion provenance: {e}"))?;
            prior = hash;
        }
        tx.commit().map_err(|e| format!("cannot commit temporary promotion: {e}"))?;
        Ok(PromotionReceipt { case, artifacts: records })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn staged<'a>(bytes: &'a [u8]) -> TemporaryEvidence<'a> {
        TemporaryEvidence { name: "sha256-digest.txt", bytes, source: "temporary.sha256" }
    }
    #[cfg(unix)]
    #[test]
    fn new_case_promotion_is_atomic_and_restart_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db.sqlite");
        let root = tmp.path().join("artifacts");
        let store = ArtifactStore::open(&db).unwrap();
        let b = b"sha256:abcd1234\n";
        let receipt = store.promote_temporary_evidence(
            &root, PromotionDestination::New {title:"Investigation",description:""},
            &[staged(b)]).unwrap();
        assert_eq!(receipt.artifacts.len(),1);
        assert_ne!(receipt.case.id, DEFAULT_CASE);
        drop(store);
        let reopened = ArtifactStore::open(&db).unwrap();
        assert_eq!(reopened.list_artifacts(&receipt.case.id).unwrap().len(),1);
        let mut f = crate::open_verified_case_artifact(&receipt.artifacts[0],&root).unwrap();
        assert_eq!(f.read_window(0,b.len(),TEMP_MAX_EACH_BYTES).unwrap(),b);
        assert_eq!(reopened.verify_case_provenance(&receipt.case.id).unwrap().verified_events,1);
    }
    #[cfg(unix)]
    #[test]
    fn existing_case_promotion_is_all_or_nothing_even_if_late_event_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("artifacts");
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let case = store.create_case("Target","").unwrap();
        store.conn.execute_batch(
            "CREATE TRIGGER fail_second BEFORE INSERT ON case_events WHEN NEW.source_description LIKE '%second%' BEGIN SELECT RAISE(ABORT,'fixture'); END;"
        ).unwrap();
        let a = TemporaryEvidence{name:"first",bytes:b"alpha",source:"temporary.sha256"};
        let b = TemporaryEvidence{name:"second",bytes:b"bravo",source:"temporary.sha256"};
        assert!(store.promote_temporary_evidence(&root,PromotionDestination::Existing(&case.id),&[a,b]).is_err());
        assert!(store.list_artifacts(&case.id).unwrap().is_empty());
        assert!(store.list_events(&case.id).unwrap().is_empty());
        let scan = store.reconcile_case_artifacts(&case.id,&root).unwrap();
        assert!(scan.entries.iter().any(|e| e.state == crate::ReconciliationState::UnindexedPublished));
    }
    #[cfg(unix)]
    #[test]
    fn denies_scratchpad_duplicate_and_ineligible_secret_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("artifacts");
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let case = store.create_case("Saved","").unwrap();
        let item = staged(b"safe digest");
        assert!(store.promote_temporary_evidence(&root,PromotionDestination::Existing(DEFAULT_CASE),&[item]).is_err());
        assert!(store.promote_temporary_evidence(&root,PromotionDestination::Existing(&case.id),&[item,item]).is_err());
        let bad = TemporaryEvidence { name:"secret",bytes:b"password=hi",source:"recovery.password" };
        assert!(store.promote_temporary_evidence(&root,PromotionDestination::Existing(&case.id),&[bad]).is_err());
        assert!(store.list_artifacts(&case.id).unwrap().is_empty());
    }
}

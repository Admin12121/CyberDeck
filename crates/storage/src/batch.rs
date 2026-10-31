//! Case-scoped atomic batch import of evidence indexes, events and findings.
//! The filesystem must be safely published before this SQLite transaction.
use crate::{
    integrity, timestamp_ms, ArtifactRecord, ArtifactStore, CaseEvent, ImportEvent, NewFinding,
    GENESIS_HASH,
};
use rusqlite::{params, OptionalExtension};
use std::{collections::HashSet, path::Path};

/// An artifact plus its ordered provenance and associated findings.
#[derive(Debug, Clone, Copy)]
pub struct ImportBatchItem<'a> {
    pub record: &'a ArtifactRecord,
    pub events: &'a [ImportEvent<'a>],
    pub findings: &'a [NewFinding],
}

impl ArtifactStore {
    /// All indexed artifacts, events, and findings succeed or roll back as one
    /// SQLite transaction. Filesystem publication remains the caller's task.
    ///
    /// Every item must belong to the same existing case; repeated IDs in the
    /// same batch are rejected rather than creating ambiguous lineage.
    pub fn commit_artifact_batch(
        &self,
        artifacts_root: &Path,
        items: &[ImportBatchItem<'_>],
    ) -> Result<Vec<Vec<i64>>, String> {
        if items.is_empty() || items.len() > 32 {
            return Err("batch must contain 1 to 32 artifacts".into());
        }
        let case_id = &items[0].record.case_id;
        if !self.case_exists(case_id)? {
            return Err("selected case does not exist".into());
        }
        let mut ids = HashSet::with_capacity(items.len());
        let mut total_events = 0usize;
        let mut total_findings = 0usize;
        // Validate *all* filesystem evidence and metadata before beginning writes.
        for item in items {
            let record = item.record;
            if &record.case_id != case_id {
                return Err("batch must use a single case".into());
            }
            if !ids.insert(&record.id) {
                return Err("duplicate artifact ID in batch".into());
            }
            i64::try_from(record.size)
                .map_err(|_| "evidence exceeds SQLite signed-size limit".to_string())?;
            if item.events.is_empty() || item.events.len() > 32 || item.findings.len() > 128 {
                return Err("invalid per-artifact operation count".into());
            }
            total_events += item.events.len();
            total_findings += item.findings.len();
            if total_events > 512 || total_findings > 512 {
                return Err("batch exceeds total operation limits".into());
            }
            for event in item.events {
                if event.source.is_empty() || event.source.len() > 80
                    || event.action.is_empty() || event.action.len() > 60
                    || event.description.len() > 512
                {
                    return Err("invalid provenance metadata".into());
                }
            }
            for finding in item.findings {
                if finding.title.is_empty() || finding.title.len() > 200
                    || finding.details.len() > 8192
                    || !matches!(finding.severity.as_str(),
                        "info" | "low" | "medium" | "high" | "critical")
                {
                    return Err("invalid finding metadata".into());
                }
            }
            integrity::verify_artifact_file(record, artifacts_root)?;
        }

        let tx = self.conn.unchecked_transaction()
            .map_err(|e| format!("cannot start batch transaction: {e}"))?;
        let tail: Option<i64> = tx.query_row(
            "SELECT id FROM case_events WHERE case_id=?1 ORDER BY id DESC LIMIT 1",
            params![case_id], |r| r.get(0),
        ).optional().map_err(|e| e.to_string())?;
        let head: Option<(i64, String)> = tx.query_row(
            "SELECT event_id,event_hash FROM case_event_integrity
             WHERE case_id=?1 ORDER BY event_id DESC LIMIT 1",
            params![case_id], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        if tail != head.as_ref().map(|(id,_)| *id) {
            return Err("provenance history is incomplete".into());
        }
        let mut previous = head.map(|(_,hash)|hash).unwrap_or_else(|| GENESIS_HASH.into());
        let mut all_ids = Vec::with_capacity(items.len());
        let now = timestamp_ms();
        for item in items {
            let record = item.record;
            let inserted = tx.execute(
                "INSERT INTO artifacts(id,case_id,name,stored_path,original_path,size,
                 sha256,md5,sha1,crc32,signature,entropy,imported_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                 ON CONFLICT(id) DO NOTHING",
                params![
                    record.id,record.case_id,record.name,record.stored_path,record.original_path,
                    record.size,record.sha256,record.md5,record.sha1,record.crc32,
                    record.signature,record.entropy,record.imported_at
                ],
            ).map_err(|e| format!("cannot index batch artifact: {e}"))?;
            if inserted == 0 {
                let indexed: Option<(String,String,i64,String)> = tx.query_row(
                    "SELECT case_id,sha256,size,stored_path FROM artifacts WHERE id=?1",
                    params![record.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
                ).optional().map_err(|e| e.to_string())?;
                let (owner,sha,size,path) = indexed
                    .ok_or_else(|| "evidence identity conflict".to_string())?;
                if owner != record.case_id || sha != record.sha256
                    || size != record.size as i64 || path != record.stored_path {
                    return Err("evidence identity conflicts with immutable index".into());
                }
            }
            let mut event_ids = Vec::with_capacity(item.events.len());
            for event in item.events {
                tx.execute(
                    "INSERT INTO case_events(case_id,source,action,artifact_id,source_description,created_ms)
                     VALUES(?1,?2,?3,?4,?5,?6)",
                    params![record.case_id,event.source,event.action,record.id,event.description,now],
                ).map_err(|e| format!("cannot append batch event: {e}"))?;
                let event_id = tx.last_insert_rowid();
                let event_record = CaseEvent {
                    id:event_id,case_id:record.case_id.clone(),source:event.source.to_string(),
                    action:event.action.to_string(),artifact_id:Some(record.id.clone()),
                    source_description:event.description.to_string(),created_ms:now,
                };
                let digest = integrity::event_hash(&event_record, &previous);
                tx.execute(
                    "INSERT INTO case_event_integrity(event_id,case_id,previous_hash,event_hash)
                     VALUES(?1,?2,?3,?4)",
                    params![event_id,record.case_id,previous,digest],
                ).map_err(|e| format!("cannot append batch provenance: {e}"))?;
                previous = digest;
                event_ids.push(event_id);
            }
            for finding in item.findings {
                tx.execute(
                    "INSERT INTO findings(case_id,source,title,severity,details,artifact_id,created_ms)
                     VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![record.case_id,item.events[0].source,finding.title,
                            finding.severity,finding.details,record.id,now],
                ).map_err(|e| format!("cannot append batch finding: {e}"))?;
            }
            all_ids.push(event_ids);
        }
        tx.commit().map_err(|e| format!("cannot commit evidence batch: {e}"))?;
        Ok(all_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sample(case_dir: &Path, name: &str, data: &[u8], case: &str) -> ArtifactRecord {
        let path = case_dir.join(name);
        std::fs::write(&path, data).unwrap();
        ArtifactRecord {
            id:name.into(),case_id:case.into(),name:name.into(),
            stored_path:path.to_string_lossy().into(),original_path:None,size:data.len() as u64,
            sha256:format!("{:x}",Sha256::digest(data)),md5:String::new(),
            sha1:String::new(),crc32:String::new(),signature:None,entropy:0.0,imported_at:"1".into(),
        }
    }

    #[test]
    fn multi_artifact_batch_preserves_order_and_case_provenance() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let case_dir = root.join(crate::DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let a = sample(&case_dir, "first", b"hello", crate::DEFAULT_CASE);
        let b = sample(&case_dir, "second", b"world", crate::DEFAULT_CASE);
        let first_events = [ImportEvent {source:"archive",action:"extract",description:"parent:zip"},
            ImportEvent {source:"forensics",action:"inspect",description:"file:first"}];
        let second_events = [ImportEvent {source:"archive",action:"extract",description:"parent:zip"}];
        let finding = [NewFinding {title:"archive".into(), severity:"info".into(), details:"found".into()}];
        let items = [
            ImportBatchItem {record:&a,events:&first_events,findings:&finding},
            ImportBatchItem {record:&b,events:&second_events,findings:&[]},
        ];
        let event_ids = store.commit_artifact_batch(&root,&items).unwrap();
        assert_eq!(event_ids.len(),2);
        assert_eq!(event_ids[0].len(),2);
        assert_eq!(event_ids[1].len(),1);
        assert!(event_ids[0][1] < event_ids[1][0]);
        assert_eq!(store.list_artifacts(crate::DEFAULT_CASE).unwrap().len(),2);
        assert_eq!(store.list_findings(crate::DEFAULT_CASE).unwrap().len(),1);
        assert_eq!(store.verify_case_provenance(crate::DEFAULT_CASE).unwrap().verified_events,3);
    }

    #[test]
    fn failed_second_member_rolls_back_entire_archive_batch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let dir = root.join(crate::DEFAULT_CASE);
        std::fs::create_dir_all(&dir).unwrap();
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let a = sample(&dir,"a",b"valid",crate::DEFAULT_CASE);
        let b = sample(&dir,"b",b"valid-two",crate::DEFAULT_CASE);
        store.conn.execute_batch(
            "CREATE TRIGGER reject_second BEFORE INSERT ON case_events
             WHEN NEW.artifact_id='b' BEGIN SELECT RAISE(ABORT,'injected'); END;"
        ).unwrap();
        let e = [ImportEvent {source:"archive",action:"extract",description:"parent:a"}];
        let items = [ImportBatchItem {record:&a,events:&e,findings:&[]},
                     ImportBatchItem {record:&b,events:&e,findings:&[]}];
        assert!(store.commit_artifact_batch(&root,&items).is_err());
        assert!(store.list_artifacts(crate::DEFAULT_CASE).unwrap().is_empty());
        assert!(store.list_events(crate::DEFAULT_CASE).unwrap().is_empty());
        assert_eq!(store.verify_case_provenance(crate::DEFAULT_CASE).unwrap().verified_events,0);
    }

    #[test]
    fn batch_rejects_cross_case_duplicate_ids_and_tampered_members_without_writes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let case_dir = root.join(crate::DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let a = sample(&case_dir,"a",b"valid",crate::DEFAULT_CASE);
        let b = sample(&case_dir,"b",b"valid-two",crate::DEFAULT_CASE);
        let e = [ImportEvent {source:"archive",action:"extract",description:"parent:a"}];
        let dup = [ImportBatchItem {record:&a,events:&e,findings:&[]},
                   ImportBatchItem {record:&a,events:&e,findings:&[]}];
        assert!(store.commit_artifact_batch(&root,&dup).is_err());
        let mut other = b.clone();
        other.case_id = "missing-case".into();
        let mixed = [ImportBatchItem {record:&a,events:&e,findings:&[]},
                     ImportBatchItem {record:&other,events:&e,findings:&[]}];
        assert!(store.commit_artifact_batch(&root,&mixed).is_err());
        std::fs::write(&b.stored_path,b"tampered").unwrap();
        let corrupt = [ImportBatchItem {record:&a,events:&e,findings:&[]},
                       ImportBatchItem {record:&b,events:&e,findings:&[]}];
        assert!(store.commit_artifact_batch(&root,&corrupt).is_err());
        assert!(store.list_artifacts(crate::DEFAULT_CASE).unwrap().is_empty());
    }
}

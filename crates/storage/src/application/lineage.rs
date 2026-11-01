//! Versioned typed lineage carried by the existing immutable event chain.
//! No schema change or mutation of historical events.
use crate::{ArtifactStore, CaseEvent};
use rusqlite::params;
use serde::{Deserialize, Serialize};

const LINEAGE_SOURCE: &str = "cases.lineage.v1";
const MAX_LINEAGE_RETURN: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactLineageHop {
    pub version: u8,
    pub source_artifact_id: String,
    pub derived_artifact_id: String,
    pub offset: u64,
    pub format: String,
    pub item_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseLineageReport {
    pub case_id: String,
    pub hops: Vec<ArtifactLineageHop>,
    pub truncated: bool,
}

impl ArtifactStore {
    /// Append an authenticated provenance event for a parent/child pair.
    /// Both artifacts must already be indexed under the same selected case.
    pub fn record_artifact_lineage(
        &self,
        case_id: &str,
        parent_id: &str,
        derived_id: &str,
        offset: u64,
        format: &str,
        item_name: &str,
    ) -> Result<i64, String> {
        crate::validate_case_id(case_id)?;
        if parent_id == derived_id {
            return Err("artifact may not derive from itself".into());
        }
        if format.is_empty()
            || format.len() > 48
            || item_name.len() > 160
            || item_name.contains('\0')
        {
            return Err("invalid lineage metadata".into());
        }
        for id in [parent_id, derived_id] {
            let record = self
                .get_artifact(id)?
                .ok_or_else(|| "lineage artifact missing".to_string())?;
            if record.case_id != case_id {
                return Err("cross-case artifact lineage is not permitted".into());
            }
        }
        let hop = ArtifactLineageHop {
            version: 1,
            source_artifact_id: parent_id.to_owned(),
            derived_artifact_id: derived_id.to_owned(),
            offset,
            format: format.to_owned(),
            item_name: item_name.to_owned(),
        };
        let encoded =
            serde_json::to_string(&hop).map_err(|e| format!("cannot encode lineage hop: {e}"))?;
        if encoded.len() > 512 {
            return Err("lineage metadata exceeds provenance event limit".into());
        }
        self.record_event(
            case_id,
            LINEAGE_SOURCE,
            "derive",
            Some(derived_id),
            &encoded,
        )
    }

    /// Return bounded typed links from verified append-only provenance.
    /// Historical text events remain untouched and are not treated as links.
    pub fn list_artifact_lineage(&self, case_id: &str) -> Result<CaseLineageReport, String> {
        self.verify_case_provenance(case_id)?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,case_id,source,action,artifact_id,source_description,created_ms
             FROM case_events
             WHERE case_id=?1 AND source=?2 AND action='derive'
             ORDER BY id ASC LIMIT ?3",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![case_id, LINEAGE_SOURCE, (MAX_LINEAGE_RETURN + 1) as i64],
                |row| {
                    Ok(CaseEvent {
                        id: row.get(0)?,
                        case_id: row.get(1)?,
                        source: row.get(2)?,
                        action: row.get(3)?,
                        artifact_id: row.get(4)?,
                        source_description: row.get(5)?,
                        created_ms: row.get(6)?,
                    })
                },
            )
            .map_err(|e| e.to_string())?;
        let mut hops = Vec::new();
        for row in rows {
            let event = row.map_err(|e| e.to_string())?;
            if hops.len() == MAX_LINEAGE_RETURN {
                return Ok(CaseLineageReport {
                    case_id: case_id.to_owned(),
                    hops,
                    truncated: true,
                });
            }
            let hop: ArtifactLineageHop = serde_json::from_str(&event.source_description)
                .map_err(|e| format!("invalid typed lineage event {}: {e}", event.id))?;
            if hop.version != 1
                || event.artifact_id.as_deref() != Some(hop.derived_artifact_id.as_str())
            {
                return Err(format!("lineage event {} identity mismatch", event.id));
            }
            hops.push(hop);
        }
        Ok(CaseLineageReport {
            case_id: case_id.to_owned(),
            hops,
            truncated: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactRecord, DEFAULT_CASE};

    fn record(id: &str, case: &str) -> ArtifactRecord {
        ArtifactRecord {
            id: id.into(),
            case_id: case.into(),
            name: id.into(),
            stored_path: format!("/irrelevant/{id}"),
            original_path: None,
            size: 0,
            sha256: "a".repeat(64),
            md5: String::new(),
            sha1: String::new(),
            crc32: String::new(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        }
    }

    #[test]
    fn typed_lineage_preserves_case_and_verifiable_provenance_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite");
        let store = ArtifactStore::open(&db).unwrap();
        let other = store.create_case("Other", "").unwrap();
        store
            .upsert_artifact(&record("source", DEFAULT_CASE))
            .unwrap();
        store
            .upsert_artifact(&record("child", DEFAULT_CASE))
            .unwrap();
        store.upsert_artifact(&record("other", &other.id)).unwrap();
        assert!(store
            .record_artifact_lineage(DEFAULT_CASE, "source", "other", 7, "tar", "a")
            .is_err());
        assert!(store
            .record_artifact_lineage(DEFAULT_CASE, "source", "source", 0, "zip", "")
            .is_err());
        let event_id = store
            .record_artifact_lineage(DEFAULT_CASE, "source", "child", 42, "zip", "readme.txt")
            .unwrap();
        assert!(event_id > 0);
        let report = store.list_artifact_lineage(DEFAULT_CASE).unwrap();
        assert_eq!(report.hops.len(), 1);
        assert_eq!(report.hops[0].offset, 42);
        assert_eq!(report.hops[0].derived_artifact_id, "child");
        assert!(!report.truncated);
        assert!(store
            .list_artifact_lineage(&other.id)
            .unwrap()
            .hops
            .is_empty());
        assert_eq!(
            store
                .verify_case_provenance(DEFAULT_CASE)
                .unwrap()
                .verified_events,
            1
        );
        drop(store);
        let reopened = ArtifactStore::open(&db).unwrap();
        assert_eq!(
            reopened.list_artifact_lineage(DEFAULT_CASE).unwrap().hops,
            report.hops
        );
    }
}

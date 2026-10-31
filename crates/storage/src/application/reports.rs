//! Case reporting use case.
use crate::{case_report_manifest_digest, timestamp_ms, ArtifactStore, CaseReport, ReportArtifact};
use rusqlite::{params, OptionalExtension};

impl ArtifactStore {
    pub fn export_case_report(&self, case_id: &str) -> Result<CaseReport, String> {
        // Bounded indexed reads: do not materialize every case or every
        // artifact just to export a path-free 2000-item report.
        let case = self
            .conn
            .query_row(
                "SELECT id,title,description,created_ms FROM cases WHERE id=?1",
                rusqlite::params![case_id],
                |row| {
                    Ok(crate::CaseRecord {
                        id: row.get(0)?,
                        title: row.get(1)?,
                        description: row.get(2)?,
                        created_ms: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "case not found".to_string())?;
        let mut statement = self
            .conn
            .prepare(
                "SELECT id,name,size,sha256,signature,imported_at
             FROM artifacts WHERE case_id=?1 ORDER BY imported_at DESC LIMIT 2001",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![case_id], |row| {
                Ok(ReportArtifact {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    size: row.get::<_, i64>(2)?.max(0) as u64,
                    sha256: row.get(3)?,
                    signature: row.get(4)?,
                    imported_at: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut artifacts = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let mut truncated = artifacts.len() > 2000;
        artifacts.truncate(2000);
        artifacts.sort_by(|a: &ReportArtifact, b: &ReportArtifact| a.id.cmp(&b.id));
        let findings = self.list_findings(case_id)?;
        let events = self.list_events(case_id)?;
        let count_findings: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM findings WHERE case_id=?1",
                params![case_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        let count_events: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM case_events WHERE case_id=?1",
                params![case_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        truncated |= count_findings > 2000 || count_events > 2000;
        let provenance = self.verify_case_provenance(case_id)?;
        let mut report = CaseReport {
            schema_version: 2,
            manifest_sha256: String::new(),
            provenance,
            generated_ms: timestamp_ms(),
            case,
            artifacts,
            findings,
            events,
            truncated,
        };
        report.manifest_sha256 = case_report_manifest_digest(&report)?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_case_report_manifest, DEFAULT_CASE};
    use rusqlite::params;

    #[test]
    fn report_is_bounded_and_preserves_portable_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        for i in 0..2003_u32 {
            let id = format!("sample-{i:04}");
            store.conn.execute(
                "INSERT INTO artifacts
                (id,case_id,name,stored_path,original_path,size,sha256,md5,sha1,crc32,signature,entropy,imported_at)
                VALUES (?1,?2,?3,?4,NULL,1,?5,'','','',NULL,0.0,?6)",
                params![id, DEFAULT_CASE, id, "/host/private/source", id, i.to_string()],
            ).unwrap();
        }
        let report = store.export_case_report(DEFAULT_CASE).unwrap();
        assert_eq!(report.artifacts.len(), 2000);
        assert!(report.truncated);
        assert!(report.artifacts.iter().all(|item| item.id != "sample-0000"));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("/host/private/source"));
        verify_case_report_manifest(&report).unwrap();
    }
}

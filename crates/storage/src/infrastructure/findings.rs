//! SQLite persistence — extracted from legacy monolithic store without changing SQL or public signatures.
use crate::{timestamp_ms, ArtifactStore, FindingRecord, NewFinding};
use rusqlite::{params, OptionalExtension};

impl ArtifactStore {
    pub fn add_findings(
        &self,
        case_id: &str,
        source: &str,
        artifact_id: Option<&str>,
        findings: &[NewFinding],
    ) -> Result<usize, String> {
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        if source.trim().is_empty() || source.len() > 80 || findings.len() > 128 {
            return Err("invalid source or too many findings".into());
        }
        if let Some(id) = artifact_id {
            let existing_case: Option<String> = self
                .conn
                .query_row(
                    "SELECT case_id FROM artifacts WHERE id=?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if existing_case.as_deref() != Some(case_id) {
                return Err("artifact does not belong to the selected case".into());
            }
        }
        for f in findings {
            if f.title.is_empty()
                || f.title.len() > 200
                || f.details.len() > 8192
                || !matches!(
                    f.severity.as_str(),
                    "info" | "low" | "medium" | "high" | "critical"
                )
            {
                return Err("finding exceeds limits or has invalid severity".into());
            }
        }
        let now = timestamp_ms();
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("cannot start findings transaction: {e}"))?;
        for f in findings {
            transaction.execute(
                "INSERT INTO findings (case_id,source,title,severity,details,artifact_id,created_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![case_id,source,f.title,f.severity,f.details,artifact_id,now],
            ).map_err(|e| format!("cannot store finding: {e}"))?;
        }
        transaction
            .commit()
            .map_err(|e| format!("cannot commit findings: {e}"))?;
        Ok(findings.len())
    }

    pub fn list_findings(&self, case_id: &str) -> Result<Vec<FindingRecord>, String> {
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,case_id,source,title,severity,details,artifact_id,created_ms
             FROM findings WHERE case_id=?1 ORDER BY id DESC LIMIT 2000",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![case_id], |r| {
                Ok(FindingRecord {
                    id: r.get(0)?,
                    case_id: r.get(1)?,
                    source: r.get(2)?,
                    title: r.get(3)?,
                    severity: r.get(4)?,
                    details: r.get(5)?,
                    artifact_id: r.get(6)?,
                    created_ms: r.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

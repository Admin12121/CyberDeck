//! SQLite persistence.
use crate::{ArtifactRecord, ArtifactStore};
use rusqlite::{params, OptionalExtension};

pub(crate) fn artifact_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArtifactRecord> {
    Ok(ArtifactRecord {
        id: row.get(0)?,
        case_id: row.get(1)?,
        name: row.get(2)?,
        stored_path: row.get(3)?,
        original_path: row.get(4)?,
        size: row.get::<_, i64>(5)?.max(0) as u64,
        sha256: row.get(6)?,
        md5: row.get(7)?,
        sha1: row.get(8)?,
        crc32: row.get(9)?,
        signature: row.get(10)?,
        entropy: row.get(11)?,
        imported_at: row.get(12)?,
    })
}

impl ArtifactStore {
    /// Insert or replace by id (idempotent imports of identical content).
    pub fn upsert_artifact(&self, record: &ArtifactRecord) -> Result<(), String> {
        if !self.case_exists(&record.case_id)? {
            return Err("case not found".into());
        }
        let inserted = self
            .conn
            .execute(
                "INSERT INTO artifacts (id, case_id, name, stored_path, original_path, size,
                                        sha256, md5, sha1, crc32, signature, entropy, imported_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(id) DO NOTHING",
                params![
                    record.id,
                    record.case_id,
                    record.name,
                    record.stored_path,
                    record.original_path,
                    record.size,
                    record.sha256,
                    record.md5,
                    record.sha1,
                    record.crc32,
                    record.signature,
                    record.entropy,
                    record.imported_at,
                ],
            )
            .map_err(|e| format!("cannot persist artifact record: {e}"))?;
        if inserted == 0 {
            let existing = self
                .get_artifact(&record.id)?
                .ok_or_else(|| "conflicting artifact disappeared".to_string())?;
            if existing.case_id != record.case_id
                || existing.sha256 != record.sha256
                || existing.size != record.size
                || existing.stored_path != record.stored_path
            {
                return Err("artifact identifier conflicts with immutable evidence".into());
            }
        }
        Ok(())
    }

    pub fn list_artifacts(&self, case_id: &str) -> Result<Vec<ArtifactRecord>, String> {
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, case_id, name, stored_path, original_path, size,
                        sha256, md5, sha1, crc32, signature, entropy, imported_at
                 FROM artifacts WHERE case_id = ?1 ORDER BY imported_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![case_id], artifact_from_row)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Direct indexed lookup avoids scanning all evidence records across cases.
    pub fn get_artifact(&self, id: &str) -> Result<Option<ArtifactRecord>, String> {
        self.conn
            .query_row(
                "SELECT id,case_id,name,stored_path,original_path,size,
                        sha256,md5,sha1,crc32,signature,entropy,imported_at
                 FROM artifacts WHERE id=?1",
                params![id],
                artifact_from_row,
            )
            .optional()
            .map_err(|e| e.to_string())
    }
}

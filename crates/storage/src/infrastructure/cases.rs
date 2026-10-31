//! SQLite persistence — extracted from legacy monolithic store without changing SQL or public signatures.
use crate::{timestamp_ms, validate_case_id, ArtifactStore, CaseRecord};
use rusqlite::params;

impl ArtifactStore {
    pub fn list_cases(&self) -> Result<Vec<CaseRecord>, String> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id,title,description,created_ms FROM cases ORDER BY created_ms DESC,id",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok(CaseRecord {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    description: row.get(2)?,
                    created_ms: row.get(3)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn case_exists(&self, case_id: &str) -> Result<bool, String> {
        validate_case_id(case_id)?;
        self.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cases WHERE id=?1)",
                params![case_id],
                |r| r.get::<_, bool>(0),
            )
            .map_err(|e| e.to_string())
    }

    pub fn create_case(&self, title: &str, description: &str) -> Result<CaseRecord, String> {
        let title = title.trim();
        let description = description.trim();
        if title.is_empty() || title.len() > 120 || description.len() > 2048 {
            return Err("case title (1-120 bytes) or description (0-2048 bytes) is invalid".into());
        }
        // SQLite rejects ID collisions, even if calls occur in the same nanosecond.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let case = CaseRecord {
            id: format!("case-{nanos:x}-{:x}", std::process::id()),
            title: title.to_string(),
            description: description.to_string(),
            created_ms: timestamp_ms(),
        };
        self.conn
            .execute(
                "INSERT INTO cases (id,title,description,created_ms) VALUES (?1,?2,?3,?4)",
                params![case.id, case.title, case.description, case.created_ms],
            )
            .map_err(|e| format!("cannot create case: {e}"))?;
        Ok(case)
    }
}

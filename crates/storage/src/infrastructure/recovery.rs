//! SQLite persistence.
use crate::{ArtifactStore, CrackEntry};
use rusqlite::params;

impl ArtifactStore {
    // --- crack history: recovered pairs persist until the user deletes them ---

    /// Insert a recovered pair; duplicates (same hash + password) are ignored.
    pub fn add_crack_entry(
        &self,
        algo: &str,
        hash: &str,
        password: &str,
        engine: &str,
        wordlist: Option<&str>,
    ) -> Result<(), String> {
        let recovered_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string());
        self.conn
            .execute(
                "INSERT OR IGNORE INTO crack_history (algo, hash, password, engine, wordlist, recovered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![algo, hash, password, engine, wordlist, recovered_at],
            )
            .map_err(|e| format!("cannot persist crack history entry: {e}"))?;
        Ok(())
    }

    pub fn list_crack_entries(&self) -> Result<Vec<CrackEntry>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, algo, hash, password, engine, wordlist, recovered_at
                 FROM crack_history ORDER BY id DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(CrackEntry {
                    id: row.get(0)?,
                    algo: row.get(1)?,
                    hash: row.get(2)?,
                    password: row.get(3)?,
                    engine: row.get(4)?,
                    wordlist: row.get(5)?,
                    recovered_at: row.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn delete_crack_entry(&self, id: i64) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM crack_history WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn clear_crack_entries(&self) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM crack_history", [])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

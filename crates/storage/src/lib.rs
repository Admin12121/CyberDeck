//! SQLite artifact index (§8.4); artifact bytes live in the case directory.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CASE: &str = "scratchpad";

/// One imported evidence file. The record is the index entry; `stored_path`
/// points into the case artifact directory where the original bytes live
/// immutably.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub stored_path: String,
    pub original_path: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub crc32: String,
    pub signature: Option<String>,
    pub entropy: f64,
    pub imported_at: String,
}

pub struct ArtifactStore {
    conn: Connection,
}

impl ArtifactStore {
    /// Open (creating if needed) the index database at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("cannot create store directory: {e}"))?;
        }
        let conn = Connection::open(path).map_err(|e| format!("cannot open artifact index: {e}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS artifacts (
                 id            TEXT PRIMARY KEY,
                 case_id       TEXT NOT NULL,
                 name          TEXT NOT NULL,
                 stored_path   TEXT NOT NULL,
                 original_path TEXT,
                 size          INTEGER NOT NULL,
                 sha256        TEXT NOT NULL,
                 md5           TEXT NOT NULL,
                 sha1          TEXT NOT NULL,
                 crc32         TEXT NOT NULL,
                 signature     TEXT,
                 entropy       REAL NOT NULL,
                 imported_at   TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
             CREATE TABLE IF NOT EXISTS crack_history (
                 id           INTEGER PRIMARY KEY AUTOINCREMENT,
                 algo         TEXT NOT NULL,
                 hash         TEXT NOT NULL,
                 password     TEXT NOT NULL,
                 engine       TEXT NOT NULL,
                 wordlist     TEXT,
                 recovered_at TEXT NOT NULL,
                 UNIQUE(hash, password)
             );",
        )
        .map_err(|e| format!("cannot initialize artifact index: {e}"))?;
        Ok(Self { conn })
    }

    /// Insert or replace by id (idempotent imports of identical content).
    pub fn upsert_artifact(&self, record: &ArtifactRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO artifacts (id, case_id, name, stored_path, original_path, size,
                                        sha256, md5, sha1, crc32, signature, entropy, imported_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(id) DO UPDATE SET
                    case_id=excluded.case_id, name=excluded.name, stored_path=excluded.stored_path,
                    original_path=excluded.original_path, size=excluded.size, sha256=excluded.sha256,
                    md5=excluded.md5, sha1=excluded.sha1, crc32=excluded.crc32,
                    signature=excluded.signature, entropy=excluded.entropy, imported_at=excluded.imported_at",
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
        Ok(())
    }

    pub fn list_artifacts(&self, case_id: &str) -> Result<Vec<ArtifactRecord>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, case_id, name, stored_path, original_path, size,
                        sha256, md5, sha1, crc32, signature, entropy, imported_at
                 FROM artifacts WHERE case_id = ?1 ORDER BY imported_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![case_id], |row| {
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
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn get_artifact(&self, id: &str) -> Result<Option<ArtifactRecord>, String> {
        Ok(self
            .list_all()?
            .into_iter()
            .find(|record| record.id == id))
    }

    fn list_all(&self) -> Result<Vec<ArtifactRecord>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, case_id, name, stored_path, original_path, size,
                        sha256, md5, sha1, crc32, signature, entropy, imported_at
                 FROM artifacts",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
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
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

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
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
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

/// One successfully recovered pair, kept until the user deletes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackEntry {
    pub id: i64,
    pub algo: String,
    pub hash: String,
    pub password: String,
    pub engine: String,
    pub wordlist: Option<String>,
    pub recovered_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> ArtifactRecord {
        ArtifactRecord {
            id: id.to_string(),
            case_id: DEFAULT_CASE.to_string(),
            name: format!("{id}.txt"),
            stored_path: format!("/store/{id}.txt"),
            original_path: Some(format!("/orig/{id}.txt")),
            size: 128,
            sha256: "deadbeef".into(),
            md5: "00".into(),
            sha1: "11".into(),
            crc32: "cbf43926".into(),
            signature: Some("ASCII text".into()),
            entropy: 4.2,
            imported_at: "2026-10-31T00:00:00Z".into(),
        }
    }

    #[test]
    fn upsert_and_list_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store.upsert_artifact(&record("a1")).unwrap();
        store.upsert_artifact(&record("a2")).unwrap();
        let list = store.list_artifacts(DEFAULT_CASE).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|r| r.case_id == DEFAULT_CASE));
    }

    #[test]
    fn upsert_same_id_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store.upsert_artifact(&record("a1")).unwrap();
        let mut updated = record("a1");
        updated.size = 999;
        store.upsert_artifact(&updated).unwrap();
        let list = store.list_artifacts(DEFAULT_CASE).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].size, 999);
    }

    #[test]
    fn get_artifact_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store.upsert_artifact(&record("xyz")).unwrap();
        assert!(store.get_artifact("xyz").unwrap().is_some());
        assert!(store.get_artifact("missing").unwrap().is_none());
    }

    #[test]
    fn reopens_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.db");
        {
            let store = ArtifactStore::open(&path).unwrap();
            store.upsert_artifact(&record("keep")).unwrap();
        }
        let reopened = ArtifactStore::open(&path).unwrap();
        assert_eq!(reopened.list_artifacts(DEFAULT_CASE).unwrap().len(), 1);
    }

    #[test]
    fn crack_history_roundtrip_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store.add_crack_entry("md5", "aaa", "hello", "native", Some("rockyou.txt")).unwrap();
        store.add_crack_entry("md5", "aaa", "hello", "native", Some("rockyou.txt")).unwrap();
        store.add_crack_entry("sha256", "bbb", "world", "hashcat", None).unwrap();
        let list = store.list_crack_entries().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].password, "world"); // newest first
        assert!(list[1].wordlist.as_deref() == Some("rockyou.txt"));
    }

    #[test]
    fn crack_history_delete_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store.add_crack_entry("md5", "a", "x", "native", None).unwrap();
        store.add_crack_entry("md5", "b", "y", "native", None).unwrap();
        let id = store.list_crack_entries().unwrap()[0].id;
        store.delete_crack_entry(id).unwrap();
        assert_eq!(store.list_crack_entries().unwrap().len(), 1);
        store.clear_crack_entries().unwrap();
        assert!(store.list_crack_entries().unwrap().is_empty());
    }
}

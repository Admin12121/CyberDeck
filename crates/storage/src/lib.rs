//! SQLite artifact index (§8.4); artifact bytes live in the case directory.

use rusqlite::{params, Connection, OptionalExtension};
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

/// A project/case owns evidence and analysis findings; scratchpad remains the
/// default for existing imports made before case management existed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub id: String,
    pub title: String,
    pub description: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: i64,
    pub case_id: String,
    pub source: String,
    pub title: String,
    pub severity: String,
    pub details: String,
    pub artifact_id: Option<String>,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFinding {
    pub title: String,
    pub severity: String,
    pub details: String,
}

/// Structured provenance is deliberately append-only at the application API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEvent {
    pub id: i64,
    pub case_id: String,
    pub source: String,
    pub action: String,
    pub artifact_id: Option<String>,
    pub source_description: String,
    pub created_ms: i64,
}

/// A portable case report includes no host-local paths or copied evidence bytes.
#[derive(Debug, Serialize)]
pub struct ReportArtifact {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub signature: Option<String>,
    pub imported_at: String,
}

#[derive(Debug, Serialize)]
pub struct CaseReport {
    pub schema_version: u8,
    pub generated_ms: i64,
    pub case: CaseRecord,
    pub artifacts: Vec<ReportArtifact>,
    pub findings: Vec<FindingRecord>,
    pub events: Vec<CaseEvent>,
    pub truncated: bool,
}

pub fn validate_case_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 100
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid case identifier".to_string());
    }
    Ok(())
}

fn timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct ArtifactStore {
    conn: Connection,
}

impl ArtifactStore {
    /// Open (creating if needed) the index database at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create store directory: {e}"))?;
        }
        let conn =
            Connection::open(path).map_err(|e| format!("cannot open artifact index: {e}"))?;
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
             CREATE TABLE IF NOT EXISTS cases (
                 id         TEXT PRIMARY KEY,
                 title      TEXT NOT NULL,
                 description TEXT NOT NULL,
                 created_ms INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO cases (id,title,description,created_ms)
                 VALUES ('scratchpad','Scratchpad','Default working case',0);
             CREATE TABLE IF NOT EXISTS findings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 case_id TEXT NOT NULL REFERENCES cases(id),
                 source TEXT NOT NULL,
                 title TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 details TEXT NOT NULL,
                 artifact_id TEXT,
                 created_ms INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id,id);
             CREATE TABLE IF NOT EXISTS case_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 case_id TEXT NOT NULL REFERENCES cases(id),
                 source TEXT NOT NULL,
                 action TEXT NOT NULL,
                 artifact_id TEXT,
                 source_description TEXT NOT NULL,
                 created_ms INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_events_case ON case_events(case_id,id);
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
        for f in findings {
            self.conn.execute(
                "INSERT INTO findings (case_id,source,title,severity,details,artifact_id,created_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![case_id,source,f.title,f.severity,f.details,artifact_id,now],
            ).map_err(|e| format!("cannot store finding: {e}"))?;
        }
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

    /// Store one small provenance event, retaining operation/source linkage.
    /// Callers must not put passwords, session tokens or captured bodies here.
    pub fn record_event(
        &self,
        case_id: &str,
        source: &str,
        action: &str,
        artifact_id: Option<&str>,
        source_description: &str,
    ) -> Result<i64, String> {
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        if source.is_empty()
            || source.len() > 80
            || action.is_empty()
            || action.len() > 60
            || source_description.len() > 512
        {
            return Err("invalid event metadata length".into());
        }
        if let Some(id) = artifact_id {
            let linked_case: Option<String> = self
                .conn
                .query_row(
                    "SELECT case_id FROM artifacts WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if linked_case.as_deref() != Some(case_id) {
                return Err("event artifact belongs to another case or is missing".into());
            }
        }
        self.conn.execute(
            "INSERT INTO case_events (case_id,source,action,artifact_id,source_description,created_ms)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![case_id,source,action,artifact_id,source_description,timestamp_ms()],
        ).map_err(|e| format!("cannot store event: {e}"))?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_events(&self, case_id: &str) -> Result<Vec<CaseEvent>, String> {
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,case_id,source,action,artifact_id,source_description,created_ms
             FROM case_events WHERE case_id=?1 ORDER BY id DESC LIMIT 2000",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![case_id], |row| {
                Ok(CaseEvent {
                    id: row.get(0)?,
                    case_id: row.get(1)?,
                    source: row.get(2)?,
                    action: row.get(3)?,
                    artifact_id: row.get(4)?,
                    source_description: row.get(5)?,
                    created_ms: row.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn export_case_report(&self, case_id: &str) -> Result<CaseReport, String> {
        let case = self
            .list_cases()?
            .into_iter()
            .find(|item| item.id == case_id)
            .ok_or_else(|| "case not found".to_string())?;
        let mut all_artifacts = self.list_artifacts(case_id)?;
        let mut truncated = all_artifacts.len() > 2000;
        all_artifacts.truncate(2000);
        let artifacts = all_artifacts
            .into_iter()
            .map(|a| ReportArtifact {
                id: a.id,
                name: a.name,
                size: a.size,
                sha256: a.sha256,
                signature: a.signature,
                imported_at: a.imported_at,
            })
            .collect();
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
        Ok(CaseReport {
            schema_version: 1,
            generated_ms: timestamp_ms(),
            case,
            artifacts,
            findings,
            events,
            truncated,
        })
    }

    /// Insert or replace by id (idempotent imports of identical content).
    pub fn upsert_artifact(&self, record: &ArtifactRecord) -> Result<(), String> {
        if !self.case_exists(&record.case_id)? {
            return Err("case not found".into());
        }
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
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn get_artifact(&self, id: &str) -> Result<Option<ArtifactRecord>, String> {
        Ok(self.list_all()?.into_iter().find(|record| record.id == id))
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
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
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
    fn provenance_and_reports_remain_case_scoped_without_local_paths() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        let alpha = store.create_case("Alpha", "report").unwrap();
        let beta = store.create_case("Beta", "separate").unwrap();
        let mut evidence = record("file1");
        evidence.case_id = alpha.id.clone();
        evidence.stored_path = "/secrets/home/analyst/file".into();
        evidence.original_path = Some("/private/input".into());
        store.upsert_artifact(&evidence).unwrap();
        assert!(store
            .record_event(&beta.id, "recipes", "derived", Some("file1"), "wrong")
            .is_err());
        store
            .record_event(&alpha.id, "recipes", "derived", Some("file1"), "packet 8")
            .unwrap();
        store
            .add_findings(
                &alpha.id,
                "crypto.recipes",
                Some("file1"),
                &[NewFinding {
                    title: "Sample".into(),
                    severity: "info".into(),
                    details: "Decoded sample".into(),
                }],
            )
            .unwrap();
        let report = store.export_case_report(&alpha.id).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("packet 8"));
        assert!(json.contains("file1"));
        assert!(!json.contains("/secrets/home"));
        assert!(!json.contains("/private/input"));
        assert!(store
            .export_case_report(&beta.id)
            .unwrap()
            .artifacts
            .is_empty());
        drop(store);
        let reopened = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        assert_eq!(reopened.list_events(&alpha.id).unwrap().len(), 1);
    }

    #[test]
    fn creates_cases_and_persists_case_scoped_findings() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("index.db");
        let store = ArtifactStore::open(&db).unwrap();
        let a = store.create_case("Lab A", "Private practice").unwrap();
        let b = store.create_case("Lab B", "").unwrap();
        assert_ne!(a.id, b.id);
        assert!(store.case_exists(DEFAULT_CASE).unwrap());
        let mut evidence = record("artifact-a");
        evidence.case_id = a.id.clone();
        store.upsert_artifact(&evidence).unwrap();
        assert_eq!(store.list_artifacts(&a.id).unwrap().len(), 1);
        assert!(store.list_artifacts(&b.id).unwrap().is_empty());
        assert!(store
            .add_findings(
                &b.id,
                "scan",
                Some(&evidence.id),
                &[NewFinding {
                    title: "Example".into(),
                    severity: "low".into(),
                    details: "Test".into()
                }]
            )
            .is_err());
        assert_eq!(
            store
                .add_findings(
                    &a.id,
                    "scan",
                    Some(&evidence.id),
                    &[NewFinding {
                        title: "Example".into(),
                        severity: "low".into(),
                        details: "Test".into()
                    }]
                )
                .unwrap(),
            1
        );
        assert_eq!(store.list_findings(&a.id).unwrap().len(), 1);
        drop(store);
        let reopened = ArtifactStore::open(&db).unwrap();
        assert_eq!(reopened.list_cases().unwrap().len(), 3);
        assert_eq!(reopened.list_findings(&a.id).unwrap().len(), 1);
        assert!(reopened.list_findings(&b.id).unwrap().is_empty());
    }

    #[test]
    fn refuses_invalid_case_identifier_and_finding() {
        assert!(validate_case_id("../escape").is_err());
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        assert!(store.create_case("   ", "").is_err());
        assert!(store
            .add_findings(
                DEFAULT_CASE,
                "web",
                None,
                &[NewFinding {
                    title: "Invalid".into(),
                    severity: "unknown".into(),
                    details: "ignored".into()
                }]
            )
            .is_err());
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
        store
            .add_crack_entry("md5", "aaa", "hello", "native", Some("rockyou.txt"))
            .unwrap();
        store
            .add_crack_entry("md5", "aaa", "hello", "native", Some("rockyou.txt"))
            .unwrap();
        store
            .add_crack_entry("sha256", "bbb", "world", "hashcat", None)
            .unwrap();
        let list = store.list_crack_entries().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].password, "world"); // newest first
        assert!(list[1].wordlist.as_deref() == Some("rockyou.txt"));
    }

    #[test]
    fn crack_history_delete_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store
            .add_crack_entry("md5", "a", "x", "native", None)
            .unwrap();
        store
            .add_crack_entry("md5", "b", "y", "native", None)
            .unwrap();
        let id = store.list_crack_entries().unwrap()[0].id;
        store.delete_crack_entry(id).unwrap();
        assert_eq!(store.list_crack_entries().unwrap().len(), 1);
        store.clear_crack_entries().unwrap();
        assert!(store.list_crack_entries().unwrap().is_empty());
    }
}

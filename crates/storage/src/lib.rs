//! SQLite artifact index (§8.4); artifact bytes live in the case directory.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod batch;
pub use batch::ImportBatchItem;
mod case_integrity;
mod ingest;
pub use case_integrity::CaseIntegritySummary;
pub use ingest::ImportEvent;
mod integrity;
pub use integrity::{verify_artifact_file, GENESIS_HASH};

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
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportArtifact {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub signature: Option<String>,
    pub imported_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseReport {
    pub schema_version: u8,
    pub manifest_sha256: String,
    pub provenance: ProvenanceVerification,
    pub generated_ms: i64,
    pub case: CaseRecord,
    pub artifacts: Vec<ReportArtifact>,
    pub findings: Vec<FindingRecord>,
    pub events: Vec<CaseEvent>,
    pub truncated: bool,
}

/// Unkeyed integrity chain; retain its head externally to detect wholesale DB rewrites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceVerification {
    pub verified_events: usize,
    pub head_sha256: String,
}

/// Recompute a portable report's digest over all fields except the digest
/// itself. Preserve the returned digest independently.
pub fn case_report_manifest_digest(report: &CaseReport) -> Result<String, String> {
    let payload = serde_json::to_vec(&(
        report.schema_version,
        report.generated_ms,
        &report.case,
        &report.artifacts,
        &report.findings,
        &report.events,
        &report.provenance,
        report.truncated,
    ))
    .map_err(|e| format!("cannot serialize case manifest: {e}"))?;
    let mut digest = Sha256::new();
    digest.update(b"cyberdeck.case-report.v2\0");
    digest.update(payload);
    Ok(format!("{:x}", digest.finalize()))
}

pub fn verify_case_report_manifest(report: &CaseReport) -> Result<(), String> {
    let calculated = case_report_manifest_digest(report)?;
    if calculated != report.manifest_sha256 {
        return Err("case report manifest SHA-256 mismatch".into());
    }
    Ok(())
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
        let mut conn =
            Connection::open(path).map_err(|e| format!("cannot open artifact index: {e}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| format!("cannot configure artifact index: {e}"))?;
        const SCHEMA_VERSION: i64 = 2;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| format!("cannot read artifact index version: {e}"))?;
        if version > SCHEMA_VERSION {
            return Err(format!(
                "artifact index schema {version} is newer than supported {SCHEMA_VERSION}"
            ));
        }
        if version < 1 {
            let migration = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| format!("cannot begin artifact index migration: {e}"))?;
            migration
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS artifacts (
                 id            TEXT PRIMARY KEY,
                 case_id       TEXT NOT NULL REFERENCES cases(id),
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
            // Trigger guards also protect legacy tables which lack artifact foreign keys.
            migration.execute_batch(r#"
                CREATE TRIGGER IF NOT EXISTS artifact_case_insert BEFORE INSERT ON artifacts
                WHEN NOT EXISTS(SELECT 1 FROM cases WHERE id=NEW.case_id)
                BEGIN SELECT RAISE(ABORT,'artifact case missing'); END;
                CREATE TRIGGER IF NOT EXISTS artifact_case_update BEFORE UPDATE OF case_id ON artifacts
                WHEN NOT EXISTS(SELECT 1 FROM cases WHERE id=NEW.case_id)
                BEGIN SELECT RAISE(ABORT,'artifact case missing'); END;
                CREATE TRIGGER IF NOT EXISTS artifact_identity_immutable BEFORE UPDATE ON artifacts
                WHEN NEW.id!=OLD.id OR NEW.case_id!=OLD.case_id OR NEW.sha256!=OLD.sha256
                  OR NEW.size!=OLD.size OR NEW.stored_path!=OLD.stored_path
                BEGIN SELECT RAISE(ABORT,'artifact identity immutable'); END;
                CREATE TRIGGER IF NOT EXISTS finding_artifact_scope BEFORE INSERT ON findings
                WHEN NEW.artifact_id IS NOT NULL AND NOT EXISTS
                    (SELECT 1 FROM artifacts WHERE id=NEW.artifact_id AND case_id=NEW.case_id)
                BEGIN SELECT RAISE(ABORT,'finding artifact case mismatch'); END;
                CREATE TRIGGER IF NOT EXISTS event_artifact_scope BEFORE INSERT ON case_events
                WHEN NEW.artifact_id IS NOT NULL AND NOT EXISTS
                    (SELECT 1 FROM artifacts WHERE id=NEW.artifact_id AND case_id=NEW.case_id)
                BEGIN SELECT RAISE(ABORT,'event artifact case mismatch'); END;
                CREATE TRIGGER IF NOT EXISTS event_immutable_update BEFORE UPDATE ON case_events
                BEGIN SELECT RAISE(ABORT,'provenance immutable'); END;
                CREATE TRIGGER IF NOT EXISTS event_immutable_delete BEFORE DELETE ON case_events
                BEGIN SELECT RAISE(ABORT,'provenance immutable'); END;
                PRAGMA user_version = 1;
            "#).map_err(|e| format!("cannot migrate artifact index: {e}"))?;
            migration
                .commit()
                .map_err(|e| format!("cannot commit artifact index migration: {e}"))?;
        }
        if version < 2 {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| format!("cannot start provenance migration: {e}"))?;
            tx.execute_batch(r#"
                CREATE TABLE IF NOT EXISTS case_event_integrity (
                    event_id INTEGER PRIMARY KEY REFERENCES case_events(id),
                    case_id TEXT NOT NULL REFERENCES cases(id),
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_event_integrity_case
                    ON case_event_integrity(case_id,event_id);
                CREATE TRIGGER IF NOT EXISTS event_integrity_update BEFORE UPDATE ON case_event_integrity
                    BEGIN SELECT RAISE(ABORT,'integrity hashes are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS event_integrity_delete BEFORE DELETE ON case_event_integrity
                    BEGIN SELECT RAISE(ABORT,'integrity hashes are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS event_integrity_scope BEFORE INSERT ON case_event_integrity
                    WHEN NOT EXISTS(SELECT 1 FROM case_events WHERE id=NEW.event_id AND case_id=NEW.case_id)
                    BEGIN SELECT RAISE(ABORT,'integrity case mismatch'); END;
            "#).map_err(|e| format!("cannot create provenance table: {e}"))?;
            // Historical events are hashed once; older databases keep their file paths.
            let events: Vec<CaseEvent> =
                {
                    let mut stmt = tx.prepare(
                    "SELECT id,case_id,source,action,artifact_id,source_description,created_ms
                     FROM case_events ORDER BY case_id,id"
                ).map_err(|e| e.to_string())?;
                    let rows = stmt
                        .query_map([], |r| {
                            Ok(CaseEvent {
                                id: r.get(0)?,
                                case_id: r.get(1)?,
                                source: r.get(2)?,
                                action: r.get(3)?,
                                artifact_id: r.get(4)?,
                                source_description: r.get(5)?,
                                created_ms: r.get(6)?,
                            })
                        })
                        .map_err(|e| e.to_string())?;
                    rows.collect::<Result<Vec<_>, _>>()
                        .map_err(|e| e.to_string())?
                };
            let mut heads = std::collections::HashMap::<String, String>::new();
            for event in events {
                let previous = heads
                    .get(&event.case_id)
                    .map(String::as_str)
                    .unwrap_or(GENESIS_HASH);
                let digest = integrity::event_hash(&event, previous);
                tx.execute(
                    "INSERT INTO case_event_integrity(event_id,case_id,previous_hash,event_hash)
                     VALUES (?1,?2,?3,?4)",
                    params![event.id, event.case_id, previous, digest],
                )
                .map_err(|e| format!("cannot backfill provenance: {e}"))?;
                heads.insert(event.case_id, digest);
            }
            tx.execute_batch("PRAGMA user_version = 2;")
                .map_err(|e| format!("cannot set provenance schema version: {e}"))?;
            tx.commit()
                .map_err(|e| format!("cannot commit provenance migration: {e}"))?;
        }
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

    /// Store one small provenance event, retaining operation/source linkage.
    /// Callers must not put passwords, session tokens or captured bodies here.
    /// Verify the full unkeyed per-case hash chain, not only the latest event.
    pub fn verify_case_provenance(&self, case_id: &str) -> Result<ProvenanceVerification, String> {
        if !self.case_exists(case_id)? {
            return Err("case not found".into());
        }
        let mut stmt = self.conn.prepare(
            "SELECT e.id,e.case_id,e.source,e.action,e.artifact_id,e.source_description,e.created_ms,
                    h.previous_hash,h.event_hash
             FROM case_events e LEFT JOIN case_event_integrity h ON e.id=h.event_id
             WHERE e.case_id=?1 ORDER BY e.id ASC"
        ).map_err(|e| e.to_string())?;
        let records = stmt
            .query_map(params![case_id], |r| {
                Ok((
                    CaseEvent {
                        id: r.get(0)?,
                        case_id: r.get(1)?,
                        source: r.get(2)?,
                        action: r.get(3)?,
                        artifact_id: r.get(4)?,
                        source_description: r.get(5)?,
                        created_ms: r.get(6)?,
                    },
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut last = GENESIS_HASH.to_string();
        let mut count = 0_usize;
        for item in records {
            let (event, previous, hash) = item.map_err(|e| e.to_string())?;
            let calculated = integrity::event_hash(&event, &last);
            if previous.as_deref() != Some(last.as_str())
                || hash.as_deref() != Some(calculated.as_str())
            {
                return Err(format!(
                    "provenance integrity failure at event {}",
                    event.id
                ));
            }
            last = calculated;
            count += 1;
        }
        Ok(ProvenanceVerification {
            verified_events: count,
            head_sha256: last,
        })
    }

    /// Check the selected case, path containment, length and actual SHA-256.
    pub fn verify_artifact(
        &self,
        case_id: &str,
        artifact_id: &str,
        artifacts_root: &std::path::Path,
    ) -> Result<(), String> {
        validate_case_id(case_id)?;
        let record = self
            .get_artifact(artifact_id)?
            .filter(|r| r.case_id == case_id)
            .ok_or_else(|| "artifact not found in selected case".to_string())?;
        integrity::verify_artifact_file(&record, artifacts_root)
    }

    /// Append event and hash together. A failed hash write rolls back the event.
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
            let owner: Option<String> = self
                .conn
                .query_row(
                    "SELECT case_id FROM artifacts WHERE id=?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if owner.as_deref() != Some(case_id) {
                return Err("event artifact belongs to another case or is missing".into());
            }
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("cannot begin provenance transaction: {e}"))?;
        let last_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM case_events WHERE case_id=?1 ORDER BY id DESC LIMIT 1",
                params![case_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let head: Option<(i64, String)> = tx
            .query_row(
                "SELECT event_id,event_hash FROM case_event_integrity
             WHERE case_id=?1 ORDER BY event_id DESC LIMIT 1",
                params![case_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if last_id != head.as_ref().map(|(id, _)| *id) {
            return Err("provenance chain is missing event records".into());
        }
        let previous = head
            .map(|(_, hash)| hash)
            .unwrap_or_else(|| GENESIS_HASH.into());
        let now = timestamp_ms();
        tx.execute(
            "INSERT INTO case_events(case_id,source,action,artifact_id,source_description,created_ms)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![case_id,source,action,artifact_id,source_description,now],
        ).map_err(|e| format!("cannot store event: {e}"))?;
        let id = tx.last_insert_rowid();
        let event = CaseEvent {
            id,
            case_id: case_id.to_string(),
            source: source.to_string(),
            action: action.to_string(),
            artifact_id: artifact_id.map(str::to_string),
            source_description: source_description.to_string(),
            created_ms: now,
        };
        let event_hash = integrity::event_hash(&event, &previous);
        tx.execute(
            "INSERT INTO case_event_integrity(event_id,case_id,previous_hash,event_hash)
             VALUES (?1,?2,?3,?4)",
            params![id, case_id, previous, event_hash],
        )
        .map_err(|e| format!("cannot store event hash: {e}"))?;
        tx.commit()
            .map_err(|e| format!("cannot commit provenance event: {e}"))?;
        Ok(id)
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
        let mut artifacts = all_artifacts
            .into_iter()
            .map(|a| ReportArtifact {
                id: a.id,
                name: a.name,
                size: a.size,
                sha256: a.sha256,
                signature: a.signature,
                imported_at: a.imported_at,
            })
            .collect::<Vec<_>>();
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

    /// Direct indexed lookup avoids scanning all evidence records across cases.
    pub fn get_artifact(&self, id: &str) -> Result<Option<ArtifactRecord>, String> {
        self.conn
            .query_row(
                "SELECT id,case_id,name,stored_path,original_path,size,
                        sha256,md5,sha1,crc32,signature,entropy,imported_at
                 FROM artifacts WHERE id=?1",
                params![id],
                |row| {
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
                },
            )
            .optional()
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
    fn upsert_same_id_is_idempotent_but_never_replaces_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store.upsert_artifact(&record("a1")).unwrap();
        store.upsert_artifact(&record("a1")).unwrap();
        let mut updated = record("a1");
        updated.size = 999;
        assert!(store.upsert_artifact(&updated).is_err());
        let list = store.list_artifacts(DEFAULT_CASE).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].size, 128);
        assert!(store
            .conn
            .execute("UPDATE artifacts SET sha256='modified' WHERE id='a1'", [])
            .is_err());
    }

    #[test]
    fn migration_preserves_legacy_index_and_enforces_cases() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("index.db");
        {
            let legacy = Connection::open(&db).unwrap();
            legacy.execute_batch(
                "CREATE TABLE artifacts (
                    id TEXT PRIMARY KEY, case_id TEXT NOT NULL, name TEXT NOT NULL,
                    stored_path TEXT NOT NULL, original_path TEXT, size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL, md5 TEXT NOT NULL, sha1 TEXT NOT NULL,
                    crc32 TEXT NOT NULL, signature TEXT, entropy REAL NOT NULL,
                    imported_at TEXT NOT NULL
                 );
                 INSERT INTO artifacts VALUES
                    ('legacy','scratchpad','old.bin','/old/path',NULL,1,'aa','bb','cc','dd',NULL,0.0,'old');"
            ).unwrap();
        }
        let store = ArtifactStore::open(&db).unwrap();
        assert_eq!(
            store.get_artifact("legacy").unwrap().unwrap().stored_path,
            "/old/path"
        );
        let v: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2);
        assert!(store.conn.execute("INSERT INTO artifacts SELECT 'orphan','not-a-case',name,stored_path,original_path,size,sha256,md5,sha1,crc32,signature,entropy,imported_at FROM artifacts WHERE id='legacy'", []).is_err());
        assert!(store
            .conn
            .execute(
                "UPDATE artifacts SET case_id='not-a-case' WHERE id='legacy'",
                []
            )
            .is_err());
        drop(store);
        assert!(ArtifactStore::open(&db).is_ok());
    }

    #[test]
    fn failed_finding_batch_rolls_back_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_test BEFORE INSERT ON findings
             WHEN NEW.title='reject' BEGIN SELECT RAISE(ABORT,'test rejection'); END;",
            )
            .unwrap();
        let result = store.add_findings(
            DEFAULT_CASE,
            "test",
            None,
            &[
                NewFinding {
                    title: "ok".into(),
                    severity: "info".into(),
                    details: "one".into(),
                },
                NewFinding {
                    title: "reject".into(),
                    severity: "info".into(),
                    details: "two".into(),
                },
            ],
        );
        assert!(result.is_err());
        assert!(store.list_findings(DEFAULT_CASE).unwrap().is_empty());
    }

    #[test]
    fn provenance_events_are_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        let id = store
            .record_event(DEFAULT_CASE, "test", "import", None, "source")
            .unwrap();
        assert!(store
            .conn
            .execute(
                "UPDATE case_events SET action='edited' WHERE id=?1",
                params![id]
            )
            .is_err());
        assert!(store
            .conn
            .execute("DELETE FROM case_events WHERE id=?1", params![id])
            .is_err());
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
    fn verify_artifact_streams_bytes_and_checks_case_containment() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("artifacts");
        let case_dir = root.join(DEFAULT_CASE);
        std::fs::create_dir_all(&case_dir).unwrap();
        let stored = case_dir.join("evidence.bin");
        let content = vec![0x42u8; 200_000];
        std::fs::write(&stored, &content).unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        let mut evidence = record("verify");
        evidence.stored_path = stored.to_string_lossy().into_owned();
        evidence.size = content.len() as u64;
        evidence.sha256 = format!("{:x}", Sha256::digest(&content));
        store.upsert_artifact(&evidence).unwrap();
        store
            .verify_artifact(DEFAULT_CASE, "verify", &root)
            .unwrap();
        std::fs::write(&stored, vec![0x43u8; content.len()]).unwrap();
        assert!(store
            .verify_artifact(DEFAULT_CASE, "verify", &root)
            .is_err());
        std::fs::write(&stored, &content).unwrap();
        let other = store.create_case("Other", "").unwrap();
        let other_dir = root.join(&other.id);
        std::fs::create_dir_all(&other_dir).unwrap();
        let out_of_scope = other_dir.join("copied.bin");
        std::fs::write(&out_of_scope, &content).unwrap();
        let mut cross = evidence;
        cross.id = "wrong-case-file".into();
        cross.stored_path = out_of_scope.to_string_lossy().into_owned();
        store.upsert_artifact(&cross).unwrap();
        assert!(store
            .verify_artifact(DEFAULT_CASE, &cross.id, &root)
            .is_err());
    }

    #[test]
    fn provenance_chain_detects_unauthorized_insert() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store
            .record_event(DEFAULT_CASE, "unit", "create", None, "alpha")
            .unwrap();
        store
            .record_event(DEFAULT_CASE, "unit", "inspect", None, "beta")
            .unwrap();
        let valid = store.verify_case_provenance(DEFAULT_CASE).unwrap();
        assert_eq!(valid.verified_events, 2);
        assert_eq!(valid.head_sha256.len(), 64);
        assert_eq!(
            store
                .export_case_report(DEFAULT_CASE)
                .unwrap()
                .provenance
                .head_sha256,
            valid.head_sha256
        );
        store
            .conn
            .execute(
                "INSERT INTO case_events(case_id,source,action,source_description,created_ms)
             VALUES (?1,'rogue','insert','unauthorized',123)",
                params![DEFAULT_CASE],
            )
            .unwrap();
        assert!(store.verify_case_provenance(DEFAULT_CASE).is_err());
        assert!(store
            .record_event(DEFAULT_CASE, "unit", "add", None, "later")
            .is_err());
    }

    #[test]
    fn provenance_v2_migration_backfills_legacy_events() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("index.db");
        let store = ArtifactStore::open(&db).unwrap();
        store
            .record_event(DEFAULT_CASE, "unit", "legacy", None, "older event")
            .unwrap();
        store
            .conn
            .execute_batch("DROP TABLE case_event_integrity; PRAGMA user_version=1;")
            .unwrap();
        drop(store);
        let reopened = ArtifactStore::open(&db).unwrap();
        let proof = reopened.verify_case_provenance(DEFAULT_CASE).unwrap();
        assert_eq!(proof.verified_events, 1);
        reopened
            .record_event(DEFAULT_CASE, "unit", "new", None, "more")
            .unwrap();
        assert_eq!(
            reopened
                .verify_case_provenance(DEFAULT_CASE)
                .unwrap()
                .verified_events,
            2
        );
    }

    #[test]
    fn case_report_manifest_is_stable_and_detects_changes() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        store.upsert_artifact(&record("manifest")).unwrap();
        store
            .record_event(DEFAULT_CASE, "import", "create", Some("manifest"), "source")
            .unwrap();
        let mut exported = store.export_case_report(DEFAULT_CASE).unwrap();
        assert_eq!(exported.manifest_sha256.len(), 64);
        verify_case_report_manifest(&exported).unwrap();
        verify_case_report_manifest(&store.export_case_report(DEFAULT_CASE).unwrap()).unwrap();
        exported.generated_ms += 1;
        assert!(verify_case_report_manifest(&exported).is_err());
        exported.generated_ms -= 1;
        exported.artifacts[0].name.push_str(".tampered");
        assert!(verify_case_report_manifest(&exported).is_err());
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

//! SQLite persistence — extracted from legacy monolithic store without changing SQL or public signatures.
use crate::integrity;
use crate::{ArtifactStore, CaseEvent, GENESIS_HASH};
use rusqlite::{params, Connection};

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
        const SCHEMA_VERSION: i64 = 3;
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
            // Stream legacy events in stable order instead of allocating
            // O(all events) in a temporary Vec during migration. Only one
            // hash head per distinct case remains resident.
            let mut heads = std::collections::HashMap::<String, String>::new();
            {
                let mut stmt = tx
                    .prepare(
                        "SELECT id,case_id,source,action,artifact_id,source_description,created_ms
                     FROM case_events ORDER BY case_id,id",
                    )
                    .map_err(|e| e.to_string())?;
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
                for item in rows {
                    let event = item.map_err(|e| e.to_string())?;
                    let previous = heads
                        .get(&event.case_id)
                        .map(String::as_str)
                        .unwrap_or(GENESIS_HASH);
                    let digest = integrity::event_hash(&event, previous);
                    tx.execute(
                        "INSERT INTO case_event_integrity(event_id,case_id,previous_hash,event_hash)
                         VALUES (?1,?2,?3,?4)",
                        params![event.id,event.case_id,previous,digest],
                    ).map_err(|e| format!("cannot backfill provenance: {e}"))?;
                    heads.insert(event.case_id, digest);
                }
            }
            tx.execute_batch("PRAGMA user_version = 2;")
                .map_err(|e| format!("cannot set provenance schema version: {e}"))?;
            tx.commit()
                .map_err(|e| format!("cannot commit provenance migration: {e}"))?;
        }
        if version < 3 {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| format!("cannot start checkpoint migration: {e}"))?;
            tx.execute_batch(r#"
                CREATE TABLE IF NOT EXISTS recovery_checkpoints (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id        TEXT NOT NULL REFERENCES cases(id),
                    run_kind       TEXT NOT NULL,
                    resume_kind    TEXT NOT NULL,
                    algorithm      TEXT NOT NULL,
                    backend        TEXT NOT NULL,
                    target_hash    TEXT NOT NULL,
                    total_budget   INTEGER NOT NULL,
                    max_matches    INTEGER NOT NULL,
                    submitted      INTEGER NOT NULL,
                    stage_index    INTEGER NOT NULL,
                    stage_submitted INTEGER NOT NULL,
                    wordlist_id    TEXT,
                    rules_set_id   TEXT,
                    preset         TEXT NOT NULL,
                    state          TEXT NOT NULL,
                    created_ms     INTEGER NOT NULL,
                    updated_ms     INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_recovery_checkpoints_case
                    ON recovery_checkpoints(case_id, id);
                CREATE TRIGGER IF NOT EXISTS checkpoint_case_scope BEFORE INSERT ON recovery_checkpoints
                    WHEN NOT EXISTS(SELECT 1 FROM cases WHERE id=NEW.case_id)
                    BEGIN SELECT RAISE(ABORT,'checkpoint case missing'); END;
            "#).map_err(|e| format!("cannot create recovery checkpoint table: {e}"))?;
            tx.execute_batch("PRAGMA user_version = 3;")
                .map_err(|e| format!("cannot set checkpoint schema version: {e}"))?;
            tx.commit()
                .map_err(|e| format!("cannot commit checkpoint migration: {e}"))?;
        }
        Ok(Self { conn })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CASE;

    #[test]
    fn streaming_provenance_backfill_preserves_long_legacy_history() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("legacy.db");
        let store = ArtifactStore::open(&db).unwrap();
        {
            let tx = store.conn.unchecked_transaction().unwrap();
            for i in 0..2048_i64 {
                tx.execute(
                    "INSERT INTO case_events
                    (case_id,source,action,artifact_id,source_description,created_ms)
                    VALUES (?1,'legacy','read',NULL,'migrated',?2)",
                    params![DEFAULT_CASE, i],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        store
            .conn
            .execute_batch("DROP TABLE case_event_integrity; PRAGMA user_version=1;")
            .unwrap();
        drop(store);

        let migrated = ArtifactStore::open(&db).unwrap();
        let proof = migrated.verify_case_provenance(DEFAULT_CASE).unwrap();
        assert_eq!(proof.verified_events, 2048);
        assert_eq!(proof.head_sha256.len(), 64);
        migrated
            .record_event(DEFAULT_CASE, "test", "new", None, "after migrate")
            .unwrap();
        assert_eq!(
            migrated
                .verify_case_provenance(DEFAULT_CASE)
                .unwrap()
                .verified_events,
            2049
        );
    }
}

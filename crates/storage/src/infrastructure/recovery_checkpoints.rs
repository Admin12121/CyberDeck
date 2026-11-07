//! Durable case-scoped resume checkpoints for recovery runs. Rows record
//! algorithm/backend/counters and library wordlist references only — never
//! candidates, recovered secrets, or arbitrary operator file paths.
use crate::domain::{NewRecoveryCheckpoint, RecoveryCheckpointRecord, RECOVERY_CHECKPOINT_STATES};
use crate::{timestamp_ms, ArtifactStore};
use rusqlite::params;

const CHECKPOINT_LIST_LIMIT: i64 = 50;

impl ArtifactStore {
    const CHECKPOINT_COLUMNS: &'static str = "id,case_id,run_kind,resume_kind,algorithm,backend,
        target_hash,total_budget,max_matches,submitted,stage_index,stage_submitted,
        wordlist_id,rules_set_id,preset,state,created_ms,updated_ms";

    fn checkpoint_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecoveryCheckpointRecord> {
        Ok(RecoveryCheckpointRecord {
            id: row.get(0)?,
            case_id: row.get(1)?,
            run_kind: row.get(2)?,
            resume_kind: row.get(3)?,
            algorithm: row.get(4)?,
            backend: row.get(5)?,
            target_hash: row.get(6)?,
            total_budget: row.get(7)?,
            max_matches: row.get(8)?,
            submitted: row.get(9)?,
            stage_index: row.get(10)?,
            stage_submitted: row.get(11)?,
            wordlist_id: row.get(12)?,
            rules_set_id: row.get(13)?,
            preset: row.get(14)?,
            state: row.get(15)?,
            created_ms: row.get(16)?,
            updated_ms: row.get(17)?,
        })
    }

    /// Open a running checkpoint row for one (case, run); returns its run id.
    pub fn start_recovery_checkpoint(
        &self,
        record: &NewRecoveryCheckpoint,
    ) -> Result<i64, String> {
        record.validate()?;
        let now = timestamp_ms();
        self.conn
            .execute(
                "INSERT INTO recovery_checkpoints
                 (case_id,run_kind,resume_kind,algorithm,backend,target_hash,
                  total_budget,max_matches,submitted,stage_index,stage_submitted,
                  wordlist_id,rules_set_id,preset,state,created_ms,updated_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,?9,?10,?11,?12,?13,'running',?14,?14)",
                params![
                    record.case_id,
                    record.run_kind,
                    record.resume_kind,
                    record.algorithm,
                    record.backend,
                    record.target_hash,
                    record.total_budget,
                    record.max_matches,
                    record.stage_index,
                    record.stage_submitted,
                    record.wordlist_id,
                    record.rules_set_id,
                    record.preset,
                    now,
                ],
            )
            .map_err(|e| format!("cannot open recovery checkpoint: {e}"))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Persist throttled progress or a terminal transition for one run row.
    /// `state` must be one of the documented run states; counters are the
    /// caller's honest values (a re-issue may legitimately lower them to the
    /// last resume boundary it can skip to).
    pub fn record_recovery_checkpoint(
        &self,
        id: i64,
        state: &str,
        submitted: u64,
        stage_index: u64,
        stage_submitted: u64,
    ) -> Result<(), String> {
        if !RECOVERY_CHECKPOINT_STATES.contains(&state) {
            return Err("invalid recovery checkpoint state".into());
        }
        let updated = self
            .conn
            .execute(
                "UPDATE recovery_checkpoints
                 SET state=?2, submitted=?3, stage_index=?4, stage_submitted=?5, updated_ms=?6
                 WHERE id=?1",
                params![id, state, submitted, stage_index, stage_submitted, timestamp_ms()],
            )
            .map_err(|e| format!("cannot update recovery checkpoint: {e}"))?;
        if updated == 0 {
            return Err("recovery checkpoint row is missing".into());
        }
        Ok(())
    }

    /// One checkpoint row by id; the caller validates case scope.
    pub fn recovery_checkpoint(&self, id: i64) -> Result<RecoveryCheckpointRecord, String> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {} FROM recovery_checkpoints WHERE id=?1",
                    Self::CHECKPOINT_COLUMNS
                ),
                params![id],
                Self::checkpoint_from_row,
            )
            .map_err(|e| format!("recovery checkpoint not found: {e}"))
    }

    /// Resumable runs for a case: rows suspended by an interrupted session or
    /// closed by operator cancellation. Completed rows never come back.
    pub fn list_resumable_recovery_checkpoints(
        &self,
        case_id: &str,
    ) -> Result<Vec<RecoveryCheckpointRecord>, String> {
        crate::validate_case_id(case_id)?;
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {} FROM recovery_checkpoints
                 WHERE case_id=?1 AND state IN ('suspended','cancelled')
                 ORDER BY id DESC LIMIT {CHECKPOINT_LIST_LIMIT}",
                Self::CHECKPOINT_COLUMNS
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![case_id], Self::checkpoint_from_row)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Reconcile rows still marked running from a dead session. Rows in
    /// `keep` belong to live jobs of the current session and stay running;
    /// everything else becomes suspended (interrupted, resumable).
    pub fn suspend_stale_recovery_checkpoints(
        &self,
        case_id: &str,
        keep: &[i64],
    ) -> Result<usize, String> {
        crate::validate_case_id(case_id)?;
        let mut sql = String::from(
            "UPDATE recovery_checkpoints SET state='suspended', updated_ms=?2
             WHERE case_id=?1 AND state='running'",
        );
        if !keep.is_empty() {
            // Placeholders stay positional; ids are bound, never interpolated.
            let placeholders = (3..3 + keep.len())
                .map(|n| format!("?{n}"))
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" AND id NOT IN ({placeholders})"));
        }
        let mut params_vec = vec![
            rusqlite::types::Value::Text(case_id.to_string()),
            rusqlite::types::Value::from(timestamp_ms()),
        ];
        params_vec.extend(keep.iter().map(|id| rusqlite::types::Value::from(*id)));
        self.conn
            .execute(&sql, rusqlite::params_from_iter(params_vec))
            .map_err(|e| format!("cannot suspend stale recovery checkpoints: {e}"))
    }

    /// Remove one checkpoint row (operator intent; never automatic).
    pub fn delete_recovery_checkpoint(&self, case_id: &str, id: i64) -> Result<bool, String> {
        crate::validate_case_id(case_id)?;
        let deleted = self
            .conn
            .execute(
                "DELETE FROM recovery_checkpoints WHERE id=?1 AND case_id=?2",
                params![id, case_id],
            )
            .map_err(|e| format!("cannot delete recovery checkpoint: {e}"))?;
        Ok(deleted > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RECOVERY_CHECKPOINT_STATES;

    fn sample(case_id: &str) -> NewRecoveryCheckpoint {
        NewRecoveryCheckpoint {
            case_id: case_id.to_string(),
            run_kind: "wordlist_gpu".into(),
            resume_kind: "chunk_boundary".into(),
            algorithm: "sha256".into(),
            backend: "hashcat_managed".into(),
            target_hash: "a".repeat(64),
            total_budget: 14_000_000,
            max_matches: 1,
            stage_index: 0,
            stage_submitted: 0,
            wordlist_id: Some("rockyou".into()),
            rules_set_id: None,
            preset: "plain".into(),
        }
    }

    #[test]
    fn checkpoint_rows_roundtrip_and_close_without_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        let case = store.create_case("Resume", "checkpoints").unwrap();
        let run = store.start_recovery_checkpoint(&sample(&case.id)).unwrap();
        store
            .record_recovery_checkpoint(run, "running", 2_000_000, 0, 0)
            .unwrap();
        let row = store.recovery_checkpoint(run).unwrap();
        assert_eq!(row.submitted, 2_000_000);
        assert_eq!(row.state, "running");
        assert_eq!(row.wordlist_id.as_deref(), Some("rockyou"));
        assert_eq!(row.target_hash, "a".repeat(64));
        store
            .record_recovery_checkpoint(run, "suspended", 2_000_000, 0, 0)
            .unwrap();
        let resumable = store.list_resumable_recovery_checkpoints(&case.id).unwrap();
        assert_eq!(resumable.len(), 1);
        assert_eq!(resumable[0].id, run);
        // A completed run never re-enters the resumable list.
        store
            .record_recovery_checkpoint(run, "completed", 14_000_000, 0, 0)
            .unwrap();
        assert!(store
            .list_resumable_recovery_checkpoints(&case.id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn stale_running_rows_suspend_except_live_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        let case = store.create_case("Restart", "reconcile").unwrap();
        let dead = store.start_recovery_checkpoint(&sample(&case.id)).unwrap();
        let live = store.start_recovery_checkpoint(&sample(&case.id)).unwrap();
        let suspended = store
            .suspend_stale_recovery_checkpoints(&case.id, &[live])
            .unwrap();
        assert_eq!(suspended, 1);
        assert_eq!(store.recovery_checkpoint(dead).unwrap().state, "suspended");
        assert_eq!(store.recovery_checkpoint(live).unwrap().state, "running");
        // Without keepers every running row reconciles to suspended.
        assert_eq!(
            store
                .suspend_stale_recovery_checkpoints(&case.id, &[])
                .unwrap(),
            1
        );
        assert_eq!(store.recovery_checkpoint(live).unwrap().state, "suspended");
    }

    #[test]
    fn checkpoint_rows_are_case_scoped_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&dir.path().join("index.db")).unwrap();
        let case = store.create_case("Scoped", "checkpoints").unwrap();
        let other = store.create_case("Other", "checkpoints").unwrap();
        let run = store.start_recovery_checkpoint(&sample(&case.id)).unwrap();
        // Case scope: another case can neither list nor delete the row.
        assert!(store
            .list_resumable_recovery_checkpoints(&other.id)
            .unwrap()
            .is_empty());
        assert!(!store.delete_recovery_checkpoint(&other.id, run).unwrap());
        assert!(store.recovery_checkpoint(run).is_ok());
        assert!(store.delete_recovery_checkpoint(&case.id, run).unwrap());
        assert!(store.recovery_checkpoint(run).is_err());
        let mut bad = sample(&case.id);
        bad.run_kind = "mask_blast".into();
        assert!(store.start_recovery_checkpoint(&bad).is_err());
        bad.run_kind = "wordlist_cpu".into();
        bad.target_hash = String::new();
        assert!(store.start_recovery_checkpoint(&bad).is_err());
        let good = store.start_recovery_checkpoint(&sample(&case.id)).unwrap();
        for state in RECOVERY_CHECKPOINT_STATES {
            assert!(store.record_recovery_checkpoint(good, state, 0, 0, 0).is_ok());
        }
        assert!(store
            .record_recovery_checkpoint(good, "detonated", 0, 0, 0)
            .is_err());
        assert!(store
            .record_recovery_checkpoint(99_999, "running", 0, 0, 0)
            .is_err());
    }
}

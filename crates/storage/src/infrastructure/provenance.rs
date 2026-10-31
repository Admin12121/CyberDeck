//! SQLite persistence — extracted from legacy monolithic store without changing SQL or public signatures.
use crate::integrity;
use crate::{timestamp_ms, ArtifactStore, CaseEvent, ProvenanceVerification, GENESIS_HASH};
use rusqlite::{params, OptionalExtension};

impl ArtifactStore {
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
}

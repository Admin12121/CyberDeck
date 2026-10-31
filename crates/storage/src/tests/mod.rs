//! Storage regression suite, separate from the public crate API.
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

//! Case database adapter: immutable artifact identity, publication and atomic
//! import transactions. Business orchestration remains in application.
use super::{publish_case_record, EvidenceCtx, PlannedArchiveEntry, MAX_IMPORT_BYTES};
use cyberdeck_crypto::{detect_signature, entropy};
use cyberdeck_storage::{
    validate_case_id, ArtifactRecord, ArtifactStore, ImportBatchItem, ImportEvent, NewFinding,
    DEFAULT_CASE,
};
use std::path::Path;

/// Publish evidence safely but defer database changes to the caller. The
/// caller holds the case store lock throughout preparation and commit.
pub(super) fn prepare_import_record(
    ctx: &EvidenceCtx,
    store: &ArtifactStore,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
) -> Result<ArtifactRecord, String> {
    validate_case_id(case_id)?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err("evidence exceeds the import size limit".into());
    }
    let hashes = cyberdeck_crypto::formats::forensic_native::digest_stream(
        std::io::Cursor::new(bytes),
        MAX_IMPORT_BYTES,
    )?;
    let sha256 = hashes.sha256;
    let md5 = hashes.md5;
    let sha1 = hashes.sha1;
    let crc32 = hashes.crc32;
    let signature = detect_signature(bytes).map(str::to_string).or_else(|| {
        let printable = bytes
            .iter()
            .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
            .count();
        (!bytes.is_empty() && printable * 100 / bytes.len() >= 95).then(|| "ASCII text".to_string())
    });
    let entropy_value = entropy(bytes);
    let imported_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let kind = if disk_source {
        "sha256"
    } else {
        "derived-sha256"
    };
    let id = if case_id == DEFAULT_CASE {
        format!("{kind}-{}", &sha256[..16])
    } else {
        format!("{case_id}:{kind}-{}", &sha256[..16])
    };
    let original_name = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "evidence.bin".into());

    if !store.case_exists(case_id)? {
        return Err("selected case does not exist".into());
    }
    let prior = store.get_artifact(&id)?;
    if let Some(old) = prior.as_ref() {
        if old.case_id != case_id || old.sha256 != sha256 || old.size != bytes.len() as u64 {
            return Err("immutable evidence identity conflict".into());
        }
    }
    let stored_path = publish_case_record(ctx, case_id, &sha256, prior.as_ref(), bytes)?;
    let record = prior.unwrap_or_else(|| ArtifactRecord {
        id,
        case_id: case_id.to_string(),
        name: original_name,
        stored_path: stored_path.to_string_lossy().to_string(),
        original_path: disk_source.then(|| source.to_string_lossy().to_string()),
        size: bytes.len() as u64,
        sha256,
        md5,
        sha1,
        crc32,
        signature,
        entropy: entropy_value,
        imported_at,
    });
    Ok(record)
}

/// Commit one immutable artifact and all its provenance and findings together.
pub(super) fn commit_import(
    ctx: &EvidenceCtx,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
    events: &[ImportEvent<'_>],
    findings: &[NewFinding],
) -> Result<ArtifactRecord, String> {
    let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
    let record = prepare_import_record(ctx, &store, source, bytes, case_id, disk_source)?;
    store.commit_artifact_import_with_events(&record, &ctx.artifacts_dir, events, findings)?;
    Ok(record)
}

pub(super) fn list_case_records(
    ctx: &EvidenceCtx,
    case_id: &str,
) -> Result<Vec<ArtifactRecord>, String> {
    validate_case_id(case_id)?;
    let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
    store.list_artifacts(case_id)
}

/// Publish every unique archive artifact under the case store lock, then
/// atomically commit its grouped events/findings in a single SQLite batch.
pub(super) fn commit_archive_records(
    ctx: &EvidenceCtx,
    case_id: &str,
    source_tag: &'static str,
    planned: &[PlannedArchiveEntry],
    digest_keys: &[String],
    distinct_count: usize,
) -> Result<Vec<ArtifactRecord>, String> {
    use std::collections::HashMap;
    let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
    let mut all_records = Vec::with_capacity(planned.len());
    let mut unique_records: Vec<ArtifactRecord> = Vec::with_capacity(distinct_count);
    let mut ids = HashMap::<String, usize>::new();
    let mut digests_to_index = HashMap::<String, usize>::new();
    let mut first_plan_by_unique = Vec::<usize>::with_capacity(distinct_count);
    for (plan_index, (plan, digest)) in planned.iter().zip(digest_keys.iter()).enumerate() {
        if let Some(&index) = digests_to_index.get(digest) {
            // Compare all bytes on a digest match, preserving exact evidence
            // identity without rerunning SHA1/MD5/CRC/entropy or disk reads.
            if planned[first_plan_by_unique[index]].bytes != plan.bytes {
                return Err("archive digest collision with distinct bytes".into());
            }
            all_records.push(unique_records[index].clone());
            continue;
        }
        let record = prepare_import_record(
            ctx,
            &store,
            Path::new(&plan.name),
            &plan.bytes,
            case_id,
            false,
        )?;
        let index = unique_records.len();
        ids.insert(record.id.clone(), index);
        digests_to_index.insert(digest.clone(), index);
        first_plan_by_unique.push(plan_index);
        unique_records.push(record.clone());
        all_records.push(record);
    }
    let mut event_groups = vec![Vec::new(); unique_records.len()];
    let mut finding_groups = vec![Vec::new(); unique_records.len()];
    for (plan, record) in planned.iter().zip(all_records.iter()) {
        let index = ids[&record.id];
        event_groups[index].push(ImportEvent {
            source: source_tag,
            action: "derived",
            description: &plan.name,
        });
        event_groups[index].push(ImportEvent {
            source: source_tag,
            action: "extract",
            description: &plan.provenance,
        });
        finding_groups[index].push(NewFinding {
            title: plan.title.clone(),
            severity: "info".into(),
            details: format!("{}\nDerived SHA-256: {}", plan.provenance, record.sha256,),
        });
    }
    let items: Vec<ImportBatchItem<'_>> = unique_records
        .iter()
        .enumerate()
        .map(|(index, record)| ImportBatchItem {
            record,
            events: &event_groups[index],
            findings: &finding_groups[index],
        })
        .collect();
    store
        .commit_artifact_batch(&ctx.artifacts_dir, &items)
        .map_err(|e| {
            format!(
                "archive database batch was rolled back: {e}; already-published \
             unindexed evidence bytes may require cleanup"
            )
        })?;
    Ok(all_records)
}

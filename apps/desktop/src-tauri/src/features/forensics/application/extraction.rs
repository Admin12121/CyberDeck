//! Forensic extraction application: archive validation, case-scoped
//! derived artifact creation and provenance transaction orchestration.
use super::{
    commit_archive_records, digest_of, import_bytes_with_events, sanitize_file_name,
    scoped_case_artifact, verified_record_window, EvidenceCtx, PlannedArchiveEntry,
};
use cyberdeck_storage::{validate_case_id, ArtifactRecord, ImportEvent, NewFinding};
use std::path::Path;

pub(super) fn import_archive_batch(
    ctx: &EvidenceCtx,
    case_id: &str,
    source_tag: &'static str,
    planned: Vec<PlannedArchiveEntry>,
) -> Result<Vec<ArtifactRecord>, String> {
    use std::collections::HashMap;
    validate_case_id(case_id)?;
    if planned.is_empty() {
        return Ok(Vec::new());
    }
    // The storage API supports up to 32 unique artifacts per atomic batch
    // and at most 32 events for any one artifact. Duplicate bytes share an
    // immutable artifact ID, so multiple archive paths aggregate lineage.
    let mut occurrences = HashMap::<String, usize>::new();
    let mut digest_keys = Vec::with_capacity(planned.len());
    for plan in &planned {
        if plan.name.is_empty()
            || plan.name.len() > 100
            || plan.provenance.len() > 512
            || plan.title.len() > 200
        {
            return Err("archive metadata exceeds atomic import limits".into());
        }
        let digest = digest_of("sha256", &plan.bytes)?;
        let seen = occurrences.entry(digest.clone()).or_default();
        digest_keys.push(digest);
        *seen += 1;
        if *seen > 16 {
            return Err("identical archive data exceeds 16 provenance paths per artifact".into());
        }
        if occurrences.len() > 32 {
            return Err("atomic archive import supports at most 32 distinct artifacts".into());
        }
    }
    commit_archive_records(
        ctx,
        case_id,
        source_tag,
        &planned,
        &digest_keys,
        occurrences.len(),
    )
}

pub(super) fn extract_gzip_from_evidence(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: usize,
) -> Result<ArtifactRecord, String> {
    use cyberdeck_crypto::extraction::{
        extract_gzip_limited, MAX_GZIP_INPUT_BYTES, MAX_GZIP_OUTPUT_BYTES,
    };
    let record = scoped_case_artifact(
        ctx,
        case_id,
        id,
        "source artifact not found in selected case",
    )?;
    if record.size > MAX_GZIP_INPUT_BYTES as u64 {
        return Err("gzip extraction limited to stored files of at most 16 MiB".into());
    }
    let (_, data) = verified_record_window(
        ctx,
        case_id,
        id,
        0,
        MAX_GZIP_INPUT_BYTES,
        MAX_GZIP_INPUT_BYTES,
    )?;
    let output = extract_gzip_limited(&data, offset, MAX_GZIP_OUTPUT_BYTES)?;
    let name = format!("gzip-offset-{offset:x}.bin");
    let derived_hash = digest_of("sha256", &output)?;
    let description = format!("Source artifact {} gzip offset 0x{offset:x}", record.id);
    let events = [
        ImportEvent {
            source: "forensics.gzip",
            action: "derived",
            description: &name,
        },
        ImportEvent {
            source: "forensics.gzip",
            action: "extract",
            description: &description,
        },
    ];
    let findings = [NewFinding {
        title: format!("Extracted Gzip member at 0x{offset:x}"),
        severity: "info".into(),
        details: format!(
            "Source: {} (sha256 {})\nDerived SHA-256: {}\nUncompressed length: {}",
            record.id,
            record.sha256,
            derived_hash,
            output.len(),
        ),
    }];
    import_bytes_with_events(
        ctx,
        Path::new(&name),
        &output,
        case_id,
        false,
        &events,
        &findings,
    )
}

pub(super) fn extract_archive_from_evidence(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    format: &str,
    offset: usize,
) -> Result<Vec<ArtifactRecord>, String> {
    use cyberdeck_crypto::extraction::{
        extract_tar_limited, extract_zip_limited, MAX_ARCHIVE_INPUT_BYTES, MAX_ARCHIVE_OUTPUT_BYTES,
    };
    validate_case_id(case_id)?;
    if format != "zip" && format != "tar" {
        return Err("only ZIP and TAR native extraction is supported".into());
    }
    let record = scoped_case_artifact(
        ctx,
        case_id,
        id,
        "source evidence does not belong to the selected case",
    )?;
    if record.size > MAX_ARCHIVE_INPUT_BYTES as u64 {
        return Err("archive source is larger than the 16 MiB limit".into());
    }
    let (_, source) = verified_record_window(
        ctx,
        case_id,
        id,
        0,
        MAX_ARCHIVE_INPUT_BYTES,
        MAX_ARCHIVE_INPUT_BYTES,
    )?;
    // Parse and verify *every* entry before saving any result into the case.
    let entries = match format {
        "zip" => extract_zip_limited(&source, offset, MAX_ARCHIVE_OUTPUT_BYTES)?,
        _ => extract_tar_limited(&source, offset, MAX_ARCHIVE_OUTPUT_BYTES)?,
    };
    let mut planned = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let base = entry.path.rsplit('/').next().unwrap_or("file");
        let safe = sanitize_file_name(base);
        let short = safe.chars().take(48).collect::<String>();
        let name = format!("{format}-{index:03}-{short}");
        let provenance = format!(
            "Source: {} (sha256 {}) | Format: {} | Archive offset: 0x{:x} | \
             Entry: {} | Header offset: 0x{:x}",
            record.id, record.sha256, format, offset, entry.path, entry.source_offset,
        );
        if provenance.len() > 512 {
            return Err(format!(
                "archive entry {index} provenance exceeds 512 bytes"
            ));
        }
        planned.push(PlannedArchiveEntry {
            name,
            bytes: entry.bytes,
            provenance,
            title: format!("Extracted {format} entry {index}"),
        });
    }
    import_archive_batch(ctx, case_id, "forensics.archive", planned)
}

pub(super) fn extract_nested_from_evidence(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    format: &str,
    offset: usize,
    max_depth: usize,
) -> Result<Vec<ArtifactRecord>, String> {
    use cyberdeck_crypto::extraction::{
        nested::extract_nested_limited, MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_INPUT_BYTES,
        MAX_ARCHIVE_OUTPUT_BYTES,
    };
    validate_case_id(case_id)?;
    let format = match format {
        "zip" => "zip",
        "tar" => "tar",
        "gzip" => "gzip",
        _ => return Err("unsupported nested archive format".into()),
    };
    let source_record = scoped_case_artifact(
        ctx,
        case_id,
        id,
        "nested source evidence is not in the selected case",
    )?;
    if source_record.size > MAX_ARCHIVE_INPUT_BYTES as u64 {
        return Err("nested source archive exceeds 16 MiB".into());
    }
    let (_, source) = verified_record_window(
        ctx,
        case_id,
        id,
        0,
        MAX_ARCHIVE_INPUT_BYTES,
        MAX_ARCHIVE_INPUT_BYTES,
    )?;
    let leafs = extract_nested_limited(
        &source,
        format,
        offset,
        max_depth,
        MAX_ARCHIVE_ENTRIES,
        MAX_ARCHIVE_OUTPUT_BYTES,
    )?;
    let mut planned = Vec::with_capacity(leafs.len());
    for (index, leaf) in leafs.into_iter().enumerate() {
        let last = leaf.lineage.last().ok_or("nested lineage is empty")?;
        let name_part = sanitize_file_name(last.item_name.rsplit('/').next().unwrap_or("member"));
        let short = name_part.chars().take(48).collect::<String>();
        let name = format!("nested-{index:03}-{short}");
        let chain = leaf
            .lineage
            .iter()
            .enumerate()
            .map(|(depth, hop)| {
                format!(
                    "{depth}:{}:{}@0x{:x}",
                    hop.format, hop.item_name, hop.source_offset,
                )
            })
            .collect::<Vec<_>>()
            .join(" -> ");
        let provenance = format!(
            "Parent: {} sha256={} | source offset 0x{:x} | {}",
            source_record.id, source_record.sha256, offset, chain,
        );
        if provenance.len() > 512 {
            return Err(format!("nested entry {index} provenance exceeds 512 bytes"));
        }
        planned.push(PlannedArchiveEntry {
            name,
            bytes: leaf.bytes,
            provenance,
            title: format!("Nested archive entry {index}"),
        });
    }
    import_archive_batch(ctx, case_id, "forensics.nested", planned)
}

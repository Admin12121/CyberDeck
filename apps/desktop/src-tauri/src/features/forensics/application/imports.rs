//! Case evidence import use cases: immutable identities, transactional
//! artifact and event persistence, and derived import validation.
use super::{
    commit_import, digest_of, list_case_records, read_import_file, sanitize_file_name, EvidenceCtx,
    MAX_DERIVED_BYTES,
};
use base64::Engine as _;
use cyberdeck_storage::{validate_case_id, ArtifactRecord, ImportEvent, NewFinding};
use std::path::Path;

pub(super) fn import_bytes(
    ctx: &EvidenceCtx,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
) -> Result<ArtifactRecord, String> {
    let description = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "evidence.bin".into());
    let events = [ImportEvent {
        source: if disk_source {
            "forensics.import"
        } else {
            "crypto.recipes"
        },
        action: if disk_source { "import" } else { "derived" },
        description: &description,
    }];
    import_bytes_with_events(ctx, source, bytes, case_id, disk_source, &events, &[])
}

pub(super) fn import_bytes_with_events(
    ctx: &EvidenceCtx,
    source: &Path,
    bytes: &[u8],
    case_id: &str,
    disk_source: bool,
    events: &[ImportEvent<'_>],
    findings: &[NewFinding],
) -> Result<ArtifactRecord, String> {
    commit_import(ctx, source, bytes, case_id, disk_source, events, findings)
}

/// Validate and persist a manually derived recipe result with immutable provenance.
pub(super) fn import_derived(
    ctx: &EvidenceCtx,
    case_id: String,
    name: String,
    data_b64: String,
    source_description: Option<String>,
) -> Result<ArtifactRecord, String> {
    validate_case_id(&case_id)?;
    if name.trim().is_empty()
        || name.len() > 100
        || data_b64.len() > (MAX_DERIVED_BYTES + 2) / 3 * 4 + 8
    {
        return Err("invalid derived artifact name or payload size".into());
    }
    let safe_name = sanitize_file_name(name.trim());
    if safe_name.is_empty() || safe_name == "." || safe_name == ".." {
        return Err("invalid derived artifact name".into());
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(&data_b64)
        .map_err(|e| format!("invalid derived artifact encoding: {e}"))?;
    if data.len() > MAX_DERIVED_BYTES {
        return Err("derived artifact exceeds 8 MiB limit".into());
    }
    let source_description = source_description.unwrap_or_else(|| "Manual Recipes input".into());
    if source_description.len() > 512 {
        return Err("source description too long".into());
    }
    let derived_hash = digest_of("sha256", &data)?;
    let events = [
        ImportEvent {
            source: "crypto.recipes",
            action: "derived",
            description: &safe_name,
        },
        ImportEvent {
            source: "crypto.recipes",
            action: "transformation",
            description: &source_description,
        },
    ];
    let findings = [NewFinding {
        title: format!("Derived file: {safe_name}"),
        severity: "info".into(),
        details: format!(
            "Saved from CyberDeck Recipes into case {}\nSHA256: {}\nSize: {} bytes",
            case_id,
            derived_hash,
            data.len()
        ),
    }];
    import_bytes_with_events(
        &ctx,
        Path::new(&safe_name),
        &data,
        &case_id,
        false,
        &events,
        &findings,
    )
}

/// Application use case for a user-selected disk file. A file adapter performs
/// the bounded read; the case import remains one immutable evidence operation.
pub(super) fn import_file_from_path(
    ctx: &EvidenceCtx,
    path: &Path,
    case_id: &str,
) -> Result<ArtifactRecord, String> {
    let bytes = read_import_file(path)?;
    import_bytes(ctx, path, &bytes, case_id, true)
}

/// List artifacts for a selected case; never panic on a poisoned store lock.
pub(super) fn list_artifacts(
    ctx: &EvidenceCtx,
    case_id: &str,
) -> Result<Vec<ArtifactRecord>, String> {
    list_case_records(ctx, case_id)
}

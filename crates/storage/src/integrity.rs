//! Native streaming evidence verification and deterministic provenance digests.
use crate::{ArtifactRecord, CaseEvent};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read};
use std::path::Path;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn field(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

pub(crate) fn event_hash(event: &CaseEvent, previous_hash: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"cyberdeck.event.v1\0");
    field(&mut hash, previous_hash);
    hash.update(event.id.to_be_bytes());
    hash.update(event.created_ms.to_be_bytes());
    field(&mut hash, &event.case_id);
    field(&mut hash, &event.source);
    field(&mut hash, &event.action);
    match &event.artifact_id {
        Some(id) => {
            hash.update([1]);
            field(&mut hash, id);
        }
        None => hash.update([0]),
    };
    field(&mut hash, &event.source_description);
    format!("{:x}", hash.finalize())
}

/// Verify stored evidence using bounded streaming SHA-256.
/// Canonical containment keeps the evidence read inside its selected case.
pub fn verify_artifact_file(record: &ArtifactRecord, root: &Path) -> Result<(), String> {
    crate::validate_case_id(&record.case_id)?;
    let canonical_root =
        std::fs::canonicalize(root).map_err(|e| format!("cannot resolve evidence root: {e}"))?;
    let case_path = root.join(&record.case_id);
    let case_meta = std::fs::symlink_metadata(&case_path)
        .map_err(|e| format!("cannot stat case evidence directory: {e}"))?;
    if case_meta.file_type().is_symlink() || !case_meta.file_type().is_dir() {
        return Err("case directory is a symlink or not a directory".into());
    }
    let canonical_case = std::fs::canonicalize(case_path)
        .map_err(|e| format!("cannot resolve case directory: {e}"))?;
    if !canonical_case.starts_with(&canonical_root) || canonical_case == canonical_root {
        return Err("case evidence directory escapes the evidence root".into());
    }
    let stored = Path::new(&record.stored_path);
    let meta = std::fs::symlink_metadata(stored)
        .map_err(|e| format!("cannot stat stored evidence: {e}"))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err("evidence path is a symlink or not a regular file".into());
    }
    let resolved =
        std::fs::canonicalize(stored).map_err(|e| format!("cannot resolve evidence path: {e}"))?;
    if !resolved.starts_with(&canonical_case) {
        return Err("stored evidence escapes its selected case".into());
    }
    let file =
        std::fs::File::open(&resolved).map_err(|e| format!("cannot open stored evidence: {e}"))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buf)
            .map_err(|e| format!("cannot stream stored evidence: {e}"))?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| "evidence size overflow".to_string())?;
        if size > record.size {
            return Err("evidence size differs from indexed evidence".into());
        }
        digest.update(&buf[..count]);
    }
    let computed = format!("{:x}", digest.finalize());
    if size != record.size || !computed.eq_ignore_ascii_case(&record.sha256) {
        return Err("evidence SHA-256 or size integrity failure".into());
    }
    Ok(())
}

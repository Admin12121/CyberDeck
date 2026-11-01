//! Immutable evidence publication and verified, bounded random-access file reads.
//! No Tauri commands or frontend types are defined in infrastructure.
use super::EvidenceCtx;
use cyberdeck_storage::{validate_case_id, ArtifactRecord};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_EVIDENCE_TEMP: AtomicU64 = AtomicU64::new(0);

/// Never trust an already-present destination merely because it exists:
/// reject symlinks/special files and compare the complete stored bytes.
pub(super) fn verify_existing_evidence(path: &Path, expected: &[u8]) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat existing evidence: {e}"))?;
    if !meta.file_type().is_file() || meta.len() != expected.len() as u64 {
        return Err("existing evidence is not a regular file of the expected size".into());
    }
    // Verify the existing immutable object incrementally, without
    // allocating a second buffer as large as the entire evidence file.
    let mut source = std::io::BufReader::with_capacity(
        64 * 1024,
        std::fs::File::open(path).map_err(|e| format!("cannot open existing evidence: {e}"))?,
    );
    let mut buffer = [0u8; 64 * 1024];
    for expected_chunk in expected.chunks(buffer.len()) {
        source
            .read_exact(&mut buffer[..expected_chunk.len()])
            .map_err(|e| format!("cannot verify existing evidence: {e}"))?;
        if buffer[..expected_chunk.len()] != *expected_chunk {
            return Err("existing evidence content integrity failure".into());
        }
    }
    Ok(())
}

/// Write to an exclusive temporary file in the case directory, sync it, then
/// publish with an atomic no-clobber hard link. Rename alone can overwrite
/// an existing destination on some platforms and is therefore not suitable.
/// No archive-controlled filename reaches this path.
pub(super) fn publish_evidence(
    case_dir: &Path,
    stored_path: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    if std::fs::symlink_metadata(stored_path).is_ok() {
        return verify_existing_evidence(stored_path, bytes);
    }
    let mut temporary = None;
    for _ in 0..16 {
        let nonce = NEXT_EVIDENCE_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = case_dir.join(format!(".evidence-{}-{nonce}.tmp", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                temporary = Some((path, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create evidence temporary file: {e}")),
        }
    }
    let (temp_path, mut file) =
        temporary.ok_or_else(|| "cannot reserve a unique evidence temporary path".to_string())?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|e| format!("cannot write evidence: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot sync evidence: {e}"))?;
        drop(file);
        match std::fs::hard_link(&temp_path, stored_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_existing_evidence(stored_path, bytes)
            }
            Err(e) => Err(format!("cannot publish immutable evidence: {e}")),
        }
    })();
    let _ = std::fs::remove_file(&temp_path);
    result
}

pub(super) fn scoped_case_artifact(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    not_found: &'static str,
) -> Result<ArtifactRecord, String> {
    validate_case_id(case_id)?;
    ctx.store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(id)?
        .filter(|item| item.case_id == case_id)
        .ok_or_else(|| not_found.to_string())
}

/// Resolve case membership, validate the storage path and read a small window
/// from the same file handle on which the complete SHA-256 is verified.
/// Retains a bounded memory footprint even for large evidence objects.
pub(super) fn verified_record_window(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: u64,
    len: usize,
    max: usize,
) -> Result<(ArtifactRecord, Vec<u8>), String> {
    if len == 0 || len > max || max > 16 * 1024 * 1024 {
        return Err("evidence window limit exceeded".into());
    }
    let record = scoped_case_artifact(ctx, case_id, id, "artifact not found in selected case")?;
    // Agent5's verified handle pins the same case-contained descriptor for
    // SHA-256 verification and bounded windows. No verified pathname reopen.
    #[cfg(unix)]
    let data = {
        let mut verified =
            cyberdeck_storage::open_verified_case_artifact(&record, &ctx.artifacts_dir)?;
        let start = offset.min(verified.size());
        let count = (verified.size() - start).min(len as u64) as usize;
        verified.read_window(start, count, max)?
    };
    // The new storage handle intentionally fails closed on Windows until a
    // reparse-aware adapter is tested. Preserve the prior Windows read path,
    // including both integrity passes, rather than breaking user workflows.
    #[cfg(not(unix))]
    let data = {
        cyberdeck_storage::verify_artifact_file(&record, &ctx.artifacts_dir)?;
        let mut file = std::fs::File::open(&record.stored_path)
            .map_err(|e| format!("cannot open case evidence: {e}"))?;
        cyberdeck_crypto::formats::forensic_native::verified_window(
            &mut file,
            record.size,
            &record.sha256,
            offset,
            len,
            max,
        )?
    };
    Ok((record, data))
}

/// Confine and publish an immutable case artifact without letting the
/// application service manipulate the filesystem directly.
pub(super) fn publish_case_record(
    ctx: &EvidenceCtx,
    case_id: &str,
    sha256: &str,
    prior: Option<&ArtifactRecord>,
    bytes: &[u8],
) -> Result<std::path::PathBuf, String> {
    let case_dir = ctx.artifacts_dir.join(case_id);
    std::fs::create_dir_all(&case_dir).map_err(|e| format!("cannot create case directory: {e}"))?;
    let case_meta = std::fs::symlink_metadata(&case_dir)
        .map_err(|e| format!("cannot inspect case directory: {e}"))?;
    if !case_meta.file_type().is_dir() || case_meta.file_type().is_symlink() {
        return Err("case evidence directory is a symlink or non-directory".into());
    }
    let root = std::fs::canonicalize(&ctx.artifacts_dir)
        .map_err(|e| format!("cannot resolve evidence root: {e}"))?;
    let resolved_case = std::fs::canonicalize(&case_dir)
        .map_err(|e| format!("cannot resolve case evidence directory: {e}"))?;
    if resolved_case == root || !resolved_case.starts_with(root) {
        return Err("case evidence directory escapes evidence root".into());
    }
    let stored_path = prior
        .map(|old| std::path::PathBuf::from(&old.stored_path))
        .unwrap_or_else(|| case_dir.join(format!("{sha256}.evidence")));
    // Existing historical names remain unchanged; new storage names are
    // digest-only, independent of the source filename.
    if let Some(old) = prior {
        cyberdeck_storage::verify_artifact_file(old, &ctx.artifacts_dir)?;
        verify_existing_evidence(&stored_path, bytes)?;
    } else {
        publish_evidence(&case_dir, &stored_path, bytes)?;
    }
    Ok(stored_path)
}

//! User-picked disk input adapters. The dialog itself stays in IPC;
//! file I/O and digesting are infrastructure operations.
use super::{FileDigestsWire, MAX_IMPORT_BYTES};
use std::io::Read;
use std::path::Path;

pub(super) fn read_import_file(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read file metadata: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "file is {} MB; the import limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    // Bound actual bytes read too: an untrusted selected file may grow after stat.
    let file = std::fs::File::open(path).map_err(|e| format!("cannot read file: {e}"))?;
    let mut reader = file.take(MAX_IMPORT_BYTES + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read file: {e}"))?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err("evidence exceeds the import size limit".into());
    }
    Ok(bytes)
}

pub(super) fn digest_disk_file(path: &Path) -> Result<FileDigestsWire, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read file metadata: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "file is {} MB; the limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let file = std::fs::File::open(path).map_err(|e| format!("cannot read file: {e}"))?;
    let found = cyberdeck_crypto::formats::forensic_native::digest_stream(file, MAX_IMPORT_BYTES)?;
    Ok(FileDigestsWire {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into()),
        size: found.bytes,
        sha256: found.sha256,
        sha1: found.sha1,
        md5: found.md5,
        crc32: found.crc32,
    })
}

//! Pure forensic domain constraints and extraction plans; no Tauri or I/O.

pub(crate) const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const MAX_HEX_REQUEST: i64 = 4096;
pub(super) const MAX_STRINGS_SCAN: usize = 8 * 1024 * 1024;
pub(super) const MAX_STRINGS_HITS: usize = 2000;
pub(super) const MAX_DERIVED_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn sanitize_file_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Extract regular files from a validated ZIP or ustar TAR into this case.
pub(super) struct PlannedArchiveEntry {
    pub(super) name: String,
    pub(super) bytes: Vec<u8>,
    pub(super) provenance: String,
    pub(super) title: String,
}

/// Preserve the legacy digest formatting (including ASCII-hex CRC32 bytes).
pub(super) fn digest_of(op: &str, bytes: &[u8]) -> Result<String, String> {
    let out = cyberdeck_crypto::apply_op(op, bytes, None)?;
    Ok(hex::encode(out))
}

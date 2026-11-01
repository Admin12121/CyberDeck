//! Stable Forensics IPC data transfer records. Fields and serialization remain compatible.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HexRow {
    pub offset: usize,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Serialize)]
pub struct HexResponse {
    pub rows: Vec<HexRow>,
    pub offset: i64,
    pub total_size: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringHit {
    pub offset: usize,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct SignatureScanResponse {
    pub hits: Vec<cyberdeck_crypto::formats::SignatureHit>,
    pub scanned_bytes: usize,
    pub file_bytes: u64,
    pub truncated: bool,
    pub integrity_checked: bool,
    pub hit_cap_reached: bool,
}

/// Offline binary format detection. No extraction or external executables.
/// Only the first 16 MiB is scanned, with a cap on returned signatures.

#[derive(Debug, Serialize)]
pub struct FileDigestsWire {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub crc32: String,
}

/// Digest a picked file without importing it into the case store.

#[derive(Debug, Serialize)]
pub struct ForensicStringsResponse {
    pub hits: Vec<cyberdeck_crypto::formats::forensic_native::StringMatch>,
    pub analyzed_offset: u64,
    pub analyzed_bytes: usize,
    pub file_bytes: u64,
    pub integrity_checked: bool,
    pub coverage_truncated: bool,
    pub hit_limit_reached: bool,
}
#[derive(Debug, Serialize)]
pub struct ForensicEntropyResponse {
    pub regions: Vec<cyberdeck_crypto::formats::forensic_native::EntropyRegion>,
    pub analyzed_offset: u64,
    pub analyzed_bytes: usize,
    pub file_bytes: u64,
    pub integrity_checked: bool,
    pub coverage_truncated: bool,
    pub block_size: usize,
}
#[derive(Debug, Serialize)]
pub struct ForensicMetadataResponse {
    pub report: cyberdeck_crypto::formats::forensic_native::MetadataReport,
    pub analyzed_offset: u64,
    pub analyzed_bytes: usize,
    pub file_bytes: u64,
    pub integrity_checked: bool,
    pub coverage_truncated: bool,
}

/// Read-only carving preview. Candidate offsets and lengths identify regions
/// of the *existing* verified case evidence; no bytes or new IDs are returned.
#[derive(Debug, Serialize)]
pub struct FileCarveResponse {
    pub candidates: Vec<cyberdeck_crypto::formats::carving::CarveCandidate>,
    pub analyzed_offset: u64,
    pub analyzed_bytes: usize,
    pub file_bytes: u64,
    pub integrity_checked: bool,
    pub coverage_truncated: bool,
    pub rejected_or_incomplete: usize,
    pub candidate_limit_reached: bool,
}

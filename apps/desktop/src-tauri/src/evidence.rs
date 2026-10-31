//! Evidence import and inspection (§5.6). Files enter only via these commands;
//! originals are copied immutably and indexed with full digests.

use cyberdeck_storage::ArtifactStore;
use std::sync::Mutex;

#[path = "features/forensics/infrastructure/evidence_files.rs"]
mod evidence_files;
use evidence_files::{publish_case_record, scoped_case_artifact, verified_record_window};

#[path = "features/forensics/infrastructure/inputs.rs"]
mod inputs;
use inputs::{digest_disk_file, read_import_file};

#[path = "features/forensics/infrastructure/repository.rs"]
mod repository;
use repository::{commit_archive_records, commit_import, list_case_records};

#[path = "features/forensics/domain/mod.rs"]
mod domain;
pub(crate) use domain::MAX_IMPORT_BYTES;
use domain::{
    digest_of, sanitize_file_name, PlannedArchiveEntry, MAX_DERIVED_BYTES, MAX_HEX_REQUEST,
    MAX_STRINGS_HITS, MAX_STRINGS_SCAN,
};

#[path = "features/forensics/application/analysis.rs"]
mod analysis;
use analysis::{
    binary_inspect, entropy_scan, hex_view, metadata_scan, signature_scan, strings, strings_scan,
};

#[path = "features/forensics/application/extraction.rs"]
mod extraction;
use extraction::{
    extract_archive_from_evidence, extract_gzip_from_evidence, extract_nested_from_evidence,
    import_archive_batch,
};

#[path = "features/forensics/application/imports.rs"]
mod imports;
use imports::{
    import_bytes, import_bytes_with_events, import_derived, import_file_from_path, list_artifacts,
};

#[path = "features/forensics/ipc/models.rs"]
mod ipc_models;
pub use ipc_models::{
    FileDigestsWire, ForensicEntropyResponse, ForensicMetadataResponse, ForensicStringsResponse,
    HexResponse, HexRow, SignatureScanResponse, StringHit,
};

pub struct EvidenceCtx {
    pub store: Mutex<ArtifactStore>,
    pub artifacts_dir: std::path::PathBuf,
}

#[path = "features/forensics/ipc/commands.rs"]
mod ipc_commands;
pub use ipc_commands::*;

#[cfg(test)]
#[path = "features/forensics/tests.rs"]
mod tests;

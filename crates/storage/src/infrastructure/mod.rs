//! Case database, schema migration and indexed evidence persistence.
mod artifacts;
pub(crate) use artifacts::artifact_from_row;
mod case_verification;
mod cases;
mod findings;
pub(crate) mod orphan_recovery;
mod provenance;
mod recovery;
mod recovery_checkpoints;
mod schema;
pub(crate) mod unregistered;
pub(crate) mod verified_handle;
#[cfg(all(windows, feature = "experimental-windows-handle"))]
mod windows_verified_handle;

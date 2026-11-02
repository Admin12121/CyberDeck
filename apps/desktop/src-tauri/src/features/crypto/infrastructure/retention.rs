//! Legacy recovery-history compatibility boundary.
//!
//! No new recovered plaintext, target digest, or wordlist provenance may be
//! written to SQLite automatically. Old history remains readable/deletable for
//! a separately coordinated storage migration; Recovery V1 keeps results
//! transient, masked and explicitly revealable.
//!
//! Preserve call compatibility with the legacy attack IPC until the frontend
//! and Cases/Storage owners migrate the history UX. Intentionally do not
//! enumerate the candidate iterator or log its contents.
use crate::features::forensics::ipc::evidence::EvidenceCtx;

#[allow(unused_variables)]
pub fn persist<'a>(
    ctx: &EvidenceCtx,
    algorithm: &str,
    target: &str,
    engine: &str,
    source: Option<&str>,
    passwords: impl IntoIterator<Item = &'a str>,
) {
    // Fail-closed: legacy plaintext history writes are disabled.
}

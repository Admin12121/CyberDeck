//! Filesystem writer for explicit user-chosen scan exports.
use std::path::Path;
pub(super) fn write_export(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("cannot write export: {e}"))
}

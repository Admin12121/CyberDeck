//! Read-only, bounded discovery of case directories whose SQL case creation
//! rolled back after immutable evidence publication. Never delete/adopt them.
use crate::ArtifactStore;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct UnregisteredCaseFolder {
    pub case_id: String,
    pub member_count: usize,
    pub member_scan_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnregisteredCaseReview {
    pub folders: Vec<UnregisteredCaseFolder>,
    pub truncated: bool,
}

impl ArtifactStore {
    pub fn review_unregistered_case_folders(
        &self,
        root: &Path,
    ) -> Result<UnregisteredCaseReview, String> {
        if !root.exists() {
            return Ok(UnregisteredCaseReview {
                folders: Vec::new(),
                truncated: false,
            });
        }
        let meta = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("unsafe evidence root for orphan review".into());
        }
        let mut folders = Vec::new();
        let mut observed = 0usize;
        let mut truncated = false;
        for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
            if observed >= 256 {
                truncated = true;
                break;
            }
            observed += 1;
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("case-")
                || crate::validate_case_id(&name).is_err()
                || self.case_exists(&name)?
            {
                continue;
            }
            let typ = entry.file_type().map_err(|e| e.to_string())?;
            if !typ.is_dir() || typ.is_symlink() {
                continue;
            }
            let mut count = 0usize;
            let mut examined = 0usize;
            let mut member_scan_truncated = false;
            for member in fs::read_dir(entry.path()).map_err(|e| e.to_string())? {
                if examined >= 256 {
                    member_scan_truncated = true;
                    break;
                }
                examined += 1;
                let member = member.map_err(|e| e.to_string())?;
                if member.file_type().map_err(|e| e.to_string())?.is_file() {
                    count += 1;
                }
            }
            folders.push(UnregisteredCaseFolder {
                case_id: name,
                member_count: count,
                member_scan_truncated,
            });
        }
        Ok(UnregisteredCaseReview { folders, truncated })
    }
}

//! Stable storage selection across the HackTool -> CyberDeck rename.
//! Existing absolute evidence paths must continue to point to their original
//! bytes; never move or duplicate a case database implicitly during upgrade.

use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

fn select_data_dir(new_app_dir: &Path) -> PathBuf {
    let fresh = new_app_dir.join("cyberdeck");
    // Tauri keys app_data_dir by application identifier. For an upgraded app,
    // the previous identifier used the adjacent "dev.hacktool.workbench" path.
    let legacy = new_app_dir.parent()
        .unwrap_or(new_app_dir)
        .join("dev.hacktool.workbench")
        .join("hacktool");
    if !fresh.join("cases.db").exists() && legacy.join("cases.db").is_file() {
        legacy
    } else {
        fresh
    }
}

pub fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(select_data_dir(&app_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgraded_install_keeps_existing_absolute_evidence_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("dev.hacktool.workbench/hacktool");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("cases.db"), b"existing").unwrap();
        let chosen = select_data_dir(&tmp.path().join("dev.cyberdeck.workbench"));
        assert_eq!(chosen, legacy);
        let fresh = tmp.path().join("dev.cyberdeck.workbench/cyberdeck");
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(fresh.join("cases.db"), b"new").unwrap();
        assert_eq!(select_data_dir(&tmp.path().join("dev.cyberdeck.workbench")), fresh);
    }
}

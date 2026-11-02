//! Standalone, dependency-free Cargo build policy.
//! Release artifacts never bypass source verification or native compilation.
pub(crate) fn defer_hashcat_on_windows_dev(
    target_os: &str,
    profile: &str,
    override_flag: Option<&str>,
) -> bool {
    target_os == "windows" && profile == "debug" && override_flag != Some("1")
}

/// Avoid touching watched desktop resources on every Cargo build-script run.
/// A changed mtime alone can cause the Tauri development watcher to rebuild.
pub(crate) fn write_if_changed(path: &std::path::Path, contents: &[u8]) -> std::io::Result<bool> {
    if std::fs::read(path).is_ok_and(|previous| previous == contents) {
        return Ok(false);
    }
    std::fs::write(path, contents)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unchanged_generated_resource_is_not_rewritten() {
        let unique = format!(
            "cyberdeck-hashcat-dev-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        assert!(write_if_changed(&path, b"unavailable").unwrap());
        assert!(!write_if_changed(&path, b"unavailable").unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"unavailable");
        assert!(write_if_changed(&path, b"available").unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"available");
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn windows_debug_can_launch_without_optional_native_compiler() {
        assert!(defer_hashcat_on_windows_dev("windows", "debug", None));
        assert!(defer_hashcat_on_windows_dev("windows", "debug", Some("0")));
    }
    #[test]
    fn explicit_opt_in_never_silently_suppresses_compilation() {
        assert!(!defer_hashcat_on_windows_dev("windows", "debug", Some("1")));
    }
    #[test]
    fn all_release_builds_require_native_compilation() {
        for os in ["windows", "linux", "macos"] {
            assert!(!defer_hashcat_on_windows_dev(os, "release", None));
        }
    }
    #[test]
    fn other_platforms_preserve_existing_strict_development_behavior() {
        for os in ["linux", "macos"] {
            assert!(!defer_hashcat_on_windows_dev(os, "debug", None));
        }
    }
}

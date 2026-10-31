//! Shell-free executable lookup for optional external crypto engines.
use std::path::Path;

/// Check PATH directly instead of starting a shell (`sh -c`/`where`).
/// This avoids shell interpretation of command names and extra subprocesses.
pub fn which_exists(binary: &str) -> bool {
    fn runnable(path: &Path) -> bool {
        if !path.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            return path
                .metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0);
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    // Desktop adapter calls this with `hashcat` or `john`, while Windows
    // resolves .exe names. Do not spawn a shell or trust PATHEXT scripts.
    let filename = if cfg!(windows) && Path::new(binary).extension().is_none() {
        format!("{binary}.exe")
    } else {
        binary.to_string()
    };
    if filename.contains('/') || filename.contains('\\') {
        return runnable(Path::new(&filename));
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| runnable(&dir.join(&filename)))
}

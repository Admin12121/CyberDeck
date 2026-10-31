//! Per-operation scratch storage for optional external password-audit engines.
//! No Tauri dependency; removes sensitive intermediate files on normal exit.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct ScratchDir(PathBuf);

impl std::ops::Deref for ScratchDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl ScratchDir {
    pub fn create(cache_root: &Path) -> Result<Self, String> {
        let base = cache_root.join("engine-scratch");
        std::fs::create_dir_all(&base)
            .map_err(|e| format!("cannot create engine scratch dir: {e}"))?;
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        for _ in 0..8 {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("cannot read system time: {e}"))?
                .as_nanos();
            let index = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("run-{}-{nonce}-{index}", std::process::id()));
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("cannot create engine scratch directory: {error}")),
            }
        }
        Err("could not allocate unique engine scratch directory".into())
    }

    pub fn write_hash_file(&self, hash: &str) -> Result<PathBuf, String> {
        // User-supplied hash text never becomes a filename component.
        let file = self.join("target.hash");
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut handle = opts.open(&file)
            .map_err(|e| format!("cannot create hash file: {e}"))?;
        handle.write_all(format!("{hash}\n").as_bytes())
            .map_err(|e| format!("cannot write hash file: {e}"))?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn scratch_directory_and_hash_file_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = ScratchDir::create(base.path()).unwrap();
        let file = dir.write_hash_file("ABC").unwrap();
        assert_eq!(std::fs::metadata(&*dir).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o077, 0);
    }

    #[test]
    fn scratch_is_unique_and_removed_on_return() {
        let dir = tempfile::tempdir().unwrap();
        let first;
        {
            let a = ScratchDir::create(dir.path()).unwrap();
            let b = ScratchDir::create(dir.path()).unwrap();
            assert_ne!(a.to_path_buf(), b.to_path_buf());
            first = a.to_path_buf();
            let file = a.write_hash_file("$2b$12$CaseSensitiveEncodedSalt").unwrap();
            assert_eq!(std::fs::read_to_string(&file).unwrap(), "$2b$12$CaseSensitiveEncodedSalt\n");
            assert_eq!(file.file_name().unwrap(), "target.hash");
            assert!(file.exists());
        }
        assert!(!first.exists());
    }
}

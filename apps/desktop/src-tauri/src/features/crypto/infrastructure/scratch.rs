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
                Err(error) => {
                    return Err(format!("cannot create engine scratch directory: {error}"))
                }
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
            use std::os::unix::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut handle = opts
            .open(&file)
            .map_err(|e| format!("cannot create hash file: {e}"))?;
        handle
            .write_all(format!("{hash}\n").as_bytes())
            .map_err(|e| format!("cannot write hash file: {e}"))?;
        Ok(file)
    }

    /// Write the hash input in john's `login:ciphertext` shape with the hash
    /// itself as login. john's `--show` prints `login:plaintext` and falls
    /// back to "?" as the login for bare `ciphertext` lines (vendored john
    /// loader.c:565, `no_username`), which the pair mapping cannot map back
    /// to its target; this keeps the hash inside every extracted pair for
    /// both the exe-spawn and DLL sidecar branches. The pot always stores
    /// `ciphertext:plaintext`, so a login of the hash itself makes --show
    /// print exactly `hash:plaintext`.
    pub fn write_john_hash_file(&self, hash: &str) -> Result<PathBuf, String> {
        let file = self.join("target.hash");
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut handle = opts
            .open(&file)
            .map_err(|e| format!("cannot create hash file: {e}"))?;
        for line in hash.lines().filter(|line| !line.trim().is_empty()) {
            let line = line.trim();
            handle
                .write_all(format!("{line}:{line}\n").as_bytes())
                .map_err(|e| format!("cannot write hash file: {e}"))?;
        }
        handle
            .flush()
            .map_err(|e| format!("cannot write hash file: {e}"))?;
        Ok(file)
    }

    /// Private bounded candidates copy for one recovery sidecar stage:
    /// at most `max_lines` wordlist lines are streamed into the scratch dir,
    /// capping the sidecar at the same candidate budget every native stage
    /// honors. The copy is bounded like the embedded rules expansion (256 MiB
    /// private file cap) and also isolates the run from library file changes.
    /// Returns the copy path and the exact candidate count it holds.
    pub fn write_bounded_candidates(
        &self,
        source: &Path,
        max_lines: u64,
    ) -> Result<(PathBuf, u64), String> {
        use std::io::{BufRead, BufReader, BufWriter, Write as _};
        const MAX_CANDIDATE_FILE_BYTES: u64 = 256 << 20;
        let input = std::fs::File::open(source).map_err(|e| format!("cannot read wordlist: {e}"))?;
        let mut reader = BufReader::with_capacity(1 << 20, input);
        let path = self.join("sidecar-candidates.words");
        let file =
            std::fs::File::create(&path).map_err(|e| format!("cannot create candidates file: {e}"))?;
        let mut writer = BufWriter::with_capacity(1 << 20, file);
        let mut lines = 0u64;
        let mut bytes = 0u64;
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    bytes += read as u64;
                    if bytes > MAX_CANDIDATE_FILE_BYTES {
                        return Err(
                            "sidecar candidates copy exceeds the 256 MiB private file cap".into(),
                        );
                    }
                    writer
                        .write_all(&buffer)
                        .map_err(|e| format!("cannot write candidates file: {e}"))?;
                    lines += 1;
                    if lines >= max_lines {
                        break;
                    }
                }
                Err(error) => return Err(format!("cannot copy wordlist: {error}")),
            }
        }
        writer
            .flush()
            .map_err(|e| format!("cannot write candidates file: {e}"))?;
        if lines == 0 {
            return Err("wordlist has no candidates for the sidecar stage".into());
        }
        Ok((path, lines))
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
        assert_eq!(
            std::fs::metadata(&*dir).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o077,
            0
        );
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
            let file = a
                .write_hash_file("$2b$12$CaseSensitiveEncodedSalt")
                .unwrap();
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                "$2b$12$CaseSensitiveEncodedSalt\n"
            );
            assert_eq!(file.file_name().unwrap(), "target.hash");
            assert!(file.exists());
        }
        assert!(!first.exists());
    }

    #[test]
    fn john_hash_file_carries_the_hash_as_its_own_login() {
        let base = tempfile::tempdir().unwrap();
        let dir = ScratchDir::create(base.path()).unwrap();
        let file = dir
            .write_john_hash_file("$1$cddeck$abc\n\n$gy$j9T$two\n")
            .unwrap();
        assert_eq!(file.file_name().unwrap(), "target.hash");
        // login:ciphertext per line, blanks dropped — john --show then prints
        // hash:plaintext pairs (loader.c:565 prints "?" for bare ciphertexts).
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "$1$cddeck$abc:$1$cddeck$abc\n$gy$j9T$two:$gy$j9T$two\n"
        );
    }
}

//! Immutable evidence verification and bounded reads from the same opened handle.
//! This is an additive contract; existing verification remains compatible.
use crate::{validate_case_id, ArtifactRecord};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Full-content verified, case-contained file handle. The underlying File is
/// intentionally private so callers cannot reopen an unchecked pathname.
#[derive(Debug)]
pub struct VerifiedArtifactHandle {
    file: File,
    size: u64,
}

impl VerifiedArtifactHandle {
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Seek and read only a caller-bounded window from the verified descriptor.
    /// Caller is also capped to 16 MiB per operation.
    pub fn read_window(&mut self, offset: u64, len: usize, max: usize) -> Result<Vec<u8>, String> {
        if len > max || len > 16 * 1024 * 1024 {
            return Err("verified evidence read exceeds window limit".into());
        }
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| "verified evidence offset overflow".to_string())?;
        if offset > self.size || end > self.size {
            return Err("verified evidence read exceeds indexed size".into());
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| format!("cannot seek verified evidence: {e}"))?;
        let mut bytes = vec![0_u8; len];
        self.file
            .read_exact(&mut bytes)
            .map_err(|e| format!("cannot read verified evidence: {e}"))?;
        Ok(bytes)
    }
}

pub(super) fn verified_file(
    mut file: File,
    record: &ArtifactRecord,
) -> Result<VerifiedArtifactHandle, String> {
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat evidence descriptor: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("evidence handle is not a regular file".into());
    }
    if metadata.len() != record.size {
        return Err(
            "evidence size integrity failure: opened file differs from indexed size".into(),
        );
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut count = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot hash opened evidence: {e}"))?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| "evidence size overflow".to_string())?;
        if count > record.size {
            return Err("evidence changed while being verified".into());
        }
        hash.update(&buffer[..read]);
    }
    if count != record.size
        || !format!("{:x}", hash.finalize()).eq_ignore_ascii_case(&record.sha256)
    {
        return Err("evidence SHA-256 or size integrity failure".into());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("cannot rewind verified evidence: {e}"))?;
    Ok(VerifiedArtifactHandle {
        file,
        size: record.size,
    })
}

fn contained_leaf(record: &ArtifactRecord, root: &Path) -> Result<(PathBuf, String), String> {
    validate_case_id(&record.case_id)?;
    let canonical_root =
        std::fs::canonicalize(root).map_err(|e| format!("cannot resolve evidence root: {e}"))?;
    let case_dir = canonical_root.join(&record.case_id);
    let stored = Path::new(&record.stored_path);
    if stored.parent() != Some(case_dir.as_path()) {
        return Err("evidence pathname is not a direct case member".into());
    }
    let name = stored
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "invalid evidence member name".to_string())?;
    if name.is_empty() || name == "." || name == ".." {
        return Err("invalid evidence member name".into());
    }
    Ok((canonical_root, name.to_owned()))
}

/// Open case and member through anchored no-follow directory descriptors,
/// then verify the exact file descriptor subsequently used for window reads.
///
/// A concurrently modified *in-place* file is not made immutable by an open
/// descriptor; immutable publication/OS permissions remain a separate rule.
#[cfg(unix)]
pub fn open_verified_case_artifact(
    record: &ArtifactRecord,
    root: &Path,
) -> Result<VerifiedArtifactHandle, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let (canonical_root, leaf) = contained_leaf(record, root)?;
    if std::fs::symlink_metadata(root)
        .map_err(|e| format!("cannot inspect evidence root: {e}"))?
        .file_type()
        .is_symlink()
    {
        return Err("evidence root may not be a symlink".into());
    }
    let root_c = CString::new(canonical_root.as_os_str().as_bytes())
        .map_err(|_| "invalid evidence root path".to_string())?;
    let case_c = CString::new(record.case_id.as_bytes())
        .map_err(|_| "invalid evidence case path".to_string())?;
    let leaf_c =
        CString::new(leaf.as_bytes()).map_err(|_| "invalid evidence file name".to_string())?;
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let file_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;

    // SAFETY: CStrings are NUL terminated; successful file descriptors are
    // immediately transferred to File and closed by RAII.
    let root_fd = unsafe { libc::open(root_c.as_ptr(), dir_flags) };
    if root_fd < 0 {
        return Err(format!(
            "cannot open anchored evidence root: {}",
            std::io::Error::last_os_error()
        ));
    }
    let root_file = unsafe { File::from_raw_fd(root_fd) };
    let case_fd = unsafe { libc::openat(root_file.as_raw_fd(), case_c.as_ptr(), dir_flags) };
    if case_fd < 0 {
        return Err(format!(
            "cannot open anchored case directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    let case_file = unsafe { File::from_raw_fd(case_fd) };
    let member_fd = unsafe { libc::openat(case_file.as_raw_fd(), leaf_c.as_ptr(), file_flags) };
    if member_fd < 0 {
        return Err(format!(
            "cannot open anchored evidence member: {}",
            std::io::Error::last_os_error()
        ));
    }
    let member = unsafe { File::from_raw_fd(member_fd) };
    verified_file(member, record)
}

/// Never silently fall back to an unconfined pathname open on Windows.
/// The existing verification API stays available until a native reparse-aware
/// open-by-handle adapter receives its Windows security tests.
#[cfg(all(windows, feature = "experimental-windows-handle"))]
pub fn open_verified_case_artifact(
    record: &ArtifactRecord,
    root: &Path,
) -> Result<VerifiedArtifactHandle, String> {
    super::windows_verified_handle::open_windows_verified_case_artifact(record, root)
}

#[cfg(not(any(unix, all(windows, feature = "experimental-windows-handle"))))]
pub fn open_verified_case_artifact(
    _record: &ArtifactRecord,
    _root: &Path,
) -> Result<VerifiedArtifactHandle, String> {
    Err("verified anchored evidence handles require a platform adapter".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CASE;

    fn sample(root: &Path, name: &str, bytes: &[u8]) -> ArtifactRecord {
        let case = root.join(DEFAULT_CASE);
        std::fs::create_dir_all(&case).unwrap();
        let path = case.join(name);
        std::fs::write(&path, bytes).unwrap();
        ArtifactRecord {
            id: "artifact-1".into(),
            case_id: DEFAULT_CASE.into(),
            name: name.into(),
            stored_path: path.to_string_lossy().into_owned(),
            original_path: None,
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            md5: String::new(),
            sha1: String::new(),
            crc32: String::new(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn verified_windows_are_bounded_and_survive_pathname_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let record = sample(&root, "one.evidence", b"immutable sample");
        let mut handle = open_verified_case_artifact(&record, &root).unwrap();
        assert_eq!(handle.read_window(4, 6, 6).unwrap(), b"table ");
        assert!(handle.read_window(0, 16, 4).is_err());
        assert!(handle.read_window(14, 4, 8).is_err());
        let path = Path::new(&record.stored_path);
        std::fs::rename(path, path.with_extension("previous")).unwrap();
        std::fs::write(path, b"replaced").unwrap();
        // The handle is pinned to the verified original, not the path.
        assert_eq!(handle.read_window(0, 16, 16).unwrap(), b"immutable sample");
        assert!(open_verified_case_artifact(&record, &root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn changed_evidence_size_and_digest_fail_with_integrity_diagnostics() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let bytes = b"immutable original";
        let record = sample(&root, "length.evidence", bytes);
        let path = Path::new(&record.stored_path);

        std::fs::write(path, b"short").unwrap();
        let too_short = open_verified_case_artifact(&record, &root).unwrap_err();
        assert!(too_short.contains("integrity"), "{too_short}");
        assert!(too_short.contains("size"), "{too_short}");

        std::fs::write(path, b"longer than immutable original").unwrap();
        let too_long = open_verified_case_artifact(&record, &root).unwrap_err();
        assert!(too_long.contains("integrity"), "{too_long}");
        assert!(too_long.contains("size"), "{too_long}");

        let mut altered = bytes.to_vec();
        altered[0] ^= 0x20;
        std::fs::write(path, altered).unwrap();
        let digest_mismatch = open_verified_case_artifact(&record, &root).unwrap_err();
        assert!(digest_mismatch.contains("integrity"), "{digest_mismatch}");
        assert!(digest_mismatch.contains("SHA-256"), "{digest_mismatch}");

        std::fs::remove_file(path).unwrap();
        std::fs::create_dir(path).unwrap();
        let unsafe_file_type = open_verified_case_artifact(&record, &root).unwrap_err();
        assert!(
            unsafe_file_type.contains("regular file"),
            "{unsafe_file_type}"
        );
        assert!(
            !unsafe_file_type.contains("integrity"),
            "{unsafe_file_type}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_case_or_member_cannot_escape_the_anchor() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let record = sample(&root, "one.evidence", b"secret");
        std::fs::remove_file(&record.stored_path).unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"secret").unwrap();
        symlink(&outside, &record.stored_path).unwrap();
        assert!(open_verified_case_artifact(&record, &root).is_err());
        std::fs::remove_dir_all(root.join(DEFAULT_CASE)).unwrap();
        symlink(temp.path(), root.join(DEFAULT_CASE)).unwrap();
        assert!(open_verified_case_artifact(&record, &root).is_err());
    }
}

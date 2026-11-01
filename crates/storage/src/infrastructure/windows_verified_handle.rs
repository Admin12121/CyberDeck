//! Native Windows NTFS evidence access using parent-relative NT handles.
//! Security acceptance requires actual Windows NTFS runtime tests.
#![cfg(windows)]
use super::verified_handle::{verified_file, VerifiedArtifactHandle};
use crate::ArtifactRecord;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr;

const ATTR_REPARSE: u32 = 0x400;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_DONT_REPARSE: u32 = 0x1000;
const READ_DATA: u32 = 0x1;
const READ_ATTRIBUTES: u32 = 0x80;
const TRAVERSE: u32 = 0x20;
const SYNCHRONIZE: u32 = 0x0010_0000;
const SHARE_READ: u32 = 0x1;
const OPEN_EXISTING: u32 = 0x1;
const DIRECTORY: u32 = 0x1;
const NON_DIRECTORY: u32 = 0x40;
const SYNC_NONALERT: u32 = 0x20;
const BACKUP_INTENT: u32 = 0x4000;
const OPEN_REPARSE: u32 = 0x0020_0000;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}
#[repr(C)]
struct IoStatusBlock {
    status_or_pointer: usize,
    information: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct FileTime {
    low: u32,
    high: u32,
}
#[repr(C)]
struct ByHandleFileInformation {
    attributes: u32,
    created: FileTime,
    last_access: FileTime,
    last_write: FileTime,
    volume_serial_number: u32,
    size_high: u32,
    size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(handle: *mut c_void, info: *mut ByHandleFileInformation) -> i32;
}

fn nt_open(parent: Option<&File>, name: &OsStr, directory: bool) -> Result<File, String> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    if wide.is_empty() || wide.contains(&0) || wide.len() > (u16::MAX as usize / 2 - 1) {
        return Err("invalid Windows evidence NT object name".into());
    }
    let len = (wide.len() * 2) as u16;
    let mut unicode = UnicodeString {
        length: len,
        maximum_length: len,
        buffer: wide.as_mut_ptr(),
    };
    let mut attrs = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent.map_or(ptr::null_mut(), |f| f.as_raw_handle().cast()),
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };
    let mut ios = IoStatusBlock {
        status_or_pointer: 0,
        information: 0,
    };
    let mut handle = ptr::null_mut();
    let access = READ_ATTRIBUTES | SYNCHRONIZE | if directory { TRAVERSE } else { READ_DATA };
    let options = SYNC_NONALERT
        | OPEN_REPARSE
        | if directory {
            DIRECTORY | BACKUP_INTENT
        } else {
            NON_DIRECTORY
        };
    // SAFETY: All counted UTF16/NT structs live across this call; on success
    // the newly owned HANDLE is transferred immediately to File for Drop.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &mut attrs,
            &mut ios,
            ptr::null_mut(),
            0,
            SHARE_READ,
            OPEN_EXISTING,
            options,
            ptr::null_mut(),
            0,
        )
    };
    if status < 0 || handle.is_null() {
        return Err(format!(
            "cannot open anchored Windows evidence: NTSTATUS 0x{:08x}",
            status as u32
        ));
    }
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn no_reparse(file: &File, directory: bool) -> Result<(), String> {
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot inspect NT evidence handle: {e}"))?;
    if meta.file_attributes() & ATTR_REPARSE != 0 {
        return Err("Windows evidence junction or reparse point rejected".into());
    }
    if meta.is_dir() != directory {
        return Err("Windows evidence opened descriptor type mismatch".into());
    }
    Ok(())
}

fn verify_identity(file: &File) -> Result<(), String> {
    let mut info = MaybeUninit::<ByHandleFileInformation>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(format!(
            "Windows evidence identity unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let info = unsafe { info.assume_init() };
    if info.attributes & ATTR_REPARSE != 0 || info.number_of_links != 1 {
        return Err("Windows evidence reparse or hard-linked file rejected".into());
    }
    if info.file_index_low == 0 && info.file_index_high == 0 && info.volume_serial_number == 0 {
        return Err("Windows evidence file identity unavailable".into());
    }
    Ok(())
}

fn local_root(root: &Path) -> Result<(PathBuf, OsString), String> {
    if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("Windows evidence root must be absolute without parent traversal".into());
    }
    let path = std::path::absolute(root).map_err(|e| format!("invalid evidence root: {e}"))?;
    let name = path.to_string_lossy();
    let disk_path = name.strip_prefix(r"\\?\").unwrap_or(&name);
    let bytes = disk_path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err("Windows evidence roots must use a local drive, not UNC/device paths".into());
    }
    Ok((path, OsString::from(format!(r"\??\{disk_path}"))))
}

/// Open the verified file through root -> case -> member NT directory handles.
/// No unverified pathname fallback; do not advertise until Windows tests pass.
pub(super) fn open_windows_verified_case_artifact(
    record: &ArtifactRecord,
    root: &Path,
) -> Result<VerifiedArtifactHandle, String> {
    crate::validate_case_id(&record.case_id)?;
    let (root_path, nt_name) = local_root(root)?;
    let path = std::path::absolute(&record.stored_path)
        .map_err(|e| format!("invalid indexed Windows evidence path: {e}"))?;
    if path.parent() != Some(root_path.join(&record.case_id).as_path()) {
        return Err("indexed Windows evidence is not a direct selected-case member".into());
    }
    let leaf = path
        .file_name()
        .ok_or("missing Windows evidence member name")?;
    if leaf.is_empty() || leaf == OsStr::new(".") || leaf == OsStr::new("..") {
        return Err("invalid Windows evidence member".into());
    }
    let root_fd = nt_open(None, &nt_name, true)?;
    no_reparse(&root_fd, true)?;
    let case_fd = nt_open(Some(&root_fd), OsStr::new(&record.case_id), true)?;
    no_reparse(&case_fd, true)?;
    let file = nt_open(Some(&case_fd), leaf, false)?;
    no_reparse(&file, false)?;
    verify_identity(&file)?;
    verified_file(file, record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn fixture(root: &Path, data: &[u8]) -> ArtifactRecord {
        let path = root.join(crate::DEFAULT_CASE).join("evidence-証拠.bin");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, data).unwrap();
        ArtifactRecord {
            id: "ntfs-1".into(),
            case_id: crate::DEFAULT_CASE.into(),
            name: "evidence".into(),
            stored_path: path.to_string_lossy().into_owned(),
            original_path: None,
            size: data.len() as u64,
            sha256: format!("{:x}", Sha256::digest(data)),
            md5: String::new(),
            sha1: String::new(),
            crc32: String::new(),
            signature: None,
            entropy: 0.0,
            imported_at: "1".into(),
        }
    }
    #[test]
    fn ntfs_same_handle_window_and_size_tamper() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let record = fixture(&root, b"sample");
        let mut fd = open_windows_verified_case_artifact(&record, &root).unwrap();
        assert_eq!(fd.read_window(0, 6, 6).unwrap(), b"sample");
        assert!(fd.read_window(5, 2, 10).is_err());
        assert!(std::fs::write(&record.stored_path, b"changed").is_err());
        drop(fd);
        std::fs::write(&record.stored_path, b"changed").unwrap();
        assert!(open_windows_verified_case_artifact(&record, &root)
            .unwrap_err()
            .contains("integrity"));
    }
    #[test]
    fn ntfs_reparse_member_and_case_directory_rejected() {
        use std::os::windows::fs::{symlink_dir, symlink_file};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let record = fixture(&root, b"secret");
        let outside = temp.path().join("outside.bin");
        std::fs::write(&outside, b"secret").unwrap();
        std::fs::remove_file(&record.stored_path).unwrap();
        match symlink_file(&outside, &record.stored_path) {
            Ok(()) => assert!(open_windows_verified_case_artifact(&record, &root).is_err()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("NTFS symlink test needs Developer Mode or symlink privilege: {e}");
                return;
            }
            Err(e) => panic!("NTFS symlink setup failed: {e}"),
        }
        std::fs::remove_file(&record.stored_path).unwrap();
        let case = root.join(crate::DEFAULT_CASE);
        std::fs::remove_dir(&case).unwrap();
        // Make the outside reparse target contain valid matching evidence,
        // so accidental junction following would otherwise return data.
        std::fs::write(temp.path().join("evidence-証拠.bin"), b"secret").unwrap();
        match symlink_dir(temp.path(), &case) {
            Ok(()) => assert!(open_windows_verified_case_artifact(&record, &root).is_err()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("NTFS case symlink test needs symlink privilege: {e}");
            }
            Err(e) => panic!("NTFS case symlink setup failed: {e}"),
        }
    }
    #[test]
    fn ntfs_open_descriptor_rejects_path_replacement_until_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let record = fixture(&root, b"unchanged");
        let mut handle = open_windows_verified_case_artifact(&record, &root).unwrap();
        let old = Path::new(&record.stored_path);
        let moved = old.with_extension("previous");
        assert!(std::fs::rename(old, &moved).is_err());
        assert_eq!(handle.read_window(0, 9, 9).unwrap(), b"unchanged");
        drop(handle);
        std::fs::rename(old, &moved).unwrap();
        std::fs::write(old, b"otherdata").unwrap();
        assert!(open_windows_verified_case_artifact(&record, &root).is_err());
    }

    #[test]
    fn ntfs_hardlink_outside_case_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("artifacts");
        let record = fixture(&root, b"secret");
        let outside = temp.path().join("outside.bin");
        std::fs::hard_link(&record.stored_path, &outside).unwrap();
        assert!(open_windows_verified_case_artifact(&record, &root).is_err());
    }
}

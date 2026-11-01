//! Single source of truth for local wordlist selection, metadata and limits.
use std::path::Path;

use crate::features::forensics::ipc::evidence::MAX_IMPORT_BYTES;

pub fn inspect(path: &Path) -> Result<(String, u64), String> {
    let meta =
        std::fs::metadata(path).map_err(|e| format!("selected wordlist is unreadable: {e}"))?;
    if !meta.is_file() {
        return Err("selected wordlist must be a regular file".into());
    }
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "wordlist is {} MB; the limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wordlist.txt".into());
    Ok((name, meta.len()))
}

/// Count logical LF-delimited candidate lines with constant memory.
/// Repeated files are read twice (count, then verify) to retain exact UI totals
/// without materializing the dictionary.
pub fn count_lines(path: &Path) -> Result<u64, String> {
    use std::io::BufRead as _;

    let file = std::fs::File::open(path).map_err(|e| format!("cannot open wordlist: {e}"))?;
    let mut reader = std::io::BufReader::with_capacity(1 << 20, file);
    let mut total = 0u64;
    let mut trailing = false;
    loop {
        let bytes = reader.fill_buf().map_err(|e| format!("read error: {e}"))?;
        if bytes.is_empty() {
            break;
        }
        total = total.saturating_add(bytes.iter().filter(|&&b| b == b'\n').count() as u64);
        trailing = bytes.last() != Some(&b'\n');
        let len = bytes.len();
        reader.consume(len);
    }
    Ok(total.saturating_add(u64::from(trailing)))
}

/// Read only the nonempty wordlist prefix consumed by hybrid/combinator use
/// cases. Returns LF-separated UTF-8 bytes for their existing byte API.
pub fn read_nonempty_prefix(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path).map_err(|e| format!("cannot read wordlist: {e}"))?;
    let reader = std::io::BufReader::with_capacity(1 << 20, file);
    let mut output = Vec::new();
    let mut count = 0usize;
    for candidate in cyberdeck_crypto::candidates::WordlistCandidates::new(reader) {
        let bytes = candidate?;
        let word = String::from_utf8_lossy(&bytes);
        let word = word.trim_end_matches(char::is_control);
        if word.is_empty() {
            continue;
        }
        output.extend_from_slice(word.as_bytes());
        output.push(b'\n');
        count += 1;
        if count >= limit {
            break;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_reader_selects_first_nonempty_candidates_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hybrid.txt");
        std::fs::write(&path, b"\nfirst\n\nsecond\nthird\n").unwrap();
        assert_eq!(read_nonempty_prefix(&path, 2).unwrap(), b"first\nsecond\n");
    }

    #[test]
    fn prefix_reader_never_touches_oversized_content_after_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-tail.txt");
        let mut body = b"word\n".repeat(500);
        body.extend(vec![b'x'; 8192]);
        std::fs::write(&path, body).unwrap();
        let result = read_nonempty_prefix(&path, 500).unwrap();
        assert_eq!(result, b"word\n".repeat(500));
    }

    #[test]
    fn zero_limit_never_opens_or_reads_a_file() {
        assert!(read_nonempty_prefix(Path::new("/not/a/real/file"), 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn line_count_is_byte_safe_including_unterminated_last_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lines.dat");
        std::fs::write(&path, b"first\n\xff\nthird").unwrap();
        assert_eq!(count_lines(&path).unwrap(), 3);
        std::fs::write(&path, b"").unwrap();
        assert_eq!(count_lines(&path).unwrap(), 0);
        std::fs::write(&path, b"\n").unwrap();
        assert_eq!(count_lines(&path).unwrap(), 1);
    }

    #[test]
    fn metadata_rejects_missing_and_nonregular_files() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(inspect(tmp.path()).is_err());
        assert!(inspect(&tmp.path().join("missing.txt")).is_err());
    }

    #[test]
    fn metadata_does_not_load_wordlist_into_memory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("candidates.txt");
        std::fs::write(&path, b"secret\n").unwrap();
        let (name, bytes) = inspect(&path).unwrap();
        assert_eq!(name, "candidates.txt");
        assert_eq!(bytes, 7);
    }
}

//! Bounded filesystem adapter for a user-selected offline packet capture.
use std::io::Read;
use std::path::Path;

const MAX_PCAP_FILE: u64 = 200 * 1024 * 1024;

/// Preserve the existing import size policy and error messages.
pub(super) fn read_capture(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read capture metadata: {e}"))?;
    if meta.len() > MAX_PCAP_FILE {
        return Err(format!(
            "capture is {} MB; the open limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_PCAP_FILE / (1024 * 1024)
        ));
    }
    // A selected file may grow after metadata inspection. Bound actual I/O,
    // including the single extra byte needed to identify an over-limit file.
    let file = std::fs::File::open(path).map_err(|e| format!("cannot read capture: {e}"))?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_PCAP_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read capture: {e}"))?;
    if bytes.len() as u64 > MAX_PCAP_FILE {
        return Err(format!(
            "capture is {} MB; the open limit this arc is {} MB",
            bytes.len() as u64 / (1024 * 1024),
            MAX_PCAP_FILE / (1024 * 1024)
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn file_read_keeps_original_bytes_and_rejects_large_metadata() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cyberdeck-packet-import-{}-{stamp}.pcap",
            std::process::id()
        ));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_PCAP_FILE + 1).unwrap();
        drop(file);
        assert!(read_capture(&path)
            .unwrap_err()
            .contains("open limit this arc"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let original = [0u8, 1, 127, 128, 255, 0, 10];
        file.write_all(&original).unwrap();
        drop(file);
        let bytes = read_capture(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(bytes, original);
    }
}

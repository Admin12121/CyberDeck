//! Bounded native Gzip extraction for forensic artifacts.
//! Never trusts embedded names or paths; callers choose the stored output name.

use std::io::Read;

pub const MAX_GZIP_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_GZIP_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

pub fn extract_gzip_limited(
    input: &[u8],
    offset: usize,
    max_output: usize,
) -> Result<Vec<u8>, String> {
    let data = input
        .get(offset..)
        .ok_or("gzip offset exceeds file length")?;
    if !data.starts_with(b"\x1f\x8b\x08") {
        return Err("gzip signature missing or unsupported compression method".into());
    }
    if data.len() > MAX_GZIP_INPUT_BYTES {
        return Err("gzip input exceeds 16 MiB limit".into());
    }
    if max_output == 0 || max_output > MAX_GZIP_OUTPUT_BYTES {
        return Err("invalid gzip output limit".into());
    }
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut output = Vec::new();
    decoder
        .by_ref()
        .take((max_output as u64) + 1)
        .read_to_end(&mut output)
        .map_err(|err| format!("gzip integrity or decoding error: {err}"))?;
    if output.len() > max_output {
        return Err("gzip output exceeds decompression safety limit".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use std::io::Write;

    fn zipped(content: &[u8]) -> Vec<u8> {
        let mut writer = flate2::write::GzEncoder::new(Vec::new(), Compression::fast());
        writer.write_all(content).unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn embedded_gzip_roundtrip() {
        let compressed = zipped(b"test artifact");
        let mut input = b"firmware-prefix".to_vec();
        let offset = input.len();
        input.extend(&compressed);
        assert_eq!(
            extract_gzip_limited(&input, offset, 4096).unwrap(),
            b"test artifact"
        );
    }

    #[test]
    fn rejects_bombs_bad_offsets_and_corrupted_checksum() {
        let compressed = zipped(&[b'A'; 8192]);
        assert!(extract_gzip_limited(&compressed, 0, 128)
            .unwrap_err()
            .contains("limit"));
        assert!(extract_gzip_limited(&compressed, 50000, 4096).is_err());
        assert!(extract_gzip_limited(b"not gzip", 0, 4096).is_err());
        let mut damaged = zipped(b"checksum");
        let len = damaged.len();
        damaged[len - 8] ^= 1;
        assert!(extract_gzip_limited(&damaged, 0, 4096).is_err());
    }
}

//! Bounded native Gzip extraction for forensic artifacts.
//! Never trusts embedded names or paths; callers choose the stored output name.

#[path = "nested.rs"]
pub mod nested;

use std::io::Read;

pub const MAX_GZIP_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_GZIP_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzipMember {
    pub bytes: Vec<u8>,
    /// Compressed bytes consumed; excludes any embedded bytes after the member.
    pub consumed_bytes: usize,
}

pub fn extract_gzip_limited(
    input: &[u8],
    offset: usize,
    max_output: usize,
) -> Result<Vec<u8>, String> {
    Ok(extract_gzip_member_limited(input, offset, max_output)?.bytes)
}

pub fn extract_gzip_member_limited(
    input: &[u8],
    offset: usize,
    max_output: usize,
) -> Result<GzipMember, String> {
    let data = input
        .get(offset..)
        .ok_or("gzip offset exceeds file length")?;
    if data.len() < 10 || !data.starts_with(b"\x1f\x8b\x08") || data[3] & 0xe0 != 0 {
        return Err("gzip signature missing or unsupported compression method".into());
    }
    if data.len() > MAX_GZIP_INPUT_BYTES {
        return Err("gzip input exceeds 16 MiB limit".into());
    }
    if max_output == 0 || max_output > MAX_GZIP_OUTPUT_BYTES {
        return Err("invalid gzip output limit".into());
    }
    let mut decoder = flate2::bufread::GzDecoder::new(data);
    let mut output = Vec::new();
    decoder
        .by_ref()
        .take((max_output as u64) + 1)
        .read_to_end(&mut output)
        .map_err(|err| format!("gzip integrity or decoding error: {err}"))?;
    if output.len() > max_output {
        return Err("gzip output exceeds decompression safety limit".into());
    }
    let consumed_bytes = data.len() - decoder.get_ref().len();
    if consumed_bytes == 0 {
        return Err("gzip member consumed no input".into());
    }
    Ok(GzipMember {
        bytes: output,
        consumed_bytes,
    })
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
    fn member_extraction_preserves_trailing_embedded_data() {
        let compressed = zipped(b"first member");
        let mut blob = compressed.clone();
        blob.extend_from_slice(b"next embedded file");
        let member = extract_gzip_member_limited(&blob, 0, 4096).unwrap();
        assert_eq!(member.bytes, b"first member");
        assert_eq!(member.consumed_bytes, compressed.len());
        assert_eq!(&blob[member.consumed_bytes..], b"next embedded file");
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

// Native, bounded ZIP/TAR extraction. Archive names never become disk paths.
// The caller stores extracted byte buffers under controlled evidence IDs.
use std::collections::HashSet;

pub const MAX_ARCHIVE_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ARCHIVE_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 128;
pub const MAX_ARCHIVE_PATH_BYTES: usize = 240;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEntry {
    pub path: String,
    pub bytes: Vec<u8>,
    pub source_offset: u64,
}

fn checked_slice(data: &[u8], at: usize, len: usize) -> Result<&[u8], String> {
    data.get(at..at.checked_add(len).ok_or("archive offset overflow")?)
        .ok_or_else(|| "truncated archive structure".into())
}
fn le16(data: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        checked_slice(data, at, 2)?.try_into().unwrap(),
    ))
}
fn le32(data: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        checked_slice(data, at, 4)?.try_into().unwrap(),
    ))
}

fn archive_path(raw: &[u8]) -> Result<String, String> {
    if raw.is_empty() || raw.len() > MAX_ARCHIVE_PATH_BYTES {
        return Err("empty or oversized archive entry path".into());
    }
    let s = std::str::from_utf8(raw).map_err(|_| "archive path is not UTF-8")?;
    if s.starts_with('/')
        || s.contains('\\')
        || s.contains(':')
        || s.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err("unsafe archive entry path".into());
    }
    let path = s.trim_end_matches('/');
    if path.is_empty()
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("unsafe archive entry path component".into());
    }
    Ok(path.to_string())
}

fn extraction_limits(data_len: usize, max_output: usize) -> Result<(), String> {
    if data_len > MAX_ARCHIVE_INPUT_BYTES
        || max_output == 0
        || max_output > MAX_ARCHIVE_OUTPUT_BYTES
    {
        return Err("archive input or output exceeds safety limit".into());
    }
    Ok(())
}

/// Ordinary ZIP archives with stored/DEFLATE files. Reject encryption, ZIP64,
/// multi-disk, links, ambiguous paths and malformed central/local headers.
pub fn extract_zip_limited(
    input: &[u8],
    offset: usize,
    max_output: usize,
) -> Result<Vec<ExtractedEntry>, String> {
    let data = input.get(offset..).ok_or("ZIP offset exceeds input")?;
    extraction_limits(data.len(), max_output)?;
    if !data.starts_with(b"PK\x03\x04") && !data.starts_with(b"PK\x05\x06") {
        return Err("ZIP signature missing".into());
    }
    // An embedded archive may have unrelated firmware bytes after its EOCD.
    let mut eocd = None;
    for i in 0..data.len().saturating_sub(21) {
        if &data[i..i + 4] != b"PK\x05\x06" {
            continue;
        }
        let comment = le16(data, i + 20)? as usize;
        let end = i.checked_add(22).and_then(|n| n.checked_add(comment));
        if end.is_none_or(|n| n > data.len()) {
            continue;
        }
        if (le32(data, i + 16)? as usize).checked_add(le32(data, i + 12)? as usize) == Some(i) {
            eocd = Some(i);
            break;
        }
    }
    let end = eocd.ok_or("ZIP central directory/EOCD missing")?;
    if le16(data, end + 4)? != 0 || le16(data, end + 6)? != 0 {
        return Err("multipart ZIP unsupported".into());
    }
    let count = le16(data, end + 10)?;
    if le16(data, end + 8)? != count || count == u16::MAX || count as usize > MAX_ARCHIVE_ENTRIES {
        return Err("ZIP64, multipart or oversized ZIP index unsupported".into());
    }
    let cd_start = le32(data, end + 16)? as usize;
    let cd_size = le32(data, end + 12)? as usize;
    if cd_start == u32::MAX as usize
        || cd_size == u32::MAX as usize
        || cd_start.checked_add(cd_size) != Some(end)
    {
        return Err("ZIP64 or inconsistent central directory".into());
    }

    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut used = 0usize;
    let mut pos = cd_start;
    for _ in 0..count {
        if checked_slice(data, pos, 4)? != b"PK\x01\x02" {
            return Err("bad ZIP central directory entry".into());
        }
        let made_by = le16(data, pos + 4)?;
        let flags = le16(data, pos + 8)?;
        let method = le16(data, pos + 10)?;
        let crc = le32(data, pos + 16)?;
        let packed = le32(data, pos + 20)? as usize;
        let unpacked = le32(data, pos + 24)? as usize;
        let name_len = le16(data, pos + 28)? as usize;
        let extra_len = le16(data, pos + 30)? as usize;
        let comment_len = le16(data, pos + 32)? as usize;
        let disk = le16(data, pos + 34)?;
        let unix_mode = le32(data, pos + 38)? >> 16;
        let local = le32(data, pos + 42)? as usize;
        let record_len = 46usize
            .checked_add(name_len)
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len))
            .ok_or("ZIP central entry length overflow")?;
        let record = checked_slice(data, pos, record_len)?;
        if pos.checked_add(record_len).is_none_or(|n| n > end) {
            return Err("ZIP central directory entry beyond EOCD".into());
        }
        let name = &record[46..46 + name_len];
        let path = archive_path(name)?;
        if !seen.insert(path.to_ascii_lowercase()) {
            return Err("duplicate ZIP entry path".into());
        }
        if flags & (1 | 0x40 | 0x2000) != 0 {
            return Err("encrypted ZIP unsupported".into());
        }
        if method != 0 && method != 8 {
            return Err("unsupported ZIP compression method".into());
        }
        if disk != 0
            || packed == u32::MAX as usize
            || unpacked == u32::MAX as usize
            || local == u32::MAX as usize
        {
            return Err("ZIP64 or multipart file unsupported".into());
        }
        if made_by >> 8 == 3 {
            let kind = unix_mode & 0o170000;
            if kind != 0 && kind != 0o100000 && kind != 0o040000 {
                return Err("ZIP links and special files forbidden".into());
            }
        }
        if local >= cd_start || checked_slice(data, local, 4)? != b"PK\x03\x04" {
            return Err("invalid ZIP local header".into());
        }
        if le16(data, local + 6)? != flags || le16(data, local + 8)? != method {
            return Err("conflicting ZIP local and central headers".into());
        }
        let local_name_len = le16(data, local + 26)? as usize;
        let local_extra_len = le16(data, local + 28)? as usize;
        if checked_slice(data, local + 30, local_name_len)? != name {
            return Err("ZIP local and central filenames differ".into());
        }
        let payload_start = local
            .checked_add(30)
            .and_then(|n| n.checked_add(local_name_len))
            .and_then(|n| n.checked_add(local_extra_len))
            .ok_or("ZIP payload overflow")?;
        let payload_end = payload_start
            .checked_add(packed)
            .ok_or("ZIP payload overflow")?;
        if payload_end > cd_start {
            return Err("ZIP payload overlaps central directory".into());
        }
        if flags & 8 == 0
            && (le32(data, local + 14)? != crc
                || le32(data, local + 18)? as usize != packed
                || le32(data, local + 22)? as usize != unpacked)
        {
            return Err("ZIP local and central CRC/size conflict".into());
        }

        let is_dir = name.last() == Some(&b'/');
        if is_dir {
            if packed != 0 || unpacked != 0 {
                return Err("ZIP directory contains data".into());
            }
        } else {
            let remaining = max_output
                .checked_sub(used)
                .ok_or("ZIP extraction budget exceeded")?;
            if unpacked > remaining {
                return Err("ZIP extraction budget exceeded".into());
            }
            let compressed = checked_slice(data, payload_start, packed)?;
            let bytes = if method == 0 {
                if packed != unpacked {
                    return Err("ZIP stored length mismatch".into());
                }
                compressed.to_vec()
            } else {
                let mut decoder = flate2::bufread::DeflateDecoder::new(compressed);
                let mut output = Vec::new();
                decoder
                    .by_ref()
                    .take(remaining as u64 + 1)
                    .read_to_end(&mut output)
                    .map_err(|e| format!("ZIP DEFLATE decode failed: {e}"))?;
                if output.len() > remaining {
                    return Err("ZIP decompression bomb rejected".into());
                }
                if !decoder.get_ref().is_empty() {
                    return Err("ZIP compressed stream has trailing bytes".into());
                }
                output
            };
            if bytes.len() != unpacked || crc32fast::hash(&bytes) != crc {
                return Err("ZIP CRC or uncompressed length check failed".into());
            }
            used += bytes.len();
            entries.push(ExtractedEntry {
                path,
                bytes,
                source_offset: (offset + local) as u64,
            });
        }
        pos += record_len;
    }
    if pos != end {
        return Err("ZIP central directory length mismatch".into());
    }
    Ok(entries)
}

fn tar_octal(bytes: &[u8]) -> Result<usize, String> {
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        return Err("base-256 TAR fields unsupported".into());
    }
    let mut value = 0usize;
    let mut started = false;
    let mut ended = false;
    for &byte in bytes {
        if !started && matches!(byte, b' ' | 0) {
            continue;
        }
        if ended {
            if !matches!(byte, b' ' | 0) {
                return Err("unexpected bytes after TAR octal terminator".into());
            }
            continue;
        }
        if (b'0'..=b'7').contains(&byte) {
            started = true;
            value = value.checked_mul(8)
                .and_then(|v| v.checked_add((byte - b'0') as usize))
                .ok_or("TAR octal overflow")?;
        } else if matches!(byte, b' ' | 0) {
            ended = true;
        } else {
            return Err("bad TAR octal digit".into());
        }
    }
    if !started {
        return Err("TAR numeric field contains no octal digits".into());
    }
    Ok(value)
}
fn nul_end(data: &[u8]) -> &[u8] {
    &data[..data.iter().position(|b| *b == 0).unwrap_or(data.len())]
}
pub fn tar_header_checksum_valid(header: &[u8]) -> bool {
    if header.len() != 512 {
        return false;
    }
    let Ok(checksum) = tar_octal(&header[148..156]) else {
        return false;
    };
    let total: usize = header
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                b' ' as usize
            } else {
                *b as usize
            }
        })
        .sum();
    checksum == total
}

/// Strict ustar reader: regular files and directories only. PAX, links,
/// devices and GNU extensions are rejected until explicitly supported.
pub fn extract_tar_limited(
    input: &[u8],
    offset: usize,
    max_output: usize,
) -> Result<Vec<ExtractedEntry>, String> {
    let data = input.get(offset..).ok_or("TAR offset exceeds input")?;
    extraction_limits(data.len(), max_output)?;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut used = 0usize;
    let mut cursor = 0usize;
    let mut headers = 0usize;
    let mut terminated = false;
    while cursor < data.len() {
        let h = checked_slice(data, cursor, 512)?;
        if h.iter().all(|b| *b == 0) {
            if checked_slice(data, cursor + 512, 512)?
                .iter()
                .any(|b| *b != 0)
            {
                return Err("TAR missing second zero end block".into());
            }
            terminated = true;
            break;
        }
        if &h[257..262] != b"ustar" || !tar_header_checksum_valid(h) {
            return Err("bad TAR ustar header or checksum".into());
        }
        headers += 1;
        if headers > MAX_ARCHIVE_ENTRIES {
            return Err("TAR entry count exceeds safety limit".into());
        }
        let prefix = nul_end(&h[345..500]);
        let name = nul_end(&h[..100]);
        let path_bytes = if prefix.is_empty() {
            name.to_vec()
        } else {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(name);
            joined
        };
        let path = archive_path(&path_bytes)?;
        if !seen.insert(path.to_ascii_lowercase()) {
            return Err("duplicate TAR entry path".into());
        }
        let size = tar_octal(&h[124..136])?;
        let kind = h[156];
        if !matches!(kind, 0 | b'0' | b'5') {
            return Err("TAR link, PAX, GNU extension or special file rejected".into());
        }
        if kind == b'5' && size != 0 {
            return Err("TAR directory contains data".into());
        }
        let data_start = cursor.checked_add(512).ok_or("TAR offset overflow")?;
        let bytes = checked_slice(data, data_start, size)?;
        if kind != b'5' {
            used = used.checked_add(size).ok_or("TAR output size overflow")?;
            if used > max_output {
                return Err("TAR extracted size exceeds safety limit".into());
            }
            entries.push(ExtractedEntry {
                path,
                bytes: bytes.to_vec(),
                source_offset: (offset + cursor) as u64,
            });
        }
        let blocks = size.checked_add(511).ok_or("TAR block overflow")? / 512;
        cursor = data_start
            .checked_add(blocks.checked_mul(512).ok_or("TAR block overflow")?)
            .ok_or("TAR cursor overflow")?;
    }
    if !terminated {
        return Err("TAR end-of-archive blocks missing".into());
    }
    Ok(entries)
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;

    fn sample_zip(name: &[u8], bytes: &[u8], deflate: bool) -> Vec<u8> {
        let compressed = if deflate {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(bytes).unwrap();
            enc.finish().unwrap()
        } else {
            bytes.to_vec()
        };
        let mode = if deflate { 8u16 } else { 0u16 };
        let crc = crc32fast::hash(bytes);
        let mut out = Vec::new();
        out.extend(b"PK\x03\x04");
        out.extend(20u16.to_le_bytes()); // minimum version
        out.extend(0u16.to_le_bytes()); // flags
        out.extend(mode.to_le_bytes());
        out.extend([0u8; 4]); // DOS time/date
        out.extend(crc.to_le_bytes());
        out.extend((compressed.len() as u32).to_le_bytes());
        out.extend((bytes.len() as u32).to_le_bytes());
        out.extend((name.len() as u16).to_le_bytes());
        out.extend(0u16.to_le_bytes()); // local extra
        out.extend(name);
        out.extend(compressed);
        let cd = out.len();
        out.extend(b"PK\x01\x02");
        out.extend(20u16.to_le_bytes()); // version made by
        out.extend(20u16.to_le_bytes()); // version needed
        out.extend(0u16.to_le_bytes()); // flags
        out.extend(mode.to_le_bytes());
        out.extend([0u8; 4]); // DOS time/date
        out.extend(crc.to_le_bytes());
        out.extend((out.len() as u32 - cd as u32 + 0).to_le_bytes()); // replaced below
        let size_pos = out.len() - 4;
        out[size_pos..size_pos + 4].copy_from_slice(
            &(if deflate {
                let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
                enc.write_all(bytes).unwrap();
                enc.finish().unwrap().len()
            } else {
                bytes.len()
            } as u32)
                .to_le_bytes(),
        );
        out.extend((bytes.len() as u32).to_le_bytes());
        out.extend((name.len() as u16).to_le_bytes());
        out.extend([0u8; 8]); // extra/comment/disk/internal
        out.extend(0u32.to_le_bytes()); // attributes
        out.extend(0u32.to_le_bytes()); // local offset
        out.extend(name);
        let cd_size = out.len() - cd;
        out.extend(b"PK\x05\x06");
        out.extend([0u8; 4]); // disk numbers
        out.extend(1u16.to_le_bytes()); // entries on disk
        out.extend(1u16.to_le_bytes()); // total entries
        out.extend((cd_size as u32).to_le_bytes());
        out.extend((cd as u32).to_le_bytes());
        out.extend(0u16.to_le_bytes()); // comment
        out
    }

    fn sample_tar(name: &[u8], bytes: &[u8], kind: u8) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].fill(b' ');
        let total = h.iter().map(|b| *b as usize).sum::<usize>();
        h[148..156].copy_from_slice(format!("{total:06o}\0 ").as_bytes());
        let mut out = h.to_vec();
        out.extend(bytes);
        let aligned = bytes.len().div_ceil(512) * 512 + 512;
        out.resize(aligned + 1024, 0);
        out
    }

    #[test]
    fn zip_stored_deflated_embedded_and_crc() {
        for deflate in [false, true] {
            let archive = sample_zip(b"folder/report.txt", b"known artifact", deflate);
            let mut wrapped = b"firmware-prefix".to_vec();
            let offset = wrapped.len();
            wrapped.extend(&archive);
            wrapped.extend(b"other-tail");
            let entries = extract_zip_limited(&wrapped, offset, 4096).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].path, "folder/report.txt");
            assert_eq!(entries[0].bytes, b"known artifact");
            assert_eq!(entries[0].source_offset, offset as u64);
            let mut corrupt = archive.clone();
            let cd = corrupt.windows(4).position(|b| b == b"PK\x01\x02").unwrap();
            corrupt[cd + 16] ^= 0x80;
            assert!(extract_zip_limited(&corrupt, 0, 4096).is_err());
        }
    }

    #[test]
    fn zip_blocks_traversal_and_bombs() {
        for name in [
            b"../bad".as_slice(),
            b"C:/evil".as_slice(),
            b"a\\b".as_slice(),
            b"/abs".as_slice(),
        ] {
            let zip = sample_zip(name, b"test", false);
            assert!(extract_zip_limited(&zip, 0, 1024).is_err());
        }
        let bomb = sample_zip(b"data", &vec![b'Z'; 2048], true);
        assert!(extract_zip_limited(&bomb, 0, 512).is_err());
    }

    #[test]
    fn tar_numeric_fields_reject_hidden_or_ambiguous_bytes() {
        assert_eq!(tar_octal(b"  00017\0 ").unwrap(), 15);
        assert!(tar_octal(b"000017\0evil").is_err());
        assert!(tar_octal(b" 00001x").is_err());
        assert!(tar_octal(b"\0\0\0\0").is_err());
    }

    #[test]
    fn tar_checks_integrity_and_paths() {
        let archive = sample_tar(b"docs/artifact.bin", b"known", b'0');
        let entries = extract_tar_limited(&archive, 0, 4096).unwrap();
        assert_eq!(entries[0].path, "docs/artifact.bin");
        assert_eq!(entries[0].bytes, b"known");
        let mut corrupt = archive.clone();
        corrupt[0] ^= 0x01;
        assert!(extract_tar_limited(&corrupt, 0, 4096).is_err());
        let unsafe_tar = sample_tar(b"../../secret", b"known", b'0');
        assert!(extract_tar_limited(&unsafe_tar, 0, 4096).is_err());
        let symlink = sample_tar(b"link", b"", b'2');
        assert!(extract_tar_limited(&symlink, 0, 4096)
            .unwrap_err()
            .contains("link"));
        assert!(extract_tar_limited(&archive, 0, 4).is_err());
    }
}

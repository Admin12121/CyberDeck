//! Bounded, native binary signature scanning.
//!
//! An independent Rust implementation of public file header formats. The
//! upstream MIT-licensed Binwalk repository is a *reference* for future
//! coverage, but no Binwalk parser/extractor code is incorporated here.
//! Each detection is a candidate, not proof of a complete/valid embedded file.

#[path = "binary.rs"]
pub mod binary;
#[path = "carving.rs"]
pub mod carving;
#[path = "forensic_native.rs"]
pub mod forensic_native;
#[path = "jpeg_boundary.rs"]
pub mod jpeg_boundary;
#[path = "riff_wave.rs"]
pub mod riff_wave;
#[path = "yara_subset.rs"]
pub mod yara_subset;

use serde::Serialize;

pub const MAX_SIGNATURE_HITS: usize = 256;
pub const MAX_SIGNATURE_SCAN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignatureHit {
    pub offset: u64,
    pub format: &'static str,
    pub description: &'static str,
}

fn matched(tail: &[u8]) -> Option<(&'static str, &'static str)> {
    if tail.len() >= 64 && tail.starts_with(b"\x27\x05\x19\x56") {
        return Some(("uimage", "U-Boot legacy image header candidate"));
    }
    if tail.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(("png", "PNG image header"));
    }
    if tail.starts_with(b"%PDF-") {
        return Some(("pdf", "PDF document header"));
    }
    if tail.len() >= 32
        && matches!(
            tail.get(..4),
            Some(
                b"\xfe\xed\xfa\xce"
                    | b"\xce\xfa\xed\xfe"
                    | b"\xfe\xed\xfa\xcf"
                    | b"\xcf\xfa\xed\xfe"
            )
        )
    {
        return Some(("mach-o", "Mach-O thin executable header"));
    }
    if tail.starts_with(b"\x7fELF")
        && tail.len() >= 16
        && matches!(tail[4], 1 | 2)
        && matches!(tail[5], 1 | 2)
        && tail[6] == 1
    {
        return Some(("elf", "ELF executable header"));
    }
    if tail.starts_with(b"PK\x03\x04") && tail.len() >= 30 {
        return Some(("zip", "ZIP local file header"));
    }
    if tail.starts_with(b"PK\x05\x06") && tail.len() >= 22 {
        return Some(("zip-eocd", "ZIP end-of-central-directory record"));
    }
    if tail.len() >= 10 && tail.starts_with(b"\x1f\x8b\x08") && tail[3] & 0xe0 == 0 {
        return Some(("gzip", "Gzip compressed stream"));
    }
    if tail.starts_with(b"\xfd7zXZ\x00") {
        return Some(("xz", "XZ compressed stream"));
    }
    if tail.starts_with(b"BZh") && tail.get(3).is_some_and(|v| (b'1'..=b'9').contains(v)) {
        return Some(("bzip2", "Bzip2 compressed stream"));
    }
    if tail.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some(("7zip", "7-Zip archive header"));
    }
    if tail.starts_with(b"Rar!\x1a\x07\x00") || tail.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return Some(("rar", "RAR archive header"));
    }
    if tail.starts_with(b"SQLite format 3\x00") {
        return Some(("sqlite", "SQLite 3 database header"));
    }
    if tail.starts_with(b"GIF89a") || tail.starts_with(b"GIF87a") {
        return Some(("gif", "GIF image header"));
    }
    if tail.starts_with(b"\xff\xd8\xff") {
        return Some(("jpeg", "JPEG image header"));
    }
    if tail.starts_with(b"OggS\x00") {
        return Some(("ogg", "Ogg container header"));
    }
    if tail.len() >= 12
        && tail.starts_with(b"RIFF")
        && (tail[8..12] == *b"WAVE" || tail[8..12] == *b"AVI ")
    {
        return Some(("riff", "RIFF audio/video container"));
    }
    if tail.len() >= 0x40 && tail.starts_with(b"MZ") {
        let pe_offset = u32::from_le_bytes(tail[0x3c..0x40].try_into().ok()?) as usize;
        if pe_offset <= 1024 * 1024
            && tail.get(pe_offset..pe_offset.saturating_add(4)) == Some(b"PE\0\0")
        {
            return Some(("pe", "Windows PE executable header"));
        }
    }
    None
}

/// Find candidate embedded formats, including a TAR header whose magic
/// lives at offset 257 relative to the start of a 512-byte header.
/// The caller bounds input to MAX_SIGNATURE_SCAN_BYTES; results are capped.
pub fn scan_signatures(bytes: &[u8], max_hits: usize) -> Vec<SignatureHit> {
    let mut found = Vec::new();
    let limit = max_hits.min(MAX_SIGNATURE_HITS);
    if limit == 0 {
        return found;
    }
    let bytes = &bytes[..bytes.len().min(MAX_SIGNATURE_SCAN_BYTES)];
    for offset in 0..bytes.len() {
        if found.len() >= limit {
            break;
        }
        let tail = &bytes[offset..];
        let first = tail[0];
        // Cheap dispatch avoids a full signature table check on most bytes.
        let candidate = if matches!(
            first,
            0x27 | 0xfe | 0xce
                | 0xcf
                | 0x89
                | b'%'
                | 0x7f
                | b'P'
                | 0x1f
                | 0xfd
                | b'B'
                | b'7'
                | b'R'
                | b'S'
                | b'G'
                | 0xff
                | b'O'
                | b'M'
        ) {
            matched(tail)
        } else {
            None
        };
        if let Some((format, description)) = candidate {
            found.push(SignatureHit {
                offset: offset as u64,
                format,
                description,
            });
            continue;
        }
        // TAR's "ustar" identifier is *not* at the file start. Verify the
        // candidate contains a complete 512-byte header before reporting it.
        if tail.len() >= 512
            && tail[257..262] == *b"ustar"
            && crate::extraction::tar_header_checksum_valid(&tail[..512])
        {
            found.push(SignatureHit {
                offset: offset as u64,
                format: "tar",
                description: "TAR archive header",
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_embedded_signatures_with_exact_offsets() {
        let mut blob = b"prefix-payload-".to_vec();
        let zip_offset = blob.len();
        blob.extend_from_slice(b"PK\x03\x04");
        blob.extend_from_slice(&[0u8; 26]);
        blob.extend_from_slice(b"other-data");
        let pdf_offset = blob.len();
        blob.extend_from_slice(b"%PDF-1.7\n");
        let hits = scan_signatures(&blob, 20);
        assert!(hits
            .iter()
            .any(|h| h.offset == zip_offset as u64 && h.format == "zip"));
        assert!(hits
            .iter()
            .any(|h| h.offset == pdf_offset as u64 && h.format == "pdf"));
    }

    #[test]
    fn validates_pe_header_and_tar_magic_offset() {
        let mut exe = vec![0u8; 512];
        exe[0..2].copy_from_slice(b"MZ");
        exe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        exe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(scan_signatures(&exe, 5)[0].format, "pe");
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        tar[148..156].fill(b' ');
        let sum = tar.iter().map(|b| *b as usize).sum::<usize>();
        tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(scan_signatures(&tar, 5)
            .iter()
            .any(|h| h.format == "tar" && h.offset == 0));
        assert!(!scan_signatures(&tar[1..], 5)
            .iter()
            .any(|h| h.format == "tar"));
    }

    #[test]
    fn rejects_partial_and_invalid_headers() {
        assert!(scan_signatures(b"PK\x03\x04", 4).is_empty());
        assert!(scan_signatures(b"BZh0", 4).is_empty());
        assert!(scan_signatures(b"MZ", 4).is_empty());
        assert!(scan_signatures(b"garbage\x1f\x8b", 4).is_empty());
        assert!(scan_signatures(b"\x89PNG", 0).is_empty());
        assert!(scan_signatures(b"\x1f\x8b\x08", 4).is_empty());
        let mut fake_tar = vec![0u8; 512];
        fake_tar[257..262].copy_from_slice(b"ustar");
        assert!(scan_signatures(&fake_tar, 4).is_empty());
    }
    #[test]
    fn detects_embedded_macho_and_rejects_short_magic() {
        let mut embedded = b"prefix".to_vec();
        embedded.extend_from_slice(b"\xcf\xfa\xed\xfe");
        embedded.extend_from_slice(&[0u8; 28]);
        assert!(scan_signatures(&embedded, 8)
            .iter()
            .any(|hit| hit.format == "mach-o" && hit.offset == 6));
        assert!(scan_signatures(b"\xcf\xfa\xed\xfe", 8).is_empty());
    }
    #[test]
    fn results_are_bounded() {
        let sample = [b"%PDF-1.5".as_slice(), b"%PDF-1.7".as_slice()].concat();
        assert_eq!(scan_signatures(&sample, 1).len(), 1);
        assert_eq!(scan_signatures(&sample, 0).len(), 0);
    }
}

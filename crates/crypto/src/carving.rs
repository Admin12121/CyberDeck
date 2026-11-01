//! Read-only, bounded file-carving candidate validation.
//!
//! Never emits reconstructed bytes or writes recovered files. Reuse the
//! existing signature scanner and native PNG chunk/CRC metadata validator.
//! A signature hit alone is not a valid carved object.
use super::{forensic_native, jpeg_boundary, riff_wave, scan_signatures, MAX_SIGNATURE_HITS};
use serde::Serialize;

#[path = "gif_boundary.rs"]
mod gif_boundary;
#[path = "uboot_image.rs"]
mod uboot_image;

pub const MAX_CARVE_SCAN_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CARVE_CANDIDATES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CarveCandidate {
    pub offset: u64,
    pub length: usize,
    pub format: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CarvePreview {
    pub candidates: Vec<CarveCandidate>,
    pub rejected_or_incomplete: usize,
    pub candidate_limit_reached: bool,
}

/// Preview fully validated PNG candidates within one explicitly bounded window.
/// Results are source offsets, not extracted bytes or new artifact identities.
/// Non-PNG signatures are deliberately ignored until other format validators
/// can prove complete boundaries and checksums.
pub fn preview_png_carving(data: &[u8], base: u64) -> Result<CarvePreview, String> {
    preview_carving_impl(data, base, false)
}

/// Extended preview for PNG, RIFF/WAVE, JPEG, GIF and CRC-checked U-Boot uImage members.
/// Does not decode pixels or audio. AVI is rejected.
pub fn preview_validated_carving(data: &[u8], base: u64) -> Result<CarvePreview, String> {
    preview_carving_impl(data, base, true)
}

fn preview_carving_impl(data: &[u8], base: u64, include_wav: bool) -> Result<CarvePreview, String> {
    if data.is_empty() || data.len() > MAX_CARVE_SCAN_BYTES {
        return Err("carving scan window must be 1..4MiB".into());
    }
    base.checked_add(data.len() as u64)
        .ok_or("carving absolute offset overflow")?;

    let signatures = scan_signatures(data, MAX_SIGNATURE_HITS);
    let scanner_cap_reached = signatures.len() == MAX_SIGNATURE_HITS;
    let mut candidates = Vec::new();
    let mut rejected_or_incomplete = 0usize;
    let mut candidate_limit_reached = scanner_cap_reached;
    for hit in signatures {
        if hit.format != "png"
            && !(include_wav && matches!(hit.format, "riff" | "jpeg" | "gif" | "uimage"))
        {
            continue;
        }
        if candidates.len() + rejected_or_incomplete >= MAX_CARVE_CANDIDATES {
            candidate_limit_reached = true;
            break;
        }
        let rel = hit.offset as usize;
        // metadata() validates PNG IHDR, every visited chunk CRC/length, and
        // the terminal IEND. It returns exactly the validated member boundary.
        let validated = if hit.format == "png" {
            forensic_native::carving_png_metadata(&data[rel..], base + hit.offset)
                .ok()
                .filter(|parsed| parsed.complete && parsed.format == "png")
                .map(|parsed| ("png", parsed.parsed_bytes))
        } else if hit.format == "riff" {
            riff_wave::validated_wave_length(&data[rel..])
                .ok()
                .map(|length| ("wav", length))
        } else if hit.format == "gif" {
            gif_boundary::validated_gif_length(&data[rel..])
                .ok()
                .map(|length| ("gif", length))
        } else if hit.format == "uimage" {
            uboot_image::validated_uimage_length(&data[rel..])
                .ok()
                .map(|length| ("uimage", length))
        } else {
            jpeg_boundary::validated_jpeg_length(&data[rel..], base + hit.offset)
                .ok()
                .map(|length| ("jpeg", length))
        };
        if let Some((format, length)) = validated {
            candidates.push(CarveCandidate {
                offset: base + hit.offset,
                length,
                format,
            });
        } else {
            rejected_or_incomplete += 1;
        }
    }
    Ok(CarvePreview {
        candidates,
        rejected_or_incomplete,
        candidate_limit_reached,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut image = Vec::new();
        for _ in 0..height {
            image.push(0); // PNG row filter: None
            image.extend(std::iter::repeat_n(0u8, width as usize * 3));
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&image).unwrap();
        let image_data = encoder.finish().unwrap();
        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        for (tag, contents) in [
            (&b"IHDR"[..], ihdr),
            (&b"IDAT"[..], image_data),
            (&b"IEND"[..], Vec::new()),
        ] {
            out.extend_from_slice(&(contents.len() as u32).to_be_bytes());
            out.extend_from_slice(tag);
            out.extend_from_slice(&contents);
            let mut digest = crc32fast::Hasher::new();
            digest.update(tag);
            digest.update(&contents);
            out.extend_from_slice(&digest.finalize().to_be_bytes());
        }
        out
    }

    #[test]
    fn carves_complete_png_from_nonzero_offset_with_source_coordinates() {
        let bytes = png(21, 31);
        let mut input = b"prefix-goes-here".to_vec();
        let rel = input.len();
        input.extend_from_slice(&bytes);
        input.extend_from_slice(b"trailing unrelated data");
        let report = preview_png_carving(&input, 4096).unwrap();
        assert_eq!(
            report.candidates,
            vec![CarveCandidate {
                offset: 4096 + rel as u64,
                length: bytes.len(),
                format: "png"
            }]
        );
        assert_eq!(report.rejected_or_incomplete, 0);
        assert!(!report.candidate_limit_reached);
    }

    #[test]
    fn does_not_claim_corrupted_truncated_or_magic_only_png() {
        let good = png(7, 11);
        let mut bad_crc = good.clone();
        bad_crc[29] ^= 0x40;
        for candidate in [
            bad_crc,
            good[..good.len() - 4].to_vec(),
            b"\x89PNG\r\n\x1a\n".to_vec(),
        ] {
            let report = preview_png_carving(&candidate, 0).unwrap();
            assert!(report.candidates.is_empty());
        }
        assert!(preview_png_carving(b"no file signature here", 0)
            .unwrap()
            .candidates
            .is_empty());
        let mut metadata_only = good.clone();
        // The signature and IHDR alone must not count as a complete carved image.
        metadata_only.truncate(8 + 25);
        metadata_only.extend_from_slice(&[0, 0, 0, 0]);
        metadata_only.extend_from_slice(b"IEND");
        metadata_only.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());
        assert!(preview_png_carving(&metadata_only, 0)
            .unwrap()
            .candidates
            .is_empty());
    }

    #[test]
    fn bounds_scan_window_candidate_work_and_absolute_offsets() {
        assert!(preview_png_carving(&[], 0).is_err());
        assert!(preview_png_carving(&vec![0; MAX_CARVE_SCAN_BYTES + 1], 0).is_err());
        assert!(preview_png_carving(&[0; 2], u64::MAX).is_err());

        let png = png(1, 1);
        let mut input = Vec::new();
        for _ in 0..(MAX_CARVE_CANDIDATES + 3) {
            input.extend_from_slice(&png);
        }
        let report = preview_png_carving(&input, 0).unwrap();
        assert_eq!(report.candidates.len(), MAX_CARVE_CANDIDATES);
        assert!(report.candidate_limit_reached);
    }

    #[test]
    fn validated_carving_finds_wave_member_and_rejects_false_riff_headers() {
        fn chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(tag);
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(body);
            if body.len() % 2 != 0 {
                out.push(0);
            }
            out
        }
        let fmt = [
            &[1, 0, 1, 0][..],
            &8_000u32.to_le_bytes(),
            &8_000u32.to_le_bytes(),
            &[1, 0, 8, 0],
        ]
        .concat();
        let mut body = b"WAVE".to_vec();
        body.extend(chunk(b"fmt ", &fmt));
        body.extend(chunk(b"data", &[0x11, 0x22, 0x33]));
        let mut wave = b"RIFF".to_vec();
        wave.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wave.extend(body);
        let mut source = b"firmware-prefix".to_vec();
        let member_offset = source.len() as u64;
        source.extend_from_slice(&wave);
        source.extend_from_slice(b"irrelevant suffix");
        let result = preview_validated_carving(&source, 800).unwrap();
        assert_eq!(
            result.candidates,
            vec![CarveCandidate {
                offset: 800 + member_offset,
                length: wave.len(),
                format: "wav",
            }]
        );
        assert!(preview_png_carving(&source, 800)
            .unwrap()
            .candidates
            .is_empty());
        let mut malformed = source.clone();
        let index = member_offset as usize + 4;
        malformed[index..index + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let rejected = preview_validated_carving(&malformed, 800).unwrap();
        assert!(rejected.candidates.is_empty());
        assert_eq!(rejected.rejected_or_incomplete, 1);
        let mut avi = b"RIFF".to_vec();
        avi.extend_from_slice(&12u32.to_le_bytes());
        avi.extend_from_slice(b"AVI ");
        avi.extend_from_slice(&[0; 8]);
        assert!(preview_validated_carving(&avi, 0)
            .unwrap()
            .candidates
            .is_empty());
    }
    #[test]
    fn deterministic_malformed_corpus_png_wav_jpeg_stays_bounded() {
        fn segment(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut part = vec![0xff, tag];
            part.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
            part.extend_from_slice(body);
            part
        }
        let mut jpeg = vec![0xff, 0xd8];
        jpeg.extend(segment(0xdb, &[0, 1, 1, 1]));
        jpeg.extend(segment(0xc0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        jpeg.extend(segment(0xc4, &[0, 0, 1]));
        jpeg.extend(segment(0xda, &[1, 1, 0, 0, 63, 0]));
        jpeg.extend_from_slice(&[0x11, 0xff, 0x00, 0x22, 0xff, 0xd9]);
        let mut wave_body = b"WAVEfmt ".to_vec();
        wave_body.extend_from_slice(&16_u32.to_le_bytes());
        wave_body.extend_from_slice(&[1, 0, 1, 0]);
        wave_body.extend_from_slice(&8_000_u32.to_le_bytes());
        wave_body.extend_from_slice(&8_000_u32.to_le_bytes());
        wave_body.extend_from_slice(&[1, 0, 8, 0]);
        wave_body.extend_from_slice(b"data");
        wave_body.extend_from_slice(&2_u32.to_le_bytes());
        wave_body.extend_from_slice(&[0, 1]);
        let mut wave = b"RIFF".to_vec();
        wave.extend_from_slice(&(wave_body.len() as u32).to_le_bytes());
        wave.extend(wave_body);
        let fixtures = [png(1, 1), wave, jpeg];

        // Reproducible xorshift32 fuzz-style corpus: fixed seed and iteration
        // count; no files, thread spawning or unbounded allocations.
        let mut state = 0x51d3_cafe_u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize
        };
        for fixture in &fixtures {
            assert!(fixture.len() < 4096);
            for i in 0..192 {
                let mut mutated = fixture.clone();
                let index = next() % mutated.len();
                mutated[index] ^= (1 << (next() % 8)) as u8;
                if i % 3 == 0 {
                    let end = next() % (mutated.len() + 1);
                    mutated.truncate(end);
                }
                if mutated.is_empty() {
                    assert!(preview_validated_carving(&mutated, 4096).is_err());
                    continue;
                }
                let first = preview_validated_carving(&mutated, 4096).unwrap();
                let second = preview_validated_carving(&mutated, 4096).unwrap();
                assert_eq!(first, second);
                assert!(first.candidates.len() <= MAX_CARVE_CANDIDATES);
                assert!(first.candidates.iter().all(|candidate| {
                    candidate.offset >= 4096
                        && candidate.offset - 4096 < mutated.len() as u64
                        && candidate.length <= mutated.len()
                        && candidate.offset - 4096 + candidate.length as u64 <= mutated.len() as u64
                }));
            }
        }
    }
}

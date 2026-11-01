//! Conservative, bounded JPEG member-boundary preview.
//!
//! Reuses the native JPEG metadata/header parser through first SOS and then
//! validates entropy-coded scan marker framing, restart/stuffed bytes, further
//! marker segments, multiple scans and terminal EOI. It does NOT decode pixels,
//! enforce Huffman/quantization semantics or claim image decodability.
use super::forensic_native::{metadata, MAX_METADATA_INPUT};

const MAX_MARKERS: usize = 4096;
const MAX_SCANS: usize = 256;

/// Return the exact EOI-terminated JPEG member length inside a bounded window.
/// A signature is necessary but insufficient: a valid nonzero SOF dimension,
/// an SOS, actual entropy data and a terminal EOI are all required.
pub fn validated_jpeg_length(input: &[u8], base: u64) -> Result<usize, String> {
    if input.len() > MAX_METADATA_INPUT || input.len() < 10 || !input.starts_with(b"\xff\xd8\xff") {
        return Err("not a bounded JPEG candidate".into());
    }
    base.checked_add(input.len() as u64)
        .ok_or("JPEG source offset overflow")?;
    // Reuse the existing segment/Exif validation up to first SOS. It stops
    // before compressed entropy and exposes the position after the SOS marker.
    let header = metadata(input, base)?;
    if header.format != "jpeg" || header.complete {
        return Err("JPEG requires frame and entropy-coded scan before EOI".into());
    }
    let frame_width = header
        .fields
        .iter()
        .find(|f| f.namespace == "jpeg" && f.key == "width")
        .and_then(|f| f.value.parse::<u16>().ok());
    let frame_height = header
        .fields
        .iter()
        .find(|f| f.namespace == "jpeg" && f.key == "height")
        .and_then(|f| f.value.parse::<u16>().ok());
    if !frame_width.is_some_and(|w| w > 0) || !frame_height.is_some_and(|h| h > 0) {
        return Err("JPEG frame dimensions missing or invalid".into());
    }
    let mut pos = header.parsed_bytes;
    if pos < 2 || input.get(pos - 2..pos) != Some(&b"\xff\xda"[..]) {
        return Err("JPEG scan marker missing".into());
    }
    let mut scans = 0usize;
    let mut markers = 0usize;
    let mut pending_sos = true;
    let mut restart_seen = false;
    loop {
        markers += 1;
        if markers > MAX_MARKERS {
            return Err("JPEG marker budget exceeded".into());
        }
        if pending_sos {
            scans += 1;
            if scans > MAX_SCANS {
                return Err("JPEG scan budget exceeded".into());
            }
            // SOS length: 6 + 2*Ns, with 1..=4 components.
            let n = u16::from_be_bytes(
                input
                    .get(pos..pos + 2)
                    .ok_or("truncated JPEG SOS length")?
                    .try_into()
                    .unwrap(),
            ) as usize;
            if n < 8 {
                return Err("invalid JPEG SOS length".into());
            }
            let end = pos.checked_add(n).ok_or("JPEG SOS overflow")?;
            let body = input
                .get(pos + 2..end)
                .ok_or("truncated JPEG SOS payload")?;
            let comps = body[0] as usize;
            if !(1..=4).contains(&comps) || n != 6 + 2 * comps {
                return Err("invalid JPEG scan components".into());
            }
            let spectral = body[1 + 2 * comps];
            let spectral_end = body[2 + 2 * comps];
            if spectral > 63 || spectral_end > 63 || spectral > spectral_end {
                return Err("invalid JPEG spectral scan selection".into());
            }
            pos = end;
            pending_sos = false;
            let mut data_seen = false;
            // Scan compressed bytes while interpreting FF00 as stuffed byte,
            // FF D0..D7 as restart, FF FF as fill and unescaped FF as markers.
            loop {
                if pos >= input.len() {
                    return Err("JPEG missing terminal EOI".into());
                }
                if input[pos] != 0xff {
                    data_seen = true;
                    pos += 1;
                    continue;
                }
                let marker_start = pos;
                while input.get(pos) == Some(&0xff) {
                    pos += 1;
                }
                let tag = *input.get(pos).ok_or("truncated JPEG scan marker")?;
                pos += 1;
                match tag {
                    0x00 => data_seen = true, // byte stuffing (FF 00)
                    0xd0..=0xd7 => {
                        if !data_seen {
                            return Err("JPEG restart without scan data".into());
                        }
                        restart_seen = true;
                    }
                    0xd9 => {
                        if !data_seen {
                            return Err("empty JPEG entropy-coded scan".into());
                        }
                        return Ok(pos);
                    }
                    0xd8 | 0x01 => return Err("unexpected standalone JPEG marker".into()),
                    _ => {
                        if !data_seen {
                            return Err("empty JPEG entropy-coded scan".into());
                        }
                        // New marker belongs to the post-scan segment parser.
                        pos = marker_start;
                        break;
                    }
                }
            }
        } else {
            if input.get(pos) != Some(&0xff) {
                return Err("invalid JPEG post-scan marker".into());
            }
            while input.get(pos) == Some(&0xff) {
                pos += 1;
            }
            let tag = *input.get(pos).ok_or("truncated JPEG post-scan marker")?;
            pos += 1;
            if tag == 0xda {
                pending_sos = true;
                continue;
            }
            if tag == 0xd9
                || tag == 0xd8
                || tag == 0x00
                || tag == 0x01
                || (0xd0..=0xd7).contains(&tag)
            {
                return Err("unexpected JPEG marker outside entropy scan".into());
            }
            // Only APP/COM, DHT/DQT/DAC/DRI and JPEG extension markers can
            // legally separate scans. Conservative fail-closed on others.
            if !((0xe0..=0xef).contains(&tag)
                || matches!(tag, 0xfe | 0xc4 | 0xcc | 0xdb | 0xdd | 0xdc | 0xdf))
            {
                return Err("unsupported JPEG inter-scan marker".into());
            }
            let n = u16::from_be_bytes(
                input
                    .get(pos..pos + 2)
                    .ok_or("truncated JPEG inter-scan length")?
                    .try_into()
                    .unwrap(),
            ) as usize;
            if n < 2 {
                return Err("invalid JPEG inter-scan length".into());
            }
            let end = pos.checked_add(n).ok_or("JPEG inter-scan overflow")?;
            if end > input.len() {
                return Err("truncated JPEG inter-scan segment".into());
            }
            pos = end;
            if restart_seen && scans > MAX_SCANS {
                return Err("JPEG restart/scan limits exceeded".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn segment(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0xff, tag];
        out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }
    pub(super) fn jpeg(multiscan: bool) -> Vec<u8> {
        let mut out = vec![0xff, 0xd8];
        out.extend(segment(0xdb, &[0, 1, 1, 1]));
        out.extend(segment(0xc0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        out.extend(segment(0xc4, &[0, 0, 1]));
        out.extend(segment(0xda, &[1, 1, 0, 0, 63, 0]));
        out.extend_from_slice(&[0x11, 0xff, 0x00, 0x22, 0xff, 0xd0, 0x33]);
        if multiscan {
            out.extend(segment(0xc4, &[0, 0, 1]));
            out.extend(segment(0xda, &[1, 1, 0, 0, 63, 0]));
            out.extend_from_slice(&[0x44, 0x55]);
        }
        out.extend_from_slice(&[0xff, 0xd9]);
        out
    }
    #[test]
    fn complete_stuffed_restart_and_multiple_scans_have_exact_boundary() {
        for multiple in [false, true] {
            let image = jpeg(multiple);
            let mut with_suffix = image.clone();
            with_suffix.extend_from_slice(b"unrelated trailer");
            assert_eq!(
                validated_jpeg_length(&with_suffix, 4096).unwrap(),
                image.len()
            );
        }
    }
    #[test]
    fn rejects_truncated_ambiguous_and_malformed_markers() {
        let good = jpeg(false);
        for truncated in [2, 4, 8, good.len() / 2, good.len() - 1] {
            assert!(validated_jpeg_length(&good[..truncated], 0).is_err());
        }
        let mut bad_sos = good.clone();
        let idx = good.windows(2).position(|w| w == [0xff, 0xda]).unwrap();
        bad_sos[idx + 3] = 4;
        assert!(validated_jpeg_length(&bad_sos, 0).is_err());
        let mut premature_soi = good.clone();
        let marker = good.windows(2).position(|w| w == [0xff, 0x00]).unwrap();
        premature_soi[marker + 1] = 0xd8;
        assert!(validated_jpeg_length(&premature_soi, 0).is_err());
        let mut no_frame = good.clone();
        let sof = good.windows(2).position(|w| w == [0xff, 0xc0]).unwrap();
        no_frame[sof + 1] = 0xe2;
        assert!(validated_jpeg_length(&no_frame, 0).is_err());
        assert!(validated_jpeg_length(&good, u64::MAX).is_err());
        assert!(validated_jpeg_length(&vec![0; MAX_METADATA_INPUT + 1], 0).is_err());
    }
}

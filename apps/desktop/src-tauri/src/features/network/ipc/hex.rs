//! Fixed-width lowercase hexadecimal display without per-byte heap strings.
//! Retains the existing no-trailing-space IPC text format.
use crate::evidence::{HexResponse, HexRow};

pub(super) fn format_hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut formatted = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (idx, &byte) in bytes.iter().enumerate() {
        if idx != 0 {
            formatted.push(' ');
        }
        formatted.push(DIGITS[usize::from(byte >> 4)] as char);
        formatted.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    formatted
}

pub(super) fn frame_hex_view(frame: &[u8], offset: i64, len: i64) -> HexResponse {
    let total = frame.len() as i64;
    let start = offset.clamp(0, total.max(0)) as usize;
    let wanted = len.clamp(1, 4096) as usize;
    let end = start.saturating_add(wanted).min(frame.len());
    let slice = &frame[start..end];
    let mut rows = Vec::with_capacity(slice.len().div_ceil(16));
    for (i, chunk) in slice.chunks(16).enumerate() {
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..=0x7e).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        rows.push(HexRow {
            offset: start + i * 16,
            hex: format_hex_bytes(chunk),
            ascii,
        });
    }
    HexResponse {
        rows,
        offset: start as i64,
        total_size: total as u64,
        complete: end >= frame.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::{format_hex_bytes, frame_hex_view};

    #[test]
    fn hex_paging_keeps_existing_offsets_and_clamps_negative_ranges() {
        let source = b"abc\x00Z";
        let view = frame_hex_view(source, -5, 2);
        assert_eq!(view.total_size, 5);
        assert_eq!(view.rows[0].hex, "61 62");
        assert_eq!(view.rows[0].ascii, "ab");
        assert_eq!(view.rows[0].offset, 0);
        assert!(!view.complete);
        let at_end = frame_hex_view(source, 999, 999);
        assert!(at_end.rows.is_empty());
        assert!(at_end.complete);
        assert_eq!(at_end.offset, 5);
    }

    #[test]
    fn produces_exact_existing_lowercase_hex_format() {
        assert_eq!(
            format_hex_bytes(&[0, 1, 15, 16, 128, 255]),
            "00 01 0f 10 80 ff"
        );
        assert_eq!(format_hex_bytes(&[]), "");
    }
}

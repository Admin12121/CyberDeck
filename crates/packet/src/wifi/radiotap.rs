//! Bounded radiotap header parsing (radiotap.org spec, header version 0).
//!
//! The parser walks the present-bitmap with the kernel's alignment/size table
//! (net/wireless/radiotap.c `rtap_namespace_sizes`, verified against the
//! vendored upstream) and extracts only the fields the packet engine needs:
//! flags, channel, data rate, antenna and dBm signal/noise. Fields that are
//! tabled but uninteresting are skipped by exact size and alignment; fields
//! outside the table (xchannel, timestamp, vendor/radiotap namespaces, HE
//! words) are honestly refused rather than guessed at. Nothing here allocates
//! unboundedly, panics on short input, or trusts any length field.
use crate::wifi::{WifiError, WifiMonitorError};

/// Present-bitmap word cap (task bound; captures with more words are refused).
pub const MAX_PRESENT_WORDS: usize = 8;
/// Total radiotap header cap (`it_len` must stay below this).
pub const MAX_HEADER_BYTES: usize = 256;
/// Minimum radiotap header: 4 fixed bytes + the first present word.
pub const MIN_HEADER_BYTES: usize = 8;

// radiotap FLAGS bits (IEEE80211_RADIOTAP_F_*).
pub const FLAG_CFP: u8 = 0x01;
pub const FLAG_SHORT_PREAMBLE: u8 = 0x02;
pub const FLAG_WEP: u8 = 0x04;
pub const FLAG_FRAGMENTED: u8 = 0x08;
/// Bit 4: four FCS bytes trail the 802.11 frame and must be stripped.
pub const FLAG_FCS_AT_END: u8 = 0x10;
/// Bit 5: some chips pad the 802.11 header to 4 bytes before the body.
pub const FLAG_DATA_PAD: u8 = 0x20;
/// Bit 6: the FCS at the end failed the hardware check.
pub const FLAG_BAD_FCS: u8 = 0x40;
pub const FLAG_SHORT_GI: u8 = 0x80;

/// Fields extracted from a radiotap header. Absent fields stay `None`; the
/// parser never invents values for fields the capture did not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Radiotap {
    pub flags: Option<u8>,
    pub rate_500kbps: Option<u8>,
    pub channel_mhz: Option<u16>,
    pub channel_flags: Option<u16>,
    pub antenna: Option<u8>,
    pub dbm_signal: Option<i8>,
    pub dbm_noise: Option<i8>,
}

impl Radiotap {
    /// The capture carries a trailing FCS (radiotap FLAGS bit 4).
    pub fn fcs_present(&self) -> bool {
        self.flags.is_some_and(|f| f & FLAG_FCS_AT_END != 0)
    }
    /// The 802.11 MAC header is 4-byte padded before the body (bit 5).
    pub fn data_padded(&self) -> bool {
        self.flags.is_some_and(|f| f & FLAG_DATA_PAD != 0)
    }
    /// Hardware reported the trailing FCS as bad (bit 6).
    pub fn fcs_bad(&self) -> bool {
        self.flags.is_some_and(|f| f & FLAG_BAD_FCS != 0)
    }
}

/// (size, alignment) per present bit, exactly the kernel's
/// `rtap_namespace_sizes` table. `None` = bit outside the table.
fn field_layout(bit: u16) -> Option<(usize, usize)> {
    Some(match bit {
        0 => (8, 8),  // TSFT
        1 => (1, 1),  // FLAGS
        2 => (1, 1),  // RATE
        3 => (4, 2),  // CHANNEL (u16 freq + u16 flags)
        4 => (2, 2),  // FHSS
        5 => (1, 1),  // DBM_ANTSIGNAL
        6 => (1, 1),  // DBM_ANTNOISE
        7 => (2, 2),  // LOCK_QUALITY
        8 => (2, 2),  // TX_ATTENUATION
        9 => (2, 2),  // DB_TX_ATTENUATION
        10 => (1, 1), // DBM_TX_POWER
        11 => (1, 1), // ANTENNA
        12 => (1, 1), // DB_ANTSIGNAL
        13 => (1, 1), // DB_ANTNOISE
        14 => (2, 2), // RX_FLAGS
        15 => (2, 2), // TX_FLAGS
        16 => (1, 1), // RTS_RETRIES
        17 => (1, 1), // DATA_RETRIES
        // 18 (XCHANNEL) is deprecated and absent from the kernel table; the
        // kernel iterator refuses it, and so do we.
        19 => (3, 1),  // MCS
        20 => (8, 4),  // AMPDU_STATUS
        21 => (12, 2), // VHT
        // 22+ (TIMESTAMP, namespaces, HE words) untabled: refused.
        _ => return None,
    })
}

fn protocol(message: impl Into<String>) -> WifiError {
    WifiError::new(WifiMonitorError::Protocol, message)
}

fn align_up(pos: usize, alignment: usize) -> usize {
    // Alignment is a power of two from the table above; plain rounding.
    pos.div_ceil(alignment) * alignment
}

/// Parse a radiotap header at the start of `bytes`. Returns the extracted
/// fields and the total header length (the offset of the 802.11 frame).
pub fn parse(bytes: &[u8]) -> Result<(Radiotap, usize), WifiError> {
    if bytes.len() < MIN_HEADER_BYTES {
        return Err(protocol(format!(
            "radiotap header truncated: {} bytes, need {MIN_HEADER_BYTES}",
            bytes.len()
        )));
    }
    // Version 0 is the only version ever deployed; the kernel rejects others.
    let version = bytes[0];
    if version != 0 {
        return Err(protocol(format!(
            "unsupported radiotap header version {version}"
        )));
    }
    let header_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if header_len < MIN_HEADER_BYTES {
        return Err(protocol(format!(
            "radiotap header length {header_len} below minimum"
        )));
    }
    if header_len > MAX_HEADER_BYTES || header_len > bytes.len() {
        return Err(protocol(format!(
            "radiotap header length {header_len} exceeds capture or bound"
        )));
    }

    // Present bitmap: first word plus extension words while bit 31 is set.
    let mut words = [0u32; MAX_PRESENT_WORDS];
    let mut word_count = 1usize;
    words[0] = u32::from_le_bytes(bytes[4..8].try_into().expect("bounded slice"));
    let mut pos = 8usize;
    while words[word_count - 1] & 0x8000_0000 != 0 {
        if word_count == MAX_PRESENT_WORDS {
            return Err(protocol(format!(
                "radiotap present bitmap exceeds {MAX_PRESENT_WORDS} words"
            )));
        }
        if pos + 4 > header_len {
            return Err(protocol(
                "radiotap extended present word exceeds header length",
            ));
        }
        words[word_count] =
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("bounded slice"));
        word_count += 1;
        pos += 4;
    }

    // Field walk: data begins directly after the last present word; `it_len`
    // bounds the whole header (fields included), exactly like the kernel
    // iterator. Alignment is relative to the start of the radiotap header.
    let mut parsed = Radiotap::default();
    let mut cursor = 4 + word_count * 4;
    for word_index in 0..word_count {
        let word = words[word_index];
        for bit in 0..32u16 {
            if word & (1u32 << bit) == 0 {
                continue;
            }
            // Bit 31 is the "more extensions" flag, never a field.
            if bit == 31 {
                continue;
            }
            let (size, alignment) = field_layout(bit).ok_or_else(|| {
                protocol(format!("radiotap field bit {bit} outside the parser table"))
            })?;
            cursor = align_up(cursor, alignment);
            let end = cursor
                .checked_add(size)
                .ok_or_else(|| protocol("radiotap field offset overflow"))?;
            if end > header_len || end > bytes.len() {
                return Err(protocol(
                    "radiotap field extends past the stated header length or the capture",
                ));
            }
            let field = &bytes[cursor..end];
            match bit {
                1 => parsed.flags = Some(field[0]),
                2 => parsed.rate_500kbps = Some(field[0]),
                3 => {
                    parsed.channel_mhz = Some(u16::from_le_bytes([field[0], field[1]]));
                    parsed.channel_flags = Some(u16::from_le_bytes([field[2], field[3]]));
                }
                5 => parsed.dbm_signal = Some(field[0] as i8),
                6 => parsed.dbm_noise = Some(field[0] as i8),
                11 => parsed.antenna = Some(field[0]),
                _ => {} // tabled but uninteresting: skipped by exact size
            }
            cursor = end;
        }
    }
    Ok((parsed, header_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le16(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    /// Build a header from present words + field bytes; layout is exactly what
    /// a real driver writes (fields in bit order, aligned to header start).
    fn build(words: &[u32], fields: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0); // version
        out.push(0); // pad
        let words_bytes: Vec<u8> = words.iter().flat_map(|w| le32(*w)).collect();
        let header_len = 4 + words_bytes.len();
        out.extend_from_slice(&le16(header_len as u16));
        out.extend_from_slice(&words_bytes);
        out.extend_from_slice(fields);
        // Patch total length to cover the fields too, like real captures do.
        let total = out.len() as u16;
        out[2..4].copy_from_slice(&le16(total));
        out
    }

    #[test]
    fn minimal_v0_header_extracts_flags_and_rate() {
        // Bits 1 (FLAGS) and 2 (RATE): the walk emits FLAGS at offset 8, then
        // RATE at 9 (both alignment 1).
        let frame = build(&[(1 << 1) | (1 << 2)], &[FLAG_FCS_AT_END | 0x02, 0x24]);
        let (radio, consumed) = parse(&frame).expect("minimal header parses");
        assert_eq!(consumed, 10);
        assert_eq!(radio.flags, Some(FLAG_FCS_AT_END | 0x02));
        assert_eq!(radio.rate_500kbps, Some(0x24));
        assert!(radio.fcs_present());
        assert!(!radio.data_padded());
        assert!(radio.channel_mhz.is_none());
    }

    #[test]
    fn channel_field_is_aligned_and_decoded() {
        // Bits: RATE (2) then CHANNEL (3). The walk emits RATE first (offset
        // 8, align 1), then CHANNEL pads to alignment 2 at offset 10.
        let present = (1u32 << 2) | (1u32 << 3);
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&le16(4 + 4));
        out.extend_from_slice(&le32(present));
        out.push(0x18); // rate at offset 8
        out.push(0); // one pad byte to reach alignment 2 at offset 10
        out.extend_from_slice(&le16(2412)); // channel freq at offset 10
        out.extend_from_slice(&le16(0x00a0)); // channel flags word
        let total = out.len() as u16;
        out[2..4].copy_from_slice(&le16(total));
        let (radio, consumed) = parse(&out).expect("channel header parses");
        assert_eq!(consumed, 14);
        assert_eq!(radio.rate_500kbps, Some(0x18));
        assert_eq!(radio.channel_mhz, Some(2412));
        assert_eq!(radio.channel_flags, Some(0x00a0));
    }

    #[test]
    fn tsft_field_forces_eight_byte_alignment_walk() {
        // Bits: TSFT (0) | FLAGS (1). TSFT occupies 0..8 (align 8), FLAGS at 8.
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&le16(4 + 4));
        out.extend_from_slice(&le32((1u32 << 0) | (1u32 << 1)));
        out.extend_from_slice(&0x1122334455667788u64.to_le_bytes());
        out.push(FLAG_DATA_PAD);
        let total = out.len() as u16;
        out[2..4].copy_from_slice(&le16(total));
        let (radio, consumed) = parse(&out).expect("aligned walk parses");
        assert_eq!(consumed, 17);
        assert_eq!(radio.flags, Some(FLAG_DATA_PAD));
        assert!(radio.data_padded());
    }

    #[test]
    fn extended_present_bitmap_walks_two_words() {
        // Word 0 has bit 31 set (more) + bit 1 (FLAGS); word 1 has bit 2 (RATE).
        let word0 = 0x8000_0002u32; // FLAGS + extension
        let word1 = 1u32 << 2; // RATE
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&le16(4 + 8));
        out.extend_from_slice(&le32(word0));
        out.extend_from_slice(&le32(word1));
        out.push(FLAG_FCS_AT_END);
        out.push(0x60);
        let total = out.len() as u16;
        out[2..4].copy_from_slice(&le16(total));
        let (radio, consumed) = parse(&out).expect("extended bitmap parses");
        assert_eq!(consumed, 14);
        assert_eq!(radio.flags, Some(FLAG_FCS_AT_END));
        assert_eq!(radio.rate_500kbps, Some(0x60));
    }

    #[test]
    fn eight_present_words_are_accepted_nine_refused() {
        // Header with 9 present words must be refused (bounded). Extension
        // words chain from word 0, so every word carries the extension bit.
        let words = vec![0x8000_0000u32; 8];
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&le16((4 + words.len() * 4) as u16));
        for w in words {
            out.extend_from_slice(&le32(w));
        }
        let total = out.len() as u16;
        out[2..4].copy_from_slice(&le16(total));
        let err = parse(&out).expect_err("nine present words refuse");
        assert_eq!(err.code, WifiMonitorError::Protocol);
        assert!(err.message.contains("present bitmap"));
    }

    #[test]
    fn unknown_field_bit_is_refused_not_guessed() {
        // Bit 22 (TIMESTAMP) is outside the table: honest refusal.
        let frame = build(&[1 << 22], &[]);
        let err = parse(&frame).expect_err("untablable bit refuses");
        assert_eq!(err.code, WifiMonitorError::Protocol);
        assert!(err.message.contains("outside the parser table"));
    }

    #[test]
    fn xchannel_bit_is_refused_like_the_kernel_table() {
        let frame = build(&[1 << 18], &[0u8; 8]);
        let err = parse(&frame).expect_err("xchannel refuses");
        assert_eq!(err.code, WifiMonitorError::Protocol);
    }

    #[test]
    fn non_zero_version_is_refused() {
        let mut frame = build(&[0], &[]);
        frame[0] = 2;
        let err = parse(&frame).expect_err("version 2 refuses");
        assert_eq!(err.code, WifiMonitorError::Protocol);
        assert!(err.message.contains("version"));
    }

    #[test]
    fn oversized_and_truncated_headers_are_refused() {
        // Header length beyond the byte bound.
        let frame = build(&[0], &[]);
        let mut huge = frame.clone();
        let oversized = (MAX_HEADER_BYTES + 1) as u16;
        huge[2..4].copy_from_slice(&le16(oversized));
        assert_eq!(parse(&huge).unwrap_err().code, WifiMonitorError::Protocol);

        // Header length past the actual capture.
        let mut past = frame;
        past[2..4].copy_from_slice(&le16(64));
        assert_eq!(parse(&past).unwrap_err().code, WifiMonitorError::Protocol);

        // Below the minimum.
        assert_eq!(
            parse(&[0u8; 7]).unwrap_err().code,
            WifiMonitorError::Protocol
        );
    }

    #[test]
    fn field_past_capture_end_is_refused() {
        // FLAGS declared but the field bytes are missing.
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&le16(4 + 4));
        out.extend_from_slice(&le32(1));
        let err = parse(&out).expect_err("missing field bytes refuse");
        assert_eq!(err.code, WifiMonitorError::Protocol);
        assert!(err.message.contains("past the stated header length"));
    }

    #[test]
    fn fcs_and_pad_flags_surface_exact_bits() {
        let frame = build(&[1 << 1], &[FLAG_FCS_AT_END | FLAG_DATA_PAD | FLAG_BAD_FCS]);
        let (radio, _) = parse(&frame).expect("parses");
        assert!(radio.fcs_present());
        assert!(radio.data_padded());
        assert!(radio.fcs_bad());
    }
}

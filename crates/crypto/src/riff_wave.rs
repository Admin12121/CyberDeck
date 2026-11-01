//! Read-only bounded RIFF/WAVE carving boundary validation.
//!
//! Validates container size and all chunk boundaries, basic PCM/IEEE-float fmt
//! consistency and a nonempty aligned data chunk. It does not decode audio.
//! No recovered bytes or paths are produced.
pub const MAX_RIFF_WAVE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RIFF_CHUNKS: usize = 4096;

fn u16le(input: &[u8], offset: usize) -> Result<u16, String> {
    let raw = input.get(offset..offset + 2).ok_or("truncated RIFF u16")?;
    Ok(u16::from_le_bytes(raw.try_into().unwrap()))
}
fn u32le(input: &[u8], offset: usize) -> Result<u32, String> {
    let raw = input.get(offset..offset + 4).ok_or("truncated RIFF u32")?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

/// Return the complete declared WAV member length, never an extracted payload.
/// Reject truncated, malformed, huge or internally inconsistent candidates.
pub fn validated_wave_length(input: &[u8]) -> Result<usize, String> {
    if input.len() < 12
        || input.len() > MAX_RIFF_WAVE_BYTES
        || input.get(0..4) != Some(&b"RIFF"[..])
        || input.get(8..12) != Some(&b"WAVE"[..])
    {
        return Err("not a bounded RIFF/WAVE candidate".into());
    }
    let declared = (u32le(input, 4)? as usize)
        .checked_add(8)
        .ok_or("RIFF size overflow")?;
    if declared < 12 || declared > input.len() {
        return Err("truncated RIFF container".into());
    }
    let mut pos = 12usize;
    let mut chunks = 0usize;
    let mut fmt_block_align = None;
    let mut data_found = false;
    while pos < declared {
        chunks += 1;
        if chunks > MAX_RIFF_CHUNKS || declared - pos < 8 {
            return Err("RIFF chunk count or header invalid".into());
        }
        let tag = input.get(pos..pos + 4).ok_or("truncated RIFF chunk")?;
        let size = u32le(input, pos + 4)? as usize;
        let body = pos.checked_add(8).ok_or("RIFF offset overflow")?;
        let end = body.checked_add(size).ok_or("RIFF chunk overflow")?;
        let padded_end = end.checked_add(size & 1).ok_or("RIFF padding overflow")?;
        if padded_end > declared {
            return Err("truncated RIFF chunk payload or padding".into());
        }
        if tag == b"fmt " {
            if fmt_block_align.is_some() || size < 16 {
                return Err("duplicate or short RIFF WAVE fmt chunk".into());
            }
            let encoding = u16le(input, body)?;
            let channels = u16le(input, body + 2)?;
            let rate = u32le(input, body + 4)?;
            let byte_rate = u32le(input, body + 8)?;
            let align = u16le(input, body + 12)?;
            let bits = u16le(input, body + 14)?;
            if !matches!(encoding, 1 | 3)
                || channels == 0
                || channels > 32
                || rate == 0
                || !matches!(bits, 8 | 16 | 24 | 32 | 64)
                || (encoding == 3 && !matches!(bits, 32 | 64))
            {
                return Err("unsupported or invalid WAVE format".into());
            }
            let expected_align = u32::from(channels) * u32::from(bits) / 8;
            if expected_align != u32::from(align)
                || rate.checked_mul(u32::from(align)) != Some(byte_rate)
            {
                return Err("inconsistent WAVE rate or sample alignment".into());
            }
            fmt_block_align = Some(align as usize);
        } else if tag == b"data" {
            if data_found || size == 0 {
                return Err("duplicate or empty WAVE data chunk".into());
            }
            data_found = true;
            // Validate alignment after the fmt chunk has been seen; this is
            // intentionally conservative and rejects data-before-fmt files.
            let align = fmt_block_align.ok_or("WAVE data precedes fmt chunk")?;
            if size % align != 0 {
                return Err("misaligned WAVE sample data".into());
            }
        }
        pos = padded_end;
    }
    if pos != declared || !data_found || fmt_block_align.is_none() {
        return Err("incomplete RIFF/WAVE structure".into());
    }
    Ok(declared)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(tag);
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(body);
        if body.len() % 2 == 1 {
            buf.push(0);
        }
        buf
    }
    fn wave() -> Vec<u8> {
        let fmt = [
            1u16.to_le_bytes().as_slice(),
            1u16.to_le_bytes().as_slice(),
            8_000u32.to_le_bytes().as_slice(),
            8_000u32.to_le_bytes().as_slice(),
            1u16.to_le_bytes().as_slice(),
            8u16.to_le_bytes().as_slice(),
        ]
        .concat();
        let mut body = b"WAVE".to_vec();
        body.extend(chunk(b"fmt ", &fmt));
        body.extend(chunk(b"data", &[1, 2, 3]));
        let mut out = b"RIFF".to_vec();
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend(body);
        out
    }
    #[test]
    fn validates_pcm_audio_chunk_boundaries_and_ignores_external_suffix() {
        let src = wave();
        assert_eq!(validated_wave_length(&src).unwrap(), src.len());
        let mut embed = src.clone();
        embed.extend_from_slice(b"unrelated trailing bytes");
        assert_eq!(validated_wave_length(&embed).unwrap(), src.len());
    }
    #[test]
    fn rejects_truncation_wrong_sizes_and_corrupted_format() {
        let good = wave();
        for size in [0, 8, good.len() - 1] {
            assert!(validated_wave_length(&good[..size]).is_err());
        }
        let mut corrupted = good.clone();
        corrupted[4..8].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert!(validated_wave_length(&corrupted).is_err());
        let mut invalid_rate = good.clone();
        invalid_rate[28] ^= 1; // byte rate in fmt block, but sample rate unchanged
        assert!(validated_wave_length(&invalid_rate).is_err());
        let mut wrong_tag = good.clone();
        wrong_tag[8] = b'X';
        assert!(validated_wave_length(&wrong_tag).is_err());
        let mut no_data = good.clone();
        no_data.truncate(12 + 8 + 16);
        let declared = (no_data.len() - 8) as u32;
        no_data[4..8].copy_from_slice(&declared.to_le_bytes());
        assert!(validated_wave_length(&no_data).is_err());
    }
    #[test]
    fn invalid_chunk_alignment_and_oversized_input_fail_closed() {
        let mut wrong_align = wave();
        // Original data size is 3 bytes for 8-bit mono. Change it to 2,
        // leaving a dangling byte/pad that fails the next chunk boundary.
        let data_len_offset = 12 + 24 + 4;
        wrong_align[data_len_offset..data_len_offset + 4].copy_from_slice(&2_u32.to_le_bytes());
        assert!(validated_wave_length(&wrong_align).is_err());
        assert!(validated_wave_length(&vec![0; MAX_RIFF_WAVE_BYTES + 1]).is_err());
    }
}

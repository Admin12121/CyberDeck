//! Bounded GIF87a/GIF89a structural member boundary validation.
//! This does not perform LZW decompression, pixel validation or fragment recovery.
pub(super) fn validated_gif_length(data: &[u8]) -> Result<usize, String> {
    if data.len() < 13 || !matches!(data.get(..6), Some(b"GIF87a") | Some(b"GIF89a")) {
        return Err("invalid GIF header".into());
    }
    let width = u16::from_le_bytes([data[6], data[7]]) as usize;
    let height = u16::from_le_bytes([data[8], data[9]]) as usize;
    if width == 0 || height == 0 {
        return Err("invalid GIF canvas dimensions".into());
    }
    let mut pos = 13usize;
    let has_global_palette = data[10] & 0x80 != 0;
    if has_global_palette {
        pos = pos
            .checked_add(palette_bytes(data[10]))
            .ok_or("GIF palette overflow")?;
        if pos > data.len() {
            return Err("truncated GIF global palette".into());
        }
    }
    let mut images = 0usize;
    for _ in 0..8192 {
        let marker = *data.get(pos).ok_or("truncated GIF block")?;
        pos += 1;
        match marker {
            0x3b => {
                if images == 0 {
                    return Err("GIF has no validated frames".into());
                }
                return Ok(pos);
            }
            0x2c => {
                let descriptor = data
                    .get(pos..pos.checked_add(9).ok_or("GIF descriptor overflow")?)
                    .ok_or("truncated GIF image descriptor")?;
                let left = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
                let top = u16::from_le_bytes([descriptor[2], descriptor[3]]) as usize;
                let frame_width = u16::from_le_bytes([descriptor[4], descriptor[5]]) as usize;
                let frame_height = u16::from_le_bytes([descriptor[6], descriptor[7]]) as usize;
                if frame_width == 0
                    || frame_height == 0
                    || left.checked_add(frame_width).is_none_or(|n| n > width)
                    || top.checked_add(frame_height).is_none_or(|n| n > height)
                    || descriptor[8] & 0x18 != 0
                {
                    return Err("invalid GIF frame dimensions or flags".into());
                }
                pos += 9;
                if !has_global_palette && descriptor[8] & 0x80 == 0 {
                    return Err("GIF frame has no global or local color table".into());
                }
                if descriptor[8] & 0x80 != 0 {
                    pos = pos
                        .checked_add(palette_bytes(descriptor[8]))
                        .ok_or("GIF local palette overflow")?;
                    if pos > data.len() {
                        return Err("truncated GIF local palette".into());
                    }
                }
                let code_size = *data.get(pos).ok_or("truncated GIF LZW code size")?;
                if !(2..=8).contains(&code_size) {
                    return Err("invalid GIF LZW code size".into());
                }
                pos += 1;
                consume_subblocks(data, &mut pos, true)?;
                images += 1;
            }
            0x21 => {
                let label = *data.get(pos).ok_or("truncated GIF extension")?;
                pos += 1;
                match label {
                    0xf9 => {
                        let gce = data
                            .get(pos..pos.checked_add(6).ok_or("GIF GCE overflow")?)
                            .ok_or("truncated GIF graphics control extension")?;
                        if gce[0] != 4 || gce[5] != 0 || gce[1] & 0xe0 != 0 {
                            return Err("invalid GIF graphics control extension".into());
                        }
                        pos += 6;
                    }
                    0xfe => consume_subblocks(data, &mut pos, false)?,
                    0xff | 0x01 => {
                        let len = if label == 0xff { 11usize } else { 12usize };
                        if data.get(pos).copied() != Some(len as u8) {
                            return Err("invalid GIF extension header length".into());
                        }
                        pos = pos.checked_add(len + 1).ok_or("GIF extension overflow")?;
                        if pos > data.len() {
                            return Err("truncated GIF extension".into());
                        }
                        consume_subblocks(data, &mut pos, false)?;
                    }
                    _ => return Err("unsupported GIF extension type".into()),
                }
            }
            _ => return Err("unexpected GIF block marker".into()),
        }
    }
    Err("GIF block limit exceeded".into())
}

fn palette_bytes(packed: u8) -> usize {
    // GIF palette exponent is only three bits, hence at most 768 bytes.
    3usize << ((packed & 0x07) as usize + 1)
}

fn consume_subblocks(data: &[u8], pos: &mut usize, require_payload: bool) -> Result<(), String> {
    let mut contains_payload = false;
    for _ in 0..8192 {
        let length = *data.get(*pos).ok_or("truncated GIF subblock")? as usize;
        *pos = pos.checked_add(1).ok_or("GIF block offset overflow")?;
        if length == 0 {
            if require_payload && !contains_payload {
                return Err("empty GIF image data".into());
            }
            return Ok(());
        }
        *pos = pos
            .checked_add(length)
            .ok_or("GIF subblock offset overflow")?;
        if *pos > data.len() {
            return Err("truncated GIF subblock payload".into());
        }
        contains_payload = true;
    }
    Err("GIF subblock count limit exceeded".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A standard single-pixel GIF89a with an actual image-data subblock.
    fn gif() -> Vec<u8> {
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b".to_vec()
    }

    #[test]
    fn gif_validates_complete_member_and_comment_extension_not_suffix() {
        let mut source = gif();
        assert_eq!(validated_gif_length(&source).unwrap(), source.len());
        source.extend_from_slice(b"trailing unrelated evidence");
        assert_eq!(validated_gif_length(&source).unwrap(), 35);
        let mut commented = gif();
        commented.splice(19..19, b"\x21\xfe\x03abc\x00".iter().copied());
        assert_eq!(validated_gif_length(&commented).unwrap(), commented.len());
        commented[..6].copy_from_slice(b"GIF87a");
        assert_eq!(validated_gif_length(&commented).unwrap(), commented.len());
    }

    #[test]
    fn gif_rejects_truncated_or_malformed_palettes_frames_lzw_and_subblocks() {
        let valid = gif();
        for end in [0, 5, 12, 13, 18, 25, 30, valid.len() - 1] {
            assert!(validated_gif_length(&valid[..end]).is_err(), "end={end}");
        }
        let mut invalid = valid.clone();
        invalid[6] = 0; // zero canvas width
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid[10] = 0; // no global palette, image has no local palette
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid[10] = 0x87; // claims 768-byte global palette
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid[23] = 2; // frame width now exceeds logical canvas
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid[29] = 1; // invalid LZW minimum code size
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid[30] = 255; // image data length beyond buffer
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid[34] = 0x00; // missing trailer
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid[19] = 0x3b; // trailer before any frame
        assert!(validated_gif_length(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid.splice(19..19, b"\x21\xff\x0bshort".iter().copied());
        assert!(validated_gif_length(&invalid).is_err());
    }
}

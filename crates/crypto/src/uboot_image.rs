//! Legacy U-Boot uImage structural boundary and CRC32 validation.
//! CRCs detect corruption, not authenticity. This never executes, unpacks,
//! decrypts or trusts embedded firmware payloads.
pub(super) fn validated_uimage_length(data: &[u8]) -> Result<usize, String> {
    const HEADER: usize = 64;
    const MAGIC: [u8; 4] = [0x27, 0x05, 0x19, 0x56];
    if data.len() < HEADER || data[..4] != MAGIC {
        return Err("invalid/truncated U-Boot legacy image header".into());
    }
    let read32 = |at: usize| {
        u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
    };
    let length = read32(12) as usize;
    let total = HEADER.checked_add(length).ok_or("uImage size overflow")?;
    if length == 0 || total > data.len() {
        return Err("empty or truncated uImage payload".into());
    }
    let mut header_crc = crc32fast::Hasher::new();
    header_crc.update(&data[..4]);
    header_crc.update(&[0, 0, 0, 0]);
    header_crc.update(&data[8..HEADER]);
    if header_crc.finalize() != read32(4) {
        return Err("uImage header CRC32 mismatch".into());
    }
    if crc32fast::hash(&data[HEADER..total]) != read32(24) {
        return Err("uImage payload CRC32 mismatch".into());
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(&[0x27, 0x05, 0x19, 0x56]);
        bytes[8..12].copy_from_slice(&0x12345678u32.to_be_bytes()); // recorded timestamp
        bytes[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
        bytes[16..20].copy_from_slice(&0x8000_8000u32.to_be_bytes()); // recorded load address
        bytes[20..24].copy_from_slice(&0x8000_8000u32.to_be_bytes());
        bytes[24..28].copy_from_slice(&crc32fast::hash(body).to_be_bytes());
        bytes[28..32].copy_from_slice(&[5, 2, 2, 1]); // Linux, ARM, kernel, gzip indicator
        bytes[32..43].copy_from_slice(b"Test Kernel");
        let header_crc = crc32fast::hash(&bytes);
        bytes[4..8].copy_from_slice(&header_crc.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn complete_uboot_member_is_crc_checked_and_boundary_exact() {
        let original = image(b"native-test-firmware");
        assert_eq!(validated_uimage_length(&original).unwrap(), original.len());
        let mut trailing = original.clone();
        trailing.extend_from_slice(b"unrelated trailing bytes");
        assert_eq!(validated_uimage_length(&trailing).unwrap(), original.len());
    }

    #[test]
    fn uimage_rejects_incomplete_header_bad_crcs_size_and_tamper() {
        let original = image(b"native-test-firmware");
        for end in [0, 3, 31, 63, 64, original.len() - 1] {
            assert!(validated_uimage_length(&original[..end]).is_err(), "end={end}");
        }
        let mut invalid = original.clone();
        invalid[0] ^= 1;
        assert!(validated_uimage_length(&invalid).is_err());
        let mut invalid = original.clone();
        invalid[32] ^= 1; // header name corruption without updated header CRC
        assert!(validated_uimage_length(&invalid).is_err());
        let mut invalid = original.clone();
        invalid[64] ^= 1; // payload corruption
        assert!(validated_uimage_length(&invalid).is_err());
        let mut invalid = original.clone();
        invalid[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(validated_uimage_length(&invalid).is_err());
        let mut invalid = original.clone();
        invalid[12..16].fill(0); // zero-length image rejected
        assert!(validated_uimage_length(&invalid).is_err());
    }
}

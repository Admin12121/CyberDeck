//! RFC 5869 HKDF-SHA256 for bounded binary key material.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::sync::atomic::{compiler_fence, Ordering};

const HASH_LEN: usize = 32;
pub const MAX_HKDF_IKM_BYTES: usize = 4096;
pub const MAX_HKDF_SALT_BYTES: usize = 1024;
pub const MAX_HKDF_INFO_BYTES: usize = 1024;
pub const MAX_HKDF_OUTPUT_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    EmptyInput,
    InputTooLong,
    SaltTooLong,
    InfoTooLong,
    InvalidOutputLength,
    InternalFailure,
}

impl fmt::Display for HkdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyInput => "input key material must not be empty",
            Self::InputTooLong => "input key material exceeds HKDF limit",
            Self::SaltTooLong => "HKDF salt exceeds length limit",
            Self::InfoTooLong => "HKDF context exceeds length limit",
            Self::InvalidOutputLength => "HKDF output length is outside supported range",
            Self::InternalFailure => "HKDF computation unavailable",
        })
    }
}

impl std::error::Error for HkdfError {}

/// Transient output key material. Not Clone, Debug, or serializable.
pub struct HkdfOutput(Vec<u8>);

impl HkdfOutput {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for HkdfOutput {
    fn drop(&mut self) {
        self.0.fill(0);
        compiler_fence(Ordering::SeqCst);
    }
}

struct SecretBlock([u8; HASH_LEN]);

impl Drop for SecretBlock {
    fn drop(&mut self) {
        self.0.fill(0);
        compiler_fence(Ordering::SeqCst);
    }
}

/// RFC 5869 extract-and-expand with HMAC-SHA256. Inputs are raw bytes.
///
/// Empty salt follows the RFC's all-zero-salt definition. HKDF does not slow
/// down password guessing: callers must supply suitable input key material,
/// rather than use this in place of password-based derivation.
pub fn derive_hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<HkdfOutput, HkdfError> {
    if ikm.is_empty() {
        return Err(HkdfError::EmptyInput);
    }
    if ikm.len() > MAX_HKDF_IKM_BYTES {
        return Err(HkdfError::InputTooLong);
    }
    if salt.len() > MAX_HKDF_SALT_BYTES {
        return Err(HkdfError::SaltTooLong);
    }
    if info.len() > MAX_HKDF_INFO_BYTES {
        return Err(HkdfError::InfoTooLong);
    }
    if output_len == 0 || output_len > MAX_HKDF_OUTPUT_BYTES {
        return Err(HkdfError::InvalidOutputLength);
    }
    let blocks = output_len
        .checked_add(HASH_LEN - 1)
        .and_then(|length| length.checked_div(HASH_LEN))
        .filter(|count| *count <= u8::MAX as usize)
        .ok_or(HkdfError::InvalidOutputLength)?;

    let zeros = [0u8; HASH_LEN];
    let extract_salt = if salt.is_empty() {
        zeros.as_slice()
    } else {
        salt
    };
    let mut extractor =
        Hmac::<Sha256>::new_from_slice(extract_salt).map_err(|_| HkdfError::InternalFailure)?;
    extractor.update(ikm);
    let mut prk = SecretBlock([0; HASH_LEN]);
    prk.0.copy_from_slice(&extractor.finalize().into_bytes());

    let mut output = HkdfOutput(vec![0; output_len]);
    let mut previous = SecretBlock([0; HASH_LEN]);
    for index in 1..=blocks {
        let mut hmac =
            Hmac::<Sha256>::new_from_slice(&prk.0).map_err(|_| HkdfError::InternalFailure)?;
        if index > 1 {
            hmac.update(&previous.0);
        }
        hmac.update(info);
        hmac.update(&[u8::try_from(index).map_err(|_| HkdfError::InvalidOutputLength)?]);
        previous.0.copy_from_slice(&hmac.finalize().into_bytes());
        let offset = (index - 1)
            .checked_mul(HASH_LEN)
            .ok_or(HkdfError::InvalidOutputLength)?;
        let length = (output_len - offset).min(HASH_LEN);
        output.0[offset..offset + length].copy_from_slice(&previous.0[..length]);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_appendix_a1_sha256() {
        let ikm = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let key = derive_hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            concat!(
                "3cb25f25faacd57a90434f64d0362f2a",
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            )
        );
    }

    #[test]
    fn rfc5869_appendix_a2_long_binary_inputs() {
        let ikm: Vec<u8> = (0u8..80).collect();
        let salt: Vec<u8> = (0x60u8..0xb0).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        let key = derive_hkdf_sha256(&ikm, &salt, &info, 82).unwrap();
        assert_eq!(
            hex::encode(key.as_bytes()),
            concat!(
                "b11e398dc80327a1c8e7f78c596a4934",
                "4f012eda2d4efad8a050cc4c19afa97c",
                "59045a99cac7827271cb41c65e590e09",
                "da3275600c2f09b8367793a9aca3db71",
                "cc30c58179ec3e87c14c01d5c1f3434f",
                "1d87"
            )
        );
    }

    #[test]
    fn rfc5869_appendix_a3_no_salt_or_context() {
        let output = derive_hkdf_sha256(&[0x0b; 22], b"", b"", 42).unwrap();
        assert_eq!(
            hex::encode(output.as_bytes()),
            concat!(
                "8da4e775a563c18f715f802a063c5a31",
                "b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8"
            )
        );
    }

    #[test]
    fn binary_context_and_deterministic_domain_separation() {
        let ikm = b"\x00\xff\x01\x80secret";
        let salt = b"\x00\xffsalt";
        let a = derive_hkdf_sha256(ikm, salt, b"\x00context\xff", 64).unwrap();
        let b = derive_hkdf_sha256(ikm, salt, b"\x00context\xff", 64).unwrap();
        let other = derive_hkdf_sha256(ikm, salt, b"\x00context\xfe", 64).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), other.as_bytes());
        assert_eq!(a.len(), 64);
        assert!(!a.is_empty());
        assert_eq!(derive_hkdf_sha256(ikm, salt, b"", 1).unwrap().len(), 1);
    }

    #[test]
    fn rejects_invalid_and_excessive_parameters_before_allocation() {
        assert_eq!(
            derive_hkdf_sha256(b"", b"", b"", 32).err(),
            Some(HkdfError::EmptyInput)
        );
        assert_eq!(
            derive_hkdf_sha256(&vec![1; MAX_HKDF_IKM_BYTES + 1], b"", b"", 32).err(),
            Some(HkdfError::InputTooLong)
        );
        assert_eq!(
            derive_hkdf_sha256(b"x", &vec![0; MAX_HKDF_SALT_BYTES + 1], b"", 32).err(),
            Some(HkdfError::SaltTooLong)
        );
        assert_eq!(
            derive_hkdf_sha256(b"x", b"", &vec![0; MAX_HKDF_INFO_BYTES + 1], 32).err(),
            Some(HkdfError::InfoTooLong)
        );
        for length in [0, MAX_HKDF_OUTPUT_BYTES + 1, usize::MAX] {
            assert_eq!(
                derive_hkdf_sha256(b"x", b"", b"", length).err(),
                Some(HkdfError::InvalidOutputLength)
            );
        }
    }

    #[test]
    fn exact_boundaries_and_multiblock_result() {
        let ikm = vec![0x33; MAX_HKDF_IKM_BYTES];
        let salt = vec![0x55; MAX_HKDF_SALT_BYTES];
        let info = vec![0x77; MAX_HKDF_INFO_BYTES];
        let max = derive_hkdf_sha256(&ikm, &salt, &info, MAX_HKDF_OUTPUT_BYTES).unwrap();
        assert_eq!(max.len(), MAX_HKDF_OUTPUT_BYTES);
        let second = derive_hkdf_sha256(&ikm, &salt, &info, MAX_HKDF_OUTPUT_BYTES).unwrap();
        assert_eq!(max.as_bytes(), second.as_bytes());
        assert_ne!(&max.as_bytes()[0..32], &max.as_bytes()[32..64]);
    }
}

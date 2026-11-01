//! Process-local AES-256-GCM with non-exportable session keys and owned nonces.

use aes_gcm::{
    aead::{rand_core::RngCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce, Tag,
};
use std::{
    fmt,
    sync::atomic::{compiler_fence, Ordering},
};

pub const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_AAD_BYTES: usize = 64 * 1024;
pub const MAX_SEALS_PER_SESSION: u64 = 1_048_576;

const MAGIC: &[u8; 4] = b"CDG1";
const VERSION: u8 = 1;
const ALGORITHM_AES_256_GCM: u8 = 1;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 4 + 1 + 1 + NONCE_BYTES + 4;
const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_PLAINTEXT_BYTES + TAG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    EntropyUnavailable,
    SessionInvalid,
    NonceExhausted,
    PlaintextTooLarge,
    AadTooLarge,
    EnvelopeTooLarge,
    MalformedEnvelope,
    UnsupportedEnvelope,
    ForeignSession,
    AuthenticationFailed,
    EncryptionFailed,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EntropyUnavailable => "secure operating-system randomness unavailable",
            Self::SessionInvalid => "encryption session is invalid",
            Self::NonceExhausted => "encryption session nonce limit exhausted",
            Self::PlaintextTooLarge => "plaintext exceeds encryption operation limit",
            Self::AadTooLarge => "associated data exceeds encryption operation limit",
            Self::EnvelopeTooLarge => "encrypted envelope exceeds operation limit",
            Self::MalformedEnvelope => "encrypted envelope is malformed",
            Self::UnsupportedEnvelope => "encrypted envelope version or algorithm unsupported",
            Self::ForeignSession => "encrypted envelope is not from this session",
            Self::AuthenticationFailed => "authenticated decryption failed",
            Self::EncryptionFailed => "authenticated encryption failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for AeadError {}

/// The key cannot be imported, exported, cloned, serialized, or persisted.
/// A fresh OS-generated key lasts only until this session is dropped or invalidated.
/// The nonce domain and counter are private; callers cannot supply or rewind nonces.
pub struct Aes256GcmSession {
    key: [u8; KEY_BYTES],
    nonce_domain: [u8; 4],
    next_nonce: u64,
    active: bool,
}

/// Plaintext returned only after successful tag validation; clears on Drop.
pub struct AuthenticatedPlaintext(Vec<u8>);

impl AuthenticatedPlaintext {
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

impl Drop for AuthenticatedPlaintext {
    fn drop(&mut self) {
        self.0.fill(0);
        compiler_fence(Ordering::SeqCst);
    }
}

impl Aes256GcmSession {
    /// Generate an ephemeral key and nonce domain from the operating-system CSPRNG.
    pub fn generate() -> Result<Self, AeadError> {
        let mut rng = OsRng;
        let mut key = [0u8; KEY_BYTES];
        if rng.try_fill_bytes(&mut key).is_err() {
            key.fill(0);
            compiler_fence(Ordering::SeqCst);
            return Err(AeadError::EntropyUnavailable);
        }
        let mut nonce_domain = [0u8; 4];
        if rng.try_fill_bytes(&mut nonce_domain).is_err() {
            key.fill(0);
            compiler_fence(Ordering::SeqCst);
            return Err(AeadError::EntropyUnavailable);
        }
        Ok(Self {
            key,
            nonce_domain,
            next_nonce: 0,
            active: true,
        })
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn invalidate(&mut self) {
        self.key.fill(0);
        self.nonce_domain.fill(0);
        compiler_fence(Ordering::SeqCst);
        self.active = false;
        self.next_nonce = MAX_SEALS_PER_SESSION;
    }

    /// Seal a bounded message; this consumes one nonce even if encryption later fails.
    ///
    /// Wire format: "CDG1" | version=1 | algorithm=1 | nonce[12] |
    /// aad_length_be[4] | ciphertext | tag[16].
    /// The entire fixed header followed by caller AAD is authenticated.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        self.ensure_active()?;
        validate_lengths(plaintext.len(), aad.len())?;
        let nonce = self.reserve_nonce()?;

        let mut header = [0u8; HEADER_BYTES];
        header[..4].copy_from_slice(MAGIC);
        header[4] = VERSION;
        header[5] = ALGORITHM_AES_256_GCM;
        header[6..18].copy_from_slice(&nonce);
        header[18..22].copy_from_slice(
            &u32::try_from(aad.len())
                .map_err(|_| AeadError::AadTooLarge)?
                .to_be_bytes(),
        );
        let authenticated_data = combined_aad(&header, aad)?;

        let mut encrypted = AuthenticatedPlaintext(plaintext.to_vec());
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_| AeadError::EncryptionFailed)?;
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &authenticated_data,
                &mut encrypted.0,
            )
            .map_err(|_| AeadError::EncryptionFailed)?;

        let capacity = HEADER_BYTES
            .checked_add(encrypted.len())
            .and_then(|len| len.checked_add(TAG_BYTES))
            .ok_or(AeadError::EnvelopeTooLarge)?;
        let mut envelope = Vec::with_capacity(capacity);
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(encrypted.as_bytes());
        envelope.extend_from_slice(tag.as_slice());
        Ok(envelope)
    }

    /// Decryption returns no plaintext unless the entire ciphertext and AAD authenticate.
    pub fn open(&self, envelope: &[u8], aad: &[u8]) -> Result<AuthenticatedPlaintext, AeadError> {
        self.ensure_active()?;
        if aad.len() > MAX_AAD_BYTES {
            return Err(AeadError::AadTooLarge);
        }
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(AeadError::EnvelopeTooLarge);
        }
        if envelope.len() < HEADER_BYTES + TAG_BYTES {
            return Err(AeadError::MalformedEnvelope);
        }
        let header = &envelope[..HEADER_BYTES];
        if &header[..4] != MAGIC {
            return Err(AeadError::MalformedEnvelope);
        }
        if header[4] != VERSION || header[5] != ALGORITHM_AES_256_GCM {
            return Err(AeadError::UnsupportedEnvelope);
        }
        if header[6..10] != self.nonce_domain {
            return Err(AeadError::ForeignSession);
        }
        if u32::from_be_bytes(
            header[18..22]
                .try_into()
                .map_err(|_| AeadError::MalformedEnvelope)?,
        ) as usize
            != aad.len()
        {
            return Err(AeadError::AuthenticationFailed);
        }
        let ciphertext_end = envelope
            .len()
            .checked_sub(TAG_BYTES)
            .ok_or(AeadError::MalformedEnvelope)?;
        let ciphertext = &envelope[HEADER_BYTES..ciphertext_end];
        if ciphertext.len() > MAX_PLAINTEXT_BYTES {
            return Err(AeadError::EnvelopeTooLarge);
        }
        let authenticated_data = combined_aad(header, aad)?;
        let mut candidate = AuthenticatedPlaintext(ciphertext.to_vec());
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|_| AeadError::EncryptionFailed)?;
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&header[6..18]),
                &authenticated_data,
                &mut candidate.0,
                Tag::from_slice(&envelope[ciphertext_end..]),
            )
            .map_err(|_| AeadError::AuthenticationFailed)?;
        Ok(candidate)
    }

    fn ensure_active(&self) -> Result<(), AeadError> {
        if self.active {
            Ok(())
        } else {
            Err(AeadError::SessionInvalid)
        }
    }

    fn reserve_nonce(&mut self) -> Result<[u8; NONCE_BYTES], AeadError> {
        if self.next_nonce >= MAX_SEALS_PER_SESSION {
            return Err(AeadError::NonceExhausted);
        }
        let current = self.next_nonce;
        self.next_nonce = current.checked_add(1).ok_or(AeadError::NonceExhausted)?;
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..4].copy_from_slice(&self.nonce_domain);
        nonce[4..].copy_from_slice(&current.to_be_bytes());
        Ok(nonce)
    }
}

impl Drop for Aes256GcmSession {
    fn drop(&mut self) {
        self.invalidate();
    }
}

fn validate_lengths(plaintext: usize, aad: usize) -> Result<(), AeadError> {
    if plaintext > MAX_PLAINTEXT_BYTES {
        return Err(AeadError::PlaintextTooLarge);
    }
    if aad > MAX_AAD_BYTES {
        return Err(AeadError::AadTooLarge);
    }
    HEADER_BYTES
        .checked_add(plaintext)
        .and_then(|len| len.checked_add(TAG_BYTES))
        .filter(|len| *len <= MAX_ENVELOPE_BYTES)
        .ok_or(AeadError::EnvelopeTooLarge)?;
    HEADER_BYTES
        .checked_add(aad)
        .ok_or(AeadError::AadTooLarge)?;
    Ok(())
}

fn combined_aad(header: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
    let capacity = header
        .len()
        .checked_add(aad.len())
        .ok_or(AeadError::AadTooLarge)?;
    let mut joined = Vec::with_capacity(capacity);
    joined.extend_from_slice(header);
    joined.extend_from_slice(aad);
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(key: [u8; 32], nonce_domain: [u8; 4], counter: u64) -> Aes256GcmSession {
        Aes256GcmSession {
            key,
            nonce_domain,
            next_nonce: counter,
            active: true,
        }
    }

    #[test]
    fn nist_aes256_gcm_zero_key_zero_nonce_known_answer_vectors() {
        // NIST AES-256-GCM zero key / zero IV: empty data and 128-bit zero block.
        let cipher = Aes256Gcm::new_from_slice(&[0u8; 32]).unwrap();
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let mut empty: Vec<u8> = vec![];
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut empty)
            .unwrap();
        assert!(empty.is_empty());
        assert_eq!(hex::encode(tag), "530f8afbc74536b9a963b4f1c4cb738b");

        let mut block = vec![0u8; 16];
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut block)
            .unwrap();
        assert_eq!(hex::encode(&block), "cea7403d4d606b6e074ec5d3baf39d18");
        assert_eq!(hex::encode(tag), "d0d1c8a799996bf0265b98b5d48ab919");
    }

    #[test]
    fn independent_node_crypto_fixture_matches_binary_aad_and_tag() {
        // Node.js createCipheriv("aes-256-gcm"), fixed binary key/nonce/P/AAD.
        let key: [u8; 32] =
            hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap()
                .try_into()
                .unwrap();
        let iv = hex::decode("0102030405060708090a0b0c").unwrap();
        let plaintext = hex::decode("0001ff007f804142ffdeadbeef").unwrap();
        let aad = hex::decode("cafe000102ffff").unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut output = plaintext.clone();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut output)
            .unwrap();
        assert_eq!(hex::encode(&output), "7a73faa09797e4031526167f83");
        assert_eq!(hex::encode(tag), "963fd60c892586c40136c52ebe958475");

        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut output, &tag)
            .unwrap();
        assert_eq!(output, plaintext);
    }

    #[test]
    fn roundtrip_empty_binary_and_aad_with_nonce_nonreuse() {
        let mut session = Aes256GcmSession::generate().unwrap();
        let empty = session.seal(b"", b"").unwrap();
        assert_eq!(empty.len(), HEADER_BYTES + TAG_BYTES);
        assert!(session.open(&empty, b"").unwrap().is_empty());
        let binary = b"\x00\xffbinary\x80\x00";
        let aad = b"case\x00id\xff";
        let first = session.seal(binary, aad).unwrap();
        let second = session.seal(binary, aad).unwrap();
        assert_ne!(&first[6..18], &second[6..18]);
        assert_ne!(first, second);
        assert_eq!(session.open(&first, aad).unwrap().as_bytes(), binary);
        assert_eq!(session.open(&second, aad).unwrap().as_bytes(), binary);
        assert_eq!(&first[..4], MAGIC);
        assert_eq!(first[4], VERSION);
        assert_eq!(first[5], ALGORITHM_AES_256_GCM);
    }

    #[test]
    fn rejects_foreign_key_wrong_aad_and_authenticated_tampering() {
        let mut sender = Aes256GcmSession::generate().unwrap();
        let other = Aes256GcmSession::generate().unwrap();
        let original = sender.seal(b"secret\x00text", b"case\xff").unwrap();
        assert_eq!(
            sender.open(&original, b"wrongaa").err(),
            Some(AeadError::AuthenticationFailed)
        );
        assert_eq!(
            sender.open(&original, b"case\xfe").err(),
            Some(AeadError::AuthenticationFailed)
        );
        assert!(matches!(
            other.open(&original, b"case\xff"),
            Err(AeadError::ForeignSession) | Err(AeadError::AuthenticationFailed)
        ));
        let matching_domain_wrong_key = test_session([0x42; 32], sender.nonce_domain, 0);
        assert_eq!(
            matching_domain_wrong_key.open(&original, b"case\xff").err(),
            Some(AeadError::AuthenticationFailed)
        );
        let mut corrupted = original.clone();
        corrupted[HEADER_BYTES] ^= 1;
        assert_eq!(
            sender.open(&corrupted, b"case\xff").err(),
            Some(AeadError::AuthenticationFailed)
        );
        let mut corrupted = original.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(
            sender.open(&corrupted, b"case\xff").err(),
            Some(AeadError::AuthenticationFailed)
        );
        let mut corrupted = original.clone();
        corrupted[17] ^= 1;
        assert_eq!(
            sender.open(&corrupted, b"case\xff").err(),
            Some(AeadError::AuthenticationFailed)
        );
        let mut corrupted = original.clone();
        corrupted[21] ^= 1;
        assert_eq!(
            sender.open(&corrupted, b"case\xff").err(),
            Some(AeadError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_truncation_format_nonce_tag_and_oversize() {
        let mut session = Aes256GcmSession::generate().unwrap();
        let envelope = session.seal(b"\x00\x01", b"").unwrap();
        for length in 0..HEADER_BYTES + TAG_BYTES {
            assert_eq!(
                session.open(&envelope[..length], b"").err(),
                Some(AeadError::MalformedEnvelope)
            );
        }
        let mut bad = envelope.clone();
        bad[0] ^= 1;
        assert_eq!(
            session.open(&bad, b"").err(),
            Some(AeadError::MalformedEnvelope)
        );
        let mut bad = envelope.clone();
        bad[4] += 1;
        assert_eq!(
            session.open(&bad, b"").err(),
            Some(AeadError::UnsupportedEnvelope)
        );
        let mut bad = envelope.clone();
        bad[5] += 1;
        assert_eq!(
            session.open(&bad, b"").err(),
            Some(AeadError::UnsupportedEnvelope)
        );
        let mut bad = envelope.clone();
        bad[6] ^= 1;
        assert_eq!(
            session.open(&bad, b"").err(),
            Some(AeadError::ForeignSession)
        );
        let mut bad = envelope.clone();
        bad.truncate(HEADER_BYTES + TAG_BYTES);
        assert_eq!(
            session.open(&bad, b"").err(),
            Some(AeadError::AuthenticationFailed)
        );
        assert_eq!(
            session.open(&vec![0; MAX_ENVELOPE_BYTES + 1], b"").err(),
            Some(AeadError::EnvelopeTooLarge)
        );
    }

    #[test]
    fn allocation_limits_checked_and_validated_before_reserving_nonce() {
        let mut session = Aes256GcmSession::generate().unwrap();
        assert_eq!(
            validate_lengths(usize::MAX, 0),
            Err(AeadError::PlaintextTooLarge)
        );
        assert_eq!(validate_lengths(0, usize::MAX), Err(AeadError::AadTooLarge));
        assert_eq!(validate_lengths(MAX_PLAINTEXT_BYTES, MAX_AAD_BYTES), Ok(()));
        assert_eq!(
            session.seal(&vec![0; MAX_PLAINTEXT_BYTES + 1], b"").err(),
            Some(AeadError::PlaintextTooLarge)
        );
        assert_eq!(
            session.seal(b"", &vec![0; MAX_AAD_BYTES + 1]).err(),
            Some(AeadError::AadTooLarge)
        );
        assert_eq!(session.next_nonce, 0);
        let bounded = session.seal(&vec![0; MAX_PLAINTEXT_BYTES], b"").unwrap();
        assert_eq!(bounded.len(), MAX_ENVELOPE_BYTES);
        assert_eq!(
            session.open(&bounded, b"").unwrap().len(),
            MAX_PLAINTEXT_BYTES
        );
        assert_eq!(session.next_nonce, 1);
    }

    #[test]
    fn exhausted_session_never_reuses_nonce_or_returns_unauthenticated_material() {
        let mut session = test_session([7u8; 32], [1, 2, 3, 4], MAX_SEALS_PER_SESSION - 1);
        let envelope = session.seal(b"last", b"").unwrap();
        assert_eq!(
            u64::from_be_bytes(envelope[10..18].try_into().unwrap()),
            MAX_SEALS_PER_SESSION - 1
        );
        assert_eq!(
            session.seal(b"next", b"").err(),
            Some(AeadError::NonceExhausted)
        );
        assert_eq!(
            session.seal(b"again", b"").err(),
            Some(AeadError::NonceExhausted)
        );
        assert_eq!(session.open(&envelope, b"").unwrap().as_bytes(), b"last");
        session.invalidate();
        assert!(!session.is_active());
        assert_eq!(session.key, [0; 32]);
        assert_eq!(
            session.seal(b"x", b"").err(),
            Some(AeadError::SessionInvalid)
        );
        assert_eq!(
            session.open(&envelope, b"").err(),
            Some(AeadError::SessionInvalid)
        );
        session.invalidate();
        assert!(!session.is_active());
    }
}

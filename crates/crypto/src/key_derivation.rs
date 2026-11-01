//! Bounded, transient PBKDF2-HMAC-SHA256 key derivation.

use sha2::Sha256;
use std::fmt;
use std::sync::atomic::{compiler_fence, Ordering};

pub const PBKDF2_SHA256_DEFAULT_ITERATIONS: u32 = 600_000;
pub const PBKDF2_SHA256_MIN_ITERATIONS: u32 = 600_000;
pub const PBKDF2_SHA256_MAX_ITERATIONS: u32 = 2_000_000;
pub const PBKDF2_SHA256_MAX_PRF_CALLS: u64 = 2_000_000;
pub const PBKDF2_SHA256_MAX_PASSWORD_BYTES: usize = 4096;
pub const PBKDF2_SHA256_MIN_SALT_BYTES: usize = 16;
pub const PBKDF2_SHA256_MAX_SALT_BYTES: usize = 1024;
pub const PBKDF2_SHA256_MIN_KEY_BYTES: usize = 16;
pub const PBKDF2_SHA256_MAX_KEY_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pbkdf2Sha256Params {
    pub iterations: u32,
    pub output_len: usize,
}

impl Default for Pbkdf2Sha256Params {
    fn default() -> Self {
        Self {
            iterations: PBKDF2_SHA256_DEFAULT_ITERATIONS,
            output_len: 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDerivationError {
    EmptyPassword,
    PasswordTooLong,
    SaltTooShort,
    SaltTooLong,
    IterationsTooLow,
    IterationsTooHigh,
    InvalidKeyLength,
    WorkLimitExceeded,
}

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPassword => "password must not be empty",
            Self::PasswordTooLong => "password length exceeds derivation limit",
            Self::SaltTooShort => "salt length is below derivation policy",
            Self::SaltTooLong => "salt length exceeds derivation limit",
            Self::IterationsTooLow => "PBKDF2 iteration count is below production policy",
            Self::IterationsTooHigh => "PBKDF2 iteration count exceeds derivation limit",
            Self::InvalidKeyLength => "derived key length is outside derivation policy",
            Self::WorkLimitExceeded => "PBKDF2 work budget exceeded",
        };
        f.write_str(message)
    }
}

impl std::error::Error for KeyDerivationError {}

impl Pbkdf2Sha256Params {
    /// This is the production policy, not the low-cost RFC interoperability policy.
    pub fn validate(self, password_len: usize, salt_len: usize) -> Result<(), KeyDerivationError> {
        if password_len == 0 {
            return Err(KeyDerivationError::EmptyPassword);
        }
        if password_len > PBKDF2_SHA256_MAX_PASSWORD_BYTES {
            return Err(KeyDerivationError::PasswordTooLong);
        }
        if salt_len < PBKDF2_SHA256_MIN_SALT_BYTES {
            return Err(KeyDerivationError::SaltTooShort);
        }
        if salt_len > PBKDF2_SHA256_MAX_SALT_BYTES {
            return Err(KeyDerivationError::SaltTooLong);
        }
        if self.iterations < PBKDF2_SHA256_MIN_ITERATIONS {
            return Err(KeyDerivationError::IterationsTooLow);
        }
        if self.iterations > PBKDF2_SHA256_MAX_ITERATIONS {
            return Err(KeyDerivationError::IterationsTooHigh);
        }
        if !(PBKDF2_SHA256_MIN_KEY_BYTES..=PBKDF2_SHA256_MAX_KEY_BYTES).contains(&self.output_len) {
            return Err(KeyDerivationError::InvalidKeyLength);
        }
        let block_count = self
            .output_len
            .checked_add(31)
            .and_then(|bytes| bytes.checked_div(32))
            .ok_or(KeyDerivationError::WorkLimitExceeded)?;
        let work = u64::from(self.iterations)
            .checked_mul(
                u64::try_from(block_count).map_err(|_| KeyDerivationError::WorkLimitExceeded)?,
            )
            .ok_or(KeyDerivationError::WorkLimitExceeded)?;
        if work > PBKDF2_SHA256_MAX_PRF_CALLS {
            return Err(KeyDerivationError::WorkLimitExceeded);
        }
        Ok(())
    }
}

/// A transient, non-serializable, non-cloneable key. Callers control exposure.
/// Drop overwrites the owned buffer on a best-effort basis, not a guarantee
/// that temporary copies, swaps, process dumps, or hardware retain no bytes.
pub struct DerivedKey {
    bytes: [u8; PBKDF2_SHA256_MAX_KEY_BYTES],
    len: usize,
}

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
        compiler_fence(Ordering::SeqCst);
    }
}

/// Derive transient key bytes without converting passwords or salts to text.
/// Parameters are rejected before any cryptographic work or heap allocation.
pub fn derive_pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    params: Pbkdf2Sha256Params,
) -> Result<DerivedKey, KeyDerivationError> {
    params.validate(password.len(), salt.len())?;
    let mut key = DerivedKey {
        bytes: [0; PBKDF2_SHA256_MAX_KEY_BYTES],
        len: params.output_len,
    };
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, params.iterations, &mut key.bytes[..key.len]);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn rfc7914_section11_low_iteration_vectors_do_not_override_policy() {
        // Independent published RFC 7914 Section 11 vectors. Intentionally
        // exercise only the vetted primitive with non-production parameters.
        let mut one = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"passwd", b"salt", 1, &mut one);
        assert_eq!(
            hex::encode(one),
            concat!(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
            )
        );
        let mut eighty_thousand = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"Password", b"NaCl", 80_000, &mut eighty_thousand);
        assert_eq!(
            hex::encode(eighty_thousand),
            concat!(
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56",
                "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
            )
        );
        assert_eq!(
            Pbkdf2Sha256Params {
                iterations: 1,
                output_len: 64
            }
            .validate(6, 16),
            Err(KeyDerivationError::IterationsTooLow)
        );
        assert_eq!(
            Pbkdf2Sha256Params {
                iterations: 80_000,
                output_len: 64
            }
            .validate(8, 16),
            Err(KeyDerivationError::IterationsTooLow)
        );
    }

    #[test]
    fn production_default_matches_independent_python_hashlib() {
        let params = Pbkdf2Sha256Params::default();
        assert_eq!(params.iterations, 600_000);
        assert_eq!(params.output_len, 32);
        let output = derive_pbkdf2_hmac_sha256(b"password", b"0123456789abcdef", params).unwrap();
        assert_eq!(
            hex::encode(output.as_bytes()),
            "996d7c90f74a4a169cf7adef42b06848f7d1bac3e568d1cc94d4f79be1ee0263"
        );
        assert_eq!(output.len(), 32);
        assert!(!output.is_empty());
    }

    #[test]
    fn arbitrary_binary_inputs_and_multiple_key_lengths_match_hashlib() {
        let password = b"pass\x00word\xff";
        let salt = b"\x00salt\xff\x01\x00salt\xff\x01\x00salt\xff\x01\x00salt\xff\x01";
        let binary =
            derive_pbkdf2_hmac_sha256(password, salt, Pbkdf2Sha256Params::default()).unwrap();
        assert_eq!(
            hex::encode(binary.as_bytes()),
            "581f7ce9a795114fd592fac53009e3ad3e276d5102acde225d0ae7bef0bd197d"
        );
        let longer = derive_pbkdf2_hmac_sha256(
            b"password",
            b"0123456789abcdef",
            Pbkdf2Sha256Params {
                iterations: 600_000,
                output_len: 64,
            },
        )
        .unwrap();
        assert_eq!(
            hex::encode(longer.as_bytes()),
            concat!(
                "996d7c90f74a4a169cf7adef42b06848f7d1bac3e568d1cc94d4f79be1ee0263",
                "8216e27f0dc60811a37ec45abde9c526465e014b3952987f6bebf9fb3a54da63"
            )
        );
        let again =
            derive_pbkdf2_hmac_sha256(password, salt, Pbkdf2Sha256Params::default()).unwrap();
        assert_eq!(again.as_bytes(), binary.as_bytes());
        assert_ne!(longer.as_bytes(), binary.as_bytes());
    }

    #[test]
    fn nondefault_production_iterations_and_shorter_key_match_hashlib() {
        let salt = b"0123456789abcdef";
        let custom = derive_pbkdf2_hmac_sha256(
            b"password",
            salt,
            Pbkdf2Sha256Params {
                iterations: 700_000,
                output_len: 16,
            },
        )
        .unwrap();
        assert_eq!(
            hex::encode(custom.as_bytes()),
            "73c945c664c5b94b147c43c0e6114070"
        );
        let default_work = derive_pbkdf2_hmac_sha256(
            b"password",
            salt,
            Pbkdf2Sha256Params {
                iterations: 600_000,
                output_len: 16,
            },
        )
        .unwrap();
        assert_eq!(
            hex::encode(default_work.as_bytes()),
            "996d7c90f74a4a169cf7adef42b06848"
        );
        assert_ne!(custom.as_bytes(), default_work.as_bytes());
    }

    #[test]
    fn rejects_invalid_lengths_iterations_and_work_before_kdf() {
        let params = Pbkdf2Sha256Params::default();
        assert_eq!(
            params.validate(0, 16),
            Err(KeyDerivationError::EmptyPassword)
        );
        assert_eq!(
            params.validate(4097, 16),
            Err(KeyDerivationError::PasswordTooLong)
        );
        assert_eq!(
            params.validate(1, 15),
            Err(KeyDerivationError::SaltTooShort)
        );
        assert_eq!(
            params.validate(1, 1025),
            Err(KeyDerivationError::SaltTooLong)
        );
        for n in [0, 1, 599_999] {
            assert_eq!(
                Pbkdf2Sha256Params {
                    iterations: n,
                    ..params
                }
                .validate(1, 16),
                Err(KeyDerivationError::IterationsTooLow)
            );
        }
        assert_eq!(
            Pbkdf2Sha256Params {
                iterations: 2_000_001,
                ..params
            }
            .validate(1, 16),
            Err(KeyDerivationError::IterationsTooHigh)
        );
        for output_len in [0, 1, 15, 65, usize::MAX] {
            assert_eq!(
                Pbkdf2Sha256Params {
                    output_len,
                    ..params
                }
                .validate(1, 16),
                Err(KeyDerivationError::InvalidKeyLength)
            );
        }
        assert_eq!(
            Pbkdf2Sha256Params {
                iterations: 1_000_001,
                output_len: 64
            }
            .validate(1, 16),
            Err(KeyDerivationError::WorkLimitExceeded)
        );
        assert_eq!(
            derive_pbkdf2_hmac_sha256(b"", b"0123456789abcdef", params).err(),
            Some(KeyDerivationError::EmptyPassword)
        );
        assert_eq!(
            derive_pbkdf2_hmac_sha256(b"a", b"short", params).err(),
            Some(KeyDerivationError::SaltTooShort)
        );
    }

    #[test]
    fn validates_exact_policy_boundaries_without_running_expensive_kdf() {
        let params = Pbkdf2Sha256Params::default();
        assert_eq!(params.validate(1, 16), Ok(()));
        assert_eq!(params.validate(4096, 1024), Ok(()));
        assert_eq!(
            Pbkdf2Sha256Params {
                iterations: 2_000_000,
                output_len: 32
            }
            .validate(4096, 1024),
            Ok(())
        );
        assert_eq!(
            Pbkdf2Sha256Params {
                iterations: 1_000_000,
                output_len: 64
            }
            .validate(4096, 1024),
            Ok(())
        );
        assert_eq!(
            Pbkdf2Sha256Params {
                iterations: 600_000,
                output_len: 16
            }
            .validate(1, 16),
            Ok(())
        );
        let text = KeyDerivationError::SaltTooShort.to_string();
        assert!(!text.contains("password") && !text.contains("0123456789abcdef"));
    }
}

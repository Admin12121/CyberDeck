//! Legacy password digest families that are not plain digests but are not
//! KDFs either: LAN Manager (DES) and MySQL pre-4.1/4.1+ style derivations.
//! Bounded, offline, own Rust code; test vectors come from john the Ripper.
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use sha1::Sha1;
use sha2::Digest;

/// LM half-encryption constant (the famous "KGS!@#$%").
const LM_MAGIC: [u8; 8] = *b"KGS!@#$%";
/// The well-known constant for an empty LM half.
pub const LM_EMPTY_HALF: [u8; 8] = [0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee];
/// LAN Manager passwords never exceed 14 characters.
pub const LM_MAX_PASSWORD_BYTES: usize = 14;

/// Expand 7 key bytes into a DES key with parity bits (the classic LM
/// schedule: bits are taken LSB-first and shifted into the high positions).
fn lm_expand_key(seven: &[u8]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = seven[0] >> 1;
    key[1] = ((seven[0] & 0x01) << 6) | (seven[1] >> 2);
    key[2] = ((seven[1] & 0x03) << 5) | (seven[2] >> 3);
    key[3] = ((seven[2] & 0x07) << 4) | (seven[3] >> 4);
    key[4] = ((seven[3] & 0x0f) << 3) | (seven[4] >> 5);
    key[5] = ((seven[4] & 0x1f) << 2) | (seven[5] >> 6);
    key[6] = ((seven[5] & 0x3f) << 1) | (seven[6] >> 7);
    key[7] = seven[6] & 0x7f;
    for byte in key.iter_mut() {
        *byte <<= 1;
    }
    key
}

fn lm_encrypt_half(seven: &[u8]) -> [u8; 8] {
    if seven.iter().all(|byte| *byte == 0) {
        return LM_EMPTY_HALF;
    }
    let key = lm_expand_key(seven);
    let cipher = Des::new_from_slice(&key).expect("DES key is always 8 bytes");
    let mut block = des::cipher::Block::<des::Des>::clone_from_slice(&LM_MAGIC);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// LAN Manager digest: UTF-16? No — OEM/ASCII uppercase, truncated to 14
/// bytes, split into two 7-byte halves, each DES-encrypting the constant.
pub fn lm_hash(password: &[u8]) -> [u8; 16] {
    let mut padded = [0u8; LM_MAX_PASSWORD_BYTES];
    let length = password.len().min(LM_MAX_PASSWORD_BYTES);
    for (index, byte) in password[..length].iter().enumerate() {
        padded[index] = byte.to_ascii_uppercase();
    }
    let first = lm_encrypt_half(&padded[..7]);
    let second = lm_encrypt_half(&padded[7..]);
    let mut digest = [0u8; 16];
    digest[..8].copy_from_slice(&first);
    digest[8..].copy_from_slice(&second);
    digest
}

/// MySQL 4.1+ digest: `*` + hex(sha1(sha1(password))).
pub fn mysql5_digest(password: &[u8]) -> [u8; 20] {
    let inner = Sha1::digest(password);
    Sha1::digest(inner).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply_op;

    #[test]
    fn lm_matches_john_test_vectors() {
        // john the Ripper LM_fmt.c vectors, combined into the 32-hex form:
        // an empty password yields two empty halves.
        assert_eq!(
            hex::encode(lm_hash(b"")),
            "aad3b435b51404eeaad3b435b51404ee"
        );
        assert_eq!(
            hex::encode(lm_hash(b"aaaaaa")),
            "a9c604d244c4e99daad3b435b51404ee"
        );
        assert_eq!(
            hex::encode(lm_hash(b"AAAAAAA")),
            "cbc501a4d2227783aad3b435b51404ee"
        );
        // Case is irrelevant: LM uppercases before digesting.
        assert_eq!(lm_hash(b"CRACKPO"), lm_hash(b"crackpo"));
        // Longer than 14 bytes truncates.
        assert_eq!(lm_hash(b"AAAAAAAAAAAAAA"), lm_hash(b"AAAAAAAAAAAAAAExtra"));
    }

    #[test]
    fn mysql5_matches_documented_derivation() {
        // MySQL 4.1+ is * + hex(sha1(sha1(password))); the canonical example
        // digest for "password" from MySQL documentation.
        let inner = apply_op("sha1", b"password", None).unwrap();
        let outer = hex::encode(Sha1::digest(&inner));
        assert_eq!(outer, "2470c0c06dee42fd1618bb99005adca2ec9d1e19");
        assert_eq!(
            hex::encode(mysql5_digest(b"password")),
            "2470c0c06dee42fd1618bb99005adca2ec9d1e19"
        );
    }
}

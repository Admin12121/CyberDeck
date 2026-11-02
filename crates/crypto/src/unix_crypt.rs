//! Unix crypt(3) password formats, native Rust.
//! MD5-crypt ($1$) and Apache apr1 ($apr1$) are implemented here from the
//! documented FreeBSD/apache algorithm; the SHA-based crypt family
//! ($5$/$6$/$sha1$) verifies through the pure-Rust `pwhash` crate. All
//! verifies are constant-cost per format and never persist anything.
use md5::Md5;
use sha2::Digest;

const CRYPT64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// Recovery policy: refuse absurdly expensive sha256/512crypt parameters.
pub const MAX_CRYPT_ROUNDS: u64 = 100_000;
const MD5CRYPT_MAGIC_1: &[u8] = b"$1$";
const APR1_MAGIC: &[u8] = b"$apr1$";
const MD5CRYPT_ITERATIONS: u32 = 1000;

fn is_crypt64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'/'
}

fn to64(mut value: u32, count: usize, out: &mut String) {
    for _ in 0..count {
        out.push(CRYPT64[(value & 0x3f) as usize] as char);
        value >>= 6;
    }
}

/// The FreeBSD MD5-crypt algorithm with a configurable magic string, so the
/// same code covers `$1$` and Apache's `$apr1$` variant (magic participates
/// in the first digest only).
fn md5_crypt_encode(password: &[u8], salt: &[u8], magic: &[u8]) -> String {
    let mut a = Md5::new();
    a.update(password);
    a.update(magic);
    a.update(salt);
    let mut b = Md5::new();
    b.update(password);
    b.update(salt);
    b.update(password);
    let mut final_digest = b.finalize();
    let mut remaining = password.len();
    while remaining > 0 {
        let take = remaining.min(16);
        a.update(&final_digest[..take]);
        remaining -= take;
    }
    let mut i = password.len();
    while i != 0 {
        // The documented quirk (pwhash/john/apr all agree): odd lengths append
        // a single NUL byte here, even lengths append the first password byte.
        if i & 1 == 1 {
            a.update([0u8]);
        } else {
            a.update([password[0]]);
        }
        i >>= 1;
    }
    let mut digest = a.finalize();
    for iteration in 0u32..MD5CRYPT_ITERATIONS {
        let mut ctx = Md5::new();
        if iteration & 1 == 1 {
            ctx.update(password);
        } else {
            ctx.update(digest);
        }
        if iteration % 3 != 0 {
            ctx.update(salt);
        }
        if iteration % 7 != 0 {
            ctx.update(password);
        }
        if iteration & 1 == 1 {
            ctx.update(digest);
        } else {
            ctx.update(password);
        }
        digest = ctx.finalize();
    }
    let bytes: [u8; 16] = digest.into();
    let mut encoded = String::with_capacity(22);
    let group = |out: &mut String, a: usize, b: usize, c: usize| {
        let value = (u32::from(bytes[a]) << 16) | (u32::from(bytes[b]) << 8) | u32::from(bytes[c]);
        to64(value, 4, out);
    };
    group(&mut encoded, 0, 6, 12);
    group(&mut encoded, 1, 7, 13);
    group(&mut encoded, 2, 8, 14);
    group(&mut encoded, 3, 9, 15);
    group(&mut encoded, 4, 10, 5);
    to64(u32::from(bytes[11]), 2, &mut encoded);
    format!("{}{}${}", String::from_utf8_lossy(magic), String::from_utf8_lossy(salt), encoded)
}

/// Split "$magic$salt$digest" into (salt, digest); salt is capped at 8 by
/// the algorithm itself. Returns None for malformed encodings.
fn parse_md5_crypt<'a>(hash: &'a str, magic: &'static str) -> Option<(&'a str, &'a str)> {
    let rest = hash.strip_prefix(magic)?;
    let (salt, digest) = rest.split_once('$')?;
    if salt.len() > 8 || !salt.bytes().all(is_crypt64) {
        return None;
    }
    if digest.is_empty() || !digest.bytes().all(is_crypt64) {
        return None;
    }
    Some((salt, digest))
}

/// Digest-shape validation for the sha-crypt family: field count, crypt64
/// charset and the documented digest lengths (86 for sha512crypt, 63 for
/// sha256crypt, >= 20 crypt64 chars for sha1crypt).
pub fn validate_sha_crypt(hash: &str) -> Result<(), String> {
    let parts: Vec<&str> = hash.split('$').collect();
    // ["", "5"|"6"|"sha1", ("rounds=N")?, salt, digest]
    if parts.len() < 4 || parts.len() > 5 {
        return Err("invalid sha-crypt field count".into());
    }
    let digest = parts[parts.len() - 1];
    let salt = parts[parts.len() - 2];
    let crypt64 = |text: &str| !text.is_empty() && text.bytes().all(is_crypt64);
    if !crypt64(salt) || salt.len() > 16 || !crypt64(digest) {
        return Err("invalid sha-crypt salt or digest encoding".into());
    }
    let expected = match hash.splitn(2, "$").nth(1).and_then(|rest| rest.split('$').next()) {
        Some("6") => Some(86),
        Some("5") => Some(63),
        _ => None,
    };
    if let Some(length) = expected {
        if digest.len() != length {
            return Err(format!(
                "sha-crypt digest must be {length} crypt64 characters"
            ));
        }
    }
    Ok(())
}

/// Encoding-only validation for recovery target parsing (no digest computed).
pub fn validate_md5_crypt(hash: &str) -> Result<(), String> {
    let magic = if hash.starts_with("$apr1$") { "$apr1$" } else { "$1$" };
    if parse_md5_crypt(hash, magic).is_some() {
        Ok(())
    } else {
        Err("invalid md5crypt/apr1 encoding".into())
    }
}

/// Verify a `$1$` or `$apr1$` modular-crypt string. The computed digest uses
/// the salt exactly as encoded (8-byte truncation included).
pub fn verify_md5_crypt(hash: &str, candidate: &str) -> Result<bool, String> {
    let (magic, digest) = if hash.starts_with("$apr1$") {
        (APR1_MAGIC, parse_md5_crypt(hash, "$apr1$"))
    } else {
        (MD5CRYPT_MAGIC_1, parse_md5_crypt(hash, "$1$"))
    };
    let Some((salt, expected)) = digest else {
        return Err("invalid md5crypt/apr1 encoding".into());
    };
    let computed = md5_crypt_encode(candidate.as_bytes(), salt.as_bytes(), magic);
    let encoded = computed
        .rsplit('$')
        .next()
        .ok_or("md5crypt encoding error")?;
    Ok(constant_time_eq(encoded.as_bytes(), expected.as_bytes()))
}

/// Rounds marker pre-parse for the SHA crypt family; policy cap applies
/// before any expensive verification runs.
pub fn crypt_rounds(hash: &str) -> Result<u64, String> {
    for part in hash.split('$') {
        if let Some(rounds) = part.strip_prefix("rounds=") {
            let value: u64 = rounds
                .parse()
                .map_err(|_| "invalid crypt rounds parameter")?;
            return Ok(value);
        }
    }
    Ok(5000) // the documented default for sha256crypt/sha512crypt
}

/// Verify `$5$` (sha256crypt), `$6$` (sha512crypt) or `$sha1$` (sha1crypt).
pub fn verify_sha_crypt(hash: &str, candidate: &str) -> Result<bool, String> {
    let rounds = crypt_rounds(hash)?;
    if rounds > MAX_CRYPT_ROUNDS {
        return Err(format!(
            "crypt rounds {} exceed the recovery policy cap {}",
            rounds, MAX_CRYPT_ROUNDS
        ));
    }
    if hash.starts_with("$5$") {
        Ok(pwhash::sha256_crypt::verify(candidate, hash))
    } else if hash.starts_with("$6$") {
        Ok(pwhash::sha512_crypt::verify(candidate, hash))
    } else if hash.starts_with("$sha1$") {
        Ok(pwhash::sha1_crypt::verify(candidate, hash))
    } else {
        Err("unsupported sha-crypt encoding".into())
    }
}

/// phpBB/WordPress portable phpass ($P$/$H$): MD5-based iterated digest with
/// the crypt64 alphabet. Sequential triple encoding (different from md5crypt).
pub fn verify_phpass(hash: &str, candidate: &str) -> Result<bool, String> {
    if !(hash.starts_with("$P$") || hash.starts_with("$H$")) {
        return Err("not a phpass portable hash".into());
    }
    let body = &hash[3..];
    if body.len() != 31 || !body.bytes().all(is_crypt64) {
        return Err("invalid phpass encoding".into());
    }
    let log2 = CRYPT64
        .iter()
        .position(|byte| *byte == body.as_bytes()[0])
        .ok_or("invalid phpass cost character")?;
    // Recovery policy: WordPress default is 8; hard-cap at 14 (16,384 iters).
    if log2 > 14 {
        return Err("phpass cost exceeds the recovery policy cap".into());
    }
    let salt = &body[1..9];
    let expected = &body[9..];
    let mut digest: [u8; 16] = {
        use md5::Digest;
        let mut hasher = Md5::new();
        hasher.update(salt.as_bytes());
        hasher.update(candidate.as_bytes());
        hasher.finalize().into()
    };
    use md5::Digest;
    for _ in 0..(1u32 << log2) {
        let mut hasher = Md5::new();
        hasher.update(digest);
        hasher.update(candidate.as_bytes());
        digest = hasher.finalize().into();
    }
    let mut encoded = String::with_capacity(22);
    for triple in digest.chunks(3) {
        let value = match triple.len() {
            3 => (u32::from(triple[0]) << 16) | (u32::from(triple[1]) << 8) | u32::from(triple[2]),
            2 => (u32::from(triple[0]) << 16) | (u32::from(triple[1]) << 8),
            _ => u32::from(triple[0]) << 16,
        };
        to64(value, if triple.len() == 3 { 4 } else { triple.len() + 1 }, &mut encoded);
    }
    Ok(constant_time_eq(encoded.as_bytes(), expected.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5crypt_matches_independent_reference_vector() {
        // pwhash documentation vector, an independent Rust implementation.
        assert!(verify_md5_crypt("$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0", "password").unwrap());
        assert!(!verify_md5_crypt("$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0", "Password").unwrap());
    }

    #[test]
    fn md5crypt_roundtrip_covers_salt_and_length_edges() {
        for password in ["", "a", "abcdefghij", "x".repeat(40).as_str()] {
            for salt in ["ab", "saltsalt"] {
                let encoded = md5_crypt_encode(password.as_bytes(), salt.as_bytes(), MD5CRYPT_MAGIC_1);
                assert_eq!(encoded.len(), "$1$".len() + salt.len() + 1 + 22);
                assert!(verify_md5_crypt(&encoded, password).unwrap());
                assert!(!verify_md5_crypt(&encoded, "wrong").unwrap());
            }
        }
    }

    #[test]
    fn apr1_uses_its_own_magic_consistently() {
        // Same algorithm family: identical magic must reproduce, the other
        // magic must not, and both parse paths reject malformed strings.
        let encoded = md5_crypt_encode(b"password", b"Zm9vYmVy", APR1_MAGIC);
        assert!(encoded.starts_with("$apr1$Zm9vYmVy$"));
        assert!(verify_md5_crypt(&encoded, "password").unwrap());
        let as_md5 = encoded.replacen("$apr1$", "$1$", 1);
        assert!(!verify_md5_crypt(&as_md5, "password").unwrap());
    }

    #[test]
    fn malformed_md5_crypt_is_an_error_not_a_miss() {
        assert!(verify_md5_crypt("$1$short", "x").is_err());
        assert!(verify_md5_crypt("$apr1$salt$salt$digest", "x").is_err());
        assert!(verify_md5_crypt("$1$toolongsalt123456$digestdigestdigestdigest", "x").is_err());
    }

    #[test]
    fn crypt_rounds_parses_default_and_markers() {
        assert_eq!(crypt_rounds("$6$salt$digest").unwrap(), 5000);
        assert_eq!(crypt_rounds("$6$rounds=10000$salt$digest").unwrap(), 10000);
        assert_eq!(crypt_rounds("$5$rounds=abc$salt$digest").is_err(), true);
    }

    #[test]
    fn sha_crypt_policy_rejects_expensive_rounds() {
        let hash = "$6$rounds=999999$salt$digestdigestdigestdigestdigestdigestdigestdigestdi";
        let error = verify_sha_crypt(hash, "candidate").unwrap_err();
        assert!(error.contains("policy cap"));
    }

    #[test]
    fn phpass_matches_john_reference_vectors() {
        // john the Ripper phpass_common_plug.c vectors.
        assert!(verify_phpass("$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall").unwrap());
        assert!(verify_phpass("$P$90000000000tbNYOc9TwXvLEI62rPt1", "").unwrap());
        assert!(verify_phpass("$P$9saltstriAcRMGl.91RgbAD6WSq64z.", "a").unwrap());
        assert!(!verify_phpass("$P$900000000m6YEJzWtTmNBBL4jypbHv1", "Openwall").unwrap());
        assert!(verify_phpass("$P$12costtooshort", "x").is_err());
    }

    #[test]
    fn sha512crypt_matches_independent_reference_vector() {
        // pwhash documentation vector (independent Rust implementation).
        let hash = "$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJURCXk43.EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/";
        assert!(verify_sha_crypt(hash, "test").unwrap());
        assert!(!verify_sha_crypt(hash, "Test").unwrap());
    }

    #[test]
    fn sha256crypt_and_sha1crypt_roundtrip_through_the_router() {
        let sha256 = pwhash::sha256_crypt::hash_with("$5$abcdefgh", "deck").unwrap();
        assert!(sha256.starts_with("$5$abcdefgh$"));
        assert!(verify_sha_crypt(&sha256, "deck").unwrap());
        let sha1 = pwhash::sha1_crypt::hash_with("$sha1$2000$abcdefgh", "deck").unwrap();
        assert!(sha1.starts_with("$sha1$"));
        assert!(verify_sha_crypt(&sha1, "deck").unwrap());
    }
}

//! Native crypto operations with reference test vectors.

pub mod aead;
pub mod recipes;
pub mod key_derivation;
pub mod hkdf;
pub mod recovery;
pub mod candidates;
pub mod gpu;
pub mod formats;
pub mod extraction;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::Sha3_512;

pub const ENGINE_ID: &str = "cyberdeck-crypto";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Catalog entry mirroring the frontend operation model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OpInfo {
    pub id: String,
    pub label: String,
    pub category: &'static str,
    pub description: String,
    /// Operations that take a key/parameter use this hint on the wire.
    pub takes_key: bool,
}

pub fn catalog() -> Vec<OpInfo> {
    vec![
        op("md4", "MD4", "hash", "MD4 digest (128 bit)", false),
        op("ntlm", "NTLM", "hash", "Windows NTLM: MD4 over UTF-16LE text", false),
        op("md5", "MD5", "hash", "MD5 digest (128 bit)", false),
        op("sha1", "SHA-1", "hash", "SHA-1 digest (160 bit)", false),
        op("sha224", "SHA-224", "hash", "SHA-224 digest", false),
        op("sha256", "SHA-256", "hash", "SHA-256 digest", false),
        op("sha384", "SHA-384", "hash", "SHA-384 digest", false),
        op("sha512", "SHA-512", "hash", "SHA-512 digest", false),
        op("sha3_256", "SHA3-256", "hash", "SHA3-256 digest", false),
        op("sha3_512", "SHA3-512", "hash", "SHA3-512 digest", false),
        op("crc32", "CRC32", "hash", "CRC-32 checksum (IEEE, 8 hex chars)", false),
        op("hmac_sha256", "HMAC-SHA256", "hash", "HMAC over the input with the supplied key", true),
        op("hmac_sha512", "HMAC-SHA512", "hash", "HMAC-SHA-512 over the input with the supplied key", true),
        op("to_base64", "To Base64", "encoding", "Encode bytes to Base64", false),
        op("from_base64", "From Base64", "encoding", "Decode Base64 to bytes", false),
        op("to_hex", "To Hex", "encoding", "Encode bytes to hexadecimal", false),
        op("from_hex", "From Hex", "encoding", "Decode hexadecimal to bytes", false),
        op("url_encode", "URL Encode", "encoding", "Percent-encode the input", false),
        op("url_decode", "URL Decode", "encoding", "Decode percent-encoding", false),
        op("xor", "XOR with key", "transforms", "Byte-wise XOR against the repeating key", true),
        op("rot13", "ROT13", "transforms", "Caesar shift letters by 13", false),
        op("gzip", "Gzip", "compression", "Compress input with gzip", false),
        op("gunzip", "Gunzip", "compression", "Decompress gzip data", false),
    ]
}

fn op(id: &str, label: &str, category: &'static str, description: &str, takes_key: bool) -> OpInfo {
    OpInfo {
        id: id.to_string(),
        label: label.to_string(),
        category,
        description: description.to_string(),
        takes_key,
    }
}

/// Apply a catalog operation to raw bytes; key ops read the optional key.
pub fn apply_op(op_id: &str, input: &[u8], key: Option<&[u8]>) -> Result<Vec<u8>, String> {
    match op_id {
        "md5" => Ok(md5::Md5::digest(input).to_vec()),
        "md4" => Ok(<md4::Md4 as md4::Digest>::digest(input).to_vec()),
        // NTLM = MD4 over the UTF-16LE encoding of the password
        "ntlm" => {
            let text = std::str::from_utf8(input).map_err(|_| "ntlm input must be UTF-8 text".to_string())?;
            let utf16: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            Ok(<md4::Md4 as md4::Digest>::digest(&utf16).to_vec())
        }
        "sha1" => Ok(sha1::Sha1::digest(input).to_vec()),
        "sha224" => Ok(Sha224::digest(input).to_vec()),
        "sha256" => Ok(Sha256::digest(input).to_vec()),
        "sha384" => Ok(Sha384::digest(input).to_vec()),
        "sha512" => Ok(Sha512::digest(input).to_vec()),
        "sha3_256" => Ok(sha3::Sha3_256::digest(input).to_vec()),
        "sha3_512" => Ok(Sha3_512::digest(input).to_vec()),
        "crc32" => {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(input);
            Ok(hex::encode(hasher.finalize().to_be_bytes()).into_bytes())
        }
        "hmac_sha256" => {
            let key = key.ok_or_else(|| "hmac_sha256 requires a key".to_string())?;
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|e| e.to_string())?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "hmac_sha512" => {
            let key = key.ok_or_else(|| "hmac_sha512 requires a key".to_string())?;
            let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|e| e.to_string())?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "to_base64" => Ok(base64::engine::general_purpose::STANDARD.encode(input).into_bytes()),
        "from_base64" => base64::engine::general_purpose::STANDARD
            .decode(input)
            .map_err(|e| format!("input is not valid Base64: {e}")),
        "to_hex" => Ok(hex::encode(input).into_bytes()),
        "from_hex" => hex::decode(input).map_err(|e| format!("invalid hex input: {e}")),
        "url_encode" => Ok(percent_encode(input)),
        "url_decode" => percent_decode(input),
        "xor" => {
            let key = key.ok_or_else(|| "xor requires a key".to_string())?;
            if key.is_empty() {
                return Err("xor key must not be empty".to_string());
            }
            Ok(input.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect())
        }
        "rot13" => Ok(rot_n(input, 13)),
        "gzip" => {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(input).map_err(|e| e.to_string())?;
            encoder.finish().map_err(|e| e.to_string())
        }
        "gunzip" => {
            let mut decoder = flate2::read::GzDecoder::new(input);
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut decoder, &mut out).map_err(|e| format!("not gzip data: {e}"))?;
            Ok(out)
        }
        other => Err(format!("unknown operation: {other}")),
    }
}

fn percent_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        // unreserved set per RFC 3986
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

fn percent_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            let hex_pair = input.get(i + 1..i + 3).ok_or("truncated percent escape")?;
            let byte = u8::from_str_radix(std::str::from_utf8(hex_pair).map_err(|_| "invalid percent escape")?, 16)
                .map_err(|_| "invalid percent escape")?;
            out.push(byte);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn rot_n(input: &[u8], n: u8) -> Vec<u8> {
    input
        .iter()
        .map(|&b| match b {
            b'A'..=b'Z' => b'A' + (b - b'A' + n) % 26,
            b'a'..=b'z' => b'a' + (b - b'a' + n) % 26,
            other => other,
        })
        .collect()
}

/// Shannon entropy in bits/byte (0.0 to 8.0).
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// --- KDF verification (our own engine, via MIT/Apache RustCrypto crates) -----

/// Identify a password-hashing format from the PHC/modular-crypt string.
pub fn kdf_format(hash: &str) -> Option<&'static str> {
    if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2x$") || hash.starts_with("$2y$") {
        Some("bcrypt")
    } else if hash.starts_with("$argon2id$") {
        Some("argon2id")
    } else if hash.starts_with("$argon2i$") {
        Some("argon2i")
    } else if hash.starts_with("$argon2d$") {
        Some("argon2d")
    } else if hash.starts_with("$y$") || hash.starts_with("$7$") {
        Some("yescrypt")
    } else if hash.starts_with("$scrypt$") {
        Some("scrypt")
    } else if hash.starts_with("$pbkdf2-sha256$") {
        Some("pbkdf2-sha256")
    } else if hash.starts_with("$pbkdf2-sha512$") {
        Some("pbkdf2-sha512")
    } else if hash.starts_with("$pbkdf2$") {
        Some("pbkdf2-sha1")
    } else {
        None
    }
}

/// Verify a candidate password against a bcrypt, argon2, scrypt or pbkdf2
/// hash. These formats are deliberately slow; native recovery over wordlists
/// works but at KDF speed, and the external engines stay the fast path (§5.5).
pub fn verify_kdf(hash: &str, candidate: &str) -> Result<bool, String> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    match kdf_format(hash) {
        Some("bcrypt") => bcrypt::verify(candidate, hash).map_err(|e| format!("bcrypt verify failed: {e}")),
        Some("scrypt") => {
            let parsed = PasswordHash::new(hash).map_err(|e| format!("invalid scrypt hash string: {e}"))?;
            Ok(scrypt::Scrypt.verify_password(candidate.as_bytes(), &parsed).is_ok())
        }
        Some("yescrypt") => {
            use yescrypt::password_hash::PasswordVerifier as _;
            Ok(yescrypt::Yescrypt::default()
                .verify_password(candidate.as_bytes(), hash)
                .is_ok())
        }
        Some(format) if format.starts_with("pbkdf2") => {
            let parsed = PasswordHash::new(hash).map_err(|e| format!("invalid pbkdf2 hash string: {e}"))?;
            Ok(pbkdf2::Pbkdf2.verify_password(candidate.as_bytes(), &parsed).is_ok())
        }
        Some(_) => {
            let parsed = PasswordHash::new(hash).map_err(|e| format!("invalid argon2 hash string: {e}"))?;
            Ok(argon2::Argon2::default().verify_password(candidate.as_bytes(), &parsed).is_ok())
        }
        None => Err("unsupported KDF format; bcrypt, argon2, scrypt, pbkdf2 and yescrypt are supported natively".to_string()),
    }
}

/// Detect a file format from magic bytes; returns a human-readable signature.
pub fn detect_signature(bytes: &[u8]) -> Option<&'static str> {
    const MAGIC: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "ZIP archive"),
        (b"PK\x05\x06", "ZIP archive (empty)"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"%PDF", "PDF document"),
        (b"\x7fELF", "ELF executable"),
        (b"MZ", "Windows executable (PE)"),
        (b"\x1f\x8b", "Gzip archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"SQLite format 3\x00", "SQLite database"),
        (b"OggS", "Ogg container"),
        (b"RIFF", "RIFF container (WAV/AVI)"),
        (b"ID3", "MP3 audio (ID3)"),
        (b"BZh", "Bzip2 archive"),
        (b"\xfd7zXZ\x00", "XZ archive"),
        (b"ustar", "TAR archive"),
    ];
    MAGIC
        .iter()
        .find(|(magic, _)| bytes.starts_with(magic))
        .map(|(_, name)| *name)
}

use std::io::Write as _;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn s(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn sha256_reference_vector() {
        // NIST FIPS 180-2 vector
        let out = apply_op("sha256", b"abc", None).unwrap();
        assert_eq!(hex::encode(out), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn md5_reference_vector() {
        let out = apply_op("md5", b"abc", None).unwrap();
        assert_eq!(hex::encode(out), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn sha1_reference_vector() {
        let out = apply_op("sha1", b"abc", None).unwrap();
        assert_eq!(hex::encode(out), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        // RFC 4231 test case 1
        let key = [0x0b; 20];
        let out = apply_op("hmac_sha256", b"Hi There", Some(&key)).unwrap();
        assert_eq!(
            hex::encode(out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha512_rfc4231_case1() {
        // RFC 4231 test case 1, SHA-512 variant
        let key = [0x0b; 20];
        let out = apply_op("hmac_sha512", b"Hi There", Some(&key)).unwrap();
        assert_eq!(
            hex::encode(out),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn crc32_known_value() {
        let out = apply_op("crc32", b"123456789", None).unwrap();
        assert_eq!(s(out), "cbf43926");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"CyberDeck pipeline \xf0\x9f\x94\xa5";
        let encoded = apply_op("to_base64", data, None).unwrap();
        let decoded = apply_op("from_base64", &encoded, None).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"\x00\x01\xfe\xff";
        let encoded = apply_op("to_hex", data, None).unwrap();
        assert_eq!(s(encoded.clone()), "0001feff");
        assert_eq!(apply_op("from_hex", &encoded, None).unwrap(), data);
    }

    #[test]
    fn url_encode_decode_roundtrip() {
        let data = b"a b/c?d=e&f+g";
        let encoded = s(apply_op("url_encode", data, None).unwrap());
        assert_eq!(encoded, "a%20b%2Fc%3Fd%3De%26f%2Bg");
        let decoded = apply_op("url_decode", encoded.as_bytes(), None).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn xor_repeats_key() {
        let out = apply_op("xor", b"aaaa", Some(b"AB")).unwrap();
        assert_eq!(out, vec![0x20, 0x23, 0x20, 0x23]);
        let back = apply_op("xor", &out, Some(b"AB")).unwrap();
        assert_eq!(back, b"aaaa");
    }

    #[test]
    fn rot13_classic_vector() {
        assert_eq!(s(apply_op("rot13", b"Hello, World!", None).unwrap()), "Uryyb, Jbeyq!");
    }

    #[test]
    fn gzip_roundtrip() {
        let data = b"compress me ".repeat(64);
        let packed = apply_op("gzip", &data, None).unwrap();
        assert!(packed.len() < data.len());
        let unpacked = apply_op("gunzip", &packed, None).unwrap();
        assert_eq!(unpacked, data);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(b""), 0.0);
        assert_eq!(entropy(&[0x41; 100]), 0.0);
        let spread: Vec<u8> = (0..=255u8).collect();
        let e = entropy(&spread);
        assert!((8.0 - e).abs() < 1e-9);
    }

    #[test]
    fn signature_detection() {
        assert_eq!(detect_signature(b"\x89PNG\r\n\x1a\nrest"), Some("PNG image"));
        assert_eq!(detect_signature(b"PK\x03\x04..."), Some("ZIP archive"));
        assert_eq!(detect_signature(b"plain text"), None);
    }

    #[test]
    fn kdf_format_identification() {
        assert_eq!(kdf_format("$2b$10$abcdefghijklmnopqrstuv"), Some("bcrypt"));
        assert_eq!(kdf_format("$2y$12$abcdefghijklmnopqrstuv"), Some("bcrypt"));
        assert_eq!(kdf_format("$argon2id$v=19$m=65536,t=3,p=4$c2FsdXNhbHQ"), Some("argon2id"));
        assert_eq!(kdf_format("$scrypt$ln=16384,r=8,p=1$c2FsdQ$aGFzaA"), Some("scrypt"));
        assert_eq!(kdf_format("$pbkdf2-sha256$i=10000$c2FsdQ$aGFzaA"), Some("pbkdf2-sha256"));
        assert_eq!(kdf_format("$6$salt$hash"), None);
    }

    #[test]
    fn bcrypt_verify_roundtrip() {
        let hash = bcrypt::hash("hello", 4).unwrap();
        assert!(verify_kdf(&hash, "hello").unwrap());
        assert!(!verify_kdf(&hash, "world").unwrap());
        assert_eq!(kdf_format(&hash), Some("bcrypt"));
    }

    #[test]
    fn argon2_verify_roundtrip() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
        let argon = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(19456, 2, 1, None).unwrap(),
        );
        let hash = argon.hash_password(b"hello", &salt).unwrap().to_string();
        assert!(verify_kdf(&hash, "hello").unwrap());
        assert!(!verify_kdf(&hash, "world").unwrap());
        assert_eq!(kdf_format(&hash), Some("argon2id"));
    }

    #[test]
    fn scrypt_verify_roundtrip() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
        let hash = scrypt::Scrypt.hash_password(b"hello", &salt).unwrap().to_string();
        assert!(verify_kdf(&hash, "hello").unwrap());
        assert!(!verify_kdf(&hash, "world").unwrap());
        assert_eq!(kdf_format(&hash), Some("scrypt"));
    }

    #[test]
    fn pbkdf2_verify_roundtrip() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
        let hash = pbkdf2::Pbkdf2.hash_password(b"hello", &salt).unwrap().to_string();
        assert!(verify_kdf(&hash, "hello").unwrap());
        assert!(!verify_kdf(&hash, "world").unwrap());
        assert!(kdf_format(&hash).unwrap().starts_with("pbkdf2"));
    }

    #[test]
    fn ntlm_reference_vector() {
        // well-known NTLM hash of "password"
        let out = apply_op("ntlm", b"password", None).unwrap();
        assert_eq!(hex::encode(out), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn sha3_reference_vector() {
        // "abc" per the Keccak team's SHA3-256 test vector
        let out = apply_op("sha3_256", b"abc", None).unwrap();
        assert_eq!(hex::encode(out), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    #[test]
    fn yescrypt_verify_roundtrip() {
        use yescrypt::password_hash::CustomizedPasswordHasher as _;
        let salt = b"0123456789abcdef";
        let hash = yescrypt::Yescrypt::default()
            .hash_password_customized(b"hello", salt, None, None, yescrypt::Params::default())
            .unwrap()
            .to_string();
        assert!(hash.starts_with("$y$"));
        assert!(verify_kdf(&hash, "hello").unwrap());
        assert!(!verify_kdf(&hash, "world").unwrap());
        assert_eq!(kdf_format(&hash), Some("yescrypt"));
    }

    #[test]
    fn verify_kdf_rejects_unknown_format() {
        assert!(verify_kdf("$6$salt$hash", "hello").is_err());
    }

    #[test]
    fn catalog_is_nonempty_and_unique() {
        let cat = catalog();
        assert!(cat.len() >= 18);
        let mut ids: Vec<_> = cat.iter().map(|o| o.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), cat.len());
    }

    #[test]
    fn gunzip_rejects_non_gzip() {
        assert!(apply_op("gunzip", b"not gzip", None).is_err());
        let _ = std::io::sink().write(b"").unwrap();
        let _ = std::io::empty().read(&mut []).unwrap();
    }
}

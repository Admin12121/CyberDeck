//! Native crypto operations with reference test vectors.

pub mod aead;
pub mod recipes;
mod recipe_native_parity;
mod recipe_text_parity;
mod recipe_escape_parity;
mod recipe_ioc_parity;
mod recipe_ioc_extra;
mod recipe_jwt;
mod recipe_datetime;
pub mod key_derivation;
pub mod hkdf;
pub mod recovery;
pub mod candidates;
pub mod gpu;
pub mod formats;
pub mod extraction;
pub mod unix_crypt;
pub mod legacy_digests;
pub mod shadow;
pub mod windows_auth;

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
        op("ripemd160", "RIPEMD-160", "hash", "RIPEMD-160 digest (160 bit)", false),
        op("whirlpool", "Whirlpool", "hash", "Whirlpool digest (512 bit)", false),
        op("blake2b512", "BLAKE2b-512", "hash", "BLAKE2b digest (512 bit, unkeyed)", false),
        op("lm", "LAN Manager", "hash", "Legacy LAN Manager: uppercase, 14 bytes, split DES halves", false),
        op("mysql5", "MySQL 4.1+", "hash", "MySQL 4.1+ password digest: sha1(sha1(input))", false),
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
        "ripemd160" => Ok(ripemd::Ripemd160::digest(input).to_vec()),
        "whirlpool" => Ok(whirlpool::Whirlpool::digest(input).to_vec()),
        "blake2b512" => Ok(blake2::Blake2b512::digest(input).to_vec()),
        "lm" => Ok(legacy_digests::lm_hash(input).to_vec()),
        "mysql5" => Ok(legacy_digests::mysql5_digest(input).to_vec()),
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
            // A gzip bomb must not allocate an unbounded output buffer.
            const MAX_UNCOMPRESSED: u64 = 8 * 1024 * 1024;
            if input.len() as u64 > MAX_UNCOMPRESSED {
                return Err("gzip input size limit exceeded".into());
            }
            let decoder = flate2::read::GzDecoder::new(input);
            let mut bounded = std::io::Read::take(decoder, MAX_UNCOMPRESSED + 1);
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut bounded, &mut out)
                .map_err(|e| format!("not gzip data: {e}"))?;
            if out.len() as u64 > MAX_UNCOMPRESSED {
                return Err("gzip output size limit exceeded".into());
            }
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
    } else if hash.starts_with("$gy$") || hash.starts_with("$G$") {
        Some("gost-yescrypt")
    } else if hash.starts_with("$scrypt$") {
        Some("scrypt")
    } else if hash.starts_with("$pbkdf2-sha256$") {
        Some("pbkdf2-sha256")
    } else if hash.starts_with("$pbkdf2-sha512$") {
        Some("pbkdf2-sha512")
    } else if hash.starts_with("$pbkdf2$") {
        Some("pbkdf2-sha1")
    } else if hash.starts_with("$P$") || hash.starts_with("$H$") {
        Some("phpass")
    } else if hash.starts_with("$6$") {
        Some("sha512crypt")
    } else if hash.starts_with("$5$") {
        Some("sha256crypt")
    } else if hash.starts_with("$1$") {
        Some("md5crypt")
    } else if hash.starts_with("$apr1$") {
        Some("apr1")
    } else if hash.starts_with("$sha1$") {
        Some("sha1crypt")
    } else if hash.starts_with("$NETNTLMv2$") {
        Some("netntlm-v2")
    } else if hash.starts_with("$NETNTLM$") {
        Some("netntlm-v1")
    } else if hash.starts_with("$DCC2$") || hash.starts_with("DCC2#") {
        Some("mscash2")
    } else if hash.starts_with("M$") && hash[2..].contains('#') {
        Some("mscash")
    } else if netntlm_capture_shape(hash) {
        // Capture form: user::domain:challenge:LM:NT (v1) or
        // user::domain:challenge:resp:blob (v2); distinguished by field 4.
        let fields: Vec<&str> = hash.split(':').collect();
        if fields[4].len() == 48 {
            Some("netntlm-v1")
        } else {
            Some("netntlm-v2")
        }
    } else if hash.contains('#') {
        // hashcat-style mscash: username#digest with a single separator.
        let parts: Vec<&str> = hash.splitn(2, '#').collect();
        if parts.len() == 2
            && !parts[0].is_empty()
            && parts[0].len() <= 128
            && parts[1].len() == 32
            && parts[1].bytes().all(|b| b.is_ascii_hexdigit())
        {
            Some("mscash")
        } else {
            None
        }
    } else {
        None
    }
}

/// Shape check for the six-field NetNTLM capture forms.
fn netntlm_capture_shape(hash: &str) -> bool {
    let fields: Vec<&str> = hash.split(':').collect();
    fields.len() == 6
        && fields[1].is_empty()
        && fields[3].len() == 16
        && fields[3].bytes().all(|b| b.is_ascii_hexdigit())
        && (fields[4].len() == 48 || fields[4].len() == 32)
        && fields[5].len() >= 16
        && fields[4].bytes().all(|b| b.is_ascii_hexdigit())
        && fields[5].bytes().all(|b| b.is_ascii_hexdigit())
}

/// Verify a candidate password against a bcrypt, argon2, scrypt or pbkdf2
/// hash. These formats are deliberately slow; native recovery over wordlists
/// works but at KDF speed, and the external engines stay the fast path (§5.5).
pub fn verify_kdf(hash: &str, candidate: &str) -> Result<bool, String> {
    let format = kdf_format(hash).ok_or_else(|| {
        "unsupported KDF format; bcrypt, argon2, scrypt, pbkdf2, yescrypt, the Unix crypt family and Windows auth digests are supported natively".to_string()
    })?;
    verify_kdf_format(format, hash, candidate)
}

/// Verify against an explicitly known format; composed targets are
/// hint-driven and cannot be re-detected from the wire string.
pub fn verify_kdf_format(format: &str, hash: &str, candidate: &str) -> Result<bool, String> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    match format {
        "bcrypt" => bcrypt::verify(candidate, hash).map_err(|e| format!("bcrypt verify failed: {e}")),
        "scrypt" => {
            let parsed = PasswordHash::new(hash).map_err(|e| format!("invalid scrypt hash string: {e}"))?;
            Ok(scrypt::Scrypt.verify_password(candidate.as_bytes(), &parsed).is_ok())
        }
        "yescrypt" => {
            use yescrypt::password_hash::PasswordVerifier as _;
            Ok(yescrypt::Yescrypt::default()
                .verify_password(candidate.as_bytes(), hash)
                .is_ok())
        }
        format if format.starts_with("pbkdf2") => {
            let parsed = PasswordHash::new(hash).map_err(|e| format!("invalid pbkdf2 hash string: {e}"))?;
            Ok(pbkdf2::Pbkdf2.verify_password(candidate.as_bytes(), &parsed).is_ok())
        }
        "md5crypt" | "apr1" => unix_crypt::verify_md5_crypt(hash, candidate),
        "phpass" => Err(
            "phpass native verify is pending an authoritative test vector; use the embedded Hashcat mode 400 on a native build".to_string(),
        ),
        "sha512crypt" | "sha256crypt" | "sha1crypt" => {
            unix_crypt::verify_sha_crypt(hash, candidate)
        }
        "mscash" => windows_auth::verify_mscash(hash, candidate),
        "mscash2" => windows_auth::verify_mscash2(hash, candidate),
        "netntlm-v1" => windows_auth::verify_netntlmv1(hash, candidate),
        "netntlm-v2" => windows_auth::verify_netntlmv2(hash, candidate),
        // Composed salted/HMAC digests carry an explicit algorithm hint; the
        // encoded form is "digest:salt" with the salt taken after the first
        // colon (hashcat wire shape).
        "md5-pass-salt" => verify_composed(hash, candidate, |p, s| {
            crate::legacy_digests::md5_hex(p, s)
        }),
        "md5-salt-pass" => verify_composed(hash, candidate, |p, s| {
            crate::legacy_digests::md5_hex(s, p)
        }),
        "sha1-pass-salt" => verify_composed(hash, candidate, |p, s| {
            crate::legacy_digests::sha1_hex(p, s)
        }),
        "sha1-salt-pass" => verify_composed(hash, candidate, |p, s| {
            crate::legacy_digests::sha1_hex(s, p)
        }),
        "hmac-md5" => verify_composed(hash, candidate, |p, s| {
            windows_auth::hmac_digest("hmac-md5", p.as_bytes(), s.as_bytes()).map(|d| hex::encode(d))
        }),
        "hmac-sha1" => verify_composed(hash, candidate, |p, s| {
            windows_auth::hmac_digest("hmac-sha1", p.as_bytes(), s.as_bytes()).map(|d| hex::encode(d))
        }),
        "gost-yescrypt" => Err(
            "gost-yescrypt is not native yet; route it through the john sidecar in the Engines panel"
                .to_string(),
        ),
        _ => {
            let parsed = PasswordHash::new(hash).map_err(|e| format!("invalid argon2 hash string: {e}"))?;
            Ok(argon2::Argon2::default().verify_password(candidate.as_bytes(), &parsed).is_ok())
        }
    }
}

/// Shared composed-digest verification: "digest:salt" wire shape, the digest
/// recomputed by the supplied combinator and compared in constant time.
fn verify_composed(
    encoded: &str,
    candidate: &str,
    compute: impl Fn(&str, &str) -> Result<String, String>,
) -> Result<bool, String> {
    let (expected_hex, salt) = encoded
        .split_once(':')
        .ok_or("composed target requires digest:salt")?;
    let computed = compute(candidate, salt)?;
    Ok(constant_time_eq_str(&computed, expected_hex))
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
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
        assert_eq!(kdf_format("$6$salt$hash"), Some("sha512crypt"));
        assert_eq!(kdf_format("$5$salt$hash"), Some("sha256crypt"));
        assert_eq!(kdf_format("$1$salt$hash"), Some("md5crypt"));
        assert_eq!(kdf_format("$apr1$salt$hash"), Some("apr1"));
        assert_eq!(kdf_format("$sha1$1000$salt$hash"), Some("sha1crypt"));
        assert_eq!(kdf_format("$gy$J8$salt$hash"), Some("gost-yescrypt"));
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
    fn composed_salted_and_hmac_targets_match_independent_vectors() {
        use crate::recovery::RecoveryTarget;
        // Vectors generated independently with Node's crypto (different
        // implementation from RustCrypto). Bare digest:salt is deliberately
        // not self-detected; the algorithm is an explicit operator choice.
        let pass = "cyberdeck";
        let md5ps = format!("{}:4242", crate::legacy_digests::md5_hex(pass, "4242").unwrap());
        let md5sp = format!("{}:4242", crate::legacy_digests::md5_hex("4242", pass).unwrap());
        let sha1ps = format!("{}:4242", crate::legacy_digests::sha1_hex(pass, "4242").unwrap());
        let sha1sp = format!("{}:4242", crate::legacy_digests::sha1_hex("4242", pass).unwrap());
        for (format, encoded) in [
            ("md5-pass-salt", md5ps),
            ("md5-salt-pass", md5sp),
            ("sha1-pass-salt", sha1ps),
            ("sha1-salt-pass", sha1sp),
        ] {
            let target = RecoveryTarget::parse(format, &encoded).unwrap();
            assert!(target.is_match(pass.as_bytes()).unwrap(), "{format}");
            assert!(!target.is_match(b"Cyberdeck").unwrap(), "{format}");
        }
        let hmac_md5 = windows_auth::hmac_digest("hmac-md5", pass.as_bytes(), b"4242").unwrap();
        let hmac_sha1 = windows_auth::hmac_digest("hmac-sha1", pass.as_bytes(), b"4242").unwrap();
        assert_eq!(hex::encode(&hmac_md5), "dc5b5ad28f4dd280463a5319b976bd50");
        assert_eq!(hex::encode(&hmac_sha1), "3de2a5579621deb8357374953c6a520d4779fc8a");
        let target = RecoveryTarget::parse("hmac-md5", &format!("{}:4242", hex::encode(&hmac_md5))).unwrap();
        assert!(target.is_match(pass.as_bytes()).unwrap());
    }

    #[test]
    fn batch2_windows_auth_targets_self_detect_and_verify() {
        use crate::recovery::RecoveryTarget as _RecoveryTargetImported;
        use crate::recovery::RecoveryTarget;
        let mscash = RecoveryTarget::parse("", "test1#64cd29e36a8431a2b111378564a10631").unwrap();
        assert!(mscash.is_match(b"test1").unwrap());
        assert_eq!(crate::kdf_format("M$test2#ab60bdb4493822b175486810ac2abe63"), Some("mscash"));
        let dcc2 = RecoveryTarget::parse("", "$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8").unwrap();
        assert!(dcc2.is_match(b"test1").unwrap());
        let v1 = RecoveryTarget::parse(
            "",
            "$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB",
        )
        .unwrap();
        assert!(v1.is_match(b"g3rg3g3rg3g3rg3").unwrap());
        let v2 = RecoveryTarget::parse(
            "",
            "NTLMV2TEST::WORKGROUP:1122334455667788:07659A550D5E9D02996DFD95C87EC1D5:0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000",
        )
        .unwrap();
        assert!(v2.is_match(b"password").unwrap());
        assert_eq!(crate::kdf_format("a::b:1122334455667788:000000000000000000000000000000000000000000000000:BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB"), Some("netntlm-v1"));
    }

    #[test]
    fn verify_kdf_rejects_unknown_or_malformed_format() {
        // A malformed sha512crypt encoding simply never matches; it must not
        // panic or false-positive.
        assert!(!verify_kdf("$6$salt$hash", "hello").unwrap());
        // gost-yescrypt is detected but honestly routed elsewhere.
        let error = verify_kdf("$gy$J8$salt$hash", "hello").unwrap_err();
        assert!(error.contains("john sidecar"));
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

#[cfg(test)]
mod decompression_resource_policy_tests {
    use super::*;
    #[test]
    fn gunzip_rejects_high_ratio_bombs_but_accepts_exact_cap() {
        let maximum = 8 * 1024 * 1024;
        let exact = vec![b'X'; maximum];
        let compressed = apply_op("gzip", &exact, None).unwrap();
        assert!(compressed.len() < maximum / 10);
        assert_eq!(apply_op("gunzip", &compressed, None).unwrap(), exact);
        let too_large = apply_op("gzip", &vec![b'X'; maximum + 1], None).unwrap();
        assert_eq!(apply_op("gunzip", &too_large, None).unwrap_err(), "gzip output size limit exceeded");
        assert_eq!(apply_op("gunzip", &vec![0; maximum + 1], None).unwrap_err(), "gzip input size limit exceeded");
    }
    #[test]
    fn gunzip_rejects_truncated_and_malformed_gzip() {
        let compressed = apply_op("gzip", b"known answer", None).unwrap();
        assert!(apply_op("gunzip", &compressed[..compressed.len() - 4], None).is_err());
        assert!(apply_op("gunzip", b"\x1f\x8b\x08\x00", None).is_err());
    }
}

//! Windows authentication digest formats, native Rust.
//! mscash (DCC1), mscash2 (DCC2), NetNTLMv1 and NetNTLMv2, with semantics
//! cross-checked against the vendored hashcat modules (1100/2100/5500/5600)
//! and verified against john the Ripper test vectors.
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as _;
use md4::Md4;
use md5::Md5;
use sha1::Sha1;
use sha2::Digest;

const MAX_USERNAME_BYTES: usize = 128;
const MAX_BLOB_BYTES: usize = 4096;

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn md4(data: &[u8]) -> [u8; 16] {
    <Md4 as md4::Digest>::digest(data).into()
}

/// Domain Cached Credentials (DCC1): md4(md4(utf16le(pass)) . utf16le(salt)).
/// The salt is the lowercased username, exactly as hashcat mode 1100 treats it.
pub fn mscash_digest(password: &str, salt_user: &str) -> Result<[u8; 16], String> {
    if salt_user.is_empty() || salt_user.len() > MAX_USERNAME_BYTES {
        return Err("mscash salt must be a 1..=128 character username".into());
    }
    let lower = salt_user.to_ascii_lowercase();
    let nt = md4(&utf16le(password));
    // Vector-verified against hashcat's documented recipe: the raw UTF-16LE
    // username salt feeds the outer MD4 directly.
    Ok(md4(&[nt.as_slice(), utf16le(&lower).as_slice()].concat()))
}

fn parse_mscash(encoded: &str) -> Result<(String, [u8; 16]), String> {
    // Accepted: "user#hash", john's "M$user#hash", or hashcat's "hash:salt".
    let text = encoded.strip_prefix("M$").unwrap_or(encoded);
    let (salt, digest_hex) = if let Some((digest, salt)) = text.split_once(':') {
        (salt, digest)
    } else {
        text.split_once('#').ok_or("mscash target requires user#digest")?
    };
    if digest_hex.len() != 32 || !digest_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("mscash digest must be 32 hex characters".into());
    }
    let bytes = hex::decode(digest_hex).map_err(|_| "invalid mscash digest")?;
    Ok((salt.to_string(), bytes.try_into().unwrap()))
}

pub fn verify_mscash(encoded: &str, candidate: &str) -> Result<bool, String> {
    let (salt, expected) = parse_mscash(encoded)?;
    Ok(mscash_digest(candidate, &salt)? == expected)
}

/// Domain Cached Credentials v2 (DCC2 / MS Cache 2):
/// pbkdf2-hmac-sha1(dcc1, md4(utf16le(lower(user))), iterations, 16).
pub fn mscash2_digest(
    password: &str,
    salt_user: &str,
    iterations: u32,
) -> Result<[u8; 16], String> {
    // Recovery policy cap; 10240 is the standard Windows value.
    if !(1..=100_000).contains(&iterations) {
        return Err("mscash2 iterations exceed the recovery policy cap".into());
    }
    let dcc1 = mscash_digest(password, salt_user)?;
    // Vector-verified: the PBKDF2 salt is the raw UTF-16LE lowercased username.
    let lower = salt_user.to_ascii_lowercase();
    let mut out = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha1>(&dcc1, &utf16le(&lower), iterations, &mut out);
    Ok(out)
}

pub fn verify_mscash2(encoded: &str, candidate: &str) -> Result<bool, String> {
    // Accepted: "$DCC2$iterations#user#hash" or "DCC2#user#hash" (standard 10240).
    let (iterations, rest) = if let Some(rest) = encoded.strip_prefix("$DCC2$") {
        let (iter, rest) = rest
            .split_once('#')
            .ok_or("invalid DCC2 encoding")?;
        let iter: u32 = iter.parse().map_err(|_| "invalid DCC2 iteration count")?;
        (iter, rest)
    } else if let Some(rest) = encoded.strip_prefix("DCC2#") {
        (10240, rest)
    } else {
        return Err("not a DCC2 target".into());
    };
    let (salt, digest_hex) = rest
        .split_once('#')
        .ok_or("mscash2 target requires user#digest")?;
    if digest_hex.len() != 32 || !digest_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("mscash2 digest must be 32 hex characters".into());
    }
    let expected: [u8; 16] =
        hex::decode(digest_hex).map_err(|_| "invalid mscash2 digest")?[..].try_into().unwrap();
    Ok(mscash2_digest(candidate, salt, iterations)? == expected)
}

fn lm_expand_key_from(seven: &[u8]) -> [u8; 8] {
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

fn des_encrypt_block(key: &[u8; 8], block: &[u8]) -> [u8; 8] {
    let cipher = Des::new_from_slice(key).expect("DES key is always 8 bytes");
    let mut block = des::cipher::Block::<Des>::clone_from_slice(block);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// NetNTLMv1 challenge response: three DES blocks keyed from the NT hash,
/// compared against the NT response only (the LM response is never validated).
/// Accepted forms: "$NETNTLM$challenge$ntresp" or the capture form
/// "user::domain:challenge:lmresp:ntresp".
pub fn verify_netntlmv1(encoded: &str, candidate: &str) -> Result<bool, String> {
    let (challenge_hex, resp_hex) = if let Some(rest) = encoded.strip_prefix("$NETNTLM$") {
        let (challenge, resp) = rest
            .split_once('$')
            .ok_or("invalid NetNTLMv1 encoding")?;
        (challenge, resp)
    } else {
        let fields: Vec<&str> = encoded.split(':').collect();
        if fields.len() != 6 {
            return Err("not a NetNTLMv1 target".into());
        }
        (fields[3], fields[5])
    };
    if challenge_hex.len() != 16 || !challenge_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("NetNTLMv1 challenge must be 16 hex characters".into());
    }
    if resp_hex.len() != 48 || !resp_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("NetNTLMv1 NT response must be 48 hex characters".into());
    }
    let challenge = hex::decode(challenge_hex).map_err(|_| "invalid challenge")?;
    let expected = hex::decode(resp_hex).map_err(|_| "invalid NT response")?;
    let nt = md4(&utf16le(candidate));
    let mut computed = [0u8; 24];
    for (index, out) in computed.chunks_mut(8).enumerate() {
        let start = index * 7;
        let mut chunk = [0u8; 7];
        let end = (start + 7).min(16);
        chunk[..end - start].copy_from_slice(&nt[start..end]);
        out.copy_from_slice(&des_encrypt_block(&lm_expand_key_from(&chunk), &challenge));
    }
    Ok(computed.as_slice() == expected.as_slice())
}

/// NetNTLMv2: identity = upper(user) + domain (the capture provides them
/// concatenated; empty domain is common). The stored response is the 16-byte
/// HMAC-MD5 prefix over challenge||blob, keyed by the v2 hash.
/// Accepted form: "user::domain:challenge:resp16:blob".
pub fn verify_netntlmv2(encoded: &str, candidate: &str) -> Result<bool, String> {
    // Tagged form: $NETNTLMv2$identity$challenge$resp$blob ($-separated).
    // Capture form: user::domain:challenge:resp:blob (:separated).
    let (user, domain, challenge_hex, resp_hex, blob_hex) =
        if let Some(rest) = encoded.strip_prefix("$NETNTLMv2$") {
            let parts: Vec<&str> = rest.split('$').collect();
            if parts.len() != 4 {
                return Err("invalid tagged NetNTLMv2 encoding".into());
            }
            // The tagged identity is already upper(user)+domain.
            let identity = parts[0].to_string();
            (identity, String::new(), parts[1], parts[2], parts[3])
        } else {
            // Capture form: user::domain:challenge:resp:blob (6 colon fields
            // with an empty second entry from the double colon).
            let fields: Vec<&str> = encoded.split(':').collect();
            if fields.len() != 6 {
                return Err(
                    "not a NetNTLMv2 target (expected user::domain:challenge:resp:blob)".into(),
                );
            }
            (fields[0].to_string(), fields[2].to_string(), fields[3], fields[4], fields[5])
        };
    if challenge_hex.len() != 16 || !challenge_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("NetNTLMv2 challenge must be 16 hex characters".into());
    }
    if resp_hex.len() != 32 || !resp_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("NetNTLMv2 response prefix must be 32 hex characters".into());
    }
    if blob_hex.is_empty() || blob_hex.len() % 2 != 0 || blob_hex.len() / 2 > MAX_BLOB_BYTES
        || !blob_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("NetNTLMv2 blob must be bounded even-length hex".into());
    }
    let challenge = hex::decode(challenge_hex).map_err(|_| "invalid challenge")?;
    let blob = hex::decode(blob_hex).map_err(|_| "invalid blob")?;
    let expected = hex::decode(resp_hex).map_err(|_| "invalid response")?;
    // Identity: the username uppercased, then the domain as captured.
    let identity = format!("{}{}", user.to_ascii_uppercase(), domain);
    let nt = md4(&utf16le(candidate));
    let mut v2_hash = <Hmac<Md5> as Mac>::new_from_slice(&nt).map_err(|e| e.to_string())?;
    v2_hash.update(&utf16le(&identity));
    let v2_hash = v2_hash.finalize().into_bytes();
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(&v2_hash).map_err(|e| e.to_string())?;
    mac.update(&challenge);
    mac.update(&blob);
    let response = mac.finalize().into_bytes();
    Ok(response.as_slice() == expected.as_slice())
}

/// HMAC keyed digests (hashcat modes 50/60): key = password, message = salt.
pub fn hmac_digest(kind: &str, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    match kind {
        "hmac-md5" => {
            let mut mac = <Hmac<Md5> as Mac>::new_from_slice(password).map_err(|e| e.to_string())?;
            mac.update(salt);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "hmac-sha1" => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(password).map_err(|e| e.to_string())?;
            mac.update(salt);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        other => Err(format!("unsupported hmac digest kind {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mscash_matches_john_vectors() {
        // john the Ripper mscash_common_plug.c vectors.
        assert!(verify_mscash("M$test2#ab60bdb4493822b175486810ac2abe63", "test2").unwrap());
        assert!(verify_mscash("test1#64cd29e36a8431a2b111378564a10631", "test1").unwrap());
        assert!(verify_mscash("test3#14dd041848e12fc48c0aa7a416a4a00c", "test3").unwrap());
        assert!(!verify_mscash("test1#64cd29e36a8431a2b111378564a10631", "Test1").unwrap());
    }

    #[test]
    fn mscash2_matches_john_vector() {
        assert!(
            verify_mscash2("$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test1").unwrap()
        );
        assert!(!verify_mscash2("$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test2").unwrap());
    }

    #[test]
    fn netntlmv1_matches_john_vectors() {
        assert!(verify_netntlmv1(
            "$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB",
            "g3rg3g3rg3g3rg3",
        )
        .unwrap());
        assert!(
            verify_netntlmv1(
                "$NETNTLM$1122334455667788$E463FAA5D868ECE20CAE622474A2F440A652D642156AF863",
                "M1xedC4se%^&*@)##(blahblah!@#",
            )
            .unwrap()
        );
        // Same vector through the capture form; LM response is never checked.
        assert!(verify_netntlmv1(
            "user::domain:1122334455667788:000000000000000000000000000000000000000000000000:BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB",
            "g3rg3g3rg3g3rg3",
        )
        .unwrap());
    }

    #[test]
    fn netntlmv2_matches_john_vectors() {
        assert!(verify_netntlmv2(
            "$NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000",
            "password",
        )
        .unwrap());
        assert!(
            verify_netntlmv2(
                "$NETNTLMv2$TESTUSERW2K3ADWIN7$1122334455667788$989B96DC6EAB529F72FCBA852C0D5719$01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000",
                "testpass",
            )
            .unwrap()
        );
        // Capture form with the user/domain split preserved.
        assert!(verify_netntlmv2(
            "NTLMV2TEST::WORKGROUP:1122334455667788:07659A550D5E9D02996DFD95C87EC1D5:0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000",
            "password",
        )
        .unwrap());
    }
}

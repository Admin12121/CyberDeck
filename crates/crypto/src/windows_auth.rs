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

fn md5(data: &[u8]) -> [u8; 16] {
    <Md5 as sha2::Digest>::digest(data).into()
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

/// The 2^16 third-key space hashcat m05500 brute-forces at parse time
/// ("precompute netntlmv1 exploit", module_05500.c:286-327).
const NETNTLMV1_M05500_THIRD_KEY_SPACE: u32 = 0x10000;

/// hashcat m05500 `transform_netntlmv1_key` (module_05500.c:63-82): the seven
/// input bytes as an MSB-first 56-bit stream, split into eight 7-bit groups,
/// each left-aligned in a byte with odd parity set. The parity bits never
/// enter the DES key schedule, so the effective key bits match the crate's
/// LM expansion; the function stays literal to the module for provenance.
fn netntlmv1_m05500_key_expand(seven: &[u8; 7]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = seven[0];
    key[1] = (seven[0] << 7) | (seven[1] >> 1);
    key[2] = (seven[1] << 6) | (seven[2] >> 2);
    key[3] = (seven[2] << 5) | (seven[3] >> 3);
    key[4] = (seven[3] << 4) | (seven[4] >> 4);
    key[5] = (seven[4] << 3) | (seven[5] >> 5);
    key[6] = (seven[5] << 2) | (seven[6] >> 6);
    key[7] = seven[6] << 1;
    for byte in key.iter_mut() {
        *byte |= 0x01;
    }
    key
}

/// Everything hashcat m05500 derives from a "NetNTLMv1 / NetNTLMv1+ESS" hash
/// line before any candidate is tested — module_05500.c:110-343
/// (`module_hash_decode`) — plus the per-candidate kernel checks of the
/// m05500 OpenCL kernels.
struct NetNTLMv1M05500 {
    /// The 8 bytes the kernels DES-encrypt: the client challenge decoded to
    /// binary (OPTS_TYPE_ST_HEX, module_05500.c:31, feeds generic_salt_decode
    /// at parser.c:592-609), or — for ESS — MD5(client[0..8] ||
    /// server[0..8])[0..8] (module_05500.c:259-284).
    challenge: [u8; 8],
    /// The 24-byte NT response split the way the module splits it:
    /// digest[0..3] = ct1||ct2 (hex_to_u32 over hash_pos+0..32, lines
    /// 245-248) and digest_tmp = ct3 (hash_pos+32..48, lines 252-255).
    /// ct3 is consumed by the parse-time brute force (it defines
    /// third_key_index) and re-checked by the KATs; the kernel path pins it
    /// through the NT-hash filter instead of re-encrypting.
    ct1: [u8; 8],
    ct2: [u8; 8],
    #[allow(dead_code)]
    ct3: [u8; 8],
    /// salt_buf[2]: the first i < 0x10000 whose two seed bytes expand to a
    /// DES key encrypting the challenge to ct3 (lines 286-322). No match is
    /// the module's PARSER_SALT_VALUE (line 322) — the line is uncrackable.
    third_key_index: u16,
}

impl NetNTLMv1M05500 {
    /// Parse the three challenge/response fields of the m05500 wire
    /// "user::domain:srvchall:ntresp:clichall" and run the parse-time
    /// precompute. Field shapes mirror the module's token attributes
    /// (module_05500.c:139-156, 205, 223): srvchall 0..=48 hex and even,
    /// ntresp exactly 48 hex, clichall exactly 16 hex.
    fn parse(
        (srvchall_hex, ntresp_hex, clichall_hex): (&str, &str, &str),
    ) -> Result<Self, String> {
        if srvchall_hex.len() > 48
            || srvchall_hex.len() % 2 != 0
            || !srvchall_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid server challenge".into());
        }
        if ntresp_hex.len() != 48 || !ntresp_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("NetNTLMv1 NT response must be 48 hex characters".into());
        }
        if clichall_hex.len() != 16 || !clichall_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid client challenge".into());
        }

        let srvchal = hex::decode(srvchall_hex).map_err(|_| "invalid server challenge")?;
        let clichall = hex::decode(clichall_hex).map_err(|_| "invalid client challenge")?;
        let ntresp = hex::decode(ntresp_hex).map_err(|_| "invalid NT response")?;

        let mut challenge = [0u8; 8];
        challenge.copy_from_slice(&clichall);

        // ESS ("special case 2", module_05500.c:259-284): a 24-byte server
        // challenge whose tail 16 bytes are zero marks an NTLMv1+ESS null
        // session capture; the challenge becomes the first 8 bytes of
        // MD5(client_challenge[0..8] || server_challenge[0..8]).
        if srvchall_hex.len() == 48 && srvchal[8..24].iter().all(|&b| b == 0) {
            let mut md5_input = [0u8; 16];
            md5_input[..8].copy_from_slice(&clichall);
            md5_input[8..].copy_from_slice(&srvchal[..8]);
            let digest = md5(&md5_input);
            challenge.copy_from_slice(&digest[..8]);
        }

        let mut ct1 = [0u8; 8];
        let mut ct2 = [0u8; 8];
        let mut ct3 = [0u8; 8];
        ct1.copy_from_slice(&ntresp[..8]);
        ct2.copy_from_slice(&ntresp[8..16]);
        ct3.copy_from_slice(&ntresp[16..24]);

        // The third DES key derives from NT-hash bytes 14..15, unknown at
        // parse time, so the module walks the whole 16-bit space for the key
        // whose encryption of the challenge matches the captured tail
        // (module_05500.c:286-322) and stores the index in salt_buf[2].
        let mut third_key_index = None;
        for i in 0..NETNTLMV1_M05500_THIRD_KEY_SPACE {
            let seed = [i as u8, (i >> 8) as u8, 0, 0, 0, 0, 0];
            if des_encrypt_block(&netntlmv1_m05500_key_expand(&seed), &challenge) == ct3 {
                third_key_index = Some(i as u16);
                break;
            }
        }
        let third_key_index =
            third_key_index.ok_or("NT response tail does not match any 16-bit third key")?;

        Ok(Self { challenge, ct1, ct2, ct3, third_key_index })
    }

    /// The m05500 kernel test for one candidate, in attack order:
    ///
    /// 1. The NT-hash filter `if ((d >> 16) != s2) continue;`
    ///    (m05500_a0-pure.cl:155 and :300, MATCHES_NONE_VS form in
    ///    m05500_a0-optimized.cl:229/:458): d = ctx.h[3] holds NT-hash bytes
    ///    12..15 little-endian, so d >> 16 is bytes 14..15 — the two bytes
    ///    the third key is derived from. A candidate whose third key differs
    ///    from the parse-time s2 can never reproduce ct3.
    /// 2. DES1 == digest[0..1] (pure.cl:308-343, the s kernel's whole
    ///    remaining test — its r2/r3 compare against the search words
    ///    themselves).
    /// 3. DES2 == digest[2..3], which the m kernel additionally compares
    ///    (pure.cl:179-196). Included so a candidate that only collides on
    ///    the first block is still rejected; a genuine preimage always
    ///    matches all three blocks.
    ///
    /// ct3 needs no separate check: the filter pins the candidate's third
    /// key to s2, whose encryption produced ct3 by construction.
    fn matches(&self, candidate: &str) -> bool {
        let nt = md4(&utf16le(candidate));
        let d = u32::from_le_bytes([nt[12], nt[13], nt[14], nt[15]]);
        if (d >> 16) != u32::from(self.third_key_index) {
            return false;
        }
        let key1 = netntlmv1_m05500_key_expand(&nt[..7].try_into().unwrap());
        if des_encrypt_block(&key1, &self.challenge) != self.ct1 {
            return false;
        }
        let key2 = netntlmv1_m05500_key_expand(&nt[7..14].try_into().unwrap());
        if des_encrypt_block(&key2, &self.challenge) != self.ct2 {
            return false;
        }
        true
    }
}

/// NetNTLMv1 challenge response: three DES blocks keyed from the NT hash,
/// compared against the NT response only (the LM response is never validated).
/// Accepted forms:
/// - "$NETNTLM$challenge$ntresp" (tagged)
/// - the classic capture "user::domain:challenge:lmresp:ntresp" — the DES
///   input is the 8-byte server challenge, all three blocks
/// - the hashcat 5500 wire "user::domain:srvchall:ntresp(48):clichall(16)"
///   ("NetNTLMv1 / NetNTLMv1+ESS", KERN_TYPE 5500) — verified with the
///   module's own semantics via [`NetNTLMv1M05500`]: the DES input is the
///   binary client challenge (or the ESS MD5 challenge), the response tail
///   is a brute-forced third block that pins a 16-bit NT-hash filter, and
///   the first 16 response bytes are checked against DES1/DES2. The two
///   capture forms are told apart by the last field's length (48 hex =
///   classic, 16 hex = hashcat wire).
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
        if fields[4].len() == 48 && fields[5].len() == 16 {
            // hashcat 5500 wire — the module's parse + kernel semantics.
            let parsed = NetNTLMv1M05500::parse((fields[3], fields[4], fields[5]))?;
            return Ok(parsed.matches(candidate));
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

/// WPA-PMKID (hashcat 22000): PMK = pbkdf2-hmac-sha1(pass, ssid, 4096, 32),
/// PMKID = hmac-sha1(PMK, "PMK Name" || ap_mac || sta_mac).
/// Wire form: WPA*01*pmkid*ap_mac*sta_mac*essid_hex**** (hashcat 22000).
pub fn verify_wpa_pmkid(encoded: &str, candidate: &str) -> Result<bool, String> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let fields: Vec<&str> = encoded.split('*').collect();
    if fields.len() < 6 || fields[0] != "WPA" || fields[1] != "01" {
        return Err("not a WPA*01* PMKID target".into());
    }
    let pmkid_hex = fields[2];
    let ap = hex::decode(fields[3]).map_err(|_| "invalid AP MAC")?;
    let sta = hex::decode(fields[4]).map_err(|_| "invalid client MAC")?;
    let essid = hex::decode(fields[5]).map_err(|_| "invalid ESSID")?;
    if pmkid_hex.len() != 40 || ap.len() != 6 || sta.len() != 6 || essid.len() > 32 {
        return Err("invalid PMKID field lengths".into());
    }
    let expected = hex::decode(pmkid_hex).map_err(|_| "invalid PMKID")?;
    let mut pmk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(candidate.as_bytes(), &essid, 4096, &mut pmk);
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&pmk).map_err(|e| e.to_string())?;
    mac.update(b"PMK Name");
    mac.update(&ap);
    mac.update(&sta);
    Ok(mac.finalize().into_bytes().as_slice() == expected.as_slice())
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
    use md5::Digest as _;
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
    fn wpa_pmkid_matches_independent_vector() {
        // Node-crypto vector: PBKDF2-HMAC-SHA1 4096 + HMAC-SHA1 over
        // "PMK Name"||AP||STA, independent of RustCrypto.
        assert!(verify_wpa_pmkid(
            "WPA*01*8f1bddadd02e1417163f03af545892cc6998eff4*aabbccddeeff*112233445566*546573744e6574****",
            "cyberdeck",
        )
        .unwrap());
        assert!(!verify_wpa_pmkid(
            "WPA*01*8f1bddadd02e1417163f03af545892cc6998eff4*aabbccddeeff*112233445566*546573744e6574****",
            "Cyberdeck",
        )
        .unwrap());
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
    fn netntlmv1_m05500_module_self_test_pair() {
        // hashcat module_05500.c:33-34 ST_PASS / ST_HASH — a NetNTLMv1+ESS
        // capture (server challenge ada06359242920a5 followed by 16 zero
        // bytes, client challenge 9c23f6c094853920). The module self-test
        // requires this exact pair to survive hash_decode (ESS MD5 challenge
        // + 2^16 third-key precompute) and the m05500 kernel filter/DES
        // checks, here on CPU.
        const ST_HASH: &str = "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920";
        assert!(verify_netntlmv1(ST_HASH, "hashcat").unwrap());

        // Wrong candidates: any password whose NT-hash bytes 14..15 do not
        // equal the brute-forced third-key index, or whose DES1/DES2 blocks
        // differ, must be rejected.
        assert!(!verify_netntlmv1(ST_HASH, "Hashcat").unwrap());
        assert!(!verify_netntlmv1(ST_HASH, "hashca").unwrap());
        assert!(!verify_netntlmv1(ST_HASH, "hashcats").unwrap());
        assert!(!verify_netntlmv1(ST_HASH, "password").unwrap());

        // Flipping one bit of digest[0..3] (the first 16 response bytes)
        // fails the DES1 comparison (m05500_a0-pure.cl:338-343).
        let tampered_head = ST_HASH.replacen("0556d529", "0556d528", 1);
        assert!(!verify_netntlmv1(&tampered_head, "hashcat").unwrap());
        // Flipping one bit of digest_tmp (the last 8 bytes, the brute-forced
        // tail) leaves no third key at all: the module's PARSER_SALT_VALUE
        // parse failure (module_05500.c:322), surfaced here as Err.
        let tampered_tail = ST_HASH.replacen("7c9704ea", "7c9704eb", 1);
        assert!(verify_netntlmv1(&tampered_tail, "hashcat").is_err());
    }

    #[test]
    fn netntlmv1_m05500_st_derived_values() {
        // The ST pair's intermediate values, re-derived line by line from
        // module_05500.c and the m05500 kernels (not from the wire alone).
        let parsed = NetNTLMv1M05500::parse((
            "ada06359242920a500000000000000000000000000000000",
            "0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea",
            "9c23f6c094853920",
        ))
        .unwrap();

        // ESS challenge (module_05500.c:263-283): MD5 over the BINARY client
        // challenge followed by the first 8 server challenge bytes — not the
        // ASCII hex (that construction was falsified by prior experiments:
        // MD5("9c23f6c0" || srvchal) = e3802fc380481e8c..., which does not
        // match the wire).
        let ess_input = [
            0x9c, 0x23, 0xf6, 0xc0, 0x94, 0x85, 0x39, 0x20, 0xad, 0xa0, 0x63, 0x59, 0x24, 0x29,
            0x20, 0xa5,
        ];
        assert_eq!(parsed.challenge, md5(&ess_input)[..8]);

        // NT hash of the ST password (MD4 over UTF-16LE "hashcat").
        let nt = md4(&utf16le("hashcat"));
        assert_eq!(
            nt,
            [0xb4, 0xb9, 0xb0, 0x2e, 0x6f, 0x09, 0xa9, 0xbd, 0x76, 0x0f, 0x38, 0x8b, 0x67, 0x35,
             0x1e, 0x2b],
        );

        // The kernel filter (m05500_a0-pure.cl:155) compares NT-hash word
        // h[3] >> 16 against salt_buf[2]; the parse-time brute force
        // (module_05500.c:290-318) must therefore land on exactly the third
        // key built from the ST password's bytes 14..15.
        let d = u32::from_le_bytes([nt[12], nt[13], nt[14], nt[15]]);
        assert_eq!(u32::from(parsed.third_key_index), d >> 16);

        // ...and that key's encryption reproduces the captured tail ct3,
        // while the first two key expansions reproduce ct1/ct2 (the DES1 and
        // DES2 kernel compares).
        let k1 = netntlmv1_m05500_key_expand(&nt[..7].try_into().unwrap());
        assert_eq!(des_encrypt_block(&k1, &parsed.challenge), parsed.ct1);
        let k2 = netntlmv1_m05500_key_expand(&nt[7..14].try_into().unwrap());
        assert_eq!(des_encrypt_block(&k2, &parsed.challenge), parsed.ct2);
        let k3 = netntlmv1_m05500_key_expand(&[nt[14], nt[15], 0, 0, 0, 0, 0]);
        assert_eq!(des_encrypt_block(&k3, &parsed.challenge), parsed.ct3);
    }

    #[test]
    fn netntlmv1_m05500_classic_shape_roundtrip() {
        // Non-ESS line (16-hex server challenge): the ESS branch is skipped
        // (module_05500.c:259) and the challenge is the binary client
        // challenge. Built exactly the way the capture variant the module
        // models produces it — third block keyed from NT-hash bytes 14..15 —
        // so the parse-time brute force recovers the same 16-bit index.
        let nt = md4(&utf16le("deck-test-1"));
        let clichall = hex::decode("9c23f6c094853920").unwrap();
        let k = |index: usize| netntlmv1_m05500_key_expand(&nt[index..index + 7].try_into().unwrap());
        let ct1 = des_encrypt_block(&k(0), &clichall);
        let ct2 = des_encrypt_block(&k(7), &clichall);
        let ct3 = des_encrypt_block(
            &netntlmv1_m05500_key_expand(&[nt[14], nt[15], 0, 0, 0, 0, 0]),
            &clichall,
        );
        let line = format!(
            "user::dom:1122334455667788:{}{}{}:9c23f6c094853920",
            hex::encode(ct1),
            hex::encode(ct2),
            hex::encode(ct3),
        );
        assert!(verify_netntlmv1(&line, "deck-test-1").unwrap());
        assert!(!verify_netntlmv1(&line, "deck-test-2").unwrap());

        // An odd-length server challenge is the module's PARSER_TOKEN_LENGTH
        // (module_05500.c:205).
        let odd = line.replacen("1122334455667788", "112233445566778", 1);
        assert!(verify_netntlmv1(&odd, "deck-test-1").is_err());
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


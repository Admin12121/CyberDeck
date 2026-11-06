//! BitLocker disk encryption recovery verifier (format batch B4). Wire format
//! and check semantics mirror the pinned upstream module 22100
//! (reference/hashcat/src/modules/module_22100.c and OpenCL/m22100-pure.cl,
//! cross-checked byte-exactly against tools/test_modules/m22100.py). Every
//! verifier runs on the CPU in bounded time so a GPU match can always be
//! re-proven independently before it is reported. Only public upstream
//! example vectors are used as fixtures.
//!
//! Pinned algorithm: the AES-256 key is the final state of the 88-byte
//! iterated hash `h = SHA-256(h || SHA-256(SHA-256(UTF-16LE(pass))) || salt
//! || iteration LE u64)` started from `h = 0x00 * 32` and run 0x100000
//! times. The 60-byte VMK blob is RFC 3610 AES-CCM with a 16-octet tag, a
//! 12-octet nonce (L = 3) and no additional authenticated data — except the
//! tag is stored first, so the whole blob decrypts under the counter
//! keystream starting at S_0 and the CBC-MAC over the 44-byte plaintext is
//! compared against the first 16 bytes. Type 0 records skip the MAC compare
//! and stop at the decrypted VMK header check (kernel early reject).

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use sha2::Digest;

/// Pinned upstream KDF iteration count (module ITERATION_BITLOCKER,
/// 0x100000); the tokenizer rejects every other value.
const ITERATION_BITLOCKER: u64 = 0x10_0000;

/// CPU policy bound for the recovery worker. The pinned module fixes the
/// wire iteration count to the same value, so the bound is a documented cap
/// rather than an additional relaxation.
const BITLOCKER_MAX_ITERATIONS: u64 = 0x10_0000;

const SALT_LEN_BITLOCKER: usize = 16;
/// Nonce length (module IV_LEN_BITLOCKER); RFC 3610 L = 15 - 12 = 3.
const NONCE_LEN_BITLOCKER: usize = 12;
const MAC_LEN: usize = 16;
/// Blob length (module DATA_LEN_BITLOCKER): MAC || 44-byte VMK descriptor.
const DATA_LEN_BITLOCKER: usize = 60;
const VMK_DATA_LEN: usize = DATA_LEN_BITLOCKER - MAC_LEN;

/// 88-byte KDF message: last hash (32) || password hash (32) || salt (16) ||
/// iteration as u64 little-endian (8); the reference kernel hashes it as the
/// two blocks `last_hash || init_hash` and `salt || counter LE32 || 0u32`.
const KDF_MESSAGE_LEN: usize = 88;

/// Parsed `$bitlocker$` record (hashcat mode 22100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitLocker {
    /// VMK descriptor type: 0 = header check only, 1 = full AES-CCM MAC
    /// verification (kernel m22100_comp).
    pub vmk_type: u8,
    pub salt: [u8; SALT_LEN_BITLOCKER],
    pub nonce: [u8; NONCE_LEN_BITLOCKER],
    /// 60 encrypted bytes: 16-byte MAC || 44-byte VMK descriptor.
    pub blob: [u8; DATA_LEN_BITLOCKER],
}

impl BitLocker {
    /// Parses a `$bitlocker$` line with the pinned module's fixed-shape
    /// tokenizer: VMK type (1 digit, 0 or 1), salt length (2 digits, 16),
    /// salt (32 hex), iterations (7 digits, 0x100000), nonce length (2
    /// digits, 12), nonce (24 hex), data length (2 digits, 60), data
    /// (120 hex).
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$bitlocker$")
            .ok_or("not a $bitlocker$ hash")?;
        let fields: Vec<&str> = rest.split('$').collect();
        if fields.len() != 8 {
            return Err("bitlocker hash must have 8 fields".into());
        }
        if fields[0].len() != 1 {
            return Err("invalid bitlocker hash VMK type field".into());
        }
        let vmk_type: u8 = fields[0]
            .parse()
            .map_err(|_| "invalid bitlocker hash VMK type field")?;
        if vmk_type > 1 {
            return Err("bitlocker VMK type must be 0 or 1".into());
        }
        if fields[1].len() != 2 {
            return Err("invalid bitlocker hash salt length field".into());
        }
        let salt_len = digit_field(fields[1], "salt length")?;
        if salt_len as usize != SALT_LEN_BITLOCKER || fields[2].len() != salt_len as usize * 2 {
            return Err("bitlocker salt must be 32 hex characters".into());
        }
        let salt = hex_field(fields[2], "salt")?;
        if fields[3].len() != 7 {
            return Err("invalid bitlocker hash iteration count field".into());
        }
        let iterations = digit_field(fields[3], "iteration count")?;
        if iterations != ITERATION_BITLOCKER || iterations > BITLOCKER_MAX_ITERATIONS {
            return Err("bitlocker iteration count is pinned to 1048576".into());
        }
        if fields[4].len() != 2 {
            return Err("invalid bitlocker hash nonce length field".into());
        }
        let nonce_len = digit_field(fields[4], "nonce length")?;
        if nonce_len as usize != NONCE_LEN_BITLOCKER || fields[5].len() != nonce_len as usize * 2 {
            return Err("bitlocker nonce must be 24 hex characters".into());
        }
        let nonce = hex_field(fields[5], "nonce")?;
        if fields[6].len() != 2 {
            return Err("invalid bitlocker hash data length field".into());
        }
        let data_len = digit_field(fields[6], "data length")?;
        if data_len as usize != DATA_LEN_BITLOCKER || fields[7].len() != data_len as usize * 2 {
            return Err("bitlocker data must be 120 hex characters".into());
        }
        let data = hex_field(fields[7], "data")?;
        Ok(Self {
            vmk_type,
            salt: salt.try_into().expect("salt length checked"),
            nonce: nonce.try_into().expect("nonce length checked"),
            blob: data.try_into().expect("data length checked"),
        })
    }

    /// Mirrors kernel m22100_comp: the KDF state becomes an AES-256 key, the
    /// 60-byte blob decrypts under the CCM counter keystream (S_0 over the
    /// stored MAC, S_1..S_3 over the VMK data), the decrypted header must be
    /// a 44-byte VMK descriptor, and type 1 records additionally require the
    /// CBC-MAC over that plaintext to match the first 16 bytes.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let key = bitlocker_kdf(candidate, &self.salt);
        let vmk_data = if self.vmk_type == 0 {
            // Type 0 carries no usable MAC; the check is the decrypted header
            // only (kernel early reject). Counters for the data run from S_1.
            let cipher = aes::Aes256::new_from_slice(&key).map_err(|_| "invalid AES key")?;
            let mut data = self.blob[MAC_LEN..].to_vec();
            ccm_ctr_xor(&cipher, &self.nonce, 15 - self.nonce.len(), 1, &mut data);
            data
        } else {
            match ccm_decrypt_and_verify::<aes::Aes256>(
                &key,
                &self.nonce,
                &[],
                &self.blob[..MAC_LEN],
                &self.blob[MAC_LEN..],
            ) {
                Some(data) => data,
                // After parse, the only reachable None is the tag mismatch.
                None => return Ok(false),
            }
        };
        // Decrypted VMK header: size 0x002c, version 0x0001, v1 <= 5 and
        // v2 = 0x20 (module comment: data_size/version/v1/v2 checks).
        Ok(vmk_data.len() == VMK_DATA_LEN
            && vmk_data[0] == 0x2c
            && vmk_data[1] == 0x00
            && vmk_data[4] == 0x01
            && vmk_data[5] == 0x00
            && vmk_data[8] <= 0x05
            && vmk_data[9] == 0x20)
    }
}

/// The pinned 88-byte key derivation (kernel m22100_loop, oracle
/// `bitlocker_kdf`): each iteration re-hashes `last || init_hash || salt ||
/// iteration LE u64` from the SHA-256 IV, starting from `last = 0x00 * 32`.
fn bitlocker_kdf(password: &str, salt: &[u8; SALT_LEN_BITLOCKER]) -> [u8; 32] {
    let password_hash = sha256(&utf16le(password));
    let init_hash = sha256(&password_hash);
    let mut message = [0u8; KDF_MESSAGE_LEN];
    message[32..64].copy_from_slice(&init_hash);
    message[64..80].copy_from_slice(salt);
    let mut last = [0u8; 32];
    for iteration in 0..ITERATION_BITLOCKER {
        message[..32].copy_from_slice(&last);
        message[80..].copy_from_slice(&iteration.to_le_bytes());
        last = sha256(&message);
    }
    last
}

/// RFC 3610 AES-CCM combined decrypt-and-verify: CBC-MAC over the encoded
/// AAD and the zero-padded plaintext, CTR recovery with counters from S_1,
/// tag check against S_0. Returns the plaintext when the tag matches, None
/// on mismatch or out-of-shape parameters. Generic so the RFC 3610 AES-128
/// vectors exercise the same code the BitLocker type 1 path runs.
fn ccm_decrypt_and_verify<C>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    tag: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>>
where
    C: BlockEncrypt + KeyInit,
{
    // Nonce 7..=13 bytes so L = 15 - len stays in 2..=8 (RFC 3610 section 2).
    if nonce.len() < 7 || nonce.len() > 13 {
        return None;
    }
    let l = 15 - nonce.len();
    if tag.len() < 4 || tag.len() > 16 || tag.len() % 2 != 0 {
        return None;
    }
    // The message length Q must fit the L-byte length field.
    if l < 8 && ciphertext.len() >= 1usize << (8 * l) {
        return None;
    }
    // Only the short AAD encoding (2-octet length) is implemented; the
    // verifiers here pass none.
    if aad.len() >= 0xff00 {
        return None;
    }
    let cipher = C::new_from_slice(key).ok()?;

    // Counters from S_1 recover the plaintext first; the CBC-MAC runs over
    // the recovered plaintext, not the ciphertext (RFC 3610 section 2.2,
    // mirrored by the kernel's out0..out3 handling).
    let mut plaintext = ciphertext.to_vec();
    ccm_ctr_xor(&cipher, nonce, l, 1, &mut plaintext);

    // B0 = flags || nonce || Q, then CBC-MAC over the AAD encoding and the
    // zero-padded plaintext.
    let mut mac = [0u8; 16];
    mac[0] = (u8::from(!aad.is_empty()) << 6) | (((tag.len() as u8 - 2) / 2) << 3) | (l as u8 - 1);
    mac[1..1 + nonce.len()].copy_from_slice(nonce);
    write_be(&mut mac[16 - l..], ciphertext.len() as u64);
    ccm_encrypt_block(&cipher, &mut mac);
    if !aad.is_empty() {
        let mut encoded = Vec::with_capacity(aad.len() + 2);
        encoded.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        encoded.extend_from_slice(aad);
        while encoded.len() % 16 != 0 {
            encoded.push(0);
        }
        for block in encoded.chunks_exact(16) {
            xor_block(&mut mac, block);
            ccm_encrypt_block(&cipher, &mut mac);
        }
    }
    let mut padded = plaintext.clone();
    padded.resize(plaintext.len() + (16 - plaintext.len() % 16) % 16, 0);
    for block in padded.chunks_exact(16) {
        xor_block(&mut mac, block);
        ccm_encrypt_block(&cipher, &mut mac);
    }

    // The stored tag decrypts under S_0 (counter blocks use flags L-1).
    let mut s0 = [0u8; 16];
    s0[0] = l as u8 - 1;
    s0[1..1 + nonce.len()].copy_from_slice(nonce);
    ccm_encrypt_block(&cipher, &mut s0);
    let mut expected = [0u8; 16];
    expected[..tag.len()].copy_from_slice(tag);
    xor_block(&mut expected, &s0);
    if !constant_time_eq(&mac[..tag.len()], &expected[..tag.len()]) {
        return None;
    }

    Some(plaintext)
}

/// XORs `data` in place with the CCM counter keystream starting at
/// `counter_start`: flags byte L-1, nonce, counter big-endian in the last L
/// bytes (RFC 3610 section 2 A_i).
fn ccm_ctr_xor<C: BlockEncrypt>(
    cipher: &C,
    nonce: &[u8],
    l: usize,
    counter_start: u64,
    data: &mut [u8],
) {
    for (counter, chunk) in (counter_start..).zip(data.chunks_mut(16)) {
        let mut block = [0u8; 16];
        block[0] = l as u8 - 1;
        block[1..1 + nonce.len()].copy_from_slice(nonce);
        write_be(&mut block[16 - l..], counter);
        ccm_encrypt_block(cipher, &mut block);
        for (byte, key) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= key;
        }
    }
}

fn ccm_encrypt_block<C: BlockEncrypt>(cipher: &C, block: &mut [u8; 16]) {
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

fn xor_block(block: &mut [u8; 16], other: &[u8]) {
    for (byte, value) in block.iter_mut().zip(other) {
        *byte ^= value;
    }
}

/// Writes `value` big-endian into the buffer (buffer length <= 8).
fn write_be(buffer: &mut [u8], value: u64) {
    let bytes = value.to_be_bytes();
    buffer.copy_from_slice(&bytes[8 - buffer.len()..]);
}

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn hex_field(text: &str, name: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid bitlocker hash {name} field"));
    }
    hex::decode(text).map_err(|_| format!("invalid bitlocker hash {name} field"))
}

fn digit_field(text: &str, name: &str) -> Result<u64, String> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid bitlocker hash {name} field"));
    }
    text.parse::<u64>()
        .map_err(|_| format!("invalid bitlocker hash {name} field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream hashcat example hash (module ST_HASH/ST_PASS, pass "hashcat").
    const BITLOCKER_ST: &str = "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb";

    // The ST only exercises type 1, so the type 0/1 pair below was produced
    // with the pinned upstream oracle
    // reference/hashcat/tools/test_modules/m22100.py
    // (module_generate_hash(b"hunter2", ST salt bytes, type=...)) and
    // confirmed against an independent implementation of the pinned kernel
    // semantics.
    const BITLOCKER_TYPE0_SYNTH: &str = "$bitlocker$0$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$182667e368b9f5a83bd97485$60$e9188d7a097332fc59d7376ae3241e7e4c5fc6189a4b3059a895099e3b521694f00208c65cc358014c70e79b2b9fa918373756f1ed6183e57fe562d6";
    const BITLOCKER_TYPE1_SYNTH: &str = "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$eda87f5979381464b8acf127$60$60367b54144ce131db9609527629d227e08a329dab2476b0ce6b2db2d54685956bd989e4508890253063dc7b0ffbba97eee2cae1ee83887fe88b7359";

    #[test]
    fn upstream_bitlocker_example_vector_verifies() {
        let parsed = BitLocker::parse(BITLOCKER_ST).unwrap();
        assert_eq!(parsed.vmk_type, 1);
        assert_eq!(parsed.salt.len(), 16);
        assert_eq!(parsed.nonce.len(), 12);
        assert_eq!(parsed.blob.len(), 60);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("Hashcat").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_bitlocker_type0_and_type1_fixtures_verify() {
        let parsed = BitLocker::parse(BITLOCKER_TYPE0_SYNTH).unwrap();
        assert_eq!(parsed.vmk_type, 0);
        assert!(parsed.verify("hunter2").unwrap());
        assert!(!parsed.verify("hunter3").unwrap());
        let parsed = BitLocker::parse(BITLOCKER_TYPE1_SYNTH).unwrap();
        assert_eq!(parsed.vmk_type, 1);
        assert!(parsed.verify("hunter2").unwrap());
        assert!(!parsed.verify("hunter3").unwrap());
    }

    #[test]
    fn rfc3610_ccm_vectors_verify() {
        // Packet Vectors #1/#2 (M = 8) and #7/#8 (M = 10) from RFC 3610,
        // AES-128 key C0..CF, nonce 13 octets (L = 2), 8-octet AAD; the
        // expected values are the authenticated and encrypted outputs with
        // the ciphertext split from the trailing tag.
        let key = hex::decode("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF").unwrap();
        let aad = hex::decode("0001020304050607").unwrap();
        let plaintext1 = hex::decode("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E").unwrap();
        let plaintext2 = hex::decode("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").unwrap();
        let vectors: [(&str, &[u8], &[u8], usize); 4] = [
            (
                "00000003020100A0A1A2A3A4A5",
                &plaintext1,
                &hex::decode("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0")
                    .unwrap(),
                8,
            ),
            (
                "00000004030201A0A1A2A3A4A5",
                &plaintext2,
                &hex::decode("72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916")
                    .unwrap(),
                8,
            ),
            (
                "00000009080706A0A1A2A3A4A5",
                &plaintext1,
                &hex::decode("0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C048C56602C97ACBB7490")
                    .unwrap(),
                10,
            ),
            (
                "0000000A090807A0A1A2A3A4A5",
                &plaintext2,
                &hex::decode(
                    "7B75399AC0831DD2F0BBD75879A2FD8F6CAE6B6CD9B7DB24C17B4433F434963F34B4",
                )
                .unwrap(),
                10,
            ),
        ];
        for (nonce_hex, plaintext, output, mac_len) in vectors {
            let nonce = hex::decode(nonce_hex).unwrap();
            let split = output.len() - mac_len;
            let recovered = ccm_decrypt_and_verify::<aes::Aes128>(
                &key,
                &nonce,
                &aad,
                &output[split..],
                &output[..split],
            )
            .expect("RFC 3610 vector must verify");
            assert_eq!(recovered, plaintext);
        }
        // A flipped ciphertext byte must fail the tag check.
        let (nonce_hex, _, output, mac_len) = vectors[0];
        let nonce = hex::decode(nonce_hex).unwrap();
        let mut corrupted = output.to_vec();
        corrupted[0] ^= 1;
        assert_eq!(
            ccm_decrypt_and_verify::<aes::Aes128>(
                &key,
                &nonce,
                &aad,
                &corrupted[output.len() - mac_len..],
                &corrupted[..output.len() - mac_len],
            ),
            None
        );
    }

    /// Replaces the wire field at `index` (0 = VMK type) on the ST line.
    fn with_field(st: &str, index: usize, value: &str) -> String {
        let mut fields: Vec<String> = st.split('$').map(str::to_string).collect();
        fields[index + 2] = value.to_string();
        fields.join("$")
    }

    #[test]
    fn bitlocker_targets_self_detect_through_the_recovery_target_parse() {
        // The embedded Hashcat KAT gate parses each fixture with an empty
        // algorithm hint; the $-marker must select the right verifier.
        let target = crate::recovery::RecoveryTarget::parse("", BITLOCKER_ST).unwrap();
        assert!(target.is_match(b"hashcat").unwrap());
        assert!(!target.is_match(b"hashcau").unwrap());
    }

    #[test]
    fn bitlocker_parse_rejects_out_of_policy_shapes() {
        assert!(BitLocker::parse(BITLOCKER_ST).is_ok());
        // VMK type: not 0/1, wrong digit count, non-digit.
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 0, "2")).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 0, "01")).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 0, "x")).is_err());
        // Iterations: pinned value, wrong digit count.
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 3, "1048575")).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 3, "01048576")).is_err());
        // Salt/nonce/data length fields: wrong pinned value or shape.
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 1, "15")).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 1, "016")).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 4, "13")).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 6, "59")).is_err());
    }

    #[test]
    fn bitlocker_parse_rejects_field_shape_drift() {
        // Hex payload fields shorter/longer than the pinned byte counts and
        // non-hex content.
        let salt = "6f972989ddc209f1eccf07313a7266a2";
        let nonce = "3a33a8eaff5e6f81d907b591";
        let data = "316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb";
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 2, &salt[..30])).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 5, &nonce[..22])).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 2, &format!("{salt}00"))).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 7, &data[..118])).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 7, &data[..60])).is_err());
        assert!(BitLocker::parse(&format!("{BITLOCKER_ST}00")).is_err());
        assert!(BitLocker::parse(&with_field(BITLOCKER_ST, 7, &"g".repeat(120))).is_err());
        // Signature and field count.
        assert!(BitLocker::parse(&BITLOCKER_ST.replacen("$bitlocker$", "$bitloker$", 1)).is_err());
        assert!(BitLocker::parse(&format!("{BITLOCKER_ST}$extra")).is_err());
        assert!(BitLocker::parse("").is_err());
    }
}

//! RAR archive recovery verifiers. Wire formats and check semantics mirror
//! the pinned upstream modules 12500 (RAR3-hp) and 13000 (RAR5). Every
//! verifier runs on the CPU in bounded time so a GPU match can always be
//! re-proven independently before it is reported. Only public upstream
//! example vectors are used as fixtures.
//!
//! RAR3-hp note: the key derivation is one continuous SHA-1 over 0x40000
//! `password || salt || counter` messages while RAR's own setup rewrites the
//! password buffer in place (the "RAR29" quirk). The semantics implemented
//! here follow the pinned upstream module oracle
//! reference/hashcat/tools/test_modules/m12500.py (`_mangle_block`,
//! `_sha1_update_rar29`), which the GPU kernels reproduce; see the derive
//! function for the details.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use sha1::Digest as _;
use sha2::Sha256;

/// RAR3-hp rounds: 0x40000 SHA-1 messages per candidate (module_12500.c
/// ROUNDS_RAR3).
const RAR3_ITERATIONS: u32 = 0x40000;
/// Every 0x4000th RAR3-hp round donates one AES-CBC IV byte.
const RAR3_IV_STEP: u32 = 0x4000;
/// The fixed RAR3-hp check plaintext. hashcat's kernel compares the first
/// eight CBC-decrypted bytes against digest words 0xc43d7b00/0x40070000
/// (module_12500.c: "\xc4\x3d\x7b\x00\x40\x07\x00" plus one zero byte).
const RAR3_CHECK_VALUE: [u8; 8] = [0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00, 0x00];
/// RAR5 PBKDF2 adds 32 rounds to the power-of-two count stored in the hash
/// (module_13000.c: salt_iter = ((1 << n) + 32) - 1 plus the init round).
const RAR5_ROUND_BIAS: u32 = 32;
/// CPU recovery policy cap on the RAR5 log2 iteration count. hashcat itself
/// accepts exponents up to 31, but 2^24 + 32 (~16.8M PBKDF2 rounds, a few
/// seconds) is the largest cost the CPU verifier still re-proves in bounded
/// time; larger exponents stay GPU-only and are rejected at parse time.
const MAX_RAR5_LOG2_ITERATIONS: u32 = 24;

fn hex_len_ok(text: &str, expected: usize) -> bool {
    text.len() == expected && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

// ------------------------------------------------------------------ RAR3-hp

/// Parsed `$RAR3$*0*` header-encrypted archive entry (hashcat mode 12500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar3Hp {
    /// 8-byte archive salt from the $RAR3$*0*<salt> line.
    pub salt: [u8; 8],
    /// First AES-128-CBC block of the encrypted header check value.
    pub crypted: [u8; 16],
}

impl Rar3Hp {
    /// Strict wire shape per module_12500.c token rules: exactly
    /// `$RAR3$*0*<16 hex salt>*<32 hex crypted>`. Type 1 archives carry file
    /// data blobs with a different shape and are not bundled.
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$RAR3$")
            .ok_or("not a $RAR3$ RAR3-hp hash")?;
        let rest = rest
            .strip_prefix('*')
            .ok_or("RAR3-hp hash is missing its leading separator")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() != 3 {
            return Err("RAR3-hp hash must have 4 fields".into());
        }
        if parts[0] != "0" {
            return Err("only header-encrypted RAR3 hashes ($RAR3$*0) are supported".into());
        }
        if !hex_len_ok(parts[1], 16) {
            return Err("RAR3-hp salt must be 16 hex characters".into());
        }
        if !hex_len_ok(parts[2], 32) {
            return Err("RAR3-hp check field must be 32 hex characters".into());
        }
        let salt = hex::decode(parts[1]).map_err(|_| "invalid RAR3-hp salt")?;
        let crypted = hex::decode(parts[2]).map_err(|_| "invalid RAR3-hp check field")?;
        Ok(Self {
            salt: salt.try_into().expect("8-byte salt"),
            crypted: crypted.try_into().expect("16-byte check block"),
        })
    }

    /// RAR3-hp check: the derived AES-128 key and IV decrypt the stored
    /// block, and the first eight plaintext bytes must equal the fixed check
    /// value. Only the first eight bytes are compared, mirroring the kernel
    /// compare (r0/r1 against 0xc43d7b00/0x40070000), so every GPU match is
    /// also accepted here.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let utf16: Vec<u8> = candidate
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let (key, iv) = rar3_hp_derive(&utf16, &self.salt);
        let mut block = *GenericArray::from_slice(&self.crypted);
        aes::Aes128::new_from_slice(&key)
            .map_err(|_| "invalid RAR3 AES key")?
            .decrypt_block(&mut block);
        let plain: [u8; 16] = block.into();
        let check: [u8; 8] = core::array::from_fn(|i| plain[i] ^ iv[i]);
        Ok(constant_time_eq(&check, &RAR3_CHECK_VALUE))
    }
}

/// One pass of RAR's own setup quirk: the 64-byte window at the mangle
/// position is replaced with words W[64..79] of the SHA-1 message schedule
/// computed from its own bytes, stored as little-endian words (upstream
/// oracle `_mangle_block`, tools/test_modules/m12500.py lines 30-40).
fn mangle_block(block: &[u8; 64]) -> [u8; 64] {
    let mut w = [0u32; 80];
    for (index, word) in block.chunks_exact(4).enumerate() {
        w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let mut out = [0u8; 64];
    for (k, word) in w[64..80].iter().enumerate() {
        out[k * 4..k * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// RAR3-hp key/IV derivation. One continuous SHA-1 hashes
/// `(password || salt || 3-byte little-endian counter)` for 0x40000 rounds
/// while the password buffer is progressively rewritten by `mangle_block`
/// whenever a full 64-byte window past the current partial block was hashed.
/// The AES-128 key is the first 16 digest bytes with each 4-byte word
/// reversed; every 0x4000th round finalizes a copy of the running state and
/// donates its last digest byte to the 16-byte CBC IV.
fn rar3_hp_derive(password_utf16le: &[u8], salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
    let mut buf = Vec::with_capacity(password_utf16le.len() + salt.len());
    buf.extend_from_slice(password_utf16le);
    buf.extend_from_slice(salt);
    let length = buf.len();
    let mut count = 0usize;
    let mut ctx = sha1::Sha1::new();
    let mut iv = [0u8; 16];
    let mut iv_index = 0usize;
    for iteration in 0..RAR3_ITERATIONS {
        ctx.update(&buf);
        // Rewrite the fully hashed 64-byte windows (oracle
        // `_sha1_update_rar29`): start past the current partial block and
        // stop before a window would run past the buffer end. The rewritten
        // bytes never influence this round's hash, only later rounds.
        let mut window = 64 - (count & 63);
        while window + 63 < length {
            let block: [u8; 64] = buf[window..window + 64]
                .try_into()
                .expect("mangling window is in bounds");
            buf[window..window + 64].copy_from_slice(&mangle_block(&block));
            window += 64;
        }
        count += length;
        let counter = iteration.to_le_bytes();
        ctx.update(&counter[..3]);
        count += 3;
        if iteration & (RAR3_IV_STEP - 1) == 0 {
            iv[iv_index] = ctx.clone().finalize()[19];
            iv_index += 1;
        }
    }
    let digest = ctx.finalize();
    let mut key = [0u8; 16];
    for t in 0..4 {
        for b in 0..4 {
            key[t * 4 + b] = digest[t * 4 + (3 - b)];
        }
    }
    (key, iv)
}

// --------------------------------------------------------------------- RAR5

/// Parsed `$rar5$` entry (hashcat mode 13000): PBKDF2-HMAC-SHA256 over the
/// raw password bytes with an exponent-encoded round count, folded to an
/// 8-byte password check value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar5 {
    pub salt: [u8; 16],
    /// Log2 of the base iteration count; the real round count is 2^n + 32.
    pub log2_iterations: u32,
    /// 16-byte AES IV carried on the wire. The upstream check never reads it
    /// (OpenCL/m13000-pure.cl compares the folded PBKDF2 output directly);
    /// it is parsed for wire parity and re-encoding only.
    pub iv: [u8; 16],
    pub check: [u8; 8],
}

impl Rar5 {
    /// Strict wire shape per module_13000.c token rules: the salt length
    /// ("16"), exponent (exactly two digits), IV and check length ("8") are
    /// fixed-width fields. Exponent 0 is rejected (PARSER_SALT_VALUE) and
    /// exponents above 31 exceed the module's own limit
    /// (PARSER_SALT_ITERATION); the CPU verifier additionally caps at
    /// MAX_RAR5_LOG2_ITERATIONS.
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash.strip_prefix("$rar5$").ok_or("not a $rar5$ RAR5 hash")?;
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 6 {
            return Err("RAR5 hash must have 7 $-separated fields".into());
        }
        if parts[0] != "16" {
            return Err("RAR5 salt length must be 16".into());
        }
        if !hex_len_ok(parts[1], 32) {
            return Err("RAR5 salt must be 32 hex characters".into());
        }
        if parts[2].len() != 2 || !parts[2].bytes().all(|b| b.is_ascii_digit()) {
            return Err("RAR5 KDF exponent must be two decimal digits".into());
        }
        let log2_iterations: u32 = parts[2]
            .parse()
            .map_err(|_| "invalid RAR5 KDF exponent")?;
        if log2_iterations == 0 {
            return Err("invalid RAR5 KDF exponent".into());
        }
        if log2_iterations > 31 {
            return Err("RAR5 KDF exponent exceeds the module limit of 31".into());
        }
        if log2_iterations > MAX_RAR5_LOG2_ITERATIONS {
            return Err("RAR5 KDF exponent exceeds the CPU recovery policy".into());
        }
        if !hex_len_ok(parts[3], 32) {
            return Err("RAR5 IV must be 32 hex characters".into());
        }
        if parts[4] != "8" {
            return Err("RAR5 check length must be 8".into());
        }
        if !hex_len_ok(parts[5], 16) {
            return Err("RAR5 check field must be 16 hex characters".into());
        }
        let salt = hex::decode(parts[1]).map_err(|_| "invalid RAR5 salt")?;
        let iv = hex::decode(parts[3]).map_err(|_| "invalid RAR5 IV")?;
        let check = hex::decode(parts[5]).map_err(|_| "invalid RAR5 check field")?;
        Ok(Self {
            salt: salt.try_into().expect("16-byte salt"),
            log2_iterations,
            iv: iv.try_into().expect("16-byte IV"),
            check: check.try_into().expect("8-byte check"),
        })
    }

    /// RAR5 check: PBKDF2-HMAC-SHA256 over the raw password bytes with
    /// (2^exponent + 32) rounds; the 32-byte key folds to 8 bytes by XORing
    /// byte lanes i, i+8, i+16, i+24 (oracle tools/test_modules/m13000.py).
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let rounds = (1u32 << self.log2_iterations) + RAR5_ROUND_BIAS;
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(candidate.as_bytes(), &self.salt, rounds, &mut key);
        let folded: [u8; 8] = core::array::from_fn(|i| {
            key[i] ^ key[i + 8] ^ key[i + 16] ^ key[i + 24]
        });
        Ok(constant_time_eq(&folded, &self.check))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    // Provenance per vector. RAR3-hp:
    // - hashcat module_12500.c ST_HASH/ST_PASS (also row 12500 of
    //   reference/hashcat/docs/hashcat-example-hashes.md), pass "hashcat".
    const RAR3_HASHCAT_ST: &str = "$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317";
    // - John the Ripper rar_common.h cpu_tests (non-DEBUG entries).
    const RAR3_JTR_TEST: &str = "$RAR3$*0*b109105f5fe0b899*d4f96690b1a8fe1f120b0290a85a2121";
    const RAR3_JTR_JOHN: &str = "$RAR3$*0*56ce6de6ddee17fb*4c957e533e00b0e18dfad6accc490ad9";
    // - John the Ripper rar_common.h test data (the widely used "password"
    //   vector, quoted verbatim from the cpu_tests array).
    const RAR3_JTR_PASSWORD: &str = "$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec";

    // RAR5:
    // - hashcat module_13000.c ST_HASH/ST_PASS (row 13000 of
    //   reference/hashcat/docs/hashcat-example-hashes.md), pass "hashcat".
    const RAR5_HASHCAT_ST: &str =
        "$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e62676a";
    // - John the Ripper rar5_common.h test vectors (default vector and
    //   -p mode entries; the last two are CMIYC 2014 contest archives).
    const RAR5_JTR_PASSWORD: &str =
        "$rar5$16$37526a0922b4adcc32f8fed5d51bb6c8$15$8955617d9b801def51d734095bb8ecdb$8$9f0b23c98ebb3653";
    const RAR5_JTR_OPENWALL: &str =
        "$rar5$16$92373e6493111cf1f2443dcd82122af9$15$011a3192b2f637d43deba9d0a08b7fa0$8$6862fcec47944d14";
    const RAR5_JTR_CMIYC_RAR: &str =
        "$rar5$16$ed9bd88cc649bd06bfd7dc418fcf5fbd$15$21771e718815d6f23073ea294540ce94$8$92c584bec0ad2979";
    const RAR5_JTR_CMIYC_WIN: &str =
        "$rar5$16$ed9bd88cc649bd06bfd7dc418fcf5fbd$15$21771e718815d6f23073ea294540ce94$8$5c4361e549c999e1";

    #[test]
    fn upstream_rar3_example_vectors_verify() {
        for (hash, positive) in [
            (RAR3_HASHCAT_ST, "hashcat"),
            (RAR3_JTR_TEST, "test"),
            (RAR3_JTR_JOHN, "john"),
            (RAR3_JTR_PASSWORD, "password"),
        ] {
            let parsed = Rar3Hp::parse(hash).unwrap();
            assert!(parsed.verify(positive).unwrap(), "{hash} positive");
            assert!(!parsed.verify("hashcau").unwrap(), "{hash} negative");
            assert!(!parsed.verify("not-the-solution").unwrap(), "{hash} negative");
        }
    }

    #[test]
    fn rar3_derivation_matches_the_upstream_python_oracle() {
        // Key/IV constants produced by running the pinned upstream module
        // oracle reference/hashcat/tools/test_modules/m12500.py (_derive,
        // hashlib only) through target/tmp-archives-crate/tools/
        // oracle_rar3.py; the same run re-encrypts the module ST_HASH check
        // bytes adbf6c5385d7a40373e8f77d7b89d317 exactly. The two long
        // passwords (40 and 30 characters) drive the RAR29 buffer-mangling
        // path, which no public -hp vector reaches ("subconsciousness"
        // hashes a 40-byte buffer, below the 64-byte window boundary).
        for (password, salt_hex, key_hex, iv_hex) in [
            ("hashcat", "45109af8ab5f297a", "e1f4cc6621f4f898d177f14ebedfc923", "1fa6d4304141bcb5dbdaf1799cc26b16"),
            ("password", "c9dea41b149b53b4", "ce7537298db2c49c3801157c3309dc67", "7a525fe92887b46b7e60fcd17d3dd3bd"),
            ("test", "b109105f5fe0b899", "eba2e49d18d1faf763c8cde7adff2f7b", "691f88e504ef5246998a9d3989623f9f"),
            ("john", "56ce6de6ddee17fb", "15c5518e2decc37b6c3ea93cce1b26a9", "4273498ba15e989c7c6889caa512a1cc"),
            ("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "0011223344556677", "6656806de3394907b32c46f18e180edc", "ffa4517037118b682c229f16ad01dce7"),
            ("abcdefghijklmnoabcdefghijklmno", "aabbccddeeff0011", "49bb4dd493f87827e8dcdc35650d3a73", "5c0ad0ab0963d03b7063cf5f5eaf40ce"),
        ] {
            let salt: [u8; 8] = hex::decode(salt_hex).unwrap().try_into().unwrap();
            let utf16: Vec<u8> = password
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            let (key, iv) = rar3_hp_derive(&utf16, &salt);
            assert_eq!(hex::encode(key), key_hex, "key for {password}");
            assert_eq!(hex::encode(iv), iv_hex, "iv for {password}");
        }
    }

    #[test]
    fn rar3_long_password_round_trip_is_self_consistent() {
        // NO public test vector exercises a wire hash whose password is long
        // enough to trigger the RAR29 mangling, so the end-to-end path for
        // those candidates is SELF-CONSISTENCY ONLY: derive with this code
        // path, re-encrypt the fixed check block, parse the synthesized wire
        // hash and verify. The mangling arithmetic itself is pinned against
        // the upstream Python oracle in the test above (40-character case).
        let password = "X".repeat(40);
        let salt_hex = "0011223344556677";
        let salt: [u8; 8] = hex::decode(salt_hex).unwrap().try_into().unwrap();
        let utf16: Vec<u8> = password
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let (key, iv) = rar3_hp_derive(&utf16, &salt);
        // CBC block 0 ciphertext = AES-128-encrypt(check block XOR IV) over
        // the fixed 16-byte RAR3 check plaintext (oracle FIXED_RAW_STRING).
        let fixed: [u8; 16] = [
            0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut block = *GenericArray::from_slice(
            &fixed.iter().zip(iv.iter()).map(|(p, i)| p ^ i).collect::<Vec<u8>>(),
        );
        aes::Aes128::new_from_slice(&key)
            .unwrap()
            .encrypt_block(&mut block);
        let hash = format!("$RAR3$*0*{salt_hex}*{}", hex::encode(block));
        let parsed = Rar3Hp::parse(&hash).unwrap();
        assert!(parsed.verify(&password).unwrap());
        assert!(!parsed.verify(&"X".repeat(39)).unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_rar5_example_vectors_verify() {
        for (hash, positive) in [
            (RAR5_HASHCAT_ST, "hashcat"),
            (RAR5_JTR_PASSWORD, "password"),
            (RAR5_JTR_OPENWALL, "openwall"),
            (RAR5_JTR_CMIYC_RAR, "rar"),
            (RAR5_JTR_CMIYC_WIN, "win"),
        ] {
            let parsed = Rar5::parse(hash).unwrap();
            assert!(parsed.verify(positive).unwrap(), "{hash} positive");
            assert!(!parsed.verify("hashcau").unwrap(), "{hash} negative");
            assert!(!parsed.verify("not-the-solution").unwrap(), "{hash} negative");
        }
    }

    #[test]
    fn rar5_check_ignores_the_wire_iv_like_the_kernel() {
        // OpenCL/m13000-pure.cl never reads the esalt IV during the compare;
        // two hashes differing only in the IV field must behave identically.
        let a = Rar5::parse(RAR5_HASHCAT_ST).unwrap();
        let other_iv =
            "$rar5$16$38466361001011015181344360681307$15$0123456789abcdef0123456789abcdef$8$cc7a30583e62676a";
        let b = Rar5::parse(other_iv).unwrap();
        assert_ne!(a.iv, b.iv);
        assert_eq!(a.verify("hashcat").unwrap(), b.verify("hashcat").unwrap());
        assert!(b.verify("hashcat").unwrap());
    }

    #[test]
    fn parse_rejects_out_of_policy_shapes() {
        // RAR3: wrong type digit, short/long/non-hex fields, extra field.
        assert!(Rar3Hp::parse("$RAR3$*1*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317").is_err());
        assert!(Rar3Hp::parse("$RAR3$*0*45109af8ab5f297*adbf6c5385d7a40373e8f77d7b89d317").is_err());
        assert!(Rar3Hp::parse("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d31").is_err());
        assert!(Rar3Hp::parse("$RAR3$*0*45109af8ab5f297g*adbf6c5385d7a40373e8f77d7b89d317").is_err());
        assert!(Rar3Hp::parse("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317*extra").is_err());
        // RAR5: wrong fixed fields, bad hex, out-of-range or malformed
        // exponents (module rejects 0 and >31; CPU policy caps at 24).
        assert!(Rar5::parse("$rar5$15$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$3846636100101101518134436068130$15$00000000000000000000000000000000$8$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$7$00000000000000000000000000000000$8$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$150$00000000000000000000000000000000$8$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$00$00000000000000000000000000000000$8$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$32$00000000000000000000000000000000$8$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$25$00000000000000000000000000000000$8$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$16$cc7a30583e62676a").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e6267").is_err());
        assert!(Rar5::parse("$rar5$16$38466361001011015181344360681307$15$0000000000000000000000000000000g$8$cc7a30583e62676a").is_err());
    }
}

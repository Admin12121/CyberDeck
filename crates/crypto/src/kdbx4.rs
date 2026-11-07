//! KeePass KDBX v4 recovery verifiers (format batch os-and-apps). Wire
//! formats and check semantics mirror the pinned upstream hashcat modules
//! 34300 (Argon2 KDF) and 34301 (AES-KDF), cross-checked against the
//! m34300/m34301 pure kernels and the upstream tools/test_modules/m34300.py
//! / m34301.py generators. The already-bundled KeePass sibling 13400 covers
//! KDBX v2/v3 only; this file handles the `$keepass$*4*` container. Every
//! verifier runs on the CPU in bounded time so a GPU match can always be
//! re-proven independently before it is reported.
//!
//! Algorithm (m34300-pure.cl:9-14, m34301-pure.cl:9-15):
//!   1. composite = SHA256(SHA256(password) . keyfile) — the keyfile bytes
//!      (32, carried hex on the wire) are appended raw; without a keyfile
//!      the composite is SHA256(SHA256(password)).
//!   2. derived =
//!        - 34300: Argon2(composite, salt = transform seed, t = iterations,
//!          m = memoryUsageInBytes / 1024 KiB, p = parallelism), variant and
//!          version (16/19) taken from the wire; or
//!        - 34301: both 16-byte halves of the composite AES-256-ECB
//!          encrypted `iterations` times under the transform seed, then
//!          SHA256 over the concatenated halves.
//!   3. final = SHA512(master seed . derived . 0x01)
//!   4. hmac key = SHA512(0xFF x 8 . final)
//!   5. header_hmac = HMAC-SHA256(hmac key, header) — the wire digest.
//!
//! The KDF is selected by the UUID field: ef636ddf = Argon2d, 9e298b19 =
//! Argon2id, c9d9f39a = AES-KDF. Frontend algorithm name: "keepass-kdbx4"
//! (GPU mode chosen by the parsed UUID, 34300 or 34301, like zip-legacy).
//! This file is self-contained on purpose: it compiles both inside
//! cyberdeck-crypto and standalone in the authoring test crate.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use hmac::Mac;
use sha2::{Digest, Sha256, Sha512};

/// Argon2d KDF UUID (module_34300.c:78).
pub const KDF_UUID_ARGON2D: &str = "ef636ddf";
/// Argon2id KDF UUID (module_34300.c:79).
pub const KDF_UUID_ARGON2ID: &str = "9e298b19";
/// AES-KDF UUID (module_34301.c).
pub const KDF_UUID_AESKDF: &str = "c9d9f39a";
/// Hashcat modes for the two KDFs.
pub const GPU_MODE_ARGON2: u32 = 34300;
pub const GPU_MODE_AESKDF: u32 = 34301;

/// CPU recovery policy caps (the wire allows far more; the GPU kernel is the
/// fast path and these bounds only gate the CPU re-proof).
const MAX_MEMORY_KIB: u32 = 1 << 20; // 1 GiB
const MAX_ARGON2_ITERATIONS: u32 = 4096;
const MAX_AESKDF_ROUNDS: u64 = 50_000_000;
/// Upstream module caps parallelism at 1..=32 (module_34300.c:312).
const MAX_PARALLELISM: u32 = 32;
/// The 34300 tokenizer demands exactly 506 hex characters (253 bytes) of
/// header; 34301 accepts 400..=512 (200..=256 bytes).
const ARGON2_HEADER_BYTES: usize = 253;
const AESKDF_HEADER_MIN: usize = 200;
const AESKDF_HEADER_MAX: usize = 256;

/// The KDF carried by the parsed container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdbx4Kdf {
    Argon2d,
    Argon2id,
    Aeskdf,
}

/// Parsed `$keepass$*4*` container header (hashcat modes 34300/34301).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kdbx4 {
    pub kdf: Kdbx4Kdf,
    /// Argon2 version on the wire (16 or 19); 0 for AES-KDF.
    pub version: u16,
    /// Argon2 passes or AES-KDF rounds.
    pub iterations: u32,
    /// Argon2 memory in KiB (wire carries bytes); 0 for AES-KDF.
    pub memory_kib: u32,
    /// Argon2 parallelism; 0 for AES-KDF.
    pub parallelism: u32,
    /// 32-byte master seed (wire field 7).
    pub master_seed: [u8; 32],
    /// 32-byte transform seed (wire field 8); the Argon2 salt or the AES-KDF
    /// ECB key.
    pub transform_seed: [u8; 32],
    /// The serialized database header the digest is computed over.
    pub header: Vec<u8>,
    /// The expected HMAC-SHA256 over the header (wire field 10).
    pub header_hmac: [u8; 32],
    /// Optional 32-byte keyfile content (wire fields 11-13).
    pub keyfile: Option<[u8; 32]>,
}

impl Kdbx4 {
    /// True for `$keepass$` lines that carry the KDBX v4 marker; the v2/v3
    /// sibling verifier (crates/crypto/src/wallets.rs) owns every other
    /// `$keepass$` shape.
    pub fn is_kdbx4_line(hash: &str) -> bool {
        hash.starts_with("$keepass$*4*")
    }

    /// Hashcat mode this hash runs as: 34300 (Argon2) or 34301 (AES-KDF).
    pub fn gpu_mode(&self) -> u32 {
        match self.kdf {
            Kdbx4Kdf::Aeskdf => GPU_MODE_AESKDF,
            _ => GPU_MODE_ARGON2,
        }
    }

    pub fn parse(hash: &str) -> Result<Self, String> {
        let parts: Vec<&str> = hash.split('*').collect();
        // The upstream tokenizer accepts 11 fields, or 14 with the keyfile
        // triple `1` / `64` / 64-hex (module_34300.c:117-203).
        if parts.len() != 11 && parts.len() != 14 {
            return Err("keepass KDBX4 hash must have 11 or 14 fields".into());
        }
        if parts[0] != "$keepass$" {
            return Err("not a $keepass$ hash".into());
        }
        if parts[1] != "4" {
            return Err("keepass KDBX4 requires database version 4".into());
        }
        let iterations: u32 = parts[2]
            .parse()
            .map_err(|_| "invalid keepass iteration count")?;
        let kdf = match parts[3] {
            KDF_UUID_ARGON2D => Kdbx4Kdf::Argon2d,
            KDF_UUID_ARGON2ID => Kdbx4Kdf::Argon2id,
            KDF_UUID_AESKDF => Kdbx4Kdf::Aeskdf,
            other => {
                return Err(format!("unsupported keepass KDF UUID: {other}"));
            }
        };
        let memory_wire: u64 = parts[4]
            .parse()
            .map_err(|_| "invalid keepass memory usage")?;
        let version: u16 = parts[5].parse().map_err(|_| "invalid keepass version")?;
        let parallelism: u32 = parts[6]
            .parse()
            .map_err(|_| "invalid keepass parallelism")?;
        // The upstream AES-KDF module requires the Argon2 fields to be zero
        // on the wire (module_34301.c:216-232).
        match kdf {
            Kdbx4Kdf::Aeskdf => {
                if memory_wire != 0 || version != 0 || parallelism != 0 {
                    return Err("keepass AES-KDF requires zero memory, version and parallelism".into());
                }
                if iterations as u64 > MAX_AESKDF_ROUNDS {
                    return Err("keepass AES-KDF rounds exceed the recovery policy".into());
                }
            }
            _ => {
                if version != 16 && version != 19 {
                    return Err("keepass Argon2 version must be 16 or 19".into());
                }
                if memory_wire < 1024 || memory_wire % 1024 != 0 {
                    return Err("keepass memory usage must be a multiple of 1024 bytes".into());
                }
                let memory_kib = (memory_wire / 1024) as u32; // module_34300.c:235
                if memory_kib > MAX_MEMORY_KIB {
                    return Err("keepass memory usage exceeds the recovery policy".into());
                }
                if iterations < 1 || iterations > MAX_ARGON2_ITERATIONS {
                    return Err("keepass Argon2 iterations exceed the recovery policy".into());
                }
                if parallelism < 1 || parallelism > MAX_PARALLELISM {
                    return Err("keepass parallelism must be 1..=32".into());
                }
            }
        }
        if !hex_len_ok(parts[7], 64) {
            return Err("keepass master seed must be 64 hex characters".into());
        }
        if !hex_len_ok(parts[8], 64) {
            return Err("keepass transform seed must be 64 hex characters".into());
        }
        let master_seed = decode32(parts[7], "master seed")?;
        let transform_seed = decode32(parts[8], "transform seed")?;
        let header_len = match kdf {
            Kdbx4Kdf::Aeskdf => AESKDF_HEADER_MIN..=AESKDF_HEADER_MAX,
            _ => ARGON2_HEADER_BYTES..=ARGON2_HEADER_BYTES,
        };
        if parts[9].len() % 2 != 0
            || !parts[9].bytes().all(|b| b.is_ascii_hexdigit())
            || !header_len.contains(&(parts[9].len() / 2))
        {
            return Err("keepass header length does not match its KDF".into());
        }
        let header = hex::decode(parts[9]).map_err(|_| "invalid keepass header")?;
        if !hex_len_ok(parts[10], 64) {
            return Err("keepass header hmac must be 64 hex characters".into());
        }
        let header_hmac = decode32(parts[10], "header hmac")?;
        let keyfile = match parts.len() {
            11 => None,
            _ => {
                if parts[11] != "1" || parts[12] != "64" {
                    return Err("keepass keyfile marker must be 1 with 64 characters".into());
                }
                if !hex_len_ok(parts[13], 64) {
                    return Err("keepass keyfile must be 64 hex characters".into());
                }
                Some(decode32(parts[13], "keyfile")?)
            }
        };
        Ok(Self {
            kdf,
            version,
            iterations,
            memory_kib: match kdf {
                Kdbx4Kdf::Aeskdf => 0,
                _ => (memory_wire / 1024) as u32,
            },
            parallelism,
            master_seed,
            transform_seed,
            header,
            header_hmac,
            keyfile,
        })
    }

    /// Full upstream check: composite key, KDF transform, then the
    /// HMAC-SHA256 over the header under SHA512(0xFF*8 . SHA512(seed .
    /// derived . 0x01)).
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut composite_input = Sha256::digest(candidate.as_bytes()).to_vec();
        if let Some(keyfile) = &self.keyfile {
            composite_input.extend_from_slice(keyfile);
        }
        let composite: [u8; 32] = Sha256::digest(&composite_input).into();
        let derived = match self.kdf {
            Kdbx4Kdf::Aeskdf => self.aeskdf_derive(&composite)?,
            _ => self.argon2_derive(&composite)?,
        };
        let mut final_input = Vec::with_capacity(32 + 32 + 1);
        final_input.extend_from_slice(&self.master_seed);
        final_input.extend_from_slice(&derived);
        final_input.push(0x01);
        let final_hash: [u8; 64] = Sha512::digest(&final_input).into();
        let mut hmac_input = Vec::with_capacity(8 + 64);
        hmac_input.extend_from_slice(&[0xFFu8; 8]);
        hmac_input.extend_from_slice(&final_hash);
        let hmac_key: [u8; 64] = Sha512::digest(&hmac_input).into();
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
            .map_err(|_| "keepass HMAC key error")?;
        mac.update(&self.header);
        let tag = mac.finalize().into_bytes();
        Ok(constant_time_eq(&tag, &self.header_hmac))
    }

    fn argon2_derive(&self, composite: &[u8; 32]) -> Result<[u8; 32], String> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let algorithm = match self.kdf {
            Kdbx4Kdf::Argon2d => Algorithm::Argon2d,
            _ => Algorithm::Argon2id,
        };
        let version = if self.version == 16 { Version::V0x10 } else { Version::V0x13 };
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|error| format!("invalid keepass Argon2 parameters: {error}"))?;
        let context = Argon2::new(algorithm, version, params);
        let mut derived = [0u8; 32];
        context
            .hash_password_into(composite, &self.transform_seed, &mut derived)
            .map_err(|error| format!("keepass Argon2 derivation failed: {error}"))?;
        Ok(derived)
    }

    fn aeskdf_derive(&self, composite: &[u8; 32]) -> Result<[u8; 32], String> {
        let cipher = aes::Aes256::new_from_slice(&self.transform_seed)
            .map_err(|_| "invalid keepass transform seed")?;
        let mut left = *GenericArray::from_slice(&composite[..16]);
        let mut right = *GenericArray::from_slice(&composite[16..]);
        for _ in 0..self.iterations {
            cipher.encrypt_block(&mut left);
            cipher.encrypt_block(&mut right);
        }
        let mut both = Vec::with_capacity(32);
        both.extend_from_slice(&left);
        both.extend_from_slice(&right);
        let derived: [u8; 32] = Sha256::digest(&both).into();
        Ok(derived)
    }
}

fn hex_len_ok(text: &str, expected: usize) -> bool {
    text.len() == expected && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode32(text: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|_| format!("invalid keepass {field}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream hashcat example hash for mode 34300 (module_34300.c
    // ST_HASH/ST_PASS, pass "hashcat"; the module comment credits the
    // upstream fixture tools/2hashcat_tests/keepass/
    // keepass4_keepass.info_2.59_argon2d_defaultsettings.hash). Argon2d,
    // version 19, t=2, m=64 MiB, p=2, no keyfile.
    const ST_34300: &str = "$keepass$*4*2*ef636ddf*67108864*19*2*e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb*af527945ec56bbb37f84ef85093735b689139f46c8003f82cad269837eb69d5f*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb0b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c040100000056040000001300000005010000004908000000020000000000000005010000004d080000000000000400000000040100000050040000000200000042010000005320000000af527945ec56bbb37f84ef85093735b689139f46c8003f82cad269837eb69d5f000710000000257fccc1e57ecdea03bbc06aab7cd13200040000000d0a0d0a*63249b86a7539e2bbdbf0ac7f196d460e781e221d1c580d4c718dcc1493eefa9";
    // Upstream hashcat example hash for mode 34301 (module_34301.c
    // ST_HASH/ST_PASS, pass "hashcat"; credited to hashcat issue 4455).
    // AES-KDF, 600000 rounds, no keyfile.
    const ST_34301: &str = "$keepass$*4*600000*c9d9f39a*0*0*0*824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d630*871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d628*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d6300b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea05010000005208000000c02709000000000042010000005320000000871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d6280007100000004131c9acd9c70ac00790dc17059c1b1f00040000000d0a0d0a*6f9ccf175ddd593a654a53fd3ec50f8559fc0abb4acf03b4f2a74353058afb39";
    // Cross vectors generated during authoring with implementations
    // independent of this crate:
    //   - AES-KDF and the composite/HMAC chain: Node crypto (sha256/sha512/
    //     hmac/aes-256-ecb).
    //   - Argon2: OpenSSL 3.5 `openssl kdf` ARGON2D/ARGON2ID, itself
    //     validated against the RFC 9106 Argon2id test vector
    //     (0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659)
    //     before use.
    const NODE_AESKDF_A: &str = "$keepass$*4*60001*c9d9f39a*0*0*0*ed15566ab9afa5901671116bb30959f0d127dd04a68400d93f8a7670839926ca*ac07cc662c104e5fa9c2d85533854108222d623fa3770b96b40b0db1996cd496*df19fbcb900092ca836a6fa79296a0107c5d32869544ce36aa7a21b38cfb81c1be0839340e7c3dfb7b469fc9f368c8f882b561ec359a01b62a52430eb4e550871be4a62d7028d3af4f35e893bdcb094f0c32e6a08c0823e52230b854e6cc17563b9ae6073d374512e739a2e8bbcd44f43248bcffe3646f1a2514f452e9d9b74c1aa03568d3766ab606894bc6a0e25f4a0e1601e383cd97c9e8f1088520216529048e71b898bf0ef9b5c882c866cfc813dd8bd6384c9bf4793887ed9ddc96f91f2aba7b8560da6c6e*bbfecfad877662435a913f750a7e5546fe966e661b91ea55b93e1c4761c68f5d";
    const NODE_AESKDF_B: &str = "$keepass$*4*123456*c9d9f39a*0*0*0*519e192b91254c3e5a564c0b15623fbac3fd20f2dad59faa10e3fc1c68cf285f*5e76363d93ff07cfb006f3bc9609b8b3de1dac0c0c11845e097b3ee6f72d4d54*cc7f6955a3f0ddde102aa9fb218b6f71569201e7cf9ed989a8c50a9678efc3cf14c4accb2d6c59e20360a16532d817518fdc8d955b450a8c87995f7f2a64fefea0be58fb3aad306edc9589578adb40926c46d219cd12c88ebdbb772f2796474c7b69d651572b2176f3d1176eb79b18a1bb78e07a9cfd2ce25c968b42a2f521e78e4a4be3e02740501a239661345f831a9b23945c918a5286960cd1023160abb6aec0f9ed99f303d2dd04e1e46cc84bfeaa7251df76a09c3b9fb510c04f7ab00170df7d19b2c7575f1286d3bc05a701*bd80def84cc97ba343a775879002868ab0f905db8d2fd2f84ecc36faaa193bb7*1*64*e7ec8ddaea14102e857b1dc754c684da271dae1a87e6783824eecbcf4be14c8b";
    const OPENSSL_ARGON2ID: &str = "$keepass$*4*2*9e298b19*262144*19*2*8fc2b413edba278375842b21bd0949130c77d01ebe5efee01f41cb61ad10edf6*8f896e7fda93c34cbc682612af42b03e3a9144b53c4a1eec3f1df1d3d409a4d8*6ef1ee1c94f80cf64b4d465041c35c15c76110ae11df287b9a62ed94c7eb59df826099b581e459d258dcbef27a7c172c272524cedf25994aa351050b893608003ad665feaa674743f3c9191e016908e4f21ba4cb4282a8780e7c416d50abba8a6d1a0f64ef6b4e71b5e96739196e640ace0ea071dd08d121cdb3d582dd179dc3c4ce959e6db67d52fedeea951891778da6d6a0a5b904cfce21112ba8790f42c2da37491767dfaaf030f2cdbf9a07f9f1cf16ef6f6f347317760ce4a926c834be8f011cfa182b19b3cebb0c47388e729542325233f242b80231d84394d625de38c057cd02706eb733f0c6f285df36f2dcfb8b184951f1ac8be5c9883792*02dd74f8a704edfcf716554d8a1a09eff835399581150afbd4064dc3cf879597";
    const OPENSSL_ARGON2D_V16: &str = "$keepass$*4*1*ef636ddf*65536*16*1*9f81bdda99b5cdb59c04a55be64a5ba6ca863f0d5ee27f32f3ff59ee7d6ef892*141ed2005db6ec474bd7fdeb2cdeb9eeea98480ecd0dc6c84cfb543243aea17f*1c3be0aa3fc7c27841a10bbfe3b11a85600aba599c46145aad178eeaf02a0ee9737d64f769479547bb5e3b5476da6e6cf4794ce3b5ce689ccbe8bd48338de8a8428cc883bb711c3713936c0fb876835e51130d7deb15e3910a252170ebbe773ff622376196c47972074b6c1eec5ac5f53d0b82b11d9cf62f34ccec4240f0d88c064b02506ef3faeb243ba9ccffc288c40750b4f6564ea14445dc56cd2ad005d1d7ff97e31469c2a6638d4eb4e81af37994afbb4fa37df3ab3ccbaf671308cea0dcbd4d145c94306220cb9dde7d4dd4c3a360aa653098c509076a6bf7810542e82386cf17d29c3361e7e850de2067b3e5f6fbb7e2438e371acbfb520d9e*8838ac2f95a99368949f36bf454b43ebe62e2041a6ce74f46238867f8bf277cd";
    const OPENSSL_ARGON2ID_KEYFILE: &str = "$keepass$*4*1*9e298b19*131072*19*1*97f6e7049a1a44c571eee95fba76d0d2eef80b5b53ebd1e5776bd1ae5996d34e*599ab092c7110dd2adaa4ae451ab28fcba25683ba798893cc884d1e9c82d88c5*b29a43cf269dac86def7b548e503668130fb88ee6b8880e138542ecfeeb88cfdcb34153ec77b3666cceff75f7daa1bc11d04464149c553d865e2e5f06e0a2c09964265fbca467c0e9cd5a9da9a2a13382f2b28fd46c5045af308e908a57e9285c0f63c3eb3e1c3c66adcaca7c7edca4a0cda65af48436ebfbce2427a79b39fb1d90c2b5cbe5b1eca2bfcfcbc2c86b6ce2b7e7bfa62348e5e401e1db36f1eddd4134e686e9d10aa456f58f77ccb032f7d5058bf52772e491832d9105af1bd5408eeaa02ef61e72fb9a7397618df39613c8e573807ebbf66f85ff92aaf40de11442c1f2b05e4438c3c7202ed457e75d88946e64a4e0c23190d6fe8166054*0cc5083f96182dcc86f0aa65127820647cfd2bdc3bc1fb077781832457a5fd4d*1*64*fff878b9f981c09d1d455dbc93463c297ffb7a42670d1013bc44db0199c36879";

    #[test]
    fn upstream_argon2_example_vector_verifies() {
        let parsed = Kdbx4::parse(ST_34300).unwrap();
        assert_eq!(parsed.gpu_mode(), 34300);
        assert_eq!(parsed.kdf, Kdbx4Kdf::Argon2d);
        assert_eq!(parsed.iterations, 2);
        assert_eq!(parsed.memory_kib, 65536);
        assert_eq!(parsed.parallelism, 2);
        assert_eq!(parsed.version, 19);
        assert!(parsed.keyfile.is_none());
        assert_eq!(parsed.header.len(), 253);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_aeskdf_example_vector_verifies() {
        let parsed = Kdbx4::parse(ST_34301).unwrap();
        assert_eq!(parsed.gpu_mode(), 34301);
        assert_eq!(parsed.kdf, Kdbx4Kdf::Aeskdf);
        assert_eq!(parsed.iterations, 600000);
        assert!(parsed.keyfile.is_none());
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn node_crypto_aeskdf_cross_vectors_verify() {
        // Without and with a keyfile; the keyfile bytes enter the composite
        // raw (SHA256(SHA256(password) . keyfile), m34301-pure.cl:76-89).
        let parsed = Kdbx4::parse(NODE_AESKDF_A).unwrap();
        assert!(parsed.verify("keepass4-aeskdf-pw").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        let parsed = Kdbx4::parse(NODE_AESKDF_B).unwrap();
        assert_eq!(parsed.keyfile.is_some(), true);
        assert!(parsed.verify("keepass4-aeskdf-pw2").unwrap());
        assert!(!parsed.verify("keepass4-aeskdf-pw").unwrap());
        // The same line without the keyfile triple must not verify: the
        // keyfile changes the composite key.
        let bare = Kdbx4::parse(&NODE_AESKDF_B.replace("*1*64*e7ec8ddaea14102e857b1dc754c684da271dae1a87e6783824eecbcf4be14c8b", "")).unwrap();
        assert!(bare.keyfile.is_none());
        assert!(!bare.verify("keepass4-aeskdf-pw2").unwrap());
    }

    #[test]
    fn openssl_argon2_cross_vectors_verify() {
        // Argon2id v19 (t=2, m=256 KiB, p=2) and Argon2d version 16.
        let parsed = Kdbx4::parse(OPENSSL_ARGON2ID).unwrap();
        assert_eq!(parsed.kdf, Kdbx4Kdf::Argon2id);
        assert!(parsed.verify("keepass4-argon2id-pw").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        let parsed = Kdbx4::parse(OPENSSL_ARGON2D_V16).unwrap();
        assert_eq!(parsed.kdf, Kdbx4Kdf::Argon2d);
        assert_eq!(parsed.version, 16);
        assert!(parsed.verify("keepass4-v16-pw").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        // Argon2id with a keyfile: exercises the composite keyfile path.
        let parsed = Kdbx4::parse(OPENSSL_ARGON2ID_KEYFILE).unwrap();
        assert_eq!(parsed.keyfile.is_some(), true);
        assert!(parsed.verify("keepass4-kf-pw").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn parse_rejects_out_of_policy_shapes() {
        assert!(Kdbx4::parse("").is_err());
        assert!(Kdbx4::parse("$keepass$*2*24569*0*seed*seed*header*hmac").is_err());
        // KDBX v2/v3 lines belong to the sibling verifier.
        assert!(!Kdbx4::is_kdbx4_line("$keepass$*2*24569*0*a*b*c*d"));
        assert!(Kdbx4::is_kdbx4_line(ST_34300));
        // Unknown KDF UUID.
        assert!(Kdbx4::parse("$keepass$*4*2*00000000*67108864*19*2*e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb*af527945ec56bbb37f84ef85093735b689139f46c8003f82cad269837eb69d5f*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000e4e48422ecb07da38401597150a7326fdd1519007b28c306c6e7418fb8ed29cb*hmac000000000000000000000000000000000000000000000000000000000000").is_err());
        // Argon2 policy: version, memory multiple, iteration and lane bounds.
        let bad_version = ST_34300.replace("*19*2*", "*20*2*");
        assert!(Kdbx4::parse(&bad_version).is_err());
        let bad_memory = ST_34300.replace("*67108864*", "*67108863*");
        assert!(Kdbx4::parse(&bad_memory).is_err());
        let big_memory = ST_34300.replace("*67108864*", &format!("*{}", 2048u64 * 1024 * 1024));
        assert!(Kdbx4::parse(&big_memory).is_err());
        let big_lanes = ST_34300.replace("*19*2*", "*19*33*");
        assert!(Kdbx4::parse(&big_lanes).is_err());
        // AES-KDF requires zeroed Argon2 fields and bounded rounds.
        let dirty_aeskdf = ST_34301.replace("*0*0*0*", "*8*0*0*");
        assert!(Kdbx4::parse(&dirty_aeskdf).is_err());
        let many_rounds = ST_34301.replace("*600000*", "*50000001*");
        assert!(Kdbx4::parse(&many_rounds).is_err());
        // Seed, header and digest field shapes.
        let short_seed = ST_34301.replace(
            "*871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d628*",
            "*871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d6*",
        );
        assert!(Kdbx4::parse(&short_seed).is_err());
        let truncated_header = ST_34301.replace("*03d9a29a", "*03d9a29"); // odd hex length
        assert!(Kdbx4::parse(&truncated_header).is_err());
        let missing_digest = ST_34301.replace("*6f9ccf175ddd593a654a53fd3ec50f8559fc0abb4acf03b4f2a74353058afb39", "");
        assert!(Kdbx4::parse(&missing_digest).is_err());
        // Keyfile marker must be exactly `1` / `64` / 64 hex.
        let bad_marker = format!("{ST_34301}*2*64*{}", "0".repeat(64));
        assert!(Kdbx4::parse(&bad_marker).is_err());
        let bad_len = format!("{ST_34301}*1*63*{}", "0".repeat(64));
        assert!(Kdbx4::parse(&bad_len).is_err());
        let short_keyfile = format!("{ST_34301}*1*64*{}", "0".repeat(63));
        assert!(Kdbx4::parse(&short_keyfile).is_err());
    }
}

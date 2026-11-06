//! Wallet container recovery verifiers (format batch B3). Wire formats and
//! check semantics mirror the pinned upstream modules 11300 (Bitcoin/Litecoin
//! wallet.dat), 13400 (KeePass KDBX v2/v3), 15600 (Ethereum PBKDF2) and
//! 15700 (Ethereum scrypt). Every verifier runs on the CPU in bounded time
//! so a GPU match can always be re-proven independently before it is
//! reported. Only public upstream example vectors are used as fixtures.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use sha2::Digest;

use crate::documents::{aes_decrypt_block, constant_time_eq};

fn sha512(data: &[u8]) -> [u8; 64] {
    sha2::Sha512::digest(data).into()
}

fn hex_field(text: &str, name: &str) -> Result<Vec<u8>, String> {
    if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid wallet hash {name} field"));
    }
    hex::decode(text).map_err(|_| format!("invalid wallet hash {name} field"))
}

fn digit_field(text: &str, name: &str) -> Result<u64, String> {
    if text.is_empty() || text.len() > 6 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid wallet hash {name} field"));
    }
    text.parse::<u64>()
        .map_err(|_| format!("invalid wallet hash {name} field"))
}

// ------------------------------------------------- Bitcoin/Litecoin wallet.dat

/// Parsed `$bitcoin$` mkey record (hashcat mode 11300).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinWallet {
    pub encrypted_master_key: Vec<u8>,
    pub salt: Vec<u8>,
    /// Total SHA-512 invocations (the wire's rounds field, not an offset).
    pub rounds: u64,
}

impl BitcoinWallet {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$bitcoin$")
            .ok_or("not a $bitcoin$ wallet hash")?;
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 9 {
            return Err("bitcoin wallet hash must have 9 fields".into());
        }
        let master_len: usize = digit_field(parts[0], "encrypted master key length")? as usize;
        if parts[0].len() > 3 {
            return Err("invalid wallet hash encrypted master key length field".into());
        }
        if parts[1].len() != master_len {
            return Err("bitcoin encrypted master key length mismatch".into());
        }
        let master = hex_field(parts[1], "encrypted master key")?;
        if master.len() < 32 || master.len() % 16 != 0 {
            return Err("bitcoin encrypted master key length mismatch".into());
        }
        if parts[2].len() != 2 {
            return Err("invalid wallet hash salt length field".into());
        }
        let salt_len: usize = digit_field(parts[2], "salt length")? as usize;
        if parts[3].len() != salt_len || !matches!(salt_len, 16 | 36) {
            return Err("bitcoin wallet salt must be 16 or 36 hex characters".into());
        }
        let salt = hex_field(parts[3], "salt")?;
        let rounds = digit_field(parts[4], "rounds")?;
        if rounds == 0 {
            return Err("bitcoin wallet rounds must be positive".into());
        }
        let ckey_len: usize = digit_field(parts[5], "ckey length")? as usize;
        if parts[6].len() != ckey_len {
            return Err("bitcoin wallet ckey length mismatch".into());
        }
        let _ckey = hex_field(parts[6], "ckey")?;
        let public_key_len: usize = digit_field(parts[7], "public key length")? as usize;
        if parts[8].len() != public_key_len {
            return Err("bitcoin wallet public key length mismatch".into());
        }
        let _public_key = hex_field(parts[8], "public key")?;
        Ok(Self { encrypted_master_key: master, salt, rounds })
    }

    /// H = SHA512(pass || salt) iterated to the wire's total round count;
    /// the AES-256 key is the first 32 digest bytes and the check decrypts
    /// only the LAST mkey block against the second-to-last block as the CBC
    /// chain value: standard wallets must yield a full 0x10 pad block, the
    /// Nexus legacy branch only its last 8 bytes of 0x08.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut digest = sha512(&[candidate.as_bytes(), self.salt.as_slice()].concat());
        for _ in 1..self.rounds {
            digest = sha512(&digest);
        }
        let key = &digest[..32];
        let master = &self.encrypted_master_key;
        let chain = &master[master.len() - 32..master.len() - 16];
        let block = &master[master.len() - 16..];
        let mut state = *GenericArray::from_slice(block);
        match key.len() {
            32 => aes::Aes256::new_from_slice(key)
                .map_err(|_| "invalid AES key")?
                .decrypt_block(&mut state),
            _ => return Err("unsupported AES key length".into()),
        }
        let out: Vec<u8> = state.iter().zip(chain.iter()).map(|(d, c)| d ^ c).collect();
        if self.salt.len() == 18 {
            return Ok(out[8..].iter().all(|b| *b == 0x08));
        }
        Ok(constant_time_eq(&out, &[0x10u8; 16]))
    }
}


// ------------------------------------------------------------------- KeePass

/// Parsed `$keepass$` KDBX v2/v3 record (hashcat mode 13400). KeePass 1.x
/// (version 1) lines with the Twofish cipher (algorithm 1) are rejected as
/// not CPU-verifiable; the AES v1 path is out of batch scope like the
/// compressed 7-Zip headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeePass {
    pub version: u8,
    pub rounds: u64,
    pub final_random_seed: Vec<u8>,
    pub transform_seed: Vec<u8>,
    pub enc_iv: Vec<u8>,
    pub expected_bytes: Vec<u8>,
    pub contents_hash: Vec<u8>,
    pub keyfile: Option<Vec<u8>>,
}

const KEEPASS_MAX_ROUNDS: u64 = 20_000_000;

impl KeePass {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$keepass$")
            .ok_or("not a $keepass$ hash")?;
        // The wire is "$keepass$*f0*...*fn": one leading separator before
        // the version field.
        let rest = rest
            .strip_prefix('*')
            .ok_or("keepass hash is missing its leading separator")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() < 8 {
            return Err("keepass hash is missing fields".into());
        }
        if parts[0].len() != 1 {
            return Err("keepass version must be a single digit".into());
        }
        let version: u8 = parts[0].parse().map_err(|_| "invalid keepass version")?;
        if version != 1 && version != 2 {
            return Err("only KeePass KDBX v2/v3 (version 2) is supported".into());
        }
        let rounds: u64 = digit_field(parts[1], "rounds")?;
        if rounds == 0 || rounds > KEEPASS_MAX_ROUNDS {
            return Err("keepass rounds exceed the recovery policy".into());
        }
        if parts[2] == "1" {
            return Err(
                "Twofish KeePass entries are not CPU-verifiable and are not bundled".into(),
            );
        }
        let seed_len = if version == 2 { 32 } else { 16 };
        let final_random_seed = hex_field(parts[3], "final random seed")?;
        if final_random_seed.len() != seed_len {
            return Err("keepass final random seed length mismatch".into());
        }
        let transform_seed = hex_field(parts[4], "transform seed")?;
        if transform_seed.len() != 32 {
            return Err("keepass transform seed length mismatch".into());
        }
        let enc_iv = hex_field(parts[5], "encryption IV")?;
        if enc_iv.len() != 16 {
            return Err("keepass encryption IV length mismatch".into());
        }
        // Version 2 lines carry an expected_bytes field before the contents
        // hash; version 1 lines go straight to the contents hash.
        let expected_index = if version == 2 { 6 } else { 5 };
        let expected_bytes = if version == 2 {
            let value = hex_field(parts[expected_index], "expected bytes")?;
            if value.len() != 32 {
                return Err("keepass expected bytes length mismatch".into());
            }
            value
        } else {
            Vec::new()
        };
        let contents_index = expected_index + 1;
        let contents_hash = hex_field(parts[contents_index], "contents hash")?;
        if contents_hash.len() != 32 {
            return Err("keepass contents hash length mismatch".into());
        }
        // Keyfile presence is a positional suffix: *<flag>*<len>*<64 hex>.
        let keyfile = if parts.len() == contents_index + 4 && parts[contents_index + 2].len() == 2 {
            let key = hex_field(parts[contents_index + 3], "keyfile")?;
            if key.len() != 32 {
                return Err("keepass keyfile length mismatch".into());
            }
            Some(key)
        } else {
            if parts.len() != contents_index + 1 {
                return Err("keepass hash field count mismatch".into());
            }
            None
        };
        Ok(Self {
            version,
            rounds,
            final_random_seed,
            transform_seed,
            enc_iv,
            expected_bytes,
            contents_hash,
            keyfile,
        })
    }

    /// Composite key per the ST-verified paths, the AES-KDF transform over
    /// two ECB blocks per round, then a one-block AES-CBC check.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        use sha2::Digest as _;
        if self.version != 2 {
            return Err("keepass version 1 verification is not bundled".into());
        }
        let mut ih = sha2::Sha256::digest(candidate.as_bytes()).to_vec();
        match &self.keyfile {
            Some(keyfile) => {
                ih = sha2::Sha256::digest([ih.as_slice(), keyfile.as_slice()].concat()).to_vec();
            }
            None => {
                ih = sha2::Sha256::digest(&ih).to_vec();
            }
        }
        let cipher = aes::Aes256::new_from_slice(&self.transform_seed)
            .map_err(|_| "invalid transform seed")?;
        for _ in 0..self.rounds {
            for chunk in ih.chunks_exact_mut(16) {
                let mut block = *GenericArray::from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        let ih = sha2::Sha256::digest(&ih).to_vec();
        let final_key = sha2::Sha256::digest(
            [self.final_random_seed.as_slice(), ih.as_slice()].concat(),
        );
        let mut block = *GenericArray::from_slice(&self.contents_hash[..16]);
        aes::Aes256::new_from_slice(&final_key)
            .map_err(|_| "invalid final key")?
            .decrypt_block(&mut block);
        let out: Vec<u8> = block
            .iter()
            .zip(self.enc_iv.iter())
            .map(|(d, i)| d ^ i)
            .collect();
        Ok(constant_time_eq(&out, &self.expected_bytes[..16]))
    }
}

// ----------------------------------------------------------------- Ethereum

/// Parsed `$ethereum$p` PBKDF2-HMAC-SHA256 entry (hashcat mode 15600).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumPbkdf2 {
    pub iterations: u64,
    pub salt: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
}

const ETHEREUM_MAX_PBKDF2_ITERATIONS: u64 = 5_000_000;

impl EthereumPbkdf2 {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$ethereum$p*")
            .ok_or("not an $ethereum$p hash")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() != 4 {
            return Err("ethereum pbkdf2 hash must have 4 fields".into());
        }
        let iterations: u64 = digit_field(parts[0], "iteration count")?;
        if iterations == 0 || iterations > ETHEREUM_MAX_PBKDF2_ITERATIONS {
            return Err("ethereum pbkdf2 iterations exceed the recovery policy".into());
        }
        if !matches!(parts[1].len(), 32 | 64) {
            return Err("ethereum salt must be 32 or 64 hex characters".into());
        }
        let salt = hex_field(parts[1], "salt")?;
        if parts[2].len() != 64 || parts[3].len() != 64 {
            return Err("ethereum ciphertext and MAC must be 64 hex characters".into());
        }
        let ciphertext = hex_field(parts[2], "ciphertext")?;
        let mac = hex_field(parts[3], "MAC")?;
        Ok(Self { iterations, salt, ciphertext, mac })
    }

    /// DK = PBKDF2-HMAC-SHA256(pass, salt, c, 32); MAC = Keccak-256 over
    /// DK[16..32] and the ciphertext. The first DK half is unused here.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut derived = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            candidate.as_bytes(),
            &self.salt,
            self.iterations as u32,
            &mut derived,
        );
        Ok(constant_time_eq(&ethereum_mac(&derived, &self.ciphertext), &self.mac))
    }
}

/// Parsed `$ethereum$s` scrypt entry (hashcat mode 15700).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumScrypt {
    pub n: u64,
    pub r: u32,
    pub p: u32,
    pub salt: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
}

/// scrypt memory is 128 * N * r bytes; bounded like the native policy.
const ETHEREUM_MAX_SCRYPT_MEMORY: u64 = 1 << 30;

impl EthereumScrypt {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$ethereum$s*")
            .ok_or("not an $ethereum$s hash")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() != 6 {
            return Err("ethereum scrypt hash must have 6 fields".into());
        }
        let n: u64 = digit_field(parts[0], "scrypt N")?;
        let r: u32 = digit_field(parts[1], "scrypt r")? as u32;
        let p: u32 = digit_field(parts[2], "scrypt p")? as u32;
        if n % 1024 != 0 {
            return Err("ethereum scrypt N must be a multiple of 1024".into());
        }
        if p == 0 {
            return Err("ethereum scrypt p must be positive".into());
        }
        let memory = (n / 2)
            .checked_mul(r as u64)
            .and_then(|value| value.checked_mul(128))
            .ok_or("ethereum scrypt memory overflow")?;
        if memory > ETHEREUM_MAX_SCRYPT_MEMORY {
            return Err("ethereum scrypt memory cost exceeds the recovery policy".into());
        }
        if parts[3].len() != 64 || parts[4].len() != 64 || parts[5].len() != 64 {
            return Err("ethereum salt, ciphertext and MAC must be 64 hex characters".into());
        }
        let salt = hex_field(parts[3], "salt")?;
        let ciphertext = hex_field(parts[4], "ciphertext")?;
        let mac = hex_field(parts[5], "MAC")?;
        Ok(Self { n, r, p, salt, ciphertext, mac })
    }

    /// DK = scrypt(pass, salt, N, r, p, 32); MAC = Keccak-256 over
    /// DK[16..32] and the ciphertext.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let params = scrypt::Params::new(self.n.trailing_zeros() as u8, self.r, self.p, 32)
            .map_err(|_| "invalid ethereum scrypt parameters")?;
        let mut derived = [0u8; 32];
        scrypt::scrypt(candidate.as_bytes(), &self.salt, &params, &mut derived)
            .map_err(|_| "ethereum scrypt derivation failed")?;
        Ok(constant_time_eq(&ethereum_mac(&derived, &self.ciphertext), &self.mac))
    }
}

/// Keccak-256 (original 0x01 padding, not NIST SHA3) over DK[16..32] || ct.
fn ethereum_mac(derived: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    use sha3::digest::Digest as _;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&derived[16..32]);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream hashcat example hashes (module ST_HASH/ST_PASS, pass "hashcat").
    const BITCOIN_ST: &str = "$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$96$480008005625057442352316337722323437108374245623701184230273883222762730232857701607167815448714$66$014754433300175043011633205413774877455616682000536368706315333388";
    const KEEPASS_ST: &str = "$keepass$*2*24569*0*c40432355cce7348c48053ceea0a28e7d18859c4ea47e3a799c6300861f64b95*265dafcc42e1537ff42e97e1e283c70014133be0fe2d420b4d24c6d57c9d2207*a00e20a852694c15aabb074d61b902fa*48dd553fb96f7996635f2414bfe6a1a8429ef0ffb71a1752abbef31853172c35*a44ae659958ad7fae8c8952cb83f3cf03fec2371ce22a8bf7fac1e687af2f249*1*64*5a26ea376cc5afc955104c334571d30486acbac512a94b75ca82a9e31dd97bf7";
    const ETHEREUM_PBKDF2_ST: &str = "$ethereum$p*1024*38353131353831333338313138363430*a8b4dfe92687dbc0afeb5dae7863f18964241e96b264f09959903c8c924583fc*0a9252861d1e235994ce33dbca91c98231764d8ecb4950015a8ae20d6415b986";
    const ETHEREUM_SCRYPT_ST: &str = "$ethereum$s*262144*8*1*3134313837333434333838303231333633373433323633373534333136363537*73da7f80ec3bd4f2a128c3a815cfb4d576ecb1a9b47024c902e62ea926f7795b*910e0f8dc1f7ba41959e1089bb769f3e919109591913cc33ba03953d7a905efd";

    #[test]
    fn upstream_bitcoin_example_vector_verifies() {
        let parsed = BitcoinWallet::parse(BITCOIN_ST).unwrap();
        assert_eq!(parsed.rounds, 200460);
        assert_eq!(parsed.salt.len(), 8);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_keepass_example_vector_verifies() {
        let parsed = KeePass::parse(KEEPASS_ST).unwrap();
        assert_eq!(parsed.version, 2);
        assert!(parsed.keyfile.is_some(), "the ST exercises the keyfile path");
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("Hashcat").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_ethereum_pbkdf2_example_vector_verifies() {
        let parsed = EthereumPbkdf2::parse(ETHEREUM_PBKDF2_ST).unwrap();
        assert_eq!(parsed.iterations, 1024);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_ethereum_scrypt_example_vector_verifies() {
        let parsed = EthereumScrypt::parse(ETHEREUM_SCRYPT_ST).unwrap();
        assert_eq!(parsed.n, 262144);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn wallet_targets_self_detect_through_the_recovery_target_parse() {
        // The embedded Hashcat KAT gate parses each fixture with an empty
        // algorithm hint; the $-markers must select the right verifier.
        for (hash, negative) in [
            (BITCOIN_ST, "hashcau"),
            (KEEPASS_ST, "Hashcat"),
            (ETHEREUM_PBKDF2_ST, "hashcau"),
            (ETHEREUM_SCRYPT_ST, "hashcau"),
        ] {
            let target = crate::recovery::RecoveryTarget::parse("", hash).unwrap();
            assert!(target.is_match(b"hashcat").unwrap(), "{hash} positive");
            assert!(!target.is_match(negative.as_bytes()).unwrap(), "{hash} negative");
        }
    }

    #[test]
    fn wallet_parse_rejects_out_of_policy_shapes() {
        assert!(KeePass::parse("$keepass$*3*24569*0*00*00*00*00*00").is_err());
        assert!(EthereumPbkdf2::parse("$ethereum$p*0*00*00*00").is_err());
        assert!(EthereumScrypt::parse("$ethereum$s*1000*8*1*00*00*00").is_err());
        assert!(EthereumScrypt::parse("$ethereum$s*1000*8*0*00*00*00").is_err());
    }

    #[test]
    fn bitcoin_parse_rejects_out_of_policy_shapes() {
        assert!(BitcoinWallet::parse("$bitcoin$95$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$0$$0$").is_err());
        assert!(BitcoinWallet::parse("$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$80172140135431$200460$0$$0$").is_err());
        assert!(BitcoinWallet::parse("$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$0$0$$0$").is_err());
    }
}

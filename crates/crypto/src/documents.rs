//! Document container recovery verifiers (format batch B2). Wire formats and
//! check semantics mirror the pinned upstream modules 9700 (MS Office 97/2003
//! $oldoffice$0/$1), 9400 (Office 2007 Agile), 9600 (Office 2013 Agile),
//! 10400 (PDF 1.1-1.3, R2) and 10500 (PDF 1.4-1.6, R3/R4). Every verifier
//! runs on the CPU in bounded time so a GPU match can always be re-proven
//! independently before it is reported. Only public upstream example vectors
//! are used as fixtures.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use md5::Digest;

const OFFICE_2007_SPIN: u64 = 50_000;
const OFFICE_2013_SPIN: u64 = 100_000;
/// MS-OFFCRYPTO Agile block keys.
const VERIFIER_HASH_INPUT_BLOCK_KEY: [u8; 8] = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
const VERIFIER_HASH_VALUE_BLOCK_KEY: [u8; 8] = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];
/// PDF standard padding constant (spec 7.6.3).
const PDF_PADDING: [u8; 32] = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
];

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    sha1::Sha1::digest(data).into()
}

fn sha512(data: &[u8]) -> [u8; 64] {
    sha2::Sha512::digest(data).into()
}

/// RC4 stream cipher (used by Office <=2003, PDF R2-R4 and Kerberos etype 23).
pub(crate) fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + state[i] as usize + key[i % key.len()] as usize) & 0xff;
        state.swap(i, j);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    let mut j = 0usize;
    for byte in data {
        i = (i + 1) & 0xff;
        j = (j + state[i] as usize) & 0xff;
        state.swap(i, j);
        out.push(byte ^ state[(state[i] as usize + state[j] as usize) & 0xff]);
    }
    out
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn hex_field(text: &str, name: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid document hash {name} field"));
    }
    hex::decode(text).map_err(|_| format!("invalid document hash {name} field"))
}

fn parse_i32(text: &str, name: &str) -> Result<i32, String> {
    text.parse::<i32>()
        .map_err(|_| format!("invalid document hash {name} field"))
}

// ------------------------------------------------- MS Office 97/2003 ($oldoffice$)

/// Parsed `$oldoffice$0/$1` entry (hashcat mode 9700).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Office97 {
    pub version: u8,
    pub salt: Vec<u8>,
    pub encrypted_verifier: Vec<u8>,
    pub encrypted_verifier_hash: Vec<u8>,
}

impl Office97 {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$oldoffice$")
            .ok_or("not an $oldoffice$ hash")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() != 4 {
            return Err("oldoffice hash must have 4 fields".into());
        }
        let version: u8 = parts[0].parse().map_err(|_| "invalid oldoffice type")?;
        if version > 1 {
            return Err("oldoffice types 2..4 are SHA1-based and not bundled".into());
        }
        let salt = hex_field(parts[1], "salt")?;
        let encrypted_verifier = hex_field(parts[2], "encrypted verifier")?;
        let encrypted_verifier_hash = hex_field(parts[3], "encrypted verifier hash")?;
        if salt.len() != 16 || encrypted_verifier.len() != 16 || encrypted_verifier_hash.len() < 16 {
            return Err("oldoffice field length mismatch".into());
        }
        Ok(Self { version, salt, encrypted_verifier, encrypted_verifier_hash })
    }

    /// Key = MD5((MD5(utf16le(pass))[0..5] || salt) x16); the verifier is
    /// RC4-decrypted, MD5-hashed, and RC4-encrypted again with the continuing
    /// keystream for comparison against the encrypted verifier hash.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let digest5 = &md5(&utf16le(candidate))[..5];
        let mut block = Vec::with_capacity(21);
        block.extend_from_slice(digest5);
        block.extend_from_slice(&self.salt);
        let mut message = Vec::with_capacity(336);
        for _ in 0..16 {
            message.extend_from_slice(&block);
        }
        let h1 = md5(&message);
        let mut key_input = Vec::with_capacity(9);
        key_input.extend_from_slice(&h1[..5]);
        key_input.extend_from_slice(&[0u8; 4]);
        let key = md5(&key_input);
        let keystream = rc4(&key, &[0u8; 32]);
        let verifier: Vec<u8> = self
            .encrypted_verifier
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();
        let verifier_md5 = md5(&verifier);
        let check: Vec<u8> = verifier_md5
            .iter()
            .zip(keystream[16..32].iter())
            .map(|(m, k)| m ^ k)
            .collect();
        Ok(constant_time_eq(&check, &self.encrypted_verifier_hash[..16]))
    }
}

// ---------------------------------------------------- MS Office 2007 / 2013 (Agile)

/// Parsed `$office$*2007` Agile entry (hashcat mode 9400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Office2007 {
    pub key_size: u32,
    pub salt: Vec<u8>,
    pub encrypted_verifier: Vec<u8>,
    pub encrypted_verifier_hash: Vec<u8>,
}

impl Office2007 {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash.strip_prefix("$office$*").ok_or("not an $office$ hash")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() != 7 {
            return Err("office hash must have 7 fields".into());
        }
        if parts[0] != "2007" {
            return Err("only Office 2007 is handled by this format".into());
        }
        if parts[1] != "20" {
            return Err("office 2007 verifier hash size must be 20".into());
        }
        let key_size: u32 = parts[2].parse().map_err(|_| "invalid key size")?;
        if key_size != 128 && key_size != 256 {
            return Err("office key size must be 128 or 256".into());
        }
        if parts[3] != "16" {
            return Err("office salt size must be 16".into());
        }
        let salt = hex_field(parts[4], "salt")?;
        let encrypted_verifier = hex_field(parts[5], "encrypted verifier")?;
        let encrypted_verifier_hash = hex_field(parts[6], "encrypted verifier hash")?;
        if salt.len() != 16 || encrypted_verifier.len() != 16 || encrypted_verifier_hash.len() < 16 {
            return Err("office field length mismatch".into());
        }
        Ok(Self { key_size, salt, encrypted_verifier, encrypted_verifier_hash })
    }

    /// H = SHA1(salt || utf16le(pass)); spinCount x H = SHA1(LE32(i) || H);
    /// key = SHA1 of the 0x36/0x5c blocks over SHA1(H||0^4); the verifier
    /// round trip through AES-(128|256) must reproduce the encrypted
    /// verifier hash.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut h = sha1(&[self.salt.as_slice(), utf16le(candidate).as_slice()].concat());
        let mut counter = [0u8; 4];
        for i in 0..OFFICE_2007_SPIN {
            counter.copy_from_slice(&(i as u32).to_le_bytes());
            h = sha1(&[counter.as_slice(), h.as_slice()].concat());
        }
        let common = sha1(&[h.as_slice(), &[0u8; 4]].concat());
        let mut ipad = vec![0x36u8; 64];
        let mut opad = vec![0x5cu8; 64];
        for (index, byte) in common.iter().enumerate() {
            ipad[index] ^= byte;
            opad[index] ^= byte;
        }
        let key: Vec<u8> = match self.key_size {
            128 => sha1(&ipad)[..16].to_vec(),
            _ => {
                let mut merged = sha1(&ipad)[..16].to_vec();
                merged.extend_from_slice(&sha1(&opad)[..16]);
                merged
            }
        };
        let decrypted = aes_decrypt_block(&key, &self.encrypted_verifier)?;
        let hash = sha1(&decrypted);
        let reencrypted = aes_encrypt_block(&key, &hash[..16])?;
        Ok(constant_time_eq(&reencrypted, &self.encrypted_verifier_hash[..16]))
    }
}

/// Parsed `$office$*2013` Agile entry (hashcat mode 9600).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Office2013 {
    pub spin_count: u64,
    pub key_size: u32,
    pub salt: Vec<u8>,
    pub encrypted_verifier: Vec<u8>,
    pub encrypted_verifier_hash: Vec<u8>,
}

impl Office2013 {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash.strip_prefix("$office$*").ok_or("not an $office$ hash")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() != 7 {
            return Err("office hash must have 7 fields".into());
        }
        if parts[0] != "2013" {
            return Err("only Office 2013 is handled by this format".into());
        }
        let spin_count: u64 = parts[1].parse().map_err(|_| "invalid spin count")?;
        if spin_count != OFFICE_2013_SPIN {
            return Err("office 2013 spin count must be 100000".into());
        }
        let key_size: u32 = parts[2].parse().map_err(|_| "invalid key size")?;
        if key_size != 128 && key_size != 256 {
            return Err("office key size must be 128 or 256".into());
        }
        if parts[3] != "16" {
            return Err("office salt size must be 16".into());
        }
        let salt = hex_field(parts[4], "salt")?;
        let encrypted_verifier = hex_field(parts[5], "encrypted verifier")?;
        let encrypted_verifier_hash = hex_field(parts[6], "encrypted verifier hash")?;
        if salt.len() != 16 || encrypted_verifier.len() != 16 || encrypted_verifier_hash.len() < 16 {
            return Err("office field length mismatch".into());
        }
        Ok(Self { spin_count, key_size, salt, encrypted_verifier, encrypted_verifier_hash })
    }

    /// Agile encryption: H = SHA512(salt || utf16le(pass)), spinCount x
    /// H = SHA512(LE32(i) || H); encryption keys derived with the MS block
    /// keys; verifier = AES-CBC(SHA512(decrypted verifier)[0..16]) with the
    /// salt as IV must reproduce the encrypted verifier hash.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut h = sha512(&[self.salt.as_slice(), utf16le(candidate).as_slice()].concat());
        let mut counter = [0u8; 4];
        for i in 0..self.spin_count {
            counter.copy_from_slice(&(i as u32).to_le_bytes());
            h = sha512(&[counter.as_slice(), h.as_slice()].concat());
        }
        let key_input = [h.as_slice(), VERIFIER_HASH_INPUT_BLOCK_KEY.as_slice()].concat();
        let value_input = [h.as_slice(), VERIFIER_HASH_VALUE_BLOCK_KEY.as_slice()].concat();
        let hash_input_key = sha512(&key_input)[..self.key_size as usize / 8].to_vec();
        let hash_value_key = sha512(&value_input)[..self.key_size as usize / 8].to_vec();
        let verifier_input = aes_cbc_decrypt(&hash_input_key, &self.salt, &self.encrypted_verifier)?;
        let verifier_hash = sha512(&verifier_input);
        let encrypted = aes_cbc_encrypt(&hash_value_key, &self.salt, &verifier_hash[..16])?;
        Ok(constant_time_eq(&encrypted, &self.encrypted_verifier_hash[..16]))
    }
}

// -------------------------------------------------------------------- PDF

/// Parsed `$pdf$1*2*40*...` entry, PDF 1.1-1.3 revision 2 (hashcat 10400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfR2 {
    pub permissions: i32,
    pub id: Vec<u8>,
    pub u_value: Vec<u8>,
    pub o_value: Vec<u8>,
}

impl PdfR2 {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let parts = parse_pdf(hash)?;
        if parts.0 != 1 || parts.1 != 2 {
            return Err("only PDF revision 2 (V1/R2) is handled by this format".into());
        }
        if parts.2 != 40 {
            return Err("PDF revision 2 key length must be 40 bits".into());
        }
        Ok(Self { permissions: parts.3, id: parts.4, u_value: parts.5, o_value: parts.6 })
    }

    /// key = MD5((pass||PAD)[0..32] || O || LE32(P) || ID)[0..5];
    /// RC4(key, PAD) must reproduce the first 16 bytes of U.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let key = pdf_user_key(candidate, &self.o_value, self.permissions, &self.id, false)?;
        let check = rc4(&key[..5], &PDF_PADDING);
        Ok(constant_time_eq(&check[..16], &self.u_value[..16]))
    }
}

/// Parsed `$pdf$2*3|4*128*...` entry, PDF 1.4-1.6 revisions 3/4 (hashcat 10500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfR34 {
    pub revision: u32,
    pub permissions: i32,
    pub encrypted_metadata: bool,
    pub id: Vec<u8>,
    pub u_value: Vec<u8>,
    pub o_value: Vec<u8>,
}

impl PdfR34 {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let (version, revision, bits, permissions, id, u_value, o_value, encrypted_metadata) =
            parse_pdf(hash)?;
        if version != 2 && version != 4 {
            return Err("only PDF revisions 3/4 (V2/V4) are handled by this format".into());
        }
        if revision != 3 && revision != 4 {
            return Err("only PDF revisions 3/4 are handled by this format".into());
        }
        if bits != 128 {
            return Err("PDF revision 3/4 key length must be 128 bits".into());
        }
        Ok(Self { revision, permissions, encrypted_metadata, id, u_value, o_value })
    }

    /// key = 50 x MD5 over the full digest of ((pass||PAD)[0..32] || O ||
    /// LE32(P) || ID [|| LE32(-1) when R4 and metadata is unencrypted]);
    /// U[0..16] = RC4^19(key XOR x, RC4(key, MD5(PAD||ID))).
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let extra = self.revision >= 4 && !self.encrypted_metadata;
        let mut key = pdf_user_key(candidate, &self.o_value, self.permissions, &self.id, extra)?;
        for _ in 0..50 {
            key = md5(&key).to_vec();
        }
        let seed = md5(&[PDF_PADDING.as_slice(), self.id.as_slice()].concat());
        let mut value = rc4(&key, &seed);
        for x in 1u16..=19 {
            let layered: Vec<u8> = key.iter().map(|b| b ^ x as u8).collect();
            value = rc4(&layered, &value);
        }
        Ok(constant_time_eq(&value[..16], &self.u_value[..16]))
    }
}

fn parse_pdf(
    hash: &str,
) -> Result<(u32, u32, u32, i32, Vec<u8>, Vec<u8>, Vec<u8>, bool), String> {
    let rest = hash.strip_prefix("$pdf$").ok_or("not a $pdf$ hash")?;
    let parts: Vec<&str> = rest.split('*').collect();
    if parts.len() != 11 {
        return Err("pdf hash must have 11 fields".into());
    }
    let version = parts[0]
        .parse::<u32>()
        .map_err(|_| "invalid pdf version")?;
    let revision = parts[1].parse::<u32>().map_err(|_| "invalid pdf revision")?;
    let bits = parts[2].parse::<u32>().map_err(|_| "invalid pdf key length")?;
    let permissions = parse_i32(parts[3], "permissions")?;
    let encrypted_metadata = parse_i32(parts[4], "encrypted metadata")? == 1;
    let id_len: usize = parts[5].parse().map_err(|_| "invalid pdf id length")?;
    if id_len != 16 {
        return Err("pdf id length must be 16 bytes".into());
    }
    let id = hex_field(parts[6], "id")?;
    let u_len: usize = parts[7].parse().map_err(|_| "invalid pdf u length")?;
    if u_len != 32 {
        return Err("pdf u length must be 32 bytes".into());
    }
    let u_value = hex_field(parts[8], "u")?;
    let o_len: usize = parts[9].parse().map_err(|_| "invalid pdf o length")?;
    if o_len != 32 {
        return Err("pdf o length must be 32 bytes".into());
    }
    let o_value = hex_field(parts[10], "o")?;
    if id.len() != 16 || u_value.len() != 32 || o_value.len() != 32 {
        return Err("pdf field length mismatch".into());
    }
    Ok((version, revision, bits, permissions, id, u_value, o_value, encrypted_metadata))
}

fn pdf_user_key(
    candidate: &str,
    o_value: &[u8],
    permissions: i32,
    id: &[u8],
    extra: bool,
) -> Result<Vec<u8>, String> {
    let mut data = candidate.as_bytes().to_vec();
    data.truncate(32);
    let pad_len = 32 - data.len();
    data.extend_from_slice(&PDF_PADDING[..pad_len]);
    data.extend_from_slice(o_value);
    data.extend_from_slice(&permissions.to_le_bytes());
    data.extend_from_slice(&id[..16]);
    if extra {
        data.extend_from_slice(&(-1i32).to_le_bytes());
    }
    Ok(md5(&data).to_vec())
}

// ------------------------------------------------------------- AES helpers

pub(crate) fn aes_decrypt_block(key: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], String> {
    let mut block = *GenericArray::from_slice(&ciphertext[..16]);
    match key.len() {
        16 => aes::Aes128::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .decrypt_block(&mut block),
        24 => aes::Aes192::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .decrypt_block(&mut block),
        32 => aes::Aes256::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .decrypt_block(&mut block),
        _ => return Err("unsupported AES key length".into()),
    }
    Ok(block.into())
}

fn aes_encrypt_block(key: &[u8], plaintext: &[u8]) -> Result<[u8; 16], String> {
    let mut block = *GenericArray::from_slice(&plaintext[..16]);
    match key.len() {
        16 => aes::Aes128::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .encrypt_block(&mut block),
        24 => aes::Aes192::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .encrypt_block(&mut block),
        32 => aes::Aes256::new_from_slice(key)
            .map_err(|_| "invalid AES key")?
            .encrypt_block(&mut block),
        _ => return Err("unsupported AES key length".into()),
    }
    Ok(block.into())
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut previous: [u8; 16] = iv.try_into().map_err(|_| "invalid CBC IV")?;
    let mut plain = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.chunks_exact(16) {
        let decrypted = aes_decrypt_block(key, block)?;
        plain.extend(decrypted.iter().zip(previous.iter()).map(|(d, p)| d ^ p));
        previous.copy_from_slice(block);
    }
    Ok(plain)
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut previous: [u8; 16] = iv.try_into().map_err(|_| "invalid CBC IV")?;
    let mut cipher = Vec::with_capacity(plaintext.len());
    for block in plaintext.chunks_exact(16) {
        let input: Vec<u8> = block.iter().zip(previous.iter()).map(|(p, i)| p ^ i).collect();
        let encrypted = aes_encrypt_block(key, &input)?;
        previous = encrypted;
        cipher.extend_from_slice(&encrypted);
    }
    Ok(cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream hashcat example hashes (module ST_HASH/ST_PASS, pass "hashcat").
    const OFFICE97_ST: &str =
        "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2";
    const OFFICE2007_ST: &str = "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f";
    const OFFICE2013_ST: &str = "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b";
    const PDF_R2_ST: &str = "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000";
    const PDF_R3_ST: &str = "$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*32*6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn rc4_matches_the_classic_test_vector() {
        // Classic RC4 vector: RC4("Key", "Plaintext") = BBF316E8D940AF0AD3.
        let out = rc4(b"Key", b"Plaintext");
        assert_eq!(hex::encode(out), "bbf316e8d940af0ad3");
    }

    #[test]
    fn upstream_office97_example_vector_verifies() {
        let parsed = Office97::parse(OFFICE97_ST).unwrap();
        assert_eq!(parsed.version, 0);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        assert!(Office97::parse("$oldoffice$2*a*b*c").is_err());
    }

    #[test]
    fn upstream_office2007_example_vector_verifies() {
        let parsed = Office2007::parse(OFFICE2007_ST).unwrap();
        assert_eq!(parsed.key_size, 128);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        assert!(Office2007::parse("$office$*2010*20*128*16*00*00*00").is_err());
    }

    #[test]
    fn upstream_office2013_example_vector_verifies() {
        let parsed = Office2013::parse(OFFICE2013_ST).unwrap();
        assert_eq!(parsed.spin_count, 100000);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        assert!(Office2013::parse("$office$*2013*50000*256*16*00*00*00").is_err());
    }

    #[test]
    fn upstream_pdf_r2_example_vector_verifies() {
        let parsed = PdfR2::parse(PDF_R2_ST).unwrap();
        assert_eq!(parsed.permissions, -1);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        assert!(PdfR2::parse("$pdf$1*3*40*-1*0*16*00*32*00*32*00").is_err());
    }

    #[test]
    fn upstream_pdf_r3_example_vector_verifies() {
        let parsed = PdfR34::parse(PDF_R3_ST).unwrap();
        assert_eq!(parsed.revision, 3);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        assert!(PdfR34::parse("$pdf$2*5*128*-4*1*16*00*32*00*32*00").is_err());
    }

    #[test]
    fn document_targets_self_detect_through_the_recovery_target_parse() {
        // The embedded Hashcat KAT gate parses each fixture with an empty
        // algorithm hint; the $-markers must select the right verifier.
        for (hash, negative) in [
            (OFFICE97_ST, "hashcau"),
            (OFFICE2007_ST, "hashcau"),
            (OFFICE2013_ST, "hashcau"),
            (PDF_R2_ST, "hashcau"),
            (PDF_R3_ST, "hashcau"),
        ] {
            let target = crate::recovery::RecoveryTarget::parse("", hash).unwrap();
            assert!(target.is_match(b"hashcat").unwrap(), "{hash} positive");
            assert!(!target.is_match(negative.as_bytes()).unwrap(), "{hash} negative");
        }
    }
}

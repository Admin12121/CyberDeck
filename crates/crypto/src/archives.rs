//! Archive container recovery verifiers (format batch B1). The wire formats
//! and check semantics mirror the pinned upstream modules 13600 (WinZip AES),
//! 11600 (7-Zip) and 17200/17210 (PKZIP legacy ZipCrypto). Every verifier runs
//! on the CPU in bounded time so a GPU match can always be re-proven
//! independently before it is reported. Only public upstream example vectors
//! are used as fixtures.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use hmac::Mac;
use sha1::Sha1;
use sha2::Digest;

const WINZIP_ROUNDS: u32 = 1000;
/// Hashcat's module buffer is 32 MiB; the CPU verifier stays well below it.
const MAX_ARCHIVE_DATA: usize = 4 << 20;
/// Inflated output cap for a compressed PKZIP entry (320 KiB stream may
/// expand more than 1000:1; 8 MiB is a generous CPU bound).
const MAX_PKZIP_UNCOMPRESSED: usize = 8 << 20;
const MAX_SEVEN_ZIP_CYCLES: u32 = 22;

// ---------------------------------------------------------------- WinZip AES

/// Parsed `$zip2$` WinZip AES container entry (hashcat mode 13600).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinZipAes {
    /// 1 = AES-128, 2 = AES-192, 3 = AES-256.
    pub mode: u8,
    pub salt: Vec<u8>,
    pub verify_bytes: u16,
    pub data: Vec<u8>,
    pub auth: Vec<u8>,
}

fn hex_len_ok(text: &str, expected: usize) -> bool {
    text.len() == expected && text.bytes().all(|b| b.is_ascii_hexdigit())
}

impl WinZipAes {
    fn key_length(&self) -> usize {
        match self.mode {
            1 => 16,
            2 => 24,
            _ => 32,
        }
    }

    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$zip2$")
            .ok_or("not a $zip2$ WinZip AES hash")?;
        let rest = rest
            .strip_suffix("$/zip2$")
            .ok_or("WinZip AES hash is missing the $/zip2$ terminator")?;
        // The wire form is "$zip2$*f0*...*f7*$/zip2$": one leading and one
        // trailing separator around the eight payload fields.
        let rest = rest
            .strip_prefix('*')
            .ok_or("WinZip AES hash is missing its leading separator")?;
        let rest = rest
            .strip_suffix('*')
            .ok_or("WinZip AES hash is missing its trailing separator")?;
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() != 8 {
            return Err("WinZip AES hash must have 8 fields".into());
        }
        if parts[0] != "0" || parts[2] != "0" {
            return Err("WinZip AES type and magic fields must be 0".into());
        }
        let mode: u8 = parts[1]
            .parse()
            .map_err(|_| "invalid WinZip AES mode")?;
        if !matches!(mode, 1 | 2 | 3) {
            return Err("WinZip AES mode must be 1, 2 or 3".into());
        }
        let salt_len = match mode {
            1 => 16,
            2 => 24,
            _ => 32,
        };
        if !hex_len_ok(parts[3], salt_len) {
            return Err("WinZip AES salt length does not match its AES mode".into());
        }
        let verify_text = parts[4];
        if verify_text.is_empty() || verify_text.len() > 4 || !verify_text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("WinZip AES verifier must be 1..4 hex characters".into());
        }
        let verify_bytes = u16::from_str_radix(verify_text, 16).map_err(|_| "invalid verifier")?;
        if parts[5].is_empty() || parts[5].len() > 6 || !parts[5].bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("WinZip AES compressed length must be 1..6 hex characters".into());
        }
        if parts[6].len() % 2 != 0 || parts[6].len() > MAX_ARCHIVE_DATA * 2 {
            return Err("WinZip AES data length exceeds the recovery policy".into());
        }
        let data = hex::decode(parts[6]).map_err(|_| "invalid WinZip AES data")?;
        if !hex_len_ok(parts[7], 20) {
            return Err("WinZip AES authentication field must be 20 hex characters".into());
        }
        let auth = hex::decode(parts[7]).map_err(|_| "invalid authentication field")?;
        Ok(Self { mode, salt: hex::decode(parts[3]).map_err(|_| "invalid salt")?, verify_bytes, data, auth })
    }

    /// Full upstream semantics: PBKDF2-HMAC-SHA1(1000) key material, the last
    /// two bytes are the password verifier and the middle klen bytes key the
    /// HMAC-SHA1 over the encrypted data (HMAC-SHA1-80 on the first 10 bytes).
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let klen = self.key_length();
        let mut material = vec![0u8; 2 * klen + 2];
        pbkdf2::pbkdf2_hmac::<Sha1>(candidate.as_bytes(), &self.salt, WINZIP_ROUNDS, &mut material);
        let verifier = u16::from_be_bytes([material[2 * klen], material[2 * klen + 1]]);
        if verifier != self.verify_bytes {
            return Ok(false);
        }
        let mut mac = <hmac::Hmac<Sha1> as Mac>::new_from_slice(&material[klen..2 * klen])
            .map_err(|_| "WinZip AES HMAC key error")?;
        mac.update(&self.data);
        let tag = mac.finalize().into_bytes();
        Ok(constant_time_eq(&tag[..10], &self.auth))
    }
}

// -------------------------------------------------------------------- 7-Zip

/// Parsed `$7z$` container header (hashcat mode 11600). Only uncompressed
/// (data type 0) headers are accepted: the CPU verifier must be able to
/// re-prove any GPU match, and compressed headers would need LZMA/ZSTD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenZip {
    /// NumCyclesPower; the KDF hashes 2^cycles rounds.
    pub cycles: u32,
    pub iv: [u8; 16],
    pub crc: u32,
    pub unpack_size: u32,
    pub data: Vec<u8>,
}

impl SevenZip {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash.strip_prefix("$7z$").ok_or("not a $7z$ hash")?;
        let parts: Vec<&str> = rest.split('$').collect();
        if parts.len() != 10 {
            if parts.len() > 10 {
                return Err("compressed 7-Zip headers are not supported; only data type 0".into());
            }
            return Err("7-Zip hash must have 10 fields".into());
        }
        if parts[0] != "0" {
            return Err("only uncompressed 7-Zip headers (data type 0) are supported".into());
        }
        let cycles: u32 = parts[1].parse().map_err(|_| "invalid 7-Zip NumCyclesPower")?;
        if cycles > MAX_SEVEN_ZIP_CYCLES {
            return Err("7-Zip NumCyclesPower exceeds the recovery policy".into());
        }
        if parts[2] != "0" {
            return Err("7-Zip hashes with salt are not supported".into());
        }
        let iv_len: u32 = parts[4].parse().map_err(|_| "invalid 7-Zip IV length")?;
        if iv_len > 16 {
            return Err("invalid 7-Zip IV length".into());
        }
        if !hex_len_ok(parts[5], 32) {
            return Err("7-Zip IV must be 32 hex characters".into());
        }
        let iv_hex = hex::decode(parts[5]).map_err(|_| "invalid 7-Zip IV")?;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_hex);
        let crc: u32 = parts[6].parse().map_err(|_| "invalid 7-Zip CRC")?;
        let data_len: usize = parts[7].parse().map_err(|_| "invalid 7-Zip data length")?;
        let unpack_size: u32 = parts[8].parse().map_err(|_| "invalid 7-Zip unpack size")?;
        if data_len % 16 != 0 || data_len > MAX_ARCHIVE_DATA {
            return Err("7-Zip data must be a bounded multiple of AES blocks".into());
        }
        if data_len * 2 != parts[9].len() {
            return Err("7-Zip data length does not match its hex field".into());
        }
        let data = hex::decode(parts[9]).map_err(|_| "invalid 7-Zip data")?;
        if unpack_size as usize > data.len() {
            return Err("7-Zip unpack size exceeds the encrypted data length".into());
        }
        Ok(Self { cycles, iv, crc, unpack_size, data })
    }

    /// 7-Zip KDF: one continuous SHA-256 stream over
    /// (UTF-16-LE password || 64-bit little-endian round counter) per round,
    /// then AES-256-CBC and a CRC-32 check over the first unpack_size bytes.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let utf16: Vec<u8> = candidate
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let mut hasher = sha2::Sha256::new();
        let rounds = 1u64 << self.cycles;
        let mut counter = [0u8; 8];
        for round in 0..rounds {
            hasher.update(&utf16);
            counter.copy_from_slice(&round.to_le_bytes());
            hasher.update(&counter);
        }
        let key = hasher.finalize();
        let cipher = aes::Aes256::new_from_slice(&key).map_err(|_| "invalid 7-Zip key")?;
        let mut plain = Vec::with_capacity(self.data.len());
        let mut previous = self.iv;
        for block in self.data.chunks_exact(16) {
            let mut state = *GenericArray::from_slice(block);
            cipher.decrypt_block(&mut state);
            for (index, byte) in state.iter().enumerate() {
                plain.push(byte ^ previous[index]);
            }
            previous.copy_from_slice(block);
        }
        let crc = crc32fast::hash(&plain[..self.unpack_size as usize]);
        Ok(crc == self.crc)
    }
}

// -------------------------------------------------------------- PKZIP legacy

/// Parsed `$pkzip2$` single-entry ZipCrypto hash (hashcat modes 17200/17210).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkZip {
    /// 1 = one-byte checksum, 2 = two-byte checksum.
    pub checksum_size: u8,
    pub crc32: u32,
    pub compression_type: u8,
    pub data_length: u32,
    pub uncompressed_length: u32,
    pub checksum_from_crc: u16,
    pub checksum_from_timestamp: u16,
    pub data: Vec<u8>,
}

impl PkZip {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let (signature, rest) = hash
            .split_once('*')
            .ok_or("PKZIP hash requires * separators")?;
        let version = if let Some(body) = signature.strip_prefix("$pkzip2$") {
            if body.len() != 1 {
                return Err("PKZIP v2 hash_count must be a single digit".into());
            }
            2
        } else if let Some(body) = signature.strip_prefix("$pkzip$") {
            if body.len() != 1 {
                return Err("PKZIP v1 hash_count must be a single digit".into());
            }
            1
        } else {
            return Err("not a $pkzip$/$pkzip2$ hash".into());
        };
        if signature.as_bytes()[signature.len() - 1] != b'1' {
            return Err("only single-entry PKZIP hashes are supported".into());
        }
        let parts: Vec<&str> = rest.split('*').collect();
        if parts.len() < 8 {
            return Err("PKZIP hash is missing fields".into());
        }
        let mut index = 0usize;
        let mut next = |error: &str| -> Result<&str, String> {
            let value = parts.get(index).copied().ok_or(error.to_string())?;
            index += 1;
            Ok(value)
        };
        let checksum_size: u8 = next("missing PKZIP checksum size")?
            .parse()
            .map_err(|_| "invalid PKZIP checksum size")?;
        if !matches!(checksum_size, 1 | 2) {
            return Err("PKZIP checksum size must be 1 or 2".into());
        }
        let data_type_enum: u8 = next("missing PKZIP data type")?
            .parse()
            .map_err(|_| "invalid PKZIP data type")?;
        if data_type_enum != 2 {
            return Err("only CRC-verified PKZIP entries (data type 2) are supported".into());
        }
        let _magic_type_enum = next("missing PKZIP magic type")?;
        let _compressed_length = parse_hex_u32(next("missing compressed length")?, "compressed length")?;
        let uncompressed_length =
            parse_hex_u32(next("missing uncompressed length")?, "uncompressed length")?;
        let crc32 = parse_hex_u32(next("missing CRC")?, "CRC")?;
        let _offset = parse_hex_u32(next("missing offset")?, "offset")?;
        let _additional_offset = parse_hex_u32(next("missing additional offset")?, "additional offset")?;
        let compression_type: u8 = next("missing compression type")?
            .parse()
            .map_err(|_| "invalid PKZIP compression type")?;
        if !matches!(compression_type, 0 | 8) {
            return Err("only stored (0) or deflate (8) PKZIP entries are supported".into());
        }
        let data_length = parse_hex_u32(next("missing data length")?, "data length")?;
        if data_length < 12 || data_length as usize > 320 * 1024 {
            return Err("PKZIP data length exceeds the recovery policy".into());
        }
        let checksum_from_crc =
            parse_hex_u32(next("missing checksum")?, "checksum")? as u16;
        let checksum_from_timestamp = if version == 2 {
            parse_hex_u32(next("missing timestamp checksum")?, "timestamp checksum")? as u16
        } else {
            checksum_from_crc
        };
        let data_hex = next("missing PKZIP data")?;
        if data_hex.len() != data_length as usize * 2 {
            return Err("PKZIP data length does not match its hex field".into());
        }
        let data = hex::decode(data_hex).map_err(|_| "invalid PKZIP data")?;
        if uncompressed_length > MAX_PKZIP_UNCOMPRESSED as u32 {
            return Err("PKZIP uncompressed length exceeds the recovery policy".into());
        }
        // A stored entry's stream is the 12-byte ZipCrypto header plus the
        // file bytes verbatim.
        if compression_type == 0
            && data_length
                != uncompressed_length
                    .checked_add(12)
                    .ok_or("PKZIP uncompressed length overflow")?
        {
            return Err("stored PKZIP entry length mismatch".into());
        }
        Ok(Self {
            checksum_size,
            crc32,
            compression_type,
            data_length,
            uncompressed_length,
            checksum_from_crc,
            checksum_from_timestamp,
            data,
        })
    }

    /// The hashcat mode this hash must run as: 17200 (compressed) or
    /// 17210 (stored).
    pub fn gpu_mode(&self) -> u32 {
        if self.compression_type == 8 { 17200 } else { 17210 }
    }

    /// ZipCrypto stream decrypt: 12-byte header checksum filter, then either
    /// a direct CRC-32 (stored) or a raw-inflate plus CRC-32 (deflate).
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut key0: u32 = 0x1234_5678;
        let mut key1: u32 = 0x2345_6789;
        let mut key2: u32 = 0x3456_7890;
        for byte in candidate.as_bytes() {
            update_key012(&mut key0, &mut key1, &mut key2, *byte);
        }
        let mut plain = Vec::with_capacity(self.data.len());
        for byte in &self.data {
            let temp = (key2 & 0xffff) | 3;
            let key3 = ((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xff;
            let value = byte ^ key3 as u8;
            update_key012(&mut key0, &mut key1, &mut key2, value);
            plain.push(value);
        }
        // The last two header bytes carry the checksum filter; the byte before
        // them is only filtered when a two-byte checksum is present.
        if self.checksum_size == 2
            && plain[10] != (self.checksum_from_crc & 0xff) as u8
            && plain[10] != (self.checksum_from_timestamp & 0xff) as u8
        {
            return Ok(false);
        }
        if plain[11] != (self.checksum_from_crc >> 8) as u8
            && plain[11] != (self.checksum_from_timestamp >> 8) as u8
        {
            return Ok(false);
        }
        if self.compression_type == 0 {
            let crc = crc32fast::hash(&plain[12..self.data_length as usize]);
            return Ok(crc == self.crc32);
        }
        let mut inflater = flate2::Decompress::new(false);
        let mut output = Vec::with_capacity(self.uncompressed_length as usize);
        let status = inflater
            .decompress_vec(&plain[12..], &mut output, flate2::FlushDecompress::Finish)
            .map_err(|_| "invalid deflate stream")?;
        if status != flate2::Status::StreamEnd || inflater.total_out() != self.uncompressed_length as u64 {
            return Ok(false);
        }
        Ok(crc32fast::hash(&output) == self.crc32)
    }
}

fn parse_hex_u32(text: &str, field: &str) -> Result<u32, String> {
    if text.is_empty() || text.len() > 8 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid PKZIP {field}"));
    }
    u32::from_str_radix(text, 16).map_err(|_| format!("invalid PKZIP {field}"))
}

fn update_key012(key0: &mut u32, key1: &mut u32, key2: &mut u32, byte: u8) {
    *key0 = (*key0 >> 8) ^ CRC_TABLE[((*key0 ^ byte as u32) & 0xff) as usize];
    *key1 = key1
        .wrapping_add(*key0 & 0xff)
        .wrapping_mul(0x0808_8405)
        .wrapping_add(1);
    *key2 = (*key2 >> 8) ^ CRC_TABLE[((*key2 ^ (*key1 >> 24)) & 0xff) as usize];
}

/// CRC-32 (IEEE) table shared by the ZipCrypto key schedule.
const CRC_TABLE: [u32; 256] = build_crc_table();

const fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 { 0xEDB8_8320 ^ (value >> 1) } else { value >> 1 };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
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

    // Upstream hashcat example hashes (module ST_HASH/ST_PASS, pass "hashcat").
    const WINZIP_ST: &str = "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$";
    const SEVEN_ZIP_ST: &str =
        "$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269";
    const PKZIP_COMPRESSED_ST: &str = "$pkzip2$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*a9fc1f4e951c8fb3031a6f903e5f4e3211c8fdc4671547bf77f6f682afbfcc7475d83898985621a7af9bccd1349d1976500a68c48f630b7f22d7a0955524d768e34868880461335417ddd149c65a917c0eb0a4bf7224e24a1e04cf4ace5eef52205f4452e66ded937db9545f843a68b1e84a2e933cc05fb36d3db90e6c5faf1bee2249fdd06a7307849902a8bb24ec7e8a0886a4544ca47979a9dfeefe034bdfc5bd593904cfe9a5309dd199d337d3183f307c2cb39622549a5b9b8b485b7949a4803f63f67ca427a0640ad3793a519b2476c52198488e3e2e04cac202d624fb7d13c2*$/pkzip2$";
    const PKZIP_STORED_ST: &str = "$pkzip2$1*1*2*0*1d1*1c5*eda7a8de*0*28*0*1d1*eda7*5096*1dea673da43d9fc7e2be1a1f4f664269fceb6cb88723a97408ae1fe07f774d31d1442ea8485081e63f919851ca0b7588d5e3442317fff19fe547a4ef97492ed75417c427eea3c4e146e16c100a2f8b6abd7e5988dc967e5a0e51f641401605d673630ea52ebb04da4b388489901656532c9aa474ca090dbac7cf8a21428d57b42a71da5f3d83fed927361e5d385ca8e480a6d42dea5b4bf497d3a24e79fc7be37c8d1721238cbe9e1ea3ae1eb91fc02aabdf33070d718d5105b70b3d7f3d2c28b3edd822e89a5abc0c8fee117c7fbfbfd4b4c8e130977b75cb0b1da080bfe1c0859e6483c42f459c8069d45a76220e046e6c2a2417392fd87e4aa4a2559eaab3baf78a77a1b94d8c8af16a977b4bb45e3da211838ad044f209428dba82666bf3d54d4eed82c64a9b3444a44746b9e398d0516a2596d84243b4a1d7e87d9843f38e45b6be67fd980107f3ad7b8453d87300e6c51ac9f5e3f6c3b702654440c543b1d808b62f7a313a83b31a6faaeedc2620de7057cd0df80f70346fe2d4dccc318f0b5ed128bcf0643e63d754bb05f53afb2b0fa90b34b538b2ad3648209dff587df4fa18698e4fa6d858ad44aa55d2bba3b08dfdedd3e28b8b7caf394d5d9d95e452c2ab1c836b9d74538c2f0d24b9b577*$/pkzip2$";

    #[test]
    fn upstream_winzip_example_vector_verifies() {
        let parsed = WinZipAes::parse(WINZIP_ST).unwrap();
        assert_eq!(parsed.mode, 1);
        assert_eq!(parsed.verify_bytes, 0x5dc5);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_seven_zip_example_vector_verifies() {
        let parsed = SevenZip::parse(SEVEN_ZIP_ST).unwrap();
        assert_eq!(parsed.cycles, 14);
        assert_eq!(parsed.unpack_size, 12);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcasu").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_pkzip_compressed_example_vector_verifies() {
        let parsed = PkZip::parse(PKZIP_COMPRESSED_ST).unwrap();
        assert_eq!(parsed.gpu_mode(), 17200);
        assert_eq!(parsed.uncompressed_length, 0x1c5);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_pkzip_stored_example_vector_verifies() {
        let parsed = PkZip::parse(PKZIP_STORED_ST).unwrap();
        assert_eq!(parsed.gpu_mode(), 17210);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn parse_rejects_out_of_policy_shapes() {
        assert!(WinZipAes::parse("$zip2$*1*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$").is_err());
        assert!(WinZipAes::parse("$zip2$*0*2*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$").is_err());
        assert!(SevenZip::parse("$7z$1$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269").is_err());
        assert!(SevenZip::parse("$7z$0$30$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269").is_err());
        assert!(PkZip::parse("$pkzip2$2*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*00*$/pkzip2$").is_err());
        assert!(PkZip::parse("$pkzip2$1*1*3*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*00*$/pkzip2$").is_err());
        assert!(PkZip::parse("$pkzip2$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*00*$/pkzip2$").is_err());
    }

    #[test]
    fn archive_targets_self_detect_through_the_recovery_target_parse() {
        // The embedded Hashcat KAT gate parses each fixture with an empty
        // algorithm hint; the $-markers must select the right verifier.
        for (hash, negative) in [
            (WINZIP_ST, "hashcau"),
            (SEVEN_ZIP_ST, "hashcasu"),
            (PKZIP_COMPRESSED_ST, "hashcau"),
            (PKZIP_STORED_ST, "hashcau"),
        ] {
            let target = crate::recovery::RecoveryTarget::parse("", hash).unwrap();
            assert!(target.is_match(b"hashcat").unwrap(), "{hash} positive");
            assert!(!target.is_match(negative.as_bytes()).unwrap(), "{hash} negative");
        }
    }
}

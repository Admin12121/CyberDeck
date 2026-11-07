//! Database server password recovery verifiers (format batch 7). The wire
//! formats and check semantics mirror the pinned upstream modules 131 (MSSQL
//! 2000), 300 (MySQL 4.1/MySQL5) and 3100 (Oracle H: Type, Oracle 7+). Every
//! verifier runs on the CPU in bounded time so a GPU match can always be
//! re-proven independently before it is reported. Only public upstream
//! example vectors are used as fixtures; the few self-derived vectors are
//! labelled as such in their tests.

use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

/// The fixed first-pass Oracle DES key (OpenCL/m03100_a4-optimized.cl:92:
/// "key is static: 0x0123456789abcdefUL"; tools/test_modules/m03100.py
/// `KEY = bytes.fromhex("0123456789ABCDEF")`).
const ORACLE_FIRST_KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
/// Upstream caps Oracle passwords at 30 characters
/// (module_03100.c:66-71, red-database-security whitepaper).
const ORACLE_PW_MAX: usize = 30;

fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    sha1::Sha1::digest(data).into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn hex_len_ok(text: &str, expected: usize) -> bool {
    text.len() == expected && text.bytes().all(|b| b.is_ascii_hexdigit())
}

// -------------------------------------------------------------- MSSQL (2000)

/// Parsed `0x0100` MSSQL (2000) entry (hashcat mode 131). Mode 131 shares
/// KERN_TYPE 130 with mode 132 (MSSQL 2005, module_00132.c:23), so both run
/// on the m00130 kernel family; 2005 differs only by dropping the uppercase
/// step and the const block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mssql2000 {
    /// The 4 bytes of the hex-decoded 8-character salt field
    /// (OPTS_TYPE_ST_HEX, module_00131.c:36).
    pub salt: [u8; 4],
    pub digest: [u8; 20],
}

impl Mssql2000 {
    /// Wire form: "0x0100" + 8-hex salt + 40-hex const block + 40-hex digest
    /// (94 characters). The 40-hex middle field is required by the upstream
    /// tokenizer (module_00131.c:80-86) but never used for cracking, and
    /// module_hash_encode re-emits it as zeros (module_00131.c:152-159), so
    /// it is validated here and discarded. MSSQL 2005 lines share the
    /// "0x0100" prefix but are 54 characters and are rejected.
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("0x0100")
            .ok_or("not a 0x0100 MSSQL (2000) hash")?;
        if hash.len() != 94 {
            return Err(
                "MSSQL (2000) hash must be 94 characters: 0x0100 + 8 hex salt + 40 hex const block + 40 hex digest"
                    .into(),
            );
        }
        if !hex_len_ok(&rest[0..8], 8) {
            return Err("MSSQL (2000) salt field must be 8 hex characters".into());
        }
        // Required by the tokenizer, ignored by the kernel: content is free.
        if !hex_len_ok(&rest[8..48], 40) {
            return Err("MSSQL (2000) const block field must be 40 hex characters".into());
        }
        if !hex_len_ok(&rest[48..88], 40) {
            return Err("MSSQL (2000) digest field must be 40 hex characters".into());
        }
        let mut salt = [0u8; 4];
        salt.copy_from_slice(&hex::decode(&rest[0..8]).map_err(|_| "invalid salt")?);
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&hex::decode(&rest[48..88]).map_err(|_| "invalid digest")?);
        Ok(Self { salt, digest })
    }

    /// sha1 over the ASCII-uppercased password widened byte by byte into
    /// UTF-16LE (OPTS_TYPE_PT_UTF16LE | OPTS_TYPE_PT_UPPER,
    /// module_00131.c:32-33) followed by the 4 raw salt bytes
    /// (HASH_RECIPE "sha1(utf16le(pass) . salt)", module_00131.c:22). Upstream
    /// widens bytes, not Unicode code points
    /// (tools/test_modules/m00131.py: `word.upper().decode("latin-1").encode("utf-16-le")`).
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut message: Vec<u8> = candidate
            .bytes()
            .map(|byte| byte.to_ascii_uppercase())
            .flat_map(|byte| [byte, 0x00])
            .collect();
        message.extend_from_slice(&self.salt);
        Ok(constant_time_eq(&sha1(&message), &self.digest))
    }
}

// ---------------------------------------------------------- MySQL 4.1 / 5.x

/// Parsed MySQL 4.1/5.x `PASSWORD()` digest (hashcat mode 300): the bare
/// 40-hex double SHA-1 stored without MySQL's leading `*` and in lower case
/// (tools/test_modules/m00300.py).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mysql41 {
    pub digest: [u8; 20],
}

impl Mysql41 {
    pub fn parse(hash: &str) -> Result<Self, String> {
        if !hex_len_ok(hash, 40) {
            return Err("MySQL 4.1/5 hash must be exactly 40 hex characters".into());
        }
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&hex::decode(hash).map_err(|_| "invalid digest")?);
        Ok(Self { digest })
    }

    /// sha1(sha1_bin(pass)) — unsalted double SHA-1 (HASH_RECIPE,
    /// module_00300.c:22). The same derivation ships as the native
    /// `mysql5` digest algorithm (legacy_digests::mysql5_digest); this
    /// verifier binds it to the hashcat mode-300 wire form.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let inner = sha1(candidate.as_bytes());
        Ok(constant_time_eq(&sha1(&inner), &self.digest))
    }
}

// ------------------------------------------------------ Oracle H: (Oracle 7+)

/// Parsed Oracle 7+ `H:` entry (hashcat mode 3100): a 16-hex uppercase
/// digest and the upper-cased user name as the "salt". The format is
/// username-coupled known-plaintext DES: the user name and password are
/// concatenated and upper-cased, spread, and DES-CBC encrypted twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleH {
    pub digest: [u8; 8],
    /// The user name exactly as parsed; OPTS_TYPE_ST_UPPER means the
    /// algorithm upper-cases it before use.
    pub username: String,
}

impl OracleH {
    /// Wire form: `digest:username` — 16 hex characters (either case, the
    /// canonical display is uppercase), the hashcat separator, and a
    /// 1..=30 character user name (module_03100.c:84-90). There is no
    /// HASH_RECIPE field: this is the older module style.
    pub fn parse(hash: &str) -> Result<Self, String> {
        let (digest_hex, username) = hash
            .split_once(':')
            .ok_or("Oracle H: hash requires digest:username")?;
        if !hex_len_ok(digest_hex, 16) {
            return Err("Oracle H: digest must be 16 hex characters".into());
        }
        if username.is_empty() || username.len() > 30 {
            return Err("Oracle H: username must be 1..=30 characters".into());
        }
        let mut digest = [0u8; 8];
        digest.copy_from_slice(&hex::decode(digest_hex).map_err(|_| "invalid digest")?);
        Ok(Self { digest, username: username.to_string() })
    }

    /// Oracle 7+ password verifier: upper-case(user || pass), every byte
    /// spread as [0x00, byte] and zero-padded to a whole DES block; the last
    /// CBC block of a DES-CBC pass under the fixed key 0x0123456789ABCDEF
    /// keys a second identical pass whose last block is the hash.
    ///
    /// The spread layout follows the pinned kernel: the message is packed
    /// little-endian into words and each word yields the DES block
    /// [0x00, m0, 0x00, m1, 0x00, m2, 0x00, m3]
    /// (OpenCL/m03100_a4-optimized.cl:147-148 together with the
    /// little-endian DES word convention of OpenCL/inc_hash_lm.cl:15-16),
    /// matching the upstream reference implementation
    /// (tools/test_modules/m03100.py: `b"".join(b"\x00" + bytes([c]))`).
    /// Oversized candidates cannot match: upstream caps passwords at 30
    /// characters (module_03100.c:66-71), so they return no-match rather
    /// than an error, as upstream does. (The kernel's 64-byte message buffer
    /// bound, OpenCL/m03100_a4-optimized.cl:190, is implied: 30 password +
    /// 30 user name bytes never exceed it.)
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        if candidate.len() > ORACLE_PW_MAX {
            return Ok(false);
        }
        let message: Vec<u8> = self
            .username
            .bytes()
            .chain(candidate.bytes())
            .map(|byte| byte.to_ascii_uppercase())
            .collect();
        let stream = spread_oracle_message(&message);
        let key = des_cbc_last_block(&ORACLE_FIRST_KEY, &stream);
        let derived = des_cbc_last_block(&key, &stream);
        Ok(constant_time_eq(&derived, &self.digest))
    }
}

/// Spread every message byte into a preceding zero byte and zero-pad the
/// stream to a multiple of 8 (tools/test_modules/m03100.py pads the widened
/// data with `b"\x00" * (-len(userpass) % 8)`).
fn spread_oracle_message(message: &[u8]) -> Vec<u8> {
    let blocks = (message.len() + 3) / 4;
    let mut stream = vec![0u8; blocks * 8];
    for (index, byte) in message.iter().enumerate() {
        stream[index * 2 + 1] = *byte;
    }
    stream
}

/// DES-CBC with a zero IV over a pre-padded stream; only the last ciphertext
/// block is used (both Oracle passes discard everything before it). The
/// second pass keys DES with the first pass's final block; DES ignores key
/// parity bits in its schedule, as do the upstream key setup and this crate's
/// `des` implementation.
fn des_cbc_last_block(key: &[u8; 8], stream: &[u8]) -> [u8; 8] {
    let cipher = Des::new_from_slice(key).expect("DES key is always 8 bytes");
    let mut previous = [0u8; 8];
    for block in stream.chunks_exact(8) {
        let mut state = des::cipher::Block::<Des>::clone_from_slice(block);
        for (byte, previous_byte) in state.iter_mut().zip(previous.iter()) {
            *byte ^= previous_byte;
        }
        cipher.encrypt_block(&mut state);
        previous.copy_from_slice(&state);
    }
    previous
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream hashcat example hashes (module ST_HASH/ST_PASS, pass "hashcat";
    // also docs/hashcat-example-hashes.md rows 30 (131), 39 (300), 88 (3100)).
    const MSSQL2000_ST: &str = "0x0100778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939";
    const MYSQL41_ST: &str = "fcf7c1b8749cf99d88e5f34271d636178fb5d130";
    const ORACLE_ST: &str = "792FCB0AE31D8489:7284616727";

    #[test]
    fn upstream_mssql_2000_example_vector_verifies() {
        // Provenance: module_00131.c:38-39 ST_PASS/ST_HASH and
        // docs/hashcat-example-hashes.md:30. The derivation was
        // independently reproduced this session with a Node script
        // (node:crypto sha1) over the same input bytes.
        let parsed = Mssql2000::parse(MSSQL2000_ST).unwrap();
        assert_eq!(parsed.salt, [0x77, 0x88, 0x83, 0x86]);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        // The uppercase step is part of the mode: lowercase folds onto it.
        assert!(parsed.verify("HASHCAT").unwrap());
    }

    #[test]
    fn mssql_2000_self_derived_vector_verifies() {
        // SELF-DERIVED vector, not an external publication: generated this
        // session with the Node reference implementation that was first
        // validated against the upstream ST vector above. Salt is the hex
        // field "deadbeef"; password "Hunter2".
        let hash = "0x0100deadbeef0000000000000000000000000000000000000000d620116f869ce3cc0c2d6231c84bfac71a01d7f4";
        let parsed = Mssql2000::parse(hash).unwrap();
        assert!(parsed.verify("Hunter2").unwrap());
        // OPTS_TYPE_PT_UPPER folds case: "hunter2" IS the password.
        assert!(parsed.verify("hunter2").unwrap());
        assert!(!parsed.verify("Hunter3").unwrap());
    }

    #[test]
    fn mssql_2000_ignores_the_required_but_unused_const_block() {
        // The 40-hex middle field is parsed but never used for cracking
        // (module_00131.c:92-118 reads only token.buf[1] and token.buf[3]),
        // and hash_encode re-emits it as zeros (module_00131.c:152-159):
        // a non-zero const block must still verify.
        let mutated = format!("0x010077888386{}eda3604e067a06f2732b05b9cb90b8a710996939", "a".repeat(40));
        let parsed = Mssql2000::parse(&mutated).unwrap();
        assert!(parsed.verify("hashcat").unwrap());
        // MSSQL 2005 (mode 132) shares the 0x0100 prefix at 54 characters
        // and must not parse as 2000.
        let mssql_2005 = "0x01004b617431118f284707047f3aca6a8aa6efc55a14ebf4bda1";
        assert!(Mssql2000::parse(mssql_2005).is_err());
    }

    #[test]
    fn upstream_mysql_example_vector_verifies() {
        // Provenance: module_00300.c:34-35 ST_PASS/ST_HASH and
        // docs/hashcat-example-hashes.md:39; independently reproduced this
        // session with Node sha1(sha1("hashcat")).
        let parsed = Mysql41::parse(MYSQL41_ST).unwrap();
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn mysql_reference_manual_vector_verifies() {
        // Provenance: the MySQL Reference Manual documents
        // PASSWORD('password') = '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19';
        // the same value is asserted in-tree at legacy_digests.rs:116-119
        // and was reproduced with Node this session. Mode 300 is the digest
        // without MySQL's leading '*'.
        let parsed = Mysql41::parse("2470c0c06dee42fd1618bb99005adca2ec9d1e19").unwrap();
        assert!(parsed.verify("password").unwrap());
        // Uppercase hex (MySQL's own display form minus the '*') parses too.
        let upper = Mysql41::parse("2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19").unwrap();
        assert!(upper.verify("password").unwrap());
        assert!(Mysql41::parse("*2470c0c06dee42fd1618bb99005adca2ec9d1e19").is_err());
    }

    #[test]
    fn upstream_oracle_example_vector_verifies() {
        // Provenance: module_03100.c:29-30 ST_PASS/ST_HASH and
        // docs/hashcat-example-hashes.md:88. The spread two-pass DES was
        // independently reproduced this session with OpenSSL DES-CBC
        // (legacy provider) over the kernel's byte layout and matched the
        // digest exactly.
        let parsed = OracleH::parse(ORACLE_ST).unwrap();
        assert_eq!(parsed.username, "7284616727");
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        // OPTS_TYPE_PT_UPPER: the candidate folds to uppercase.
        assert!(parsed.verify("HASHCAT").unwrap());
        // OPTS_TYPE_ST_UPPER: the stored user name case is irrelevant.
        let lower = OracleH::parse("792fcb0ae31d8489:7284616727").unwrap();
        assert!(lower.verify("hashcat").unwrap());
    }

    #[test]
    fn oracle_self_derived_vectors_verify() {
        // SELF-DERIVED vectors, not external publications: generated this
        // session with the Node+OpenSSL reference that reproduces the
        // upstream ST vector and mirrors tools/test_modules/m03100.py.
        // They exercise the spread padding corners: combined lengths of
        // 13 (3 pad bytes), 12 (exact blocks) and 9 (3 pad bytes, user name
        // shorter than one DES block).
        // D4DF7931AB130E37:system is additionally the value widely published
        // for the classic SYSTEM/MANAGER default credentials (web-search
        // corroboration; no primary citation captured here).
        for (hash, candidate) in [
            ("D4DF7931AB130E37:system", "manager"),
            ("BEFDE0D97885629E:scott", "tiger12"),
            ("5AD9B02115FAD3C6:sa", "tiger12"),
        ] {
            let parsed = OracleH::parse(hash).unwrap();
            assert!(parsed.verify(candidate).unwrap(), "{hash} positive");
            assert!(!parsed.verify("not-the-solution").unwrap(), "{hash} negative");
        }
    }

    #[test]
    fn parse_rejects_out_of_policy_shapes() {
        assert!(Mssql2000::parse("0x0200778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939").is_err());
        assert!(Mssql2000::parse("0x0100778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a71099693").is_err());
        assert!(Mssql2000::parse("0x01007788838X0000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939").is_err());
        assert!(Mssql2000::parse("0x01007788838600000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939").is_err());
        assert!(Mysql41::parse("fcf7c1b8749cf99d88e5f34271d636178fb5d13").is_err());
        assert!(Mysql41::parse("fcf7c1b8749cf99d88e5f34271d636178fb5d1300").is_err());
        assert!(Mysql41::parse("fcf7c1b8749cf99d88e5f34271d636178fb5d13g").is_err());
        assert!(OracleH::parse("792FCB0AE31D8489").is_err());
        assert!(OracleH::parse("792FCB0AE31D848:7284616727").is_err());
        assert!(OracleH::parse("792FCB0AE31D8489:").is_err());
        assert!(OracleH::parse("792FCB0AE31D848G:7284616727").is_err());
        assert!(OracleH::parse("792FCB0AE31D8489:0123456789012345678901234567890").is_err());
    }

    #[test]
    fn cyberdeck_public_kat_rows_verify() {
        // The exact fixture rows destined for the embedded Hashcat
        // PUBLIC_KATS table (see the integration checklist). SELF-DERIVED
        // this session with the Node+OpenSSL reference validated against the
        // upstream ST vectors above; salts follow the in-tree "Kat1" (132) /
        // "Kat2" (1731) series with "Kat3" = 4b617433. All three must verify
        // with the password "cyberdeck".
        let mssql = Mssql2000::parse(
            "0x01004b617433000000000000000000000000000000000000000051c88bd2152a6c7862d3db9c9b011e0513fbd941",
        )
        .unwrap();
        assert!(mssql.verify("cyberdeck").unwrap());
        let mysql = Mysql41::parse("87c7b8262d3208503687a0b37014057a334c19e4").unwrap();
        assert!(mysql.verify("cyberdeck").unwrap());
        let oracle = OracleH::parse("ED122223D01263D6:cyberdeck").unwrap();
        assert!(oracle.verify("cyberdeck").unwrap());
        assert!(!mssql.verify("cyberdeck2").unwrap());
        assert!(!mysql.verify("cyberdeck2").unwrap());
        assert!(!oracle.verify("cyberdeck2").unwrap());
    }

    #[test]
    fn oracle_rejects_oversized_candidates_as_no_match() {
        // module_pw_max caps passwords at 30 characters
        // (module_03100.c:66-71); longer candidates cannot match any hash
        // and report no-match instead of an error.
        let parsed = OracleH::parse(ORACLE_ST).unwrap();
        assert!(parsed.verify("a".repeat(30).as_str()).is_ok());
        assert!(!parsed.verify("a".repeat(31).as_str()).unwrap());
    }
}

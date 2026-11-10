//! macOS v10.4/v10.5/v10.6 password verifier (hashcat mode 122, format batch
//! os-and-apps). Wire formats and check semantics mirror the pinned upstream
//! module 122 (`reference/hashcat/src/modules/module_00122.c`, KERN_TYPE 120):
//! the line is a 48 hex character string — an 8 character hex encoded 4 byte
//! salt followed by the 40 character hex SHA-1 — and the recipe is
//! sha1(salt . pass) (`HASH_RECIPE`, module_00122.c:22; the salt is stored
//! hex, `OPTS_TYPE_ST_HEX`, module_00122.c:34). The shared m00120 optimized
//! kernel family already staged for sibling mode 120 computes the same
//! digest, so a GPU match can always be re-proven on the CPU here.
//!
//! Frontend algorithm name: "macos-salted-sha1". This file is
//! self-contained on purpose: it compiles both inside cyberdeck-crypto and
//! standalone in the authoring test crate.

use sha1::Sha1;

/// The wire salt is exactly 8 hex characters (4 raw bytes).
const SALT_HEX: usize = 8;
/// The digest is a raw SHA-1, 20 bytes / 40 hex characters.
const DIGEST_HEX: usize = 40;
/// Hashcat mode 122.
pub const GPU_MODE: u32 = 122;

/// Parsed macOS salted SHA-1 line (hashcat mode 122).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsSaltedSha1 {
    /// The 4 salt bytes carried hex encoded on the wire.
    pub salt: [u8; 4],
    /// The expected SHA-1 of salt . password.
    pub digest: [u8; 20],
}

impl MacOsSaltedSha1 {
    /// Parse the 48 hex character wire form; the upstream tokenizer
    /// (module_00122.c:63-71) demands exactly two fixed length hex tokens of
    /// 8 and 40 characters.
    pub fn parse(hash: &str) -> Result<Self, String> {
        if hash.len() != SALT_HEX + DIGEST_HEX
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("macOS salted SHA-1 must be 8 hex salt + 40 hex digest characters".into());
        }
        let salt_hex = hex::decode(&hash[..SALT_HEX]).map_err(|_| "invalid macOS salt")?;
        let digest_hex = hex::decode(&hash[SALT_HEX..]).map_err(|_| "invalid macOS digest")?;
        let mut salt = [0u8; 4];
        salt.copy_from_slice(&salt_hex);
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&digest_hex);
        Ok(Self { salt, digest })
    }

    /// sha1(salt . candidate); the digest compare is constant time.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let mut input = Vec::with_capacity(4 + candidate.len());
        input.extend_from_slice(&self.salt);
        input.extend_from_slice(candidate.as_bytes());
        let digest = <Sha1 as sha1::Digest>::digest(&input);
        Ok(constant_time_eq(&digest, &self.digest))
    }
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

    // Upstream hashcat example hash: module_00122.c ST_HASH/ST_PASS
    // (reference/hashcat example hash for mode 122, pass "hashcat"; the same
    // row appears in the upstream docs and tools/test_modules/m00122.py).
    const ST_HASH: &str = "86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9";
    const ST_PASS: &str = "hashcat";
    // Cross vector generated with Node crypto (createHash("sha1")) during
    // authoring — an implementation independent of RustCrypto.
    const NODE_VECTOR: &str = "a1b2c3d43e50ab2f12b851a12f951c81064b3e57e05cd43e";
    const NODE_PASS: &str = "cyberdeck-os-apps";

    #[test]
    fn upstream_example_vector_verifies() {
        let parsed = MacOsSaltedSha1::parse(ST_HASH).unwrap();
        assert_eq!(parsed.salt, [0x86, 0x58, 0x68, 0x86]);
        assert_eq!(hex::encode(parsed.digest), &ST_HASH[8..]);
        assert!(parsed.verify(ST_PASS).unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn node_crypto_cross_vector_verifies() {
        let parsed = MacOsSaltedSha1::parse(NODE_VECTOR).unwrap();
        assert!(parsed.verify(NODE_PASS).unwrap());
        assert!(!parsed.verify("Cyberdeck-os-apps").unwrap());
        // The same password under a different salt verifies against its own
        // true digest (sha1 of salt a1b2c3d5 . NODE_PASS, Node crypto).
        let other = MacOsSaltedSha1::parse("a1b2c3d5fe67faed47d4e86ce1ad24e25761399ba89036cf").unwrap();
        assert!(other.verify(NODE_PASS).unwrap());
        // Mixing salts must not verify: the a1b2c3d4 digest under salt a1b2c3d5.
        let wrong_salt = MacOsSaltedSha1::parse(&format!("a1b2c3d5{}", &NODE_VECTOR[8..])).unwrap();
        assert!(!wrong_salt.verify(NODE_PASS).unwrap());
    }

    #[test]
    fn parse_rejects_out_of_policy_shapes() {
        // Length and hex alphabet are the upstream tokenizer contract.
        assert!(MacOsSaltedSha1::parse("").is_err());
        assert!(MacOsSaltedSha1::parse("86586886b8bd3c379d2e176243a7225e6aae969d293fe9a").is_err());
        assert!(MacOsSaltedSha1::parse("86586886b8bd3c379d2e176243a7225e6aae969d293fe9a99").is_err());
        assert!(MacOsSaltedSha1::parse("86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9extra").is_err());
        assert!(MacOsSaltedSha1::parse("86586886b8bd3c379d2e176243a7225e6aae969d293fe9gg").is_err());
        assert!(MacOsSaltedSha1::parse("8658688gb8bd3c379d2e176243a7225e6aae969d293fe9a9").is_err());
        assert!(MacOsSaltedSha1::parse("8658688-b8bd3c379d2e176243a7225e6aae969d293fe9a9").is_err());
    }
}

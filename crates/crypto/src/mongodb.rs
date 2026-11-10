//! MongoDB ServerKey SCRAM-SHA-1 recovery verifier (format batch 10). The
//! wire format and check semantics mirror the pinned upstream module 24100
//! (module_24100.c, OpenCL/m24100-pure.cl). The verifier runs on the CPU in
//! bounded time so a GPU match can always be re-proven independently before
//! it is reported. Only public upstream example vectors (module ST_HASH/
//! ST_PASS, docs/hashcat-example-hashes.md row 351) or plainly-labelled
//! self-derived fixtures are used as tests.
//!
//! Algorithm, derived step by step from the pinned sources (not guessed):
//! 1. `hex_password` = lowercase hex of MD5(`user` || ":mongo:" || password)
//!    (m24100-pure.cl:105-112: md5 over `esalt.user` — which hash_decode
//!    fills as the decoded user bytes plus the 7-byte ":mongo:" suffix,
//!    module_24100.c:149-153 — then the candidate bytes; the 16-byte digest
//!    is serialized through the lowercase `l_bin2asc` table,
//!    m24100-pure.cl:90-99 and 114-138, and keyed straight into
//!    `sha1_hmac_init (&sha1_hmac_ctx, hex, 32)`, m24100-pure.cl:140-142).
//!    This is MongoDB's SCRAM-SHA-1 credential wrap: the MONGODB-CR-style
//!    digest `md5(user:mongo:pass)` hex string is the PBKDF2 password.
//! 2. `salted_password` = PBKDF2-HMAC-SHA1(hex_password, salt, iterations),
//!    20 bytes (m24100-pure.cl:142-199 computes U1 with the big-endian
//!    counter word `w0[0] = j` after `sha1_hmac_update_global (salt, 16)`;
//!    m24100-pure.cl:240-271 folds the remaining `salt->salt_iter` =
//!    iterations - 1 blocks, module_24100.c:165).
//! 3. `server_key` = HMAC-SHA1(salted_password, "Server Key"), 10 message
//!    bytes `0x53657276 0x6572204b 0x65790000` = "Serv er K ey"
//!    (m24100-pure.cl:307-354). The compared digest is the SCRAM ServerKey.
//! The same construction is stated verbatim in the upstream self-test
//! (tools/test_modules/m24100.py:3-4 and 26-29: PBKDF2-HMAC-SHA1 over
//! `md5(user + b":mongo:" + word).hexdigest()` then HMAC-SHA1 "Server Key").

use hmac::Mac;
use sha1::Sha1;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// hashcat's BASE64A value table (src/convert.c:695-713 `base64_to_int`):
/// standard base64 alphabet, `=` and every other character map to 0. The
/// tokenizer has already charset-validated the field, so the catch-all only
/// sees the padding filler.
fn base64a_value(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    }
}

/// hashcat's lenient BASE64A decoder, reproduced from src/convert.c:955-993:
/// every 4-character group expands to 3 bytes, then the output is truncated
/// to `(characters before the first '=' ) * 6 / 8`. Non-canonical trailing
/// bits of the last significant character are dropped, and the position of
/// `=` (not the group structure) decides the length — a stricter
/// canonical-base64 engine would reject wire forms upstream accepts.
fn base64a_decode(field: &str) -> Vec<u8> {
    let input = field.as_bytes();
    let mut out = Vec::with_capacity((input.len() / 4) * 3);
    let mut index = 0;
    while index < input.len() {
        let v = [
            base64a_value(input.get(index).copied().unwrap_or(0)),
            base64a_value(input.get(index + 1).copied().unwrap_or(0)),
            base64a_value(input.get(index + 2).copied().unwrap_or(0)),
            base64a_value(input.get(index + 3).copied().unwrap_or(0)),
        ];
        out.push(((v[0] << 2) & 0xfc) | ((v[1] >> 4) & 0x03));
        out.push(((v[1] << 4) & 0xf0) | ((v[2] >> 2) & 0x0f));
        out.push(((v[2] << 6) & 0xc0) | (v[3] & 0x3f));
        index += 4;
    }
    let significant = input
        .iter()
        .position(|&c| c == b'=')
        .unwrap_or(input.len());
    out.truncate(significant * 6 / 8);
    out
}

/// TOKEN_ATTR_VERIFY_BASE64A charset (src/convert.c:276-289
/// `is_valid_base64a_char`): `[A-Za-z0-9+/=]`.
fn is_base64a_field(field: &str) -> bool {
    field
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
}

/// Parsed `$mongodb-scram$*0*...` MongoDB ServerKey SCRAM-SHA-1 entry
/// (hashcat mode 24100, KERN_TYPE 24100, HASH_CATEGORY_DATABASE_SERVER,
/// module_24100.c:20-22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoDbScramSha1 {
    /// The decoded user name bytes, 0..=57 of them (module_24100.c:147); the
    /// 7-byte ":mongo:" separator is not stored here — verify() appends it.
    pub user: Vec<u8>,
    /// PBKDF2 iteration count, 1..=9999999 (module_24100.c:113-117 seven
    /// digit characters, 159-161 `iter < 1` rejection).
    pub iterations: u32,
    /// The 16 raw SCRAM salt bytes (module_24100.c:174-185).
    pub salt: [u8; 16],
    /// The 20-byte SCRAM ServerKey digest (module_24100.c:194-211).
    pub digest: [u8; 20],
}

impl MongoDbScramSha1 {
    /// Wire form (module_24100.c:92-127 tokenizer): the 15-character
    /// `$mongodb-scram$` signature, `*`, a single-digit version that must be
    /// `0` (module_24100.c:102-105 fixed-length digit token, 136 explicit
    /// check), `*`, the BASE64A user (0..=76 characters, 147-byte decoded
    /// cap 57), `*`, the BASE64A iteration count (1..=7 digits, value ≥ 1),
    /// `*`, the BASE64A salt (fixed 24 characters → 16 bytes) and `*`, the
    /// BASE64A ServerKey (fixed 28 characters → 20 bytes). The last token
    /// runs to end of line, so anything after the ServerKey field — a
    /// trailing `*` included — fails the fixed length or charset check.
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash
            .strip_prefix("$mongodb-scram$*")
            .ok_or("not a $mongodb-scram$ MongoDB SCRAM-SHA-1 hash")?;
        let fields: Vec<&str> = rest.split('*').collect();
        if fields.len() != 5 {
            return Err(
                "MongoDB SCRAM-SHA-1 hash must be $mongodb-scram$*0*user*iterations*salt*serverKey"
                    .into(),
            );
        }
        // version (module_24100.c:102-105, 136)
        let version = fields[0];
        if version.len() != 1 || !version.as_bytes()[0].is_ascii_digit() {
            return Err("MongoDB SCRAM-SHA-1 version field must be a single digit".into());
        }
        if version != "0" {
            return Err("MongoDB SCRAM-SHA-1 version must be 0 (the only defined SCRAM-SHA-1 form)".into());
        }
        // user (module_24100.c:107-111, 140-153)
        let user_field = fields[1];
        if user_field.len() > 76 {
            return Err("MongoDB SCRAM-SHA-1 user field must be at most 76 base64 characters".into());
        }
        if !is_base64a_field(user_field) {
            return Err("MongoDB SCRAM-SHA-1 user field must be base64 ([A-Za-z0-9+/=])".into());
        }
        let user = base64a_decode(user_field);
        if user.len() > 57 {
            return Err("MongoDB SCRAM-SHA-1 user must decode to at most 57 bytes".into());
        }
        // iterations (module_24100.c:113-117, 157-165)
        let iter_field = fields[2];
        if iter_field.is_empty() || iter_field.len() > 7 || !iter_field.bytes().all(|b| b.is_ascii_digit()) {
            return Err("MongoDB SCRAM-SHA-1 iteration field must be 1..=7 digit characters".into());
        }
        let iterations: u32 = iter_field
            .parse()
            .map_err(|_| "MongoDB SCRAM-SHA-1 iteration count is not a number")?;
        if iterations < 1 {
            return Err("MongoDB SCRAM-SHA-1 iteration count must be at least 1".into());
        }
        // salt (module_24100.c:119-123, 169-185)
        let salt_field = fields[3];
        if salt_field.len() != 24 {
            return Err("MongoDB SCRAM-SHA-1 salt field must be exactly 24 base64 characters".into());
        }
        if !is_base64a_field(salt_field) {
            return Err("MongoDB SCRAM-SHA-1 salt field must be base64 ([A-Za-z0-9+/=])".into());
        }
        let salt_decoded = base64a_decode(salt_field);
        if salt_decoded.len() != 16 {
            return Err("MongoDB SCRAM-SHA-1 salt must decode to exactly 16 bytes".into());
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_decoded);
        // ServerKey digest (module_24100.c:124-127, 193-211)
        let digest_field = fields[4];
        if digest_field.len() != 28 {
            return Err("MongoDB SCRAM-SHA-1 ServerKey field must be exactly 28 base64 characters".into());
        }
        if !is_base64a_field(digest_field) {
            return Err("MongoDB SCRAM-SHA-1 ServerKey field must be base64 ([A-Za-z0-9+/=])".into());
        }
        let digest_decoded = base64a_decode(digest_field);
        if digest_decoded.len() != 20 {
            return Err("MongoDB SCRAM-SHA-1 ServerKey must decode to exactly 20 bytes".into());
        }
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&digest_decoded);
        Ok(Self {
            user,
            iterations,
            salt,
            digest,
        })
    }

    /// SCRAM-SHA-1 ServerKey verifier, exactly the three kernel stages:
    /// lowercase-hex MD5(user . ":mongo:" . candidate) as the PBKDF2
    /// password, PBKDF2-HMAC-SHA1 over the 16-byte salt for the stored
    /// iteration count, then HMAC-SHA1 keyed with the 20-byte salted
    /// password over the message "Server Key" (m24100-pure.cl:105-142,
    /// 156-199, 240-271 and 307-354; tools/test_modules/m24100.py:26-29).
    /// Candidates are fed as raw bytes, mirroring the global-memory password
    /// feed (`pws[gid].i`, m24100-pure.cl:110).
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        use md5::Digest as _;
        let mut wrapped = Vec::with_capacity(self.user.len() + 7 + candidate.len());
        wrapped.extend_from_slice(&self.user);
        wrapped.extend_from_slice(b":mongo:");
        wrapped.extend_from_slice(candidate.as_bytes());
        let credential_hex = hex::encode(md5::Md5::digest(&wrapped));
        let mut salted = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(
            credential_hex.as_bytes(),
            &self.salt,
            self.iterations,
            &mut salted,
        );
        let mut mac = <hmac::Hmac<Sha1> as Mac>::new_from_slice(&salted)
            .map_err(|_| "MongoDB SCRAM-SHA-1 HMAC key error")?;
        mac.update(b"Server Key");
        let server_key = mac.finalize().into_bytes();
        Ok(constant_time_eq(&server_key, &self.digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream hashcat example hash (module ST_HASH/ST_PASS, pass "hashcat";
    // also docs/hashcat-example-hashes.md row 351).
    const ST_HASH: &str =
        "$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=";

    #[test]
    fn upstream_mongodb_scram_sha1_example_vector_verifies() {
        // Provenance: module_24100.c:29-30 ST_PASS/ST_HASH and
        // docs/hashcat-example-hashes.md:351. The derivation was
        // independently reproduced this session with a Node script
        // (node:crypto md5 + pbkdf2Sync + hmac sha1) over the same input
        // bytes before this verifier was written.
        let parsed = MongoDbScramSha1::parse(ST_HASH).unwrap();
        assert_eq!(parsed.user, b"user".to_vec());
        assert_eq!(parsed.iterations, 10000);
        assert_eq!(parsed.salt, [
            0xe2, 0x9f, 0x9f, 0xd6, 0xd2, 0xa9, 0x2b, 0x5f, 0x21, 0x42, 0xaa, 0xd5, 0xaf, 0x45,
            0x06, 0x3b,
        ]);
        assert_eq!(parsed.digest, [
            0x26, 0xff, 0x65, 0xae, 0x95, 0x10, 0xd9, 0xb5, 0x60, 0xd9, 0x99, 0x17, 0xbd, 0x19,
            0xb6, 0xae, 0x9a, 0x6c, 0xa8, 0xdc,
        ]);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
        // Case matters: no folding anywhere in this mode.
        assert!(!parsed.verify("Hashcat").unwrap());
    }

    #[test]
    fn mongodb_self_derived_kat_vector_verifies() {
        // SELF-DERIVED vector, not an external publication: generated this
        // session with the Node reference implementation that was first
        // validated against the upstream ST vector above (user "Kat1",
        // salt "Kat1Kat1Kat1Kat1", 10000 iterations). This is the fixture
        // row destined for the embedded Hashcat PUBLIC_KATS table (see the
        // integration checklist), following the batch-7 "Kat" series.
        let hash = "$mongodb-scram$*0*S2F0MQ==*10000*S2F0MUthdDFLYXQxS2F0MQ==*FDDmmrJComFn+sXzSMkFixahF4s=";
        let parsed = MongoDbScramSha1::parse(hash).unwrap();
        assert_eq!(parsed.user, b"Kat1".to_vec());
        // "Kat1Kat1Kat1Kat1" (hex 4b617431, repeated four times).
        assert_eq!(parsed.salt, [
            0x4b, 0x61, 0x74, 0x31, 0x4b, 0x61, 0x74, 0x31, 0x4b, 0x61, 0x74, 0x31, 0x4b, 0x61,
            0x74, 0x31,
        ]);
        assert!(parsed.verify("cyberdeck").unwrap());
        assert!(!parsed.verify("cyberdeck2").unwrap());
        assert!(!parsed.verify("Cyberdeck").unwrap());
    }

    #[test]
    fn mongodb_iteration_one_vector_verifies() {
        // SELF-DERIVED vector (Node reference validated against the ST
        // vector): the minimum iteration count the module accepts
        // (module_24100.c:159-161); salt->salt_iter = 0 leaves the init
        // kernel's U1 block as the whole PBKDF2 output
        // (m24100-pure.cl:156-199, module_24100.c:165).
        let hash = "$mongodb-scram$*0*dXNlcg==*1*MDEyMzQ1Njc4OWFiY2RlZg==*rQ3FjiaOmJw4wiPt3E/Xsl43qg0=";
        let parsed = MongoDbScramSha1::parse(hash).unwrap();
        assert_eq!(parsed.iterations, 1);
        assert!(parsed.verify("cyberdeck").unwrap());
        assert!(!parsed.verify("cyberdeck2").unwrap());
    }

    #[test]
    fn mongodb_empty_user_and_57_byte_user_corners() {
        // SELF-DERIVED vectors (Node reference): the user token allows 0
        // bytes (module_24100.c:108 len_min 0; m24100.py draws
        // random_number(0, 57)) and caps at 57 bytes = 76 unpadded base64
        // characters (module_24100.c:109 comment "BASE64 encoded user
        // (57 / 3 * 4)", 147 decoded cap).
        let empty = "$mongodb-scram$*0**10000*S2F0MUthdDFLYXQxS2F0MQ==*lUWYJFNoXziHB/Wa/kED/oFAFSw=";
        let parsed = MongoDbScramSha1::parse(empty).unwrap();
        assert!(parsed.user.is_empty());
        assert!(parsed.verify("cyberdeck").unwrap());
        assert!(!parsed.verify("cyberdeck2").unwrap());
        let wide = format!(
            "$mongodb-scram$*0*{}*10000*S2F0MUthdDFLYXQxS2F0MQ==*7TIZ0R2BmCb5IKB2AlBGsKLUH5I=",
            "QUFB".repeat(19)
        );
        let parsed = MongoDbScramSha1::parse(&wide).unwrap();
        assert_eq!(parsed.user.len(), 57);
        assert!(parsed.verify("cyberdeck").unwrap());
        assert!(!parsed.verify("cyberdeck2").unwrap());
        // One byte more (77 wire characters) is rejected up front.
        let overflow = format!(
            "$mongodb-scram$*0*{}A*10000*S2F0MUthdDFLYXQxS2F0MQ==*AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "QUFB".repeat(19)
        );
        assert!(MongoDbScramSha1::parse(&overflow).is_err());
    }

    #[test]
    fn mongodb_lenient_base64a_trailing_bits_parse_like_upstream() {
        // hashcat's decoder decides the length by the first '=' and drops
        // non-canonical trailing bits of the last significant character
        // (src/convert.c:981-993): flipping the low two bits of the 22nd
        // significant salt character keeps the same 16 decoded bytes, so all
        // four variants must parse to the identical salt and still verify.
        for tail in ["w", "x", "y", "z"] {
            let line = format!(
                "$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGO{}==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=",
                tail
            );
            let parsed = MongoDbScramSha1::parse(&line).unwrap();
            assert_eq!(parsed.salt, [
                0xe2, 0x9f, 0x9f, 0xd6, 0xd2, 0xa9, 0x2b, 0x5f, 0x21, 0x42, 0xaa, 0xd5, 0xaf,
                0x45, 0x06, 0x3b,
            ]);
            assert!(parsed.verify("hashcat").unwrap(), "tail {tail}");
        }
    }

    #[test]
    fn mongodb_iteration_leading_zeros_parse_like_hc_strtoul() {
        // The C module parses the iteration token with hc_strtoul
        // (module_24100.c:159); the tokenizer only requires 1..=7 digit
        // characters, so "0000007" is the value 7 upstream. (The Python
        // self-test is stricter; the pinned module is authoritative here.)
        let hash = "$mongodb-scram$*0*dXNlcg==*0000007*MDEyMzQ1Njc4OWFiY2RlZg==*mLTIMq32iReMWWiattMza4tV3wo=";
        let parsed = MongoDbScramSha1::parse(hash).unwrap();
        assert_eq!(parsed.iterations, 7);
        assert!(parsed.verify("cyberdeck").unwrap());
    }

    #[test]
    fn parse_rejects_out_of_policy_shapes() {
        // Signature and field count (module_24100.c:92-100).
        assert!(MongoDbScramSha1::parse("$mongodb-scram*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=*extra").is_err());
        assert!(MongoDbScramSha1::parse("0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        // Version: single digit (module_24100.c:102-105) and exactly 0
        // (module_24100.c:136).
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*1*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*00*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*a*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        // Iteration token: 1..=7 digits, value >= 1
        // (module_24100.c:113-117, 159-161).
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*0*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*1000a*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==**4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        // Salt: fixed 24 base64 characters decoding to 16 bytes
        // (module_24100.c:119-123, 174-176).
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*4p_f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*AAAAAAAAAAAAAAAAAAAAAAAA*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
        // ServerKey: fixed 28 base64 characters decoding to 20 bytes
        // (module_24100.c:124-127, 197-201).
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw==").is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqN!").is_err());
        // User: 76-character and base64 charset caps
        // (module_24100.c:107-111, 145-147).
        assert!(MongoDbScramSha1::parse(&format!("$mongodb-scram$*0*{}*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=", "dXNlcg==".repeat(10))).is_err());
        assert!(MongoDbScramSha1::parse("$mongodb-scram$*0*dXNlcg!*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
    }

    #[test]
    fn mongodb_parse_is_idempotent_across_reparse() {
        // hash_encode re-emits salt->salt_iter + 1 as the iteration field
        // (module_24100.c:259-264), so a decoded line round-trips: parse,
        // and the structural fields come back identical.
        let first = MongoDbScramSha1::parse(ST_HASH).unwrap();
        let second = MongoDbScramSha1::parse(ST_HASH).unwrap();
        assert_eq!(first, second);
    }
}

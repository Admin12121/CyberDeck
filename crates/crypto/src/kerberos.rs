//! Kerberos 5 etype 23 (RC4-HMAC) recovery verifiers (format batch B4). Wire
//! formats and check semantics mirror the pinned upstream hashcat modules
//! 13100 (`$krb5tgs$23$`, TGS-REP) and 18200 (`$krb5asrep$23$`, AS-REP),
//! cross-checked against the m13100/m18200 pure kernels and the upstream
//! tools/test_modules generators. Every verifier runs on the CPU in bounded
//! time so a GPU match can always be re-proven independently before it is
//! reported. Only public upstream example vectors are used as fixtures.
//!
//! Etype 23 keys are saltless: the RC4-HMAC schedule derives everything from
//! the NT hash, so the account info carried on the wire (realm, SPN, UPN) is
//! metadata only and never enters the crypto. The two formats differ in the
//! HMAC usage constant (2 for TGS-REP tickets, 8 for AS-REP encrypted parts)
//! and in the ASN.1 markers the decrypted plaintext must show. Frontend
//! algorithm names: "kerberos-tgs-rep" (13100) and "kerberos-as-rep" (18200).

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;

/// RFC 4757 usage for the TGS-REP ticket encrypted part (hashcat 13100).
const TGS_REP_USAGE: u32 = 2;
/// RFC 4757 usage for the AS-REP encrypted part (hashcat 18200); Windows
/// quirk: 8, not the RFC 4120 value 3.
const AS_REP_USAGE: u32 = 8;
/// The upstream esalt stores account info in a 512 x u32 buffer; fields of
/// 2048 or more bytes are rejected at parse time.
const ACCOUNT_INFO_MAX_BYTES: usize = 2047;
/// The checksum field is always 32 hex characters (16 bytes).
const CHECKSUM_HEX: usize = 32;
/// Upstream token bounds: edata2 carries 64..=40958 hex characters.
const EDATA2_MIN_HEX: usize = 64;
const EDATA2_MAX_HEX: usize = 40958;
/// The ASN.1 gate reads plaintext bytes 8..20 (TGS) or 8..16 (AS-REP); parse
/// guarantees at least 32 edata2 bytes, but the core stays defensive.
const HEADER_BYTES: usize = 20;

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn md4(data: &[u8]) -> [u8; 16] {
    <Md4 as md4::Digest>::digest(data).into()
}

fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("MD5 output is always a valid HMAC key");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// RC4 stream cipher. Self-contained duplicate of `crate::documents::rc4` so
/// this module compiles and tests standalone; identical construction.
fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn checksum_and_edata2(tail: &str) -> Result<(&str, &str), String> {
    let (checksum_hex, edata2_hex) = tail
        .split_once('$')
        .ok_or("kerberos hash is missing the edata2 separator")?;
    if checksum_hex.len() != CHECKSUM_HEX
        || !checksum_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid kerberos hash checksum field".into());
    }
    if edata2_hex.len() < EDATA2_MIN_HEX
        || edata2_hex.len() > EDATA2_MAX_HEX
        || edata2_hex.len() % 2 != 0
        || !edata2_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid kerberos hash edata2 field".into());
    }
    Ok((checksum_hex, edata2_hex))
}

fn checksum_bytes(checksum_hex: &str) -> [u8; 16] {
    let mut checksum = [0u8; 16];
    for (index, byte) in checksum_hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = (byte[0] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (byte[1] as char).to_digit(16).unwrap_or(0) as u8;
        checksum[index] = (hi << 4) | lo;
    }
    checksum
}

/// Shared etype 23 check (RFC 4757 as implemented by the upstream kernels):
/// K1 = HMAC-MD5(NT hash, LE32(usage)); K3 = HMAC-MD5(K1, checksum); the
/// edata2 plaintext must pass the ASN.1 header gate and HMAC-MD5(K1,
/// plaintext) must reproduce the checksum. The kernels decrypt the 16-byte
/// header first and only run the full RC4 pass for candidates that survive
/// the gate; this core keeps that two-phase shape.
fn verify_etype23(
    candidate: &str,
    usage: u32,
    checksum: &[u8; 16],
    edata2: &[u8],
    header_ok: fn(&[u8]) -> bool,
) -> bool {
    if edata2.len() < HEADER_BYTES {
        return false;
    }
    let nt_hash = md4(&utf16le(candidate));
    let k1 = hmac_md5(&nt_hash, &usage.to_le_bytes());
    let k3 = hmac_md5(&k1, checksum);
    let header = rc4(&k3, &edata2[..HEADER_BYTES]);
    if !header_ok(&header) {
        return false;
    }
    let plaintext = rc4(&k3, edata2);
    let mac = hmac_md5(&k1, &plaintext);
    constant_time_eq(&mac, checksum)
}

/// Plaintext ASN.1 gate from m13100_a0-pure.cl: the enc-ticket-part is DER
/// tagged 0x63 with either a one-byte long-form length (63 81 .. 30) or a
/// two-byte one (63 82 .. ..), and the key field shows 03 05 00 (BIT STRING,
/// etype follows) or the pre-auth variant A0 07 03 05.
fn tgs_rep_header_ok(header: &[u8]) -> bool {
    let tag = u32::from_le_bytes(header[8..12].try_into().expect("16-byte header"));
    let key = u32::from_le_bytes(header[16..20].try_into().expect("20-byte header"));
    let shape = (tag & 0xff00_ffff) == 0x3000_8163 || (tag & 0x0000_ffff) == 0x0000_8263;
    let key_field = (key & 0x00ff_ffff) == 0x0000_0503 || key == 0x0503_07a0;
    shape && key_field
}

/// Plaintext ASN.1 gate from m18200_a0-pure.cl: the AS-REP encrypted part is
/// application tag 0x79 with a short length (79 <0x80 30), a one-byte
/// long-form length (79 81 .. 30) or a two-byte one (79 82 .. .. 30).
fn as_rep_header_ok(header: &[u8]) -> bool {
    let tag = u32::from_le_bytes(header[8..12].try_into().expect("16-byte header"));
    let next = u32::from_le_bytes(header[12..16].try_into().expect("16-byte header"));
    (tag & 0x00ff_80ff) == 0x0030_0079
        || (tag & 0xff00_ffff) == 0x3000_8179
        || ((tag & 0x0000_ffff) == 0x0000_8279 && (next & 0x0000_00ff) == 0x0000_0030)
}

// ------------------------------------------------- Kerberos 5 TGS-REP (13100)

/// Parsed `$krb5tgs$` TGS-REP entry (hashcat mode 13100). All three upstream
/// wire forms are accepted; the format is preserved for re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTgsRep {
    /// Upstream wire format: 1 = hashcat `$krb5tgs$23$*user$realm$spn*$...`,
    /// 2 = hashcat `$krb5tgs$23$checksum$edata2`, 3 = john
    /// `$krb5tgs$spn:checksum$edata2`.
    pub format: u8,
    /// Realm/SPN metadata exactly as the upstream esalt stores it: format 1
    /// keeps the surrounding asterisks and trailing separator
    /// (`*user$realm$test/spn*$`), format 2 is empty, format 3 carries the
    /// bare SPN. Never used by the etype 23 crypto.
    pub account_info: String,
    /// The 16-byte RC4-HMAC checksum from the wire.
    pub checksum: [u8; 16],
    /// The RC4-encrypted ticket (DER enc-ticket-part behind an 8-byte nonce).
    pub edata2: Vec<u8>,
}

impl KerberosTgsRep {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash.strip_prefix("$krb5tgs$").ok_or("not a $krb5tgs$ hash")?;
        // The upstream module routes on the literal "23$" after the
        // signature: with a leading '*' that is format 1, without it format
        // 2; anything else falls back to the john format 3 (which carries no
        // etype field, so non-23 etypes only survive if the remainder
        // happens to parse as format 3).
        if let Some(rest) = rest.strip_prefix("23$") {
            if let Some(body) = rest.strip_prefix('*') {
                // Format 1: the account info token runs from the opening '*'
                // through the closing '*' plus the following separator
                // character, exactly like the upstream esalt stores it.
                let close = body
                    .find('*')
                    .ok_or("kerberos tgs-rep hash has an unterminated account info field")?;
                let account_len = close + 3;
                if account_len > ACCOUNT_INFO_MAX_BYTES {
                    return Err("kerberos account info exceeds the 2047 byte wire limit".into());
                }
                if account_len > rest.len() {
                    return Err("kerberos tgs-rep hash is truncated".into());
                }
                let (checksum_hex, edata2_hex) = checksum_and_edata2(&rest[account_len..])?;
                return Ok(Self {
                    format: 1,
                    account_info: rest[..account_len].to_string(),
                    checksum: checksum_bytes(checksum_hex),
                    edata2: hex::decode(edata2_hex)
                        .map_err(|_| "invalid kerberos hash edata2 field")?,
                });
            }
            let (checksum_hex, edata2_hex) = checksum_and_edata2(rest)?;
            return Ok(Self {
                format: 2,
                account_info: String::new(),
                checksum: checksum_bytes(checksum_hex),
                edata2: hex::decode(edata2_hex).map_err(|_| "invalid kerberos hash edata2 field")?,
            });
        }
        let (spn, tail) = rest
            .split_once(':')
            .ok_or("kerberos tgs-rep hash is missing the ':' separator")?;
        if spn.len() > ACCOUNT_INFO_MAX_BYTES {
            return Err("kerberos account info exceeds the 2047 byte wire limit".into());
        }
        let (checksum_hex, edata2_hex) = checksum_and_edata2(tail)?;
        Ok(Self {
            format: 3,
            account_info: spn.to_string(),
            checksum: checksum_bytes(checksum_hex),
            edata2: hex::decode(edata2_hex).map_err(|_| "invalid kerberos hash edata2 field")?,
        })
    }

    /// RC4-HMAC (RFC 4757) over the encrypted ticket with usage 2: NT hash
    /// keys HMAC-MD5 over LE32(2), that key keys HMAC-MD5 over the wire
    /// checksum to make the RC4 key, and the checksum must equal HMAC-MD5
    /// of the decrypted ticket after the ASN.1 markers check out.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        Ok(verify_etype23(
            candidate,
            TGS_REP_USAGE,
            &self.checksum,
            &self.edata2,
            tgs_rep_header_ok,
        ))
    }
}

// ------------------------------------------------- Kerberos 5 AS-REP (18200)

/// Parsed `$krb5asrep$` AS-REP entry (hashcat mode 18200). Both upstream
/// wire forms are accepted; the format is preserved for re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosAsRep {
    /// Upstream wire format: 1 = hashcat `$krb5asrep$23$upn:...`, 2 = john
    /// `$krb5asrep$upn:...`.
    pub format: u8,
    /// User principal name (up to the first ':'); metadata only, never used
    /// by the etype 23 crypto.
    pub account_info: String,
    /// The 16-byte RC4-HMAC checksum from the wire.
    pub checksum: [u8; 16],
    /// The RC4-encrypted enc-part (DER application tag 0x79 behind an
    /// 8-byte nonce).
    pub edata2: Vec<u8>,
}

impl KerberosAsRep {
    pub fn parse(hash: &str) -> Result<Self, String> {
        let rest = hash.strip_prefix("$krb5asrep$").ok_or("not a $krb5asrep$ hash")?;
        // The literal "23$" after the signature selects the hashcat format;
        // anything else is the john format, which carries no etype field.
        let (format, body) = if let Some(body) = rest.strip_prefix("23$") {
            (1, body)
        } else {
            (2, rest)
        };
        let (upn, tail) = body
            .split_once(':')
            .ok_or("kerberos as-rep hash is missing the ':' separator")?;
        if upn.len() > ACCOUNT_INFO_MAX_BYTES {
            return Err("kerberos account info exceeds the 2047 byte wire limit".into());
        }
        let (checksum_hex, edata2_hex) = checksum_and_edata2(tail)?;
        Ok(Self {
            format,
            account_info: upn.to_string(),
            checksum: checksum_bytes(checksum_hex),
            edata2: hex::decode(edata2_hex).map_err(|_| "invalid kerberos hash edata2 field")?,
        })
    }

    /// RC4-HMAC (RFC 4757) over the encrypted enc-part with usage 8 (the
    /// Windows AS-REP value): NT hash keys HMAC-MD5 over LE32(8), that key
    /// keys HMAC-MD5 over the wire checksum to make the RC4 key, and the
    /// checksum must equal HMAC-MD5 of the decrypted enc-part after the
    /// ASN.1 markers check out.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        Ok(verify_etype23(
            candidate,
            AS_REP_USAGE,
            &self.checksum,
            &self.edata2,
            as_rep_header_ok,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream hashcat example hashes (module ST_HASH/ST_PASS, pass "hashcat").
    const TGS_REP_ST: &str = "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a";
    const AS_REP_ST: &str = "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac";

    #[test]
    fn upstream_tgs_rep_example_vector_verifies() {
        let parsed = KerberosTgsRep::parse(TGS_REP_ST).unwrap();
        assert_eq!(parsed.format, 1);
        assert_eq!(parsed.account_info, "*user$realm$test/spn*$");
        assert_eq!(parsed.checksum.len(), 16);
        assert_eq!(parsed.edata2.len(), 187);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_as_rep_example_vector_verifies() {
        let parsed = KerberosAsRep::parse(AS_REP_ST).unwrap();
        assert_eq!(parsed.format, 1);
        assert_eq!(parsed.account_info, "user@domain.com");
        assert_eq!(parsed.checksum.len(), 16);
        assert_eq!(parsed.edata2.len(), 234);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn kerberos_accepts_the_alternate_wire_forms() {
        // The ST checksum/edata2 re-expressed in the bare hashcat format 2,
        // the john TGS format 3 and the john AS-REP format 2; the account
        // info never enters the etype 23 crypto, so all verify identically.
        let checksum = "b548e10f5694ae018d7ad63c257af7dc";
        let edata2 = &TGS_REP_ST[TGS_REP_ST.rfind('$').unwrap() + 1..];
        let bare = KerberosTgsRep::parse(&format!("$krb5tgs$23${checksum}${edata2}")).unwrap();
        assert_eq!(bare.format, 2);
        assert!(bare.account_info.is_empty());
        assert!(bare.verify("hashcat").unwrap());
        let john = KerberosTgsRep::parse(&format!("$krb5tgs$test/spn:{checksum}${edata2}")).unwrap();
        assert_eq!(john.format, 3);
        assert_eq!(john.account_info, "test/spn");
        assert!(john.verify("hashcat").unwrap());
        let as_checksum = "3e156ada591263b8aab0965f5aebd837";
        let as_edata2 = &AS_REP_ST[AS_REP_ST.rfind('$').unwrap() + 1..];
        let john_as = KerberosAsRep::parse(&format!(
            "$krb5asrep$user@domain.com:{as_checksum}${as_edata2}"
        ))
        .unwrap();
        assert_eq!(john_as.format, 2);
        assert_eq!(john_as.account_info, "user@domain.com");
        assert!(john_as.verify("hashcat").unwrap());
        // The upstream VERIFY_HEX token attribute accepts upper case hex.
        let upper = KerberosTgsRep::parse(&format!(
            "$krb5tgs$23$*user$realm$test/spn*${}${}",
            checksum.to_uppercase(),
            edata2.to_uppercase()
        ))
        .unwrap();
        assert!(upper.verify("hashcat").unwrap());
    }

    #[test]
    fn tgs_rep_and_as_rep_usages_are_not_interchangeable() {
        // The same RC4-HMAC schedule with a different LE32 usage constant
        // and a different plaintext gate: each format must reject the
        // other's checksum/edata2 pair.
        let tgs = KerberosTgsRep::parse(TGS_REP_ST).unwrap();
        let as_rep = KerberosAsRep::parse(AS_REP_ST).unwrap();
        let tgs_as = KerberosAsRep::parse(&format!(
            "$krb5asrep$23$user@domain.com:{}${}",
            hex::encode(tgs.checksum),
            hex::encode(&tgs.edata2)
        ))
        .unwrap();
        assert!(!tgs_as.verify("hashcat").unwrap());
        let as_tgs = KerberosTgsRep::parse(&format!(
            "$krb5tgs$23$*user$realm$test/spn*${}${}",
            hex::encode(as_rep.checksum),
            hex::encode(&as_rep.edata2)
        ))
        .unwrap();
        assert!(!as_tgs.verify("hashcat").unwrap());
    }

    #[test]
    fn kerberos_targets_self_detect_through_the_recovery_target_parse() {
        // The embedded Hashcat KAT gate parses each fixture with an empty
        // algorithm hint; the $-markers must select the right verifier.
        for (hash, mode) in [(TGS_REP_ST, "kerberos-tgs-rep"), (AS_REP_ST, "kerberos-as-rep")] {
            let target = crate::recovery::RecoveryTarget::parse("", hash).unwrap();
            assert!(target.is_match(b"hashcat").unwrap(), "{mode} positive");
            assert!(!target.is_match(b"hashcatx").unwrap(), "{mode} negative");
        }
    }

    #[test]
    fn kerberos_parse_rejects_out_of_policy_shapes() {
        let edata2 = &TGS_REP_ST[TGS_REP_ST.rfind('$').unwrap() + 1..];
        let checksum = "b548e10f5694ae018d7ad63c257af7dc";
        // Signature and structure.
        assert!(KerberosTgsRep::parse("").is_err());
        assert!(KerberosTgsRep::parse("$krb5tgs$").is_err());
        assert!(KerberosTgsRep::parse("$krb5tgs$23$").is_err());
        assert!(KerberosAsRep::parse("$krb5asrep$").is_err());
        assert!(KerberosAsRep::parse("$krb5asrep$23$user@domain.com").is_err());
        // Format 1 account info needs its closing asterisk and separator.
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23$*user$realm${checksum}${edata2}")).is_err());
        assert!(KerberosTgsRep::parse("$krb5tgs$23$*user$realm$test/spn*").is_err());
        // Checksum field must be exactly 32 hex characters.
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23${}${edata2}", &checksum[..31])).is_err());
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23${checksum}0${edata2}")).is_err());
        assert!(KerberosAsRep::parse(&format!(
            "$krb5asrep$23$user@domain.com:{}${edata2}",
            "3e156ada591263b8aab0965f5aebd83"
        ))
        .is_err());
        // Missing separator between checksum and edata2.
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23${checksum}{edata2}")).is_err());
        // edata2 bounds: below 64 hex characters, odd count, non-hex.
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23${checksum}${}", &edata2[..62])).is_err());
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23${checksum}${edata2}0")).is_err());
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23${checksum}$g{}", &edata2[1..])).is_err());
        // Account info beyond the 2047 byte esalt cap; the boundary itself
        // parses (the format 1 token is interior + "*$" around it).
        let long_spn = "a".repeat(2048);
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs${long_spn}:{checksum}${edata2}")).is_err());
        assert!(KerberosAsRep::parse(&format!("$krb5asrep$23${long_spn}:{checksum}${edata2}")).is_err());
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$23$*{}*$${edata2}", "a".repeat(2045))).is_err());
        let boundary = KerberosTgsRep::parse(&format!(
            "$krb5tgs$23$*{}*${checksum}${edata2}",
            "a".repeat(2044)
        ))
        .unwrap();
        assert_eq!(boundary.account_info.len(), 2047);
        // A non-23 etype in the hashcat position falls through to the john
        // branch and finds no ':' separator.
        assert!(KerberosTgsRep::parse(&format!("$krb5tgs$17$*user$realm${checksum}${edata2}")).is_err());
    }
}

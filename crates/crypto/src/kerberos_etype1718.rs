//! Kerberos 5 TGS-REP etype 17/18 recovery verifiers (format batch
//! os-and-apps). Wire formats and check semantics mirror the pinned upstream
//! hashcat modules 19600 (etype 17, AES128-CTS-HMAC-SHA1-96) and 19700 (etype
//! 18, AES256-CTS-HMAC-SHA1-96), cross-checked against the m19600/m19700
//! pure kernels and the upstream tools/test_modules/m19600.py / m19700.py
//! generators. Every verifier runs on the CPU in bounded time so a GPU match
//! can always be re-proven independently before it is reported.
//!
//! Algorithm (RFC 3961/3962 as implemented by the upstream kernels):
//!   1. seed = PBKDF2-HMAC-SHA1(password, upper(realm) . user, 4096, keysize)
//!      — the module stores uppercase(domain) . user in account_info
//!      (module_19600.c:220-234) and 4096 PBKDF2 iterations.
//!   2. key = DK(nfold("kerberos", 16), seed) with the upstream DK/DR chain
//!      (E(k, constant, iv=0), each 16-byte output block re-encrypted with
//!      iv=0 until keysize bytes exist; m19600-pure.cl:347-414, m19600.py
//!      `_dk`). keysize is 16 for etype 17 and 32 for etype 18.
//!   3. ki = DK(nfold(usage 2 . 0x55), key), ke = DK(nfold(usage 2 . 0xAA),
//!      key) — checksum and encryption keys for key usage 2 (TGS-REP ticket).
//!   4. plaintext = AES-CTS-decrypt(ke, iv=0, edata2) — RFC 2040 CBC-CS3
//!      ciphertext stealing exactly as the comp kernels implement it. For a
//!      full 16-byte final block the kernels keep the same crafted-block
//!      formula (m19600-pure.cl:923-944), which places the last two
//!      plaintext blocks in swapped ciphertext positions; this core mirrors
//!      that kernel-exact shape. Every upstream ground-truth vector (both
//!      ST_HASHes, 195 bytes, X = 3) exercises the partial-block path where
//!      kernel and RFC agree; no authoritative X = 16 vector exists (the
//!      upstream generator's aligned path is broken by a Python [-0:] quirk,
//!      so upstream can neither emit nor crack aligned tickets) — the X = 16
//!      vector below is cross-implementation only (Node <-> Rust).
//!   5. the decrypted enc-ticket-part must show the ASN.1 markers the kernel
//!      gates on (m19600-pure.cl:486-488): tag 63 81 .. 30 or 63 82 at
//!      plaintext[16..20] (behind the 16-byte confounder) and the etype field
//!      03 05 00 or A0 07 03 05 at plaintext[24..28].
//!   6. checksum = HMAC-SHA1(ki, plaintext) truncated to 12 bytes
//!      (m19600-pure.cl:983-985; the wire carries 24 hex characters).
//!
//! The SPN wire segment is metadata: only upper(realm) . user enters the
//! crypto (module_19600.c:220-234). Frontend algorithm names:
//! "kerberos-tgs-rep-17" (19600) and "kerberos-tgs-rep-18" (19700).
//! This file is self-contained on purpose: it compiles both inside
//! cyberdeck-crypto and standalone in the authoring test crate.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::Mac;
use sha1::Sha1;

/// etype 17 key size (AES-128).
pub const ETYPE_17_KEYSIZE: usize = 16;
/// etype 18 key size (AES-256).
pub const ETYPE_18_KEYSIZE: usize = 32;
/// PBKDF2 iteration count (module_19600.c:265, salt_iter 4096 - 1 plus the
/// kernel's first block pass).
pub const PBKDF2_ITERATIONS: u32 = 4096;
/// The wire checksum is HMAC-SHA1 truncated to 12 bytes (24 hex characters).
const CHECKSUM_HEX: usize = 24;
/// Upstream token bounds: edata2 carries 64..=40960 hex characters
/// (module_19600.c:141-144), user and realm 1..=512 bytes each.
const EDATA2_MIN_HEX: usize = 64;
const EDATA2_MAX_HEX: usize = 40960;
const ACCOUNT_FIELD_MAX: usize = 512;
/// DK well-known constants precomputed upstream (m19600-pure.cl:350-353,
/// 383-386, 403-406; identical in m19700-pure.cl).
const NFOLD_KERBEROS: [u8; 16] = [
    0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73, 0x7b, 0x9b, 0x5b, 0x2b, 0x93, 0x13, 0x2b, 0x93,
];
const NFOLD_KI: [u8; 16] = [
    0x62, 0xdc, 0x6e, 0x37, 0x1a, 0x63, 0xa8, 0x09, 0x58, 0xac, 0x56, 0x2b, 0x15, 0x40, 0x4a, 0xc5,
];
const NFOLD_KE: [u8; 16] = [
    0xb5, 0xb0, 0x58, 0x2c, 0x14, 0xb6, 0x50, 0x0a, 0xad, 0x56, 0xab, 0x55, 0xaa, 0x80, 0x55, 0x6a,
];

/// Parsed `$krb5tgs$17$`/`$krb5tgs$18$` TGS-REP entry (hashcat modes
/// 19600/19700). Both upstream wire forms are accepted and the account info
/// is preserved for re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTgs1718 {
    /// 17 (AES-128) or 18 (AES-256).
    pub etype: u8,
    /// Account user exactly as it appears on the wire (1..=512 bytes).
    pub user: String,
    /// Account realm exactly as it appears on the wire (1..=512 bytes).
    pub realm: String,
    /// The `*spn*$` metadata segment when the line carries one; never used
    /// by the etype 17/18 crypto.
    pub spn: Option<String>,
    /// The 12-byte truncated HMAC-SHA1 checksum from the wire.
    pub checksum: [u8; 12],
    /// The AES-CTS encrypted enc-ticket-part (DER behind a 16-byte
    /// confounder).
    pub edata2: Vec<u8>,
}

impl KerberosTgs1718 {
    /// Hashcat mode this hash runs as: 19600 (etype 17) or 19700 (etype 18).
    pub fn gpu_mode(&self) -> u32 {
        if self.etype == 17 { 19600 } else { 19700 }
    }

    pub fn parse(hash: &str) -> Result<Self, String> {
        let (etype, rest) = if let Some(rest) = hash.strip_prefix("$krb5tgs$17$") {
            (17u8, rest)
        } else if let Some(rest) = hash.strip_prefix("$krb5tgs$18$") {
            (18u8, rest)
        } else {
            return Err("not a $krb5tgs$17$/$krb5tgs$18$ hash".into());
        };
        // Mirror the upstream tokenizer (module_19600.c:115-160): form A is
        // user$realm$checksum$edata2; form B is user$realm$*spn*$checksum$
        // edata2 where the SPN segment runs from its opening '*' through the
        // closing '*' plus the following separator character. A '*' inside
        // the user or realm fields misaligns the upstream fixed-length token
        // and is rejected there; it is rejected here as well.
        let mut fields = rest.splitn(3, '$');
        let user = fields.next().unwrap_or("");
        let realm = fields.next().unwrap_or("");
        let remainder = fields.next().unwrap_or("");
        if user.is_empty() || user.len() > ACCOUNT_FIELD_MAX || user.contains('*') {
            return Err("invalid kerberos tgs-rep user field".into());
        }
        if realm.is_empty() || realm.len() > ACCOUNT_FIELD_MAX || realm.contains('*') {
            return Err("invalid kerberos tgs-rep realm field".into());
        }
        let (spn, tail) = if let Some(body) = remainder.strip_prefix('*') {
            let close = body
                .find('*')
                .ok_or("kerberos tgs-rep hash has an unterminated SPN segment")?;
            if close + 1 >= body.len() {
                return Err("kerberos tgs-rep hash is truncated".into());
            }
            let spn_token = &remainder[..close + 3];
            if !spn_token.ends_with("*$") {
                return Err("invalid kerberos tgs-rep SPN segment".into());
            }
            (Some(spn_token.to_string()), &body[close + 2..])
        } else {
            (None, remainder)
        };
        let mut tail_fields = tail.split('$');
        let checksum_hex = tail_fields.next().unwrap_or("");
        let edata2_hex = tail_fields.next().unwrap_or("");
        if tail_fields.next().is_some() {
            return Err("kerberos tgs-rep hash has too many fields".into());
        }
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
        let checksum_bytes = hex::decode(checksum_hex).map_err(|_| "invalid kerberos checksum")?;
        let edata2 = hex::decode(edata2_hex).map_err(|_| "invalid kerberos edata2")?;
        let mut checksum = [0u8; 12];
        checksum.copy_from_slice(&checksum_bytes);
        Ok(Self {
            etype,
            user: user.to_string(),
            realm: realm.to_string(),
            spn,
            checksum,
            edata2,
        })
    }

    /// The PBKDF2 salt: uppercase(realm) . user (module_19600.c:226-232,
    /// ASCII uppercase like the upstream `uppercase ()`).
    pub fn account_info(&self) -> Vec<u8> {
        let mut salt: Vec<u8> = self
            .realm
            .bytes()
            .map(|byte| byte.to_ascii_uppercase())
            .collect();
        salt.extend_from_slice(self.user.as_bytes());
        salt
    }

    /// Full upstream check: PBKDF2 seed, DK chain, AES-CTS decrypt of the
    /// ticket, ASN.1 markers gate and the 12-byte truncated HMAC-SHA1.
    pub fn verify(&self, candidate: &str) -> Result<bool, String> {
        let keysize = if self.etype == 17 { ETYPE_17_KEYSIZE } else { ETYPE_18_KEYSIZE };
        let mut seed = vec![0u8; keysize];
        pbkdf2::pbkdf2_hmac::<Sha1>(
            candidate.as_bytes(),
            &self.account_info(),
            PBKDF2_ITERATIONS,
            &mut seed,
        );
        let key_bytes = dk(&NFOLD_KERBEROS, &seed);
        let ki = dk(&NFOLD_KI, &key_bytes);
        let ke = dk(&NFOLD_KE, &key_bytes);
        let Some(plain) = aes_cts_decrypt(&ke, &self.edata2) else {
            return Ok(false);
        };
        if !enc_ticket_part_gate(&plain) {
            return Ok(false);
        }
        let mut mac = <hmac::Hmac<Sha1> as Mac>::new_from_slice(&ki)
            .map_err(|_| "kerberos HMAC key error")?;
        mac.update(&plain);
        let tag = mac.finalize().into_bytes();
        Ok(constant_time_eq(&tag[..12], &self.checksum))
    }
}

/// RFC 3961 DK/DR as implemented upstream (m19600.py `_dk`): AES-CBC-encrypt
/// the 16-byte folded constant with a zero IV, then re-encrypt each output
/// block with a zero IV until keysize bytes exist. With a zero IV the chain
/// is plain ECB over the previous output block.
fn dk(nfolded: &[u8; 16], key: &[u8]) -> Vec<u8> {
    let mut block = aes_ecb_encrypt(key, nfolded);
    let mut out = block.to_vec();
    while out.len() < key.len() {
        block = aes_ecb_encrypt(key, &block);
        out.extend_from_slice(&block);
    }
    out.truncate(key.len());
    out
}

fn aes_ecb_encrypt(key: &[u8], block: &[u8]) -> [u8; 16] {
    let mut out = *GenericArray::from_slice(block);
    if key.len() == ETYPE_17_KEYSIZE {
        aes::Aes128::new_from_slice(key).expect("etype 17 key is 16 bytes").encrypt_block(&mut out);
    } else {
        aes::Aes256::new_from_slice(key).expect("etype 18 key is 32 bytes").encrypt_block(&mut out);
    }
    out.into()
}

fn aes_ecb_decrypt(key: &[u8], block: &[u8]) -> [u8; 16] {
    let mut out = *GenericArray::from_slice(block);
    if key.len() == ETYPE_17_KEYSIZE {
        aes::Aes128::new_from_slice(key).expect("etype 17 key is 16 bytes").decrypt_block(&mut out);
    } else {
        aes::Aes256::new_from_slice(key).expect("etype 18 key is 32 bytes").decrypt_block(&mut out);
    }
    out.into()
}

/// AES-CBC ciphertext-stealing decrypt (RFC 2040 CBC-CS3 as implemented by
/// the upstream comp kernels, m19600-pure.cl:472-979): plain CBC over the
/// leading full blocks, then the crafted last two blocks. The ciphertext
/// needs at least the two final blocks (32 bytes); with a zero-length CBC
/// region the previous block is the zero IV.
fn aes_cts_decrypt(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 {
        return None;
    }
    let total = data.len();
    let last = if total % 16 == 0 { 16 } else { total % 16 };
    let need = total - 16 - last; // plain-CBC region, a multiple of 16
    let mut plain = Vec::with_capacity(total);
    // C1..Ck: standard CBC with a zero IV.
    let mut previous = [0u8; 16];
    for block in data[..need].chunks_exact(16) {
        let decrypted = aes_ecb_decrypt(key, block);
        plain.extend_from_slice(&xor16(&decrypted, &previous));
        previous.copy_from_slice(block);
    }
    // C(n-1) full block, Cn = final `last` bytes.
    let c_n1 = &data[need..need + 16];
    let c_n = &data[need + 16..];
    let d = aes_ecb_decrypt(key, c_n1);
    // P(n) = Cn ^ D[..last]; P(n-1) = AES_dec(Cn || D[last..]) ^ C(n-2).
    let mut crafted = [0u8; 16];
    crafted[..last].copy_from_slice(c_n);
    crafted[last..].copy_from_slice(&d[last..]);
    let n1 = aes_ecb_decrypt(key, &crafted);
    plain.extend_from_slice(&xor16(&n1, &previous));
    plain.extend_from_slice(&d[..last]);
    // The last `last` bytes xor against Cn, not against D.
    let stolen = &mut plain[total - last..];
    for (index, byte) in c_n.iter().enumerate() {
        stolen[index] ^= byte;
    }
    Some(plain)
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for index in 0..16 {
        out[index] = a[index] ^ b[index];
    }
    out
}

/// Plaintext ASN.1 gate from the comp kernels (m19600-pure.cl:486-488): the
/// enc-ticket-part is DER tagged 0x63 with either a one-byte long-form length
/// (63 81 .. 30) or a two-byte one (63 82 .. ..), and the etype field shows
/// 03 05 00 or the pre-auth variant A0 07 03 05.
fn enc_ticket_part_gate(plain: &[u8]) -> bool {
    if plain.len() < 28 {
        return false;
    }
    let tag_ok = (plain[16] == 0x63 && plain[17] == 0x81 && plain[19] == 0x30)
        || (plain[16] == 0x63 && plain[17] == 0x82);
    let key_ok = (plain[24] == 0x03 && plain[25] == 0x05 && plain[26] == 0x00)
        || (plain[24] == 0xA0 && plain[25] == 0x07 && plain[26] == 0x03 && plain[27] == 0x05);
    tag_ok && key_ok
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

    // Upstream hashcat example hashes (module_19600.c / module_19700.c
    // ST_HASH/ST_PASS, pass "hashcat"; etype 17 and 18 with user srv_http,
    // realm synacktiv.local, form A wire shape).
    const ST_19600: &str = "$krb5tgs$17$srv_http$synacktiv.local$849e31b3db1c1f203fa20b85$948690f5875125348286ad3346d27b43eaabc71896b620c16de7ddcdbd561628c650c508856a3f574261948b6db4b48332d30536e978046a423ad4368f9a69b4dc4642dab4e0d475d8299be718fd6f98ac85a771b457b2453e78c9411dfce572b19660fe7a5a8246d9b2a91ea2f14d1986ea0a77ecf9b8330bc8fd9ab540bcf46b74c5aa7005cfccd89ec05f66aeab30c6b2bf8595cf6c9a1b68ad885258850c4b1dd9265f270fb2af52fd76c16246df51ea67efc58a65c345686c84e43642febe908a";
    const ST_19700: &str = "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23643a516834795f0c010da8f549b7e65063e5a367ca9240f9b800adad1734df7e7d5dd8307e785de4f40aacf901df41aa6ce695f8619ec579c1fa57ee93661cf402aeef4e3a42e7e3477645d52c09dc72feade03512dffe0df517344f673c63532b790c242cc1d50f4b4b34976cb6e08ab325b3aefb2684262a5ee9faacb14d059754f50553be5bfa5c4c51e833ff2b6ac02c6e5d4c4eb193e27d7dde301bd1ddf480e5e282b8c27ef37b136c8f140b56de105b73adeb1de16232fa1ab5c9f6";
    // Cross vectors generated with Node crypto (pbkdf2Sync, aes-128/256-ecb
    // and the CTS construction of the upstream m19600.py generator) during
    // authoring — implementations independent of RustCrypto. The etype 17
    // tickets exercise final-block sizes X = 13, X = 6, X = 7 and the full
    // 16-byte final block X = 16 (kernel case 4; see the module comment).
    const NODE_19600: &str = "$krb5tgs$17$alice$example.com$736dc84f6656c11a532b8d1c$b96fb6de40f580bc7b043152883dda9e95371fb7367a811381d8d2910c321d8d9e9ed495f863d42ad128420c265f3327ba6b8b15b60908d5fffc4b08874de0610822d928825df3e918c9cd7c09e4e14aed8ea89b1f098bb1b120cadfd3c6b0b1070adc67ad51b63d51821b1935b859e1cf25c68bb2b32982122ac30e1d2ef1c03fe9d93a097cf27c088df77dc63df2e1f7bcc2a0b8e258d45aa4a0a6eda61aa6039ebc0c873acd92314dcccffeef21848ab5315eb67914a6d3bc8815813c055ea0861a";
    const NODE_19600_X6: &str = "$krb5tgs$17$alice$example.com$12fe7d18eeef94e88d2938dc$d51912608baf9ea4a178ba100f38248f42cd75a8b29fdd4b295c3eca14acab699662bcbafeeef4bd9f21bb32f5b8a6af61e2b09bf2a3a5c7ddbfde962ceffcb186af554f999b4613f75c32b0578ddb3b91957f6eca56d7206a5a8583dcd0f008537baf3310651569da6aed8416182ed47f0dcea5bf39c8dbc2e4b5c7e032a3522643285df69a8f27912b4977eb58b70630a2e91adc4fbfabb9df80e8c0db98da932b1fafc14142d6dfbffa24162fd26f1f6078e28797166b24784efa5cf96111979f99338b68";
    const NODE_19600_X7: &str = "$krb5tgs$17$alice$example.com$ff54b0d54f7fe8ae140d4b9d$94ce4f544ee6aa01d3fac9cde2f8a0120fd3566806425c68cd53e9b61cb6831cca9f5b16949127a9b5bf19a10f8b0af167fea507bc8314325455cf305dbe0887fa61fbceb55db96c2a8821e9c01694c58bf2128d1108f691fe154227bba8c5ec76b13a85efdcdefb7e241da83a480f449669cbccff2ac47acd8a1510dfff37d7f951076fa083dbc1baf0e117ffafd4d6028607c717b55123985ea984c96fd859fca8035a4e9f3cd98fbbbeb561d768bbb79b33f2ed5c10";
    const NODE_19600_X16: &str = "$krb5tgs$17$alice$example.com$85ffd54e806b53f67d890bee$dc6fec09ae4f0d9f9fd1b98be99a48210b5636bb86221dba95d3196dfef9b45e4293c758acdc21add1d9adc3357c1d3c846ac0a90d0f96e7121b118429d21908d0043c33ca15927c5b24e7b4ac140d13cb48fefb5a7618403d0506d08373f24f5a6f7f04dce078aff599c5c07ae0f7a0e251cde4037d5d0ea2784af4fc60fabb7f88ead11d90d91577008c57a2d21bc92f49c11332b936dd811cf0156d0d72a9a713ad1694d61c7cf1b558cd9332fc7d3b210b7da917b60ca37389797703173fcfbb2fb57c0251f6df4b1dcd0768259f";
    const NODE_19700: &str = "$krb5tgs$18$bob.smith$corp.example.net$72a542844f9163148fcead38$a6db99198f7bfbe8750b7890284a09c14de1455e52f9e6779b92f38fc2e74f24a3dedfe959b9ee78fd5c9380f878f0bc53e7cf53c5826973df01c764892060550068b15a85e07f66fba41c4e16ffaa1a9eb4d270ac5b4131710da1f1082b7cf1ea16aaa68414c2d2a7d20f5a3b29ffc368d101eceeca234ba567aabe0e0d4eeac28d012b8bb7610c3d4130d2acc5e38d75cbe85cb7176cfc0fa990fbdf986d79baa4b542cf5711ed81454dfd39031d6c0dde4a7b2b0796975d0dee52bccb6e52d83cad";

    #[test]
    fn upstream_etype17_example_vector_verifies() {
        let parsed = KerberosTgs1718::parse(ST_19600).unwrap();
        assert_eq!(parsed.gpu_mode(), 19600);
        assert_eq!(parsed.etype, 17);
        assert_eq!(parsed.user, "srv_http");
        assert_eq!(parsed.realm, "synacktiv.local");
        assert!(parsed.spn.is_none());
        assert_eq!(parsed.account_info(), b"SYNACKTIV.LOCALsrv_http");
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn upstream_etype18_example_vector_verifies() {
        let parsed = KerberosTgs1718::parse(ST_19700).unwrap();
        assert_eq!(parsed.gpu_mode(), 19700);
        assert_eq!(parsed.etype, 18);
        assert!(parsed.verify("hashcat").unwrap());
        assert!(!parsed.verify("hashcau").unwrap());
        assert!(!parsed.verify("not-the-solution").unwrap());
    }

    #[test]
    fn node_crypto_cross_vectors_verify() {
        for (hash, pass) in [
            // Final stolen block X = 13 (the ST_HASH shape).
            (NODE_19600, "hunter2"),
            // X = 6 and X = 7 partial final blocks.
            (NODE_19600_X6, "hunter2"),
            (NODE_19600_X7, "hunter2"),
            // X = 16: full final block, kernel case-4 semantics.
            (NODE_19600_X16, "hunter2"),
            (NODE_19700, "correct horse"),
        ] {
            let parsed = KerberosTgs1718::parse(hash).unwrap();
            assert!(parsed.verify(pass).unwrap(), "{hash}");
            assert!(!parsed.verify("not-the-solution").unwrap(), "{hash}");
        }
    }

    #[test]
    fn spn_wire_form_is_metadata_only() {
        // The same checksum/edata2 with an SPN segment inserted must parse
        // and verify identically (only upper(realm) . user enters the
        // crypto; module_19600.c stores the SPN outside account_info).
        let parsed = KerberosTgs1718::parse(
            "$krb5tgs$17$alice$example.com$*host/example.com*$736dc84f6656c11a532b8d1c$b96fb6de40f580bc7b043152883dda9e95371fb7367a811381d8d2910c321d8d9e9ed495f863d42ad128420c265f3327ba6b8b15b60908d5fffc4b08874de0610822d928825df3e918c9cd7c09e4e14aed8ea89b1f098bb1b120cadfd3c6b0b1070adc67ad51b63d51821b1935b859e1cf25c68bb2b32982122ac30e1d2ef1c03fe9d93a097cf27c088df77dc63df2e1f7bcc2a0b8e258d45aa4a0a6eda61aa6039ebc0c873acd92314dcccffeef21848ab5315eb67914a6d3bc8815813c055ea0861a",
        )
        .unwrap();
        assert_eq!(parsed.spn.as_deref(), Some("*host/example.com*$"));
        assert!(parsed.verify("hunter2").unwrap());
        // Realm casing on the wire is irrelevant: the salt uppercases it.
        let upper = KerberosTgs1718::parse(&NODE_19600.replacen("example.com", "EXAMPLE.COM", 1)).unwrap();
        assert!(upper.verify("hunter2").unwrap());
    }

    #[test]
    fn etype17_and_18_are_not_interchangeable() {
        // Different key sizes: each format must reject the other's line.
        let swapped = KerberosTgs1718::parse(&ST_19600.replacen("$krb5tgs$17$", "$krb5tgs$18$", 1)).unwrap();
        assert!(!swapped.verify("hashcat").unwrap());
        let swapped = KerberosTgs1718::parse(&ST_19700.replacen("$krb5tgs$18$", "$krb5tgs$17$", 1)).unwrap();
        assert!(!swapped.verify("hashcat").unwrap());
    }

    #[test]
    fn parse_rejects_out_of_policy_shapes() {
        // Signature and structure.
        assert!(KerberosTgs1718::parse("").is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$").is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$17$").is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$19$srv_http$realm$0b8f31413d230a45b013491e$00").is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$23$user$realm$0b8f31413d230a45b013491e$00").is_err());
        // Empty or oversized account fields (upstream token bounds 1..=512).
        assert!(KerberosTgs1718::parse(&format!("$krb5tgs$17$$realm$0b8f31413d230a45b013491e$00")).is_err());
        assert!(KerberosTgs1718::parse(&format!(
            "$krb5tgs$17${}$realm$0b8f31413d230a45b013491e$00",
            "a".repeat(513)
        ))
        .is_err());
        assert!(KerberosTgs1718::parse(&format!(
            "$krb5tgs$17$user${}$0b8f31413d230a45b013491e$00",
            "a".repeat(513)
        ))
        .is_err());
        // Unterminated SPN segment.
        assert!(KerberosTgs1718::parse(&format!("$krb5tgs$17$user$realm$*spn$0b8f31413d230a45b013491e$00")).is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$17$user$realm$*spn*").is_err());
        // Checksum must be exactly 24 hex characters.
        assert!(KerberosTgs1718::parse("$krb5tgs$17$user$realm$0b8f31413d230a45b01349$00").is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$17$user$realm$0b8f31413d230a45b013491$00").is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$17$user$realm$0b8f31413d230a45b01349gg$00").is_err());
        // edata2 bounds: below 64 hex characters, odd count, non-hex.
        assert!(KerberosTgs1718::parse(&format!("$krb5tgs$17$user$realm$0b8f31413d230a45b013491e${}", "0".repeat(62))).is_err());
        assert!(KerberosTgs1718::parse(&format!(
            "$krb5tgs$17$user$realm$0b8f31413d230a45b013491e${}0",
            &ST_19600[ST_19600.rfind('$').unwrap() + 1..]
        ))
        .is_err());
        assert!(KerberosTgs1718::parse("$krb5tgs$17$user$realm$0b8f31413d230a45b013491e$gg00gg00gg00gg00gg00gg00gg00gg00gg00gg00gg00gg00gg00gg00gg00gg00").is_err());
    }
}

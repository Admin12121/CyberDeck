//! TLS 1.2 record-layer decryption (RFC 5246) over reconstructed TCP stream
//! bytes, driven exclusively by a user-supplied NSS keylog's retained
//! `CLIENT_RANDOM` master secret (`super::keylog`). This is passive,
//! defensive analysis of already-captured traffic: decryption is attempted
//! ONLY when the keylog explicitly carries the connection's master secret
//! AND a plaintext ServerHello has been observed (it supplies the server
//! random and the negotiated suite), and a record is emitted only when its
//! GCM tag verifies — or, for the CBC suites below, when its MAC verifies —
//! no key guessing, ever.
//!
//! Key schedule (RFC 5246 §6.3): `key_block = PRF(master_secret, "key
//! expansion", server_random || client_random)` with the RFC §5 P_SHA256
//! expansion, partitioned into per-direction write keys and fixed IVs (the
//! MAC-key slots are zero-length for AEAD suites; the CBC suites take their
//! HMAC keys first, §6.3 order). The PRF and key_block derivation are
//! hand-rolled here on top of the landed `hmac_sha256` primitive; the AEAD
//! itself is the landed `gcm` module untouched. CBC decryption needs the
//! AES inverse direction, hand-rolled here too (the landed `aes` module is
//! encryption-only) plus SHA-1/HMAC-SHA1 for the `_SHA` suites' MAC.
//!
//! Sequence numbers (RFC 5246 §6.1) restart at zero whenever a
//! ChangeCipherSpec switches a direction to its pending write keys; the
//! counters here are per direction and only advance on a verified record.
//! The CBC exception: a MAC-verification failure advances the counter too
//! (Wireshark semantics — every CBC record resyncs through its own
//! explicit per-record IV, so the next record decrypts on its own seq).
//!
//! Bounds mirror the TLS 1.3 sibling: at most [`MAX_CIPHERTEXT_RECORD`]
//! bytes per record (records beyond that are refused, never sliced), at
//! most [`MAX_DECRYPTED_RECORDS`] decrypted records per stream (then the
//! walk stops with an honest marker). CBC adds one: a direction stops the
//! walk after [`MAX_CONSECUTIVE_CBC_FAILURES`] consecutive MAC-verification
//! failures, because CBC (MAC-then-encrypt unless RFC 7366 encrypt-then-MAC
//! was negotiated) cannot authenticate a record before stripping it, and a
//! midstream capture without the keys would otherwise grind forever.
//!
//! Supported suites, all SHA-256 PRF. AES-128-GCM (RFC 5288/5289):
//! `0x009C` `TLS_RSA_WITH_AES_128_GCM_SHA256`, `0x00A2`
//! `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256`, `0xC02B`
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `0xC02F`
//! `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. AES-128-CBC (RFC 5246
//! §6.2.3.2): `0x002F` `TLS_RSA_WITH_AES_128_CBC_SHA`, `0xC013`
//! `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` (HMAC-SHA1 MACs), `0x003C`
//! `TLS_RSA_WITH_AES_128_CBC_SHA256`, `0xC027`
//! `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` (HMAC-SHA256 MACs) — with the
//! RFC 7366 encrypt-then-MAC record shape whenever the ServerHello echoed
//! the extension, and the classic MAC-then-encrypt mailbox rule otherwise.
//! Everything else — the CBC-256 suites and the AES-256-GCM suites (they
//! mandate the SHA-384 PRF, and the crate's AES/GCM primitives are 128-bit
//! only) — is refused with an honest per-stream note and its ciphertext
//! left untouched. CLIENT_RANDOM keylog entries cover every TLS 1.2 key
//! exchange, so the suite table is the only limit on coverage.

use super::gcm;
use super::hkdf::hmac_sha256;
use super::keylog::KeylogStore;
use super::tls13::StreamWalk;

/// Per-record ciphertext bound: 2^14 content + headroom for padding-shaped
/// fragments + tag (TLS 1.2 AES-GCM wire records are at most
/// 2^14 + 8 explicit nonce + 16 tag = 16_400 bytes).
pub const MAX_CIPHERTEXT_RECORD: usize = 16 * 1024 + 256 + 16;
/// Hard cap on decrypted records per stream before the walk stops honestly.
pub const MAX_DECRYPTED_RECORDS: usize = 512;

pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_ALERT: u8 = 21;
pub const CONTENT_HANDSHAKE: u8 = 22;
pub const CONTENT_APPLICATION_DATA: u8 = 23;

/// RFC 5246 §5 `P_<hash>` with SHA-256: `A(0) = label || seed`,
/// `A(i) = HMAC(secret, A(i-1))`, output = the first `out_len` bytes of
/// `HMAC(secret, A(1) || label || seed) || HMAC(secret, A(2) || label ||
/// seed) || ...`. The message parts are hashed without being concatenated
/// in memory.
pub fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut a = hmac_sha256(secret, &[label, seed]);
    let mut out = Vec::with_capacity(out_len + 32);
    while out.len() < out_len {
        out.extend_from_slice(&hmac_sha256(secret, &[&a, label, seed]));
        a = hmac_sha256(secret, &[&a]);
    }
    out.truncate(out_len);
    out
}

/// SHA-1 (FIPS 180-4), hand-rolled here because the CBC suites' MAC is
/// HMAC-SHA1 and the crate is zero-dependency: same incremental shape as
/// the landed `sha256` module, so HMAC never concatenates its inputs. The
/// FIPS vectors in the tests anchor it.
const SHA1_H0: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

fn sha1_compress(state: &mut [u32; 5], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let mut v = *state;
    for i in 0..80 {
        let (f, k) = match i {
            0..=19 => ((v[1] & v[2]) | (!v[1] & v[3]), 0x5a82_7999),
            20..=39 => (v[1] ^ v[2] ^ v[3], 0x6ed9_eba1),
            40..=59 => ((v[1] & v[2]) | (v[1] & v[3]) | (v[2] & v[3]), 0x8f1b_bcdc),
            _ => (v[1] ^ v[2] ^ v[3], 0xca62_c1d6),
        };
        let t = v[0]
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(v[4])
            .wrapping_add(k)
            .wrapping_add(w[i]);
        v[4] = v[3];
        v[3] = v[2];
        v[2] = v[1].rotate_left(30);
        v[1] = v[0];
        v[0] = t;
    }
    for i in 0..5 {
        state[i] = state[i].wrapping_add(v[i]);
    }
}

/// Incremental SHA-1, mirroring `Sha256`.
struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffered: usize,
    length_bits: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: SHA1_H0,
            buffer: [0u8; 64],
            buffered: 0,
            length_bits: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.length_bits = self
            .length_bits
            .wrapping_add((data.len() as u64).checked_mul(8).unwrap_or(u64::MAX));
        let mut rest = data;
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(rest.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                sha1_compress(&mut self.state, &block);
                self.buffered = 0;
            }
        }
        let blocks = rest.len() / 64;
        for i in 0..blocks {
            sha1_compress(&mut self.state, &rest[64 * i..64 * i + 64]);
        }
        rest = &rest[64 * blocks..];
        if !rest.is_empty() {
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.buffered = rest.len();
        }
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.length_bits;
        let mut tail = [0u8; 128];
        tail[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
        tail[self.buffered] = 0x80;
        let total = if self.buffered + 9 <= 64 { 64 } else { 128 };
        tail[total - 8..total].copy_from_slice(&bit_len.to_be_bytes());
        let mut at = 0usize;
        while at < total {
            sha1_compress(&mut self.state, &tail[at..at + 64]);
            at += 64;
        }
        let mut out = [0u8; 20];
        for i in 0..5 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

/// One-shot SHA-1 over a bounded slice.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

/// HMAC-SHA1 (RFC 2104 §2) over any number of message parts, mirroring
/// `hmac_sha256`; the parts are hashed in order without being concatenated.
fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut padded = [0u8; 64];
    if key.len() > 64 {
        padded[..20].copy_from_slice(&sha1(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }
    let mut inner = Sha1::new();
    inner.update(&ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_out = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_out);
    outer.finalize()
}

/// AES-128 block decryption (FIPS 197 §5.3). The landed `aes` module is
/// encryption-only — QUIC header protection and GCM need just the forward
/// cipher — so the inverse cipher lives here, in the same derived-table
/// style: the inverse S-box below is the forward table inverted in const
/// context, never transcribed, and the key expansion matches `aes::Aes128`.
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

/// FIPS 197 §5.3.2 forward S-box, derived exactly as the landed `aes`
/// module derives it (inverse in GF(2^8) plus the affine transform).
const SBOX: [u8; 256] = {
    let mut sbox = [0u8; 256];
    sbox[0] = 0x63; // 0 has no inverse; fixed by the standard.
    let mut i = 1usize;
    while i < 256 {
        let mut inverse = 0u8;
        let mut j = 1usize;
        while j < 256 {
            if gf_mul(i as u8, j as u8) == 1 {
                inverse = j as u8;
                break;
            }
            j += 1;
        }
        let b = inverse;
        sbox[i] =
            b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63;
        i += 1;
    }
    sbox
};

/// FIPS 197 §5.3.2 inverse S-box: the forward table inverted in const
/// context, so the pair can never drift apart.
const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
};

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// An expanded AES-128 key for the inverse cipher, expanded exactly as the
/// landed `aes::Aes128` expands it (eleven 16-byte round keys).
struct Aes128Decryptor {
    round_keys: [[u8; 16]; 11],
}

impl Aes128Decryptor {
    fn new(key: &[u8; 16]) -> Self {
        let mut round_keys = [[0u8; 16]; 11];
        round_keys[0] = *key;
        for round in 1..=10 {
            let prev = round_keys[round - 1];
            // RotWord then SubWord over the last word, then the round constant.
            let mut w = [prev[12], prev[13], prev[14], prev[15]];
            w.rotate_left(1);
            for byte in w.iter_mut() {
                *byte = SBOX[*byte as usize];
            }
            w[0] ^= RCON[round - 1];
            let mut current = [0u8; 16];
            for c in 0..4 {
                current[c] = prev[c] ^ w[c];
            }
            for c in 4..16 {
                current[c] = prev[c] ^ current[c - 4];
            }
            round_keys[round] = current;
        }
        Self { round_keys }
    }

    /// Inverse cipher of one 16-byte block (FIPS 197 §5.3.5 InvCipher).
    fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        add_round_key(&mut s, &self.round_keys[10]);
        for round in (1..10).rev() {
            inv_shift_rows(&mut s);
            inv_sub_bytes(&mut s);
            add_round_key(&mut s, &self.round_keys[round]);
            inv_mix_columns(&mut s);
        }
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, &self.round_keys[0]);
        s
    }
}

fn add_round_key(s: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        s[i] ^= key[i];
    }
}

fn inv_sub_bytes(s: &mut [u8; 16]) {
    for byte in s.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

/// FIPS 197 §5.3.5 InvShiftRows: the column-major inverse of the forward
/// `shift_rows` — row `r` shifts right by `r` positions.
fn inv_shift_rows(s: &mut [u8; 16]) {
    let old = *s;
    for r in 0..4 {
        for c in 0..4 {
            s[r + 4 * c] = old[r + 4 * ((c + 4 - r) % 4)];
        }
    }
}

/// FIPS 197 §5.3.5 InvMixColumns, expanded per column with the
/// [0e 0b 0d 09] matrix over GF(2^8).
fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let a0 = s[4 * c];
        let a1 = s[4 * c + 1];
        let a2 = s[4 * c + 2];
        let a3 = s[4 * c + 3];
        s[4 * c] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[4 * c + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[4 * c + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[4 * c + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/// AES-CBC record body decryption (RFC 5246 §6.2.3.2): the explicit
/// per-record IV seeds the chain (TLS 1.1+ replaced the TLS 1.0 CBC
/// residue with it), `p_i = D_k(c_i) XOR c_{i-1}`.
fn cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let aes = Aes128Decryptor::new(key);
    let mut prev = *iv;
    let mut plain = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.chunks_exact(CBC_BLOCK) {
        let mut cur = [0u8; CBC_BLOCK];
        cur.copy_from_slice(block);
        let dec = aes.decrypt_block(&cur);
        let mut out = [0u8; CBC_BLOCK];
        for i in 0..CBC_BLOCK {
            out[i] = dec[i] ^ prev[i];
        }
        plain.extend_from_slice(&out);
        prev = cur;
    }
    plain
}

/// AES-CBC record shape (RFC 5246 §6.2.3.2): the explicit IV is one 16-byte
/// block and the ciphertext is whole blocks.
const CBC_BLOCK: usize = 16;
/// Largest padding this decryptor strips. RFC 5246 allows up to 255, but
/// real senders pad at most one extra block, and anything larger is
/// indistinguishable from a wrong-key guess — honest refusal either way.
const MAX_CBC_PADDING: usize = 16;
/// Consecutive CBC MAC-verification failures after which a direction stops
/// its stream walk with an honest marker (the TLS 1.3 sibling's record
/// limit, applied to the fact that a CBC record cannot be authenticated
/// before its padding strip — a midstream capture without the keys would
/// otherwise grind through every record producing nothing).
pub const MAX_CONSECUTIVE_CBC_FAILURES: usize = 8;

/// The MAC algorithm a CBC suite pairs with (RFC 5246 Appendix A: the plain
/// `_SHA` suites use HMAC-SHA1, the `_SHA256` suites HMAC-SHA256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CbcMac {
    Sha1,
    Sha256,
}

impl CbcMac {
    fn mac_len(self) -> usize {
        match self {
            CbcMac::Sha1 => 20,
            CbcMac::Sha256 => 32,
        }
    }

    /// RFC 5246 §6.2.3.1 MAC over the message parts (never concatenated).
    fn mac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            CbcMac::Sha1 => hmac_sha1(key, parts).to_vec(),
            CbcMac::Sha256 => hmac_sha256(key, parts).to_vec(),
        }
    }
}

/// One direction's AES-128-CBC write material (RFC 5246 §6.3 partition):
/// the MAC key, the 16-byte AES key, and the 16-byte fixed-IV slot the
/// §6.3 partition allocates. TLS 1.1+ CBC chains each record from its own
/// explicit per-record IV instead of the fixed IV (that slot exists for the
/// §6.3 layout and the TLS 1.0 CBC residue), so it is carried but never
/// used for chaining. The per-direction sequence number and the
/// consecutive-failure counter ride along.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbcWriteKeys {
    pub mac_key: Vec<u8>,
    pub key: [u8; 16],
    pub fixed_iv: [u8; 16],
    mac: CbcMac,
    seq: u64,
    failures: usize,
}

/// Both directions' CBC write material, partitioned from one key_block in
/// RFC 5246 §6.3 order (client MAC key, server MAC key, client key, server
/// key, client fixed IV, server fixed IV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbcKeyBlock {
    pub client: CbcWriteKeys,
    pub server: CbcWriteKeys,
}

/// Derive the RFC 5246 §6.3 key_block for one negotiated AES-128-CBC suite:
/// MAC keys first (20 bytes HMAC-SHA1 / 32 bytes HMAC-SHA256 per
/// direction), then the 16-byte write keys, then the 16-byte fixed-IV
/// slots. Returns None for any other suite — never a guessed partition.
pub fn cbc_key_block(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    cipher_suite: u16,
) -> Option<CbcKeyBlock> {
    let mac = match cipher_suite {
        0x002F | 0xC013 => CbcMac::Sha1,
        0x003C | 0xC027 => CbcMac::Sha256,
        _ => return None,
    };
    let mac_len = mac.mac_len();
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    let block = prf_sha256(
        master_secret,
        b"key expansion",
        &seed,
        2 * (mac_len + CBC_BLOCK + CBC_BLOCK),
    );
    let mut client = CbcWriteKeys {
        mac_key: block[..mac_len].to_vec(),
        key: [0u8; 16],
        fixed_iv: [0u8; 16],
        mac,
        seq: 0,
        failures: 0,
    };
    let mut server = CbcWriteKeys {
        mac_key: block[mac_len..2 * mac_len].to_vec(),
        key: [0u8; 16],
        fixed_iv: [0u8; 16],
        mac,
        seq: 0,
        failures: 0,
    };
    client
        .key
        .copy_from_slice(&block[2 * mac_len..2 * mac_len + CBC_BLOCK]);
    server
        .key
        .copy_from_slice(&block[2 * mac_len + CBC_BLOCK..2 * mac_len + 2 * CBC_BLOCK]);
    client
        .fixed_iv
        .copy_from_slice(&block[2 * mac_len + 2 * CBC_BLOCK..2 * mac_len + 3 * CBC_BLOCK]);
    server
        .fixed_iv
        .copy_from_slice(&block[2 * mac_len + 3 * CBC_BLOCK..2 * mac_len + 4 * CBC_BLOCK]);
    Some(CbcKeyBlock { client, server })
}

/// The write-material shape one negotiated suite produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteKeys {
    Gcm(KeyBlock),
    Cbc(CbcKeyBlock),
}

/// Derive the RFC 5246 §6.3 key_block for any supported suite: the AES-GCM
/// suites through [`key_block`], the AES-128-CBC suites through
/// [`cbc_key_block`]. Returns None for anything else — never a guess.
pub fn suite_key_block(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    cipher_suite: u16,
) -> Option<SuiteKeys> {
    if let Some(block) = key_block(master_secret, server_random, client_random, cipher_suite) {
        return Some(SuiteKeys::Gcm(block));
    }
    cbc_key_block(master_secret, server_random, client_random, cipher_suite).map(SuiteKeys::Cbc)
}

/// One direction's AES-128-GCM write material (RFC 5246 §6.3 partition):
/// the 16-byte AES key and the 4-byte fixed IV salt (RFC 5246 §6.2.3.3).
/// The per-record sequence number rides along and only advances through
/// verified decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteKeys {
    pub key: [u8; 16],
    pub salt: [u8; 4],
    seq: u64,
}

/// Both directions' write material, partitioned from one key_block in
/// RFC 5246 §6.3 order (client key, server key, client IV, server IV — the
/// MAC-key slots are zero-length for the supported AEAD suites).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    pub client: WriteKeys,
    pub server: WriteKeys,
}

/// Derive the RFC 5246 §6.3 key_block for one negotiated suite. Returns
/// None for any suite this decryptor does not support — never a guessed
/// partition.
pub fn key_block(
    master_secret: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    cipher_suite: u16,
) -> Option<KeyBlock> {
    // AES-128-GCM suites only: 16-byte keys, 4-byte fixed IVs, no MAC keys.
    let key_len = match cipher_suite {
        0x009C | 0x00A2 | 0xC02B | 0xC02F => 16usize,
        _ => return None,
    };
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    let block = prf_sha256(
        master_secret,
        b"key expansion",
        &seed,
        2 * key_len + 8, // 2 keys + 2 fixed IVs; MAC-key slots are empty
    );
    let mut client = WriteKeys {
        key: [0u8; 16],
        salt: [0u8; 4],
        seq: 0,
    };
    let mut server = WriteKeys {
        key: [0u8; 16],
        salt: [0u8; 4],
        seq: 0,
    };
    client.key.copy_from_slice(&block[..key_len]);
    server.key.copy_from_slice(&block[key_len..2 * key_len]);
    client
        .salt
        .copy_from_slice(&block[2 * key_len..2 * key_len + 4]);
    server
        .salt
        .copy_from_slice(&block[2 * key_len + 4..2 * key_len + 8]);
    Some(KeyBlock { client, server })
}

/// The plaintext facts a passive observer takes from one ServerHello: the
/// server random (the second half of the §6.3 seed) and the negotiated
/// cipher suite, plus the negotiated version (the supported_versions
/// extension when present, else the legacy version field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloParams {
    pub server_random: [u8; 32],
    pub cipher_suite: u16,
    pub negotiated_version: u16,
    /// Whether the ServerHello echoed the encrypt_then_mac extension (RFC
    /// 7366 §2, type 22, empty extension_data): CBC records then carry
    /// MAC(ciphertext) after the ciphertext instead of the classic
    /// MAC-then-encrypt shape.
    pub encrypt_then_mac: bool,
}

/// Parse one well-framed plaintext ServerHello record (5-byte TLS header
/// included). Bounded: only the record's own handshake bytes are read.
fn parse_server_hello(record: &[u8]) -> Option<ServerHelloParams> {
    if record.len() < 9 || record[0] != CONTENT_HANDSHAKE || record[1] != 3 || record[5] != 2 {
        return None;
    }
    let handshake_len =
        ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    if 4 + handshake_len > record.len() - 5 || handshake_len < 38 {
        // 38 = version(2) + random(32) + session-id length(1) + suite(2)
        // + compression(1) — the smallest well-formed ServerHello.
        return None;
    }
    let body = &record[9..9 + handshake_len];
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let server_random: [u8; 32] = body[2..34].try_into().ok()?;
    let session_id_len = body[34] as usize;
    let mut at = 35 + session_id_len;
    if at + 3 > body.len() {
        return None;
    }
    let cipher_suite = u16::from_be_bytes([body[at], body[at + 1]]);
    at += 3; // suite + compression method
    let mut negotiated_version = legacy_version;
    let mut encrypt_then_mac = false;
    if at < body.len() {
        // Extensions block (TLS 1.3 ServerHellos carry supported_versions
        // here). Bounded walk, at most 128 extensions, nothing guessed.
        let ext_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        let block_end = (at + 2 + ext_len).min(body.len());
        let mut cursor = at + 2;
        let mut seen = 0usize;
        while cursor + 4 <= block_end && seen < 128 {
            let kind = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
            let len = u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]) as usize;
            if cursor + 4 + len > block_end {
                break;
            }
            if kind == 43 && len == 2 {
                negotiated_version = u16::from_be_bytes([body[cursor + 4], body[cursor + 5]]);
            }
            if kind == 22 {
                // RFC 7366 §2: the server echoed encrypt_then_mac.
                encrypt_then_mac = true;
            }
            cursor += 4 + len;
            seen += 1;
        }
    }
    Some(ServerHelloParams {
        server_random,
        cipher_suite,
        negotiated_version,
        encrypt_then_mac,
    })
}

/// Scan a reconstructed direction for its first plaintext ServerHello
/// record. Bounded to the first 16 records of the direction; broken framing
/// or a direction that never carries a ServerHello yields None.
pub fn find_server_hello(data: &[u8]) -> Option<ServerHelloParams> {
    let mut at = 0usize;
    for _ in 0..16 {
        if data.len() - at < 5 {
            return None;
        }
        let length = u16::from_be_bytes([data[at + 3], data[at + 4]]) as usize;
        let end = match at.checked_add(5).and_then(|h| h.checked_add(length)) {
            Some(end) if end <= data.len() => end,
            _ => return None,
        };
        let record = &data[at..end];
        if record[0] == CONTENT_HANDSHAKE && record[1] == 3 && record.len() >= 9 && record[5] == 2 {
            return parse_server_hello(record);
        }
        at = end;
    }
    None
}

/// One fed record's outcome. `Plain` covers records that are legitimately
/// unencrypted (change_cipher_spec, pre-key handshake/alert records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    Plain,
    Decrypted {
        content_type: u8,
        plaintext: Vec<u8>,
    },
    Undecryptable,
}

/// One direction's write state: the keys derived from the key_block (only
/// once a ServerHello supplied both randoms — either family) and whether
/// that direction's ChangeCipherSpec has switched them in.
#[derive(Default)]
struct Direction {
    keys: Option<WriteKeys>,
    cbc: Option<CbcWriteKeys>,
    active: bool,
}

/// The TLS 1.2 decryptor for one stream, bound to one connection's
/// `CLIENT_RANDOM` master secret via the ClientHello random. `None`
/// construction means the keylog has no master secret for this connection
/// — no decryption is ever attempted.
pub struct Tls12Decryptor {
    client_random: [u8; 32],
    master_secret: [u8; 48],
    client: Direction,
    server: Direction,
    server_hello_seen: bool,
    unsupported_suite: Option<u16>,
    /// RFC 7366 encrypt-then-MAC negotiated in the ServerHello: CBC records
    /// then carry MAC(ciphertext) after the ciphertext, verified before
    /// decryption. One connection-wide flag (both directions negotiate it).
    encrypt_then_mac: bool,
    /// Set once a direction hit [`MAX_CONSECUTIVE_CBC_FAILURES`]: the walk
    /// stops with an honest marker instead of grinding garbage MAC checks.
    cbc_stalled: bool,
    decrypted: usize,
    limit_reached: bool,
}

impl Tls12Decryptor {
    /// Bind the keylog's `CLIENT_RANDOM` master secret for this
    /// connection's ClientHello random. Returns None when the keylog does
    /// not cover this connection.
    pub fn new(store: &KeylogStore, client_random: &[u8; 32]) -> Option<Self> {
        let master_secret = *store.master_secret_for(client_random)?;
        Some(Self {
            client_random: *client_random,
            master_secret,
            client: Direction::default(),
            server: Direction::default(),
            server_hello_seen: false,
            unsupported_suite: None,
            encrypt_then_mac: false,
            cbc_stalled: false,
            decrypted: 0,
            limit_reached: false,
        })
    }

    pub fn decrypted_count(&self) -> usize {
        self.decrypted
    }

    pub fn limit_reached(&self) -> bool {
        self.limit_reached
    }

    /// True once a plaintext ServerHello has been consumed (the second
    /// random and the negotiated suite are known).
    pub fn server_hello_seen(&self) -> bool {
        self.server_hello_seen
    }

    /// The negotiated suite this decryptor refused, if any. The stream is
    /// reported honestly as unsupported; nothing is ever guessed.
    pub fn unsupported_suite(&self) -> Option<u16> {
        self.unsupported_suite
    }

    /// True when this direction holds derived write keys (either family).
    pub fn direction_has_keys(&self, from_client: bool) -> bool {
        let dir = self.direction(from_client);
        dir.keys.is_some() || dir.cbc.is_some()
    }

    fn direction(&self, from_client: bool) -> &Direction {
        if from_client {
            &self.client
        } else {
            &self.server
        }
    }

    fn direction_mut(&mut self, from_client: bool) -> &mut Direction {
        if from_client {
            &mut self.client
        } else {
            &mut self.server
        }
    }

    /// Consume a plaintext ServerHello's facts (server random, negotiated
    /// suite, and whether RFC 7366 encrypt-then-MAC was negotiated) and
    /// derive the §6.3 key_block. The first ServerHello wins: renegotiation
    /// is not attempted, and an unsupported suite is recorded honestly
    /// instead of guessed around. Idempotent after the first call.
    pub fn set_server_hello(
        &mut self,
        server_random: &[u8; 32],
        cipher_suite: u16,
        encrypt_then_mac: bool,
    ) {
        if self.server_hello_seen {
            return;
        }
        self.server_hello_seen = true;
        self.encrypt_then_mac = encrypt_then_mac;
        match suite_key_block(
            &self.master_secret,
            server_random,
            &self.client_random,
            cipher_suite,
        ) {
            Some(SuiteKeys::Gcm(block)) => {
                self.client.keys = Some(block.client);
                self.server.keys = Some(block.server);
            }
            Some(SuiteKeys::Cbc(cbc)) => {
                self.client.cbc = Some(cbc.client);
                self.server.cbc = Some(cbc.server);
            }
            None => self.unsupported_suite = Some(cipher_suite),
        }
    }

    /// Feed one full TLS record (5-byte header included, exactly as
    /// reconstructed from the stream). Every encrypted record is verified
    /// before any plaintext is produced — the GCM tag for AEAD suites, the
    /// CBC MAC per the negotiated record shape otherwise — and a
    /// ServerHello from the server direction is consumed automatically.
    pub fn feed(&mut self, from_client: bool, record: &[u8]) -> RecordOutcome {
        if record.len() < 5 {
            return RecordOutcome::Undecryptable;
        }
        let record_type = record[0];
        let length = u16::from_be_bytes([record[3], record[4]]) as usize;
        let Some(payload) = record.get(5..5usize.checked_add(length).unwrap_or(usize::MAX)) else {
            return RecordOutcome::Undecryptable;
        };
        if length > MAX_CIPHERTEXT_RECORD || payload.is_empty() {
            return RecordOutcome::Undecryptable;
        }
        match record_type {
            // ChangeCipherSpec is sent in the clear (RFC 5246 §7.4: exactly
            // one 0x01 byte). Only the well-formed record switches the
            // SENDING direction to its pending write keys and resets its
            // sequence number (RFC 5246 §6.1).
            CONTENT_CHANGE_CIPHER_SPEC => {
                if payload == [1] {
                    let dir = self.direction_mut(from_client);
                    dir.active = true;
                    if let Some(keys) = dir.keys.as_mut() {
                        keys.seq = 0;
                    }
                    // The CBC family resets the same way (RFC 5246 §6.1),
                    // and the switch forgives any MAC-failure run before it.
                    if let Some(cbc) = dir.cbc.as_mut() {
                        cbc.seq = 0;
                        cbc.failures = 0;
                    }
                }
                RecordOutcome::Plain
            }
            CONTENT_HANDSHAKE | CONTENT_ALERT | CONTENT_APPLICATION_DATA => {
                let active = self.direction(from_client).active;
                if !active {
                    // Pre-key records: the handshake flight and alerts are
                    // legitimately plaintext. Application data is never
                    // plaintext in TLS 1.2 — a type-23 record without that
                    // direction's CCS is ciphertext (capture started
                    // midstream, or this is not a TLS 1.2 session at all).
                    if record_type == CONTENT_APPLICATION_DATA {
                        return RecordOutcome::Undecryptable;
                    }
                    // A ServerHello from the server direction supplies the
                    // second random and the negotiated suite.
                    if record_type == CONTENT_HANDSHAKE
                        && !from_client
                        && record.len() >= 9
                        && record[5] == 2
                    {
                        if let Some(params) = parse_server_hello(record) {
                            self.set_server_hello(
                                &params.server_random,
                                params.cipher_suite,
                                params.encrypt_then_mac,
                            );
                        }
                    }
                    return RecordOutcome::Plain;
                }
                // Negotiated CBC suites take the MAC-then-encrypt (or RFC
                // 7366 encrypt-then-MAC) record path below; the AES-GCM
                // path after this dispatch is untouched.
                if self.direction(from_client).cbc.is_some() {
                    return self.feed_cbc(from_client, record_type, record, payload);
                }
                let Some(keys) = self.direction_mut(from_client).keys.as_mut() else {
                    // CCS already seen but no keys were derived: the suite
                    // was refused, so the records stay ciphertext.
                    return RecordOutcome::Undecryptable;
                };
                if payload.len() < 8 + gcm::TAG_LEN {
                    return RecordOutcome::Undecryptable;
                }
                // RFC 5246 §6.2.3.3: nonce = 4-byte fixed salt || 8-byte
                // explicit nonce carried at the start of the fragment.
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&keys.salt);
                nonce[4..].copy_from_slice(&payload[..8]);
                // AAD = sequence number (8, big-endian) || the 5-byte
                // record header (type, version, length).
                let mut aad = [0u8; 13];
                aad[..8].copy_from_slice(&keys.seq.to_be_bytes());
                aad[8..].copy_from_slice(&record[..5]);
                let Some(plaintext) = gcm::open(&keys.key, &nonce, &aad, &payload[8..]) else {
                    // Tag mismatch: the record stays ciphertext and the
                    // sequence number stays put, exactly as for the sibling.
                    return RecordOutcome::Undecryptable;
                };
                keys.seq = keys.seq.wrapping_add(1);
                self.bump_and_check_limit();
                RecordOutcome::Decrypted {
                    content_type: record_type,
                    plaintext,
                }
            }
            _ => RecordOutcome::Plain,
        }
    }

    fn bump_and_check_limit(&mut self) {
        self.decrypted = self.decrypted.saturating_add(1);
        if self.decrypted >= MAX_DECRYPTED_RECORDS {
            self.limit_reached = true;
        }
    }

    /// Feed one encrypted record under a negotiated AES-128-CBC suite (RFC
    /// 5246 §6.2.3.2, or the RFC 7366 encrypt-then-MAC shape when the
    /// ServerHello echoed the extension). The honesty contract: a record is
    /// emitted only when its MAC verifies — before decryption under EtM,
    /// after the constant-time padding strip otherwise (the mailbox rule,
    /// since classic CBC cannot authenticate before stripping) — a failed
    /// record stays ciphertext while its sequence number ADVANCES anyway
    /// (Wireshark semantics: every record carries its own explicit IV, so
    /// the walk resyncs through the next record's sequence number), and a
    /// bounded run of consecutive failures stops the stream with an honest
    /// marker instead of grinding on garbage.
    fn feed_cbc(
        &mut self,
        from_client: bool,
        record_type: u8,
        record: &[u8],
        payload: &[u8],
    ) -> RecordOutcome {
        let etm = self.encrypt_then_mac;
        let (outcome, verified, stalled) = {
            let Some(cbc) = self.direction_mut(from_client).cbc.as_mut() else {
                return RecordOutcome::Undecryptable;
            };
            let mac_len = cbc.mac.mac_len();
            // GenericBlockCipher shape: explicit IV (one block) || whole
            // ciphertext blocks, with the trailing MAC outside the
            // ciphertext under RFC 7366. Malformed shapes are refused
            // whole, never sliced, and never touch the sequence state.
            let Some(body_len) = payload
                .len()
                .checked_sub(if etm { mac_len } else { 0 })
                .filter(|&b| b >= 2 * CBC_BLOCK && (b - CBC_BLOCK) % CBC_BLOCK == 0)
            else {
                return RecordOutcome::Undecryptable;
            };
            let mut outcome = RecordOutcome::Undecryptable;
            let mut verified = false;
            let seq_bytes = cbc.seq.to_be_bytes();
            let mut iv = [0u8; CBC_BLOCK];
            iv.copy_from_slice(&payload[..CBC_BLOCK]);
            if etm {
                // RFC 7366 §3: MAC(seq || type || version || length ||
                // IV || ciphertext), with the length covering IV ||
                // ciphertext but not the MAC — verified BEFORE decryption.
                let expected = cbc.mac.mac(
                    &cbc.mac_key,
                    &[
                        &seq_bytes,
                        &[record_type],
                        &record[1..3],
                        &(body_len as u16).to_be_bytes(),
                        &payload[..body_len],
                    ],
                );
                let mut diff = 0u8;
                for i in 0..mac_len {
                    diff |= expected[i] ^ payload[body_len + i];
                }
                if diff == 0 {
                    let mut plain = cbc_decrypt(&cbc.key, &iv, &payload[CBC_BLOCK..body_len]);
                    let total = plain.len();
                    let pad = plain[total - 1] as usize;
                    if pad <= MAX_CBC_PADDING && total >= 1 + pad {
                        plain.truncate(total - 1 - pad);
                        outcome = RecordOutcome::Decrypted {
                            content_type: record_type,
                            plaintext: plain,
                        };
                        verified = true;
                    }
                }
            } else {
                // RFC 5246 §6.2.3.2 MAC-then-encrypt, mailbox rule: the MAC
                // cannot be checked before the padding strip, so decrypt
                // under the candidate padding, verify HMAC-SHA1/SHA256 over
                // the stripped content (seq || type || version || length ||
                // fragment) constant-time, and emit only when every check
                // folds true. (The checks are computed unconditionally; the
                // single fold keeps malformed padding and a MAC mismatch
                // indistinguishable from outside — both stay ciphertext.)
                let mut plain = cbc_decrypt(&cbc.key, &iv, &payload[CBC_BLOCK..]);
                let total = plain.len();
                let pad = plain[total - 1] as usize;
                let fits = pad <= MAX_CBC_PADDING && total >= 1 + pad + mac_len;
                let content_len = total.saturating_sub(1 + pad + mac_len);
                // Constant-time padding value check over a fixed window:
                // every byte inside the declared padding must equal its
                // declared length.
                let mut pad_diff = 0u8;
                for i in 0..MAX_CBC_PADDING {
                    let in_padding = ((i as u32) < pad as u32) as u8;
                    if let Some(k) = total.checked_sub(i + 2) {
                        pad_diff |= in_padding & (plain[k] ^ pad as u8);
                    } else {
                        pad_diff |= in_padding;
                    }
                }
                let expected = cbc.mac.mac(
                    &cbc.mac_key,
                    &[
                        &seq_bytes,
                        &[record_type],
                        &record[1..3],
                        &(content_len as u16).to_be_bytes(),
                        &plain[..content_len],
                    ],
                );
                let mut mac_diff = 1u8;
                if let Some(found) = plain.get(content_len..content_len + mac_len) {
                    mac_diff = 0;
                    for i in 0..mac_len {
                        mac_diff |= expected[i] ^ found[i];
                    }
                }
                if fits && pad_diff == 0 && mac_diff == 0 {
                    plain.truncate(content_len);
                    outcome = RecordOutcome::Decrypted {
                        content_type: record_type,
                        plaintext: plain,
                    };
                    verified = true;
                }
            }
            if verified {
                cbc.seq = cbc.seq.wrapping_add(1);
                cbc.failures = 0;
            } else {
                // Honesty contract: the record stays ciphertext and the
                // sequence number advances anyway (Wireshark semantics —
                // the next record's own explicit IV resyncs the walk).
                cbc.seq = cbc.seq.wrapping_add(1);
                cbc.failures += 1;
            }
            let stalled = !verified && cbc.failures >= MAX_CONSECUTIVE_CBC_FAILURES;
            (outcome, verified, stalled)
        };
        if stalled {
            self.cbc_stalled = true;
        }
        if verified {
            self.bump_and_check_limit();
        }
        outcome
    }
}

/// Walk one direction's reconstructed bytes record-by-record and decrypt
/// with the bound master secret. Stops honestly at the record limit or at
/// broken framing; concatenated decrypted content is returned in
/// [`StreamWalk`] (the same shape the TLS 1.3 sibling emits).
pub fn walk_stream(decryptor: &mut Tls12Decryptor, from_client: bool, data: &[u8]) -> StreamWalk {
    let mut walk = StreamWalk {
        complete: true,
        ..Default::default()
    };
    let mut at = 0usize;
    while at < data.len() {
        if data.len() - at < 5 {
            walk.complete = false;
            break;
        }
        let length = u16::from_be_bytes([data[at + 3], data[at + 4]]) as usize;
        if length > MAX_CIPHERTEXT_RECORD {
            walk.complete = false;
            break;
        }
        let end = match at.checked_add(5).and_then(|h| h.checked_add(length)) {
            Some(end) if end <= data.len() => end,
            _ => {
                walk.complete = false;
                break;
            }
        };
        match decryptor.feed(from_client, &data[at..end]) {
            RecordOutcome::Plain => walk.plain_records += 1,
            RecordOutcome::Decrypted {
                content_type,
                plaintext,
            } => {
                walk.decrypted_records += 1;
                if content_type == CONTENT_APPLICATION_DATA {
                    walk.app_records.push(plaintext.clone());
                }
                walk.plaintext.extend_from_slice(&plaintext);
            }
            RecordOutcome::Undecryptable => walk.undecryptable_records += 1,
        }
        at = end;
        if decryptor.limit_reached() {
            walk.complete = false;
            break;
        }
        // A CBC direction that failed MAC verification too many consecutive
        // times stops the walk with the same honest marker.
        if decryptor.cbc_stalled {
            walk.complete = false;
            break;
        }
    }
    walk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes::Aes128;
    use crate::crypto::keylog::KeylogStore;

    const CLIENT_RANDOM_HEX: &str =
        "4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a";
    const MASTER_SECRET_HEX: &str = concat!(
        "21212121212121212121212121212121", // 16 bytes
        "21212121212121212121212121212121", // 16 bytes
        "21212121212121212121212121212121", // 16 bytes
    );
    const SERVER_RANDOM_HEX: &str =
        "5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b";
    const SUITE: u16 = 0xC02F; // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::new();
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn fixture_randoms() -> ([u8; 32], [u8; 32], [u8; 48]) {
        (
            hex(CLIENT_RANDOM_HEX).try_into().unwrap(),
            hex(SERVER_RANDOM_HEX).try_into().unwrap(),
            hex(MASTER_SECRET_HEX).try_into().unwrap(),
        )
    }

    /// A keylog binding exactly this fixture's master secret.
    fn store_with_master() -> KeylogStore {
        let text = format!("CLIENT_RANDOM {CLIENT_RANDOM_HEX} {MASTER_SECRET_HEX}\n");
        KeylogStore::parse(&text).unwrap()
    }

    /// A decryptor already bound and keyed for the fixture session.
    fn keyed_decryptor() -> (Tls12Decryptor, KeyBlock) {
        let (client_random, server_random, _) = fixture_randoms();
        let store = store_with_master();
        let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
        let block = key_block(
            &hex(MASTER_SECRET_HEX).try_into().unwrap(),
            &server_random,
            &client_random,
            SUITE,
        )
        .unwrap();
        dec.set_server_hello(&server_random, SUITE, false);
        (dec, block)
    }

    /// Encrypt one TLS 1.2 AES-GCM record exactly as the wire carries it,
    /// using the crate's own gcm::seal (encrypt-then-decrypt
    /// self-consistency through the real crypto path).
    fn seal_record(
        block: &KeyBlock,
        from_client: bool,
        seq: u64,
        content: &[u8],
        content_type: u8,
    ) -> Vec<u8> {
        let keys = if from_client {
            &block.client
        } else {
            &block.server
        };
        let mut explicit = [0u8; 8];
        explicit.copy_from_slice(&seq.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&keys.salt);
        nonce[4..].copy_from_slice(&explicit);
        let body_len = (content.len() as u16 + 8 + 16).to_be_bytes();
        let header = [content_type, 3, 3, body_len[0], body_len[1]];
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..].copy_from_slice(&header);
        let mut record = header.to_vec();
        record.extend_from_slice(&explicit);
        record.extend_from_slice(&gcm::seal(&keys.key, &nonce, &aad, content));
        record
    }

    fn server_hello_record(cipher_suite: u16, negotiated_version: Option<u16>) -> Vec<u8> {
        let (_, server_random, _) = fixture_randoms();
        let mut body = vec![3, 3];
        body.extend_from_slice(&server_random);
        body.push(0); // empty session id
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0); // compression
        if let Some(v) = negotiated_version {
            let mut exts = vec![0, 43, 0, 2]; // supported_versions, 2 bytes
            exts.extend_from_slice(&v.to_be_bytes());
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(&exts);
        }
        let mut message = vec![2, 0, 0, body.len() as u8];
        message.extend_from_slice(&body);
        let mut record = vec![CONTENT_HANDSHAKE, 3, 3];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    fn ccs_record() -> Vec<u8> {
        vec![CONTENT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]
    }

    fn key_block_reference() -> String {
        // Cross-checked against a trusted platform implementation
        // (Python hashlib HMAC-SHA256) of RFC 5246 §5/§6.3 during
        // development, exactly like the sha256.rs FIPS vectors.
        "8209e94936e8563e290d36aab96901409b4dd2acc52ac3e2b89b7b86fe3763936985ebf9b4b4ed3e".into()
    }

    #[test]
    fn prf_key_block_matches_the_trusted_reference() {
        let (client_random, server_random, master) = fixture_randoms();
        // Every supported (AES-128-GCM, SHA-256 PRF) suite derives the same
        // 40-byte block for the same master/randoms.
        for suite in [0x009Cu16, 0x00A2, 0xC02B, SUITE] {
            let block = key_block(&master, &server_random, &client_random, suite).unwrap();
            let mut got = Vec::new();
            got.extend_from_slice(&block.client.key);
            got.extend_from_slice(&block.server.key);
            got.extend_from_slice(&block.client.salt);
            got.extend_from_slice(&block.server.salt);
            assert_eq!(hex(&key_block_reference()), got, "suite {suite:#06x}");
        }
        // RFC 5246 §6.3 partition order: client key, server key, client
        // IV, server IV — asserted through the reference's own slices.
        let reference = hex(&key_block_reference());
        let block = key_block(&master, &server_random, &client_random, SUITE).unwrap();
        assert_eq!(
            block.client.key,
            <[u8; 16]>::try_from(&reference[..16]).unwrap()
        );
        assert_eq!(
            block.server.key,
            <[u8; 16]>::try_from(&reference[16..32]).unwrap()
        );
        assert_eq!(
            block.client.salt,
            <[u8; 4]>::try_from(&reference[32..36]).unwrap()
        );
        assert_eq!(
            block.server.salt,
            <[u8; 4]>::try_from(&reference[36..40]).unwrap()
        );
    }

    #[test]
    fn key_block_refuses_unsupported_suites_and_is_order_sensitive() {
        let (client_random, server_random, master) = fixture_randoms();
        // AES-256-GCM suites (SHA-384 PRF) and CBC suites are refused —
        // never a guessed partition.
        for suite in [
            0x009Du16, 0x00A3, 0xC02C, 0xC030, 0x002F, 0x0035, 0xC027, 0x1301,
        ] {
            assert!(
                key_block(&master, &server_random, &client_random, suite).is_none(),
                "suite {suite:#06x} must be refused"
            );
        }
        // The seed order matters: server_random || client_random is the
        // RFC 5246 §6.3 order (trusted reference for the swapped order).
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&client_random);
        seed[32..].copy_from_slice(&server_random);
        assert_eq!(
            to_hex(&prf_sha256(&master, b"key expansion", &seed, 8)),
            "cb56a8aa8eae0463"
        );
        // And the label matters.
        let mut forward = [0u8; 64];
        forward[..32].copy_from_slice(&server_random);
        forward[32..].copy_from_slice(&client_random);
        assert_eq!(
            to_hex(&prf_sha256(&master, b"key expansioN", &forward, 8)),
            "f60a2b93c17ba8e7"
        );
    }

    #[test]
    fn decryptor_requires_a_matching_client_random() {
        let (client_random, _, _) = fixture_randoms();
        let store = store_with_master();
        assert!(Tls12Decryptor::new(&store, &client_random).is_some());
        // Wrong random: no entry, no decryptor, no attempt.
        assert!(Tls12Decryptor::new(&store, &[0u8; 32]).is_none());
        // A TLS 1.3-only keylog never binds a TLS 1.2 stream.
        let only13 = KeylogStore::parse(&format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {CLIENT_RANDOM_HEX} {}",
            "4".repeat(64)
        ))
        .unwrap();
        assert!(Tls12Decryptor::new(&only13, &client_random).is_none());
    }

    #[test]
    fn server_hello_binds_keys_and_the_first_one_wins() {
        let (client_random, server_random, _) = fixture_randoms();
        let store = store_with_master();
        let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
        assert!(!dec.server_hello_seen());
        assert!(!dec.direction_has_keys(false));
        // The server-direction ServerHello is consumed and keys derive.
        assert_eq!(
            dec.feed(false, &server_hello_record(SUITE, None)),
            RecordOutcome::Plain
        );
        assert!(dec.server_hello_seen());
        assert!(dec.direction_has_keys(true));
        assert!(dec.direction_has_keys(false));
        assert_eq!(dec.unsupported_suite(), None);
        // A second ServerHello (renegotiation) never replaces the first.
        dec.set_server_hello(&[0x99; 32], 0xC02B, false);
        let keys_before = dec.client.keys.clone();
        dec.set_server_hello(&server_random, SUITE, false);
        assert_eq!(dec.client.keys, keys_before);
    }

    #[test]
    fn handshake_and_application_records_round_trip_both_directions() {
        let (mut dec, block) = keyed_decryptor();
        // Client flight: CCS, encrypted Finished (handshake), then two
        // application records with ascending sequence numbers.
        let mut client_stream = ccs_record();
        client_stream.extend_from_slice(&seal_record(
            &block,
            true,
            0,
            b"\x14finished",
            CONTENT_HANDSHAKE,
        ));
        client_stream.extend_from_slice(&seal_record(
            &block,
            true,
            1,
            b"GET /a HTTP/1.1\r\n",
            CONTENT_APPLICATION_DATA,
        ));
        client_stream.extend_from_slice(&seal_record(
            &block,
            true,
            2,
            b"app payload",
            CONTENT_APPLICATION_DATA,
        ));
        let walk = walk_stream(&mut dec, true, &client_stream);
        assert_eq!(walk.decrypted_records, 3);
        assert_eq!(walk.plain_records, 1); // the CCS
        assert_eq!(
            walk.plaintext,
            b"\x14finishedGET /a HTTP/1.1\r\napp payload".to_vec()
        );
        assert_eq!(
            walk.app_records,
            vec![b"GET /a HTTP/1.1\r\n".to_vec(), b"app payload".to_vec()]
        );
        assert!(walk.complete);

        // Server flight: ServerHello (plaintext), CCS, encrypted response.
        let mut server_stream = server_hello_record(SUITE, None);
        server_stream.extend_from_slice(&ccs_record());
        server_stream.extend_from_slice(&seal_record(
            &block,
            false,
            0,
            b"HTTP/1.1 200 OK\r\n",
            CONTENT_APPLICATION_DATA,
        ));
        let walk = walk_stream(&mut dec, false, &server_stream);
        assert_eq!(walk.decrypted_records, 1);
        assert_eq!(walk.app_records, vec![b"HTTP/1.1 200 OK\r\n".to_vec()]);
        assert!(walk.complete);
        assert_eq!(dec.decrypted_count(), 4);
        assert!(dec.server_hello_seen());
    }

    #[test]
    fn sequence_numbers_reset_after_change_cipher_spec() {
        let (mut dec, block) = keyed_decryptor();
        // Two records under seq 0,1, then a second CCS resetting the same
        // direction back to seq 0 (RFC 5246 §6.1 state change).
        let mut stream = ccs_record();
        stream.extend_from_slice(&seal_record(
            &block,
            true,
            0,
            b"first",
            CONTENT_APPLICATION_DATA,
        ));
        stream.extend_from_slice(&seal_record(
            &block,
            true,
            1,
            b"second",
            CONTENT_APPLICATION_DATA,
        ));
        stream.extend_from_slice(&ccs_record());
        stream.extend_from_slice(&seal_record(
            &block,
            true,
            0,
            b"third",
            CONTENT_APPLICATION_DATA,
        ));
        stream.extend_from_slice(&seal_record(
            &block,
            true,
            1,
            b"fourth",
            CONTENT_APPLICATION_DATA,
        ));
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(walk.decrypted_records, 4);
        assert_eq!(walk.plaintext, b"firstsecondthirdfourth".to_vec());
        assert!(walk.complete);
    }

    #[test]
    fn wrong_master_secret_never_produces_plaintext() {
        let (client_random, server_random, _) = fixture_randoms();
        let store = store_with_master();
        let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
        dec.set_server_hello(&server_random, SUITE, false);
        // Encrypt under a master secret that is NOT the keylog's.
        let foreign = key_block(&[0x77u8; 48], &server_random, &client_random, SUITE).unwrap();
        let record = seal_record(
            &foreign,
            false,
            0,
            b"secret payload",
            CONTENT_APPLICATION_DATA,
        );
        let walk = walk_stream(&mut dec, false, &record);
        assert_eq!(walk.undecryptable_records, 1);
        assert!(walk.plaintext.is_empty());
    }

    #[test]
    fn corrupted_tag_stays_ciphertext_and_does_not_desync_the_sequence() {
        let (mut dec, block) = keyed_decryptor();
        assert_eq!(dec.feed(false, &ccs_record()), RecordOutcome::Plain);
        let record = seal_record(&block, false, 0, b"payload", CONTENT_APPLICATION_DATA);
        let mut corrupted = record.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        assert_eq!(dec.feed(false, &corrupted), RecordOutcome::Undecryptable);
        // The failed record did not advance the sequence: the genuine
        // record under the same seq still verifies.
        assert_eq!(
            dec.feed(false, &record),
            RecordOutcome::Decrypted {
                content_type: CONTENT_APPLICATION_DATA,
                plaintext: b"payload".to_vec()
            }
        );
        assert_eq!(dec.decrypted_count(), 1);
    }

    #[test]
    fn encrypted_records_before_a_server_hello_stay_ciphertext() {
        let (client_random, _, _) = fixture_randoms();
        let store = store_with_master();
        let (_, block) = keyed_decryptor();
        let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
        // Application data with no ServerHello yet: ciphertext, never
        // claimed as plaintext, and no keys exist to guess with.
        let record = seal_record(&block, false, 0, b"midstream", CONTENT_APPLICATION_DATA);
        assert_eq!(dec.feed(false, &record), RecordOutcome::Undecryptable);
        assert!(!dec.server_hello_seen());
        assert!(!dec.direction_has_keys(false));
        // Once the ServerHello is consumed, CCS switches the direction and
        // the same record decrypts under seq 0.
        assert_eq!(
            dec.feed(false, &server_hello_record(SUITE, None)),
            RecordOutcome::Plain
        );
        assert_eq!(dec.feed(false, &ccs_record()), RecordOutcome::Plain);
        assert_eq!(
            dec.feed(false, &record),
            RecordOutcome::Decrypted {
                content_type: CONTENT_APPLICATION_DATA,
                plaintext: b"midstream".to_vec()
            }
        );
        assert_eq!(dec.server_hello_seen(), true);
        assert_eq!(dec.decrypted_count(), 1);
        // And the ServerHello in the CLIENT direction is never adopted: no
        // keys derive, so the direction's records stay ciphertext.
        let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
        let mut wrong_side = server_hello_record(SUITE, None);
        wrong_side.extend_from_slice(&ccs_record());
        wrong_side.extend_from_slice(&record);
        assert_eq!(dec.server_hello_seen(), false);
        let walk = walk_stream(&mut dec, true, &wrong_side);
        assert_eq!(walk.undecryptable_records, 1);
    }

    #[test]
    fn unsupported_suites_are_refused_without_guessing() {
        let (client_random, _, _) = fixture_randoms();
        let store = store_with_master();
        let (_, block) = keyed_decryptor();
        // The CBC-256 suites (0x0035 RSA/SHA1, 0x003D RSA/SHA256, 0xC014
        // ECDHE/SHA1, 0xC028 ECDHE/SHA-384-PRF) and the AES-256-GCM
        // SHA-384-PRF family are honestly refused: the crate's AES/GCM
        // primitives are 128-bit only.
        for suite in [0x0035u16, 0x003D, 0xC014, 0xC028, 0xC030, 0x009D] {
            let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
            dec.set_server_hello(&[0x5b; 32], suite, false);
            assert_eq!(dec.unsupported_suite(), Some(suite), "suite {suite:#06x}");
            assert!(!dec.direction_has_keys(false));
            // Encrypted traffic stays ciphertext; CCS cannot activate keys
            // that were never derived.
            assert_eq!(dec.feed(false, &ccs_record()), RecordOutcome::Plain);
            let record = seal_record(&block, false, 0, b"payload", CONTENT_APPLICATION_DATA);
            assert_eq!(dec.feed(false, &record), RecordOutcome::Undecryptable);
            assert_eq!(dec.decrypted_count(), 0);
        }
    }

    #[test]
    fn truncated_and_oversized_records_are_refused_not_sliced() {
        let (mut dec, block) = keyed_decryptor();
        let record = seal_record(&block, false, 0, b"payload", CONTENT_APPLICATION_DATA);
        // Header claims more than present: the walk stops at broken framing.
        let mut stream = record.clone();
        stream.truncate(record.len() - 10);
        let walk = walk_stream(&mut dec, false, &stream);
        assert_eq!(walk.undecryptable_records, 0);
        assert!(!walk.complete);
        assert!(walk.plaintext.is_empty());
        // A record beyond the size bound is refused whole.
        let mut oversized = vec![CONTENT_APPLICATION_DATA, 3, 3, 0xff, 0xff];
        oversized.extend_from_slice(&[0u8; 64]);
        assert_eq!(dec.feed(false, &oversized), RecordOutcome::Undecryptable);
        // A GCM fragment too short to carry explicit nonce + tag is refused
        // even with the direction keyed and switched.
        assert_eq!(dec.feed(false, &ccs_record()), RecordOutcome::Plain);
        let mut short = vec![CONTENT_APPLICATION_DATA, 3, 3, 0, 12];
        short.extend_from_slice(&[0u8; 12]);
        assert_eq!(dec.feed(false, &short), RecordOutcome::Undecryptable);
    }

    #[test]
    fn record_limit_stops_the_walk_with_an_honest_marker() {
        let (mut dec, block) = keyed_decryptor();
        let mut stream = ccs_record();
        for seq in 0..(MAX_DECRYPTED_RECORDS + 2) {
            stream.extend_from_slice(&seal_record(
                &block,
                true,
                seq as u64,
                b"x",
                CONTENT_APPLICATION_DATA,
            ));
        }
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(dec.decrypted_count(), MAX_DECRYPTED_RECORDS);
        assert!(dec.limit_reached());
        assert!(!walk.complete);
        assert_eq!(walk.decrypted_records, MAX_DECRYPTED_RECORDS);
    }

    #[test]
    fn find_server_hello_reads_the_negotiated_version_and_suite() {
        // A TLS 1.2 ServerHello: negotiated version is the legacy field.
        let record = server_hello_record(SUITE, None);
        let params = find_server_hello(&record).unwrap();
        assert_eq!(params.negotiated_version, 0x0303);
        assert_eq!(params.cipher_suite, SUITE);
        let (_, server_random, _) = fixture_randoms();
        assert_eq!(params.server_random, server_random);
        // A TLS 1.3 ServerHello negotiating 0x0304 through supported_versions.
        let record = server_hello_record(0x1302, Some(0x0304));
        let params = find_server_hello(&record).unwrap();
        assert_eq!(params.negotiated_version, 0x0304);
        assert_eq!(params.cipher_suite, 0x1302);
        // The scan skips preceding records but stays bounded by framing.
        let mut stream = vec![CONTENT_HANDSHAKE, 3, 3, 0, 2, 1, 0]; // tiny handshake, kind 1
        stream.extend_from_slice(&record);
        assert_eq!(find_server_hello(&stream).unwrap(), params);
        // Non-ServerHello records, broken framing and empty input are None.
        assert!(find_server_hello(&record[..record.len() - 4]).is_none());
        assert!(find_server_hello(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(find_server_hello(&[]).is_none());
        // Malformed ServerHello bodies (truncation mid-handshake) are None.
        let mut bad = server_hello_record(SUITE, None);
        bad.truncate(bad.len() - 2);
        assert!(find_server_hello(&bad).is_none());
    }

    #[test]
    fn unknown_record_types_pass_through_as_plain() {
        let (mut dec, _) = keyed_decryptor();
        let ccs = [CONTENT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1];
        assert_eq!(dec.feed(true, &ccs), RecordOutcome::Plain);
        let unknown = [99, 3, 3, 0, 1, 1];
        assert_eq!(dec.feed(true, &unknown), RecordOutcome::Plain);
    }

    // ─────────────────────────────────────── AES-128-CBC suite family ──

    const CBC_SHA1_SUITE: u16 = 0x002F; // TLS_RSA_WITH_AES_128_CBC_SHA
    const CBC_SHA1_ECDHE_SUITE: u16 = 0xC013; // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    const CBC_SHA256_SUITE: u16 = 0x003C; // TLS_RSA_WITH_AES_128_CBC_SHA256
    const CBC_SHA256_ECDHE_SUITE: u16 = 0xC027; // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    const ALL_CBC_SUITES: [u16; 4] = [
        CBC_SHA1_SUITE,
        CBC_SHA1_ECDHE_SUITE,
        CBC_SHA256_SUITE,
        CBC_SHA256_ECDHE_SUITE,
    ];

    /// Trusted-reference CBC key_block partitions for the fixture randoms
    /// (Python hashlib HMAC-SHA256 of RFC 5246 §5/§6.3 during development,
    /// exactly like the GCM reference above — the same PRF stream, cut at
    /// the §6.3 block-cipher boundaries: MAC keys, keys, fixed IVs).
    const CBC_SHA1_KEY_BLOCK_REF: &str = concat!(
        "8209e94936e8563e290d36aab96901409b4dd2ac", // client MAC key (20)
        "c52ac3e2b89b7b86fe3763936985ebf9b4b4ed3e", // server MAC key (20)
        "5634461afb01b4ab66b95846db6a7966",         // client key
        "4b65168b092c847c963a570069ec8fc2",         // server key
        "7c2478d84a1235a122ffdd1de4d59c18",         // client fixed IV
        "80a99c814c6ccfa3c1c00863f36c566f",         // server fixed IV
    );
    const CBC_SHA256_KEY_BLOCK_REF: &str = concat!(
        "8209e94936e8563e290d36aab96901409b4dd2acc52ac3e2b89b7b86fe376393", // client MAC key (32)
        "6985ebf9b4b4ed3e5634461afb01b4ab66b95846db6a79664b65168b092c847c", // server MAC key (32)
        "963a570069ec8fc27c2478d84a1235a1",                                 // client key
        "22ffdd1de4d59c1880a99c814c6ccfa3",                                 // server key
        "c1c00863f36c566f4888d1583f457b85",                                 // client fixed IV
        "b2896a0e3463601dcea13671efdf4591",                                 // server fixed IV
    );

    /// Trimmed real OpenSSL captures made for this change (Node.js TLS
    /// endpoints against a self-signed localhost RSA server, TLS 1.2, raw
    /// TCP-side byte taps, fresh session per capture). Client direction =
    /// ClientHello, CCS, encrypted Finished, three application records
    /// ("ping one\n", "second message two\n", "third three\n"); server
    /// direction = ServerHello, CCS, encrypted Finished, the same three
    /// records uppercased. The decryption construction was cross-checked
    /// against a parallel Python/Node prototype before being embedded.
    const OPENSSL_MTE_SHA1_CLIENT: &str = concat!(
        "16030100800100007c03030014a09e39c6a67d2727af39afc8714f5baf552f20",
        "36356f3a9415c4bc7d6bbd000002002f01000051ff010001000000000e000c00",
        "00096c6f63616c686f7374002300000016000000170000000d002a0028040305",
        "030603080708080809080a080b08040805080604010501060103030301030204",
        "02050206021403030001011603030040344aa37ed1ac1a1c78411488f7b2056b",
        "29e75f174cd4401ff3b6a1ba3ea5c60a58fbc78e00f6ac59efbb8f6aeda643ca",
        "fae8dd9159348692c0e630bb7ca1bd571703030030671034f8bd20937fa3cd49",
        "33d80ffa9d6a79883a899a94c8c25345d580225c8cd6a0175e946379a9042f35",
        "ed8bd8e9271703030040fb8d327234afbb5a3214cf3dec393bf288cf99c0e7c8",
        "360fdc6e40699fa17be6d695c9dc39f87eeb61f8f04e57a2b0ee5293eb95ae11",
        "cfef01f2e14d4a8d82a51703030040dde4c63c1e42b9c0e47468ef111d5063f0",
        "ea09864b647ec52e310586e652248f83a9526ca886e5d65d4256bb2261d57183",
        "1d81af67e0425fff2b10d52876061e",
    );
    const OPENSSL_MTE_SHA1_SERVER: &str = concat!(
        "1603030039020000350303a75fd48d00aa369944fcc89e6ff77a81bca5d9562a",
        "75d3f55a4b06d7553c548a00002f00000dff0100010000230000001700001403",
        "030001011603030040628d8e819e538ee86e08e976801984343fff3283ddc398",
        "ed4825e2a3d9127288e99d15fd623fc1f04b4415533a8510ce8483a28f652d34",
        "5d125e53f268b427cb17030300309332e52489c8a43adb1bca2f4f6fa8eff05d",
        "e18e0fe6356c4b960f2970cf3d4d6a322e83a730446385c16e76d74ded591703",
        "03004008ea88178fa9eebf064fe2a838e0afee26bc6eace1aedbaa267cc40145",
        "aedbe63a340e5e6af45e8aec5e09ffd4901df85c98decb394f564c3b36af2185",
        "e338d217030300401aac70829b05d50235a2baff2f04d2d4b682196ae86c2761",
        "e5c6f6b491dcda89653fc7948a8e93eafc8de7b3d45c7acff3659335702712c3",
        "71d9c08292079d67",
    );
    const OPENSSL_MTE_SHA1_KEYLOG: &str = concat!(
        "CLIENT_RANDOM 0014a09e39c6a67d2727af39afc8714f5baf552f2036356f3a",
        "9415c4bc7d6bbd d6dd9acacd9e2812bd9383eb74e6b5921158c82d4a128b498",
        "ecde5c6282235e8d0133e44ed15bc6d5fb62b89196fa3f0",
    );
    const OPENSSL_ETM_SHA256_CLIENT: &str = concat!(
        "16030100800100007c03036840143134b87002b9452bbafd5e514702c894b450",
        "03038999e65f0cc3ca6822000002003c01000051ff010001000000000e000c00",
        "00096c6f63616c686f7374002300000016000000170000000d002a0028040305",
        "030603080708080809080a080b08040805080604010501060103030301030204",
        "0205020602140303000101160303005085ddb93f36e29313fe3b998a0286e537",
        "8a0792733b6539f71a2e8e861c3ba2afc0c9154ed87834bea73534142e83acc5",
        "37e99c1266c3f0d964bdfc4679b3fb4eb0709d1051b6680a8bc0225614e67add",
        "17030300408eb56f7de27fb34d8337d426c3852021ee3b61f2941556ddf98689",
        "c3db2bdf26616ab77c42bf8573fb4d9cdf7634955179f49fde68ba8869eb0d49",
        "b9d2832b6a1703030050f820e6ee8120f2856f9d1fff90f1781c9a38424d6554",
        "acd6f7c8d35beb82d48e4bb6074f2060099bbf4cf84c1daa73acb9e196467e04",
        "ce7e2a421290df4196a629c366edd72b036b6fac5e1257fd2f8e1703030040c6",
        "51f0e6dea0cffaf5a2aea28c26184b9d45c5266315ad44f86dff3c8215f4babe",
        "1f31eacf1fffcc84da7f8d09dabdd54cba1c74ca7845dfde6205a412dfe09e",
    );
    const OPENSSL_ETM_SHA256_SERVER: &str = concat!(
        "160303003d020000390303267023d47d42e763fc88b4afef0bbdfeb1dcf7bdd4",
        "20c288f57cac98f1f4edfd00003c000011ff0100010000230000001600000017",
        "00001403030001011603030050f1d8f57a8aa953ec83169b98b63a8e631ce18d",
        "a2e522166b2958d30f00b75692a685b1c4f882bb25030cdcd3867d9bb9a34ba5",
        "9baf009c9a0d15eef4ae40c6a8409498aa362beb6adaa97b7f72fc53ff170303",
        "0040350a864356bc7869ed1f71001e410c2c04282235c0dfe887ed3ac2a1c47f",
        "ef6ddcbf1fafdae9de6bd17a6623aa000cfe54a283db242433a1783000709ec0",
        "54ab1703030050a16ba7dd8d949ac3c382b8cfd96f8908843820ebd84651810d",
        "e3c36466f9abba264a66117315ad4d9550153555909b7d05624432026d335166",
        "5c33f16c556aceafab43d4f97452d7190b065115c2b6b01703030040799aa2c9",
        "c1ca855d7b2f9427de14b18bed2f483e6e978d3fd879ee79646acd41406e8c31",
        "0338a52db13f7cb1a1ac52533ebb804e5c169ac5ece89da8b33d11c6",
    );
    const OPENSSL_ETM_SHA256_KEYLOG: &str = concat!(
        "CLIENT_RANDOM 6840143134b87002b9452bbafd5e514702c894b45003038999",
        "e65f0cc3ca6822 506f43e4145b4ee553dd8b436e2cf6989b589a5ce888d5096",
        "12005c1d2367b88134046c67fcd9da8fc26aa8cfe34cd72",
    );

    fn is_sha1_suite(suite: u16) -> bool {
        matches!(suite, 0x002F | 0xC013)
    }

    /// The RFC-minimal padding length a sender computes for one inner
    /// plaintext (content || MAC || padding || length byte must fill whole
    /// blocks).
    fn minimal_pad(content_len: usize, mac_len: usize) -> usize {
        (CBC_BLOCK - ((content_len + mac_len + 1) % CBC_BLOCK)) % CBC_BLOCK
    }

    fn cbc_test_mac(suite: u16, mac_key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        if is_sha1_suite(suite) {
            hmac_sha1(mac_key, parts).to_vec()
        } else {
            hmac_sha256(mac_key, parts).to_vec()
        }
    }

    /// A decryptor already bound and keyed for the fixture session under a
    /// CBC suite (`etm` selects the RFC 7366 record shape).
    fn cbc_keyed_decryptor(suite: u16, etm: bool) -> (Tls12Decryptor, CbcKeyBlock) {
        let (client_random, server_random, master) = fixture_randoms();
        let store = store_with_master();
        let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
        let block = cbc_key_block(&master, &server_random, &client_random, suite).unwrap();
        dec.set_server_hello(&server_random, suite, etm);
        (dec, block)
    }

    /// CBC-encrypt one inner plaintext with the landed forward cipher
    /// (encrypt-then-decrypt self-consistency through the real crypto path)
    /// from a fresh per-record IV.
    fn cbc_encrypt(keys: &CbcWriteKeys, seq: u64, inner: &[u8]) -> ([u8; 16], Vec<u8>) {
        let aes = Aes128::new(&keys.key);
        let mut iv = [0u8; CBC_BLOCK];
        for (i, b) in iv.iter_mut().enumerate() {
            *b = (seq as u8) ^ (i as u8);
        }
        let mut prev = iv;
        let mut ct = Vec::with_capacity(inner.len());
        for block in inner.chunks_exact(CBC_BLOCK) {
            let mut cur = [0u8; CBC_BLOCK];
            cur.copy_from_slice(block);
            for (c, p) in cur.iter_mut().zip(prev.iter()) {
                *c ^= p;
            }
            let enc = aes.encrypt_block(&cur);
            ct.extend_from_slice(&enc);
            prev = enc;
        }
        (iv, ct)
    }

    fn cbc_record_header(content_type: u8, fragment_len: usize) -> Vec<u8> {
        let mut header = vec![content_type, 3, 3];
        header.extend_from_slice(&(fragment_len as u16).to_be_bytes());
        header
    }

    /// Seal one RFC 5246 §6.2.3.2 MAC-then-encrypt record exactly as the
    /// wire carries it: IV || ENC(content || MAC || padding || length byte).
    /// `pad` is the sender's chosen padding length (0, one byte, or a full
    /// block for the edge cases below).
    fn seal_cbc_mte_record(
        suite: u16,
        keys: &CbcWriteKeys,
        seq: u64,
        content: &[u8],
        content_type: u8,
        pad: usize,
    ) -> Vec<u8> {
        let mac_len = if is_sha1_suite(suite) { 20 } else { 32 };
        assert_eq!(
            (content.len() + mac_len + pad + 1) % CBC_BLOCK,
            0,
            "synthetic record must fill whole blocks"
        );
        let mac = cbc_test_mac(
            suite,
            &keys.mac_key,
            &[
                &seq.to_be_bytes(),
                &[content_type],
                &[3, 3],
                &(content.len() as u16).to_be_bytes(),
                content,
            ],
        );
        let mut inner = content.to_vec();
        inner.extend_from_slice(&mac);
        inner.extend(std::iter::repeat(pad as u8).take(pad));
        inner.push(pad as u8);
        let (iv, ct) = cbc_encrypt(keys, seq, &inner);
        let mut record = cbc_record_header(content_type, CBC_BLOCK + ct.len());
        record.extend_from_slice(&iv);
        record.extend_from_slice(&ct);
        record
    }

    /// Seal one RFC 7366 encrypt-then-MAC record: IV ||
    /// ENC(content || padding || length byte) || MAC(ciphertext).
    fn seal_cbc_etm_record(
        suite: u16,
        keys: &CbcWriteKeys,
        seq: u64,
        content: &[u8],
        content_type: u8,
    ) -> Vec<u8> {
        let pad = minimal_pad(content.len(), 0);
        let mut inner = content.to_vec();
        inner.extend(std::iter::repeat(pad as u8).take(pad));
        inner.push(pad as u8);
        let (iv, ct) = cbc_encrypt(keys, seq, &inner);
        let mut enc = iv.to_vec();
        enc.extend_from_slice(&ct);
        let mac = cbc_test_mac(
            suite,
            &keys.mac_key,
            &[
                &seq.to_be_bytes(),
                &[content_type],
                &[3, 3],
                &(enc.len() as u16).to_be_bytes(),
                &enc,
            ],
        );
        let mut record = cbc_record_header(content_type, enc.len() + mac.len());
        record.extend_from_slice(&enc);
        record.extend_from_slice(&mac);
        record
    }

    /// A ServerHello carrying (or omitting) the RFC 7366 extension.
    fn server_hello_record_etm(cipher_suite: u16, etm: bool) -> Vec<u8> {
        let (_, server_random, _) = fixture_randoms();
        let mut body = vec![3, 3];
        body.extend_from_slice(&server_random);
        body.push(0); // empty session id
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0); // compression
        if etm {
            let exts = vec![0, 22, 0, 0]; // encrypt_then_mac, empty data
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(&exts);
        }
        let mut message = vec![2, 0, 0, body.len() as u8];
        message.extend_from_slice(&body);
        let mut record = vec![CONTENT_HANDSHAKE, 3, 3];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    #[test]
    fn aes_inverse_cipher_matches_fips_197_and_the_landed_forward_cipher() {
        // FIPS 197 Appendix C.1 inverse known answer.
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let cipher: [u8; 16] = hex("69c4e0d86a7b0430d8cdb78070b4c55a").try_into().unwrap();
        assert_eq!(
            to_hex(&Aes128Decryptor::new(&key).decrypt_block(&cipher)),
            "00112233445566778899aabbccddeeff"
        );
        // The inverse cipher must invert the landed forward cipher exactly,
        // so every CBC decryption composes with the GCM path's primitive.
        for k in 0u8..8 {
            let mut key = [0u8; 16];
            let mut plaintext = [0u8; 16];
            for i in 0..16 {
                key[i] = k.wrapping_mul(37) ^ i as u8;
                plaintext[i] = k.wrapping_add(11) ^ (i as u8).wrapping_mul(29);
            }
            let cipher = Aes128::new(&key).encrypt_block(&plaintext);
            assert_eq!(
                Aes128Decryptor::new(&key).decrypt_block(&cipher),
                plaintext,
                "key family {k}"
            );
        }
    }

    #[test]
    fn sha1_and_hmac_sha1_match_the_trusted_references() {
        // FIPS 180-4 example vectors.
        assert_eq!(
            to_hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            to_hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            to_hex(&sha1(msg)),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let long = vec![b'a'; 1_000_000];
        assert_eq!(
            to_hex(&sha1(&long)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
        // Incremental updates match the one-shot.
        let data: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        for split in [0usize, 1, 63, 64, 65, 128, 999, 1000] {
            let mut h = Sha1::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), sha1(&data), "split at {split}");
        }
        // RFC 2202 Appendix, HMAC-SHA1 test cases 1, 2, 6 and 7 (6/7 cover
        // the longer-than-block key path).
        assert_eq!(
            to_hex(&hmac_sha1(&[0x0b; 20], &[b"Hi There"])),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            to_hex(&hmac_sha1(b"Jefe", &[b"what do ya want for nothing?"])),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            to_hex(&hmac_sha1(
                &[0xaa; 80],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
        assert_eq!(
            to_hex(&hmac_sha1(
                &[0xaa; 80],
                &[b"Test Using Larger Than Block-Size Key And Larger Than One Block-Size Data"]
            )),
            "ad7c0b86f1c95d463029e816638ca253899eea11"
        );
    }

    #[test]
    fn cbc_key_block_partition_matches_the_trusted_reference() {
        let (client_random, server_random, master) = fixture_randoms();
        let reference = hex(CBC_SHA1_KEY_BLOCK_REF);
        assert_eq!(reference.len(), 104);
        for suite in [CBC_SHA1_SUITE, CBC_SHA1_ECDHE_SUITE] {
            let block = cbc_key_block(&master, &server_random, &client_random, suite).unwrap();
            assert_eq!(block.client.mac_key, reference[..20], "suite {suite:#06x}");
            assert_eq!(block.server.mac_key, reference[20..40]);
            assert_eq!(
                block.client.key,
                <[u8; 16]>::try_from(&reference[40..56]).unwrap()
            );
            assert_eq!(
                block.server.key,
                <[u8; 16]>::try_from(&reference[56..72]).unwrap()
            );
            assert_eq!(
                block.client.fixed_iv,
                <[u8; 16]>::try_from(&reference[72..88]).unwrap()
            );
            assert_eq!(
                block.server.fixed_iv,
                <[u8; 16]>::try_from(&reference[88..104]).unwrap()
            );
        }
        let reference = hex(CBC_SHA256_KEY_BLOCK_REF);
        assert_eq!(reference.len(), 128);
        for suite in [CBC_SHA256_SUITE, CBC_SHA256_ECDHE_SUITE] {
            let block = cbc_key_block(&master, &server_random, &client_random, suite).unwrap();
            assert_eq!(block.client.mac_key, reference[..32], "suite {suite:#06x}");
            assert_eq!(block.server.mac_key, reference[32..64]);
            assert_eq!(
                block.client.key,
                <[u8; 16]>::try_from(&reference[64..80]).unwrap()
            );
            assert_eq!(
                block.server.key,
                <[u8; 16]>::try_from(&reference[80..96]).unwrap()
            );
            assert_eq!(
                block.client.fixed_iv,
                <[u8; 16]>::try_from(&reference[96..112]).unwrap()
            );
            assert_eq!(
                block.server.fixed_iv,
                <[u8; 16]>::try_from(&reference[112..128]).unwrap()
            );
        }
    }

    #[test]
    fn cbc_key_block_refuses_non_aes128_cbc_suites() {
        let (client_random, server_random, master) = fixture_randoms();
        // CBC-256 (all four PRFs) and unrelated suites are refused — never
        // a guessed partition.
        for suite in [0x0035u16, 0x003D, 0xC014, 0xC028, 0x009C, 0xC02F, 0x1301] {
            assert!(
                cbc_key_block(&master, &server_random, &client_random, suite).is_none(),
                "suite {suite:#06x} must be refused"
            );
        }
    }

    #[test]
    fn decryptor_negotiates_cbc_suites_and_the_etm_extension() {
        let store = store_with_master();
        for suite in ALL_CBC_SUITES {
            let mut dec = Tls12Decryptor::new(&store, &[0x4a; 32]).unwrap();
            assert_eq!(
                dec.feed(false, &server_hello_record_etm(suite, false)),
                RecordOutcome::Plain
            );
            assert!(dec.server_hello_seen());
            assert!(dec.direction_has_keys(true) && dec.direction_has_keys(false));
            assert_eq!(dec.unsupported_suite(), None, "suite {suite:#06x}");
        }
        // The extension walk records encrypt_then_mac presence in the
        // ServerHello and only there.
        let params = find_server_hello(&server_hello_record_etm(CBC_SHA1_SUITE, true)).unwrap();
        assert!(params.encrypt_then_mac);
        assert_eq!(params.cipher_suite, CBC_SHA1_SUITE);
        let params = find_server_hello(&server_hello_record_etm(CBC_SHA1_SUITE, false)).unwrap();
        assert!(!params.encrypt_then_mac);
        let params = find_server_hello(&server_hello_record(0xC02F, None)).unwrap();
        assert!(!params.encrypt_then_mac);
        // CBC-256 and SHA-384-PRF suites stay honestly refused.
        for suite in [0x0035u16, 0x003D, 0xC014, 0xC028] {
            let mut dec = Tls12Decryptor::new(&store, &[0x4a; 32]).unwrap();
            dec.set_server_hello(&[0x5b; 32], suite, false);
            assert_eq!(dec.unsupported_suite(), Some(suite), "suite {suite:#06x}");
            assert!(!dec.direction_has_keys(false));
        }
    }

    #[test]
    fn mac_then_encrypt_records_round_trip_all_four_suites() {
        for suite in ALL_CBC_SUITES {
            let mac_len = if is_sha1_suite(suite) { 20 } else { 32 };
            let (mut dec, block) = cbc_keyed_decryptor(suite, false);
            // Content lengths pinning the padding edge cases: one byte of
            // padding, a full 16-byte padding block, and the RFC-minimum
            // zero padding.
            let cases: [(usize, usize); 3] = if mac_len == 20 {
                [(10, 1), (11, 16), (27, 0)]
            } else {
                [(14, 1), (15, 16), (15, 0)]
            };
            let mut client_stream = ccs_record();
            let mut expected = Vec::new();
            for (i, (len, pad)) in cases.iter().enumerate() {
                let content = vec![b'a' + i as u8; *len];
                client_stream.extend_from_slice(&seal_cbc_mte_record(
                    suite,
                    &block.client,
                    i as u64,
                    &content,
                    CONTENT_APPLICATION_DATA,
                    *pad,
                ));
                expected.extend_from_slice(&content);
            }
            let walk = walk_stream(&mut dec, true, &client_stream);
            assert_eq!(walk.decrypted_records, 3, "suite {suite:#06x}");
            assert_eq!(walk.plain_records, 1); // the CCS
            assert_eq!(walk.plaintext, expected);
            assert_eq!(walk.app_records.len(), 3);
            assert!(walk.complete);
            // The server direction round-trips the same way under its own
            // keys, after the ServerHello and CCS in the clear.
            let mut server_stream = server_hello_record(suite, None);
            server_stream.extend_from_slice(&ccs_record());
            let content = vec![b's'; 17];
            server_stream.extend_from_slice(&seal_cbc_mte_record(
                suite,
                &block.server,
                0,
                &content,
                CONTENT_APPLICATION_DATA,
                minimal_pad(17, mac_len),
            ));
            let walk = walk_stream(&mut dec, false, &server_stream);
            assert_eq!(walk.decrypted_records, 1, "suite {suite:#06x}");
            assert_eq!(walk.plain_records, 2); // ServerHello + CCS
            assert_eq!(walk.plaintext, content);
            assert!(walk.complete);
        }
    }

    #[test]
    fn encrypt_then_mac_records_round_trip_all_four_suites() {
        for suite in ALL_CBC_SUITES {
            let (mut dec, block) = cbc_keyed_decryptor(suite, true);
            let mut stream = ccs_record();
            let mut expected = Vec::new();
            for (i, content) in [
                b"ping one\n".to_vec(),
                b"second message two\n".to_vec(),
                b"third three\n".to_vec(),
            ]
            .iter()
            .enumerate()
            {
                stream.extend_from_slice(&seal_cbc_etm_record(
                    suite,
                    &block.client,
                    i as u64,
                    content,
                    CONTENT_APPLICATION_DATA,
                ));
                expected.extend_from_slice(content);
            }
            let walk = walk_stream(&mut dec, true, &stream);
            assert_eq!(walk.decrypted_records, 3, "suite {suite:#06x}");
            assert_eq!(walk.plain_records, 1); // the CCS
            assert_eq!(walk.plaintext, expected);
            assert!(walk.complete);
        }
    }

    #[test]
    fn cbc_mac_failure_stays_ciphertext_and_advances_the_sequence() {
        // Both record shapes, one suite per MAC family: a corrupted record
        // is never emitted, and its sequence number is consumed anyway —
        // the genuine follow-up arrives at seq 1 and verifies (Wireshark
        // semantics; each record resyncs through its own explicit IV).
        for suite in [CBC_SHA1_SUITE, CBC_SHA256_SUITE] {
            for etm in [false, true] {
                let (mut dec, block) = cbc_keyed_decryptor(suite, etm);
                assert_eq!(dec.feed(true, &ccs_record()), RecordOutcome::Plain);
                let record = if etm {
                    seal_cbc_etm_record(
                        suite,
                        &block.client,
                        0,
                        b"payload",
                        CONTENT_APPLICATION_DATA,
                    )
                } else {
                    seal_cbc_mte_record(
                        suite,
                        &block.client,
                        0,
                        b"payload",
                        CONTENT_APPLICATION_DATA,
                        minimal_pad(7, if is_sha1_suite(suite) { 20 } else { 32 }),
                    )
                };
                let mut corrupted = record.clone();
                let last = corrupted.len() - 1;
                corrupted[last] ^= 0x01;
                assert_eq!(
                    dec.feed(true, &corrupted),
                    RecordOutcome::Undecryptable,
                    "suite {suite:#06x} etm {etm}"
                );
                assert_eq!(dec.decrypted_count(), 0);
                let follow = if etm {
                    seal_cbc_etm_record(suite, &block.client, 1, b"after", CONTENT_APPLICATION_DATA)
                } else {
                    seal_cbc_mte_record(
                        suite,
                        &block.client,
                        1,
                        b"after",
                        CONTENT_APPLICATION_DATA,
                        minimal_pad(5, if is_sha1_suite(suite) { 20 } else { 32 }),
                    )
                };
                assert_eq!(
                    dec.feed(true, &follow),
                    RecordOutcome::Decrypted {
                        content_type: CONTENT_APPLICATION_DATA,
                        plaintext: b"after".to_vec()
                    }
                );
            }
        }
    }

    #[test]
    fn consecutive_cbc_failures_stop_the_walk_with_an_honest_marker() {
        let suite = CBC_SHA1_SUITE;
        let mac_len = 20;
        // Eight consecutive failures stop the stream honestly — the record
        // limit behavior of the TLS 1.3 sibling, applied to CBC's inability
        // to authenticate before stripping.
        let (mut dec, block) = cbc_keyed_decryptor(suite, false);
        let mut stream = ccs_record();
        for seq in 0..MAX_CONSECUTIVE_CBC_FAILURES as u64 {
            let mut record = seal_cbc_mte_record(
                suite,
                &block.client,
                seq,
                b"payload",
                CONTENT_APPLICATION_DATA,
                minimal_pad(7, mac_len),
            );
            let last = record.len() - 1;
            record[last] ^= 0x01;
            stream.extend_from_slice(&record);
        }
        // A genuine record right after the run would decrypt — the walk
        // stops at the bound, not at broken framing.
        stream.extend_from_slice(&seal_cbc_mte_record(
            suite,
            &block.client,
            MAX_CONSECUTIVE_CBC_FAILURES as u64,
            b"after",
            CONTENT_APPLICATION_DATA,
            minimal_pad(5, mac_len),
        ));
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(walk.undecryptable_records, MAX_CONSECUTIVE_CBC_FAILURES);
        assert_eq!(walk.decrypted_records, 0);
        assert!(walk.plaintext.is_empty());
        assert!(!walk.complete);
        assert!(dec.cbc_stalled);
        // Seven failures leave room: the genuine record at seq 7 still
        // verifies and the walk completes.
        let (mut dec, block) = cbc_keyed_decryptor(suite, false);
        let mut stream = ccs_record();
        for seq in 0..(MAX_CONSECUTIVE_CBC_FAILURES - 1) as u64 {
            let mut record = seal_cbc_mte_record(
                suite,
                &block.client,
                seq,
                b"payload",
                CONTENT_APPLICATION_DATA,
                minimal_pad(7, mac_len),
            );
            let last = record.len() - 1;
            record[last] ^= 0x01;
            stream.extend_from_slice(&record);
        }
        stream.extend_from_slice(&seal_cbc_mte_record(
            suite,
            &block.client,
            (MAX_CONSECUTIVE_CBC_FAILURES - 1) as u64,
            b"recovered",
            CONTENT_APPLICATION_DATA,
            minimal_pad(9, mac_len),
        ));
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(walk.undecryptable_records, MAX_CONSECUTIVE_CBC_FAILURES - 1);
        assert_eq!(walk.plaintext, b"recovered".to_vec());
        assert!(walk.complete);
        assert!(!dec.cbc_stalled);
    }

    #[test]
    fn ccs_resets_the_cbc_sequence_and_failure_counter() {
        let suite = CBC_SHA1_SUITE;
        let mac_len = 20;
        // Two CCS cycles, like the GCM sibling's test: the same direction
        // restarts at seq 0 under the pending keys.
        let (mut dec, block) = cbc_keyed_decryptor(suite, false);
        let mut stream = ccs_record();
        for (seq, content) in [
            (0u64, &b"first"[..]),
            (1, &b"second"[..]),
            (0, &b"third"[..]),
            (1, &b"fourth"[..]),
        ] {
            stream.extend_from_slice(&seal_cbc_mte_record(
                suite,
                &block.client,
                seq,
                content,
                CONTENT_APPLICATION_DATA,
                minimal_pad(content.len(), mac_len),
            ));
            if seq == 1 {
                // The second CCS switches the same direction back to seq 0
                // (RFC 5246 §6.1 state change) after "second".
                stream.extend_from_slice(&ccs_record());
            }
        }
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(walk.plaintext, b"firstsecondthirdfourth".to_vec());
        assert!(walk.complete);
        // A failure run does not survive a ChangeCipherSpec either: the
        // switch forgives the counter and resets the sequence.
        let (mut dec, block) = cbc_keyed_decryptor(suite, false);
        let mut stream = ccs_record();
        let mut doomed = seal_cbc_mte_record(
            suite,
            &block.client,
            0,
            b"doomed",
            CONTENT_APPLICATION_DATA,
            minimal_pad(6, mac_len),
        );
        let last = doomed.len() - 1;
        doomed[last] ^= 0x01;
        stream.extend_from_slice(&doomed);
        stream.extend_from_slice(&ccs_record());
        stream.extend_from_slice(&seal_cbc_mte_record(
            suite,
            &block.client,
            0,
            b"fresh",
            CONTENT_APPLICATION_DATA,
            minimal_pad(5, mac_len),
        ));
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(walk.undecryptable_records, 1);
        assert_eq!(walk.plaintext, b"fresh".to_vec());
        assert!(walk.complete);
        assert!(!dec.cbc_stalled);
    }

    #[test]
    fn cbc_structural_bounds_refuse_records_without_guessing() {
        let suite = CBC_SHA1_SUITE;
        let (mut dec, block) = cbc_keyed_decryptor(suite, false);
        assert_eq!(dec.feed(true, &ccs_record()), RecordOutcome::Plain);
        // A fragment too short to carry IV + one ciphertext block.
        let mut short = vec![CONTENT_APPLICATION_DATA, 3, 3, 0, 24];
        short.extend_from_slice(&[0u8; 24]);
        assert_eq!(dec.feed(true, &short), RecordOutcome::Undecryptable);
        // A fragment whose ciphertext is not whole blocks (IV + 20 bytes).
        let mut ragged = vec![CONTENT_APPLICATION_DATA, 3, 3, 0, 36];
        ragged.extend_from_slice(&[0u8; 36]);
        assert_eq!(dec.feed(true, &ragged), RecordOutcome::Undecryptable);
        // Structural refusals never consume sequence numbers: the genuine
        // record at seq 0 still verifies.
        assert_eq!(
            dec.feed(
                true,
                &seal_cbc_mte_record(
                    suite,
                    &block.client,
                    0,
                    b"ok",
                    CONTENT_APPLICATION_DATA,
                    minimal_pad(2, 20)
                )
            ),
            RecordOutcome::Decrypted {
                content_type: CONTENT_APPLICATION_DATA,
                plaintext: b"ok".to_vec()
            }
        );
        // Padding beyond one block is refused honestly (the sender is not
        // guessed to have padded more than MAX_CBC_PADDING).
        let content = vec![b'z'; 11]; // 11 + 20 + 32 + 1 fills 4 blocks
        assert_eq!(
            dec.feed(
                true,
                &seal_cbc_mte_record(
                    suite,
                    &block.client,
                    1,
                    &content,
                    CONTENT_APPLICATION_DATA,
                    32
                )
            ),
            RecordOutcome::Undecryptable
        );
        // Under RFC 7366 the fragment must also carry the trailing MAC.
        let (mut dec, _) = cbc_keyed_decryptor(suite, true);
        assert_eq!(dec.feed(false, &ccs_record()), RecordOutcome::Plain);
        let mut short_etm = vec![CONTENT_APPLICATION_DATA, 3, 3, 0, 32];
        short_etm.extend_from_slice(&[0u8; 32]); // IV + one block, no MAC
        assert_eq!(dec.feed(true, &short_etm), RecordOutcome::Undecryptable);
    }

    /// Walk one real capture both directions and assert the honest record
    /// counts and the exact application bytes.
    fn walk_real_capture(
        client_hex: &str,
        server_hex: &str,
        keylog_line: &str,
        expect_etm: bool,
        expect_suite: u16,
    ) {
        let client_data = hex(client_hex);
        let server_data = hex(server_hex);
        let store = KeylogStore::parse(keylog_line).unwrap();
        let params = find_server_hello(&server_data).expect("ServerHello in the capture");
        assert_eq!(params.cipher_suite, expect_suite);
        assert_eq!(params.encrypt_then_mac, expect_etm);
        assert_eq!(params.negotiated_version, 0x0303);
        // The decryptor binds through the capture's own ClientHello random.
        let client_random: [u8; 32] = client_data[11..43].try_into().unwrap();
        let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
        dec.set_server_hello(
            &params.server_random,
            params.cipher_suite,
            params.encrypt_then_mac,
        );
        let client_walk = walk_stream(&mut dec, true, &client_data);
        assert_eq!(client_walk.decrypted_records, 4); // Finished + 3 app
        assert_eq!(client_walk.plain_records, 2); // ClientHello + CCS
        assert_eq!(
            client_walk.app_records,
            vec![
                b"ping one\n".to_vec(),
                b"second message two\n".to_vec(),
                b"third three\n".to_vec(),
            ]
        );
        assert!(client_walk.complete);
        let server_walk = walk_stream(&mut dec, false, &server_data);
        assert_eq!(server_walk.decrypted_records, 4);
        assert_eq!(server_walk.plain_records, 2); // ServerHello + CCS
        assert_eq!(
            server_walk.app_records,
            vec![
                b"PING ONE\n".to_vec(),
                b"SECOND MESSAGE TWO\n".to_vec(),
                b"THIRD THREE\n".to_vec(),
            ]
        );
        assert!(server_walk.complete);
        assert_eq!(dec.decrypted_count(), 8);
        assert!(!dec.cbc_stalled);
    }

    #[test]
    fn real_openssl_mac_then_encrypt_capture_decrypts_round_trip() {
        walk_real_capture(
            OPENSSL_MTE_SHA1_CLIENT,
            OPENSSL_MTE_SHA1_SERVER,
            OPENSSL_MTE_SHA1_KEYLOG,
            false,
            CBC_SHA1_SUITE,
        );
    }

    #[test]
    fn real_openssl_encrypt_then_mac_capture_decrypts_round_trip() {
        walk_real_capture(
            OPENSSL_ETM_SHA256_CLIENT,
            OPENSSL_ETM_SHA256_SERVER,
            OPENSSL_ETM_SHA256_KEYLOG,
            true,
            CBC_SHA256_SUITE,
        );
    }
}

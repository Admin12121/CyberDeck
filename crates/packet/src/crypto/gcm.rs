//! AES-128-GCM (NIST SP 800-38D): GHASH over GF(2^128), counter-mode
//! encryption and 128-bit tags. Only the shapes QUIC and TLS 1.3 use are
//! implemented: 128-bit keys, 96-bit nonces, 16-byte tags. Every function
//! takes bounded slices and reports failure instead of panicking.

use super::aes::Aes128;

pub const TAG_LEN: usize = 16;

/// GF(2^128) multiplication used by GHASH (SP 800-38D §6.3), MSB-first bit
/// order with the reduction constant R = 0xe1 || 0^120.
fn gf_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        if (x[i >> 3] >> (7 - (i & 7))) & 1 == 1 {
            for (a, b) in z.iter_mut().zip(v.iter()) {
                *a ^= b;
            }
        }
        let lsb = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    z
}

fn xor_block(y: &mut [u8; 16], block: &[u8; 16]) {
    for (a, b) in y.iter_mut().zip(block.iter()) {
        *a ^= b;
    }
}

/// GHASH (SP 800-38D §7.1): Y_i = (Y_{i-1} ^ X_i) · H over zero-padded
/// blocks; the caller appends the 128-bit length block at the end.
struct Ghash {
    h: [u8; 16],
    y: [u8; 16],
}

impl Ghash {
    fn new(h: [u8; 16]) -> Self {
        Self { h, y: [0u8; 16] }
    }

    fn update(&mut self, data: &[u8]) {
        let mut blocks = data.chunks_exact(16);
        for chunk in &mut blocks {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            xor_block(&mut self.y, &block);
            self.y = gf_mul(&self.y, &self.h);
        }
        let rem = blocks.remainder();
        if !rem.is_empty() {
            let mut block = [0u8; 16];
            block[..rem.len()].copy_from_slice(rem);
            xor_block(&mut self.y, &block);
            self.y = gf_mul(&self.y, &self.h);
        }
    }

    /// The trailing block [len(A)]64 || [len(C)]64 in bits.
    fn update_lengths(&mut self, aad_len: u64, ct_len: u64) {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&aad_len.wrapping_mul(8).to_be_bytes());
        block[8..].copy_from_slice(&ct_len.wrapping_mul(8).to_be_bytes());
        xor_block(&mut self.y, &block);
        self.y = gf_mul(&self.y, &self.h);
    }

    fn finalize(self) -> [u8; 16] {
        self.y
    }
}

/// J0 for a 96-bit nonce (SP 800-38D §8.1): IV || 0^31 || 1.
fn j0(nonce: &[u8; 12]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..12].copy_from_slice(nonce);
    block[15] = 1;
    block
}

/// Increment the rightmost 32 bits of the counter block (SP 800-38D §6.2).
fn inc32(counter: &mut [u8; 16]) {
    for byte in counter[12..].iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// GCTR (SP 800-38D §6.5): XOR `data` with the counter-mode keystream
/// starting at `counter`, in place.
fn gctr(aes: &Aes128, mut counter: [u8; 16], data: &mut [u8]) {
    for chunk in data.chunks_mut(16) {
        let keystream = aes.encrypt_block(&counter);
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
            *b ^= k;
        }
        inc32(&mut counter);
    }
}

fn tag_for(aes: &Aes128, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let h = aes.encrypt_block(&[0u8; 16]);
    let mut ghash = Ghash::new(h);
    ghash.update(aad);
    ghash.update(ciphertext);
    ghash.update_lengths(aad.len() as u64, ciphertext.len() as u64);
    let s = ghash.finalize();
    let ek_j0 = aes.encrypt_block(&j0(nonce));
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ ek_j0[i];
    }
    tag
}

/// Encrypt and authenticate: returns ciphertext || tag.
pub fn seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(key);
    let mut counter = j0(nonce);
    inc32(&mut counter);
    let mut out = plaintext.to_vec();
    gctr(&aes, counter, &mut out);
    let tag = tag_for(&aes, nonce, aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// Verify the tag and decrypt. Returns None on any tag mismatch (constant-
/// time comparison), missing tag, or malformed input — never a partial
/// plaintext.
pub fn open(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Option<Vec<u8>> {
    if ct_and_tag.len() < TAG_LEN {
        return None;
    }
    let (ciphertext, tag) = ct_and_tag.split_at(ct_and_tag.len() - TAG_LEN);
    let aes = Aes128::new(key);
    let expected = tag_for(&aes, nonce, aad, ciphertext);
    // Constant-time tag comparison over untrusted bytes.
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= expected[i] ^ tag[i];
    }
    if diff != 0 {
        return None;
    }
    let mut counter = j0(nonce);
    inc32(&mut counter);
    let mut plaintext = ciphertext.to_vec();
    gctr(&aes, counter, &mut plaintext);
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::new();
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn bytes(hexstr: &str) -> Vec<u8> {
        (0..hexstr.len() / 2)
            .map(|i| u8::from_str_radix(&hexstr[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn gf_mul_is_a_commutative_group_operation() {
        // Identity, commutativity and associativity in GF(2^128): the
        // algebraic properties GHASH relies on. The identity element in the
        // GCM bit convention is the block with the leftmost bit set (0x80).
        let mut one = [0u8; 16];
        one[0] = 0x80;
        let a = [
            0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let b = [
            0xffu8, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        let c = [
            0x0fu8, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
            0xe1, 0xf0,
        ];
        assert_eq!(gf_mul(&one, &a), a);
        assert_eq!(gf_mul(&a, &one), a);
        assert_eq!(gf_mul(&a, &b), gf_mul(&b, &a));
        let ab_c = gf_mul(&gf_mul(&a, &b), &c);
        let a_bc = gf_mul(&a, &gf_mul(&b, &c));
        assert_eq!(ab_c, a_bc);
        // Non-degenerate inputs multiply to something new.
        assert_ne!(gf_mul(&a, &b), a);
        assert_ne!(gf_mul(&a, &b), b);
    }

    #[test]
    fn gcm_spec_test_case_1_empty_inputs() {
        // McGrew/Viega GCM spec Appendix B, Test Case 1 (also carried in the
        // task's "RFC 8439 §5.2" reference; RFC 8439 itself covers
        // ChaCha20-Poly1305, so the AES-GCM vectors come from the GCM spec).
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let out = seal(&key, &nonce, &[], &[]);
        assert_eq!(hex(&out), "58e2fccefa7e3061367f1d57a4e7455a");
        assert_eq!(open(&key, &nonce, &[], &out), Some(Vec::new()));
    }

    #[test]
    fn gcm_spec_test_case_3_no_aad() {
        // McGrew/Viega GCM spec Appendix B, Test Case 3: 64-byte plaintext,
        // no AAD. (The task's "RFC 8439 §5.2" reference points here; RFC
        // 8439 itself covers ChaCha20-Poly1305, so the AES-GCM vectors come
        // from the GCM spec, cross-checked against Bouncy Castle's GCMTest.)
        let key: [u8; 16] = bytes("feffe9928665731c6d6a8f9467308308")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = bytes("cafebabefacedbaddecaf888").try_into().unwrap();
        let plaintext = bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let out = seal(&key, &nonce, &[], &plaintext);
        assert_eq!(
            hex(&out),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
             4d5c2af327cd64a62cf35abd2ba6fab4"
        );
        assert_eq!(open(&key, &nonce, &[], &out), Some(plaintext));
    }

    #[test]
    fn gcm_spec_test_case_4_with_aad() {
        // GCM spec Appendix B, Test Case 4: 60-byte plaintext, 20-byte AAD.
        let key: [u8; 16] = bytes("feffe9928665731c6d6a8f9467308308")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = bytes("cafebabefacedbaddecaf888").try_into().unwrap();
        let plaintext = bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let out = seal(&key, &nonce, &aad, &plaintext);
        assert_eq!(
            hex(&out),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             5bc94fbc3221a5db94fae95ae7121a47"
        );
        assert_eq!(open(&key, &nonce, &aad, &out), Some(plaintext));
    }

    #[test]
    fn corrupted_tag_or_aad_fails_closed() {
        let key = [7u8; 16];
        let nonce = [9u8; 12];
        let sealed = seal(&key, &nonce, b"aad", b"payload bytes");
        let mut flipped = sealed.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert_eq!(open(&key, &nonce, b"aad", &flipped), None);
        let mut flipped_ct = sealed.clone();
        flipped_ct[0] ^= 0x01;
        assert_eq!(open(&key, &nonce, b"aad", &flipped_ct), None);
        assert_eq!(open(&key, &nonce, b"wrong aad", &sealed), None);
        // Too short to carry a tag at all.
        assert_eq!(open(&key, &nonce, b"aad", &[0u8; 15]), None);
        // Tag-only input decrypts to the empty plaintext.
        let empty = seal(&key, &nonce, &[], &[]);
        assert_eq!(empty.len(), TAG_LEN);
        assert_eq!(open(&key, &nonce, &[], &empty), Some(Vec::new()));
    }
}

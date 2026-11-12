//! Hand-rolled cryptographic primitives for QUIC Initial decryption
//! (RFC 9001 §5). The `packet` crate is zero-dependency (serde only), so
//! SHA-256 (FIPS 180-4), HMAC/HKDF (RFC 5869), AES-128 (FIPS 197) and
//! AES-128-GCM (NIST SP 800-38D) are implemented here, bounded and
//! testable. Scope discipline: these primitives exist for the keyless
//! Initial-packet derivation only — nothing here is a general TLS stack,
//! and no decryption beyond what the public header permits is attempted.

pub mod aes;
pub mod gcm;
pub mod hkdf;
pub mod sha256;

/// RFC 9001 §5.2: the salt for version 1
/// (`0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9001 §5.2: `initial_secret = HKDF-Extract(initial_salt, dcid)`.
pub fn initial_secret(dcid: &[u8]) -> [u8; 32] {
    hkdf::hkdf_extract(&INITIAL_SALT_V1, dcid)
}

/// The secrets for protecting client packets (RFC 9001 §5.2, "client in").
pub fn client_initial_secret(initial_secret: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::hkdf_expand_label(initial_secret, b"client in", &[], &mut out);
    out
}

/// The secrets for protecting server packets (RFC 9001 §5.2, "server in").
pub fn server_initial_secret(initial_secret: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::hkdf_expand_label(initial_secret, b"server in", &[], &mut out);
    out
}

/// The AEAD key, static IV and header-protection key for one direction
/// (RFC 9001 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

/// RFC 9001 §5.1: `quic key` (16), `quic iv` (12), `quic hp` (16).
pub fn protection_keys(secret: &[u8; 32]) -> ProtectionKeys {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf::hkdf_expand_label(secret, b"quic key", &[], &mut key);
    hkdf::hkdf_expand_label(secret, b"quic iv", &[], &mut iv);
    hkdf::hkdf_expand_label(secret, b"quic hp", &[], &mut hp);
    ProtectionKeys { key, iv, hp }
}

/// RFC 9001 §5.3: the AEAD nonce is the static IV XOR the 32-bit packet
/// number (zero-padded on the left into the nonce's trailing 4 bytes).
pub fn aead_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn = (packet_number as u32).to_be_bytes();
    for i in 0..4 {
        nonce[8 + i] ^= pn[i];
    }
    nonce
}

/// RFC 9001 §5.4.3: `mask = AES-ECB(hp_key, sample)[0..5]`. The sample must
/// be exactly 16 bytes; anything else returns None rather than guessing.
pub fn header_protection_mask(hp: &[u8; 16], sample: &[u8]) -> Option<[u8; 5]> {
    if sample.len() != 16 {
        return None;
    }
    let mut block = [0u8; 16];
    block.copy_from_slice(sample);
    let encrypted = aes::Aes128::new(hp).encrypt_block(&block);
    Some([
        encrypted[0],
        encrypted[1],
        encrypted[2],
        encrypted[3],
        encrypted[4],
    ])
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

    /// The RFC 9001 Appendix A sample DCID.
    const A1_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn rfc_9001_a1_initial_secrets() {
        // RFC 9001 Appendix A.1, values verified against the RFC text.
        let secret = initial_secret(&A1_DCID);
        assert_eq!(
            hex(&secret),
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
        );
        let client = client_initial_secret(&secret);
        assert_eq!(
            hex(&client),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        let server = server_initial_secret(&secret);
        assert_eq!(
            hex(&server),
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
        );
    }

    #[test]
    fn rfc_9001_a1_protection_keys() {
        // Client and server "quic key" / "quic iv" / "quic hp" for the A.1
        // DCID (Appendix A.1).
        let secret = initial_secret(&A1_DCID);
        let client = protection_keys(&client_initial_secret(&secret));
        assert_eq!(hex(&client.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&client.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&client.hp), "9f50449e04a0e810283a1e9933adedd2");
        let server = protection_keys(&server_initial_secret(&secret));
        assert_eq!(hex(&server.key), "cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(hex(&server.iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(hex(&server.hp), "c206b8d9b9f0f37644430b490eeaa314");
    }

    #[test]
    fn header_protection_mask_matches_rfc_9001_a2_sample() {
        // RFC 9001 Appendix A.2: sample and mask for the client Initial.
        let secret = initial_secret(&A1_DCID);
        let client = protection_keys(&client_initial_secret(&secret));
        let sample = bytes("d1b1c98dd7689fb8ec11d242b123dc9b");
        let mask = header_protection_mask(&client.hp, &sample).unwrap();
        assert_eq!(hex(&mask), "437b9aec36");
        // A wrong-size sample is refused, never guessed.
        assert!(header_protection_mask(&client.hp, &sample[..15]).is_none());
    }

    #[test]
    fn aead_nonce_xors_the_packet_number_into_the_trailing_bytes() {
        // RFC 9001 §5.3 shape: nonce = IV XOR 0^64 || PN(32).
        let iv: [u8; 12] = bytes("fa044b2f42a3fd3b46fb255c").try_into().unwrap();
        let nonce = aead_nonce(&iv, 2);
        assert_eq!(hex(&nonce), "fa044b2f42a3fd3b46fb255e");
        // Packet number 0 leaves the IV untouched.
        assert_eq!(aead_nonce(&iv, 0), iv);
    }

    #[test]
    fn rfc_9001_a3_server_initial_round_trips_through_the_primitives() {
        // The published server Initial (Appendix A.3) decrypts with the
        // server keys derived from the client's first DCID — an end-to-end
        // published-vector check of extract → expand-label → AES → GHASH →
        // GCM and the header-protection mask order. The packet's own DCID is
        // the client's SCID, so the keys derive from the ORIGINAL client
        // DCID, not the header value.
        let packet = bytes(
            "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a\
             5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3\
             dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84\
             022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4\
             2158407dd074ee",
        );
        let secret = initial_secret(&A1_DCID);
        let keys = protection_keys(&server_initial_secret(&secret));
        // Header: cf 00000001 00 08 f067a5502a4262b5 00 00 4075 = 18 bytes;
        // a 2-byte packet number starts at offset 18.
        let pn_offset = 18usize;
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let mask = header_protection_mask(&keys.hp, sample).unwrap();
        assert_eq!(hex(&mask), "2ec0d8356a");
        let first = packet[0] ^ (mask[0] & 0x0f);
        assert_eq!(first, 0xc1); // long header, server Initial, 2-byte pn
        let pn_len = usize::from(first & 0x03) + 1;
        assert_eq!(pn_len, 2);
        let mut pn_bytes = [0u8; 4];
        for i in 0..pn_len {
            pn_bytes[i] = packet[pn_offset + i] ^ mask[1 + i];
        }
        assert_eq!(hex(&pn_bytes[..pn_len]), "0001"); // packet number 1
        let mut packet_number: u64 = 0;
        for i in 0..pn_len {
            packet_number = (packet_number << 8) | u64::from(pn_bytes[i]);
        }
        assert_eq!(packet_number, 1);
        let nonce = aead_nonce(&keys.iv, packet_number);
        let mut aad = packet[..pn_offset].to_vec();
        aad[0] = first;
        aad.extend_from_slice(&pn_bytes[..pn_len]);
        let ciphertext = &packet[pn_offset + pn_len..];
        let plaintext = gcm::open(&keys.key, &nonce, &aad, ciphertext).expect("AEAD must verify");
        assert_eq!(plaintext.len(), 99);
        // The unprotected frames from Appendix A.3: ACK then CRYPTO.
        assert_eq!(
            hex(&plaintext),
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
             88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
             0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
             020304"
        );
    }
}

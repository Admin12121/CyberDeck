//! TLS 1.2 record-layer decryption (RFC 5246) over reconstructed TCP stream
//! bytes, driven exclusively by a user-supplied NSS keylog's retained
//! `CLIENT_RANDOM` master secret (`super::keylog`). This is passive,
//! defensive analysis of already-captured traffic: decryption is attempted
//! ONLY when the keylog explicitly carries the connection's master secret
//! AND a plaintext ServerHello has been observed (it supplies the server
//! random and the negotiated suite), and a record is emitted only when its
//! GCM tag verifies — no key guessing, ever.
//!
//! Key schedule (RFC 5246 §6.3): `key_block = PRF(master_secret, "key
//! expansion", server_random || client_random)` with the RFC §5 P_SHA256
//! expansion, partitioned into per-direction write keys and fixed IVs (the
//! MAC-key slots are zero-length for AEAD suites). The PRF and key_block
//! derivation are hand-rolled here on top of the landed `hmac_sha256`
//! primitive; the AEAD itself is the landed `gcm` module untouched.
//!
//! Sequence numbers (RFC 5246 §6.1) restart at zero whenever a
//! ChangeCipherSpec switches a direction to its pending write keys; the
//! counters here are per direction and only advance on a verified record.
//!
//! Bounds mirror the TLS 1.3 sibling: at most [`MAX_CIPHERTEXT_RECORD`]
//! bytes per record (records beyond that are refused, never sliced), at
//! most [`MAX_DECRYPTED_RECORDS`] decrypted records per stream (then the
//! walk stops with an honest marker).
//!
//! Supported suites (AES-128-GCM, RFC 5288/5289, all SHA-256 PRF):
//! `0x009C` `TLS_RSA_WITH_AES_128_GCM_SHA256`, `0x00A2`
//! `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256`, `0xC02B`
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `0xC02F`
//! `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. Everything else — CBC suites,
//! the AES-256-GCM suites (they mandate the SHA-384 PRF, and the crate's
//! AES/GCM primitives are 128-bit only) — is refused with an honest
//! per-stream note and its ciphertext left untouched. CLIENT_RANDOM keylog
//! entries cover every TLS 1.2 key exchange, so the suite table is the
//! only limit on coverage.

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
            cursor += 4 + len;
            seen += 1;
        }
    }
    Some(ServerHelloParams {
        server_random,
        cipher_suite,
        negotiated_version,
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
/// once a ServerHello supplied both randoms) and whether that direction's
/// ChangeCipherSpec has switched them in.
#[derive(Default)]
struct Direction {
    keys: Option<WriteKeys>,
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

    /// True when this direction holds derived write keys.
    pub fn direction_has_keys(&self, from_client: bool) -> bool {
        self.direction(from_client).keys.is_some()
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

    /// Consume a plaintext ServerHello's facts (server random + negotiated
    /// suite) and derive the §6.3 key_block. The first ServerHello wins:
    /// renegotiation is not attempted, and an unsupported suite is recorded
    /// honestly instead of guessed around. Idempotent after the first call.
    pub fn set_server_hello(&mut self, server_random: &[u8; 32], cipher_suite: u16) {
        if self.server_hello_seen {
            return;
        }
        self.server_hello_seen = true;
        let Some(block) = key_block(
            &self.master_secret,
            server_random,
            &self.client_random,
            cipher_suite,
        ) else {
            self.unsupported_suite = Some(cipher_suite);
            return;
        };
        self.client.keys = Some(block.client);
        self.server.keys = Some(block.server);
    }

    /// Feed one full TLS record (5-byte header included, exactly as
    /// reconstructed from the stream). Every encrypted record is verified
    /// with the GCM tag before any plaintext is produced, and a ServerHello
    /// from the server direction is consumed automatically.
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
                            self.set_server_hello(&params.server_random, params.cipher_suite);
                        }
                    }
                    return RecordOutcome::Plain;
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
    }
    walk
}

#[cfg(test)]
mod tests {
    use super::*;
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
        dec.set_server_hello(&server_random, SUITE);
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
        dec.set_server_hello(&[0x99; 32], 0xC02B);
        let keys_before = dec.client.keys.clone();
        dec.set_server_hello(&server_random, SUITE);
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
        dec.set_server_hello(&server_random, SUITE);
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
        // CBC (0x0035 RSA AES-256-CBC-SHA1, 0xC027 ECDHE AES-128-CBC-SHA256)
        // and the AES-256-GCM SHA-384-PRF family are honestly refused.
        for suite in [0x0035u16, 0xC027, 0xC030, 0x009D] {
            let mut dec = Tls12Decryptor::new(&store, &client_random).unwrap();
            dec.set_server_hello(&[0x5b; 32], suite);
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
}

//! TLS 1.3 record-layer decryption over reconstructed TCP stream bytes
//! (RFC 8446 §5.2), driven exclusively by a user-supplied NSS keylog
//! (`super::keylog`). This is passive, defensive analysis of
//! already-captured traffic: decryption is attempted ONLY when the keylog
//! explicitly carries the traffic secrets for the stream's own ClientHello
//! random, and a record is emitted only when its GCM tag verifies — no key
//! guessing, ever.
//!
//! Bounds: at most 16 KiB + 256 padding + tag per record (records beyond
//! that are refused, never sliced), at most [`MAX_DECRYPTED_RECORDS`]
//! decrypted records per stream (then the caller stops with an honest
//! marker). The keylog secrets ARE the traffic secrets; only `key` (16
//! bytes, AES-128) and `iv` (12 bytes) are derived here via
//! `hkdf_expand_label` (RFC 8446 §7.1).

use super::gcm;
use super::hkdf::hkdf_expand_label;
use super::keylog::KeylogStore;

/// Per-record ciphertext bound: 2^14 content + 256 zero padding + 16 tag.
pub const MAX_CIPHERTEXT_RECORD: usize = 16 * 1024 + 256 + 16;
/// Hard cap on decrypted records per stream before the walk stops honestly.
pub const MAX_DECRYPTED_RECORDS: usize = 512;

pub const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_ALERT: u8 = 21;
pub const CONTENT_HANDSHAKE: u8 = 22;
pub const CONTENT_APPLICATION_DATA: u8 = 23;

/// AES-128-GCM traffic keys for one direction and key phase, plus that
/// phase's own per-record sequence number (RFC 8446 §5.2: the nonce is the
/// static IV XOR the 64-bit big-endian sequence in the trailing 8 bytes).
#[derive(Clone)]
struct PhaseKeys {
    key: [u8; 16],
    iv: [u8; 12],
    seq: u64,
}

fn phase_keys(traffic_secret: &[u8; 32]) -> Option<PhaseKeys> {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    if !hkdf_expand_label(traffic_secret, b"key", &[], &mut key) {
        return None;
    }
    if !hkdf_expand_label(traffic_secret, b"iv", &[], &mut iv) {
        return None;
    }
    Some(PhaseKeys { key, iv, seq: 0 })
}

impl PhaseKeys {
    /// RFC 8446 §5.2 nonce construction.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq[i];
        }
        nonce
    }
}

/// One direction's key phases. Each phase keeps its own sequence counter so
/// records stay verifiable regardless of the exact change_cipher_spec
/// placement (Wireshark-style: the verified GCM tag decides the phase, the
/// per-phase sequence order decides the nonce).
#[derive(Clone, Default)]
struct Direction {
    handshake: Option<PhaseKeys>,
    application: Option<PhaseKeys>,
    /// Phase that verified last, tried first for the next record.
    last_phase: Option<Phase>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Handshake,
    Application,
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

/// The TLS 1.3 decryptor for one stream, bound to one connection's keylog
/// entry via the ClientHello random. `None` construction means the keylog
/// has no entry for this connection — no decryption is ever attempted.
pub struct Tls13Decryptor {
    client: Direction,
    server: Direction,
    decrypted: usize,
    limit_reached: bool,
}

impl Tls13Decryptor {
    /// Bind the keylog entry for this connection's ClientHello random.
    /// Returns None when the keylog does not cover this connection.
    pub fn new(store: &KeylogStore, client_random: &[u8; 32]) -> Option<Self> {
        let secrets = store.secrets_for(client_random)?;
        let keys = |secret: &Option<[u8; 32]>| secret.as_ref().and_then(phase_keys);
        Some(Self {
            client: Direction {
                handshake: keys(&secrets.client_handshake),
                application: keys(&secrets.client_application),
                last_phase: None,
            },
            server: Direction {
                handshake: keys(&secrets.server_handshake),
                application: keys(&secrets.server_application),
                last_phase: None,
            },
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

    /// True when this direction holds at least one derived key phase.
    pub fn direction_has_keys(&self, from_client: bool) -> bool {
        let dir = if from_client {
            &self.client
        } else {
            &self.server
        };
        dir.handshake.is_some() || dir.application.is_some()
    }

    /// Feed one full TLS record (5-byte header included, exactly as
    /// reconstructed from the stream). Every encrypted record is verified
    /// with the GCM tag before any plaintext is produced.
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
            // change_cipher_spec is sent in the clear (RFC 8446 §5).
            CONTENT_CHANGE_CIPHER_SPEC => RecordOutcome::Plain,
            CONTENT_HANDSHAKE | CONTENT_ALERT | CONTENT_APPLICATION_DATA => {
                let dir = if from_client {
                    &mut self.client
                } else {
                    &mut self.server
                };
                if dir.handshake.is_none() && dir.application.is_none() {
                    // Pre-key ClientHello/ServerHello/alert records are
                    // legitimately plaintext; anything else stays ciphertext.
                    return RecordOutcome::Plain;
                }
                let aad = &record[..5];
                // Try the phase that verified last first; the GCM tag decides.
                let order = match dir.last_phase {
                    Some(Phase::Application) => [Phase::Application, Phase::Handshake],
                    _ => [Phase::Handshake, Phase::Application],
                };
                for phase in order {
                    let Some(keys) = (match phase {
                        Phase::Handshake => dir.handshake.as_mut(),
                        Phase::Application => dir.application.as_mut(),
                    }) else {
                        continue;
                    };
                    let nonce = keys.nonce();
                    let Some(mut plaintext) = gcm::open(&keys.key, &nonce, aad, payload) else {
                        continue;
                    };
                    keys.seq = keys.seq.wrapping_add(1);
                    dir.last_phase = Some(phase);
                    // TLSInnerPlaintext = content || zero padding || real
                    // content type (RFC 8446 §5.4): the first non-zero byte
                    // scanning backward is the type, the zero run before it
                    // is padding, everything earlier is content.
                    let Some(inner) = plaintext.iter().rposition(|&b| b != 0).and_then(|pos| {
                        let content_type = plaintext[pos];
                        let mut end = pos;
                        while end > 0 && plaintext[end - 1] == 0 {
                            end -= 1;
                        }
                        plaintext.truncate(end);
                        Some(content_type)
                    }) else {
                        // Tag verified but no content type byte: refuse the
                        // record rather than invent content.
                        self.bump_and_check_limit();
                        return RecordOutcome::Undecryptable;
                    };
                    self.bump_and_check_limit();
                    return RecordOutcome::Decrypted {
                        content_type: inner,
                        plaintext,
                    };
                }
                RecordOutcome::Undecryptable
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

/// The 32-byte random of a captured ClientHello record (5-byte TLS header,
/// 4-byte handshake header with kind + 3-byte length, 2-byte legacy
/// version, then the random), used to bind a keylog entry to a stream.
/// Only well-framed ClientHello records yield a random.
pub fn client_hello_random(record: &[u8]) -> Option<[u8; 32]> {
    if record.len() < 5 + 4 + 2 + 32 || record[0] != CONTENT_HANDSHAKE || record[1] != 3 {
        return None;
    }
    let handshake_len =
        ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    if record[5] != 1 /* ClientHello */ || handshake_len < 34 {
        return None;
    }
    if 4 + handshake_len > record.len() - 5 {
        return None;
    }
    Some(record[11..43].try_into().ok()?)
}

/// Per-direction result of walking a reconstructed stream through the
/// decryptor. `complete` is false when record framing broke midstream
/// (capture started mid-connection) or a record exceeded the size bound.
/// `app_records` carries each decrypted application-data record's own
/// plaintext so protocol hints can anchor on record boundaries instead of
/// the concatenated stream (handshake bytes precede application bytes).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StreamWalk {
    pub decrypted_records: usize,
    pub undecryptable_records: usize,
    pub plain_records: usize,
    pub plaintext: Vec<u8>,
    pub app_records: Vec<Vec<u8>>,
    pub complete: bool,
}

/// Walk one direction's reconstructed bytes record-by-record and decrypt
/// with the bound keylog. Stops honestly at the record limit or at broken
/// framing; concatenated decrypted content is returned in `StreamWalk`.
pub fn walk_stream(decryptor: &mut Tls13Decryptor, from_client: bool, data: &[u8]) -> StreamWalk {
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

    const HELLO_RANDOM_HEX: &str =
        "b3b1b0aa97b0fdfbbfb17e26bfd11b7fb2b252db4f6dfe95f4a25a77ba01d988";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn store_with(random_hex: &str) -> ([u8; 32], KeylogStore) {
        let mut keylog = String::new();
        for label in [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
        ] {
            keylog.push_str(&format!(
                "{label} {random_hex} {}\n",
                format!("{:064x}", label.len() as u128 + 0xdead)
            ));
        }
        let store = KeylogStore::parse(&keylog).unwrap();
        let random: [u8; 32] = hex(random_hex).try_into().unwrap();
        (random, store)
    }

    /// Derive the SAME keys the decryptor derives, to encrypt synthetic
    /// records with the crate's own gcm::seal (encrypt-then-decrypt
    /// self-consistency through the real crypto path).
    fn keys_for(label: &str) -> (PhaseKeys, [u8; 32]) {
        let secret: [u8; 32] = hex(&format!("{:064x}", label.len() as u128 + 0xdead))
            .try_into()
            .unwrap();
        (phase_keys(&secret).unwrap(), secret)
    }

    /// Encrypt one TLS 1.3 record exactly as the wire carries it.
    fn seal_record(
        secret: &[u8; 32],
        seq: u64,
        content: &[u8],
        content_type: u8,
        pad: usize,
    ) -> Vec<u8> {
        let keys = phase_keys(secret).unwrap();
        let mut inner = content.to_vec();
        inner.extend(std::iter::repeat(0u8).take(pad));
        inner.push(content_type);
        let body_len = (inner.len() as u16 + 16).to_be_bytes();
        let header = [CONTENT_APPLICATION_DATA, 3, 3, body_len[0], body_len[1]];
        let nonce_iv = {
            let mut n = keys.iv;
            let s = seq.to_be_bytes();
            for i in 0..8 {
                n[4 + i] ^= s[i];
            }
            n
        };
        let mut record = header.to_vec();
        record.extend_from_slice(&gcm::seal(&keys.key, &nonce_iv, &header, &inner));
        record
    }

    fn hello_record() -> Vec<u8> {
        // Minimal ClientHello: version + random + session id "" + suites.
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&hex(HELLO_RANDOM_HEX));
        hello.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        let mut message = vec![1, 0, 0, hello.len() as u8];
        message.extend_from_slice(&hello);
        let mut record = vec![CONTENT_HANDSHAKE, 3, 1];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    #[test]
    fn client_hello_random_is_extracted_from_well_framed_records() {
        let record = hello_record();
        let random = client_hello_random(&record).unwrap();
        assert_eq!(hex(HELLO_RANDOM_HEX).as_slice(), &random[..]);
        // A ServerHello (kind 2) never yields a ClientHello random.
        let mut server = record.clone();
        server[5] = 2;
        assert!(client_hello_random(&server).is_none());
        // Truncated or non-TLS records are refused.
        assert!(client_hello_random(&record[..40]).is_none());
        assert!(client_hello_random(b"GET / HTTP/1.1\r\n\r\n....").is_none());
    }

    #[test]
    fn decryptor_requires_a_matching_client_hello_random() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        assert!(Tls13Decryptor::new(&store, &random).is_some());
        // Wrong random: no entry, no decryptor, no attempt.
        assert!(Tls13Decryptor::new(&store, &[0u8; 32]).is_none());
    }

    #[test]
    fn handshake_and_application_records_round_trip_both_directions() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        let (client_hs, client_hs_secret) = keys_for("CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        let (server_app, server_app_secret) = keys_for("SERVER_TRAFFIC_SECRET_0");
        assert_eq!(client_hs.key, phase_keys(&client_hs_secret).unwrap().key);
        let mut dec = Tls13Decryptor::new(&store, &random).unwrap();

        // Client handshake-phase record (e.g. Finished) with padding.
        let hs = seal_record(
            &client_hs_secret,
            0,
            b"\x08finished-ish",
            CONTENT_HANDSHAKE,
            3,
        );
        let mut stream = hello_record();
        stream.extend_from_slice(&hs);
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(walk.decrypted_records, 1);
        assert_eq!(walk.plaintext, b"\x08finished-ish".to_vec());
        assert!(walk.complete);

        // Server application records with inner HTTP/2 frame bytes. The
        // first record's content must not end in a zero byte: per RFC 8446
        // §5.4 the zero run before the inner content type is padding, so
        // trailing content zeros are removed by the same rule as on the
        // wire (this record ends with a DATA-like marker byte).
        let mut frames = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        frames.extend_from_slice(&[0, 0, 4, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0]); // SETTINGS
        frames.extend_from_slice(b"h2-payload-1");
        let r0 = seal_record(&server_app_secret, 0, &frames, CONTENT_APPLICATION_DATA, 0);
        let r1 = seal_record(
            &server_app_secret,
            1,
            b"app payload",
            CONTENT_APPLICATION_DATA,
            2,
        );
        let mut server_stream = hello_record();
        server_stream.extend_from_slice(&r0);
        server_stream.extend_from_slice(&r1);
        let walk = walk_stream(&mut dec, false, &server_stream);
        assert_eq!(walk.decrypted_records, 2);
        // The padded record contributes its content only; padding is stripped.
        let mut expected = frames.clone();
        expected.extend_from_slice(b"app payload");
        assert_eq!(walk.plaintext, expected);
        assert!(walk.complete);
        assert_eq!(dec.decrypted_count(), 3);
    }

    #[test]
    fn truncated_and_malformed_records_stay_ciphertext() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        let (_, secret) = keys_for("SERVER_TRAFFIC_SECRET_0");
        let mut dec = Tls13Decryptor::new(&store, &random).unwrap();
        let record = seal_record(&secret, 0, b"payload", CONTENT_APPLICATION_DATA, 0);
        // Truncate the ciphertext body: header claims more than present, so
        // the walk stops at broken framing before feeding anything.
        let mut stream = record.clone();
        stream.truncate(record.len() - 10);
        let walk = walk_stream(&mut dec, false, &stream);
        assert_eq!(walk.undecryptable_records, 0);
        assert!(!walk.complete);
        assert!(walk.plaintext.is_empty());
        // Corrupted tag byte: framing is fine, verification must fail.
        let mut corrupted = record.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        let mut dec2 = Tls13Decryptor::new(&store, &random).unwrap();
        let walk = walk_stream(&mut dec2, false, &corrupted);
        assert_eq!(walk.undecryptable_records, 1);
        assert!(walk.complete);
        assert!(walk.plaintext.is_empty());
    }

    #[test]
    fn oversized_records_are_refused_not_sliced() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        let mut dec = Tls13Decryptor::new(&store, &random).unwrap();
        let mut record = vec![CONTENT_APPLICATION_DATA, 3, 3, 0xff, 0xff];
        record.extend_from_slice(&[0u8; 64]);
        let outcome = dec.feed(false, &record);
        assert_eq!(outcome, RecordOutcome::Undecryptable);
    }

    #[test]
    fn wrong_keylog_secrets_never_produce_plaintext() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        // Encrypt under a secret that is NOT in the keylog.
        let foreign_secret = [0x42u8; 32];
        let record = seal_record(
            &foreign_secret,
            0,
            b"secret payload",
            CONTENT_APPLICATION_DATA,
            0,
        );
        let mut dec = Tls13Decryptor::new(&store, &random).unwrap();
        let walk = walk_stream(&mut dec, false, &record);
        assert_eq!(walk.undecryptable_records, 1);
        assert!(walk.plaintext.is_empty());
    }

    #[test]
    fn record_limit_stops_the_walk_with_an_honest_marker() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        let (_, secret) = keys_for("SERVER_TRAFFIC_SECRET_0");
        let mut dec = Tls13Decryptor::new(&store, &random).unwrap();
        let mut stream = hello_record();
        for seq in 0..(MAX_DECRYPTED_RECORDS + 2) {
            stream.extend_from_slice(&seal_record(
                &secret,
                seq as u64,
                b"x",
                CONTENT_APPLICATION_DATA,
                0,
            ));
        }
        let walk = walk_stream(&mut dec, false, &stream);
        assert_eq!(dec.decrypted_count(), MAX_DECRYPTED_RECORDS);
        assert!(dec.limit_reached());
        assert!(!walk.complete);
        assert_eq!(walk.decrypted_records, MAX_DECRYPTED_RECORDS);
    }

    #[test]
    fn unknown_record_types_pass_through_as_plain() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        let mut dec = Tls13Decryptor::new(&store, &random).unwrap();
        let ccs = [CONTENT_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1];
        assert_eq!(dec.feed(true, &ccs), RecordOutcome::Plain);
        // Unrecognized type 99 with no keys at all is Plain (not claimed).
        let unknown = [99, 3, 3, 0, 1, 1];
        assert_eq!(dec.feed(true, &unknown), RecordOutcome::Plain);
    }

    #[test]
    fn per_phase_sequence_numbers_follow_the_wire_order() {
        let (random, store) = store_with(HELLO_RANDOM_HEX);
        let (_, secret) = keys_for("CLIENT_TRAFFIC_SECRET_0");
        let mut dec = Tls13Decryptor::new(&store, &random).unwrap();
        let mut stream = hello_record();
        stream.extend_from_slice(&seal_record(
            &secret,
            0,
            b"first",
            CONTENT_APPLICATION_DATA,
            0,
        ));
        stream.extend_from_slice(&seal_record(
            &secret,
            1,
            b"second",
            CONTENT_APPLICATION_DATA,
            0,
        ));
        stream.extend_from_slice(&seal_record(
            &secret,
            2,
            b"third",
            CONTENT_APPLICATION_DATA,
            0,
        ));
        let walk = walk_stream(&mut dec, true, &stream);
        assert_eq!(walk.plaintext, b"firstsecondthird".to_vec());
        assert_eq!(walk.decrypted_records, 3);
        assert!(walk.complete);
    }
}

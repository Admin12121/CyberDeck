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

// --- coordinator-insert (TLS 1.3 keylog slice): additive module declarations
// --- for the new files below; the existing primitives above are untouched.
pub mod keylog;
pub mod tls13;

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

// --- coordinator-insert (QUIC Handshake/1-RTT key-schedule slice): the
// --- section below is purely additive — the Initial derivation above is
// --- untouched. It derives QUIC protection keys from TLS 1.3 keylog
// --- traffic secrets (RFC 9001 §5.1) and carries the bounded per-capture
// --- connection state the dissection layer holds to decrypt Handshake and
// --- 1-RTT packets. Decryption itself always happens through the AEAD
// --- tag: this store never derives or guesses secrets.

use std::cell::RefCell;
use std::collections::HashMap;

/// The four protection-key sets one QUIC connection can carry (RFC 9001
/// §5.1): for each direction, the handshake and application traffic
/// secrets from the user-supplied keylog expand to `quic key` (16),
/// `quic iv` (12) and `quic hp` (16). A `None` slot means the keylog
/// carries no secret for that phase — that phase stays ciphertext, never
/// guessed. Early (0-RTT) secrets are intentionally unmapped: early-data
/// decryption is out of scope and stays header-only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicProtectionKeys {
    pub client_handshake: Option<ProtectionKeys>,
    pub server_handshake: Option<ProtectionKeys>,
    pub client_application: Option<ProtectionKeys>,
    pub server_application: Option<ProtectionKeys>,
}

/// RFC 9001 §5.1 key schedule from one keylog entry's traffic secrets:
/// every present secret expands through the same `quic key`/`quic iv`/
/// `quic hp` labels the Initial derivation above uses.
pub fn quic_protection_keys(secrets: &keylog::KeylogSecrets) -> QuicProtectionKeys {
    let derive = |secret: &Option<[u8; 32]>| secret.as_ref().map(protection_keys);
    QuicProtectionKeys {
        client_handshake: derive(&secrets.client_handshake),
        server_handshake: derive(&secrets.server_handshake),
        client_application: derive(&secrets.client_application),
        server_application: derive(&secrets.server_application),
    }
}

/// One (direction, phase) key slot of a connection. The variant order is
/// the index into a connection's largest-packet-number state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicKeySlot {
    ClientHandshake,
    ServerHandshake,
    ClientApplication,
    ServerApplication,
}

impl QuicKeySlot {
    fn index(self) -> usize {
        match self {
            QuicKeySlot::ClientHandshake => 0,
            QuicKeySlot::ServerHandshake => 1,
            QuicKeySlot::ClientApplication => 2,
            QuicKeySlot::ServerApplication => 3,
        }
    }
}

/// The packet direction a passive observer works with: which side SENT the
/// packet. A route's side is the side that sends packets carrying that
/// destination connection id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicSide {
    Client,
    Server,
}

impl QuicSide {
    pub fn opposite(self) -> Self {
        match self {
            QuicSide::Client => QuicSide::Server,
            QuicSide::Server => QuicSide::Client,
        }
    }
}

/// RFC 9000 Appendix A.3 `DecodePacketNumber`: reconstruct the full packet
/// number from the on-wire truncated value and the connection's largest
/// verified packet number. The underflow-guarded previous-window branch
/// stays on the primary candidate instead of fabricating a negative
/// number — the AEAD tag decides in every case.
pub fn reconstruct_pn_with(largest: u64, truncated: u64, pn_len: usize) -> u64 {
    let pn_nbits = (pn_len * 8) as u32;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let candidate = (largest & !pn_mask) | (truncated & pn_mask);
    if candidate + pn_hwin <= largest {
        // The candidate sits beyond the window's halfway point: next window.
        return candidate.wrapping_add(pn_win);
    }
    if candidate > largest.saturating_add(pn_hwin) && candidate >= pn_win {
        // The candidate sits before the window's halfway point: previous
        // window, when one exists.
        return candidate - pn_win;
    }
    candidate
}

/// One connection's derived QUIC keys plus the packet-number reconstruction
/// state each (direction, phase) needs (RFC 9000 §A). The largest packet
/// number per slot moves ONLY through [`QuicConnectionKeys::commit_pn`],
/// which the dissection layer calls after a packet's AEAD tag verified —
/// an unverified packet never shifts the window.
#[derive(Debug, Clone, Default)]
pub struct QuicConnectionKeys {
    pub keys: QuicProtectionKeys,
    largest_pn: [Option<u64>; 4],
}

impl QuicConnectionKeys {
    pub fn new(keys: QuicProtectionKeys) -> Self {
        Self {
            keys,
            largest_pn: [None; 4],
        }
    }

    /// True once the slot has committed at least one verified packet
    /// number; first-flight slots decode the on-wire value as-is.
    pub(crate) fn slot_has_state(&self, slot: QuicKeySlot) -> bool {
        self.largest_pn[slot.index()].is_some()
    }

    /// The primary RFC 9000 §A.3 candidate for the slot. Without state yet
    /// the on-wire value returns as-is — exact for first-flight traffic and
    /// never fabricated.
    pub fn reconstruct_pn(&self, slot: QuicKeySlot, truncated: u64, pn_len: usize) -> u64 {
        match self.largest_pn[slot.index()] {
            None => truncated,
            Some(largest) => reconstruct_pn_with(largest, truncated, pn_len),
        }
    }

    /// Primary candidate plus its window neighbors, for captures with mild
    /// reordering. Every candidate is only accepted when its own AEAD tag
    /// verifies; the count is at most 3.
    pub fn pn_candidates(
        &self,
        slot: QuicKeySlot,
        truncated: u64,
        pn_len: usize,
    ) -> ([u64; 3], usize) {
        let primary = self.reconstruct_pn(slot, truncated, pn_len);
        let win = 1u64 << (pn_len * 8);
        let mut out = [primary; 3];
        let mut count = 1usize;
        if let Some(plus) = primary.checked_add(win) {
            out[count] = plus;
            count += 1;
        }
        if primary >= win {
            out[count] = primary - win;
            count += 1;
        }
        (out, count)
    }

    /// Commit a packet number whose AEAD tag verified (RFC 9000 §A:
    /// OnPacketDecrypted keeps the maximum).
    pub fn commit_pn(&mut self, slot: QuicKeySlot, packet_number: u64) {
        let entry = &mut self.largest_pn[slot.index()];
        *entry = Some(match *entry {
            Some(largest) if largest >= packet_number => largest,
            _ => packet_number,
        });
    }
}

/// Bounded state sizes: at most 64 keylog-bound connections per capture
/// (LRU evicted) and at most 8 destination CIDs routed per connection.
pub const MAX_QUIC_CONNECTIONS: usize = 64;
pub(crate) const MAX_CIDS_PER_CONNECTION: usize = 8;
/// Short-header route attempts per packet: candidates are tag-decided, but
/// the attempt count stays bounded.
pub(crate) const MAX_ROUTE_ATTEMPTS: usize = 4;

/// A hashable length-prefixed connection id (QUIC caps CIDs at 20 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct QuicCid([u8; 21]);

impl QuicCid {
    fn new(cid: &[u8]) -> Option<Self> {
        if cid.len() > 20 {
            return None;
        }
        let mut key = [0u8; 21];
        key[0] = cid.len() as u8;
        key[1..1 + cid.len()].copy_from_slice(cid);
        Some(Self(key))
    }

    pub(crate) fn len(&self) -> usize {
        self.0[0] as usize
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0[1..1 + self.0[0] as usize]
    }
}

/// One destination-CID route: which connection owns it and which side
/// sends packets addressed to it (that side's keys apply).
#[derive(Debug, Clone, Copy)]
pub(crate) struct QuicRoute {
    pub(crate) slot: usize,
    pub(crate) side: QuicSide,
}

/// One keylog-bound connection: the keys derived from its keylog entry and
/// the original client DCID that derives the connection's Initial secrets.
pub(crate) struct QuicConnection {
    pub(crate) client_random: [u8; 32],
    pub(crate) keys: QuicConnectionKeys,
    pub(crate) initial_dcid: Vec<u8>,
    pub(crate) last_used: u64,
}

/// Bounded per-capture QUIC decryption state: the user-supplied keylog plus
/// a ≤[`MAX_QUIC_CONNECTIONS`] LRU of keylog-bound connections and their
/// CID routes. The state exists so Handshake and 1-RTT packets can be
/// decrypted with keys the keylog explicitly provides for the connection's
/// own ClientHello random; each packet is still emitted only when its AEAD
/// tag verifies. Hold one per capture; install it around a parse with
/// [`quic_capture_install`] or feed it explicitly through
/// `QuicDecryptor::dissect` (implemented in the dissection layer).
pub struct QuicDecryptor {
    pub(crate) keylog: keylog::KeylogStore,
    pub(crate) routes: HashMap<QuicCid, QuicRoute>,
    pub(crate) connections: Vec<QuicConnection>,
    pub(crate) stamp: u64,
}

impl QuicDecryptor {
    pub fn new(keylog: keylog::KeylogStore) -> Self {
        Self {
            keylog,
            routes: HashMap::new(),
            connections: Vec::new(),
            stamp: 0,
        }
    }

    /// The destination-CID route for a parsed header, if one is bound.
    pub(crate) fn route_lookup(&self, cid: &[u8]) -> Option<(usize, QuicSide)> {
        let route = *self.routes.get(&QuicCid::new(cid)?)?;
        Some((route.slot, route.side))
    }

    /// Short-header route candidates: a short header carries no DCID
    /// length, so bound state supplies it — every route whose CID matches
    /// the bytes right after the first byte is a candidate (longest first,
    /// bounded).
    pub(crate) fn short_header_routes(
        &self,
        after_first_byte: &[u8],
    ) -> Vec<(QuicCid, usize, QuicSide)> {
        let mut out: Vec<(QuicCid, usize, QuicSide)> = self
            .routes
            .iter()
            .filter(|(cid, _)| {
                cid.len() <= after_first_byte.len() && cid.bytes() == &after_first_byte[..cid.len()]
            })
            .map(|(cid, route)| (*cid, route.slot, route.side))
            .collect();
        out.sort_by_key(|(cid, _, _)| std::cmp::Reverse(cid.len()));
        out.truncate(MAX_ROUTE_ATTEMPTS);
        out
    }

    pub(crate) fn conn_mut(&mut self, slot: usize) -> Option<&mut QuicConnection> {
        self.connections.get_mut(slot)
    }

    /// LRU touch: records that the slot's state was just used.
    pub(crate) fn touch(&mut self, slot: usize) {
        self.stamp = self.stamp.wrapping_add(1);
        if let Some(conn) = self.connections.get_mut(slot) {
            conn.last_used = self.stamp;
        }
    }

    /// Bind a connection from a decrypted client Initial: keys come from
    /// the keylog entry matching the ClientHello random carried in the
    /// CRYPTO frame — no match, no binding, no attempt anywhere else.
    pub(crate) fn bind_client_initial(&mut self, dcid: &[u8], scid: &[u8], random: [u8; 32]) {
        let secrets = match self.keylog.secrets_for(&random) {
            Some(secrets) => secrets.clone(),
            None => return,
        };
        let keys = quic_protection_keys(&secrets);
        let slot = match self.slot_for_random(&random) {
            Some(slot) => slot,
            None => {
                if self.connections.len() >= MAX_QUIC_CONNECTIONS {
                    self.evict_one();
                }
                self.stamp = self.stamp.wrapping_add(1);
                self.connections.push(QuicConnection {
                    client_random: random,
                    keys: QuicConnectionKeys::new(keys),
                    initial_dcid: Vec::new(),
                    last_used: self.stamp,
                });
                self.connections.len() - 1
            }
        };
        {
            let conn = &mut self.connections[slot];
            conn.initial_dcid = dcid.to_vec();
            conn.last_used = self.stamp;
        }
        // Packets addressed to the client's source CID are sent by the
        // server (server Handshake/1-RTT land here).
        self.insert_route(scid, slot, QuicSide::Server);
    }

    /// Record the sender's source CID as the destination its opposite side
    /// targets (a server Handshake's SCID is where client 1-RTT goes).
    pub(crate) fn bind_scid(&mut self, slot: usize, scid: &[u8], sender: QuicSide) {
        self.insert_route(scid, slot, sender.opposite());
    }

    /// NEW_CONNECTION_ID frames announce CIDs the sender's opposite side
    /// will address; each joins the connection's route set (bounded).
    pub(crate) fn bind_new_cids(&mut self, slot: usize, sender: QuicSide, cids: &[Vec<u8>]) {
        for cid in cids {
            self.bind_scid(slot, cid, sender);
        }
    }

    /// The original client DCID stored by the bound connection whose route
    /// a server packet's DCID (the client's SCID) names. This is what lets
    /// a server Initial verify after the client flight was seen.
    pub(crate) fn initial_dcid_for(&self, cid: &[u8]) -> Option<Vec<u8>> {
        let route = *self.routes.get(&QuicCid::new(cid)?)?;
        Some(self.connections.get(route.slot)?.initial_dcid.clone())
    }

    fn slot_for_random(&self, random: &[u8; 32]) -> Option<usize> {
        self.connections
            .iter()
            .position(|conn| conn.client_random == *random)
    }

    fn insert_route(&mut self, cid: &[u8], slot: usize, side: QuicSide) {
        let Some(key) = QuicCid::new(cid) else {
            return;
        };
        if let Some(route) = self.routes.get_mut(&key) {
            route.slot = slot;
            route.side = side;
            return;
        }
        let owned = self
            .routes
            .values()
            .filter(|route| route.slot == slot)
            .count();
        if owned >= MAX_CIDS_PER_CONNECTION {
            return;
        }
        self.routes.insert(key, QuicRoute { slot, side });
    }

    /// Evict the least-recently-used connection and every route to it.
    /// Slot indices are compacted: the moved tail's routes re-point.
    fn evict_one(&mut self) {
        let Some(oldest) = self
            .connections
            .iter()
            .enumerate()
            .min_by_key(|(_, conn)| conn.last_used)
            .map(|(index, _)| index)
        else {
            return;
        };
        // Drop the evicted connection's routes before indices move.
        self.routes.retain(|_, route| route.slot != oldest);
        let last = self.connections.len() - 1;
        self.connections.swap_remove(oldest);
        if oldest != last {
            for route in self.routes.values_mut() {
                if route.slot == last {
                    route.slot = oldest;
                }
            }
        }
    }
}

thread_local! {
    static QUIC_CAPTURE: RefCell<Option<QuicDecryptor>> = const { RefCell::new(None) };
}

/// RAII installation of a per-capture QUIC decryptor on the current thread.
/// The guard clears the installation when dropped — including on early
/// returns — so a forgotten clear cannot leak bound keys into unrelated
/// parses on the same thread.
#[must_use = "the capture-scoped decryptor clears only when the guard drops"]
pub struct QuicCaptureGuard(());

impl Drop for QuicCaptureGuard {
    fn drop(&mut self) {
        QUIC_CAPTURE.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Install `decryptor` for the current thread; every `dissect` call until
/// the returned guard drops routes through its bound state. Nothing is
/// stored globally beyond the guard's lifetime.
pub fn quic_capture_install(decryptor: QuicDecryptor) -> QuicCaptureGuard {
    QUIC_CAPTURE.with(|slot| *slot.borrow_mut() = Some(decryptor));
    QuicCaptureGuard(())
}

/// Run `f` with the installed capture decryptor, if any (crate-internal:
/// the dissection entry consults this instead of threading state through
/// every link/network/transport signature).
pub(crate) fn with_quic_capture<R>(f: impl FnOnce(Option<&mut QuicDecryptor>) -> R) -> R {
    QUIC_CAPTURE.with(|slot| {
        let mut guard = slot.borrow_mut();
        f(guard.as_mut())
    })
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

    fn keylog_secret(label: &str) -> [u8; 32] {
        // A deterministic per-label secret: FNV-1a over the label bytes, so
        // distinct labels never collide by construction.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in label.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        bytes(&format!("{hash:064x}")).try_into().unwrap()
    }

    fn keylog_secrets(labels: &[&str]) -> keylog::KeylogSecrets {
        let mut text = String::new();
        let random = "b3b1b0aa97b0fdfbbfb17e26bfd11b7fb2b252db4f6dfe95f4a25a77ba01d988";
        for label in labels {
            let secret = hex(&keylog_secret(label));
            text.push_str(&format!("{label} {random} {secret}\n"));
        }
        keylog::KeylogStore::parse(&text)
            .unwrap()
            .secrets_for(&bytes(random).try_into().unwrap())
            .cloned()
            .unwrap()
    }

    #[test]
    fn quic_protection_keys_derive_each_direction_and_phase_from_keylog_secrets() {
        let all = keylog_secrets(&[
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
        ]);
        let keys = quic_protection_keys(&all);
        // Every slot is exactly the §5.1 expansion of its own secret —
        // identical to the path the Initial derivation uses.
        assert_eq!(
            keys.client_handshake,
            Some(protection_keys(&keylog_secret(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
            )))
        );
        assert_eq!(
            keys.server_handshake,
            Some(protection_keys(&keylog_secret(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET"
            )))
        );
        assert_eq!(
            keys.client_application,
            Some(protection_keys(&keylog_secret("CLIENT_TRAFFIC_SECRET_0")))
        );
        assert_eq!(
            keys.server_application,
            Some(protection_keys(&keylog_secret("SERVER_TRAFFIC_SECRET_0")))
        );
        // The four phases derive distinct key material.
        let distinct: Vec<[u8; 16]> = [
            keys.client_handshake.clone(),
            keys.server_handshake.clone(),
            keys.client_application.clone(),
            keys.server_application.clone(),
        ]
        .into_iter()
        .flatten()
        .map(|k| k.key)
        .collect();
        for i in 0..distinct.len() {
            for j in i + 1..distinct.len() {
                assert_ne!(distinct[i], distinct[j]);
            }
        }
        // Missing secrets stay None — that phase is never guessed.
        let partial = keylog_secrets(&["SERVER_HANDSHAKE_TRAFFIC_SECRET"]);
        let keys = quic_protection_keys(&partial);
        assert!(keys.server_handshake.is_some());
        assert!(keys.client_handshake.is_none());
        assert!(keys.client_application.is_none());
        assert!(keys.server_application.is_none());
        // Early (0-RTT) secrets are intentionally unmapped.
        let early_only = keylog_secrets(&["CLIENT_EARLY_TRAFFIC_SECRET"]);
        assert_eq!(
            quic_protection_keys(&early_only),
            QuicProtectionKeys::default()
        );
    }

    #[test]
    fn pn_reconstruction_follows_the_rfc_9000_appendix_a_window() {
        // First packet of a slot: no state, the on-wire value as-is.
        let conn = QuicConnectionKeys::default();
        assert_eq!(
            conn.reconstruct_pn(QuicKeySlot::ClientApplication, 1300, 2),
            1300
        );
        // The large jump from the slice scope: pn 0 → 1300 carried in a
        // 2-byte encoding reconstructs exactly once state exists.
        let mut conn = QuicConnectionKeys::default();
        conn.commit_pn(QuicKeySlot::ClientApplication, 0);
        assert_eq!(
            conn.reconstruct_pn(QuicKeySlot::ClientApplication, 1300, 2),
            1300
        );
        // After committing 1300, a 1-byte encoding of the next packet
        // (1301 → truncated 0x15) reconstructs through the window math.
        conn.commit_pn(QuicKeySlot::ClientApplication, 1300);
        assert_eq!(
            conn.reconstruct_pn(QuicKeySlot::ClientApplication, 0x15, 1),
            1301
        );
        // Direct RFC 9000 §A.3 shape: largest 0xaa82, 1-byte truncated 0x83.
        assert_eq!(reconstruct_pn_with(0xaa82, 0x83, 1), 0xaa83);
        // Next-window branch: a candidate at/below the halfway point moves
        // forward one window (43520 + 128 <= 43650).
        assert_eq!(reconstruct_pn_with(0xaa82, 0x00, 1), 0xab00);
        // Commit keeps the maximum — a reordered older packet never moves
        // the window backwards (largest stays 1300 here, so the next
        // 1-byte encoding still reconstructs through the same window).
        conn.commit_pn(QuicKeySlot::ClientApplication, 5);
        assert!(conn.slot_has_state(QuicKeySlot::ClientApplication));
        assert!(!conn.slot_has_state(QuicKeySlot::ServerApplication));
        assert_eq!(
            conn.reconstruct_pn(QuicKeySlot::ClientApplication, 0x15, 1),
            1301
        );
    }

    #[test]
    fn pn_candidates_stay_bounded_and_deduplicated() {
        let conn = QuicConnectionKeys::default();
        // No state: the primary is the wire value; the previous-window
        // neighbor is dropped when it would underflow (7 < 256).
        let (candidates, count) = conn.pn_candidates(QuicKeySlot::ServerHandshake, 7, 1);
        assert_eq!(count, 2);
        assert_eq!(candidates[0], 7);
        assert_eq!(candidates[1], 7 + 256);
        // With committed state and room on both sides, all three candidates
        // appear (largest 1300 → 1-byte truncated 0x15 reconstructs 1301).
        let mut conn = QuicConnectionKeys::default();
        conn.commit_pn(QuicKeySlot::ServerHandshake, 1300);
        let (candidates, count) = conn.pn_candidates(QuicKeySlot::ServerHandshake, 0x15, 1);
        assert_eq!(count, 3);
        assert_eq!(candidates[0], 1301);
        assert_eq!(candidates[1], 1301 + 256);
        assert_eq!(candidates[2], 1301 - 256);
    }

    #[test]
    fn quic_capture_guard_installs_and_clears_on_the_same_thread() {
        use super::keylog::KeylogStore;
        assert!(with_quic_capture(|dec| dec.is_none()));
        let guard = quic_capture_install(QuicDecryptor::new(KeylogStore::parse("").unwrap()));
        assert!(with_quic_capture(|dec| dec.is_some()));
        drop(guard);
        assert!(with_quic_capture(|dec| dec.is_none()));
    }
}

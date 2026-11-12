//! Bounded QUIC dissection over UDP/443: long-header version, packet type
//! and destination connection id — plus, for version-1 Initial packets,
//! full payload decryption; and, when per-capture
//! [`crypto::QuicDecryptor`] state is bound to a user-supplied NSS keylog,
//! Handshake (long-header) and 1-RTT (short-header) decryption for the
//! connections whose ClientHello random the keylog covers. The Initial
//! keys derive from the public Destination Connection ID (RFC 9001 §5.2);
//! Handshake and 1-RTT keys derive from the keylog's TLS 1.3 traffic
//! secrets (RFC 9001 §5.1, in `crypto::quic_protection_keys`). Header
//! protection is removed (§5.4), the AEAD tag is verified (AES-128-GCM,
//! §5.3) and the frames are decoded — PADDING, PING, ACK, CRYPTO and the
//! closes everywhere, plus STREAM (bounded reassembly), NEW_CONNECTION_ID
//! and the PATH frames for 1-RTT. CRYPTO bytes surface the TLS handshake
//! they carry through the existing hello walk, the same shape the TCP path
//! feeds it.
//!
//! Honesty contracts, enforced everywhere below:
//! - A packet is decrypted only when its AEAD tag verifies under keys the
//!   keylog explicitly provides — Initial keys derived from the DCID, or
//!   Handshake/application keys bound through the connection's own
//!   ClientHello random. Partial plaintext is never claimed.
//! - 0-RTT payloads and key-phase-1 (key update) 1-RTT payloads stay
//!   header-only: no secret for either exists in a keylog binding here.
//! - A standalone server Initial still fails verification (its keys derive
//!   from the CLIENT's first DCID, absent from its own header). When bound
//!   state already saw the client flight, the stored DCID derives the keys
//!   and the tag decides.
//! - Without bound state, short headers stay header-only: the DCID length
//!   the header omits is unrecoverable, and packet numbers cannot be
//!   reconstructed (RFC 9000 §A) or keyed.
//! - Any AEAD failure degrades to the header-only view plus a note naming
//!   the phase attempted; packet-number state moves only on verified tags.

use super::link::color_for;
use crate::crypto::{QuicDecryptor, QuicKeySlot, QuicSide};
use crate::{crypto, Dissected, Layer};

const LONG_HEADER_BIT: u8 = 0x80;
/// Version 1 (RFC 9000) and the fixed version-negotiation marker (RFC 8999).
const VERSION_V1: u32 = 0x0000_0001;
const VERSION_NEGOTIATION: u32 = 0x0000_0000;
/// QUIC caps connection IDs at 20 bytes (RFC 9000 §7.2).
const MAX_CONNECTION_ID: usize = 20;

/// Decode-effort caps for decrypted Initial payloads. A captured Initial
/// beyond any of these stays header-only with an honest note.
const MAX_DECODE_PAYLOAD: usize = 65_536; // RFC 9001 §5.4 payload cap: 64 KiB
const MAX_FRAMES: usize = 256;
const MAX_LISTED_FRAMES: usize = 12;
const MAX_ACK_RANGES: usize = 64;
const MAX_CRYPTO_BYTES: usize = 16_384;
const AEAD_TAG: usize = 16; // AES-128-GCM tag (RFC 9001 §5.1)
const SAMPLE_LEN: usize = 16; // header-protection sample (RFC 9001 §5.4.2)
/// Reassembled STREAM data bound per 1-RTT packet (TLS-record sized).
const MAX_STREAM_PAYLOAD: usize = 16_384;
/// NEW_CONNECTION_ID frames registered per decoded 1-RTT packet.
const MAX_NEW_CIDS_PER_PACKET: usize = 8;

fn layer(label: &str, value: impl ToString) -> Layer {
    Layer {
        label: label.into(),
        value: value.to_string(),
    }
}

fn dissected(layers: Vec<Layer>, info: String) -> Dissected {
    Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: "QUIC".into(),
        info: info.clone(),
        color_hint: color_for("UDP"),
        layers,
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
    }
}

fn v1_packet_type(first_byte: u8) -> &'static str {
    // Bits 4-5 of the long-header first byte (mask 0x30).
    match (first_byte & 0x30) >> 4 {
        0 => "Initial",
        1 => "0-RTT",
        2 => "Handshake",
        _ => "Retry",
    }
}

/// QUIC variable-length integer (RFC 9000 §16): the two high bits of the
/// first byte encode the width. Returns (value, encoded width) with every
/// bound checked against the captured bytes.
fn varint(payload: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *payload.get(at)?;
    let width = match first >> 6 {
        0 => 1usize,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let end = at.checked_add(width)?;
    if end > payload.len() {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &payload[at + 1..end] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, width))
}

/// Read one varint and advance the cursor; None leaves the cursor moved
/// only if a full varint was present (it never advances on failure).
fn varint_at(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let (value, width) = varint(data, *cursor)?;
    *cursor += width;
    Some(value)
}

fn hex_bounded(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for byte in bytes.iter().take(MAX_CONNECTION_ID) {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// One packet whose AEAD tag verified: which direction's keys matched, the
/// decoded packet number, whether per-connection state reconstructed it,
/// and the plaintext frames.
struct DecodedPacket {
    client_keys: bool,
    packet_number: u64,
    pn_len: usize,
    pn_reconstructed: bool,
    plaintext: Vec<u8>,
}

/// The header-protection-removed first byte and packet-number bytes of a
/// long header (RFC 9001 §5.4.1: the low 4 bits of the first byte).
struct UnprotectedLong {
    first: u8,
    pn_len: usize,
    pn_bytes: [u8; 4],
}

/// RFC 9001 §5.4.1/§5.4.2 long-header protection removal with `hp`: the
/// 16-byte sample starts 4 bytes after the packet-number field begins (a
/// fixed offset, read from the bytes as received — coalesced bytes count;
/// RFC 9000 §17.1 guarantees the space exists). Returns None unless the
/// unmasked header is a valid long header (form, fixed and reserved bits),
/// so a wrong key unmask is visible immediately.
fn unprotect_long_header(
    payload: &[u8],
    pn_offset: usize,
    hp: &[u8; 16],
) -> Option<UnprotectedLong> {
    let sample = payload.get(pn_offset + 4..pn_offset + 4 + SAMPLE_LEN)?;
    let mask = crypto::header_protection_mask(hp, sample)?;
    let first = payload[0] ^ (mask[0] & 0x0f);
    if first & LONG_HEADER_BIT == 0 || first & 0x40 == 0 || first & 0x0c != 0 {
        return None;
    }
    let pn_len = usize::from(first & 0x03) + 1;
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = payload[pn_offset + i] ^ mask[1 + i];
    }
    Some(UnprotectedLong {
        first,
        pn_len,
        pn_bytes,
    })
}

/// The header-protection-removed first byte and packet-number bytes of a
/// short header. Short headers protect the low 5 bits (RFC 9001 §5.4.1):
/// packet-number length, key phase and the reserved bits — the spin, fixed
/// and form bits above them are already readable in the protected byte.
struct UnprotectedShort {
    first: u8,
    pn_len: usize,
    pn_bytes: [u8; 4],
}

fn unprotect_short_header(
    payload: &[u8],
    pn_offset: usize,
    hp: &[u8; 16],
) -> Option<UnprotectedShort> {
    let sample = payload.get(pn_offset + 4..pn_offset + 4 + SAMPLE_LEN)?;
    let mask = crypto::header_protection_mask(hp, sample)?;
    let first = payload[0] ^ (mask[0] & 0x1f);
    // Form and fixed bits sit above the protected mask, so the raw byte
    // already carries them; the reserved bits must unmask to zero.
    if payload[0] & 0xc0 != 0x40 || first & 0x18 != 0 {
        return None;
    }
    let pn_len = usize::from(first & 0x03) + 1;
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = payload[pn_offset + i] ^ mask[1 + i];
    }
    Some(UnprotectedShort {
        first,
        pn_len,
        pn_bytes,
    })
}

/// Stateless packet-number decode: the on-wire value as-is. The RFC 9000
/// §A.3 sliding window needs per-connection largest-pn state a stateless
/// caller does not have; taking the wire value is exact for first-flight
/// traffic — the only packets a stateless dissector can verify — and never
/// fabricated.
fn wire_packet_number(pn_bytes: &[u8; 4], pn_len: usize) -> u64 {
    pn_bytes
        .iter()
        .take(pn_len)
        .fold(0u64, |pn, byte| (pn << 8) | u64::from(*byte))
}

/// RFC 9001 §5.2/§5.3/§5.4 decode of one version-1 Initial packet, tried
/// with both directions' secrets (the packet carries no direction marker).
/// Client Initials verify on the first attempt: their keys derive from
/// exactly the DCID in this header. Returns None when neither direction's
/// AEAD verifies — the caller must then claim nothing about the payload.
fn decode_initial(
    payload: &[u8],
    pn_offset: usize,
    declared: usize,
    dcid: &[u8],
) -> Option<DecodedPacket> {
    let secret = crypto::initial_secret(dcid);
    for client_keys in [true, false] {
        let direction = if client_keys {
            crypto::client_initial_secret(&secret)
        } else {
            crypto::server_initial_secret(&secret)
        };
        let keys = crypto::protection_keys(&direction);
        let Some(unprotected) = unprotect_long_header(payload, pn_offset, &keys.hp) else {
            continue; // these keys did not produce a valid long header
        };
        let pn_len = unprotected.pn_len;
        if declared < pn_len + AEAD_TAG {
            continue; // cannot hold packet number + tag in this encoding
        }
        let packet_number = wire_packet_number(&unprotected.pn_bytes, pn_len);
        // nonce = static IV XOR packet number (RFC 9001 §5.3).
        let nonce = crypto::aead_nonce(&keys.iv, packet_number);
        // AAD: the full header with header protection removed — everything
        // before the packet number plus the unmasked packet-number bytes.
        let mut aad = payload[..pn_offset].to_vec();
        aad[0] = unprotected.first;
        aad.extend_from_slice(&unprotected.pn_bytes[..pn_len]);
        let ciphertext = payload.get(pn_offset + pn_len..pn_offset + declared)?;
        if let Some(plaintext) = crypto::gcm::open(&keys.key, &nonce, &aad, ciphertext) {
            return Some(DecodedPacket {
                client_keys,
                packet_number,
                pn_len,
                pn_reconstructed: false,
                plaintext,
            });
        }
    }
    None
}

/// The two long-header payload phases this dissector decrypts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Handshake,
    Application,
}

fn key_slot(side: QuicSide, phase: Phase) -> QuicKeySlot {
    match (side, phase) {
        (QuicSide::Client, Phase::Handshake) => QuicKeySlot::ClientHandshake,
        (QuicSide::Server, Phase::Handshake) => QuicKeySlot::ServerHandshake,
        (QuicSide::Client, Phase::Application) => QuicKeySlot::ClientApplication,
        (QuicSide::Server, Phase::Application) => QuicKeySlot::ServerApplication,
    }
}

fn side_name(side: QuicSide) -> &'static str {
    match side {
        QuicSide::Client => "client",
        QuicSide::Server => "server",
    }
}

/// RFC 9001 decode of one Handshake packet with the keylog-bound connection
/// keys. The routed side is tried first and the opposite side second — the
/// AEAD tag, not the routing, decides. Packet numbers reconstruct through
/// the per-connection state (RFC 9000 §A.3) and the winning number is
/// committed only after its tag verified.
fn decode_handshake_tracked(
    payload: &[u8],
    pn_offset: usize,
    declared: usize,
    dcid: &[u8],
    decryptor: &mut QuicDecryptor,
) -> Result<(DecodedPacket, usize, QuicSide), &'static str> {
    let Some((slot, routed_side)) = decryptor.route_lookup(dcid) else {
        return Err(
            "protected payload — no keylog binding for this connection (Handshake attempted)",
        );
    };
    decryptor.touch(slot);
    let mut keys_missing = true;
    for side in [routed_side, routed_side.opposite()] {
        let slot_key = key_slot(side, Phase::Handshake);
        let Some(conn) = decryptor.conn_mut(slot) else {
            continue;
        };
        let Some(pk) = (match side {
            QuicSide::Client => conn.keys.keys.client_handshake.as_ref(),
            QuicSide::Server => conn.keys.keys.server_handshake.as_ref(),
        })
        .cloned() else {
            continue;
        };
        keys_missing = false;
        let Some(unprotected) = unprotect_long_header(payload, pn_offset, &pk.hp) else {
            continue;
        };
        let pn_len = unprotected.pn_len;
        if declared < pn_len + AEAD_TAG {
            continue;
        }
        let pn_reconstructed = conn.keys.slot_has_state(slot_key);
        let truncated = wire_packet_number(&unprotected.pn_bytes, pn_len);
        let (candidates, candidate_count) = conn.keys.pn_candidates(slot_key, truncated, pn_len);
        let mut aad = payload[..pn_offset].to_vec();
        aad[0] = unprotected.first;
        aad.extend_from_slice(&unprotected.pn_bytes[..pn_len]);
        let ciphertext = payload
            .get(pn_offset + pn_len..pn_offset + declared)
            .ok_or("protected payload — Handshake frame length exceeds capture")?;
        for &packet_number in candidates[..candidate_count].iter() {
            let nonce = crypto::aead_nonce(&pk.iv, packet_number);
            if let Some(plaintext) = crypto::gcm::open(&pk.key, &nonce, &aad, ciphertext) {
                decryptor
                    .conn_mut(slot)
                    .expect("slot borrowed above")
                    .keys
                    .commit_pn(slot_key, packet_number);
                return Ok((
                    DecodedPacket {
                        client_keys: side == QuicSide::Client,
                        packet_number,
                        pn_len,
                        pn_reconstructed,
                        plaintext,
                    },
                    slot,
                    side,
                ));
            }
        }
    }
    Err(if keys_missing {
        "protected payload — no Handshake secrets for this connection in the keylog (Handshake attempted)"
    } else {
        "protected payload — Handshake keys did not verify (Handshake attempted)"
    })
}

/// RFC 9000 §17.3 short-header decode with bound state: the route supplies
/// the DCID length the header omits; key phase 0 decrypts with the routed
/// side's application keys; key phase 1 (key update) is refused honestly —
/// update secrets are never in a keylog binding. Returns Err with the
/// untouched layers plus the honest note when one is due (a packet too
/// truncated to attempt stays silent, mirroring the Initial path).
fn decode_1rtt_tracked(
    payload: &[u8],
    decryptor: &mut QuicDecryptor,
    layers: Vec<Layer>,
) -> Result<Dissected, (Vec<Layer>, Option<&'static str>)> {
    let candidates = decryptor.short_header_routes(&payload[1..]);
    if candidates.is_empty() {
        return Err((
            layers,
            Some("protected payload — no keylog binding for this DCID (1-RTT attempted)"),
        ));
    }
    let mut key_phase_one = false;
    let mut sample_possible = false;
    let mut keys_available = false;
    let mut keys_tried = false;
    for (cid, slot, routed_side) in candidates {
        let pn_offset = 1 + cid.len();
        // Attempt space: the full 16-byte protection sample after the
        // packet-number field's start, and a payload within the decode cap.
        if payload.len() < pn_offset + 4 + SAMPLE_LEN {
            continue;
        }
        let remaining = payload.len() - pn_offset;
        if remaining > MAX_DECODE_PAYLOAD {
            continue;
        }
        sample_possible = true;
        for side in [routed_side, routed_side.opposite()] {
            let slot_key = key_slot(side, Phase::Application);
            let Some(conn) = decryptor.conn_mut(slot) else {
                continue;
            };
            let Some(pk) = (match side {
                QuicSide::Client => conn.keys.keys.client_application.as_ref(),
                QuicSide::Server => conn.keys.keys.server_application.as_ref(),
            })
            .cloned() else {
                continue;
            };
            keys_available = true;
            let Some(unprotected) = unprotect_short_header(payload, pn_offset, &pk.hp) else {
                continue;
            };
            keys_tried = true;
            // Key phase 1 selects key-update keys (RFC 9000 §17.3); the
            // keylog carries none, so nothing is attempted and the fact is
            // reported once no phase-0 candidate verified.
            if unprotected.first & 0x04 != 0 {
                key_phase_one = true;
                continue;
            }
            let pn_len = unprotected.pn_len;
            if remaining < pn_len + AEAD_TAG {
                continue;
            }
            let pn_reconstructed = conn.keys.slot_has_state(slot_key);
            let truncated = wire_packet_number(&unprotected.pn_bytes, pn_len);
            let (candidates_pn, candidate_count) =
                conn.keys.pn_candidates(slot_key, truncated, pn_len);
            let mut aad = payload[..pn_offset].to_vec();
            aad[0] = unprotected.first;
            aad.extend_from_slice(&unprotected.pn_bytes[..pn_len]);
            let ciphertext = &payload[pn_offset + pn_len..];
            for &packet_number in candidates_pn[..candidate_count].iter() {
                let nonce = crypto::aead_nonce(&pk.iv, packet_number);
                if let Some(plaintext) = crypto::gcm::open(&pk.key, &nonce, &aad, ciphertext) {
                    decryptor
                        .conn_mut(slot)
                        .expect("slot borrowed above")
                        .keys
                        .commit_pn(slot_key, packet_number);
                    let parsed = parse_frames(&plaintext, FrameClass::OneRtt);
                    // The packet's NEW_CONNECTION_ID frames enrich the
                    // connection's route set for later packets.
                    decryptor.bind_new_cids(slot, side, &parsed.new_cids);
                    let decoded = DecodedPacket {
                        client_keys: side == QuicSide::Client,
                        packet_number,
                        pn_len,
                        pn_reconstructed,
                        plaintext,
                    };
                    return Ok(emit_1rtt(
                        layers,
                        side,
                        cid.bytes(),
                        &decoded,
                        ciphertext.len(),
                        &parsed,
                    ));
                }
            }
        }
    }
    let note = if !sample_possible {
        None
    } else if !keys_available {
        Some("protected payload — no application secrets for this connection in the keylog (1-RTT attempted)")
    } else if key_phase_one {
        Some("protected payload — key phase 1 (key update) secrets are not in the keylog (1-RTT attempted)")
    } else if keys_tried {
        Some("protected payload — 1-RTT application keys did not verify (1-RTT attempted)")
    } else {
        None
    };
    Err((layers, note))
}

/// The 32-byte ClientHello random of a well-formed reassembled ClientHello
/// (message type 1, bounded declared length, random at message offset 6).
/// TLS 1.3 keylogs bind to exactly this random; anything else binds nothing.
fn client_hello_random(crypto_data: &[u8]) -> Option<[u8; 32]> {
    if crypto_data.len() < 6 || crypto_data[0] != 0x01 {
        return None;
    }
    let handshake_len = ((crypto_data[1] as usize) << 16)
        | ((crypto_data[2] as usize) << 8)
        | crypto_data[3] as usize;
    if !(34..=MAX_CRYPTO_BYTES).contains(&handshake_len) || crypto_data.len() < 4 + handshake_len {
        return None;
    }
    Some(crypto_data[6..38].try_into().expect("length checked above"))
}

/// Binding after a verified Initial. A client Initial carries the
/// ClientHello random the keylog is keyed by (no keylog entry, no
/// binding); a server Initial's sender SCID becomes the destination the
/// client's later packets target.
fn bind_after_initial(
    decryptor: &mut QuicDecryptor,
    dcid: &[u8],
    scid: &[u8],
    decoded: &DecodedPacket,
    crypto_data: &[u8],
) {
    if decoded.client_keys {
        if let Some(random) = client_hello_random(crypto_data) {
            decryptor.bind_client_initial(dcid, scid, random);
        }
    } else if let Some((slot, _side)) = decryptor.route_lookup(dcid) {
        decryptor.bind_scid(slot, scid, QuicSide::Server);
    }
}

/// Which frame set one decrypted packet's payload may carry (RFC 9000
/// §17.2): long-header packets (Initial, Handshake) carry the handshake
/// frames only, 1-RTT adds STREAM, NEW_CONNECTION_ID and the PATH frames.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameClass {
    LongHeader,
    OneRtt,
}

/// The bounded frame walk's output: frame descriptions, the CRYPTO bytes
/// reassembled from a contiguous run starting at offset 0 (the handshake
/// flight shape; empty when the frames are gapped or past the cap), the
/// STREAM data reassembled for 1-RTT (bounded), the honest stop note and
/// the NEW_CONNECTION_ID CIDs the decryptor can route on.
struct ParsedFrames {
    frames: Vec<String>,
    crypto: Vec<u8>,
    stream: Vec<u8>,
    stream_truncated: bool,
    stop: Option<String>,
    new_cids: Vec<Vec<u8>>,
}

/// Bounded frame walk (RFC 9000 §12.4, §19) over a decrypted payload.
/// Long-header packets may only carry PADDING, PING, ACK, CRYPTO and
/// CONNECTION_CLOSE; anything else stops the walk with an honest note.
fn parse_frames(plaintext: &[u8], class: FrameClass) -> ParsedFrames {
    let mut frames: Vec<String> = Vec::new();
    let mut crypto_data = Vec::new();
    let mut crypto_contiguous = true;
    let mut stream_data = Vec::new();
    let mut stream_truncated = false;
    let mut new_cids = Vec::new();
    let mut stop = None;
    let mut at = 0usize;
    'walk: while at < plaintext.len() {
        if frames.len() >= MAX_FRAMES {
            stop = Some(format!(
                "frame cap {MAX_FRAMES} reached; remainder not decoded"
            ));
            break;
        }
        match plaintext[at] {
            0x00 => {
                // Each PADDING byte is its own frame (RFC 9000 §19.1), but a
                // run is described once to keep the listing bounded.
                let start = at;
                while at < plaintext.len() && plaintext[at] == 0x00 {
                    at += 1;
                }
                frames.push(format!("PADDING x{}", at - start));
            }
            0x01 => {
                at += 1;
                frames.push("PING".into());
            }
            0x02 | 0x03 => {
                // ACK (RFC 9000 §19.3): largest acknowledged, delay, range
                // count, first range, then gap/range pairs; the ECN form
                // (0x03) appends three counters. Ranges are skipped, not
                // materialized, and capped — the loop is additionally bounded
                // by the data itself (each pair consumes at least 2 bytes).
                let mut cursor = at + 1;
                let Some(largest) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("ACK fields truncated".into());
                    break 'walk;
                };
                let Some(_delay) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("ACK fields truncated".into());
                    break 'walk;
                };
                let Some(range_count) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("ACK fields truncated".into());
                    break 'walk;
                };
                let Some(_first_range) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("ACK fields truncated".into());
                    break 'walk;
                };
                let mut ranges = 1u64; // the first range is already read
                let mut complete = true;
                while ranges < range_count {
                    if ranges >= MAX_ACK_RANGES as u64 {
                        stop = Some(format!(
                            "ACK range cap {MAX_ACK_RANGES} reached; remainder not decoded"
                        ));
                        complete = false;
                        break;
                    }
                    if varint_at(plaintext, &mut cursor).is_none()
                        || varint_at(plaintext, &mut cursor).is_none()
                    {
                        stop = Some("ACK range data truncated".into());
                        complete = false;
                        break;
                    }
                    ranges += 1;
                }
                if complete && plaintext[at] == 0x03 {
                    // ECN counts: ECT(0), ECT(1), CE-Count.
                    for _ in 0..3 {
                        if varint_at(plaintext, &mut cursor).is_none() {
                            stop = Some("ACK ECN counts truncated".into());
                            complete = false;
                            break;
                        }
                    }
                }
                if !complete {
                    break 'walk;
                }
                at = cursor;
                frames.push(format!("ACK largest={largest}, {range_count} range(s)"));
            }
            0x06 => {
                // CRYPTO (RFC 9000 §19.6): offset, length, data. Only a
                // contiguous run from offset 0 is reassembled — the shape of
                // a handshake flight — anything else is described but not
                // joined.
                let mut cursor = at + 1;
                let Some(offset) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("CRYPTO fields truncated".into());
                    break 'walk;
                };
                let Some(length) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("CRYPTO fields truncated".into());
                    break 'walk;
                };
                let data_start = cursor;
                let data_end = cursor as u64 + length;
                if data_end > plaintext.len() as u64 {
                    stop = Some(format!(
                        "CRYPTO data truncated ({length} byte(s) declared, {} captured)",
                        plaintext.len().saturating_sub(data_start)
                    ));
                    break 'walk;
                }
                if crypto_contiguous
                    && offset == crypto_data.len() as u64
                    && length <= (MAX_CRYPTO_BYTES - crypto_data.len()) as u64
                {
                    crypto_data.extend_from_slice(&plaintext[data_start..data_end as usize]);
                } else {
                    crypto_contiguous = false;
                }
                at = data_end as usize;
                frames.push(format!("CRYPTO offset={offset}, {length} byte(s)"));
            }
            0x08..=0x0f if class == FrameClass::OneRtt => {
                // STREAM (RFC 9000 §19.8): stream id, optional offset and
                // length, data. The AEAD tag verified this packet, so the
                // data may be claimed; reassembly is bounded.
                let flags = plaintext[at];
                let mut cursor = at + 1;
                let Some(stream_id) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("STREAM fields truncated".into());
                    break 'walk;
                };
                let mut offset = 0u64;
                if flags & 0x04 != 0 {
                    let Some(value) = varint_at(plaintext, &mut cursor) else {
                        stop = Some("STREAM fields truncated".into());
                        break 'walk;
                    };
                    offset = value;
                }
                let (data_start, data_len) = if flags & 0x02 != 0 {
                    let Some(length) = varint_at(plaintext, &mut cursor) else {
                        stop = Some("STREAM fields truncated".into());
                        break 'walk;
                    };
                    if cursor as u64 + length > plaintext.len() as u64 {
                        stop = Some(format!(
                            "STREAM data truncated ({length} byte(s) declared, {} captured)",
                            plaintext.len().saturating_sub(cursor)
                        ));
                        break 'walk;
                    }
                    (cursor, length as usize)
                } else {
                    // A length-less STREAM frame runs to the end of the
                    // packet (RFC 9000 §19.8: only valid as the last frame).
                    (cursor, plaintext.len() - cursor)
                };
                if stream_data.len() + data_len <= MAX_STREAM_PAYLOAD {
                    stream_data.extend_from_slice(&plaintext[data_start..data_start + data_len]);
                } else {
                    let take = MAX_STREAM_PAYLOAD - stream_data.len();
                    stream_data.extend_from_slice(&plaintext[data_start..data_start + take]);
                    stream_truncated = true;
                }
                at = data_start + data_len;
                let fin = if flags & 0x01 != 0 { ", FIN" } else { "" };
                let offset_part = if flags & 0x04 != 0 {
                    format!("offset={offset}, ")
                } else {
                    String::new()
                };
                frames.push(format!(
                    "STREAM id={stream_id}, {offset_part}{} byte(s){fin}",
                    data_len
                ));
            }
            0x18 if class == FrameClass::OneRtt => {
                // NEW_CONNECTION_ID (RFC 9000 §19.15): sequence, retire
                // prior-to, CID length, CID, stateless reset token. The CID
                // joins the connection's route set (bounded); the token is
                // never decoded.
                let mut cursor = at + 1;
                let Some(sequence) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("NEW_CONNECTION_ID fields truncated".into());
                    break 'walk;
                };
                let Some(_retire) = varint_at(plaintext, &mut cursor) else {
                    stop = Some("NEW_CONNECTION_ID fields truncated".into());
                    break 'walk;
                };
                let Some(cid_len) = plaintext.get(cursor).copied() else {
                    stop = Some("NEW_CONNECTION_ID truncated".into());
                    break 'walk;
                };
                cursor += 1;
                if usize::from(cid_len) > MAX_CONNECTION_ID {
                    stop = Some(format!(
                        "NEW_CONNECTION_ID CID length {cid_len} exceeds the {MAX_CONNECTION_ID}-byte limit"
                    ));
                    break 'walk;
                }
                let cid_end = cursor + usize::from(cid_len) + 16; // + reset token
                if cid_end > plaintext.len() {
                    stop = Some("NEW_CONNECTION_ID truncated".into());
                    break 'walk;
                }
                if new_cids.len() < MAX_NEW_CIDS_PER_PACKET {
                    new_cids.push(plaintext[cursor..cursor + usize::from(cid_len)].to_vec());
                }
                at = cid_end;
                frames.push(format!(
                    "NEW_CONNECTION_ID seq={sequence}, CID {cid_len} byte(s)"
                ));
            }
            0x1a | 0x1b if class == FrameClass::OneRtt => {
                // PATH_CHALLENGE / PATH_RESPONSE (RFC 9000 §19.17/§19.18):
                // exactly 8 opaque bytes; contents are never claimed.
                let name = if plaintext[at] == 0x1a {
                    "PATH_CHALLENGE"
                } else {
                    "PATH_RESPONSE"
                };
                if plaintext.len() < at + 9 {
                    stop = Some(format!("{name} truncated"));
                    break 'walk;
                }
                at += 9;
                frames.push(format!("{name} 8 byte(s) (not decoded)"));
            }
            0x1c | 0x1d => {
                // CONNECTION_CLOSE (RFC 9000 §19.4): error code, the
                // triggering frame type (QUIC-close form only), reason
                // length, reason. Reason contents stay unclaimed — the
                // length is the bounded, honest summary. Terminal frame.
                let name = if plaintext[at] == 0x1c {
                    "CONNECTION_CLOSE"
                } else {
                    "APPLICATION_CLOSE"
                };
                let mut cursor = at + 1;
                let Some(code) = varint_at(plaintext, &mut cursor) else {
                    stop = Some(format!("{name} fields truncated"));
                    break 'walk;
                };
                let mut trigger = 0u64;
                if name == "CONNECTION_CLOSE" {
                    let Some(value) = varint_at(plaintext, &mut cursor) else {
                        stop = Some(format!("{name} fields truncated"));
                        break 'walk;
                    };
                    trigger = value;
                }
                let Some(reason_len) = varint_at(plaintext, &mut cursor) else {
                    stop = Some(format!("{name} reason truncated"));
                    break 'walk;
                };
                if cursor as u64 + reason_len > plaintext.len() as u64 {
                    stop = Some(format!("{name} reason truncated"));
                    break 'walk;
                }
                let reason = if reason_len > 0 {
                    format!(", reason {reason_len} byte(s)")
                } else {
                    String::new()
                };
                if name == "CONNECTION_CLOSE" {
                    frames.push(format!(
                        "{name} code=0x{code:x}, frame 0x{trigger:x}{reason}"
                    ));
                } else {
                    frames.push(format!("{name} code=0x{code:x}{reason}"));
                }
                break; // close is terminal; trailing bytes are not decoded
            }
            other => {
                stop = Some(format!(
                    "frame type 0x{other:02x} not decodable here; remainder not decoded"
                ));
                break 'walk;
            }
        }
    }
    let reassembled = if crypto_contiguous {
        crypto_data
    } else {
        Vec::new()
    };
    if stream_truncated && stop.is_none() {
        stop = Some(format!(
            "stream data cap {MAX_STREAM_PAYLOAD} reached; remainder not reassembled"
        ));
    }
    ParsedFrames {
        frames,
        crypto: reassembled,
        stream: stream_data,
        stream_truncated,
        stop,
        new_cids,
    }
}

/// Bounded frame-listing layers shared by every decrypted emission.
fn push_frame_layers(layers: &mut Vec<Layer>, frames: &[String], stop: &Option<String>) {
    for describe in frames.iter().take(MAX_LISTED_FRAMES) {
        layers.push(layer("QUIC frame", describe.clone()));
    }
    if frames.len() > MAX_LISTED_FRAMES {
        layers.push(layer(
            "QUIC frame",
            format!(
                "+{} more (cap {MAX_LISTED_FRAMES})",
                frames.len() - MAX_LISTED_FRAMES
            ),
        ));
    }
    if let Some(note) = stop {
        layers.push(layer("frame decode", note.clone()));
    }
}

/// Layer emission for a verified long-header packet (Initial or Handshake):
/// packet number, frame listing, TLS hello (when the CRYPTO bytes carry
/// one) and the handshake bytes as the payload for further analysis.
/// Returns the reassembled CRYPTO bytes for the keylog binding step.
fn emit_decrypted_long_header(
    mut layers: Vec<Layer>,
    mut info: String,
    decoded: &DecodedPacket,
    phase: &str,
    declared: usize,
    coalesced: usize,
) -> (Dissected, Vec<u8>) {
    let side = if decoded.client_keys {
        "client"
    } else {
        "server"
    };
    layers.push(layer(
        "QUIC protected payload",
        format!("{declared} byte(s), decrypted with {side} {phase} keys"),
    ));
    layers.push(layer(
        "packet number",
        format!(
            "{} ({}-byte encoding, {})",
            decoded.packet_number,
            decoded.pn_len,
            if decoded.pn_reconstructed {
                "reconstructed from connection state"
            } else {
                "stateless decode"
            }
        ),
    ));
    let parsed = parse_frames(&decoded.plaintext, FrameClass::LongHeader);
    push_frame_layers(&mut layers, &parsed.frames, &parsed.stop);
    info.push_str(&format!(
        ", pn {}, {} frame(s)",
        decoded.packet_number,
        parsed.frames.len()
    ));
    // QUIC CRYPTO frames carry raw TLS handshake messages (no record
    // layer). Wrapping them in a synthetic TLS record header lets the
    // existing hello walk — the same one TCP streams feed — decode them.
    if !parsed.crypto.is_empty() {
        match parsed.crypto.first() {
            Some(&0x01) | Some(&0x02) => {
                let mut record = Vec::with_capacity(parsed.crypto.len() + 5);
                record.extend_from_slice(&[0x16, 0x03, 0x03]);
                record.extend_from_slice(&(parsed.crypto.len() as u16).to_be_bytes());
                record.extend_from_slice(&parsed.crypto);
                match super::protocol::tls_hello(&record) {
                    Some(hello) => {
                        info.push_str(if hello.client {
                            ", ClientHello"
                        } else {
                            ", ServerHello"
                        });
                        if let Some(sni) = &hello.sni {
                            info.push_str(&format!(" SNI={sni}"));
                        }
                        layers.push(layer("TLS", super::protocol::tls_description(&hello)));
                    }
                    None => {
                        layers.push(layer("TLS", "handshake not decoded (truncated in CRYPTO)"))
                    }
                }
            }
            _ => layers.push(layer(
                "TLS",
                "CRYPTO does not start with a hello; handshake not decoded",
            )),
        }
    }
    if coalesced > 0 {
        layers.push(layer(
            "coalesced",
            format!("{coalesced} byte(s) after the frame; not decoded"),
        ));
    }
    let mut dissected = dissected(layers, info);
    // The decrypted handshake bytes become the transport payload, mirroring
    // what a TCP flow exposes to payload consumers.
    dissected.payload = parsed.crypto.clone();
    (dissected, parsed.crypto)
}

/// Layer emission for a verified 1-RTT packet: the bound route's DCID, the
/// application keys that verified, the reconstructed packet number and the
/// frame listing; verified STREAM data becomes the transport payload.
fn emit_1rtt(
    mut layers: Vec<Layer>,
    side: QuicSide,
    cid: &[u8],
    decoded: &DecodedPacket,
    payload_len: usize,
    parsed: &ParsedFrames,
) -> Dissected {
    layers.push(layer(
        "QUIC",
        format!(
            "short header (1-RTT), key phase 0, decrypted with {} application keys",
            side_name(side)
        ),
    ));
    layers.push(layer("destination connection id", hex_bounded(cid)));
    layers.push(layer(
        "QUIC protected payload",
        format!(
            "{payload_len} byte(s), decrypted with {} application keys (1-RTT)",
            side_name(side)
        ),
    ));
    layers.push(layer(
        "packet number",
        format!(
            "{} ({}-byte encoding, {})",
            decoded.packet_number,
            decoded.pn_len,
            if decoded.pn_reconstructed {
                "reconstructed from connection state"
            } else {
                "stateless decode"
            }
        ),
    ));
    push_frame_layers(&mut layers, &parsed.frames, &parsed.stop);
    if !parsed.stream.is_empty() {
        layers.push(layer(
            "stream data",
            format!(
                "{} byte(s) reassembled{}",
                parsed.stream.len(),
                if parsed.stream_truncated {
                    format!(" (cap {MAX_STREAM_PAYLOAD})")
                } else {
                    String::new()
                }
            ),
        ));
    }
    let mut info = format!("QUIC short header (1-RTT), DCID {}", hex_bounded(cid));
    info.push_str(&format!(
        ", pn {}, {} frame(s)",
        decoded.packet_number,
        parsed.frames.len()
    ));
    let mut dissected = dissected(layers, info);
    // Verified STREAM data is the packet's application payload.
    dissected.payload = parsed.stream.clone();
    dissected
}

/// Dissect one QUIC datagram (the UDP payload on port 443). The protocol
/// claim follows the port plus the header-form bit — the same strength as
/// the TLS claim on TCP/443 — and every structural refusal degrades to an
/// honest QUIC row instead of a bare truncation note. When a capture-scoped
/// [`crypto::QuicDecryptor`] is installed (`crypto::quic_capture_install`)
/// decryption routes through its bound state; without one the stateless
/// view below applies verbatim.
pub fn dissect_quic(payload: &[u8], layers: Vec<Layer>) -> Dissected {
    crypto::with_quic_capture(|decryptor| dissect_quic_inner(payload, layers, decryptor))
}

impl QuicDecryptor {
    /// Dissect one QUIC datagram through this capture's bound state: the
    /// same honest layers as [`dissect_quic`], with Handshake and 1-RTT
    /// decryption attempted wherever this state binds the connection.
    pub fn dissect(&mut self, payload: &[u8], layers: Vec<Layer>) -> Dissected {
        dissect_quic_inner(payload, layers, Some(self))
    }
}

/// The dissection body, parameterized over the optional bound decryptor so
/// the stateless path stays exactly what it was.
fn dissect_quic_inner(
    payload: &[u8],
    mut layers: Vec<Layer>,
    mut decryptor: Option<&mut QuicDecryptor>,
) -> Dissected {
    let first = match payload.first() {
        Some(&first) => first,
        None => {
            layers.push(layer("QUIC", "datagram with no captured payload byte(s)"));
            return dissected(layers, "QUIC datagram, no captured payload byte(s)".into());
        }
    };
    if payload.len() < 6 {
        // Too small to carry version + connection-id length; nothing is
        // decodable, so say exactly that.
        layers.push(layer("QUIC", "header incomplete; not decoded"));
        return dissected(
            layers,
            format!("QUIC header incomplete, {} byte(s) captured", payload.len()),
        );
    }
    if first & LONG_HEADER_BIT == 0 {
        // Bound state supplies the DCID length the short header omits; a
        // verified AEAD tag then decides. Without a matching route the
        // header-only view below stays exactly as it was.
        let mut attempted: Option<&'static str> = None;
        if let Some(decryptor) = decryptor.as_deref_mut() {
            match decode_1rtt_tracked(payload, decryptor, layers) {
                Ok(dissected) => return dissected,
                Err((layers_back, note)) => {
                    layers = layers_back;
                    attempted = note;
                }
            }
        }
        layers.push(layer(
            "QUIC",
            "QUIC short header (1-RTT); DCID not recoverable without prior state",
        ));
        layers.push(layer("packet type", "short header (1-RTT)"));
        if let Some(note) = attempted {
            layers.push(layer("payload decryption", note));
        }
        return dissected(
            layers,
            "QUIC short header (1-RTT); DCID not recoverable without prior state".into(),
        );
    }
    // Long header: version (bytes 1..5) and DCID length (byte 5) exist now.
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    layers.push(layer(
        "QUIC",
        format!("long header, version 0x{version:08x}"),
    ));
    layers.push(layer(
        "version",
        match version {
            VERSION_NEGOTIATION => "0x00000000 (version negotiation)".to_string(),
            VERSION_V1 => "1 (RFC 9000)".to_string(),
            other => format!("0x{other:08x}"),
        },
    ));
    let dcid_len = payload[5] as usize;
    if dcid_len > MAX_CONNECTION_ID {
        // A connection-id length beyond the QUIC limit is invalid; refuse it
        // honestly and stop rather than slicing into following fields.
        layers.push(layer(
            "destination connection id",
            format!("{dcid_len} byte(s) exceeds the {MAX_CONNECTION_ID}-byte QUIC limit; refused"),
        ));
        if version == VERSION_V1 {
            layers.push(layer("packet type", v1_packet_type(first)));
        }
        return dissected(
            layers,
            format!("QUIC long header, DCID refused ({dcid_len} byte(s) declared)"),
        );
    }
    let Some(dcid) = payload.get(6..6 + dcid_len) else {
        layers.push(layer(
            "destination connection id",
            format!(
                "{dcid_len} byte(s) declared, {} captured; truncated",
                payload.len() - 6
            ),
        ));
        if version == VERSION_V1 {
            layers.push(layer("packet type", v1_packet_type(first)));
        }
        return dissected(
            layers,
            format!("QUIC long header, DCID truncated ({dcid_len} byte(s) declared)"),
        );
    };
    let dcid_hex = hex_bounded(dcid);
    layers.push(layer("destination connection id", dcid_hex.clone()));

    let mut info = match version {
        VERSION_NEGOTIATION => {
            layers.push(layer("packet type", "version negotiation"));
            format!("QUIC version negotiation, DCID {dcid_hex}")
        }
        VERSION_V1 => {
            let type_name = v1_packet_type(first);
            layers.push(layer("packet type", type_name));
            format!("QUIC {type_name}, DCID {dcid_hex}")
        }
        other => {
            layers.push(layer(
                "packet type",
                format!("unknown version 0x{other:08x}; type not decoded"),
            ));
            format!("QUIC long header, version 0x{other:08x} (not decoded)")
        }
    };
    if version != VERSION_V1 {
        return dissected(layers, info);
    }

    // v1 walk: source connection id (skipped, never decoded), then the
    // Initial token, then the frame length that covers the protected bytes.
    let type_name = v1_packet_type(first);
    let mut cursor = 6 + dcid_len;
    let Some(scid_len) = payload.get(cursor).copied() else {
        layers.push(layer(
            "source connection id",
            "length byte missing; header incomplete",
        ));
        return dissected(layers, format!("{info}, header incomplete"));
    };
    cursor += 1;
    if usize::from(scid_len) > MAX_CONNECTION_ID {
        layers.push(layer(
            "source connection id",
            format!(
                "{} byte(s) exceeds the {MAX_CONNECTION_ID}-byte QUIC limit; refused",
                scid_len
            ),
        ));
        return dissected(layers, format!("{info}, SCID refused"));
    }
    let Some(scid_end) = cursor.checked_add(usize::from(scid_len)) else {
        layers.push(layer(
            "source connection id",
            "length overflow; not decoded",
        ));
        return dissected(layers, format!("{info}, header incomplete"));
    };
    if scid_end > payload.len() {
        layers.push(layer(
            "source connection id",
            format!(
                "{} byte(s) declared, {} captured; truncated",
                scid_len,
                payload.len() - cursor
            ),
        ));
        return dissected(layers, format!("{info}, SCID truncated"));
    }
    // The SCID is skipped for decoding but kept: a verified packet's SCID
    // is the destination its opposite side targets (route registration).
    let scid = &payload[cursor..scid_end];
    cursor = scid_end;

    if type_name == "Initial" {
        match varint(payload, cursor) {
            None => {
                layers.push(layer("token", "length varint truncated; token not decoded"));
                return dissected(layers, format!("{info}, token length truncated"));
            }
            // The 4- and 8-byte varint forms are not decoded for the token.
            Some((_, width)) if width > 2 => {
                layers.push(layer("token", "long token (not decoded)"));
                return dissected(layers, format!("{info}, long token (not decoded)"));
            }
            Some((token_len, width)) => {
                let token_len = token_len as usize;
                let Some(token_end) = cursor.checked_add(width.saturating_add(token_len)) else {
                    layers.push(layer("token", "length overflow; token not decoded"));
                    return dissected(layers, format!("{info}, token length overflow"));
                };
                if token_end > payload.len() {
                    layers.push(layer(
                        "token",
                        format!(
                            "{token_len} byte(s) declared, {} captured; truncated",
                            payload.len().saturating_sub(cursor + width)
                        ),
                    ));
                    return dissected(layers, format!("{info}, token truncated"));
                }
                if token_len == 0 {
                    layers.push(layer("token", "no token"));
                } else {
                    layers.push(layer(
                        "token",
                        format!("token {token_len} byte(s) (not decoded)"),
                    ));
                    info.push_str(&format!(", token {token_len} byte(s)"));
                }
                cursor = token_end;
            }
        }
    }
    if type_name == "Retry" {
        // A Retry carries an opaque retry token plus a 16-byte integrity tag
        // instead of a length-prefixed protected payload: nothing to claim.
        return dissected(layers, info);
    }

    // Initial, 0-RTT and Handshake end with the frame length varint. For
    // version-1 Initial packets the RFC 9001 §5.2 keys derive from the
    // public DCID, so decryption is attempted below; 0-RTT stays header-only
    // (no keylog carries early secrets), and Handshake decrypts only with
    // bound state's keylog-derived connection keys.
    let Some((declared, width)) = varint(payload, cursor) else {
        layers.push(layer(
            "QUIC protected payload",
            "frame length varint truncated; not measured",
        ));
        return dissected(layers, format!("{info}, frame length truncated"));
    };
    cursor += width;
    let remaining = payload.len() - cursor;
    if declared > remaining as u64 {
        layers.push(layer(
            "QUIC protected payload",
            format!("{remaining} byte(s), keys unavailable (frame declares {declared})"),
        ));
        return dissected(
            layers,
            format!("{info}, {remaining} of {declared} protected byte(s) captured"),
        );
    }
    let declared = declared as usize;
    let coalesced = remaining - declared;

    if type_name == "Initial" {
        // Attempt decryption only when the packet can actually hold a
        // protected payload and the RFC 9001 §5.4.2 sample region exists:
        // pn (>=1) + tag (16) inside `declared`, and 20 bytes after the
        // packet-number field's start.
        let attemptable = declared >= 1 + AEAD_TAG
            && payload.len() >= cursor + 4 + SAMPLE_LEN
            && declared <= MAX_DECODE_PAYLOAD;
        if attemptable {
            if let Some(decoded) = decode_initial(payload, cursor, declared, dcid) {
                let (dissected, crypto_data) = emit_decrypted_long_header(
                    layers, info, &decoded, "Initial", declared, coalesced,
                );
                if let Some(decryptor) = decryptor.as_deref_mut() {
                    // The verified ClientHello random binds the keylog's
                    // traffic secrets to this connection for later packets.
                    bind_after_initial(decryptor, dcid, scid, &decoded, &crypto_data);
                }
                return dissected;
            }
            // With bound state a server Initial can finally verify: its
            // keys derive from the CLIENT's first DCID, which the bound
            // connection stored when the client Initial decrypted.
            if let Some(decryptor) = decryptor.as_deref_mut() {
                if let Some(initial_dcid) = decryptor.initial_dcid_for(dcid) {
                    if initial_dcid.as_slice() != dcid {
                        if let Some(decoded) =
                            decode_initial(payload, cursor, declared, &initial_dcid)
                        {
                            let (dissected, crypto_data) = emit_decrypted_long_header(
                                layers, info, &decoded, "Initial", declared, coalesced,
                            );
                            bind_after_initial(decryptor, dcid, scid, &decoded, &crypto_data);
                            return dissected;
                        }
                    }
                }
            }
            // Verification failed with both directions' keys: fall back to
            // the header-only view plus the honest note. No partial
            // plaintext is ever claimed.
            layers.push(layer(
                "payload decryption",
                "protected payload — Initial keys mismatch",
            ));
        }
    }
    if type_name == "Handshake" {
        // Bound-state Handshake decryption: the same HP/AEAD machinery as
        // the Initial path, keyed by the connection's keylog-derived
        // handshake secrets instead of the public DCID. No route, no
        // attempt — and every failure keeps the header-only layers verbatim
        // plus a note naming the phase attempted.
        if let Some(decryptor) = decryptor {
            let attemptable = declared >= 1 + AEAD_TAG
                && payload.len() >= cursor + 4 + SAMPLE_LEN
                && declared <= MAX_DECODE_PAYLOAD;
            if attemptable {
                match decode_handshake_tracked(payload, cursor, declared, dcid, decryptor) {
                    Ok((decoded, slot, side)) => {
                        let (dissected, _crypto) = emit_decrypted_long_header(
                            layers,
                            info,
                            &decoded,
                            "Handshake",
                            declared,
                            coalesced,
                        );
                        // The sender's SCID is the destination its opposite
                        // side targets — route it for later 1-RTT packets.
                        decryptor.bind_scid(slot, scid, side);
                        return dissected;
                    }
                    Err(note) => layers.push(layer("payload decryption", note)),
                }
            }
        }
    }
    if coalesced > 0 {
        // QUIC datagrams may coalesce packets; bytes past the declared frame
        // are left alone instead of being folded into this packet's claim.
        layers.push(layer(
            "QUIC protected payload",
            format!("{declared} byte(s), keys unavailable"),
        ));
        layers.push(layer(
            "coalesced",
            format!("{coalesced} byte(s) after the frame; not decoded"),
        ));
        return dissected(
            layers,
            format!("{info}, {declared} byte(s) protected, {coalesced} coalesced"),
        );
    }
    layers.push(layer(
        "QUIC protected payload",
        format!("{declared} byte(s), keys unavailable"),
    ));
    info.push_str(&format!(", {declared} protected byte(s)"));
    dissected(layers, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_header(version: u32, type_bits: u8, dcid: &[u8]) -> Vec<u8> {
        let mut out = vec![LONG_HEADER_BIT | (type_bits << 4) | 0x03];
        out.extend_from_slice(&version.to_be_bytes());
        out.push(dcid.len() as u8);
        out.extend_from_slice(dcid);
        out
    }

    /// Decode a hex string into bytes for the RFC 9001 Appendix A vectors.
    fn hex_bytes(hexstr: &str) -> Vec<u8> {
        (0..hexstr.len() / 2)
            .map(|i| u8::from_str_radix(&hexstr[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::new();
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// The RFC 9001 Appendix A.2 protected client Initial packet (1200
    /// bytes), transcribed from the RFC text. Its header is header-protected
    /// (first byte c0), so the packet type reads correctly even before the
    /// protection is removed — only the low 4 bits are masked.
    const RFC9001_A2_CLIENT_INITIAL: &str =
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11\
         d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399\
         1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c\
         8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212\
         30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5\
         457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208\
         4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec\
         4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3\
         485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db\
         059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c\
         7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8\
         9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556\
         be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74\
         68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a\
         c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00\
         f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632\
         291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964\
         25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd\
         14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff\
         ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198\
         e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd\
         c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73\
         203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f\
         cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e\
         fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade\
         a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047\
         90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2\
         162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4\
         40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0\
         6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e\
         8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0\
         be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400\
         54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab\
         760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9\
         f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4\
         056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064\
         7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241\
         e221af44860018ab0856972e194cd934";

    /// The CRYPTO frame payload from Appendix A.2 (the ClientHello flight):
    /// the expected reassembled handshake bytes for the packet above (the
    /// frame header 06 00 40f1 is not part of the reassembled data).
    const RFC9001_A2_CLIENT_CRYPTO: &str = "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cf\
         d3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e0000\
         0b6578616d706c652e636f6dff01000100000a00080006001d00170018001000\
         07000504616c706e000500050100000000003300260024001d00209370b2c9ca\
         a47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302\
         0304000d0010000e0403050306030203080408050806002d00020101001c0002\
         4001003900320408ffffffffffffffff05048000ffff07048000ffff08011001\
         04800075300901100f088394c8f03e51570806048000ffff";

    #[test]
    fn version_one_initial_parses_header_fields_and_refuses_to_claim_payload() {
        let mut datagram = long_header(VERSION_V1, 0, &[0xaa, 0xbb, 0xcc, 0xdd]);
        datagram.push(0); // SCID length
        datagram.push(0x00); // token length varint: 0 (no token)
        datagram.extend([0x40, 0x08]); // frame length varint: 8
        datagram.extend_from_slice(&[0u8; 8]); // protected payload
        let dissected = dissect_quic(&datagram, Vec::new());
        assert_eq!(dissected.protocol, "QUIC");
        assert!(dissected
            .layers
            .iter()
            .any(|l| l.label == "version" && l.value.contains("RFC 9000")));
        assert!(dissected
            .layers
            .iter()
            .any(|l| l.label == "packet type" && l.value == "Initial"));
        assert!(dissected
            .layers
            .iter()
            .any(|l| l.label == "destination connection id" && l.value == "aabbccdd"));
        assert!(dissected.layers.iter().any(
            |l| l.label == "QUIC protected payload" && l.value == "8 byte(s), keys unavailable"
        ));
        assert!(dissected
            .layers
            .iter()
            .any(|l| l.label == "token" && l.value == "no token"));
        assert!(dissected.info.contains("8 protected byte(s)"));
        // Never claims decrypted contents.
        assert!(dissected
            .layers
            .iter()
            .all(|l| !l.value.to_lowercase().contains("sni")));
    }

    #[test]
    fn handshake_and_short_headers_classify() {
        let mut handshake = long_header(VERSION_V1, 2, &[0x01]);
        handshake.push(0); // SCID length
        handshake.push(0x02); // frame length varint: 2
        handshake.extend([0xde, 0xad]);
        let d = dissect_quic(&handshake, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "packet type" && l.value == "Handshake"));
        assert!(d.layers.iter().any(
            |l| l.label == "QUIC protected payload" && l.value == "2 byte(s), keys unavailable"
        ));
        let short = vec![0x40, 0xaa, 0xbb, 0x01, 0x02, 0x03];
        let d = dissect_quic(&short, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC" && l.value.contains("short header")));
        assert!(d.info.contains("short header"));
        assert!(d.info.contains("DCID not recoverable"));
    }

    #[test]
    fn version_negotiation_is_named() {
        let vn = long_header(VERSION_NEGOTIATION, 0, &[0x01]);
        let d = dissect_quic(&vn, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "packet type" && l.value == "version negotiation"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "version" && l.value.contains("version negotiation")));
    }

    #[test]
    fn oversized_or_truncated_dcids_degrade_honestly_not_panic() {
        let oversized = long_header(VERSION_V1, 0, &[0xaa; 21]);
        let d = dissect_quic(&oversized, Vec::new());
        assert_eq!(d.protocol, "QUIC");
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "destination connection id" && l.value.contains("refused")));
        assert!(d.info.contains("DCID refused"));

        let truncated = long_header(VERSION_V1, 0, &[0xaa, 0xbb]);
        let mut cut = truncated.clone();
        cut.pop();
        let d = dissect_quic(&cut, Vec::new());
        assert_eq!(d.protocol, "QUIC");
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "destination connection id" && l.value.contains("truncated")));

        let tiny = vec![0xc0, 0x00];
        let d = dissect_quic(&tiny, Vec::new());
        assert_eq!(d.protocol, "QUIC");
        assert!(d.info.contains("incomplete"));
        assert!(dissect_quic(&[], Vec::new())
            .info
            .contains("no captured payload"));
    }

    #[test]
    fn dcid_is_bounded_in_output() {
        let mut datagram = long_header(VERSION_V1, 0, &[0xab; 20]);
        datagram.push(0); // SCID length
        datagram.push(0x00); // token length varint: 0
        datagram.push(0x04); // frame length varint: 4
        datagram.extend_from_slice(&[0u8; 4]); // protected payload
        let d = dissect_quic(&datagram, Vec::new());
        let dcid = d
            .layers
            .iter()
            .find(|l| l.label == "destination connection id")
            .unwrap();
        assert_eq!(dcid.value.len(), 40);
    }

    #[test]
    fn scid_is_skipped_before_token_and_length() {
        let mut datagram = long_header(VERSION_V1, 0, &[0x11]);
        datagram.push(3); // SCID length
        datagram.extend([0x22, 0x33, 0x44]); // SCID (never decoded)
        datagram.extend([0x40, 0x02]); // token length varint: 2 (2-byte form)
        datagram.extend([0x99, 0x98]); // token bytes (not decoded)
        datagram.push(0x03); // frame length varint: 3
        datagram.extend([0x01, 0x02, 0x03]);
        let d = dissect_quic(&datagram, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "token" && l.value == "token 2 byte(s) (not decoded)"));
        assert!(d.layers.iter().any(
            |l| l.label == "QUIC protected payload" && l.value == "3 byte(s), keys unavailable"
        ));
        assert!(d.info.contains("token 2 byte(s)"));
    }

    #[test]
    fn long_token_varints_are_named_not_decoded() {
        let mut datagram = long_header(VERSION_V1, 0, &[0x11]);
        datagram.push(0); // SCID length
        datagram.push(0x82); // token length varint: 4-byte form (long token)
        datagram.extend([0x00, 0x00, 0x10, 0x00]);
        datagram.extend_from_slice(&[0u8; 8]);
        let d = dissect_quic(&datagram, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "token" && l.value == "long token (not decoded)"));
        assert!(d.info.contains("long token"));
        // Without a decoded token length there is no frame-length claim.
        assert!(d.layers.iter().all(|l| l.label != "QUIC protected payload"));
    }

    #[test]
    fn declared_length_exceeding_capture_is_reported_honestly() {
        let mut datagram = long_header(VERSION_V1, 0, &[0x11]);
        datagram.push(0); // SCID length
        datagram.push(0x00); // token length varint: 0
        datagram.extend([0x40, 0x40]); // frame length varint: 64
        datagram.extend([0x01, 0x02, 0x03, 0x04]); // only 4 captured
        let d = dissect_quic(&datagram, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC protected payload" && l.value.contains("frame declares 64")));
        assert!(d.info.contains("4 of 64 protected byte(s) captured"));
    }

    #[test]
    fn rfc_9001_a2_client_initial_decrypts_end_to_end() {
        // The published Appendix A.2 packet: full derivation, header
        // protection removal, AEAD verification and frame walk in one pass.
        let datagram = hex_bytes(RFC9001_A2_CLIENT_INITIAL);
        let d = dissect_quic(&datagram, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value == "1182 byte(s), decrypted with client Initial keys"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "packet number" && l.value.starts_with("2 (4-byte encoding")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "CRYPTO offset=0, 241 byte(s)"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "PADDING x917"));
        assert!(d.layers.iter().any(|l| l.label == "TLS"
            && l.value.contains("ClientHello")
            && l.value.contains("SNI=example.com")));
        assert!(d.info.contains("pn 2, 2 frame(s)"));
        assert!(d.info.contains("SNI=example.com"));
        // No "keys unavailable" claim survives a verified decryption.
        assert!(d
            .layers
            .iter()
            .all(|l| !l.value.contains("keys unavailable")));
        // The TLS handshake bytes surface as the payload, TCP-flow style.
        assert_eq!(d.payload, hex_bytes(RFC9001_A2_CLIENT_CRYPTO));
    }

    #[test]
    fn corrupted_initial_payload_falls_back_without_claiming_plaintext() {
        let mut datagram = hex_bytes(RFC9001_A2_CLIENT_INITIAL);
        let last = datagram.len() - 1;
        datagram[last] ^= 0xff; // corrupt the AEAD tag
        let d = dissect_quic(&datagram, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC protected payload"
                && l.value == "1182 byte(s), keys unavailable"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.value == "protected payload — Initial keys mismatch"));
        // Nothing decrypted is claimed anywhere.
        assert!(d.layers.iter().all(|l| l.label != "TLS"));
        assert!(d.layers.iter().all(|l| l.label != "QUIC frame"));
        assert!(d.layers.iter().all(|l| l.label != "packet number"));
        assert!(d.payload.is_empty());
        assert!(d.info.contains("1182 protected byte(s)"));
    }

    #[test]
    fn initial_too_short_for_sampling_stays_header_only() {
        // 17 declared bytes (1 pn + 16 tag) with only 17 bytes captured: the
        // RFC 9001 §5.4.2 sample needs 20 bytes after the pn field, so no
        // decryption is attempted and no mismatch note is issued.
        let mut datagram = long_header(VERSION_V1, 0, &[0x11]);
        datagram.push(0); // SCID length
        datagram.push(0x00); // token length varint: 0
        datagram.push(0x11); // frame length varint: 17
        datagram.extend_from_slice(&[0x42u8; 17]);
        let d = dissect_quic(&datagram, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC protected payload"
                && l.value == "17 byte(s), keys unavailable"));
        assert!(d
            .layers
            .iter()
            .all(|l| l.value != "protected payload — Initial keys mismatch"));
    }

    /// Encode a QUIC varint (RFC 9000 §16) in the minimal form.
    fn encode_varint(value: u64) -> Vec<u8> {
        match value {
            0..=63 => vec![value as u8],
            64..=16_383 => vec![(0x40 | (value >> 8)) as u8, value as u8],
            16_384..=1_073_741_823 => (0x8000_0000u32 | value as u32).to_be_bytes().to_vec(),
            _ => (0xC000_0000_0000_0000u64 | value).to_be_bytes().to_vec(),
        }
    }

    /// Build a protected version-1 Initial with an explicit direction, as an
    /// encrypt-then-dissect round trip. `client_keys` selects which
    /// direction's secrets protect the payload. Any padding needed for the
    /// header-protection sample goes INSIDE the sealed payload (RFC 9000
    /// §17.1), exactly as a real sender would pad.
    fn protected_initial(
        dcid: &[u8],
        scid: &[u8],
        client_keys: bool,
        packet_number: u64,
        frames: &[u8],
    ) -> Vec<u8> {
        let secret = crypto::initial_secret(dcid);
        let direction = if client_keys {
            crypto::client_initial_secret(&secret)
        } else {
            crypto::server_initial_secret(&secret)
        };
        protected_long_header(
            0,
            dcid,
            scid,
            &crypto::protection_keys(&direction),
            packet_number,
            2,
            frames,
        )
    }

    /// Encrypt one protected long-header packet with explicit keys — the
    /// encrypt side of the round-trip harness. `type_bits` selects Initial
    /// (0, empty token) or Handshake (2).
    fn protected_long_header(
        type_bits: u8,
        dcid: &[u8],
        scid: &[u8],
        keys: &crypto::ProtectionKeys,
        packet_number: u64,
        pn_len: usize,
        frames: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0xc0u8 | (type_bits << 4) | (pn_len as u8 - 1)];
        packet.extend_from_slice(&VERSION_V1.to_be_bytes());
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);
        if type_bits == 0 {
            packet.push(0); // Initial token: none
        }
        let payload = padded_payload(frames, pn_len);
        let protected_len = pn_len + payload.len() + AEAD_TAG;
        packet.extend(encode_varint(protected_len as u64));
        seal_and_protect(&mut packet, keys, packet_number, pn_len, &payload, 0x0f);
        packet
    }

    /// Encrypt one 1-RTT short-header packet (RFC 9000 §17.3 shape) with
    /// explicit application keys; `key_phase` sets the protected K bit.
    fn protected_1rtt(
        dcid: &[u8],
        keys: &crypto::ProtectionKeys,
        packet_number: u64,
        pn_len: usize,
        key_phase: bool,
        frames: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0x40u8 | (pn_len as u8 - 1) | if key_phase { 0x04 } else { 0x00 }];
        packet.extend_from_slice(dcid);
        let payload = padded_payload(frames, pn_len);
        seal_and_protect(&mut packet, keys, packet_number, pn_len, &payload, 0x1f);
        packet
    }

    /// Pad the frames so the header-protection sample — 16 bytes starting 4
    /// after the pn field — sits inside the datagram.
    fn padded_payload(frames: &[u8], pn_len: usize) -> Vec<u8> {
        let mut payload = frames.to_vec();
        let min_frames = 4 + SAMPLE_LEN - pn_len - AEAD_TAG;
        while payload.len() < min_frames {
            payload.push(0x00); // PADDING frames
        }
        payload
    }

    /// Seal `payload` onto `packet` (the packet-number field starts at the
    /// current length) and apply header protection over `first_byte_bits`.
    fn seal_and_protect(
        packet: &mut Vec<u8>,
        keys: &crypto::ProtectionKeys,
        packet_number: u64,
        pn_len: usize,
        payload: &[u8],
        first_byte_bits: u8,
    ) {
        let pn_offset = packet.len();
        let pn_bytes = packet_number.to_be_bytes();
        let pn_slice = &pn_bytes[8 - pn_len..];
        let nonce = crypto::aead_nonce(&keys.iv, packet_number);
        let mut aad = packet.clone();
        aad.extend_from_slice(pn_slice);
        let sealed = crypto::gcm::seal(&keys.key, &nonce, &aad, payload);
        packet.extend_from_slice(pn_slice);
        packet.extend_from_slice(&sealed);
        let mask = crypto::header_protection_mask(&keys.hp, &packet[pn_offset + 4..pn_offset + 20])
            .expect("16-byte sample");
        packet[0] ^= mask[0] & first_byte_bits;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }

    #[test]
    fn server_keyed_initial_round_trips_through_the_dissector() {
        // Self-generated round trip with the SERVER secrets: validates the
        // second derivation branch, HP removal, the nonce and the frame walk
        // through the public entry point.
        let dcid = [0x83u8, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let mut frames = vec![0x01u8]; // PING
        frames.extend([0x02, 0x00, 0x00, 0x01, 0x01]); // ACK largest=0, 1 range
        let packet = protected_initial(&dcid, &[], false, 1, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value.contains("decrypted with server Initial keys")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "packet number" && l.value.starts_with("1 (2-byte encoding")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "PING"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "ACK largest=0, 1 range(s)"));
        // No hello in these CRYPTO-free frames: no TLS layer, empty payload.
        assert!(d.layers.iter().all(|l| l.label != "TLS"));
        assert!(d.payload.is_empty());
    }

    #[test]
    fn frame_caps_and_undecodable_types_stop_with_honest_notes() {
        let dcid = [0x11u8; 8];
        // 300 PING frames trip the frame cap at 256 parsed; only 12 are
        // listed and the remainder is summarized.
        let frames = vec![0x01u8; 300];
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        let listed: Vec<&Layer> = d
            .layers
            .iter()
            .filter(|l| l.label == "QUIC frame")
            .collect();
        assert_eq!(listed.len(), MAX_LISTED_FRAMES + 1); // 12 + the cap line
        assert_eq!(listed[MAX_LISTED_FRAMES].value, "+244 more (cap 12)");
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "frame decode" && l.value.contains("frame cap 256 reached")));

        // An undecodable frame type (STREAM 0x08) stops the walk with a note
        // naming the type.
        let mut frames = vec![0x01u8, 0x08, 0x00];
        frames.extend([0x00; 24]);
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "frame decode"
                && l.value.contains("frame type 0x08 not decodable here")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "PING"));
    }

    #[test]
    fn ack_bounds_and_truncation_are_bounded() {
        let dcid = [0x22u8; 8];
        // A well-formed ACK with 200 ranges is capped honestly at 64.
        let mut frames = vec![0x02u8]; // ACK
        frames.extend([0x40, 0x64]); // largest = 100
        frames.push(0x00); // delay = 0
        frames.extend([0x40, 0xc8]); // range count = 200
        frames.push(0x40); // first range = 64
        for _ in 0..199 {
            frames.push(0x00); // gap = 0
            frames.push(0x00); // range = 0
        }
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "frame decode" && l.value.contains("ACK range cap 64 reached")));

        // A truncated ACK (declared ranges missing) stops with a note.
        let frames = vec![0x02u8, 0x05, 0x00, 0x05, 0x01]; // 5 ranges, none present
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "frame decode" && l.value.contains("ACK range data truncated")));
    }

    #[test]
    fn crypto_gap_and_oversize_are_described_but_not_reassembled() {
        let dcid = [0x33u8; 8];
        // Two CRYPTO frames with a gap between them: only a contiguous run
        // from offset 0 reassembles, so no TLS attempt is made on the join.
        let mut frames = vec![0x06u8]; // CRYPTO
        frames.extend([0x00, 0x04]); // offset 0, length 4
        frames.extend([0x01, 0x00, 0x00, 0x00]); // partial hello header
        frames.push(0x06); // CRYPTO
        frames.extend([0x40, 0x0a, 0x04]); // offset 10, length 4 — gap
        frames.extend([0x00; 4]);
        frames.extend([0x00; 16]); // PADDING so the sample region exists
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "CRYPTO offset=0, 4 byte(s)"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "CRYPTO offset=10, 4 byte(s)"));
        // The gapped reassembly is refused; the partial hello is never
        // claimed as a decoded handshake.
        assert!(d.payload.is_empty());

        // A CRYPTO frame longer than the reassembly cap is described but
        // leaves the payload empty; no TLS attempt is made on nothing.
        let mut frames = vec![0x06u8, 0x00]; // CRYPTO offset 0
        frames.extend(encode_varint(17_000));
        frames.extend([0x41u8; 17_000]);
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "CRYPTO offset=0, 17000 byte(s)"));
        assert!(d.payload.is_empty());
        assert!(d.layers.iter().all(|l| l.label != "TLS"));

        // CRYPTO bytes that do not start with a hello are surfaced as the
        // payload but never claimed as a decoded handshake.
        let mut frames = vec![0x06u8, 0x00, 0x04]; // CRYPTO offset 0, 4 bytes
        frames.extend([0x41u8; 4]);
        frames.extend([0x00u8; 16]); // PADDING for the sample region
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "CRYPTO offset=0, 4 byte(s)"));
        assert_eq!(d.payload, vec![0x41u8; 4]);
        // Any TLS-labeled row is an honest refusal, never a hello claim.
        assert!(d
            .layers
            .iter()
            .all(|l| l.label != "TLS" || l.value.contains("not decoded")));
    }

    #[test]
    fn connection_close_frames_are_described_bounded() {
        let dcid = [0x44u8; 8];
        let mut frames = vec![0x01u8]; // PING
        frames.extend([0x1c, 0x03, 0x01, 0x00]); // QUIC close, code 3, frame 1, no reason
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "CONNECTION_CLOSE code=0x3, frame 0x1"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "PING"));

        // Application-close with a reason length is summarized by length.
        let mut frames = vec![0x1du8, 0x00, 0x03];
        frames.extend(b"abc");
        let packet = protected_initial(&dcid, &[], true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC frame"
            && l.value == "APPLICATION_CLOSE code=0x0, reason 3 byte(s)"));
        // The reason contents stay unclaimed.
        assert!(d.layers.iter().all(|l| !l.value.contains("abc")));
    }

    #[test]
    fn mutated_a2_packet_never_panics_and_never_half_claims() {
        // Every single-byte mutation inside the protected payload region
        // (packet number, ciphertext, tag) of the published vector breaks
        // AEAD verification: the dissector must fall back with the honest
        // note and never claim partial plaintext. (Header mutations change
        // the packet's identity — version, DCID, length — and are covered by
        // the dedicated header tests above.)
        let base = hex_bytes(RFC9001_A2_CLIENT_INITIAL);
        for at in 18..base.len() {
            for value in [0x00u8, 0xff] {
                let mut data = base.clone();
                if data[at] == value {
                    data[at] ^= 0x55;
                } else {
                    data[at] = value;
                }
                let d = dissect_quic(&data, Vec::new());
                assert!(
                    d.layers
                        .iter()
                        .any(|l| l.value == "protected payload — Initial keys mismatch"),
                    "mutation at {at} (0x{value:02x}) lost the note"
                );
                assert!(d.layers.iter().all(|l| l.label != "TLS"));
                assert!(d.layers.iter().all(|l| l.label != "QUIC frame"));
                assert!(d.payload.is_empty());
            }
        }
    }

    // ------------------------------------------- keylog-bound decryption ----
    //
    // The RFC 9001 A.2/A.3 self-consistency approach, extended: a synthetic
    // connection derives its Initial keys from a chosen DCID, carries a
    // ClientHello with a known random in its CRYPTO frame, and continues
    // with Handshake/1-RTT packets sealed under per-label traffic secrets
    // written into a synthetic keylog — the same encrypt-then-dissect
    // round trip through the crate's own crypto path.

    const CH_RANDOM_HEX: &str = "b3b1b0aa97b0fdfbbfb17e26bfd11b7fb2b252db4f6dfe95f4a25a77ba01d988";

    /// An EncryptedExtensions-shaped handshake message (never a hello, so
    /// the TLS layer must refuse it honestly).
    const ENCRYPTED_EXTENSIONS: &[u8] = &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00];

    /// A deterministic per-label traffic secret (FNV-1a over the label), so
    /// distinct labels never collide by construction.
    fn secret_for(label: &str) -> [u8; 32] {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in label.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hex_bytes(&format!("{hash:064x}")).try_into().unwrap()
    }

    /// A keylog covering `random_hex` with all four traffic secrets.
    fn keylog_for(random_hex: &str) -> crypto::keylog::KeylogStore {
        let mut text = String::new();
        for label in [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
        ] {
            text.push_str(&format!(
                "{label} {random_hex} {}\n",
                hex(&secret_for(label))
            ));
        }
        crypto::keylog::KeylogStore::parse(&text).unwrap()
    }

    /// A minimal well-framed ClientHello message carrying `random_hex` at
    /// message offset 6 — exactly the shape the binding step reads, and
    /// complete enough for the hello walk to decode (empty session id, one
    /// cipher suite, the null compression method, no extensions).
    fn client_hello(random_hex: &str) -> Vec<u8> {
        let mut hello = vec![0x03, 0x03];
        hello.extend(hex_bytes(random_hex));
        hello.extend([0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00]);
        let mut message = vec![0x01, 0x00, 0x00, hello.len() as u8];
        message.extend(hello);
        message
    }

    /// A CRYPTO frame at offset 0 carrying one handshake message.
    fn crypto_frame(message: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06u8, 0x00];
        frame.extend(encode_varint(message.len() as u64));
        frame.extend_from_slice(message);
        frame
    }

    /// Bind one synthetic connection: feed the client Initial (decrypts and
    /// registers the keylog's secrets for its ClientHello random) and the
    /// server Handshake (registers the server's SCID route). Returns the
    /// connection's CIDs for the later packets.
    fn bind_connection(dec: &mut QuicDecryptor) -> ([u8; 8], [u8; 8], [u8; 4]) {
        let dcid = [0x83u8, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let client_scid = [0xf0u8, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
        let server_scid = [0x5au8, 0x5b, 0x5c, 0x5d];
        let initial = protected_initial(
            &dcid,
            &client_scid,
            true,
            0,
            &crypto_frame(&client_hello(CH_RANDOM_HEX)),
        );
        let d = dec.dissect(&initial, Vec::new());
        assert!(d.layers.iter().any(
            |l| l.label == "QUIC protected payload" && l.value.contains("client Initial keys")
        ));
        assert!(d.info.contains("ClientHello"), "info: {}", d.info);
        let server_hs = crypto::protection_keys(&secret_for("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
        let handshake = protected_long_header(
            2,
            &client_scid,
            &server_scid,
            &server_hs,
            0,
            2,
            &crypto_frame(ENCRYPTED_EXTENSIONS),
        );
        let d = dec.dissect(&handshake, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC protected payload"
                && l.value.contains("server Handshake keys")));
        // The connection's first Handshake packet decodes statelessly.
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "packet number"
                && l.value == "0 (2-byte encoding, stateless decode)"));
        (dcid, client_scid, server_scid)
    }

    #[test]
    fn handshake_round_trips_through_bound_state() {
        let mut dec = QuicDecryptor::new(keylog_for(CH_RANDOM_HEX));
        let (_dcid, client_scid, server_scid) = bind_connection(&mut dec);
        let server_hs = crypto::protection_keys(&secret_for("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
        let packet = protected_long_header(
            2,
            &client_scid,
            &server_scid,
            &server_hs,
            0,
            2,
            &crypto_frame(ENCRYPTED_EXTENSIONS),
        );
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value.ends_with("decrypted with server Handshake keys")));
        // The slot has state now, so this packet number reconstructs.
        assert!(d.layers.iter().any(|l| l.label == "packet number"
            && l.value == "0 (2-byte encoding, reconstructed from connection state)"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "CRYPTO offset=0, 6 byte(s)"));
        // EncryptedExtensions are not a hello: the TLS layer refuses
        // honestly instead of claiming anything.
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "TLS" && l.value.contains("not decoded")));
        assert_eq!(d.payload, ENCRYPTED_EXTENSIONS.to_vec());
    }

    #[test]
    fn one_rtt_round_trips_stream_data_and_reconstructs_packet_numbers() {
        let mut dec = QuicDecryptor::new(keylog_for(CH_RANDOM_HEX));
        let (_dcid, client_scid, server_scid) = bind_connection(&mut dec);
        let client_app = crypto::protection_keys(&secret_for("CLIENT_TRAFFIC_SECRET_0"));
        let mut frames = vec![0x0au8, 0x00, 0x05]; // STREAM id=0, length present
        frames.extend_from_slice(b"hello");
        frames.extend([0x02, 0x00, 0x00, 0x01, 0x01]); // ACK largest=0, 1 range
        let packet = protected_1rtt(&server_scid, &client_app, 2, 1, false, &frames);
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value
                .ends_with("decrypted with client application keys (1-RTT)")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "packet number"
                && l.value == "2 (1-byte encoding, stateless decode)"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "STREAM id=0, 5 byte(s)"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "ACK largest=0, 1 range(s)"));
        assert_eq!(d.payload, b"hello".to_vec());
        assert!(d
            .info
            .contains("QUIC short header (1-RTT), DCID 5a5b5c5d, pn 2, 2 frame(s)"));

        // The large packet-number jump from the slice scope: pn 0-committed
        // state, then pn 1300 in a 2-byte encoding, then pn 1301 in a 1-byte
        // encoding — RFC 9000 §A window reconstruction with verified tags.
        let packet = protected_1rtt(&server_scid, &client_app, 1300, 2, false, &[0x01, 0x00]);
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "packet number"
            && l.value == "1300 (2-byte encoding, reconstructed from connection state)"));
        let packet = protected_1rtt(
            &server_scid,
            &client_app,
            1301,
            1,
            false,
            &[0x01, 0x00, 0x00],
        );
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "packet number"
            && l.value == "1301 (1-byte encoding, reconstructed from connection state)"));

        // Server→client 1-RTT with NEW_CONNECTION_ID: the announced CID
        // routes later client packets on the same connection.
        let server_app = crypto::protection_keys(&secret_for("SERVER_TRAFFIC_SECRET_0"));
        let mut ncid = vec![0x18u8, 0x01, 0x00, 0x04]; // seq=1, retire=0, CID len 4
        ncid.extend([0xaau8, 0xbb, 0xcc, 0xdd]);
        ncid.extend([0u8; 16]); // stateless reset token, never decoded
        let packet = protected_1rtt(&client_scid, &server_app, 0, 1, false, &ncid);
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value
                .ends_with("decrypted with server application keys (1-RTT)")));
        assert!(d.layers.iter().any(
            |l| l.label == "QUIC frame" && l.value == "NEW_CONNECTION_ID seq=1, CID 4 byte(s)"
        ));
        let packet = protected_1rtt(
            &[0xaau8, 0xbb, 0xcc, 0xdd],
            &client_app,
            1302,
            1,
            false,
            &[0x01, 0x00, 0x00],
        );
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value
                .ends_with("decrypted with client application keys (1-RTT)")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "destination connection id" && l.value == "aabbccdd"));
    }

    #[test]
    fn server_initial_verifies_through_bound_state_and_chains_forward() {
        // A standalone server Initial cannot verify (its keys derive from
        // the CLIENT's first DCID, absent from its own header). With the
        // client flight bound, the stored DCID derives the keys — and the
        // verified server SCID then routes the client's own Handshake.
        let dcid = [0x83u8, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let client_scid = [0xf0u8, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
        let server_scid = [0x5au8, 0x5b, 0x5c, 0x5d];
        let mut dec = QuicDecryptor::new(keylog_for(CH_RANDOM_HEX));
        let initial = protected_initial(
            &dcid,
            &client_scid,
            true,
            0,
            &crypto_frame(&client_hello(CH_RANDOM_HEX)),
        );
        assert!(dec
            .dissect(&initial, Vec::new())
            .info
            .contains("ClientHello"));
        let server_hello = [0x02u8, 0x00, 0x00, 0x04, 0x03, 0x03, 0xaa, 0xbb];
        let server_initial_keys = crypto::protection_keys(&crypto::server_initial_secret(
            &crypto::initial_secret(&dcid),
        ));
        let packet = protected_long_header(
            0,
            &client_scid,
            &server_scid,
            &server_initial_keys,
            1,
            2,
            &crypto_frame(&server_hello),
        );
        // Stateless first: the server Initial fails honestly on its own.
        let d = dissect_quic(&packet.clone(), Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.value == "protected payload — Initial keys mismatch"));
        // Bound: the stored original DCID derives the server keys.
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value.contains("decrypted with server Initial keys")));
        // The verified server SCID now routes the client→server flight.
        let client_hs = crypto::protection_keys(&secret_for("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));
        let handshake = protected_long_header(
            2,
            &server_scid,
            &client_scid,
            &client_hs,
            0,
            2,
            &crypto_frame(ENCRYPTED_EXTENSIONS),
        );
        let d = dec.dissect(&handshake, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value.contains("decrypted with client Handshake keys")));
    }

    #[test]
    fn one_rtt_without_binding_stays_header_only_with_the_verbatim_view() {
        let mut dec = QuicDecryptor::new(keylog_for(CH_RANDOM_HEX));
        // No Initial fed: no route, so the DCID length is unrecoverable and
        // the stateless view applies verbatim — plus the honest note.
        let client_app = crypto::protection_keys(&secret_for("CLIENT_TRAFFIC_SECRET_0"));
        let packet = protected_1rtt(
            &[0x11u8, 0x22],
            &client_app,
            0,
            1,
            false,
            &[0x01, 0x00, 0x00],
        );
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC"
            && l.value == "QUIC short header (1-RTT); DCID not recoverable without prior state"));
        assert!(d.layers.iter().any(|l| l.label == "payload decryption"
            && l.value == "protected payload — no keylog binding for this DCID (1-RTT attempted)"));
        assert!(d.layers.iter().all(|l| l.label != "QUIC frame"));
        assert!(d.payload.is_empty());
    }

    #[test]
    fn wrong_keylog_random_binds_nothing_and_handshake_stays_ciphertext() {
        // The keylog covers a different connection: the A2 client Initial
        // still decrypts (its keys derive from the public DCID) but binds
        // nothing, so the Handshake flight stays header-only.
        let mut dec = QuicDecryptor::new(keylog_for(&format!("{:064x}", 0xfeed_u128)));
        let d = dec.dissect(&hex_bytes(RFC9001_A2_CLIENT_INITIAL), Vec::new());
        assert!(d.layers.iter().any(
            |l| l.label == "QUIC protected payload" && l.value.contains("client Initial keys")
        ));
        let server_hs = crypto::protection_keys(&secret_for("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
        let packet = protected_long_header(
            2,
            &[0xf0u8, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5],
            &[0x5au8, 0x5b, 0x5c, 0x5d],
            &server_hs,
            0,
            2,
            &crypto_frame(ENCRYPTED_EXTENSIONS),
        );
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "payload decryption"
            && l.value
                .contains("no keylog binding for this connection (Handshake attempted)")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC protected payload" && l.value.ends_with("keys unavailable")));
        assert!(d.layers.iter().all(|l| l.label != "QUIC frame"));
        assert!(d.payload.is_empty());
    }

    #[test]
    fn corrupted_1rtt_tag_and_key_phase_one_report_honestly() {
        let mut dec = QuicDecryptor::new(keylog_for(CH_RANDOM_HEX));
        let (_dcid, _client_scid, server_scid) = bind_connection(&mut dec);
        let client_app = crypto::protection_keys(&secret_for("CLIENT_TRAFFIC_SECRET_0"));
        let packet = protected_1rtt(
            &server_scid,
            &client_app,
            0,
            1,
            false,
            &[0x0au8, 0x00, 0x02, 0x41, 0x42], // STREAM "AB"
        );
        let mut corrupted = packet.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xff; // break the AEAD tag
        let d = dec.dissect(&corrupted, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "payload decryption"
            && l.value
                == "protected payload — 1-RTT application keys did not verify (1-RTT attempted)"));
        assert!(d.layers.iter().all(|l| l.label != "QUIC frame"));
        assert!(d.payload.is_empty());

        // Key phase 1 selects key-update keys, which no keylog carries:
        // refused without any plaintext claim.
        let packet = protected_1rtt(
            &server_scid,
            &client_app,
            1,
            1,
            true,
            &[0x0au8, 0x00, 0x02, 0x41, 0x42],
        );
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "payload decryption"
            && l.value
                == "protected payload — key phase 1 (key update) secrets are not in the keylog (1-RTT attempted)"));
        assert!(d.payload.is_empty());
    }

    #[test]
    fn path_frames_are_named_but_never_decoded() {
        let mut dec = QuicDecryptor::new(keylog_for(CH_RANDOM_HEX));
        let (_dcid, _client_scid, server_scid) = bind_connection(&mut dec);
        let client_app = crypto::protection_keys(&secret_for("CLIENT_TRAFFIC_SECRET_0"));
        let mut frames = vec![0x1au8]; // PATH_CHALLENGE
        frames.extend([0x42u8; 8]);
        frames.push(0x01); // PING
        let packet = protected_1rtt(&server_scid, &client_app, 0, 1, false, &frames);
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(
            |l| l.label == "QUIC frame" && l.value == "PATH_CHALLENGE 8 byte(s) (not decoded)"
        ));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC frame" && l.value == "PING"));
        assert!(d.payload.is_empty());
    }

    #[test]
    fn stateless_dissect_quic_stays_header_only_without_capture_state() {
        // No decryptor installed: the stateless entry behaves exactly as
        // before this slice — no notes, no claims.
        let server_hs = crypto::protection_keys(&secret_for("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
        let packet = protected_long_header(
            2,
            &[0xf0u8, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5],
            &[0x5au8, 0x5b, 0x5c, 0x5d],
            &server_hs,
            0,
            2,
            &crypto_frame(ENCRYPTED_EXTENSIONS),
        );
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC protected payload" && l.value.ends_with("keys unavailable")));
        assert!(d.layers.iter().all(|l| l.label != "payload decryption"));
        assert!(d.payload.is_empty());
        let client_app = crypto::protection_keys(&secret_for("CLIENT_TRAFFIC_SECRET_0"));
        let short = protected_1rtt(
            &[0x11u8, 0x22],
            &client_app,
            0,
            1,
            false,
            &[0x01, 0x00, 0x00],
        );
        let d = dissect_quic(&short, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC"
            && l.value == "QUIC short header (1-RTT); DCID not recoverable without prior state"));
        assert!(d.layers.iter().all(|l| l.label != "payload decryption"));
    }

    #[test]
    fn capture_scoped_install_decrypts_and_the_guard_clears() {
        let mut dec = QuicDecryptor::new(keylog_for(CH_RANDOM_HEX));
        let (_dcid, client_scid, server_scid) = bind_connection(&mut dec);
        let server_hs = crypto::protection_keys(&secret_for("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
        let packet = protected_long_header(
            2,
            &client_scid,
            &server_scid,
            &server_hs,
            0,
            2,
            &crypto_frame(ENCRYPTED_EXTENSIONS),
        );
        {
            let guard = crypto::quic_capture_install(dec);
            let d = dissect_quic(&packet, Vec::new());
            assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
                && l.value.contains("server Handshake keys")));
            drop(guard);
        }
        // The guard cleared the installation: later parses on this thread
        // see the stateless view again.
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "QUIC protected payload" && l.value.ends_with("keys unavailable")));
        assert!(d.layers.iter().all(|l| l.label != "QUIC frame"));
    }

    /// A deterministic per-connection traffic secret for the LRU test.
    fn lru_secret(connection: u8, label_index: usize) -> [u8; 32] {
        let value = ((connection as u128) << 8) | label_index as u128;
        hex_bytes(&format!("{value:064x}")).try_into().unwrap()
    }

    #[test]
    fn connection_state_is_lru_bounded_at_64() {
        // 65 synthetic connections, each a client Initial with its own
        // random and SCID; the keylog covers all of them. The oldest falls
        // out of the LRU (routes included) while the newest keeps working.
        let mut text = String::new();
        for i in 0..65u8 {
            for (label_index, label) in [
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0",
                "SERVER_TRAFFIC_SECRET_0",
            ]
            .iter()
            .enumerate()
            {
                text.push_str(&format!(
                    "{label} {:064x} {}\n",
                    0x1000u128 + i as u128,
                    hex(&lru_secret(i, label_index))
                ));
            }
        }
        let store = crypto::keylog::KeylogStore::parse(&text).unwrap();
        let mut dec = QuicDecryptor::new(store);
        for i in 0..65u8 {
            let random_hex = format!("{:064x}", 0x1000u128 + i as u128);
            let dcid = [i, 0, 0, 0, 0, 0, 0, 8];
            let scid = [0x50u8 + i, 1, 2, 3];
            let initial = protected_initial(
                &dcid,
                &scid,
                true,
                0,
                &crypto_frame(&client_hello(&random_hex)),
            );
            let d = dec.dissect(&initial, Vec::new());
            assert!(d
                .layers
                .iter()
                .any(|l| l.label == "QUIC protected payload"
                    && l.value.contains("client Initial keys")));
        }
        assert_eq!(dec.connections.len(), crypto::MAX_QUIC_CONNECTIONS);
        // Connection 0 was evicted: its SCID route is gone.
        let app0 = crypto::protection_keys(&lru_secret(0, 2));
        let packet = protected_1rtt(&[0x50u8, 1, 2, 3], &app0, 0, 1, false, &[0x01, 0x00, 0x00]);
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "payload decryption"
            && l.value.contains("no keylog binding for this DCID")));
        // The newest connection still decrypts.
        let app64 = crypto::protection_keys(&lru_secret(64, 2));
        let packet = protected_1rtt(
            &[0x50u8 + 64, 1, 2, 3],
            &app64,
            0,
            1,
            false,
            &[0x01, 0x00, 0x00],
        );
        let d = dec.dissect(&packet, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload"
            && l.value
                .ends_with("decrypted with client application keys (1-RTT)")));
    }
}

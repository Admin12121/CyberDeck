//! Bounded QUIC dissection over UDP/443: long-header version, packet type
//! and destination connection id — plus, for version-1 Initial packets only,
//! full payload decryption. The Initial keys derive from the public
//! Destination Connection ID (RFC 9001 §5.2), so the header protection is
//! removed (§5.4), the AEAD tag is verified (AES-128-GCM, §5.3) and the
//! frames (PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE) are decoded.
//! CRYPTO bytes surface the TLS handshake they carry through the existing
//! hello walk, the same shape the TCP path feeds it.
//!
//! Honesty contracts, enforced everywhere below:
//! - 0-RTT and Handshake payloads need per-connection traffic secrets a
//!   passive observer cannot reconstruct; they stay header-only.
//! - Server Initials derive their keys from the CLIENT's first DCID, which
//!   is not in the server packet's header, so a standalone server Initial is
//!   expected to fail verification and fall back honestly.
//! - Any AEAD failure degrades to the header-only view plus a note; partial
//!   plaintext is never claimed.

use super::link::color_for;
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

/// One Initial packet whose AEAD tag verified: which direction's keys
/// matched, the decoded packet number, and the plaintext frames.
struct DecodedInitial {
    client_keys: bool,
    packet_number: u64,
    pn_len: usize,
    plaintext: Vec<u8>,
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
) -> Option<DecodedInitial> {
    let secret = crypto::initial_secret(dcid);
    for client_keys in [true, false] {
        let direction = if client_keys {
            crypto::client_initial_secret(&secret)
        } else {
            crypto::server_initial_secret(&secret)
        };
        let keys = crypto::protection_keys(&direction);
        // RFC 9001 §5.4.2: the 16-byte sample starts 4 bytes after the
        // packet-number field begins — a fixed offset, read from the bytes
        // as received (coalesced bytes count; RFC 9000 §17.1 guarantees the
        // space exists).
        let sample = payload.get(pn_offset + 4..pn_offset + 4 + SAMPLE_LEN)?;
        let mask = crypto::header_protection_mask(&keys.hp, sample)?;
        // Long headers protect the low 4 bits of the first byte (RFC 9001
        // §5.4.1). Bits 0-1 then carry the packet-number length and bits 2-3
        // are reserved-zero, so a wrong key unmask is visible immediately.
        let first = payload[0] ^ (mask[0] & 0x0f);
        if first & LONG_HEADER_BIT == 0 || first & 0x40 == 0 || first & 0x0c != 0 {
            continue; // these keys did not produce a valid long header
        }
        let pn_len = usize::from(first & 0x03) + 1;
        if declared < pn_len + AEAD_TAG {
            continue; // cannot hold packet number + tag in this encoding
        }
        let mut pn_bytes = [0u8; 4];
        for i in 0..pn_len {
            pn_bytes[i] = payload[pn_offset + i] ^ mask[1 + i];
        }
        // Stateless packet-number reconstruction: with no connection state
        // the RFC 9000 §A.3 sliding window cannot be applied, so the on-wire
        // value is taken as-is. That is exact for first-flight traffic — the
        // only Initials this dissector can verify — and never fabricated.
        let mut packet_number: u64 = 0;
        for i in 0..pn_len {
            packet_number = (packet_number << 8) | u64::from(pn_bytes[i]);
        }
        // nonce = static IV XOR packet number (RFC 9001 §5.3).
        let nonce = crypto::aead_nonce(&keys.iv, packet_number);
        // AAD: the full header with header protection removed — everything
        // before the packet number plus the unmasked packet-number bytes.
        let mut aad = payload[..pn_offset].to_vec();
        aad[0] = first;
        aad.extend_from_slice(&pn_bytes[..pn_len]);
        let ciphertext = payload.get(pn_offset + pn_len..pn_offset + declared)?;
        if let Some(plaintext) = crypto::gcm::open(&keys.key, &nonce, &aad, ciphertext) {
            return Some(DecodedInitial {
                client_keys,
                packet_number,
                pn_len,
                plaintext,
            });
        }
    }
    None
}

/// Bounded frame walk (RFC 9000 §12.4, §19) over a decrypted Initial
/// payload. Initials may only carry PADDING, PING, ACK, CRYPTO and
/// CONNECTION_CLOSE; anything else stops the walk with an honest note.
/// Returns the frame descriptions, the CRYPTO bytes reassembled from a
/// contiguous run starting at offset 0 (the handshake flight shape; empty
/// when the frames are gapped or past the cap) and the stop note, if any.
fn parse_initial_frames(plaintext: &[u8]) -> (Vec<String>, Vec<u8>, Option<String>) {
    let mut frames: Vec<String> = Vec::new();
    let mut crypto_data = Vec::new();
    let mut crypto_contiguous = true;
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
    (frames, reassembled, stop)
}

/// Layer emission for a verified Initial: packet number, frame listing,
/// TLS hello (when the CRYPTO bytes carry one) and the handshake bytes as
/// the payload for further analysis.
fn emit_decrypted_initial(
    mut layers: Vec<Layer>,
    mut info: String,
    decoded: DecodedInitial,
    declared: usize,
    coalesced: usize,
) -> Dissected {
    let side = if decoded.client_keys {
        "client"
    } else {
        "server"
    };
    layers.push(layer(
        "QUIC protected payload",
        format!("{declared} byte(s), decrypted with {side} Initial keys"),
    ));
    layers.push(layer(
        "packet number",
        format!(
            "{} ({}-byte encoding, stateless decode)",
            decoded.packet_number, decoded.pn_len
        ),
    ));
    let (frames, crypto_data, stop) = parse_initial_frames(&decoded.plaintext);
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
        layers.push(layer("frame decode", note));
    }
    info.push_str(&format!(
        ", pn {}, {} frame(s)",
        decoded.packet_number,
        frames.len()
    ));
    // QUIC CRYPTO frames carry raw TLS handshake messages (no record
    // layer). Wrapping them in a synthetic TLS record header lets the
    // existing hello walk — the same one TCP streams feed — decode them.
    if !crypto_data.is_empty() {
        match crypto_data.first() {
            Some(&0x01) | Some(&0x02) => {
                let mut record = Vec::with_capacity(crypto_data.len() + 5);
                record.extend_from_slice(&[0x16, 0x03, 0x03]);
                record.extend_from_slice(&(crypto_data.len() as u16).to_be_bytes());
                record.extend_from_slice(&crypto_data);
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
    dissected.payload = crypto_data;
    dissected
}

/// Dissect one QUIC datagram (the UDP payload on port 443). The protocol
/// claim follows the port plus the header-form bit — the same strength as
/// the TLS claim on TCP/443 — and every structural refusal degrades to an
/// honest QUIC row instead of a bare truncation note.
pub fn dissect_quic(payload: &[u8], mut layers: Vec<Layer>) -> Dissected {
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
        layers.push(layer(
            "QUIC",
            "QUIC short header (1-RTT); DCID not recoverable without prior state",
        ));
        layers.push(layer("packet type", "short header (1-RTT)"));
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
    // public DCID, so decryption is attempted below; 0-RTT and Handshake
    // need session traffic secrets and stay header-only by design.
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
                return emit_decrypted_initial(layers, info, decoded, declared, coalesced);
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
        let keys = crypto::protection_keys(&direction);
        // Header up to (not including) the length varint, to learn the
        // packet-number offset.
        let mut packet = vec![0xc1u8]; // Initial, 2-byte packet number
        packet.extend_from_slice(&VERSION_V1.to_be_bytes());
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);
        packet.push(0); // SCID length
        packet.push(0); // token length
                        // Pad the payload so the header-protection sample — 16 bytes
                        // starting 4 after the pn field — is inside the datagram.
        let mut payload = frames.to_vec();
        let min_frames = 4 + SAMPLE_LEN - 2 - AEAD_TAG;
        while payload.len() < min_frames {
            payload.push(0x00); // PADDING frames
        }
        let protected_len = 2 + payload.len() + AEAD_TAG;
        packet.extend(encode_varint(protected_len as u64));
        let pn_offset = packet.len(); // packet number starts here
        let pn_bytes = (packet_number as u16).to_be_bytes();
        let nonce = crypto::aead_nonce(&keys.iv, packet_number);
        let mut aad = packet.clone();
        aad.extend_from_slice(&pn_bytes);
        let sealed = crypto::gcm::seal(&keys.key, &nonce, &aad, &payload);
        packet.extend_from_slice(&pn_bytes);
        packet.extend_from_slice(&sealed);
        // Apply header protection (RFC 9001 §5.4.1).
        let mask = crypto::header_protection_mask(&keys.hp, &packet[pn_offset + 4..pn_offset + 20])
            .expect("16-byte sample");
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..2 {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    #[test]
    fn server_keyed_initial_round_trips_through_the_dissector() {
        // Self-generated round trip with the SERVER secrets: validates the
        // second derivation branch, HP removal, the nonce and the frame walk
        // through the public entry point.
        let dcid = [0x83u8, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let mut frames = vec![0x01u8]; // PING
        frames.extend([0x02, 0x00, 0x00, 0x01, 0x01]); // ACK largest=0, 1 range
        let packet = protected_initial(&dcid, false, 1, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
        let d = dissect_quic(&packet, Vec::new());
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "frame decode" && l.value.contains("ACK range cap 64 reached")));

        // A truncated ACK (declared ranges missing) stops with a note.
        let frames = vec![0x02u8, 0x05, 0x00, 0x05, 0x01]; // 5 ranges, none present
        let packet = protected_initial(&dcid, true, 0, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
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
        let packet = protected_initial(&dcid, true, 0, &frames);
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
}

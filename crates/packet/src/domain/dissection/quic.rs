//! Bounded QUIC dissection over UDP/443: long-header version, packet type
//! and destination connection id only. QUIC payloads are header-protected
//! with keys this dissector does not have, so nothing beyond the public
//! header is ever claimed — no SNI, no frame contents, no secrets guessed.

use super::link::color_for;
use crate::{Dissected, Layer};

const LONG_HEADER_BIT: u8 = 0x80;
/// Version 1 (RFC 9000) and the fixed version-negotiation marker (RFC 8999).
const VERSION_V1: u32 = 0x0000_0001;
const VERSION_NEGOTIATION: u32 = 0x0000_0000;
/// QUIC caps connection IDs at 20 bytes (RFC 9000 §7.2).
const MAX_CONNECTION_ID: usize = 20;

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

fn hex_bounded(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for byte in bytes.iter().take(MAX_CONNECTION_ID) {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
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
        layers.push(layer("source connection id", "length overflow; not decoded"));
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
                layers.push(layer(
                    "token",
                    "length varint truncated; token not decoded",
                ));
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

    // Initial, 0-RTT and Handshake end with the frame length varint; the
    // bytes it covers are header-protected and the keys are unavailable.
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
    if remaining > declared {
        // QUIC datagrams may coalesce packets; bytes past the declared frame
        // are left alone instead of being folded into this packet's claim.
        layers.push(layer(
            "QUIC protected payload",
            format!("{declared} byte(s), keys unavailable"),
        ));
        layers.push(layer(
            "coalesced",
            format!("{} byte(s) after the frame; not decoded", remaining - declared),
        ));
        return dissected(
            layers,
            format!(
                "{info}, {declared} byte(s) protected, {} coalesced",
                remaining - declared
            ),
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

    #[test]
    fn version_one_initial_parses_header_fields_and_refuses_to_claim_payload() {
        let mut datagram = long_header(VERSION_V1, 0, &[0xaa, 0xbb, 0xcc, 0xdd]);
        datagram.push(0); // SCID length
        datagram.push(0x00); // token length varint: 0 (no token)
        datagram.extend([0x40, 0x08]); // frame length varint: 8
        datagram.extend_from_slice(&[0u8; 8]); // protected payload
        let dissected = dissect_quic(&datagram, Vec::new());
        assert_eq!(dissected.protocol, "QUIC");
        assert!(dissected.layers.iter().any(|l| l.label == "version" && l.value.contains("RFC 9000")));
        assert!(dissected.layers.iter().any(|l| l.label == "packet type" && l.value == "Initial"));
        assert!(dissected.layers.iter().any(|l| l.label == "destination connection id" && l.value == "aabbccdd"));
        assert!(dissected.layers.iter().any(|l| l.label == "QUIC protected payload" && l.value == "8 byte(s), keys unavailable"));
        assert!(dissected.layers.iter().any(|l| l.label == "token" && l.value == "no token"));
        assert!(dissected.info.contains("8 protected byte(s)"));
        // Never claims decrypted contents.
        assert!(dissected.layers.iter().all(|l| !l.value.to_lowercase().contains("sni")));
    }

    #[test]
    fn handshake_and_short_headers_classify() {
        let mut handshake = long_header(VERSION_V1, 2, &[0x01]);
        handshake.push(0); // SCID length
        handshake.push(0x02); // frame length varint: 2
        handshake.extend([0xde, 0xad]);
        let d = dissect_quic(&handshake, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "packet type" && l.value == "Handshake"));
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload" && l.value == "2 byte(s), keys unavailable"));
        let short = vec![0x40, 0xaa, 0xbb, 0x01, 0x02, 0x03];
        let d = dissect_quic(&short, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC" && l.value.contains("short header")));
        assert!(d.info.contains("short header"));
        assert!(d.info.contains("DCID not recoverable"));
    }

    #[test]
    fn version_negotiation_is_named() {
        let vn = long_header(VERSION_NEGOTIATION, 0, &[0x01]);
        let d = dissect_quic(&vn, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "packet type" && l.value == "version negotiation"));
        assert!(d.layers.iter().any(|l| l.label == "version" && l.value.contains("version negotiation")));
    }

    #[test]
    fn oversized_or_truncated_dcids_degrade_honestly_not_panic() {
        let oversized = long_header(VERSION_V1, 0, &[0xaa; 21]);
        let d = dissect_quic(&oversized, Vec::new());
        assert_eq!(d.protocol, "QUIC");
        assert!(d.layers.iter().any(|l| l.label == "destination connection id" && l.value.contains("refused")));
        assert!(d.info.contains("DCID refused"));

        let truncated = long_header(VERSION_V1, 0, &[0xaa, 0xbb]);
        let mut cut = truncated.clone();
        cut.pop();
        let d = dissect_quic(&cut, Vec::new());
        assert_eq!(d.protocol, "QUIC");
        assert!(d.layers.iter().any(|l| l.label == "destination connection id" && l.value.contains("truncated")));

        let tiny = vec![0xc0, 0x00];
        let d = dissect_quic(&tiny, Vec::new());
        assert_eq!(d.protocol, "QUIC");
        assert!(d.info.contains("incomplete"));
        assert!(dissect_quic(&[], Vec::new()).info.contains("no captured payload"));
    }

    #[test]
    fn dcid_is_bounded_in_output() {
        let mut datagram = long_header(VERSION_V1, 0, &[0xab; 20]);
        datagram.push(0); // SCID length
        datagram.push(0x00); // token length varint: 0
        datagram.push(0x04); // frame length varint: 4
        datagram.extend_from_slice(&[0u8; 4]); // protected payload
        let d = dissect_quic(&datagram, Vec::new());
        let dcid = d.layers.iter().find(|l| l.label == "destination connection id").unwrap();
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
        assert!(d.layers.iter().any(|l| l.label == "token" && l.value == "token 2 byte(s) (not decoded)"));
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload" && l.value == "3 byte(s), keys unavailable"));
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
        assert!(d.layers.iter().any(|l| l.label == "token" && l.value == "long token (not decoded)"));
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
        assert!(d.layers.iter().any(|l| l.label == "QUIC protected payload" && l.value.contains("frame declares 64")));
        assert!(d.info.contains("4 of 64 protected byte(s) captured"));
    }
}

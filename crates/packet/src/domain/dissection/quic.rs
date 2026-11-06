//! Bounded QUIC dissection over UDP/443: long-header version, packet type
//! and destination connection id only. QUIC payloads are header-protected
//! with keys this dissector does not have, so nothing beyond the public
//! header is ever claimed — no SNI, no frame contents, no secrets guessed.

use super::link::{color_for, empty_frame};
use crate::{Dissected, Layer};

const LONG_HEADER_BIT: u8 = 0x80;
/// Version 1 (RFC 9000) and the fixed version-negotiation marker.
const VERSION_V1: u32 = 0x0000_0001;
const VERSION_NEGOTIATION: u32 = 0x0000_0000;
const MAX_DCID_LEN: usize = 20;

fn packet_type_name(first_byte: u8, version: u32) -> Option<&'static str> {
    if version == VERSION_NEGOTIATION {
        return Some("version negotiation");
    }
    // Bits 4-5 of the long-header first byte (mask 0x30) shifted to 0..3.
    match (first_byte & 0x30) >> 4 {
        0 => Some("initial"),
        1 => Some("0-RTT"),
        2 => Some("handshake"),
        3 => Some("retry"),
        _ => None,
    }
}

/// Decode a QUIC variable-length integer at `at` (RFC 9000 §16). Only the
/// 1- and 2-byte forms are decoded: token/payload lengths beyond 16383 are
/// reported as "long" by the caller instead of pretending precision.
fn varint_short(payload: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *payload.get(at)?;
    match first >> 6 {
        0 => Some((u64::from(first & 0x3f), 1)),
        1 => {
            let second = *payload.get(at + 1)?;
            Some(((u64::from(first & 0x3f) << 8) | u64::from(second), 2))
        }
        _ => None,
    }
}

fn hex_bounded(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for byte in bytes.iter().take(MAX_DCID_LEN) {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Dissect one QUIC datagram. The caller (dissect_udp) supplies the UDP
/// payload; the returned Dissected replaces the plain-UDP projection.
pub fn dissect_quic(payload: &[u8], mut layers: Vec<Layer>) -> Dissected {
    // Both QUIC shapes need at least 6 bytes to carry decodable fields;
    // anything smaller degrades to the transport row.
    if payload.len() < 6 {
        return empty_frame();
    }
    let first = payload[0];
    if first & LONG_HEADER_BIT == 0 {
        layers.push(Layer {
            label: "QUIC".into(),
            value: "short header (1-RTT)".into(),
        });
        layers.push(Layer {
            label: "protected payload".into(),
            value: format!(
                "{} byte(s), DCID not recoverable without prior state; keys unavailable",
                payload.len()
            ),
        });
        return Dissected {
            source: String::new(),
            destination: String::new(),
            protocol: "QUIC".into(),
            info: format!("QUIC short header (1-RTT), {} byte(s)", payload.len()),
            color_hint: color_for("UDP"),
            layers,
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        };
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let dcid_len = payload[5] as usize;
    if dcid_len > MAX_DCID_LEN {
        return empty_frame();
    }
    let Some(dcid) = payload.get(6..6 + dcid_len) else {
        return empty_frame();
    };
    let dcid_hex = hex_bounded(dcid);
    layers.push(Layer {
        label: "QUIC".into(),
        value: format!("long header, version 0x{version:08x}"),
    });
    layers.push(Layer {
        label: "version".into(),
        value: if version == VERSION_NEGOTIATION {
            "version negotiation".into()
        } else if version == VERSION_V1 {
            "1 (RFC 9000)".into()
        } else {
            format!("0x{version:08x}")
        },
    });
    layers.push(Layer {
        label: "destination connection id".into(),
        value: dcid_hex.clone(),
    });

    let mut info = format!("QUIC long header, DCID {dcid_hex}");
    if version == VERSION_NEGOTIATION {
        layers.push(Layer {
            label: "packet type".into(),
            value: "version negotiation".into(),
        });
        info.push_str(", version negotiation");
    } else if version == VERSION_V1 {
        let type_name = packet_type_name(first, version).unwrap_or("unknown");
        layers.push(Layer {
            label: "packet type".into(),
            value: type_name.into(),
        });
        info.push_str(", ");
        info.push_str(type_name);
        // Initial packets carry an unencrypted token + length before the
        // protected payload; decode those two varints and stop there.
        if type_name == "initial" {
            let mut cursor = 6 + dcid_len;
            let Some(scid_len) = payload.get(cursor).copied() else {
                return empty_frame();
            };
            cursor += 1 + usize::from(scid_len);
            if let Some((token_len, _)) = varint_short(payload, cursor) {
                cursor += 1;
                let token_note = if token_len == 0 {
                    "no token".to_string()
                } else if token_len > 16383 {
                    format!("long token ({token_len} byte(s), not decoded)")
                } else {
                    format!("token {token_len} byte(s)")
                };
                layers.push(Layer {
                    label: "token".into(),
                    value: token_note.clone(),
                });
                info.push_str(", ");
                info.push_str(&token_note);
            }
        }
        // The payload after the headers is protected; state that plainly.
        let protected = payload.len().saturating_sub(6 + dcid_len);
        layers.push(Layer {
            label: "protected payload".into(),
            value: format!("{protected} byte(s), keys unavailable"),
        });
        info.push_str(&format!(", {protected} byte(s) protected"));
    } else {
        layers.push(Layer {
            label: "packet type".into(),
            value: format!("version 0x{version:08x} (not v1; type not decoded)"),
        });
    }

    Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: "QUIC".into(),
        info,
        color_hint: color_for("UDP"),
        layers,
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
    }
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
        datagram.push(0x00); // token length varint: 0
        datagram.push(0x40); // payload length varint: 64
        datagram.extend_from_slice(&[0u8; 8]);
        let dissected = dissect_quic(&datagram, Vec::new());
        assert_eq!(dissected.protocol, "QUIC");
        assert!(dissected.layers.iter().any(|l| l.label == "version" && l.value.contains("RFC 9000")));
        assert!(dissected.layers.iter().any(|l| l.label == "packet type" && l.value == "initial"));
        assert!(dissected.layers.iter().any(|l| l.label == "destination connection id" && l.value == "aabbccdd"));
        assert!(dissected.layers.iter().any(|l| l.label == "protected payload" && l.value.contains("keys unavailable")));
        // Never claims decrypted contents.
        assert!(dissected.layers.iter().all(|l| !l.value.contains("SNI")));
    }

    #[test]
    fn handshake_and_short_headers_classify() {
        let handshake = long_header(VERSION_V1, 2, &[0x01]);
        let d = dissect_quic(&handshake, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "packet type" && l.value == "handshake"));
        let short = vec![0x40, 0xaa, 0xbb, 0x01, 0x02, 0x03];
        let d = dissect_quic(&short, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "QUIC" && l.value.contains("short header")));
        assert!(d.info.contains("short header"));
    }

    #[test]
    fn version_negotiation_is_named() {
        let vn = long_header(VERSION_NEGOTIATION, 0, &[0x01]);
        let d = dissect_quic(&vn, Vec::new());
        assert!(d.layers.iter().any(|l| l.label == "packet type" && l.value == "version negotiation"));
    }

    #[test]
    fn oversized_or_truncated_dcids_degrade_not_panic() {
        let oversized = long_header(VERSION_V1, 0, &[0xaa; 21]);
        assert_eq!(dissect_quic(&oversized, Vec::new()).protocol, "MALFORMED");
        let truncated = long_header(VERSION_V1, 0, &[0xaa, 0xbb]);
        let mut cut = truncated.clone();
        cut.pop();
        assert_eq!(dissect_quic(&cut, Vec::new()).protocol, "MALFORMED");
        let tiny = vec![0xc0, 0x00];
        assert_eq!(dissect_quic(&tiny, Vec::new()).protocol, "MALFORMED");
    }

    #[test]
    fn dcid_is_bounded_in_output() {
        let mut datagram = long_header(VERSION_V1, 0, &[0xab; 20]);
        datagram.push(0); // SCID length
        datagram.push(0x00); // token length varint: 0
        datagram.extend_from_slice(&[0u8; 4]); // protected payload
        let d = dissect_quic(&datagram, Vec::new());
        let dcid = d.layers.iter().find(|l| l.label == "destination connection id").unwrap();
        assert_eq!(dcid.value.len(), 40);
    }
}

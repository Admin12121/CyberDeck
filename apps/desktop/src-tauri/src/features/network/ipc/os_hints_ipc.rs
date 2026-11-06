// Passive OS-family hints over the currently opened capture (read-only).
// Signatures are rebuilt strictly from the dissection layers the packet
// crate already emits; a feature the dissector did not record stays absent
// from the signature rather than being inferred from raw bytes here. The
// classifier output is always a low-confidence hint with its evidence basis,
// never a verdict — see crates/packet/src/os_hints.rs for the honesty
// contract and the documented breakpoints it uses.

use cyberdeck_packet::os_hints::{
    classify, OsHint, StackSignature, MAX_OPTION_ORDER, OPTION_KIND_MSS,
    OPTION_KIND_SACK_BLOCKS, OPTION_KIND_SACK_PERMITTED, OPTION_KIND_TIMESTAMPS,
    OPTION_KIND_WINDOW_SCALE,
};
use serde::Serialize;
use tauri::State;

use super::pcap::PcapCtx;

/// Bounded response contract: at most this many hints per call. `sampled`
/// still reports the full handshake-segment count so a truncated answer is
/// visible instead of silent.
pub const MAX_OS_HINTS: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct OsHintWire {
    pub family: String,
    pub confidence: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsHintObservationWire {
    pub source: String,
    pub destination: String,
    /// True when the segment was the server's SYN/ACK rather than a bare SYN.
    pub syn_ack: bool,
    pub hint: OsHintWire,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsHintsWire {
    pub hints: Vec<OsHintObservationWire>,
    /// Total handshake segments seen, including any beyond the returned cap.
    pub sampled: usize,
    /// The bound applied to `hints`; `sampled` may exceed it.
    pub cap: usize,
}

impl From<OsHint> for OsHintWire {
    fn from(hint: OsHint) -> Self {
        OsHintWire {
            family: hint.family,
            confidence: hint.confidence,
            evidence: hint.evidence,
        }
    }
}

fn text_of<'a>(layers: &'a [cyberdeck_packet::Layer], label: &str) -> Option<&'a str> {
    layers
        .iter()
        .find(|layer| layer.label == label)
        .map(|layer| layer.value.as_str())
}

fn option_kind(label: &str) -> Option<u8> {
    // Wire kind codes for the option-order evidence; each decoded layer maps
    // to its real TCP option kind (SACK permission 4 vs SACK blocks 5).
    match label {
        "TCP maximum segment size" => Some(OPTION_KIND_MSS),
        "TCP window scale" => Some(OPTION_KIND_WINDOW_SCALE),
        "TCP SACK permitted" => Some(OPTION_KIND_SACK_PERMITTED),
        "TCP selective ACK blocks" => Some(OPTION_KIND_SACK_BLOCKS),
        "TCP timestamps" => Some(OPTION_KIND_TIMESTAMPS),
        _ => None,
    }
}

/// Build a signature strictly from existing dissection layers. Returns None
/// when the packet carries no TTL layer (IPv6 hop limits are NOT borrowed as
/// a fake TTL: the classifier's breakpoints are IPv4 initial-TTL defaults).
/// The DF bit is never parsed from raw bytes here because the shared network
/// dissection does not emit it as a layer this arc — absent evidence stays
/// absent and the classifier reports "DF not visible" instead of guessing.
pub(crate) fn signature_from(
    layers: &[cyberdeck_packet::Layer],
    flags: u8,
) -> Option<StackSignature> {
    let ttl = text_of(layers, "ttl")?.parse::<u8>().ok()?;
    let window = text_of(layers, "TCP receive window (raw)")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let mss = text_of(layers, "TCP maximum segment size")
        .and_then(|value| value.parse::<u16>().ok());
    let window_scale = text_of(layers, "TCP window scale")
        .and_then(|value| value.parse::<u8>().ok());
    // Option order: TCP option layers precede the transport summary layer in
    // the dissection output, so the walk stops at the first transport layer.
    let mut option_order = Vec::new();
    for layer in layers {
        if layer.label == "Transmission Control Protocol" {
            break;
        }
        if let Some(kind) = option_kind(&layer.label) {
            if option_order.last() != Some(&kind) && option_order.len() < MAX_OPTION_ORDER {
                option_order.push(kind);
            }
        }
    }
    Some(StackSignature {
        ttl,
        ipv4_df: None,
        window,
        mss,
        window_scale,
        option_order,
        syn_ack: flags & 0x02 != 0 && flags & 0x10 != 0,
    })
}

/// Passive OS-family hints for TCP SYN/SYN-ACK segments in the opened capture.
/// Read-only over the capture cache; nothing is transmitted and nothing here
/// is affirmative evidence — every hint carries low or very-low confidence
/// with its evidence basis by design. `sampled` counts every qualifying
/// handshake segment even when the response is capped, so truncation is
/// always visible to the caller.
pub(crate) fn classify_capture(
    packets: &[cyberdeck_packet::PacketMeta],
) -> (Vec<OsHintObservationWire>, usize) {
    let mut hints = Vec::new();
    let mut sampled = 0usize;
    for packet in packets {
        let Some(tcp) = packet.dissected.tcp.as_ref() else {
            continue;
        };
        // Both handshake directions carry stack evidence; plain ACKs and
        // data segments are skipped (their windows reflect flow control,
        // not stack defaults).
        if tcp.flags & 0x02 == 0 {
            continue;
        }
        sampled += 1;
        if hints.len() >= MAX_OS_HINTS {
            continue;
        }
        let Some(signature) = signature_from(&packet.dissected.layers, tcp.flags) else {
            continue;
        };
        hints.push(OsHintObservationWire {
            source: packet.dissected.source.clone(),
            destination: packet.dissected.destination.clone(),
            syn_ack: signature.syn_ack,
            hint: classify(&signature).into(),
        });
    }
    (hints, sampled)
}

#[tauri::command]
pub fn capture_os_hints_v1(ctx: State<'_, PcapCtx>) -> Result<OsHintsWire, String> {
    let guard = ctx
        .current
        .lock()
        .map_err(|_| "capture cache unavailable".to_string())?;
    let capture = guard.as_ref().ok_or("no capture is open")?;
    let (hints, sampled) = classify_capture(&capture.packets);
    Ok(OsHintsWire {
        hints,
        sampled,
        cap: MAX_OS_HINTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_packet::{Dissected, Layer, PacketMeta, TcpMeta};

    fn layers() -> Vec<Layer> {
        vec![
            Layer { label: "Internet Protocol Version 4".into(), value: "10.0.0.1 → 10.0.0.2".into() },
            Layer { label: "ttl".into(), value: "64".into() },
            Layer { label: "TCP maximum segment size".into(), value: "1460".into() },
            Layer { label: "TCP window scale".into(), value: "7".into() },
            Layer { label: "TCP SACK permitted".into(), value: "yes".into() },
            Layer { label: "Transmission Control Protocol".into(), value: "syn".into() },
            Layer { label: "TCP receive window (raw)".into(), value: "64240".into() },
        ]
    }

    fn tcp_meta(flags: u8) -> TcpMeta {
        TcpMeta {
            source_port: 40000,
            destination_port: 443,
            sequence: 1,
            flags,
        }
    }

    fn dissected(layers: Vec<Layer>, flags: u8) -> Dissected {
        Dissected {
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            protocol: "TCP".into(),
            info: "syn".into(),
            color_hint: "tcp".into(),
            layers,
            stream_id: None,
            tcp: Some(tcp_meta(flags)),
            payload: Vec::new(),
        }
    }

    #[test]
    fn signature_builds_from_existing_dissection_layers() {
        let signature = signature_from(&layers(), 0x02).expect("signature");
        assert_eq!(signature.ttl, 64);
        assert_eq!(signature.window, 64240);
        assert_eq!(signature.mss, Some(1460));
        assert_eq!(signature.window_scale, Some(7));
        assert_eq!(signature.option_order, vec![2, 3, 4]);
        assert!(!signature.syn_ack);
        assert_eq!(signature.ipv4_df, None);
        // 64240 (0xFAF0) is a documented Linux client-SYN window shape.
        let hint = classify(&signature);
        assert_eq!(hint.family, "linux");
        assert_eq!(hint.confidence, "low");
    }

    #[test]
    fn syn_ack_flag_comes_from_tcp_flags() {
        let signature = signature_from(&layers(), 0x12).expect("signature");
        assert!(signature.syn_ack);
        // A bare ACK flag without SYN is not a handshake segment.
        let signature = signature_from(&layers(), 0x10).expect("signature");
        assert!(!signature.syn_ack);
    }

    #[test]
    fn ipv6_segments_without_ttl_layer_are_skipped() {
        let mut ipv6 = layers();
        ipv6[1].label = "hop limit".into();
        assert!(signature_from(&ipv6, 0x02).is_none());
    }

    #[test]
    fn malformed_layer_values_fail_closed_to_absent() {
        let mut bad = layers();
        bad[2].value = "not-a-number".into();
        let signature = signature_from(&bad, 0x02).expect("signature");
        assert_eq!(signature.mss, None);
        let mut bad_window = layers();
        bad_window[6].value = "".into();
        let signature = signature_from(&bad_window, 0x02).expect("signature");
        assert_eq!(signature.window, 0);
    }

    #[test]
    fn classify_capture_counts_sampled_and_caps_hints() {
        let mut packets = Vec::new();
        for _ in 0..(MAX_OS_HINTS + 12) {
            packets.push(PacketMeta {
                offset: 0,
                incl_len: 0,
                orig_len: 0,
                ts_sec: 0,
                ts_subsec: 0,
                dissected: dissected(layers(), 0x02),
            });
        }
        // Non-handshake and non-TCP packets are skipped entirely.
        packets.push(PacketMeta {
            offset: 0,
            incl_len: 0,
            orig_len: 0,
            ts_sec: 0,
            ts_subsec: 0,
            dissected: dissected(layers(), 0x10),
        });
        let (hints, sampled) = classify_capture(&packets);
        assert_eq!(hints.len(), MAX_OS_HINTS);
        assert_eq!(sampled, MAX_OS_HINTS + 12);
        for hint in &hints {
            assert!(!hint.hint.evidence.is_empty());
            // Every wire row carries the standing low-confidence disclaimer.
            assert!(hint
                .hint
                .evidence
                .last()
                .is_some_and(|e| e.contains("never a verdict")));
            assert!(matches!(hint.hint.confidence.as_str(), "low" | "very_low"));
        }
    }

    #[test]
    fn wire_projection_maps_all_fields() {
        let hint = OsHint {
            family: "linux".into(),
            confidence: "low".into(),
            evidence: vec!["ttl 64".into()],
        };
        let wire: OsHintWire = hint.into();
        assert_eq!(wire.family, "linux");
        assert_eq!(wire.evidence.len(), 1);
    }
}

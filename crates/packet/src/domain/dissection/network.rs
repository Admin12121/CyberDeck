//! Bounded IPv4/IPv6 network headers, extension handling and transport dispatch.
use super::link::{color_for, empty_frame, ipv4_to_string};
use super::transport::{dissect_tcp, dissect_udp};
use crate::{Dissected, Layer};

pub(super) fn dissect_ipv4(payload: &[u8], parent_layers: &[Layer]) -> Dissected {
    // An Ethernet/SLL ethertype is not proof that the IP header version matches.
    // Do not interpret version-mismatched bytes as valid transport traffic.
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return empty_frame();
    }
    let ihl = (payload[0] & 0x0f) as usize * 4;
    if ihl < 20 || payload.len() < ihl {
        return empty_frame();
    }
    let total_length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let ttl = payload[8];
    let proto = payload[9];
    let source = ipv4_to_string(&payload[12..16]);
    let destination = ipv4_to_string(&payload[16..20]);
    let mut layers = parent_layers.to_vec();
    layers.push(Layer {
        label: "Internet Protocol Version 4".to_string(),
        value: format!("{source} → {destination}"),
    });
    layers.push(Layer {
        label: "ttl".to_string(),
        value: ttl.to_string(),
    });
    layers.push(Layer {
        label: "total length".to_string(),
        value: total_length.to_string(),
    });

    if total_length < ihl {
        return empty_frame();
    }
    // Snapshot-length truncation is not IP fragmentation. A partial TCP
    // payload must not become part of a supposedly reconstructed stream.
    if total_length > payload.len() {
        return Dissected {
            source,
            destination,
            protocol: "IPv4-truncated".into(),
            info: format!("Captured {} of {total_length} IPv4 byte(s)", payload.len()),
            color_hint: color_for("other"),
            layers,
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        };
    }
    let effective_end = total_length;
    let transport = &payload[ihl..effective_end];
    let fragment_bits = u16::from_be_bytes([payload[6], payload[7]]);
    let fragment_offset = (fragment_bits & 0x1fff) as usize * 8;
    let more_fragments = fragment_bits & 0x2000 != 0;
    if fragment_offset != 0 || more_fragments {
        return Dissected {
            source,
            destination,
            protocol: "IPv4-fragment".into(),
            info: format!("IPv4 fragment offset {fragment_offset}, more={more_fragments}"),
            color_hint: color_for("other"),
            layers,
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        };
    }
    match proto {
        6 => dissect_tcp(
            transport,
            &source,
            &destination,
            total_length.saturating_sub(ihl),
            layers,
        ),
        17 => dissect_udp(transport, &source, &destination, layers),
        1 => {
            let dissected = super::icmp::dissect_icmpv4(transport, layers);
            Dissected {
                source,
                destination,
                ..dissected
            }
        }
        other => {
            let info = format!("IP protocol {other}, {} bytes", transport.len());
            Dissected {
                source,
                destination,
                protocol: format!("IP-{other}"),
                info,
                color_hint: color_for("other"),
                layers,
                stream_id: None,
                tcp: None,
                payload: transport.to_vec(),
            }
        }
    }
}

/// IPv6 headers are walked with a strict bound on extension count and bytes.
/// Fragment reassembly and jumbograms are not supported: never attempt to
/// decode a noninitial fragment as an ordinary TCP/UDP header.
pub(super) fn dissect_ipv6(payload: &[u8], parent_layers: &[Layer]) -> Dissected {
    if payload.len() < 40 || payload[0] >> 4 != 6 {
        return empty_frame();
    }
    let source = format_ipv6(&payload[8..24]);
    let destination = format_ipv6(&payload[24..40]);
    let mut next = payload[6];
    let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let mut layers = parent_layers.to_vec();
    layers.push(Layer {
        label: "Internet Protocol Version 6".to_string(),
        value: format!("{source} → {destination}"),
    });
    // A zero payload length with bytes after the IPv6 header may be a
    // jumbogram. Do not guess its upper-layer bounds or transport protocol.
    if payload_len == 0 && payload.len() > 40 {
        return Dissected {
            source,
            destination,
            protocol: "IPv6".into(),
            info: "IPv6 jumbogram or unspecified payload length (not decoded)".into(),
            color_hint: color_for("IPv6"),
            layers,
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        };
    }
    let Some(end) = 40usize.checked_add(payload_len) else {
        return empty_frame();
    };
    if end > payload.len() {
        return Dissected {
            source,
            destination,
            protocol: "IPv6-truncated".into(),
            info: format!("Captured {} of {end} IPv6 byte(s)", payload.len()),
            color_hint: color_for("IPv6"),
            layers,
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        };
    }
    let mut cursor = 40usize;
    for _ in 0..8 {
        let extension = next;
        match extension {
            0 | 43 | 60 => {
                let Some(header) = payload.get(cursor..cursor.saturating_add(2)) else {
                    return empty_frame();
                };
                let header_len = (header[1] as usize + 1) * 8;
                if cursor.checked_add(header_len).is_none_or(|e| e > end) {
                    return empty_frame();
                }
                next = header[0];
                cursor += header_len;
            }
            51 => {
                let Some(header) = payload.get(cursor..cursor.saturating_add(2)) else {
                    return empty_frame();
                };
                let header_len = (header[1] as usize + 2) * 4;
                if cursor.checked_add(header_len).is_none_or(|e| e > end) {
                    return empty_frame();
                }
                next = header[0];
                cursor += header_len;
            }
            44 => {
                let Some(fragment) = payload.get(cursor..cursor.saturating_add(8)) else {
                    return empty_frame();
                };
                if cursor + 8 > end {
                    return empty_frame();
                }
                let raw = u16::from_be_bytes([fragment[2], fragment[3]]);
                let offset = (raw & 0xfff8) as usize;
                layers.push(Layer {
                    label: "IPv6 fragment".into(),
                    value: format!("offset {offset} byte(s), more={}", raw & 1 == 1),
                });
                if offset != 0 || raw & 1 != 0 {
                    return Dissected {
                        source,
                        destination,
                        protocol: "IPv6-fragment".into(),
                        info: format!("IPv6 fragment offset {offset}, more={}", raw & 1 != 0),
                        color_hint: color_for("IPv6"),
                        layers,
                        stream_id: None,
                        tcp: None,
                        payload: Vec::new(),
                    };
                }
                next = fragment[0];
                cursor += 8;
            }
            _ => break,
        }
    }
    // A chain with more than eight extensions is deliberately not decoded.
    if matches!(next, 0 | 43 | 44 | 51 | 60) {
        return empty_frame();
    }
    let Some(transport) = payload.get(cursor..end) else {
        return empty_frame();
    };
    match next {
        6 => dissect_tcp(transport, &source, &destination, transport.len(), layers),
        17 => dissect_udp(transport, &source, &destination, layers),
        58 => {
            let dissected = super::icmp::dissect_icmpv6(transport, layers);
            Dissected {
                source,
                destination,
                ..dissected
            }
        }
        other => Dissected {
            source,
            destination,
            protocol: format!("IPv6-{other}"),
            info: format!("next header {other}"),
            color_hint: color_for("IPv6"),
            layers,
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        },
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    let Some(addr) = <[u8; 16]>::try_from(bytes).ok() else {
        return String::new();
    };
    std::net::Ipv6Addr::from(addr).to_string()
}

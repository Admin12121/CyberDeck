//! Bounded TCP and UDP metadata, payload and passive application hints.
use super::link::{color_for, empty_frame};
use super::{http2, quic};
use super::protocol;
use super::protocol::HttpFields;
use crate::{dns, Dissected, Layer, TcpMeta};

fn well_known_name(proto: u8, src_port: u16, dst_port: u16) -> &'static str {
    for port in [dst_port, src_port] {
        match (proto, port) {
            (17, 53) => return "DNS",
            (17, 67) | (17, 68) => return "DHCP",
            (17, 123) => return "NTP",
            (6, 80) | (6, 8080) => return "HTTP",
            (6, 443) => return "TLS",
            (6, 22) => return "SSH",
            (6, 25) => return "SMTP",
            _ => {}
        }
    }
    ""
}

pub(super) fn dissect_tcp(
    transport: &[u8],
    source: &str,
    destination: &str,
    ip_payload_len: usize,
    mut layers: Vec<Layer>,
) -> Dissected {
    if transport.len() < 20 {
        return empty_frame();
    }
    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    let seq = u32::from_be_bytes([transport[4], transport[5], transport[6], transport[7]]);
    let data_offset = (transport[12] >> 4) as usize * 4;
    if data_offset < 20 || data_offset > transport.len() {
        return empty_frame();
    }
    let flags_byte = transport[13];
    let mut flags = String::new();
    for (mask, name) in [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ] {
        if flags_byte & mask != 0 {
            if !flags.is_empty() {
                flags.push_str(", ");
            }
            flags.push_str(name);
        }
    }
    if transport[12] & 0x01 != 0 {
        if !flags.is_empty() {
            flags.push_str(", ");
        }
        flags.push_str("NS");
    }
    let ack = u32::from_be_bytes([transport[8], transport[9], transport[10], transport[11]]);
    let window = u16::from_be_bytes([transport[14], transport[15]]);
    let checksum = u16::from_be_bytes([transport[16], transport[17]]);
    let urgent = u16::from_be_bytes([transport[18], transport[19]]);
    let payload_len = ip_payload_len
        .saturating_sub(data_offset)
        .min(transport.len().saturating_sub(data_offset));
    let info = format!("{src_port} → {dst_port} [{flags}] Seq={seq} Len={payload_len}");
    let service = well_known_name(6, src_port, dst_port);
    let protocol = if service.is_empty() { "TCP" } else { service };
    let payload_end = (data_offset + payload_len).min(transport.len());
    let payload = transport
        .get(data_offset..payload_end)
        .unwrap_or(&[])
        .to_vec();
    let mut endpoints = [
        format!("{source}:{src_port}"),
        format!("{destination}:{dst_port}"),
    ];
    endpoints.sort();
    let stream_id = Some(format!("tcp|{}|{}", endpoints[0], endpoints[1]));
    // Passive application parsing looks only at bytes in the captured frame.
    // A split TCP segment cannot be claimed as a complete HTTP/TLS message.
    if http2::is_http2_preface(&payload) {
        if let Some(dissected) = http2::dissect_http2(&payload, layers.clone()) {
            return Dissected {
                source: source.to_string(),
                destination: destination.to_string(),
                ..dissected
            };
        }
    }
    let http = protocol::http_start_line(&payload);
    let tls = protocol::tls_hello(&payload);
    let protocol = if http.is_some() {
        "HTTP"
    } else if tls.is_some() {
        "TLS"
    } else {
        protocol
    };
    if let Some(line) = &http {
        layers.push(Layer {
            label: "HTTP/1.x start line".into(),
            value: line.clone(),
        });
        // Header fields come from the same captured segment as the start
        // line; a segment boundary ends extraction without inventing data.
        if let Some(fields) = protocol::http_fields(&payload) {
            let HttpFields { host, user_agent, status_code, content_type, location } = fields;
            if let Some(host) = host {
                layers.push(Layer { label: "HTTP Host".into(), value: host });
            }
            if let Some(agent) = user_agent {
                layers.push(Layer { label: "HTTP User-Agent".into(), value: agent });
            }
            if let Some(code) = status_code {
                layers.push(Layer { label: "HTTP status".into(), value: code.to_string() });
            }
            if let Some(kind) = content_type {
                layers.push(Layer { label: "HTTP Content-Type".into(), value: kind });
            }
            if let Some(target) = location {
                layers.push(Layer { label: "HTTP Location".into(), value: target });
            }
        }
    }
    if let Some(hello) = &tls {
        layers.push(Layer {
            label: "TLS handshake".into(),
            value: protocol::tls_description(hello),
        });
        if let Some(host) = &hello.sni {
            layers.push(Layer {
                label: "TLS Server Name Indication".into(),
                value: host.clone(),
            });
        }
        if !hello.alpn.is_empty() {
            layers.push(Layer {
                label: "TLS ALPN".into(),
                value: hello.alpn.join(", "),
            });
        }
    }
    let info = if let Some(line) = http {
        format!("{src_port} → {dst_port} {line}")
    } else if let Some(hello) = tls {
        format!(
            "{src_port} → {dst_port} {}",
            protocol::tls_description(&hello)
        )
    } else {
        info
    };
    let color = color_for(protocol);
    if data_offset > 20 {
        // TCP options are within the header, not the application payload.
        // Decode only complete, bounded TLVs; report malformed claims
        // without discarding original frame evidence.
        match super::tcp_options::decode(&transport[20..data_offset]) {
            Ok(fields) => layers.extend(fields),
            Err(reason) => layers.push(Layer {
                label: "TCP option warning".into(),
                value: format!("Malformed TCP options: {reason}"),
            }),
        }
    }
    layers.push(Layer {
        label: "Transmission Control Protocol".to_string(),
        value: info.clone(),
    });
    layers.push(Layer {
        label: "source port".to_string(),
        value: src_port.to_string(),
    });
    layers.push(Layer {
        label: "destination port".to_string(),
        value: dst_port.to_string(),
    });
    layers.push(Layer {
        label: "flags".to_string(),
        value: flags,
    });
    layers.push(Layer {
        label: "TCP acknowledgment number".into(),
        value: ack.to_string(),
    });
    layers.push(Layer {
        label: "TCP receive window (raw)".into(),
        value: window.to_string(),
    });
    layers.push(Layer {
        label: "TCP header length".into(),
        value: format!("{data_offset} byte(s)"),
    });
    layers.push(Layer {
        label: "TCP checksum (not independently verified)".into(),
        value: format!("0x{checksum:04x}"),
    });
    if transport[13] & 0x20 != 0 {
        layers.push(Layer {
            label: "TCP urgent pointer".into(),
            value: urgent.to_string(),
        });
    }
    Dissected {
        source: source.to_string(),
        destination: destination.to_string(),
        protocol: protocol.to_string(),
        info,
        color_hint: color,
        layers,
        stream_id,
        tcp: Some(TcpMeta {
            source_port: src_port,
            destination_port: dst_port,
            sequence: seq,
            flags: flags_byte,
        }),
        payload,
    }
}

pub(super) fn dissect_udp(
    transport: &[u8],
    source: &str,
    destination: &str,
    mut layers: Vec<Layer>,
) -> Dissected {
    if transport.len() < 8 {
        return empty_frame();
    }
    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    // QUIC rides on UDP/443; the bounded header dissector replaces the
    // plain-UDP projection when the payload carries a QUIC shape.
    if (src_port == 443 || dst_port == 443) && transport.len() > 8 {
        let dissected = quic::dissect_quic(&transport[8..], layers);
        return Dissected {
            source: source.to_string(),
            destination: destination.to_string(),
            ..dissected
        };
    }
    let length = u16::from_be_bytes([transport[4], transport[5]]);
    if length < 8 {
        return empty_frame();
    }
    // A full IP datagram cannot carry fewer bytes than its UDP length.
    // Do not promote a partial UDP payload to a usable stream.
    if length as usize > transport.len() {
        let info = format!(
            "UDP length {} exceeds {} available IP payload byte(s)",
            length,
            transport.len()
        );
        layers.push(Layer {
            label: "User Datagram Protocol".into(),
            value: info.clone(),
        });
        return Dissected {
            source: source.to_string(),
            destination: destination.to_string(),
            protocol: "UDP-truncated".into(),
            info,
            color_hint: color_for("other"),
            layers,
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        };
    }
    let end = length as usize;
    let payload = transport.get(8..end).unwrap_or(&[]).to_vec();
    let mut endpoints = [
        format!("{source}:{src_port}"),
        format!("{destination}:{dst_port}"),
    ];
    endpoints.sort();
    let stream_id = Some(format!("udp|{}|{}", endpoints[0], endpoints[1]));
    let service = well_known_name(17, src_port, dst_port);
    let protocol = if service.is_empty() { "UDP" } else { service };
    let mut info = format!("{src_port} → {dst_port} Len={}", length.saturating_sub(8));
    let decoded_service = if matches!(src_port, 67 | 68) || matches!(dst_port, 67 | 68) {
        super::udp_services::dhcp(&payload)
    } else if src_port == 123 || dst_port == 123 {
        super::udp_services::ntp(&payload)
    } else if matches!(src_port, 3478 | 3479 | 5349) || matches!(dst_port, 3478 | 3479 | 5349) {
        super::udp_services::stun(&payload)
    } else if (src_port == 5353 || dst_port == 5353) && src_port != 53 && dst_port != 53 {
        super::udp_services::mdns(&payload)
    } else if (src_port == 5355 || dst_port == 5355) && src_port != 53 && dst_port != 53 {
        super::udp_services::llmnr(&payload)
    } else {
        None
    };
    // Port numbers alone are not proof of these application protocols.
    // An incomplete or malformed packet remains valid transport evidence.
    let protocol = if matches!(protocol, "DHCP" | "NTP") && decoded_service.is_none() {
        "UDP"
    } else if let Some(service) = &decoded_service {
        service.protocol
    } else {
        protocol
    };
    if let Some(service) = decoded_service {
        info = service.info;
        layers.extend(service.layers);
    }
    if protocol == "DNS" {
        if let Some(summary) = dns::parse_dns(&payload) {
            info = dns::describe_dns(&summary);
            layers.push(Layer {
                label: "Domain Name System".into(),
                value: info.clone(),
            });
            for (index, answer) in summary.answer_records.iter().enumerate() {
                layers.push(Layer {
                    label: format!("DNS answer {}", index + 1),
                    value: format!(
                        "{} {} = {} (TTL {}s)",
                        answer.name,
                        dns::record_type_label(answer.record_type),
                        answer.value,
                        answer.ttl_seconds,
                    ),
                });
            }
        } else {
            info = "DNS query/response (incomplete or malformed header)".into();
        }
    }
    layers.push(Layer {
        label: "User Datagram Protocol".to_string(),
        value: info.clone(),
    });
    layers.push(Layer {
        label: "source port".to_string(),
        value: src_port.to_string(),
    });
    layers.push(Layer {
        label: "destination port".to_string(),
        value: dst_port.to_string(),
    });
    Dissected {
        source: source.to_string(),
        destination: destination.to_string(),
        protocol: protocol.to_string(),
        info,
        color_hint: color_for(protocol),
        layers,
        stream_id,
        tcp: None,
        payload,
    }
}

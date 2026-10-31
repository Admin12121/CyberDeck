//! Bounded TCP and UDP metadata, payload and passive application hints.
use super::link::{color_for, empty_frame};
use super::protocol;
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
    ] {
        if flags_byte & mask != 0 {
            if !flags.is_empty() {
                flags.push_str(", ");
            }
            flags.push_str(name);
        }
    }
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

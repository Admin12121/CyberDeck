//! Bounded TCP and UDP metadata, payload and passive application hints.
use super::link::{color_for, empty_frame};
use super::protocol;
use super::protocol::HttpFields;
use super::{http2, quic, smb};
use crate::{dns, Dissected, Layer, TcpMeta};

fn well_known_name(proto: u8, src_port: u16, dst_port: u16) -> &'static str {
    for port in [dst_port, src_port] {
        match (proto, port) {
            (17, 53) => return "DNS",
            (17, 67) | (17, 68) => return "DHCP",
            (17, 123) => return "NTP",
            (6, 80) | (6, 8080) => return "HTTP",
            (6, 443) => return "TLS",
            (6, 445) => return "SMB",
            (6, 139) => return "NetBIOS",
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
    // SMB (TCP 445/139) claims only what the HTTP and TLS checks declined;
    // the ordering is pinned by the transport tests below.
    let app_protocol_claimed = http.is_some() || tls.is_some();
    let mut protocol = if http.is_some() {
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
            let HttpFields {
                host,
                user_agent,
                status_code,
                content_type,
                location,
            } = fields;
            if let Some(host) = host {
                layers.push(Layer {
                    label: "HTTP Host".into(),
                    value: host,
                });
            }
            if let Some(agent) = user_agent {
                layers.push(Layer {
                    label: "HTTP User-Agent".into(),
                    value: agent,
                });
            }
            if let Some(code) = status_code {
                layers.push(Layer {
                    label: "HTTP status".into(),
                    value: code.to_string(),
                });
            }
            if let Some(kind) = content_type {
                layers.push(Layer {
                    label: "HTTP Content-Type".into(),
                    value: kind,
                });
            }
            if let Some(target) = location {
                layers.push(Layer {
                    label: "HTTP Location".into(),
                    value: target,
                });
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
    let mut info = if let Some(line) = http {
        format!("{src_port} → {dst_port} {line}")
    } else if let Some(hello) = tls {
        format!(
            "{src_port} → {dst_port} {}",
            protocol::tls_description(&hello)
        )
    } else {
        info
    };
    let mut color = color_for(protocol);
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
    // SMB file sharing rides on TCP 445/139 behind NetBIOS session framing.
    // The HTTP and TLS checks above claim their payloads first; SMB only
    // claims what they decline, and a payload without SMB evidence keeps
    // the plain transport row — service-named by port, like TLS on 443.
    if !app_protocol_claimed
        && (matches!(src_port, 445 | 139) || matches!(dst_port, 445 | 139))
    {
        if let Some(service) = smb::dissect(&payload) {
            protocol = service.protocol;
            info = service.info;
            color = color_for(protocol);
            layers.extend(service.layers);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_with_payload(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&49812u16.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[12] = 0x50; // data offset 5
        t[13] = 0x18; // PSH|ACK
        t.extend_from_slice(payload);
        t
    }

    fn dissect_port_445(payload: &[u8]) -> Dissected {
        let frame = tcp_with_payload(445, payload);
        dissect_tcp(&frame, "10.0.0.1", "10.0.0.2", frame.len(), Vec::new())
    }

    /// NBSS-wrapped SMB2 negotiate request: one dialect, array form with
    /// the invariants the dissector requires (offset 64+36, len count*2).
    fn nbss_smb2_negotiate() -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(b"\xfeSMB");
        inner.extend_from_slice(&64u16.to_le_bytes()); // structure size
        inner.extend_from_slice(&[0u8; 58]); // command 0 (negotiate) + rest
        let mut body = vec![0u8; 36];
        body[0..2].copy_from_slice(&37u16.to_le_bytes());
        body[30..32].copy_from_slice(&1u16.to_le_bytes()); // dialect count
        body[32..34].copy_from_slice(&100u16.to_le_bytes()); // offset
        body[34..36].copy_from_slice(&2u16.to_le_bytes()); // length
        inner.extend_from_slice(&body);
        inner.extend_from_slice(&0x0311u16.to_le_bytes());
        let mut out = vec![0u8, 0];
        out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        out.extend_from_slice(&inner);
        out
    }

    fn tls_client_hello() -> Vec<u8> {
        let mut hello = vec![3u8, 3];
        hello.extend([7u8; 32]);
        hello.push(0); // empty session id
        hello.extend([0u8, 2, 0x13, 0x01]); // one cipher suite
        hello.extend([1u8, 0]); // one compression method
        let mut handshake = vec![1u8, 0, 0, hello.len() as u8];
        handshake.extend_from_slice(&hello);
        let mut record = vec![22u8, 3, 3];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn smb_claims_port_445_after_http_and_tls_decline() {
        let d = dissect_port_445(&nbss_smb2_negotiate());
        assert_eq!(d.protocol, "SMB");
        assert_eq!(d.info, "SMB2 negotiate, 1 dialect(s) offered");
        // TCP evidence layers stay in front of the SMB layers so the
        // protocol hierarchy counts ip → tcp → smb like any TCP row.
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "Transmission Control Protocol"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "NetBIOS session" && l.value.contains("session message")));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "command" && l.value == "negotiate"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "dialects offered" && l.value.contains("SMB 3.1.1")));
    }

    #[test]
    fn tls_and_http_claims_win_over_smb_on_port_445() {
        let tls = dissect_port_445(&tls_client_hello());
        assert_eq!(tls.protocol, "TLS");
        assert!(tls.info.contains("TLS ClientHello"));
        assert!(!tls.layers.iter().any(|l| l.label == "command"));

        let http = dissect_port_445(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(http.protocol, "HTTP");
        assert!(!http.layers.iter().any(|l| l.label == "command"));
    }

    #[test]
    fn unrelated_payload_on_445_keeps_the_transport_row() {
        let d = dissect_port_445(b"plain bytes, not smb");
        // The port names the service (like TLS on 443), the original TCP
        // info survives, and no SMB layers are invented.
        assert_eq!(d.protocol, "SMB");
        assert!(d.info.contains("49812 → 445"));
        assert!(d
            .layers
            .iter()
            .any(|l| l.label == "Transmission Control Protocol"));
        assert!(!d.layers.iter().any(|l| l.label == "command"));
    }

    #[test]
    fn port_139_smb_claims_and_netbios_fallback() {
        let frame = tcp_with_payload(139, &nbss_smb2_negotiate());
        let d = dissect_tcp(&frame, "10.0.0.1", "10.0.0.2", frame.len(), Vec::new());
        assert_eq!(d.protocol, "SMB");
        assert!(d.info.contains("SMB2 negotiate"));

        // A NetBIOS session request on 139 is a NetBIOS row, not SMB.
        let frame = tcp_with_payload(139, &[0x81, 0, 0, 6, b'a', b'b', b'c', b'd', b'e', b'f']);
        let d = dissect_tcp(&frame, "10.0.0.1", "10.0.0.2", frame.len(), Vec::new());
        assert_eq!(d.protocol, "NetBIOS");
        assert!(d.info.contains("session request"));
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
    // QUIC rides on UDP/443; the bounded header dissector replaces the
    // plain-UDP projection. Dispatch after the UDP length checks so the
    // dissector only ever sees the declared datagram payload — never
    // Ethernet padding or bytes beyond the length field — and keep the
    // UDP evidence layers in front of the QUIC layers like DNS/STUN rows.
    if src_port == 443 || dst_port == 443 {
        layers.push(Layer {
            label: "User Datagram Protocol".into(),
            value: info.clone(),
        });
        layers.push(Layer {
            label: "source port".into(),
            value: src_port.to_string(),
        });
        layers.push(Layer {
            label: "destination port".into(),
            value: dst_port.to_string(),
        });
        let dissected = quic::dissect_quic(&payload, layers);
        return Dissected {
            source: source.to_string(),
            destination: destination.to_string(),
            ..dissected
        };
    }
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

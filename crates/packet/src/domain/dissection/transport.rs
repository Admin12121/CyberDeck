//! Bounded TCP and UDP metadata, payload and passive application hints.
use super::link::{color_for, empty_frame};
use super::protocol;
use super::protocol::HttpFields;
use super::{http2, mqtt, quic, rdp, smb, socks};
use crate::{dns, Dissected, Layer, TcpMeta};

fn well_known_name(proto: u8, src_port: u16, dst_port: u16) -> &'static str {
    for port in [dst_port, src_port] {
        match (proto, port) {
            (17, 53) => return "DNS",
            (17, 67) | (17, 68) => return "DHCP",
            (17, 123) => return "NTP",
            (17, 546) | (17, 547) => return "DHCPv6",
            (6, 80) | (6, 8080) => return "HTTP",
            (6, 443) => return "TLS",
            (6, 445) => return "SMB",
            (6, 139) => return "NetBIOS",
            (6, 1883) | (6, 8883) => return "MQTT",
            (6, 1080) => return "SOCKS",
            (6, 3389) => return "RDP",
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
    let claimed_by_tls = tls.is_some();
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
    // MQTT (TCP 1883) joins after the HTTP/TLS/SMB claims: a payload with
    // MQTT fixed-header marker evidence claims an MQTT row, anything else
    // keeps the port-named transport row — the port alone is not MQTT
    // evidence.
    if !app_protocol_claimed && (src_port == 1883 || dst_port == 1883) {
        if let Some(service) = mqtt::dissect(&payload) {
            protocol = service.protocol;
            info = service.info;
            color = color_for(protocol);
            layers.extend(service.layers);
        }
    }
    // MQTT on 8883 is TLS-wrapped: when the TLS check above claims the
    // payload, the row surfaces only the honest hand-off note — encrypted
    // MQTT bytes are never dissected, and without a TLS claim the row
    // stays the port-named transport row.
    if claimed_by_tls && (src_port == 8883 || dst_port == 8883) {
        layers.push(Layer {
            label: "MQTT over TLS".into(),
            value: "TLS claims the payload (encrypted MQTT not decoded)".into(),
        });
    }
    // SOCKS (TCP 1080): version/shape-gated rows after the HTTP/TLS/SMB
    // claims; the port side dictates which message direction may claim,
    // and a payload with no valid shape keeps the port-named row.
    if !app_protocol_claimed && (src_port == 1080 || dst_port == 1080) {
        if let Some(service) = socks::dissect(&payload, dst_port == 1080) {
            protocol = service.protocol;
            info = service.info;
            color = color_for(protocol);
            layers.extend(service.layers);
        }
    }
    // RDP (TCP 3389): TPKT + X.224 marker-gated rows after the HTTP/TLS/
    // SMB claims; session bytes beyond negotiation stay "not decoded".
    if !app_protocol_claimed && (src_port == 3389 || dst_port == 3389) {
        if let Some(service) = rdp::dissect(&payload, dst_port == 3389) {
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

    fn tcp_between(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&src_port.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[12] = 0x50; // data offset 5
        t[13] = 0x18; // PSH|ACK
        t.extend_from_slice(payload);
        t
    }

    fn dissect_ports(src_port: u16, dst_port: u16, payload: &[u8]) -> Dissected {
        let frame = tcp_between(src_port, dst_port, payload);
        dissect_tcp(&frame, "10.0.0.1", "10.0.0.2", frame.len(), Vec::new())
    }

    /// MQTT 3.1.1 CONNECT: protocol name "MQTT", level 4, clean session,
    /// keepalive 60, client-id "dev".
    fn mqtt_connect() -> Vec<u8> {
        let mut body = vec![0u8, 4, b'M', b'Q', b'T', b'T', 4, 0x02];
        body.extend_from_slice(&60u16.to_be_bytes());
        body.extend_from_slice(&[0u8, 3, b'd', b'e', b'v']);
        let mut packet = vec![0x10u8, body.len() as u8];
        packet.extend_from_slice(&body);
        packet
    }

    fn mqtt_publish() -> Vec<u8> {
        let mut body = vec![0u8, 0x0b];
        body.extend_from_slice(b"sensor/temp");
        let mut packet = vec![0x33u8, body.len() as u8];
        packet.extend_from_slice(&body);
        packet
    }

    fn socks5_request() -> Vec<u8> {
        let mut request = vec![5u8, 1, 0, 1, 10, 0, 0, 1];
        request.extend_from_slice(&8080u16.to_be_bytes());
        request
    }

    fn rdp_cr() -> Vec<u8> {
        let mut frame = vec![3u8, 0];
        frame.extend_from_slice(&19u16.to_be_bytes());
        frame.push(0x0e); // length indicator
        frame.push(0xE0); // connection request
        frame.extend_from_slice(&[0, 0, 0, 0, 0]);
        frame.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]); // neg request
        frame.extend_from_slice(&3u32.to_le_bytes()); // SSL | HYBRID
        frame
    }

    fn rdp_cc() -> Vec<u8> {
        let mut frame = vec![3u8, 0];
        frame.extend_from_slice(&19u16.to_be_bytes());
        frame.push(0x0e);
        frame.push(0xD0); // connection confirm
        frame.extend_from_slice(&[0, 0, 0, 0, 0]);
        frame.extend_from_slice(&[0x02, 0x00, 0x08, 0x00]); // neg response
        frame.extend_from_slice(&2u32.to_le_bytes()); // HYBRID
        frame
    }

    fn udp_between(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 8];
        t[0..2].copy_from_slice(&src_port.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[4..6].copy_from_slice(&(payload.len() as u16 + 8).to_be_bytes());
        t.extend_from_slice(payload);
        t
    }

    fn dhcpv6_solicit() -> Vec<u8> {
        let mut datagram = vec![1u8, 0x01, 0x02, 0x03];
        datagram.extend_from_slice(&[0x00, 0x01, 0x00, 0x0c]);
        datagram.extend_from_slice(&[
            0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x00, 0x0e,
        ]);
        datagram
    }

    #[test]
    fn mqtt_claims_1883_after_http_and_tls_decline() {
        let connect = dissect_ports(49812, 1883, &mqtt_connect());
        assert_eq!(connect.protocol, "MQTT");
        assert_eq!(
            connect.info,
            "MQTT CONNECT, MQTT 3.1.1, keepalive 60s, client-id \"dev\""
        );
        // TCP evidence layers stay in front of the MQTT layers.
        assert!(connect
            .layers
            .iter()
            .any(|l| l.label == "Transmission Control Protocol"));
        assert!(connect
            .layers
            .iter()
            .any(|l| l.label == "client id" && l.value == "\"dev\""));

        let publish = dissect_ports(1883, 49812, &mqtt_publish());
        assert_eq!(publish.protocol, "MQTT");
        assert_eq!(
            publish.info,
            "MQTT PUBLISH, topic \"sensor/temp\", QoS 1, retained"
        );

        // Payload without MQTT marker evidence keeps the port-named
        // transport row, like TLS on 443 and SMB on 445.
        let plain = dissect_ports(49812, 1883, b"plain bytes, not mqtt");
        assert_eq!(plain.protocol, "MQTT");
        assert!(plain.info.contains("49812 → 1883"));
        assert!(plain
            .layers
            .iter()
            .any(|l| l.label == "Transmission Control Protocol"));
        assert!(!plain.layers.iter().any(|l| l.label == "MQTT packet"));
    }

    #[test]
    fn http_and_tls_claims_win_over_mqtt_markers() {
        let http = dissect_ports(1883, 49812, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(http.protocol, "HTTP");
        assert!(!http.layers.iter().any(|l| l.label == "MQTT packet"));

        let tls = dissect_ports(1883, 49812, &tls_client_hello());
        assert_eq!(tls.protocol, "TLS");
        assert!(!tls.layers.iter().any(|l| l.label == "MQTT packet"));
    }

    #[test]
    fn tls_claim_on_8883_surfaces_only_the_mqtt_handoff_note() {
        let tls = dissect_ports(49812, 8883, &tls_client_hello());
        assert_eq!(tls.protocol, "TLS");
        assert!(tls.info.contains("TLS ClientHello"));
        let note = tls
            .layers
            .iter()
            .find(|l| l.label == "MQTT over TLS")
            .unwrap();
        assert!(note.value.contains("TLS claims the payload"));
        assert!(!tls.layers.iter().any(|l| l.label == "MQTT packet"));

        // Without a TLS claim, 8883 stays the plain port-named transport
        // row — ciphertext is never dissected as MQTT.
        let cipher = dissect_ports(49812, 8883, &[0x17u8, 0x03, 0x03, 0x00, 0x10, 0xde, 0xad]);
        assert_eq!(cipher.protocol, "MQTT");
        assert!(cipher.info.contains("49812 → 8883"));
        assert!(!cipher.layers.iter().any(|l| l.label == "MQTT packet"));
        assert!(!cipher.layers.iter().any(|l| l.label == "MQTT over TLS"));

        // And the note never appears on 1883 TLS handshakes.
        let plain_tls = dissect_ports(49812, 1883, &tls_client_hello());
        assert_eq!(plain_tls.protocol, "TLS");
        assert!(!plain_tls.layers.iter().any(|l| l.label == "MQTT over TLS"));
    }

    #[test]
    fn socks5_claims_1080_and_garbage_keeps_the_port_named_row() {
        let request = dissect_ports(49812, 1080, &socks5_request());
        assert_eq!(request.protocol, "SOCKS");
        assert_eq!(request.info, "SOCKS5 CONNECT to 10.0.0.1:8080");
        assert!(request
            .layers
            .iter()
            .any(|l| l.label == "SOCKS5 target" && l.value == "10.0.0.1:8080"));

        // A reply shape answered on the proxy port is a server → client row.
        let reply = vec![5u8, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let reply = dissect_ports(1080, 49812, &reply);
        assert_eq!(reply.protocol, "SOCKS");
        assert!(reply.info.contains("SOCKS5 reply, succeeded"));

        // A SOCKS4 reply shape offered as a client request claims nothing
        // beyond the port-named transport row.
        let client_sent = dissect_ports(49812, 1080, &[0u8, 90, 0, 0, 0, 0, 0, 0]);
        assert_eq!(client_sent.protocol, "SOCKS");
        assert!(client_sent.info.contains("49812 → 1080"));
        assert!(!client_sent.layers.iter().any(|l| l.label == "SOCKS5"));
        assert!(!client_sent.layers.iter().any(|l| l.label == "SOCKS4"));
    }

    #[test]
    fn rdp_x224_rows_claim_3389_with_direction_gating() {
        let request = dissect_ports(49812, 3389, &rdp_cr());
        assert_eq!(request.protocol, "RDP");
        assert_eq!(
            request.info,
            "RDP connection request, requested SSL, HYBRID (CredSSP/NLA)"
        );
        assert!(request
            .layers
            .iter()
            .any(|l| l.label == "TPKT" && l.value.contains("version 3")));

        let confirm = dissect_ports(3389, 49812, &rdp_cc());
        assert_eq!(confirm.protocol, "RDP");
        assert_eq!(
            confirm.info,
            "RDP connection confirm, selected HYBRID (CredSSP/NLA)"
        );

        // A CR arriving on the server side claims nothing beyond the
        // port-named transport row.
        let wrong_side = dissect_ports(3389, 49812, &rdp_cr());
        assert_eq!(wrong_side.protocol, "RDP");
        assert!(wrong_side.info.contains("3389 → 49812"));
        assert!(!wrong_side
            .layers
            .iter()
            .any(|l| l.label == "RDP negotiation"));

        // Session data beyond negotiation is honestly not decoded.
        let mut data = vec![3u8, 0];
        data.extend_from_slice(&13u16.to_be_bytes());
        data.extend_from_slice(&[2u8, 0xF0, 0x80]);
        data.extend_from_slice(b"sessio");
        let session = dissect_ports(49812, 3389, &data);
        assert_eq!(session.protocol, "RDP");
        assert_eq!(session.info, "RDP session (NLA) — not decoded");
    }

    #[test]
    fn dhcpv6_joins_the_udp_dispatch_with_direction_from_ports() {
        // Client → server datagram claims the DHCPv6 row with the UDP
        // evidence layers in front, like DNS/QUIC rows.
        let client = dissect_udp(
            &udp_between(546, 547, &dhcpv6_solicit()),
            "fe80::1",
            "fe80::2",
            Vec::new(),
        );
        assert_eq!(client.protocol, "DHCPv6");
        assert_eq!(client.info, "DHCPv6 SOLICIT xid=0x010203");
        assert!(client
            .layers
            .iter()
            .any(|l| l.label == "User Datagram Protocol"));
        assert!(client
            .layers
            .iter()
            .any(|l| l.label == "DHCPv6 direction" && l.value.contains("client → server")));

        // Server → client datagram claims the server-side row.
        let mut advertise = vec![2u8, 0x04, 0x05, 0x06];
        advertise.extend_from_slice(&[0x00, 0x02, 0x00, 0x0c]);
        advertise.extend_from_slice(&[
            0x00, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x01, 0x00, 0x0e,
        ]);
        let server = dissect_udp(
            &udp_between(547, 546, &advertise),
            "fe80::2",
            "fe80::1",
            Vec::new(),
        );
        assert_eq!(server.protocol, "DHCPv6");
        assert!(server.info.contains("ADVERTISE"));

        // A SOLICIT on the server side and malformed payloads keep the
        // plain UDP row (port names are downgraded like DHCPv4).
        let wrong_side = dissect_udp(
            &udp_between(547, 546, &dhcpv6_solicit()),
            "fe80::2",
            "fe80::1",
            Vec::new(),
        );
        assert_eq!(wrong_side.protocol, "UDP");
        let garbage = dissect_udp(
            &udp_between(546, 547, b"not dhcpv6"),
            "fe80::1",
            "fe80::2",
            Vec::new(),
        );
        assert_eq!(garbage.protocol, "UDP");
    }

    #[test]
    fn bare_port_rows_name_the_service_without_inventing_layers() {
        for (port, service) in [
            (1883u16, "MQTT"),
            (8883, "MQTT"),
            (1080, "SOCKS"),
            (3389, "RDP"),
        ] {
            let frame = tcp_with_payload(port, &[]);
            let d = dissect_tcp(&frame, "10.0.0.1", "10.0.0.2", frame.len(), Vec::new());
            assert_eq!(d.protocol, service, "port {port}");
            assert!(d
                .layers
                .iter()
                .any(|l| l.label == "Transmission Control Protocol"));
        }
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
    } else if matches!(src_port, 546 | 547) || matches!(dst_port, 546 | 547) {
        super::udp_services::dhcpv6(&payload, src_port, dst_port)
    } else {
        None
    };
    // Port numbers alone are not proof of these application protocols.
    // An incomplete or malformed packet remains valid transport evidence.
    let protocol = if matches!(protocol, "DHCP" | "NTP" | "DHCPv6") && decoded_service.is_none() {
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

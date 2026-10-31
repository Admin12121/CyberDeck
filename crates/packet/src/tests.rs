//! Packet core regression tests remain outside the public crate entrypoint.
use super::*;

/// Build a classic pcap file from (ts_sec, packet bytes) records.
fn build_pcap(packets: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PCAP_MAGIC_LE_USEC.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // vmaj
    out.extend_from_slice(&4u16.to_le_bytes()); // vmin
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // linktype ethernet
    for (ts, packet) in packets {
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // usec
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        out.extend_from_slice(packet);
    }
    out
}

fn arp_frame() -> Vec<u8> {
    let mut f = vec![0xff; 6]; // dst broadcast
    f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    f.extend_from_slice(&0x0806u16.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes()); // request
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.extend_from_slice(&6u8.to_le_bytes());
    f.extend_from_slice(&4u8.to_le_bytes());
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    f.extend_from_slice(&[192, 168, 1, 24]);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&[192, 168, 1, 1]);
    f
}

fn tcp_syn_frame() -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.push(0x45); // v4 ihl 5
    f.push(0x00); // tos
    f.extend_from_slice(&40u16.to_be_bytes()); // total length
    f.extend_from_slice(&[0, 0, 0, 0]); // id, flags
    f.push(64); // ttl
    f.push(6); // tcp
    f.extend_from_slice(&[0, 0]); // checksum
    f.extend_from_slice(&[192, 168, 1, 24]);
    f.extend_from_slice(&[10, 0, 0, 42]);
    f.extend_from_slice(&49812u16.to_be_bytes());
    f.extend_from_slice(&443u16.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes()); // seq
    f.extend_from_slice(&0u32.to_be_bytes()); // ack
    f.push(0x50); // data offset 5
    f.push(0x02); // SYN
    f.extend_from_slice(&[0x0f, 0xaf]); // window
    f.extend_from_slice(&[0, 0]); // checksum
    f.extend_from_slice(&[0, 0]); // urgent
    f
}

#[test]
fn parses_header_and_endianness() {
    let bytes = build_pcap(&[]);
    let parsed = parse_pcap(&bytes).unwrap();
    assert_eq!(parsed.linktype, 1);
    assert_eq!(parsed.endianness, Endianness::Little);
    assert!(!parsed.nanosecond);
    assert!(parsed.packets.is_empty());
}

#[test]
fn rejects_pcapng_and_garbage() {
    let mut pcapng = vec![0x0a, 0x0d, 0x0d, 0x0a];
    pcapng.extend_from_slice(&[0; 60]);
    assert!(parse_pcap(&pcapng).unwrap_err().contains("pcapng"));
    let garbage = [7u8; 24];
    assert!(parse_pcap(&garbage).unwrap_err().contains("not a pcap"));
}

#[test]
fn linux_cooked_linktype_uses_16_byte_header() {
    let mut bytes = vec![0u8; 14];
    bytes.extend_from_slice(&0x0800u16.to_be_bytes());
    bytes.extend_from_slice(&[
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 10, 192, 0, 2, 11,
    ]);
    let packet = dissect(113, &bytes);
    assert_eq!(packet.source, "192.0.2.10");
    assert_eq!(packet.destination, "192.0.2.11");
    assert_eq!(packet.protocol, "ICMP");
    assert!(packet
        .layers
        .iter()
        .any(|layer| layer.label.contains("cooked")));
}

#[test]
fn dissects_arp_request() {
    let bytes = build_pcap(&[(1000, arp_frame())]);
    let parsed = parse_pcap(&bytes).unwrap();
    assert_eq!(parsed.packets.len(), 1);
    let d = &parsed.packets[0].dissected;
    assert_eq!(d.protocol, "ARP");
    assert_eq!(d.source, "192.168.1.24");
    assert_eq!(d.destination, "192.168.1.1");
    assert_eq!(d.info, "Who has 192.168.1.1? Tell 192.168.1.24");
    assert_eq!(d.color_hint, "arp");
}

#[test]
fn dissects_tcp_syn() {
    let bytes = build_pcap(&[(1000, tcp_syn_frame())]);
    let parsed = parse_pcap(&bytes).unwrap();
    let d = &parsed.packets[0].dissected;
    assert_eq!(d.protocol, "TLS"); // dst port 443
    assert_eq!(d.source, "192.168.1.24");
    assert_eq!(d.destination, "10.0.0.42");
    assert!(d.info.contains("49812 → 443 [SYN] Seq=0 Len=0"));
    assert!(d
        .layers
        .iter()
        .any(|l| l.label == "flags" && l.value == "SYN"));
}

#[test]
fn records_offsets_and_lengths() {
    let bytes = build_pcap(&[(1, arp_frame()), (2, tcp_syn_frame())]);
    let parsed = parse_pcap(&bytes).unwrap();
    assert_eq!(parsed.packets.len(), 2);
    assert_eq!(parsed.packets[0].incl_len, arp_frame().len());
    assert_eq!(parsed.packets[0].orig_len, parsed.packets[0].incl_len);
    assert_eq!(parsed.packets[0].offset, 24 + 16);
    assert_eq!(parsed.packets[1].offset, 24 + 16 + 16 + arp_frame().len());
    assert!(!parsed.malformed_tail);
}

#[test]
fn truncated_tail_is_flagged_not_fatal() {
    let mut bytes = build_pcap(&[(1, arp_frame())]);
    bytes.push(0xff); // dangling half header
    let parsed = parse_pcap(&bytes).unwrap();
    assert_eq!(parsed.packets.len(), 1);
    assert!(parsed.malformed_tail);
}

#[test]
fn absurd_length_does_not_allocate() {
    let mut bytes = build_pcap(&[(1, arp_frame())]);
    // second record claims 100 MB
    bytes.extend_from_slice(&[0, 0, 0, 1]);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend_from_slice(&(100u32 * 1024 * 1024).to_le_bytes());
    bytes.extend_from_slice(&(100u32 * 1024 * 1024).to_le_bytes());
    let parsed = parse_pcap(&bytes).unwrap();
    assert_eq!(parsed.packets.len(), 1);
    assert!(parsed.malformed_tail);
}

#[test]
fn udp_dns_gets_protocol_name() {
    let mut frame = vec![0xff; 6];
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.push(0x45);
    frame.push(0);
    frame.extend_from_slice(&57u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.push(64);
    frame.push(17);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[192, 168, 1, 24]);
    frame.extend_from_slice(&[1, 1, 1, 1]);
    frame.extend_from_slice(&5353u16.to_be_bytes()); // src 53 for naming
    frame.extend_from_slice(&53u16.to_be_bytes());
    frame.extend_from_slice(&37u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0xab, 0xcd]); // dns id
    frame.extend_from_slice(&[0x01, 0x00]); // flags
    frame.extend_from_slice(&[0x00, 0x01]); // one question
    frame.extend_from_slice(&[0x00, 0x00]); // zero answers
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // authority + additional
    frame.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let parsed = parse_pcap(&build_pcap(&[(1, frame)])).unwrap();
    let d = &parsed.packets[0].dissected;
    assert_eq!(d.protocol, "DNS");
    assert_eq!(d.color_hint, "dns");
    assert!(d.info.contains("example.com A"));
}

#[test]
fn packet_parser_to_tcp_reassembly_end_to_end() {
    fn tcp_frame(seq: u32, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&((40 + data.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0; 4]);
        frame.extend_from_slice(&[64, 6, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(&[192, 0, 2, 2]);
        frame.extend_from_slice(&1234u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&[0x50, 0x18]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(data);
        frame
    }
    let mut out_of_order = tcp_frame(108, b"rld");
    let mut fragment = tcp_frame(110, b"ignored");
    fragment[20..22].copy_from_slice(&1u16.to_be_bytes());
    let capture = build_pcap(&[
        (1, tcp_frame(100, b"hell")),
        (2, std::mem::take(&mut out_of_order)),
        (3, tcp_frame(104, b"o wo")),
        (4, tcp_frame(104, b"o wo")),
        (5, fragment),
    ]);
    let parsed = parse_capture(&capture).unwrap();
    assert_eq!(parsed.packets[4].dissected.protocol, "IPv4-fragment");
    assert!(parsed.packets[4].dissected.stream_id.is_none());
    let id = parsed.packets[0].dissected.stream_id.as_ref().unwrap();
    assert!(id.starts_with("tcp|"));
    let result = streams::follow_stream(&parsed.packets, id).unwrap();
    let text = result
        .chunks
        .iter()
        .filter(|c| c.kind == "data")
        .map(|c| c.text.as_str())
        .collect::<String>();
    assert_eq!(text, "hello world");
    assert_eq!(result.gaps, 0);
    assert_eq!(result.retransmissions, 1);
}

#[test]
fn ipv6_hop_by_hop_udp_dns_is_decoded_with_canonical_addresses() {
    let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    dns.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let udp_len = 8 + dns.len();
    let mut ip = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&((8 + udp_len) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 64]); // next header hop-by-hop
    ip.extend_from_slice(&[0; 15]);
    ip.push(1);
    ip.extend_from_slice(&[0; 15]);
    ip.push(2);
    ip.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    ip.extend_from_slice(&5353u16.to_be_bytes());
    ip.extend_from_slice(&53u16.to_be_bytes());
    ip.extend_from_slice(&(udp_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(&dns);
    let parsed = dissect(101, &ip);
    assert_eq!(parsed.source, "::1");
    assert_eq!(parsed.destination, "::2");
    assert_eq!(parsed.protocol, "DNS");
    assert!(parsed.info.contains("example.com A"));
}

#[test]
fn ipv4_initial_fragment_with_more_flag_is_not_a_transport_packet() {
    let mut ip = vec![0x45, 0, 0, 28, 0, 1, 0x20, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    ip.extend_from_slice(&[0x04, 0xd2, 0, 53, 0, 16, 0, 0]);
    let parsed = dissect(101, &ip);
    assert_eq!(parsed.protocol, "IPv4-fragment");
    assert!(parsed.stream_id.is_none());
    assert!(parsed.payload.is_empty());
}

#[test]
fn ipv6_initial_fragment_with_more_flag_is_not_a_transport_packet() {
    let mut ip = vec![0x60, 0, 0, 0, 0, 16, 44, 64];
    ip.extend_from_slice(&[0; 32]);
    ip.extend_from_slice(&[17, 0, 0, 1, 0, 0, 0, 1]);
    ip.extend_from_slice(&[0x04, 0xd2, 0, 53, 0, 16, 0, 0]);
    let parsed = dissect(101, &ip);
    assert_eq!(parsed.protocol, "IPv6-fragment");
    assert!(parsed.stream_id.is_none());
    assert!(parsed.payload.is_empty());
}

#[test]
fn ipv6_noninitial_fragment_is_not_mistaken_for_udp() {
    let mut ip = vec![0x60, 0, 0, 0, 0, 16, 44, 64];
    ip.extend_from_slice(&[0; 32]);
    ip.extend_from_slice(&[17, 0, 0, 8, 0, 0, 0, 1]);
    ip.extend_from_slice(&[0; 8]);
    let parsed = dissect(101, &ip);
    assert_eq!(parsed.protocol, "IPv6-fragment");
    assert!(parsed.stream_id.is_none());
    assert!(parsed.payload.is_empty());
    ip[40] = 0; // malformed extension chain
    assert_eq!(dissect(101, &ip).protocol, "IPv6-fragment");
}

#[test]
fn passive_http_and_tls_metadata_reach_packet_layers() {
    fn ip_tcp(body: &[u8], port: u16) -> Vec<u8> {
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((40 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        ip.extend_from_slice(&12345u16.to_be_bytes());
        ip.extend_from_slice(&port.to_be_bytes());
        ip.extend_from_slice(&1u32.to_be_bytes());
        ip.extend_from_slice(&0u32.to_be_bytes());
        ip.extend_from_slice(&[0x50, 0x18, 0, 0, 0, 0, 0, 0]);
        ip.extend_from_slice(body);
        ip
    }
    let http = dissect(
        101,
        &ip_tcp(b"GET /lab HTTP/1.1\r\nHost: example.com\r\n\r\n", 80),
    );
    assert_eq!(http.protocol, "HTTP");
    assert!(http.info.contains("GET /lab HTTP/1.1"));
    assert!(http.layers.iter().any(|l| l.label == "HTTP/1.x start line"));
    let mut hello = vec![3, 3];
    hello.extend([7; 32]);
    hello.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
    let mut handshake = vec![1, 0, 0, hello.len() as u8];
    handshake.extend(hello);
    let mut tls = vec![22, 3, 3];
    tls.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    tls.extend(handshake);
    let parsed = dissect(101, &ip_tcp(&tls, 443));
    assert_eq!(parsed.protocol, "TLS");
    assert!(parsed.info.contains("ClientHello"));
    assert!(parsed.layers.iter().any(|l| l.label == "TLS handshake"));
}

#[test]
fn classic_pcap_packet_count_has_a_fixed_upper_bound() {
    // A short file containing many zero-length records must not cause
    // millions of metadata allocations.
    let mut capture = build_pcap(&[]);
    for _ in 0..(MAX_CAPTURE_PACKETS + 1) {
        capture.extend_from_slice(&[0u8; 16]);
    }
    let parsed = parse_pcap(&capture).unwrap();
    assert_eq!(parsed.packets.len(), MAX_CAPTURE_PACKETS);
    assert!(parsed.malformed_tail);
}

#[test]
fn hostile_small_buffers_do_not_panic_application_parsers() {
    let mut seed = 0x9e37_79b9u32;
    for len in 0..512 {
        let mut input = Vec::with_capacity(len);
        for _ in 0..len {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            input.push((seed & 0xff) as u8);
        }
        let _ = application::tls_hello(&input);
        let _ = application::http_start_line(&input);
        let _ = dns::parse_dns(&input);
        let _ = dissect(101, &input);
    }
}

#[test]
fn pcap_tcp_session_reuse_and_split_http_are_detected_end_to_end() {
    fn tcp_frame(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x02; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        frame.extend_from_slice(&1234u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&[0x50, flags, 0, 0, 0, 0, 0, 0]);
        frame.extend_from_slice(payload);
        frame
    }

    let first = b"GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let second = b"POST /second HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    let capture = build_pcap(&[
        (1, tcp_frame(1000, 0x02, b"")),
        (2, tcp_frame(1001, 0x18, &first[..8])),
        (3, tcp_frame(1009, 0x18, &first[8..])),
        (4, tcp_frame(1100, 0x04, b"")), // RST closes the first epoch
        (5, tcp_frame(2000, 0x02, b"")),
        (6, tcp_frame(2001, 0x18, &second[..7])),
        (7, tcp_frame(2008, 0x18, &second[7..])),
    ]);
    let parsed = parse_capture(&capture).unwrap();
    let first_id = parsed.packets[1].dissected.stream_id.as_ref().unwrap();
    let second_id = parsed.packets[5].dissected.stream_id.as_ref().unwrap();
    assert_ne!(first_id, second_id);
    assert!(first_id.ends_with("#1"));
    assert!(second_id.ends_with("#2"));
    let first_transcript = streams::follow_stream(&parsed.packets, first_id).unwrap();
    let second_transcript = streams::follow_stream(&parsed.packets, second_id).unwrap();
    assert_eq!(
        first_transcript.application_hints[0].summary,
        "GET /first HTTP/1.1"
    );
    assert_eq!(
        second_transcript.application_hints[0].summary,
        "POST /second HTTP/1.1"
    );
    assert_eq!(first_transcript.conflicts, 0);
    assert_eq!(second_transcript.conflicts, 0);
}

#[test]
fn classic_pcap_keeps_fragment_rows_but_reports_derived_datagram() {
    fn ethernet_ipv4_fragment(id: u16, offset: usize, more: bool, part: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + part.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&id.to_be_bytes());
        ip.extend_from_slice(
            &(((offset / 8) as u16) | if more { 0x2000 } else { 0 }).to_be_bytes(),
        );
        ip.extend_from_slice(&[64, 17, 0, 0]);
        ip.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        ip.extend_from_slice(part);
        frame.extend(ip);
        frame
    }
    let mut udp = vec![0x04, 0xd2, 0, 53, 0, 24, 0, 0];
    udp.extend_from_slice(&[0x42; 16]);
    let capture = build_pcap(&[
        (1, ethernet_ipv4_fragment(771, 16, false, &udp[16..])),
        (2, ethernet_ipv4_fragment(771, 0, true, &udp[..16])),
    ]);
    let parsed = parse_capture(&capture).unwrap();
    assert_eq!(parsed.packets.len(), 2);
    assert!(parsed
        .packets
        .iter()
        .all(|p| p.dissected.protocol == "IPv4-fragment"));
    assert!(parsed
        .packets
        .iter()
        .all(|p| p.dissected.stream_id.is_none()));
    assert_eq!(parsed.reassembly.completed.len(), 1);
    let derived = &parsed.reassembly.completed[0];
    assert_eq!(derived.identification, 771);
    assert_eq!(derived.first_packet_index, 0);
    assert_eq!(derived.last_packet_index, 1);
    assert_eq!(derived.dissected.protocol, "DNS");
    assert_eq!(&derived.ip_packet[20..], &udp);
}

#[test]
fn ipv4_snaplen_truncation_never_promotes_partial_udp() {
    let mut ip = vec![0x45, 0, 0, 36, 0, 1, 0, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    ip.extend_from_slice(&[0x04, 0xd2, 0x1f, 0x90, 0, 8, 0, 0]);
    let truncated = dissect(101, &ip);
    assert_eq!(truncated.protocol, "IPv4-truncated");
    assert!(truncated.stream_id.is_none());
    assert!(truncated.payload.is_empty());
    assert!(truncated.tcp.is_none());
    let captured_len = ip.len() as u16;
    ip[2..4].copy_from_slice(&captured_len.to_be_bytes());
    assert_eq!(dissect(101, &ip).protocol, "UDP");
}

#[test]
fn ipv6_snaplen_truncation_never_promotes_partial_udp() {
    let mut ip = vec![0x60, 0, 0, 0, 0, 24, 17, 64];
    ip.extend_from_slice(&[0; 15]);
    ip.push(1);
    ip.extend_from_slice(&[0; 15]);
    ip.push(2);
    ip.extend_from_slice(&[0x04, 0xd2, 0x1f, 0x90, 0, 8, 0, 0]);
    let truncated = dissect(101, &ip);
    assert_eq!(truncated.protocol, "IPv6-truncated");
    assert!(truncated.stream_id.is_none());
    assert!(truncated.payload.is_empty());
    ip[4..6].copy_from_slice(&8u16.to_be_bytes());
    assert_eq!(dissect(101, &ip).protocol, "UDP");
}

#[test]
fn ipv4_udp_length_larger_than_complete_ip_payload_is_not_streamed() {
    let mut ip = vec![0x45, 0, 0, 32, 0, 1, 0, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    ip.extend_from_slice(&[0x04, 0xd2, 0x1f, 0x90, 0, 20, 0, 0]);
    ip.extend_from_slice(b"test");
    let invalid = dissect(101, &ip);
    assert_eq!(invalid.protocol, "UDP-truncated");
    assert!(invalid.stream_id.is_none());
    assert!(invalid.payload.is_empty());

    ip[24..26].copy_from_slice(&12u16.to_be_bytes());
    let valid = dissect(101, &ip);
    assert_eq!(valid.protocol, "UDP");
    assert_eq!(valid.payload, b"test");
}

#[test]
fn ipv6_udp_length_larger_than_complete_ip_payload_is_not_streamed() {
    let mut ip = vec![0x60, 0, 0, 0, 0, 12, 17, 64];
    ip.extend_from_slice(&[0; 15]);
    ip.push(1);
    ip.extend_from_slice(&[0; 15]);
    ip.push(2);
    ip.extend_from_slice(&[0x04, 0xd2, 0x1f, 0x90, 0, 20, 0, 0]);
    ip.extend_from_slice(b"test");
    let invalid = dissect(101, &ip);
    assert_eq!(invalid.protocol, "UDP-truncated");
    assert!(invalid.stream_id.is_none());
    assert!(invalid.payload.is_empty());

    ip[44..46].copy_from_slice(&12u16.to_be_bytes());
    let valid = dissect(101, &ip);
    assert_eq!(valid.protocol, "UDP");
    assert_eq!(valid.payload, b"test");
}

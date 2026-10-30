//! hacktool-packet: classic PCAP parsing plus a first-pass Ethernet/IPv4/
//! TCP/UDP/ARP/ICMP/HTTP dissector. Wireshark-compatible display filters and
//! reassembly arrive in a later arc; this module gives the Packet Studio real
//! captures now (Master Plan §5.1). Guard rails: packet length fields are
//! validated before allocation and truncated captures parse until the first
//! bad record.

use serde::Serialize;

pub const MAX_PACKET_BYTES: usize = 262_144;
pub const PCAP_MAGIC_LE_USEC: u32 = 0xa1b2_c3d4;
pub const PCAP_MAGIC_BE_USEC: u32 = 0xd4c3_b2a1;
pub const PCAP_MAGIC_LE_NSEC: u32 = 0xa1b2_3c4d;
pub const PCAP_MAGIC_BE_NSEC: u32 = 0x4d3c_b2a1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Serialize)]
pub struct Layer {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dissected {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub info: String,
    pub color_hint: String,
    pub layers: Vec<Layer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketMeta {
    pub offset: usize,
    pub incl_len: usize,
    pub orig_len: usize,
    pub ts_sec: u64,
    pub ts_subsec: u32,
    #[serde(skip)]
    pub dissected: Dissected,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapFile {
    pub linktype: u32,
    pub endianness: Endianness,
    pub nanosecond: bool,
    pub packets: Vec<PacketMeta>,
    /// Records skipped because their length fields were implausible.
    pub malformed_tail: bool,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn u16(&mut self) -> Option<u16> {
        let b = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(if self.big_endian { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(if self.big_endian {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.data.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(b)
    }
}

/// Parse a classic PCAP capture. PCAPNG is intentionally rejected with a
/// clear message until that parser lands.
pub fn parse_pcap(data: &[u8]) -> Result<PcapFile, String> {
    if data.len() < 24 {
        return Err("file is too small to be a pcap capture".to_string());
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if matches!(magic, 0x0a0d_0d0a) {
        return Err("pcapng captures arrive in a later arc; save as classic pcap".to_string());
    }
    let (big_endian, nanosecond, linktype) = match magic {
        PCAP_MAGIC_LE_USEC => (false, false, u32::from_le_bytes([data[20], data[21], data[22], data[23]])),
        PCAP_MAGIC_BE_USEC => (true, false, u32::from_be_bytes([data[20], data[21], data[22], data[23]])),
        PCAP_MAGIC_LE_NSEC => (false, true, u32::from_le_bytes([data[20], data[21], data[22], data[23]])),
        PCAP_MAGIC_BE_NSEC => (true, true, u32::from_be_bytes([data[20], data[21], data[22], data[23]])),
        other => return Err(format!("not a pcap capture (magic 0x{other:08x})")),
    };

    let mut reader = Reader { data, pos: 24, big_endian };
    let mut packets = Vec::new();
    let mut malformed_tail = false;
    while reader.pos < data.len() {
        let Some(ts_sec) = reader.u32() else { malformed_tail = true; break };
        let Some(ts_subsec) = reader.u32() else { malformed_tail = true; break };
        let Some(incl_len) = reader.u32() else { malformed_tail = true; break };
        let Some(orig_len) = reader.u32() else { malformed_tail = true; break };
        if incl_len as usize > MAX_PACKET_BYTES || reader.pos + incl_len as usize > data.len() {
            malformed_tail = true;
            break;
        }
        let offset = reader.pos;
        let bytes = reader.bytes(incl_len as usize).unwrap_or(&[]);
        let dissected = dissect(linktype, bytes);
        packets.push(PacketMeta {
            offset,
            incl_len: incl_len as usize,
            orig_len: orig_len as usize,
            ts_sec: ts_sec as u64,
            ts_subsec,
            dissected,
        });
    }
    Ok(PcapFile { linktype, endianness: if big_endian { Endianness::Big } else { Endianness::Little }, nanosecond, packets, malformed_tail })
}

fn mac_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn ipv4_to_string(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn color_for(protocol: &str) -> String {
    match protocol {
        "DNS" => "dns",
        "HTTP" => "http",
        "TLS" | "TLSv1.2" | "TLSv1.3" => "tls",
        "ARP" => "arp",
        "ICMP" => "icmp",
        "UDP" => "udp",
        "IPv6" => "ipv6",
        "TCP" => "tcp",
        _ => "other",
    }
    .to_string()
}

/// Dissect one link-layer frame. Unknown protocols still produce a usable
/// frame row with the raw hex prefix as info.
pub fn dissect(linktype: u32, frame: &[u8]) -> Dissected {
    match linktype {
        1 => dissect_ethernet(frame),
        101 => dissect_raw_ip(frame), // LINKTYPE_RAW
        113 => dissect_ethernet(frame), // LINKTYPE_LINUX_SLL is close enough for arc 3
        _ => Dissected {
            source: String::new(),
            destination: String::new(),
            protocol: "LINK".to_string(),
            info: format!("linktype {linktype} frame, {} bytes", frame.len()),
            color_hint: "other".to_string(),
            layers: vec![Layer { label: "Frame".to_string(), value: format!("{} bytes", frame.len()) }],
        },
    }
}

fn dissect_raw_ip(frame: &[u8]) -> Dissected {
    if frame.is_empty() {
        return empty_frame();
    }
    match frame[0] >> 4 {
        4 => dissect_ipv4(frame, &[]),
        6 => dissect_ipv6(frame, &[]),
        _ => empty_frame(),
    }
}

fn empty_frame() -> Dissected {
    Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: "MALFORMED".to_string(),
        info: "truncated frame".to_string(),
        color_hint: "other".to_string(),
        layers: vec![Layer { label: "Frame".to_string(), value: "truncated".to_string() }],
    }
}

fn dissect_ethernet(frame: &[u8]) -> Dissected {
    if frame.len() < 14 {
        return empty_frame();
    }
    let dst_mac = mac_to_string(&frame[0..6]);
    let src_mac = mac_to_string(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload = &frame[14..];
    let mut layers = vec![
        Layer { label: "Ethernet II".to_string(), value: format!("{src_mac} → {dst_mac}") },
        Layer { label: "EtherType".to_string(), value: format!("0x{ethertype:04x}") },
    ];
    let mut d = match ethertype {
        0x0800 => dissect_ipv4(payload, &layers),
        0x86dd => dissect_ipv6(payload, &layers),
        0x0806 => dissect_arp(payload),
        _ => {
            let mut d = empty_frame();
            d.protocol = "ETH".to_string();
            d.info = format!("ethertype 0x{ethertype:04x}, {} bytes", payload.len());
            d
        }
    };
    // ethernet layers prefix everything from the network layer up
    let mut prefixed = layers;
    prefixed.extend(d.layers.drain(..));
    d.layers = prefixed;
    d
}

fn dissect_arp(payload: &[u8]) -> Dissected {
    if payload.len() < 28 {
        return empty_frame();
    }
    let operation = u16::from_be_bytes([payload[6], payload[7]]);
    let sender_ip = ipv4_to_string(&payload[14..18]);
    let target_ip = ipv4_to_string(&payload[24..28]);
    let info = match operation {
        1 => format!("Who has {target_ip}? Tell {sender_ip}"),
        2 => format!("{sender_ip} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", payload[8], payload[9], payload[10], payload[11], payload[12], payload[13]),
        _ => format!("ARP operation {operation}"),
    };
    Dissected {
        source: sender_ip.clone(),
        destination: target_ip.clone(),
        protocol: "ARP".to_string(),
        info: info.clone(),
        color_hint: color_for("ARP"),
        layers: vec![
            Layer { label: "Address Resolution Protocol".to_string(), value: info },
            Layer { label: "sender IP".to_string(), value: sender_ip },
            Layer { label: "target IP".to_string(), value: target_ip },
        ],
    }
}

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

fn dissect_ipv4(payload: &[u8], parent_layers: &[Layer]) -> Dissected {
    if payload.len() < 20 {
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
    layers.push(Layer { label: "Internet Protocol Version 4".to_string(), value: format!("{source} → {destination}") });
    layers.push(Layer { label: "ttl".to_string(), value: ttl.to_string() });
    layers.push(Layer { label: "total length".to_string(), value: total_length.to_string() });

    let transport = &payload[ihl..];
    match proto {
        6 => dissect_tcp(transport, &source, &destination, total_length.saturating_sub(ihl), layers),
        17 => dissect_udp(transport, &source, &destination, layers),
        1 => {
            let info = format!("ICMP type={} code={}", transport.first().copied().unwrap_or(0), transport.get(1).copied().unwrap_or(0));
            Dissected {
                source,
                destination,
                protocol: "ICMP".to_string(),
                info,
                color_hint: color_for("ICMP"),
                layers,
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
            }
        }
    }
}

fn dissect_ipv6(payload: &[u8], parent_layers: &[Layer]) -> Dissected {
    if payload.len() < 40 {
        return empty_frame();
    }
    let source = format_ipv6(&payload[8..24]);
    let destination = format_ipv6(&payload[24..40]);
    let next_header = payload[6];
    let mut layers = parent_layers.to_vec();
    layers.push(Layer { label: "Internet Protocol Version 6".to_string(), value: format!("{source} → {destination}") });
    let transport = &payload[40..];
    match next_header {
        6 => dissect_tcp(transport, &source, &destination, transport.len(), layers),
        17 => dissect_udp(transport, &source, &destination, layers),
        other => Dissected {
            source,
            destination,
            protocol: format!("IPv6-{other}"),
            info: format!("next header {other}"),
            color_hint: color_for("IPv6"),
            layers,
        },
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    (0..8)
        .map(|i| u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]).to_string())
        .collect::<Vec<_>>()
        .join(":")
}

fn dissect_tcp(transport: &[u8], source: &str, destination: &str, ip_payload_len: usize, mut layers: Vec<Layer>) -> Dissected {
    if transport.len() < 20 {
        return empty_frame();
    }
    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    let seq = u32::from_be_bytes([transport[4], transport[5], transport[6], transport[7]]);
    let data_offset = (transport[12] >> 4) as usize * 4;
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
    let payload_len = ip_payload_len.saturating_sub(data_offset);
    let info = format!("{src_port} → {dst_port} [{flags}] Seq={seq} Len={payload_len}");
    let service = well_known_name(6, src_port, dst_port);
    let protocol = if service.is_empty() { "TCP" } else { service };
    // HTTP piggybacks on the well-known port plus a recognizable payload
    let protocol = if payload_len > 0 && matches!(src_port, 80 | 8080) || matches!(dst_port, 80 | 8080) {
        let http_start = transport.get(data_offset..data_offset + 5);
        if let Some(head) = http_start {
            if head.starts_with(b"HTTP/") || head.starts_with(b"GET ") || head.starts_with(b"POST ") || head.starts_with(b"PUT ") || head.starts_with(b"HEAD ") || head.starts_with(b"DELETE ") {
                "HTTP"
            } else {
                protocol
            }
        } else {
            protocol
        }
    } else {
        protocol
    };
    let color = color_for(protocol);
    layers.push(Layer { label: "Transmission Control Protocol".to_string(), value: info.clone() });
    layers.push(Layer { label: "source port".to_string(), value: src_port.to_string() });
    layers.push(Layer { label: "destination port".to_string(), value: dst_port.to_string() });
    layers.push(Layer { label: "flags".to_string(), value: flags });
    Dissected { source: source.to_string(), destination: destination.to_string(), protocol: protocol.to_string(), info, color_hint: color, layers }
}

fn dissect_udp(transport: &[u8], source: &str, destination: &str, mut layers: Vec<Layer>) -> Dissected {
    if transport.len() < 8 {
        return empty_frame();
    }
    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    let length = u16::from_be_bytes([transport[4], transport[5]]);
    let service = well_known_name(17, src_port, dst_port);
    let protocol = if service.is_empty() { "UDP" } else { service };
    let mut info = format!("{src_port} → {dst_port} Len={}", length.saturating_sub(8));
    if protocol == "DNS" && transport.len() > 12 {
        let questions = u16::from_be_bytes([transport[10], transport[11]]);
        info = format!("Standard query, {questions} question(s)");
    }
    layers.push(Layer { label: "User Datagram Protocol".to_string(), value: info.clone() });
    layers.push(Layer { label: "source port".to_string(), value: src_port.to_string() });
    layers.push(Layer { label: "destination port".to_string(), value: dst_port.to_string() });
    Dissected { source: source.to_string(), destination: destination.to_string(), protocol: protocol.to_string(), info, color_hint: color_for(protocol), layers }
}

#[cfg(test)]
mod tests {
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
        assert!(d.layers.iter().any(|l| l.label == "flags" && l.value == "SYN"));
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
        frame.extend_from_slice(&34u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[192, 168, 1, 24]);
        frame.extend_from_slice(&[1, 1, 1, 1]);
        frame.extend_from_slice(&5353u16.to_be_bytes()); // src 53 for naming
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&14u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[0xab, 0xcd]); // dns id
        frame.extend_from_slice(&[0x01, 0x00]); // flags
        frame.extend_from_slice(&[0x00, 0x01]); // one question
        let parsed = parse_pcap(&build_pcap(&[(1, frame)])).unwrap();
        let d = &parsed.packets[0].dissected;
        assert_eq!(d.protocol, "DNS");
        assert_eq!(d.color_hint, "dns");
        assert!(d.info.contains("question"));
    }
}

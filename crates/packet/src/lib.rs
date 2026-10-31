//! Classic PCAP parsing + Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP dissection.
//! Guard rails: length fields validated, malformed tails flagged.

use serde::Serialize;

pub mod application;
pub mod dns;
pub mod fragments;
pub mod pcapng;
pub mod streams;

/// Detect either classic PCAP or PCAPNG without invoking external tools.
pub fn parse_capture(data: &[u8]) -> Result<PcapFile, String> {
    let mut capture = if data.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        pcapng::parse_pcapng(data)?
    } else {
        parse_pcap(data)?
    };
    streams::assign_tcp_sessions(&mut capture.packets);
    Ok(capture)
}

pub const MAX_PACKET_BYTES: usize = 262_144;
/// Avoid unbounded metadata allocation for captures full of tiny/empty records.
pub const MAX_CAPTURE_PACKETS: usize = 200_000;
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
pub struct TcpMeta {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub flags: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dissected {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub info: String,
    pub color_hint: String,
    pub layers: Vec<Layer>,
    /// Canonical "endpointA|endpointB" for TCP/UDP streams.
    pub stream_id: Option<String>,
    pub tcp: Option<TcpMeta>,
    /// Transport payload bytes for TCP/UDP (bounded).
    pub payload: Vec<u8>,
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
    /// Derived, bounded IP fragment results; original frames are never rewritten.
    pub reassembly: fragments::ReassemblyReport,
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
        Some(if self.big_endian {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
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
        PCAP_MAGIC_LE_USEC => (
            false,
            false,
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        ),
        PCAP_MAGIC_BE_USEC => (
            true,
            false,
            u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        ),
        PCAP_MAGIC_LE_NSEC => (
            false,
            true,
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        ),
        PCAP_MAGIC_BE_NSEC => (
            true,
            true,
            u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        ),
        other => return Err(format!("not a pcap capture (magic 0x{other:08x})")),
    };

    let mut reader = Reader {
        data,
        pos: 24,
        big_endian,
    };
    let mut packets = Vec::new();
    let mut assembler = fragments::FragmentReassembler::new();
    let mut malformed_tail = false;
    while reader.pos < data.len() {
        if packets.len() >= MAX_CAPTURE_PACKETS {
            malformed_tail = true;
            break;
        }
        let Some(ts_sec) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        let Some(ts_subsec) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        let Some(incl_len) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        let Some(orig_len) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        if incl_len as usize > MAX_PACKET_BYTES || reader.pos + incl_len as usize > data.len() {
            malformed_tail = true;
            break;
        }
        let offset = reader.pos;
        let bytes = reader.bytes(incl_len as usize).unwrap_or(&[]);
        let dissected = dissect(linktype, bytes);
        assembler.push_frame(linktype, bytes, packets.len());
        packets.push(PacketMeta {
            offset,
            incl_len: incl_len as usize,
            orig_len: orig_len as usize,
            ts_sec: ts_sec as u64,
            ts_subsec,
            dissected,
        });
    }
    Ok(PcapFile {
        linktype,
        endianness: if big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        },
        nanosecond,
        packets,
        reassembly: assembler.finish(),
        malformed_tail,
    })
}

fn mac_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
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
        101 => dissect_raw_ip(frame),    // LINKTYPE_RAW
        113 => dissect_linux_sll(frame), // Linux cooked capture v1: 16-byte header
        _ => Dissected {
            source: String::new(),
            destination: String::new(),
            protocol: "LINK".to_string(),
            info: format!("linktype {linktype} frame, {} bytes", frame.len()),
            color_hint: "other".to_string(),
            layers: vec![Layer {
                label: "Frame".to_string(),
                value: format!("{} bytes", frame.len()),
            }],
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        },
    }
}

/// Linux cooked capture v1 has a 16-byte header, not an Ethernet header.
fn dissect_linux_sll(frame: &[u8]) -> Dissected {
    if frame.len() < 16 {
        return empty_frame();
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    let layer = Layer {
        label: "Linux cooked capture".to_string(),
        value: format!("protocol 0x{protocol:04x}"),
    };
    let mut d = match protocol {
        0x0800 => dissect_ipv4(&frame[16..], &[]),
        0x86dd => dissect_ipv6(&frame[16..], &[]),
        0x0806 => dissect_arp(&frame[16..]),
        _ => {
            let mut d = empty_frame();
            d.protocol = "SLL".to_string();
            d.info = format!("Linux cooked protocol 0x{protocol:04x}");
            d
        }
    };
    d.layers.insert(0, layer);
    d
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
        layers: vec![Layer {
            label: "Frame".to_string(),
            value: "truncated".to_string(),
        }],
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
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
        Layer {
            label: "Ethernet II".to_string(),
            value: format!("{src_mac} → {dst_mac}"),
        },
        Layer {
            label: "EtherType".to_string(),
            value: format!("0x{ethertype:04x}"),
        },
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
        2 => format!(
            "{sender_ip} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[8], payload[9], payload[10], payload[11], payload[12], payload[13]
        ),
        _ => format!("ARP operation {operation}"),
    };
    Dissected {
        source: sender_ip.clone(),
        destination: target_ip.clone(),
        protocol: "ARP".to_string(),
        info: info.clone(),
        color_hint: color_for("ARP"),
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
        layers: vec![
            Layer {
                label: "Address Resolution Protocol".to_string(),
                value: info,
            },
            Layer {
                label: "sender IP".to_string(),
                value: sender_ip,
            },
            Layer {
                label: "target IP".to_string(),
                value: target_ip,
            },
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
            let info = format!(
                "ICMP type={} code={}",
                transport.first().copied().unwrap_or(0),
                transport.get(1).copied().unwrap_or(0)
            );
            Dissected {
                source,
                destination,
                protocol: "ICMP".to_string(),
                info,
                color_hint: color_for("ICMP"),
                layers,
                stream_id: None,
                tcp: None,
                payload: transport.to_vec(),
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
fn dissect_ipv6(payload: &[u8], parent_layers: &[Layer]) -> Dissected {
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
            let info = format!(
                "ICMPv6 type={} code={}",
                transport.first().copied().unwrap_or(0),
                transport.get(1).copied().unwrap_or(0),
            );
            Dissected {
                source,
                destination,
                protocol: "ICMPv6".into(),
                info,
                color_hint: color_for("ICMP"),
                layers,
                stream_id: None,
                tcp: None,
                payload: transport.to_vec(),
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

fn dissect_tcp(
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
    let stream_id = Some(format!("tcp|{}", endpoints.join("|")));
    // Passive application parsing looks only at bytes in the captured frame.
    // A split TCP segment cannot be claimed as a complete HTTP/TLS message.
    let http = application::http_start_line(&payload);
    let tls = application::tls_hello(&payload);
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
            value: application::tls_description(hello),
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
            application::tls_description(&hello)
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

fn dissect_udp(
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
    let stream_id = Some(format!("udp|{}", endpoints.join("|")));
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
}

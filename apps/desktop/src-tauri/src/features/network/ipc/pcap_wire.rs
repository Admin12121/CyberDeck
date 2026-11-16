//! IPC wire types and packet timestamp/metadata presentation projection.
//! Stable fields and serialized names are shared with the desktop frontend.
use std::collections::HashMap;

use cyberdeck_packet::{fragments::ReassemblyReport, PacketMeta};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct LayerWire {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct PcapPacketWire {
    pub index: usize,
    pub time_ms: f64,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
    pub color_hint: String,
    pub stream_id: Option<String>,
    pub layers: Vec<LayerWire>,
}

#[derive(Debug, Serialize)]
pub struct PcapOpenWire {
    pub format: String,
    pub linktype: u32,
    pub packet_count: usize,
    pub shown: usize,
    pub malformed_tail: bool,
    pub file_name: String,
    pub packets: Vec<PcapPacketWire>,
    /// Additive open-time summary of the bounded fragment reassembly pass.
    /// `Option` + serde default keep older wire consumers compiling; `None`
    /// means the capture held no fragment evidence worth surfacing.
    #[serde(default)]
    pub reassembly: Option<ReassemblySummaryWire>,
}

/// Bounded reassembly summary. Original frames remain the evidence; this only
/// reports what the passive assembler derived or flagged while opening.
#[derive(Debug, Serialize)]
pub struct ReassemblySummaryWire {
    pub datagram_count: usize,
    pub flagged_overlap_count: usize,
    /// Identifiers of the first reassembled datagrams, capped at 8 so one
    /// pathological capture cannot bloat the wire or the banner.
    pub first_datagram_ids: Vec<String>,
}

/// `None` unless the reassembly pass actually reconstructed a datagram or
/// flagged an overlap conflict; otherwise a bounded projection of the report.
pub(super) fn reassembly_summary(report: &ReassemblyReport) -> Option<ReassemblySummaryWire> {
    if report.completed.is_empty() && report.conflicts == 0 {
        return None;
    }
    Some(ReassemblySummaryWire {
        datagram_count: report.completed.len(),
        flagged_overlap_count: report.conflicts,
        first_datagram_ids: report
            .completed
            .iter()
            .take(8)
            .map(|datagram| {
                format!(
                    "v{} id=0x{:x} frames {}-{}",
                    datagram.ip_version,
                    datagram.identification,
                    datagram.first_packet_index,
                    datagram.last_packet_index
                )
            })
            .collect(),
    })
}

pub(super) fn wire_packet(
    index: usize,
    meta: &PacketMeta,
    first: Option<&PacketMeta>,
    nanosecond: bool,
) -> PcapPacketWire {
    let scale = if nanosecond {
        1_000_000_000i128
    } else {
        1_000_000i128
    };
    let current = meta.ts_sec as i128 * scale + meta.ts_subsec as i128;
    let base = first
        .map(|p| p.ts_sec as i128 * scale + p.ts_subsec as i128)
        .unwrap_or(0);
    let ts_ms = (current - base) as f64 / (scale as f64 / 1000.0);
    PcapPacketWire {
        index,
        time_ms: ts_ms,
        source: meta.dissected.source.clone(),
        destination: meta.dissected.destination.clone(),
        protocol: meta.dissected.protocol.clone(),
        length: meta.orig_len,
        info: meta.dissected.info.clone(),
        color_hint: meta.dissected.color_hint.clone(),
        stream_id: meta.dissected.stream_id.clone(),
        layers: meta
            .dissected
            .layers
            .iter()
            .map(|l| LayerWire {
                label: l.label.clone(),
                value: l.value.clone(),
            })
            .collect(),
    }
}

// ---------------------------------------------------- capture statistics ----
//
// Wireshark-parity capture-wide statistics over the FULL capture cache (up to
// MAX_CAPTURE_PACKETS packet metas), not the 20k shown-packet window the
// client-side model aggregates. Pure functions over PacketMeta: no Tauri
// state, no I/O, unit-testable directly. Defensive projection only — counts,
// lengths and addresses, never packet bytes.

/// Hard bound on IO graph buckets (one v1 graph, ≤ 120 time buckets).
pub(crate) const IO_GRAPH_MAX_BUCKETS: usize = 120;
/// Bucket-width floor: shorter captures get fewer, 1 ms-wide buckets instead
/// of 120 empty slivers.
const IO_GRAPH_MIN_BUCKET_NS: i128 = 1_000_000;
/// Hard bound on endpoint rows returned to the UI (top talkers by bytes).
pub(crate) const ENDPOINTS_MAX_ROWS: usize = 64;

/// One bounded time bucket of the capture-wide IO graph.
#[derive(Debug, Clone, Serialize)]
pub struct IoBucketWire {
    /// Bucket start in milliseconds relative to the first packet.
    pub from_ms: f64,
    pub packets: u64,
    pub bytes: u64,
    /// Frames whose dissection carries TCP metadata.
    pub tcp_packets: u64,
    /// Frames dissected through UDP (any UDP-based application protocol).
    pub udp_packets: u64,
    /// ARP, ICMP, IP fragments and everything the dissector left unresolved.
    pub other_packets: u64,
}

/// Bounded capture-wide IO graph; `buckets.len() ≤ IO_GRAPH_MAX_BUCKETS`.
#[derive(Debug, Clone, Serialize)]
pub struct IoGraphWire {
    pub packet_count: usize,
    pub bucket_count: usize,
    pub bucket_width_ms: f64,
    pub total_bytes: u64,
    pub buckets: Vec<IoBucketWire>,
}

/// One endpoint row; byte columns follow Wireshark's talker convention:
/// bytes under Tx are frames where the endpoint is the source address.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointRowWire {
    pub address: String,
    /// "ip4" | "ip6" | "mac" — the client endpoint family names.
    pub family: String,
    pub packets: u64,
    pub bytes: u64,
    pub packets_out: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub bytes_in: u64,
}

/// Bounded top-talker table; `rows.len() ≤ ENDPOINTS_MAX_ROWS`, sorted by
/// total bytes descending.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointsWire {
    pub packet_count: usize,
    /// Distinct endpoints found before the bounded top-N projection.
    pub endpoint_count: usize,
    /// True when more than ENDPOINTS_MAX_ROWS endpoints exist and only the
    /// heaviest rows are returned.
    pub truncated: bool,
    pub rows: Vec<EndpointRowWire>,
}

enum TransportClass {
    Tcp,
    Udp,
    Other,
}

/// TCP presence comes from the parser's TCP meta; UDP from the "User Datagram
/// Protocol" layer the UDP dissector always pushes (also under DNS/DHCP/QUIC).
/// Everything else is other — no guessing from ports or protocol names.
fn transport_class(meta: &PacketMeta) -> TransportClass {
    if meta.dissected.tcp.is_some() {
        return TransportClass::Tcp;
    }
    if meta
        .dissected
        .layers
        .iter()
        .any(|layer| layer.label == "User Datagram Protocol")
    {
        return TransportClass::Udp;
    }
    TransportClass::Other
}

/// Capture-wide IO graph in two bounded passes over the packet metas. Time is
/// integer nanoseconds from the source-file scale (`nanosecond` selects ns vs
/// µs subseconds), so bucket math never drifts. Bucket width is span/120 with
/// a 1 ms floor; a packet landing exactly on the capture's last instant
/// shares the final bucket (same convention as the client-side series).
pub(super) fn io_graph_of(packets: &[PacketMeta], nanosecond: bool) -> IoGraphWire {
    if packets.is_empty() {
        return IoGraphWire {
            packet_count: 0,
            bucket_count: 0,
            bucket_width_ms: 0.0,
            total_bytes: 0,
            buckets: Vec::new(),
        };
    }
    let scale_ns: i128 = if nanosecond { 1 } else { 1_000 };
    let stamp_ns = |meta: &PacketMeta| {
        meta.ts_sec as i128 * 1_000_000_000 + meta.ts_subsec as i128 * scale_ns
    };
    let mut min_ns = i128::MAX;
    let mut max_ns = i128::MIN;
    let mut total_bytes = 0u64;
    for meta in packets {
        let time = stamp_ns(meta);
        min_ns = min_ns.min(time);
        max_ns = max_ns.max(time);
        total_bytes += meta.orig_len as u64;
    }
    let span_ns = (max_ns - min_ns).max(0);
    let width_ns = (span_ns / IO_GRAPH_MAX_BUCKETS as i128)
        .max(IO_GRAPH_MIN_BUCKET_NS)
        .max(1);
    // ceil((span + 1) / width) without unstable signed div_ceil; the +1
    // keeps a packet on the capture's last instant inside the bucket range.
    let bucket_count =
        ((span_ns + width_ns) / width_ns).clamp(1, IO_GRAPH_MAX_BUCKETS as i128) as usize;
    let mut buckets = vec![
        IoBucketWire {
            from_ms: 0.0,
            packets: 0,
            bytes: 0,
            tcp_packets: 0,
            udp_packets: 0,
            other_packets: 0,
        };
        bucket_count
    ];
    for (index, bucket) in buckets.iter_mut().enumerate() {
        bucket.from_ms = (index as i128 * width_ns) as f64 / 1_000_000.0;
    }
    let last = bucket_count - 1;
    for meta in packets {
        let rel_ns = (stamp_ns(meta) - min_ns).max(0);
        let slot = ((rel_ns / width_ns) as usize).min(last);
        let bucket = &mut buckets[slot];
        bucket.packets += 1;
        bucket.bytes += meta.orig_len as u64;
        match transport_class(meta) {
            TransportClass::Tcp => bucket.tcp_packets += 1,
            TransportClass::Udp => bucket.udp_packets += 1,
            TransportClass::Other => bucket.other_packets += 1,
        }
    }
    IoGraphWire {
        packet_count: packets.len(),
        bucket_count,
        bucket_width_ms: width_ns as f64 / 1_000_000.0,
        total_bytes,
        buckets,
    }
}

/// Address-family classification from the dissector's presentation strings:
/// formatted IPv6 always contains ':', IPv4 is a strict dotted quad. ARP
/// sender/target IPs therefore count as IPv4 endpoints, like Wireshark.
fn ip_family(address: &str) -> Option<&'static str> {
    if address.contains(':') {
        return Some("ip6");
    }
    let octets: Vec<&str> = address.split('.').collect();
    let dotted_quad = octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u16>().map(|value| value <= 255).unwrap_or(false)
        });
    dotted_quad.then_some("ip4")
}

/// Ethernet dissection prefixes every frame with the "Ethernet II" layer
/// whose value is "src → dst"; MAC endpoints come only from that layer when
/// the capture actually carries one (raw-IP/SLL captures contribute none).
fn ethernet_mac_pair(meta: &PacketMeta) -> Option<(String, String)> {
    let layer = meta.dissected.layers.first()?;
    if layer.label != "Ethernet II" {
        return None;
    }
    let (source, destination) = layer.value.split_once(" → ")?;
    Some((source.to_string(), destination.to_string()))
}

#[derive(Default)]
struct EndpointAgg {
    family: &'static str,
    packets_out: u64,
    bytes_out: u64,
    packets_in: u64,
    bytes_in: u64,
}

/// Capture-wide endpoint aggregation in one bounded pass. Distinct endpoints
/// are structurally capped at 2 × MAX_CAPTURE_PACKETS; the returned rows are
/// the byte-heaviest ≤ ENDPOINTS_MAX_ROWS, ties broken by address for stable
/// output.
pub(super) fn endpoints_of(packets: &[PacketMeta]) -> EndpointsWire {
    let mut map: HashMap<String, EndpointAgg> = HashMap::new();
    let record = |map: &mut HashMap<String, EndpointAgg>,
                      address: &str,
                      family: Option<&'static str>,
                      talker: bool,
                      bytes: u64| {
        let Some(family) = family else { return };
        let entry = map
            .entry(address.to_string())
            .or_insert_with(|| EndpointAgg {
                family,
                ..Default::default()
            });
        if talker {
            entry.packets_out += 1;
            entry.bytes_out += bytes;
        } else {
            entry.packets_in += 1;
            entry.bytes_in += bytes;
        }
    };
    for meta in packets {
        let bytes = meta.orig_len as u64;
        record(
            &mut map,
            &meta.dissected.source,
            ip_family(&meta.dissected.source),
            true,
            bytes,
        );
        record(
            &mut map,
            &meta.dissected.destination,
            ip_family(&meta.dissected.destination),
            false,
            bytes,
        );
        if let Some((source, destination)) = ethernet_mac_pair(meta) {
            record(&mut map, &source, Some("mac"), true, bytes);
            record(&mut map, &destination, Some("mac"), false, bytes);
        }
    }
    let mut rows: Vec<EndpointRowWire> = map
        .into_iter()
        .map(|(address, agg)| EndpointRowWire {
            packets: agg.packets_in + agg.packets_out,
            bytes: agg.bytes_in + agg.bytes_out,
            address,
            family: agg.family.to_string(),
            packets_out: agg.packets_out,
            bytes_out: agg.bytes_out,
            packets_in: agg.packets_in,
            bytes_in: agg.bytes_in,
        })
        .collect();
    rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.address.cmp(&b.address)));
    let endpoint_count = rows.len();
    let truncated = endpoint_count > ENDPOINTS_MAX_ROWS;
    rows.truncate(ENDPOINTS_MAX_ROWS);
    EndpointsWire {
        packet_count: packets.len(),
        endpoint_count,
        truncated,
        rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_packet::{Dissected, Layer, TcpMeta};

    /// PacketMeta in the µs subsecond scale (pcap files without the ns magic).
    fn meta_at(ms: u64, orig_len: usize, dissected: Dissected) -> PacketMeta {
        PacketMeta {
            offset: 0,
            incl_len: orig_len,
            orig_len,
            ts_sec: ms / 1000,
            ts_subsec: ((ms % 1000) * 1_000) as u32,
            dissected,
        }
    }

    /// Same, but subseconds stated in nanoseconds (pcap ns magic).
    fn ns_meta_at(ms: u64, orig_len: usize, dissected: Dissected) -> PacketMeta {
        PacketMeta {
            offset: 0,
            incl_len: orig_len,
            orig_len,
            ts_sec: ms / 1000,
            ts_subsec: ((ms % 1000) * 1_000_000) as u32,
            dissected,
        }
    }

    fn udp_dissected() -> Dissected {
        Dissected {
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            protocol: "UDP".into(),
            info: String::new(),
            color_hint: "udp".into(),
            layers: vec![Layer {
                label: "User Datagram Protocol".into(),
                value: String::new(),
            }],
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        }
    }

    fn tcp_dissected() -> Dissected {
        Dissected {
            tcp: Some(TcpMeta {
                source_port: 443,
                destination_port: 5000,
                sequence: 0,
                flags: 0x10,
            }),
            protocol: "TCP".into(),
            layers: vec![Layer {
                label: "Transmission Control Protocol".into(),
                value: String::new(),
            }],
            ..udp_dissected()
        }
    }

    fn other_dissected() -> Dissected {
        Dissected {
            protocol: "ARP".into(),
            color_hint: "arp".into(),
            layers: Vec::new(),
            ..udp_dissected()
        }
    }

    #[test]
    fn io_graph_empty_capture_yields_no_buckets_and_zero_totals() {
        let wire = io_graph_of(&[], false);
        assert_eq!(wire.packet_count, 0);
        assert_eq!(wire.bucket_count, 0);
        assert_eq!(wire.total_bytes, 0);
        assert!(wire.buckets.is_empty());
    }

    #[test]
    fn io_graph_single_packet_lands_in_one_exact_bucket() {
        let packets = vec![meta_at(0, 1234, udp_dissected())];
        let wire = io_graph_of(&packets, false);
        assert_eq!(wire.packet_count, 1);
        assert_eq!(wire.bucket_count, 1);
        assert!((wire.bucket_width_ms - 1.0).abs() < 1e-9);
        assert_eq!(wire.buckets[0].packets, 1);
        assert_eq!(wire.buckets[0].bytes, 1234);
        assert_eq!(wire.buckets[0].udp_packets, 1);
        assert_eq!(wire.buckets[0].tcp_packets, 0);
        assert_eq!(wire.buckets[0].other_packets, 0);
        assert_eq!(wire.total_bytes, 1234);
    }

    #[test]
    fn io_graph_span_wider_than_the_cap_is_capped_at_120_buckets() {
        // Two packets 2000 s apart: width = span/120, count = 120.
        let packets = vec![
            meta_at(0, 100, udp_dissected()),
            meta_at(2_000_000, 200, tcp_dissected()),
        ];
        let wire = io_graph_of(&packets, false);
        assert_eq!(wire.bucket_count, IO_GRAPH_MAX_BUCKETS);
        assert!((wire.bucket_width_ms - 2_000_000.0 / 120.0).abs() < 1e-6);
        assert_eq!(wire.buckets[0].packets, 1);
        assert_eq!(wire.buckets[0].udp_packets, 1);
        // The packet at the exact last instant shares the final bucket.
        let last = &wire.buckets[IO_GRAPH_MAX_BUCKETS - 1];
        assert_eq!(last.packets, 1);
        assert_eq!(last.tcp_packets, 1);
        assert_eq!(wire.total_bytes, 300);
    }

    #[test]
    fn io_graph_short_span_uses_the_one_ms_bucket_floor() {
        // A 60 ms span would give a 0.5 ms width at 120 buckets; the 1 ms
        // floor yields 61 exact one-millisecond buckets instead.
        let packets = vec![
            meta_at(0, 10, udp_dissected()),
            meta_at(60, 20, udp_dissected()),
        ];
        let wire = io_graph_of(&packets, false);
        assert_eq!(wire.bucket_count, 61);
        assert!((wire.bucket_width_ms - 1.0).abs() < 1e-9);
        assert_eq!(wire.buckets[0].bytes, 10);
        assert_eq!(wire.buckets[60].bytes, 20);
    }

    #[test]
    fn io_graph_timestamp_scale_follows_the_source_file() {
        // Subseconds read as ns: two packets 50 ms apart → 51 one-ms buckets.
        // Misreading them as µs would inflate the span by 1000x.
        let packets = vec![
            ns_meta_at(0, 10, udp_dissected()),
            ns_meta_at(50, 10, udp_dissected()),
        ];
        let wire = io_graph_of(&packets, true);
        assert_eq!(wire.bucket_count, 51);
        assert!((wire.bucket_width_ms - 1.0).abs() < 1e-9);
        let wire = io_graph_of(&packets, false);
        assert_eq!(wire.bucket_count, IO_GRAPH_MAX_BUCKETS);
    }

    #[test]
    fn io_graph_byte_and_packet_sums_are_exact_per_bucket() {
        let packets = vec![
            meta_at(0, 1, tcp_dissected()),
            meta_at(1, 2, udp_dissected()),
            meta_at(2, 3, udp_dissected()),
            meta_at(3, 4, other_dissected()),
            meta_at(4, 5, other_dissected()),
        ];
        let wire = io_graph_of(&packets, false);
        let sum = |get: fn(&IoBucketWire) -> u64| -> u64 {
            wire.buckets.iter().map(get).sum()
        };
        assert_eq!(sum(|b| b.packets), 5);
        assert_eq!(sum(|b| b.bytes), 15);
        assert_eq!(sum(|b| b.tcp_packets), 1);
        assert_eq!(sum(|b| b.udp_packets), 2);
        assert_eq!(sum(|b| b.other_packets), 2);
        for (index, bucket) in wire.buckets.iter().enumerate() {
            assert_eq!(bucket.bytes, (index + 1) as u64);
            assert_eq!(bucket.packets, 1);
        }
    }

    /// Ethernet ARP frame: sender aa:bb:cc:dd:ee:ff / 192.168.1.24 asks for
    /// 192.168.1.1 behind dst 00:11:22:33:44:55.
    fn arp_ethernet_frame(orig_len: usize) -> PacketMeta {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        let mut arp = Vec::new();
        arp.extend_from_slice(&1u16.to_be_bytes());
        arp.extend_from_slice(&0x0800u16.to_be_bytes());
        arp.push(6);
        arp.push(4);
        arp.extend_from_slice(&1u16.to_be_bytes());
        arp.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        arp.extend_from_slice(&[192, 168, 1, 24]);
        arp.extend_from_slice(&[0u8; 6]);
        arp.extend_from_slice(&[192, 168, 1, 1]);
        frame.extend_from_slice(&arp);
        PacketMeta {
            offset: 0,
            incl_len: orig_len,
            orig_len,
            ts_sec: 0,
            ts_subsec: 0,
            dissected: cyberdeck_packet::dissect(1, &frame),
        }
    }

    /// Ethernet UDP frame between the same two hosts.
    fn udp_ethernet_frame(orig_len: usize) -> PacketMeta {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        ip.extend_from_slice(&[192, 168, 1, 24]);
        ip.extend_from_slice(&[192, 168, 1, 1]);
        let mut udp = Vec::new();
        udp.extend_from_slice(&5000u16.to_be_bytes());
        udp.extend_from_slice(&5000u16.to_be_bytes());
        udp.extend_from_slice(&8u16.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        ip[2..4].copy_from_slice(&(20 + udp.len() as u16).to_be_bytes());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&udp);
        PacketMeta {
            offset: 0,
            incl_len: orig_len,
            orig_len,
            ts_sec: 0,
            ts_subsec: 0,
            dissected: cyberdeck_packet::dissect(1, &frame),
        }
    }

    #[test]
    fn endpoints_aggregate_real_dissected_frames_by_family_with_talker_directions() {
        let packets = vec![
            arp_ethernet_frame(42),
            udp_ethernet_frame(42),
        ];
        let wire = endpoints_of(&packets);
        assert_eq!(wire.packet_count, 2);
        assert_eq!(wire.endpoint_count, 4);
        assert!(!wire.truncated);
        let by_address = |address: &str| -> &EndpointRowWire {
            wire.rows
                .iter()
                .find(|row| row.address == address)
                .unwrap_or_else(|| panic!("missing endpoint {address}"))
        };
        let talker = by_address("192.168.1.24");
        assert_eq!(talker.family, "ip4");
        assert_eq!(talker.packets, 2);
        assert_eq!(talker.bytes, 84);
        assert_eq!(talker.packets_out, 2);
        assert_eq!(talker.bytes_out, 84);
        assert_eq!(talker.packets_in, 0);
        assert_eq!(talker.bytes_in, 0);
        let receiver = by_address("192.168.1.1");
        assert_eq!(receiver.packets_in, 2);
        assert_eq!(receiver.bytes_in, 84);
        assert_eq!(receiver.packets_out, 0);
        let src_mac = by_address("aa:bb:cc:dd:ee:ff");
        assert_eq!(src_mac.family, "mac");
        assert_eq!(src_mac.bytes_out, 84);
        assert_eq!(src_mac.bytes_in, 0);
        let dst_mac = by_address("00:11:22:33:44:55");
        assert_eq!(dst_mac.family, "mac");
        assert_eq!(dst_mac.bytes_in, 84);
        assert_eq!(dst_mac.bytes_out, 0);
    }

    /// Raw-IP (linktype 101) UDP-over-IPv6 frame: no Ethernet layer, so no
    /// MAC endpoints may be invented.
    fn udp_ipv6_frame(address_last_byte: u8, orig_len: usize) -> PacketMeta {
        let mut frame = vec![0x60, 0, 0, 0];
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.push(17);
        frame.push(64);
        let mut host = vec![0xfe, 0x80];
        host.extend_from_slice(&[0u8; 12]);
        host.push(0);
        host.push(address_last_byte);
        frame.extend_from_slice(&host);
        let mut peer = vec![0xfe, 0x80];
        peer.extend_from_slice(&[0u8; 12]);
        peer.push(0);
        peer.push(address_last_byte.wrapping_add(1));
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&5000u16.to_be_bytes());
        frame.extend_from_slice(&5000u16.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        PacketMeta {
            offset: 0,
            incl_len: orig_len,
            orig_len,
            ts_sec: 0,
            ts_subsec: 0,
            dissected: cyberdeck_packet::dissect(101, &frame),
        }
    }

    #[test]
    fn endpoints_cap_at_64_rows_sorted_by_bytes_desc_and_disclose_truncation() {
        let mut packets = vec![udp_ipv6_frame(1, 2000)];
        for index in 0..70u8 {
            packets.push(meta_at(
                0,
                1000 - index as usize,
                Dissected {
                    source: format!("10.0.0.{index}"),
                    destination: format!("10.0.1.{index}"),
                    ..udp_dissected()
                },
            ));
        }
        let wire = endpoints_of(&packets);
        assert_eq!(wire.packet_count, 71);
        assert_eq!(wire.endpoint_count, 142);
        assert!(wire.truncated);
        assert_eq!(wire.rows.len(), ENDPOINTS_MAX_ROWS);
        // The IPv6 frame yields both of its 2000-byte endpoints at the top
        // (ties broken by address), ahead of the heaviest IPv4 pair.
        assert_eq!(wire.rows[0].family, "ip6");
        assert_eq!(wire.rows[0].bytes, 2000);
        assert_eq!(wire.rows[1].family, "ip6");
        assert_eq!(wire.rows[1].bytes, 2000);
        assert_eq!(wire.rows[2].family, "ip4");
        assert_eq!(wire.rows[2].bytes, 1000);
        for pair in wire.rows.windows(2) {
            assert!(pair[0].bytes >= pair[1].bytes);
        }
        assert!(wire
            .rows
            .iter()
            .all(|row| matches!(row.family.as_str(), "ip4" | "ip6" | "mac")));
        // Raw-IP frames carry no Ethernet layer: no MAC endpoints exist.
        assert!(wire.rows.iter().all(|row| row.family != "mac"));
    }

    #[test]
    fn endpoints_empty_capture_is_an_empty_bounded_table() {
        let wire = endpoints_of(&[]);
        assert_eq!(wire.packet_count, 0);
        assert_eq!(wire.endpoint_count, 0);
        assert!(!wire.truncated);
        assert!(wire.rows.is_empty());
    }
}

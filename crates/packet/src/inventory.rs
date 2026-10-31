//! Bounded passive host and transport-flow inventory from offline packet metadata.
//! No active probing, traffic generation or remote interaction.
use crate::PacketMeta;
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr};

pub const MAX_INVENTORY_HOSTS: usize = 4096;
pub const MAX_INVENTORY_FLOWS: usize = 8192;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostObservation {
    pub address: String,
    pub first_packet_index: usize,
    pub last_packet_index: usize,
    pub packets_sent: usize,
    pub packets_received: usize,
    /// Captured frame bytes (including link headers); not IP payload size.
    pub captured_bytes_sent: u64,
    pub captured_bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowObservation {
    /// Native TCP session ID or UDP stream ID, not a reconstructed transport session.
    pub stream_id: String,
    pub first_packet_index: usize,
    pub last_packet_index: usize,
    pub packet_count: usize,
    pub captured_bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PassiveInventory {
    pub packets_scanned: usize,
    pub skipped_non_ip_packets: usize,
    pub hosts_limited: bool,
    pub flows_limited: bool,
    pub hosts: Vec<HostObservation>,
    pub flows: Vec<FlowObservation>,
}

/// Observe *only* source/destination pairs that both parse as actual IP addresses.
/// Capture rows are identified by their original zero-based packet index, and no
/// reassembled datagram is silently inserted or counted as a captured packet.
pub fn observe(packets: &[PacketMeta]) -> PassiveInventory {
    let mut hosts: BTreeMap<IpAddr, HostObservation> = BTreeMap::new();
    let mut flows: BTreeMap<String, FlowObservation> = BTreeMap::new();
    let mut skipped = 0usize;
    let mut hosts_limited = false;
    let mut flows_limited = false;

    for (index, packet) in packets.iter().enumerate() {
        let d = &packet.dissected;
        let (Ok(src), Ok(dst)) = (d.source.parse::<IpAddr>(), d.destination.parse::<IpAddr>())
        else {
            skipped += 1;
            continue;
        };
        let bytes = packet.incl_len as u64;
        let mut endpoints_recorded = true;
        for (ip, sending) in [(src, true), (dst, false)] {
            if !hosts.contains_key(&ip) && hosts.len() == MAX_INVENTORY_HOSTS {
                hosts_limited = true;
                endpoints_recorded = false;
                continue;
            }
            let h = hosts.entry(ip).or_insert_with(|| HostObservation {
                address: ip.to_string(),
                first_packet_index: index,
                last_packet_index: index,
                packets_sent: 0,
                packets_received: 0,
                captured_bytes_sent: 0,
                captured_bytes_received: 0,
            });
            h.last_packet_index = index;
            if sending {
                h.packets_sent = h.packets_sent.saturating_add(1);
                h.captured_bytes_sent = h.captured_bytes_sent.saturating_add(bytes);
            } else {
                h.packets_received = h.packets_received.saturating_add(1);
                h.captured_bytes_received = h.captured_bytes_received.saturating_add(bytes);
            }
        }

        // A flow must not reference a host omitted by the inventory limit.
        if !endpoints_recorded {
            continue;
        }
        let Some(stream_id) = d.stream_id.as_ref() else {
            continue;
        };
        if !stream_id.starts_with("tcp|") && !stream_id.starts_with("udp|") {
            continue;
        }
        if !flows.contains_key(stream_id) && flows.len() == MAX_INVENTORY_FLOWS {
            flows_limited = true;
            continue;
        }
        let flow = flows
            .entry(stream_id.clone())
            .or_insert_with(|| FlowObservation {
                stream_id: stream_id.clone(),
                first_packet_index: index,
                last_packet_index: index,
                packet_count: 0,
                captured_bytes: 0,
            });
        flow.last_packet_index = index;
        flow.packet_count = flow.packet_count.saturating_add(1);
        flow.captured_bytes = flow.captured_bytes.saturating_add(bytes);
    }
    PassiveInventory {
        packets_scanned: packets.len(),
        skipped_non_ip_packets: skipped,
        hosts_limited,
        flows_limited,
        hosts: hosts.into_values().collect(),
        flows: flows.into_values().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dissected, PacketMeta};

    fn packet(src: &str, dst: &str, id: Option<&str>, bytes: usize) -> PacketMeta {
        PacketMeta {
            offset: 0,
            incl_len: bytes,
            orig_len: bytes,
            ts_sec: 0,
            ts_subsec: 0,
            dissected: Dissected {
                source: src.into(),
                destination: dst.into(),
                protocol: "UDP".into(),
                info: String::new(),
                color_hint: String::new(),
                layers: vec![],
                stream_id: id.map(str::to_string),
                tcp: None,
                payload: vec![],
            },
        }
    }

    #[test]
    fn counts_both_directions_and_tracks_original_frame_indices() {
        let packets = vec![
            packet("192.0.2.1", "192.0.2.2", Some("udp|1:10|2:20"), 100),
            packet("192.0.2.2", "192.0.2.1", Some("udp|1:10|2:20"), 80),
            packet("192.0.2.1", "192.0.2.2", None, 64),
        ];
        let result = observe(&packets);
        assert_eq!(result.packets_scanned, 3);
        assert_eq!(result.hosts.len(), 2);
        let a = &result.hosts[0];
        assert_eq!(a.address, "192.0.2.1");
        assert_eq!((a.packets_sent, a.packets_received), (2, 1));
        assert_eq!(
            (a.captured_bytes_sent, a.captured_bytes_received),
            (164, 80)
        );
        assert_eq!((a.first_packet_index, a.last_packet_index), (0, 2));
        assert_eq!(result.flows.len(), 1);
        assert_eq!(result.flows[0].packet_count, 2);
        assert_eq!(result.flows[0].captured_bytes, 180);
    }

    #[test]
    fn ipv6_addresses_are_canonical_and_never_invented_from_mac_or_invalid_rows() {
        let packets = vec![
            packet("2001:0db8::0001", "2001:db8::2", Some("tcp|v6#1"), 70),
            packet("aa:bb:cc:dd:ee:ff", "2001:db8::3", Some("tcp|bad#1"), 50),
            packet("", "", None, 0),
        ];
        let observed = observe(&packets);
        assert_eq!(observed.hosts.len(), 2);
        assert_eq!(observed.hosts[0].address, "2001:db8::1");
        assert_eq!(observed.skipped_non_ip_packets, 2);
        assert_eq!(observed.flows.len(), 1);
    }

    #[test]
    fn same_address_counts_sent_and_received_without_duplicate_hosts() {
        let observed = observe(&[packet("127.0.0.1", "127.0.0.1", Some("udp|loop"), 42)]);
        assert_eq!(observed.hosts.len(), 1);
        assert_eq!(observed.hosts[0].packets_sent, 1);
        assert_eq!(observed.hosts[0].packets_received, 1);
    }

    #[test]
    fn invalid_transport_ids_are_not_reported_as_flows() {
        let observed = observe(&[
            packet("192.0.2.1", "192.0.2.2", Some("malformed"), 70),
            packet("192.0.2.1", "192.0.2.2", None, 70),
        ]);
        assert!(observed.flows.is_empty());
        assert_eq!(observed.hosts.len(), 2);
    }

    #[test]
    fn inventory_bounds_do_not_drop_already_known_hosts() {
        let mut packets = Vec::new();
        for n in 0..(MAX_INVENTORY_HOSTS + 1) {
            let a = std::net::Ipv4Addr::from(n as u32 + 1).to_string();
            packets.push(packet(&a, "198.51.100.1", None, 50));
        }
        packets.push(packet("0.0.0.1", "198.51.100.1", None, 50));
        let result = observe(&packets);
        assert!(result.hosts_limited);
        assert_eq!(result.hosts.len(), MAX_INVENTORY_HOSTS);
        assert_eq!(result.packets_scanned, MAX_INVENTORY_HOSTS + 2);
        assert_eq!(
            result
                .hosts
                .iter()
                .find(|h| h.address == "0.0.0.1")
                .unwrap()
                .packets_sent,
            2
        );
    }
    #[test]
    fn inventory_flow_limit_preserves_previously_seen_flow_counters() {
        let mut packets = Vec::with_capacity(MAX_INVENTORY_FLOWS + 2);
        for n in 0..(MAX_INVENTORY_FLOWS + 1) {
            let id = format!("udp|a:{n}|b:53");
            packets.push(packet("192.0.2.1", "192.0.2.2", Some(&id), 60));
        }
        packets.push(packet("192.0.2.1", "192.0.2.2", Some("udp|a:0|b:53"), 40));
        let observed = observe(&packets);
        assert_eq!(observed.flows.len(), MAX_INVENTORY_FLOWS);
        assert!(observed.flows_limited);
        assert_eq!(observed.packets_scanned, MAX_INVENTORY_FLOWS + 2);
        let existing = observed
            .flows
            .iter()
            .find(|flow| flow.stream_id == "udp|a:0|b:53")
            .expect("first flow is retained");
        assert_eq!(existing.packet_count, 2);
        assert_eq!(existing.captured_bytes, 100);
        assert_eq!(existing.last_packet_index, MAX_INVENTORY_FLOWS + 1);
    }

    #[test]
    fn host_limit_never_creates_orphaned_flows_without_known_endpoints() {
        let mut packets = Vec::new();
        for n in 0..(MAX_INVENTORY_HOSTS - 1) {
            let ip = std::net::Ipv4Addr::from(n as u32 + 1).to_string();
            packets.push(packet(&ip, "198.51.100.1", None, 50));
        }
        packets.push(packet("192.0.2.1", "198.51.100.1", Some("udp|orphan"), 60));
        packets.push(packet("0.0.0.1", "198.51.100.1", Some("udp|existing"), 40));
        let observed = observe(&packets);
        assert!(observed.hosts_limited);
        assert_eq!(observed.hosts.len(), MAX_INVENTORY_HOSTS);
        assert!(observed.flows.iter().all(|flow| flow.stream_id != "udp|orphan"));
        assert!(observed.flows.iter().any(|flow| flow.stream_id == "udp|existing"));
    }

}

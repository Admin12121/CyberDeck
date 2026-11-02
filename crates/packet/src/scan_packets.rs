//! Independently authored bounded network-layer probe packet builders.
//! No sockets, elevated operations, hidden traffic or target enumeration.
//! The caller must independently verify scope, local interface/source address,
//! routing, authorization, per-host rate limits and cancellation *before* send.
//! The returned bytes are NOT confirmation that any probe was transmitted.
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketBuildError {
    InvalidAddress,
    InvalidHopLimit,
    InvalidPort,
    InvalidMac,
}

/// RFC 1071 one's complement checksum. Each fragment is explicitly even
/// length, so there is no cross-fragment odd-byte ambiguity.
fn checksum(even_chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for chunk in even_chunks {
        debug_assert!(chunk.len() % 2 == 0);
        for word in chunk.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn valid_ipv4_source(source: Ipv4Addr) -> bool {
    !source.is_unspecified() && !source.is_multicast() && !source.is_broadcast()
}
fn valid_ipv4_target(target: Ipv4Addr) -> bool {
    !target.is_unspecified() && !target.is_multicast() && !target.is_broadcast()
}
fn valid_ipv6(source: Ipv6Addr) -> bool {
    !source.is_unspecified() && !source.is_multicast()
}
fn valid_hop(hop: u8) -> bool {
    hop != 0
}
fn ipv4_header(
    source: Ipv4Addr,
    target: Ipv4Addr,
    length: u16,
    protocol: u8,
    identification: u16,
    hop_limit: u8,
) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&length.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // do not fragment
    header[8] = hop_limit;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&target.octets());
    let sum = checksum(&[&header]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    header
}
fn tcp_syn(local_port: u16, remote_port: u16, initial_sequence: u32) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[0..2].copy_from_slice(&local_port.to_be_bytes());
    header[2..4].copy_from_slice(&remote_port.to_be_bytes());
    header[4..8].copy_from_slice(&initial_sequence.to_be_bytes());
    header[12] = 0x50; // fixed 20-byte header, no TCP options
    header[13] = 0x02; // SYN, no other flags
    header[14..16].copy_from_slice(&64240u16.to_be_bytes());
    header
}
fn valid_ports(local: u16, target: u16) -> bool {
    local != 0 && target != 0
}

/// 40-byte IPv4/TCP SYN datagram. Does not spoof source identities: the caller
/// must prove that source is assigned to the selected route/interface.
pub fn ipv4_tcp_syn(
    source: Ipv4Addr,
    target: Ipv4Addr,
    local_port: u16,
    target_port: u16,
    initial_sequence: u32,
    identification: u16,
    hop_limit: u8,
) -> Result<[u8; 40], PacketBuildError> {
    if !valid_ipv4_source(source) || !valid_ipv4_target(target) {
        return Err(PacketBuildError::InvalidAddress);
    }
    if !valid_ports(local_port, target_port) {
        return Err(PacketBuildError::InvalidPort);
    }
    if !valid_hop(hop_limit) {
        return Err(PacketBuildError::InvalidHopLimit);
    }
    let mut packet = [0u8; 40];
    packet[..20].copy_from_slice(&ipv4_header(
        source,
        target,
        40,
        6,
        identification,
        hop_limit,
    ));
    let mut tcp = tcp_syn(local_port, target_port, initial_sequence);
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&source.octets());
    pseudo[4..8].copy_from_slice(&target.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
    let value = checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&value.to_be_bytes());
    packet[20..].copy_from_slice(&tcp);
    Ok(packet)
}

/// 60-byte IPv6/TCP SYN packet, excluding link-layer framing.
pub fn ipv6_tcp_syn(
    source: Ipv6Addr,
    target: Ipv6Addr,
    local_port: u16,
    target_port: u16,
    initial_sequence: u32,
    hop_limit: u8,
) -> Result<[u8; 60], PacketBuildError> {
    if !valid_ipv6(source) || !valid_ipv6(target) {
        return Err(PacketBuildError::InvalidAddress);
    }
    if !valid_ports(local_port, target_port) {
        return Err(PacketBuildError::InvalidPort);
    }
    if !valid_hop(hop_limit) {
        return Err(PacketBuildError::InvalidHopLimit);
    }
    let mut packet = [0u8; 60];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&20u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&target.octets());
    let mut tcp = tcp_syn(local_port, target_port, initial_sequence);
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&source.octets());
    pseudo[16..32].copy_from_slice(&target.octets());
    pseudo[32..36].copy_from_slice(&20u32.to_be_bytes());
    pseudo[39] = 6;
    let sum = checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    packet[40..].copy_from_slice(&tcp);
    Ok(packet)
}

/// IPv4 ICMP echo datagram for explicitly scoped unicast host discovery.
pub fn ipv4_icmp_echo(
    source: Ipv4Addr,
    target: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    identification: u16,
    hop_limit: u8,
) -> Result<[u8; 28], PacketBuildError> {
    if !valid_ipv4_source(source) || !valid_ipv4_target(target) {
        return Err(PacketBuildError::InvalidAddress);
    }
    if !valid_hop(hop_limit) {
        return Err(PacketBuildError::InvalidHopLimit);
    }
    let mut bytes = [0u8; 28];
    bytes[..20].copy_from_slice(&ipv4_header(
        source,
        target,
        28,
        1,
        identification,
        hop_limit,
    ));
    bytes[20] = 8;
    bytes[24..26].copy_from_slice(&identifier.to_be_bytes());
    bytes[26..28].copy_from_slice(&sequence.to_be_bytes());
    let sum = checksum(&[&bytes[20..28]]);
    bytes[22..24].copy_from_slice(&sum.to_be_bytes());
    Ok(bytes)
}

/// Ethernet ARP request for an already-authorized *on-link* IPv4 neighbor.
/// The sender MAC must be the real selected local interface, never a guessed
/// identity. The target is a single unicast address, not a multicast range.
pub fn ethernet_arp_request(
    sender_mac: [u8; 6],
    source: Ipv4Addr,
    target: Ipv4Addr,
) -> Result<[u8; 42], PacketBuildError> {
    if !valid_ipv4_source(source) || !valid_ipv4_target(target) {
        return Err(PacketBuildError::InvalidAddress);
    }
    if sender_mac == [0; 6] || sender_mac[0] & 1 != 0 {
        return Err(PacketBuildError::InvalidMac);
    }
    let mut bytes = [0u8; 42];
    bytes[..6].fill(0xff); // Ethernet broadcast for ARP
    bytes[6..12].copy_from_slice(&sender_mac);
    bytes[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    bytes[14..16].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    bytes[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    bytes[18] = 6;
    bytes[19] = 4;
    bytes[20..22].copy_from_slice(&1u16.to_be_bytes()); // request
    bytes[22..28].copy_from_slice(&sender_mac);
    bytes[28..32].copy_from_slice(&source.octets());
    bytes[38..42].copy_from_slice(&target.octets());
    Ok(bytes)
}

/// IPv6 ICMP echo packet with the mandatory IPv6 pseudoheader checksum.
/// Only an explicitly authorized unicast target is accepted.
pub fn ipv6_icmp_echo(
    source: Ipv6Addr,
    target: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    hop_limit: u8,
) -> Result<[u8; 48], PacketBuildError> {
    if !valid_ipv6(source) || !valid_ipv6(target) {
        return Err(PacketBuildError::InvalidAddress);
    }
    if !valid_hop(hop_limit) {
        return Err(PacketBuildError::InvalidHopLimit);
    }
    let mut packet = [0u8; 48];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    packet[6] = 58;
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&target.octets());
    packet[40] = 128; // ICMPv6 Echo Request
    packet[44..46].copy_from_slice(&identifier.to_be_bytes());
    packet[46..48].copy_from_slice(&sequence.to_be_bytes());
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&source.octets());
    pseudo[16..32].copy_from_slice(&target.octets());
    pseudo[32..36].copy_from_slice(&8u32.to_be_bytes());
    pseudo[39] = 58;
    let sum = checksum(&[&pseudo, &packet[40..]]);
    packet[42..44].copy_from_slice(&sum.to_be_bytes());
    Ok(packet)
}

/// RFC 4861 IPv6 Neighbor Solicitation on an explicitly confirmed on-link
/// interface. The destination multicast MAC and IPv6 address are derived
/// strictly from the single requested neighbor, not from a user supplied
/// multicast target. Fixed Ethernet II + IPv6 + ICMPv6 NS + source MAC option.
pub fn ethernet_ipv6_neighbor_solicitation(
    sender_mac: [u8; 6],
    source: Ipv6Addr,
    neighbor: Ipv6Addr,
) -> Result<[u8; 86], PacketBuildError> {
    if !valid_ipv6(source) || !valid_ipv6(neighbor) {
        return Err(PacketBuildError::InvalidAddress);
    }
    if sender_mac == [0; 6] || sender_mac[0] & 1 != 0 {
        return Err(PacketBuildError::InvalidMac);
    }
    let octets = neighbor.octets();
    let mut target = [0u8; 16];
    target[0] = 0xff;
    target[1] = 0x02;
    target[11] = 0x01;
    target[12] = 0xff;
    target[13..16].copy_from_slice(&octets[13..16]);

    let mut frame = [0u8; 86];
    frame[..6].copy_from_slice(&[0x33, 0x33, 0xff, octets[13], octets[14], octets[15]]);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&32u16.to_be_bytes());
    frame[20] = 58;
    frame[21] = 255; // mandatory for IPv6 Neighbor Discovery
    frame[22..38].copy_from_slice(&source.octets());
    frame[38..54].copy_from_slice(&target);
    frame[54] = 135; // Neighbor Solicitation
    frame[62..78].copy_from_slice(&octets); // target of question
    frame[78] = 1; // source link-layer address option
    frame[79] = 1; // 1 * 8 bytes
    frame[80..86].copy_from_slice(&sender_mac);
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&source.octets());
    pseudo[16..32].copy_from_slice(&target);
    pseudo[32..36].copy_from_slice(&32u32.to_be_bytes());
    pseudo[39] = 58;
    let sum = checksum(&[&pseudo, &frame[54..]]);
    frame[56..58].copy_from_slice(&sum.to_be_bytes());
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_echo_checksum_matches_ipv6_pseudoheader() {
        let local: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let target: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = ipv6_icmp_echo(local, target, 11, 12, 9).unwrap();
        assert_eq!(packet.len(), 48);
        assert_eq!(packet[6], 58);
        assert_eq!(packet[7], 9);
        assert_eq!(&packet[4..6], &8u16.to_be_bytes());
        assert_eq!(packet[40], 128);
        assert_eq!(&packet[44..48], &[0, 11, 0, 12]);
        let mut pseudo = [0u8; 40];
        pseudo[..16].copy_from_slice(&local.octets());
        pseudo[16..32].copy_from_slice(&target.octets());
        pseudo[32..36].copy_from_slice(&8u32.to_be_bytes());
        pseudo[39] = 58;
        assert_eq!(checksum(&[&pseudo, &packet[40..]]), 0);
    }

    #[test]
    fn neighbor_solicitation_is_single_target_and_has_valid_checksum() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let local: Ipv6Addr = "fe80::1".parse().unwrap();
        let neighbor: Ipv6Addr = "fe80::1234:5678".parse().unwrap();
        let frame = ethernet_ipv6_neighbor_solicitation(mac, local, neighbor).unwrap();
        assert_eq!(frame.len(), 86);
        assert_eq!(&frame[..6], &[0x33, 0x33, 0xff, 0x34, 0x56, 0x78]);
        assert_eq!(&frame[12..14], &0x86ddu16.to_be_bytes());
        assert_eq!(frame[20], 58);
        assert_eq!(frame[21], 255);
        assert_eq!(frame[54], 135);
        assert_eq!(&frame[62..78], &neighbor.octets());
        assert_eq!(&frame[78..80], &[1, 1]);
        assert_eq!(&frame[80..86], &mac);
        let mut pseudo = [0u8; 40];
        pseudo[..16].copy_from_slice(&local.octets());
        pseudo[16..32].copy_from_slice(&frame[38..54]);
        pseudo[32..36].copy_from_slice(&32u32.to_be_bytes());
        pseudo[39] = 58;
        assert_eq!(checksum(&[&pseudo, &frame[54..]]), 0);
        assert!(ethernet_ipv6_neighbor_solicitation([1, 0, 0, 0, 0, 0], local, neighbor).is_err());
        assert!(ethernet_ipv6_neighbor_solicitation(mac, Ipv6Addr::UNSPECIFIED, neighbor).is_err());
    }

    #[test]
    fn ipv4_syn_headers_and_both_checksums_are_correct() {
        let local: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let target: Ipv4Addr = "192.0.2.2".parse().unwrap();
        let packet = ipv4_tcp_syn(local, target, 40000, 443, 0x12345678, 7, 64).unwrap();
        assert_eq!(packet.len(), 40);
        assert_eq!(packet[0], 0x45);
        assert_eq!(&packet[2..4], &40u16.to_be_bytes());
        assert_eq!(packet[8], 64);
        assert_eq!(packet[9], 6);
        assert_eq!(packet[33], 2); // SYN only
        assert_eq!(checksum(&[&packet[..20]]), 0);
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&local.octets());
        pseudo[4..8].copy_from_slice(&target.octets());
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(checksum(&[&pseudo, &packet[20..]]), 0);
        let mut corrupted = packet;
        corrupted[39] ^= 1;
        assert_ne!(checksum(&[&pseudo, &corrupted[20..]]), 0);
    }

    #[test]
    fn ipv6_syn_uses_correct_pseudoheader_and_fixed_hop_limit() {
        let local: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let target: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = ipv6_tcp_syn(local, target, 49152, 22, 42, 42).unwrap();
        assert_eq!(packet.len(), 60);
        assert_eq!(packet[0], 0x60);
        assert_eq!(packet[6], 6);
        assert_eq!(packet[7], 42);
        assert_eq!(&packet[4..6], &20u16.to_be_bytes());
        assert_eq!(&packet[40..42], &49152u16.to_be_bytes());
        assert_eq!(packet[53], 2);
        let mut pseudo = [0u8; 40];
        pseudo[..16].copy_from_slice(&local.octets());
        pseudo[16..32].copy_from_slice(&target.octets());
        pseudo[32..36].copy_from_slice(&20u32.to_be_bytes());
        pseudo[39] = 6;
        assert_eq!(checksum(&[&pseudo, &packet[40..]]), 0);
    }

    #[test]
    fn icmp_echo_has_independent_ip_and_icmp_checksums() {
        let bytes = ipv4_icmp_echo(
            "198.51.100.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
            0xdead,
            0x1234,
            1,
            3,
        )
        .unwrap();
        assert_eq!(bytes.len(), 28);
        assert_eq!(bytes[8], 3);
        assert_eq!(bytes[9], 1);
        assert_eq!(bytes[20], 8);
        assert_eq!(&bytes[24..26], &0xdeadu16.to_be_bytes());
        assert_eq!(checksum(&[&bytes[..20]]), 0);
        assert_eq!(checksum(&[&bytes[20..]]), 0);
    }

    #[test]
    fn arp_request_is_ethernet_broadcast_but_targets_only_one_ipv4_host() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let frame = ethernet_arp_request(
            mac,
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(&frame[..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &mac);
        assert_eq!(&frame[12..14], &0x0806u16.to_be_bytes());
        assert_eq!(&frame[20..22], &1u16.to_be_bytes());
        assert_eq!(&frame[22..28], &mac);
        assert_eq!(&frame[28..32], &[192, 0, 2, 1]);
        assert_eq!(&frame[32..38], &[0u8; 6]);
        assert_eq!(&frame[38..42], &[192, 0, 2, 2]);
    }

    #[test]
    fn packet_builders_refuse_non_unicast_addresses_zero_ports_and_hop() {
        assert_eq!(
            ipv4_tcp_syn(
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::LOCALHOST,
                40000,
                80,
                1,
                1,
                64
            ),
            Err(PacketBuildError::InvalidAddress)
        );
        assert_eq!(
            ipv4_tcp_syn(
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::BROADCAST,
                40000,
                80,
                1,
                1,
                64
            ),
            Err(PacketBuildError::InvalidAddress)
        );
        assert_eq!(
            ipv4_tcp_syn(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 0, 80, 1, 1, 64),
            Err(PacketBuildError::InvalidPort)
        );
        assert_eq!(
            ipv4_tcp_syn(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 40000, 80, 1, 1, 0),
            Err(PacketBuildError::InvalidHopLimit)
        );
        assert_eq!(
            ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST, 40000, 80, 1, 64),
            Err(PacketBuildError::InvalidAddress)
        );
        assert_eq!(
            ethernet_arp_request([0xff; 6], Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST),
            Err(PacketBuildError::InvalidMac)
        );
    }
}

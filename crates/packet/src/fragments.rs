//! Bounded, passive IPv4/IPv6 fragment reassembly. Original frames stay unchanged.
//! IPv6 walks bounded extension-header chains preceding the Fragment header
//! and preserves the unfragmentable prefix in derived datagrams.
//! Ambiguous overlaps and malformed fragments are never promoted to datagrams.

use serde::Serialize;
use std::collections::{HashMap, HashSet};

const MAX_ACTIVE_DATAGRAMS: usize = 64;
const MAX_COMPLETED_DATAGRAMS: usize = 128;
const MAX_FRAGMENTS_TOTAL: usize = 8192;
const MAX_FRAGMENTS_PER_DATAGRAM: usize = 128;
const MAX_DATAGRAM_BYTES: usize = 65_535;

#[derive(Debug, Clone, Serialize)]
pub struct ReassembledDatagram {
    pub ip_version: u8,
    pub identification: u32,
    pub first_packet_index: usize,
    pub last_packet_index: usize,
    /// Derived, checksum-corrected IP datagram; never a replacement for evidence.
    pub ip_packet: Vec<u8>,
    pub dissected: crate::Dissected,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReassemblyReport {
    pub completed: Vec<ReassembledDatagram>,
    pub incomplete: usize,
    pub conflicts: usize,
    pub malformed: usize,
    pub limited: bool,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct Key {
    version: u8,
    source: [u8; 16],
    destination: [u8; 16],
    id: u32,
    next: u8,
}

struct Piece<'a> {
    key: Key,
    offset: usize,
    more: bool,
    body: &'a [u8],
    first_header: Option<Vec<u8>>,
    ipv6_next_offset: usize,
}

enum Extract<'a> {
    Skip,
    Invalid,
    Fragment(Piece<'a>),
}

fn extract(linktype: u32, frame: &[u8]) -> Extract<'_> {
    let network = match linktype {
        101 => frame,
        1 if frame.len() >= 14 => {
            let mut cursor = 12usize;
            let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            cursor += 2;
            for _ in 0..2 {
                if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                    break;
                }
                let Some(tail) = frame.get(cursor..cursor + 4) else {
                    return Extract::Invalid;
                };
                ethertype = u16::from_be_bytes([tail[2], tail[3]]);
                cursor += 4;
            }
            if !matches!(ethertype, 0x0800 | 0x86dd) {
                return Extract::Skip;
            }
            &frame[cursor..]
        }
        113 if frame.len() >= 16 => {
            let ethertype = u16::from_be_bytes([frame[14], frame[15]]);
            if !matches!(ethertype, 0x0800 | 0x86dd) {
                return Extract::Skip;
            }
            &frame[16..]
        }
        _ => return Extract::Skip,
    };
    if network.is_empty() {
        return Extract::Skip;
    }
    match network[0] >> 4 {
        4 => ipv4_fragment(network),
        6 => ipv6_fragment(network),
        _ => Extract::Skip,
    }
}

fn ipv4_fragment(ip: &[u8]) -> Extract<'_> {
    if ip.len() < 20 {
        return Extract::Invalid;
    }
    let ihl = (ip[0] as usize & 0x0f) * 4;
    if ihl < 20 || ip.len() < ihl {
        return Extract::Invalid;
    }
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total < ihl || total > ip.len() {
        return Extract::Invalid;
    }
    let flags = u16::from_be_bytes([ip[6], ip[7]]);
    let offset = (flags as usize & 0x1fff) * 8;
    let more = flags & 0x2000 != 0;
    if offset == 0 && !more {
        return Extract::Skip;
    }
    if flags & 0x4000 != 0 {
        return Extract::Invalid;
    }
    let body = &ip[ihl..total];
    if body.is_empty() || (more && body.len() % 8 != 0) {
        return Extract::Invalid;
    }
    let Some(end) = offset.checked_add(body.len()) else {
        return Extract::Invalid;
    };
    if end > MAX_DATAGRAM_BYTES {
        return Extract::Invalid;
    }
    let mut source = [0u8; 16];
    let mut destination = [0u8; 16];
    source[..4].copy_from_slice(&ip[12..16]);
    destination[..4].copy_from_slice(&ip[16..20]);
    Extract::Fragment(Piece {
        key: Key {
            version: 4,
            source,
            destination,
            id: u16::from_be_bytes([ip[4], ip[5]]) as u32,
            next: ip[9],
        },
        offset,
        more,
        body,
        first_header: (offset == 0).then(|| ip[..ihl].to_vec()),
        ipv6_next_offset: 0,
    })
}

fn ipv6_fragment(ip: &[u8]) -> Extract<'_> {
    if ip.len() < 40 {
        return Extract::Invalid;
    }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    if payload_len == 0 && ip.len() > 40 {
        return Extract::Skip;
    }
    let Some(end) = 40usize.checked_add(payload_len) else {
        return Extract::Invalid;
    };
    if end > ip.len() {
        return Extract::Invalid;
    }
    let mut cursor = 40usize;
    let mut next = ip[6];
    let mut previous_next_offset = 6usize;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 | 51 => {
                let Some(prefix) = ip.get(cursor..cursor.saturating_add(2)) else {
                    return Extract::Invalid;
                };
                let length = if next == 51 {
                    (prefix[1] as usize + 2) * 4
                } else {
                    (prefix[1] as usize + 1) * 8
                };
                if cursor.checked_add(length).is_none_or(|p| p > end) {
                    return Extract::Invalid;
                }
                previous_next_offset = cursor;
                next = prefix[0];
                cursor += length;
            }
            44 => break,
            _ => return Extract::Skip,
        }
    }
    if next != 44 {
        return Extract::Invalid;
    }
    let Some(header) = ip.get(cursor..cursor.saturating_add(8)) else {
        return Extract::Invalid;
    };
    if cursor + 8 > end {
        return Extract::Invalid;
    }
    let raw = u16::from_be_bytes([header[2], header[3]]);
    if raw & 0x0006 != 0 {
        return Extract::Invalid;
    }
    let offset = (raw & 0xfff8) as usize;
    let more = raw & 1 != 0;
    if offset == 0 && !more {
        return Extract::Skip;
    }
    let body = &ip[cursor + 8..end];
    if body.is_empty() || (more && body.len() % 8 != 0) {
        return Extract::Invalid;
    }
    let Some(payload_end) = offset.checked_add(body.len()) else {
        return Extract::Invalid;
    };
    if payload_end > MAX_DATAGRAM_BYTES {
        return Extract::Invalid;
    }
    let mut source = [0u8; 16];
    let mut destination = [0u8; 16];
    source.copy_from_slice(&ip[8..24]);
    destination.copy_from_slice(&ip[24..40]);
    Extract::Fragment(Piece {
        key: Key {
            version: 6,
            source,
            destination,
            id: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            next: header[0],
        },
        offset,
        more,
        body,
        first_header: (offset == 0).then(|| ip[..cursor].to_vec()),
        ipv6_next_offset: previous_next_offset,
    })
}

struct Group {
    bytes: Vec<u8>,
    present: Vec<u8>,
    count: usize,
    highest_end: usize,
    pieces: usize,
    expected: Option<usize>,
    header: Option<Vec<u8>>,
    ipv6_next_offset: usize,
    first_index: usize,
    last_index: usize,
}

impl Group {
    fn new(index: usize) -> Self {
        Self {
            bytes: vec![0; MAX_DATAGRAM_BYTES],
            present: vec![0; MAX_DATAGRAM_BYTES],
            count: 0,
            highest_end: 0,
            pieces: 0,
            expected: None,
            header: None,
            ipv6_next_offset: 6,
            first_index: index,
            last_index: index,
        }
    }
    fn insert(&mut self, piece: &Piece<'_>, index: usize) -> Result<bool, ()> {
        self.pieces += 1;
        if self.pieces > MAX_FRAGMENTS_PER_DATAGRAM {
            return Err(());
        }
        let end = piece.offset.checked_add(piece.body.len()).ok_or(())?;
        if end > MAX_DATAGRAM_BYTES {
            return Err(());
        }
        if let Some(expected) = self.expected {
            if end > expected || (!piece.more && end != expected) {
                return Err(());
            }
        }
        if !piece.more {
            self.expected = Some(end);
            if self.highest_end > end {
                return Err(());
            }
        }
        if let Some(header) = &piece.first_header {
            if let Some(previous) = &self.header {
                if previous != header {
                    return Err(());
                }
            } else {
                self.header = Some(header.clone());
                self.ipv6_next_offset = piece.ipv6_next_offset;
            }
        }
        for (pos, &byte) in piece.body.iter().enumerate() {
            let i = piece.offset + pos;
            if self.present[i] != 0 {
                // IPv6 overlapping fragments must be discarded, even if identical.
                if piece.key.version == 6 || self.bytes[i] != byte {
                    return Err(());
                }
            } else {
                self.bytes[i] = byte;
                self.present[i] = 1;
                self.count += 1;
            }
        }
        self.highest_end = self.highest_end.max(end);
        self.first_index = self.first_index.min(index);
        self.last_index = self.last_index.max(index);
        Ok(self.expected.is_some_and(|end| self.count == end) && self.header.is_some())
    }
    fn finish(&self, key: Key) -> Option<Vec<u8>> {
        let mut header = self.header.clone()?;
        let end = self.expected?;
        let body = self.bytes.get(..end)?;
        if key.version == 4 {
            let total = header.len().checked_add(end)?;
            if total > u16::MAX as usize {
                return None;
            }
            header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            header[6..8].copy_from_slice(&[0, 0]);
            header[10..12].copy_from_slice(&[0, 0]);
            let mut sum = 0u32;
            for chunk in header.chunks_exact(2) {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            header[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        } else {
            let ipv6_payload_len = header.len().checked_sub(40)?.checked_add(end)?;
            if ipv6_payload_len > u16::MAX as usize {
                return None;
            }
            header[4..6].copy_from_slice(&(ipv6_payload_len as u16).to_be_bytes());
            *header.get_mut(self.ipv6_next_offset)? = key.next;
        }
        header.extend_from_slice(body);
        Some(header)
    }
}

/// Use one assembler per capture or capture section. This API does not change
/// original packet bytes, and no reassembled data is silently inserted into
/// TCP streams. Consumers must explicitly opt into derived datagrams.
pub struct FragmentReassembler {
    active: HashMap<Key, Group>,
    rejected: HashSet<Key>,
    report: ReassemblyReport,
    inspected: usize,
    blocked: bool,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self {
            active: HashMap::new(),
            rejected: HashSet::new(),
            report: ReassemblyReport::default(),
            inspected: 0,
            blocked: false,
        }
    }
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_frame(&mut self, linktype: u32, frame: &[u8], packet_index: usize) {
        if self.blocked || self.inspected >= MAX_FRAGMENTS_TOTAL {
            self.report.limited = true;
            return;
        }
        let piece = match extract(linktype, frame) {
            Extract::Skip => return,
            Extract::Invalid => {
                self.report.malformed += 1;
                return;
            }
            Extract::Fragment(p) => p,
        };
        self.inspected += 1;
        let key = piece.key;
        if self.rejected.contains(&key) {
            return;
        }
        if !self.active.contains_key(&key) && self.active.len() >= MAX_ACTIVE_DATAGRAMS {
            self.report.limited = true;
            return;
        }
        let state = self
            .active
            .entry(key)
            .or_insert_with(|| Group::new(packet_index));
        match state.insert(&piece, packet_index) {
            Err(_) => {
                self.active.remove(&key);
                self.report.conflicts += 1;
                if self.rejected.len() < MAX_ACTIVE_DATAGRAMS {
                    self.rejected.insert(key);
                } else {
                    // Do not re-accept an untracked, previously rejected
                    // datagram once poisoned-key capacity is exhausted.
                    self.report.limited = true;
                    self.blocked = true;
                }
            }
            Ok(true) => {
                let state = self.active.remove(&key).expect("inserted group");
                let Some(raw) = state.finish(key) else {
                    self.report.malformed += 1;
                    return;
                };
                if self.report.completed.len() == MAX_COMPLETED_DATAGRAMS {
                    self.report.limited = true;
                    return;
                }
                let dissected = crate::dissect(101, &raw);
                self.report.completed.push(ReassembledDatagram {
                    ip_version: key.version,
                    identification: key.id,
                    first_packet_index: state.first_index,
                    last_packet_index: state.last_index,
                    ip_packet: raw,
                    dissected,
                });
            }
            Ok(false) => {}
        }
    }

    /// End a PCAPNG section without mixing identical fragment IDs across sections.
    pub fn reset_section(&mut self) {
        self.report.incomplete += self.active.len();
        self.active.clear();
        self.rejected.clear();
        self.blocked = false;
    }

    pub fn finish(mut self) -> ReassemblyReport {
        self.report.incomplete += self.active.len();
        self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(id: u16, offset: usize, more: bool, body: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&id.to_be_bytes());
        let field = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
        ip.extend_from_slice(&field.to_be_bytes());
        ip.extend_from_slice(&[64, 17, 0, 0]);
        ip.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        ip.extend_from_slice(body);
        ip
    }

    fn v6(id: u32, offset: usize, more: bool, body: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[44, 64]);
        ip.extend_from_slice(&[0; 15]);
        ip.push(1);
        ip.extend_from_slice(&[0; 15]);
        ip.push(2);
        let flag = (offset as u16) | if more { 1 } else { 0 };
        ip.extend_from_slice(&[17, 0]);
        ip.extend_from_slice(&flag.to_be_bytes());
        ip.extend_from_slice(&id.to_be_bytes());
        ip.extend_from_slice(body);
        ip
    }

    fn udp() -> Vec<u8> {
        let mut b = vec![0x04, 0xd2, 0, 53, 0, 24, 0, 0];
        b.extend_from_slice(&[0x42; 16]);
        b
    }

    #[test]
    fn ipv4_out_of_order_fragments_reconstruct_only_when_complete() {
        let bytes = udp();
        let mut a = FragmentReassembler::new();
        a.push_frame(101, &v4(7, 16, false, &bytes[16..]), 2);
        a.push_frame(101, &v4(7, 0, true, &bytes[..16]), 1);
        let r = a.finish();
        assert_eq!(r.completed.len(), 1);
        assert_eq!(r.completed[0].ip_version, 4);
        assert_eq!(&r.completed[0].ip_packet[20..], &bytes);
        assert_eq!(r.completed[0].dissected.protocol, "DNS");
        assert_eq!(r.completed[0].first_packet_index, 1);
        assert_eq!(r.incomplete, 0);
    }

    #[test]
    fn ipv6_out_of_order_fragments_reconstruct_correctly() {
        let bytes = udp();
        let mut a = FragmentReassembler::new();
        a.push_frame(101, &v6(0x12345678, 16, false, &bytes[16..]), 3);
        a.push_frame(101, &v6(0x12345678, 0, true, &bytes[..16]), 2);
        let r = a.finish();
        assert_eq!(r.completed.len(), 1);
        assert_eq!(r.completed[0].ip_packet[6], 17);
        assert_eq!(&r.completed[0].ip_packet[40..], &bytes);
        assert_eq!(r.completed[0].dissected.protocol, "DNS");
    }

    #[test]
    fn overlap_conflicts_fail_closed() {
        let bytes = udp();
        let mut changed = bytes[..16].to_vec();
        changed[4] ^= 1;
        let mut a = FragmentReassembler::new();
        a.push_frame(101, &v4(8, 0, true, &bytes[..16]), 1);
        a.push_frame(101, &v4(8, 0, true, &changed), 2);
        a.push_frame(101, &v4(8, 16, false, &bytes[16..]), 3);
        let r = a.finish();
        assert_eq!(r.completed.len(), 0);
        assert_eq!(r.conflicts, 1);
    }

    #[test]
    fn gaps_remain_incomplete_and_duplicates_are_idempotent() {
        let bytes = udp();
        let mut a = FragmentReassembler::new();
        a.push_frame(101, &v4(9, 0, true, &bytes[..16]), 1);
        a.push_frame(101, &v4(9, 0, true, &bytes[..16]), 2);
        assert_eq!(a.finish().incomplete, 1);
    }

    #[test]
    fn nonaligned_or_truncated_fragments_are_rejected() {
        let bytes = udp();
        let mut a = FragmentReassembler::new();
        a.push_frame(101, &v4(9, 0, true, &bytes[..15]), 1);
        let mut bad = v4(9, 0, true, &bytes[..16]);
        bad.truncate(bad.len() - 1);
        a.push_frame(101, &bad, 2);
        assert_eq!(a.finish().malformed, 2);
    }

    #[test]
    fn active_groups_have_a_hard_limit() {
        let mut a = FragmentReassembler::new();
        for n in 0..(MAX_ACTIVE_DATAGRAMS + 3) {
            a.push_frame(101, &v4(n as u16, 0, true, &[7; 8]), n);
        }
        let r = a.finish();
        assert_eq!(r.incomplete, MAX_ACTIVE_DATAGRAMS);
        assert!(r.limited);
    }

    #[test]
    fn atomic_ipv6_fragments_and_unfragmented_packets_are_not_reassembled() {
        let mut a = FragmentReassembler::new();
        a.push_frame(101, &v6(11, 0, false, &udp()), 1);
        a.push_frame(101, &v4(11, 0, false, &udp()), 2);
        let r = a.finish();
        assert_eq!(r.completed.len(), 0);
        assert_eq!(r.incomplete, 0);
    }

    #[test]
    fn ipv6_identical_overlaps_also_invalidate_datagram() {
        let bytes = udp();
        let mut asm = FragmentReassembler::new();
        asm.push_frame(101, &v6(51, 0, true, &bytes[..16]), 0);
        asm.push_frame(101, &v6(51, 8, true, &bytes[8..16]), 1);
        asm.push_frame(101, &v6(51, 16, false, &bytes[16..]), 2);
        let report = asm.finish();
        assert!(report.completed.is_empty());
        assert_eq!(report.conflicts, 1);
    }

    #[test]
    fn conflicting_final_lengths_and_earlier_data_beyond_end_are_rejected() {
        let mut asm = FragmentReassembler::new();
        asm.push_frame(101, &v4(52, 24, false, &[0x42; 8]), 0);
        asm.push_frame(101, &v4(52, 16, false, &[0x42; 8]), 1);
        assert_eq!(asm.finish().conflicts, 1);

        let mut asm = FragmentReassembler::new();
        asm.push_frame(101, &v4(53, 40, true, &[0x42; 8]), 0);
        asm.push_frame(101, &v4(53, 16, false, &[0x42; 8]), 1);
        assert_eq!(asm.finish().conflicts, 1);
    }

    #[test]
    fn ipv6_hop_by_hop_before_fragment_reassembles_and_retains_extension() {
        fn with_hop(id: u32, offset: usize, more: bool, bytes: &[u8]) -> Vec<u8> {
            let mut ip = v6(id, offset, more, bytes);
            ip[6] = 0;
            let length = u16::from_be_bytes([ip[4], ip[5]]);
            ip[4..6].copy_from_slice(&(length + 8).to_be_bytes());
            ip.splice(40..40, [44, 0, 0, 0, 0, 0, 0, 0]);
            ip
        }
        let bytes = udp();
        let mut assembler = FragmentReassembler::new();
        assembler.push_frame(101, &with_hop(0x10203040, 16, false, &bytes[16..]), 1);
        assembler.push_frame(101, &with_hop(0x10203040, 0, true, &bytes[..16]), 2);
        let report = assembler.finish();
        assert_eq!(report.completed.len(), 1);
        let ip = &report.completed[0].ip_packet;
        assert_eq!(ip[6], 0);
        assert_eq!(ip[40], 17);
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), (8 + bytes.len()) as u16);
        assert_eq!(&ip[48..], &bytes);
        assert_eq!(report.completed[0].dissected.protocol, "DNS");
    }

    #[test]
    fn ipv6_malformed_extension_length_is_rejected() {
        let bytes = udp();
        let mut sample = v6(0x1010, 0, true, &bytes[..16]);
        sample[6] = 0;
        sample[41] = 255; // Hop-by-Hop length exceeds advertised payload
        let mut assembler = FragmentReassembler::new();
        assembler.push_frame(101, &sample, 0);
        assert_eq!(assembler.finish().malformed, 1);
    }

    #[test]
    fn rejected_key_cap_exhaustion_fails_closed() {
        let original = udp();
        let mut changed = original[..16].to_vec();
        changed[1] ^= 1;
        let mut assembler = FragmentReassembler::new();
        for i in 0..=MAX_ACTIVE_DATAGRAMS {
            assembler.push_frame(101, &v4(i as u16, 0, true, &original[..16]), i * 2);
            assembler.push_frame(101, &v4(i as u16, 0, true, &changed), i * 2 + 1);
        }
        assembler.push_frame(101, &v4(200, 0, true, &original[..16]), 1000);
        assembler.push_frame(101, &v4(200, 16, false, &original[16..]), 1001);
        let report = assembler.finish();
        assert!(report.completed.is_empty());
        assert!(report.limited);
    }
}

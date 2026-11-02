//! Correlate existing immutable capture frames to a backend-owned scan probe.
//! No network interaction, capture rewriting, credential storage or implicit
//! case authorization. Callers must ensure the source bytes belong to the
//! selected case; matching never invents an observed packet or timestamp.
use crate::parse_capture;
use crate::scan_replies::{correlate_ethernet_response, ProbeIdentity, ReplyEvidence};

pub const MAX_CORRELATION_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CORRELATION_PACKETS: usize = 50_000;
pub const MAX_CORRELATION_MATCHES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrelatedFrame {
    /// Index in the original capture's packet table, zero-based.
    pub packet_index: usize,
    /// Absolute original file byte offset of the Ethernet frame (not header).
    pub source_offset: usize,
    pub source_length: usize,
    pub ts_sec: u64,
    pub ts_subsec: u32,
    pub evidence: ReplyEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationReport {
    pub frames_inspected: usize,
    pub limit_reached: bool,
    pub matches: Vec<CorrelatedFrame>,
}

/// Match only DLT_EN10MB frames. The underlying PCAP/PCAPNG parser verifies
/// the source headers/lengths and retains original byte offsets. Malformed
/// captures are refused instead of silently losing possible evidence.
/// An offline match is *evidence of packets captured*, not proof of a currently
/// open remote service or permission to transmit a new probe.
pub fn correlate_capture(
    original_bytes: &[u8],
    probe: &ProbeIdentity,
    max_matches: usize,
) -> Result<CorrelationReport, String> {
    if original_bytes.len() > MAX_CORRELATION_CAPTURE_BYTES {
        return Err("scan correlation source exceeds 64 MiB limit".into());
    }
    if !(1..=MAX_CORRELATION_MATCHES).contains(&max_matches) {
        return Err(format!(
            "scan correlation match limit must be 1..={MAX_CORRELATION_MATCHES}"
        ));
    }
    let capture = parse_capture(original_bytes)?;
    if capture.linktype != 1 {
        return Err("scan correlation supports only exact Ethernet DLT_EN10MB captures".into());
    }
    if capture.malformed_tail || capture.packets.len() > MAX_CORRELATION_PACKETS {
        return Err("scan correlation refuses malformed or oversized capture packet tables".into());
    }

    let mut report = CorrelationReport {
        frames_inspected: 0,
        limit_reached: false,
        matches: Vec::new(),
    };
    for (index, row) in capture.packets.iter().enumerate() {
        let end = row
            .offset
            .checked_add(row.incl_len)
            .ok_or("capture packet offset overflow")?;
        let frame = original_bytes
            .get(row.offset..end)
            .ok_or("capture metadata points beyond original evidence")?;
        report.frames_inspected += 1;
        if let Some(evidence) = correlate_ethernet_response(frame, probe) {
            if report.matches.len() >= max_matches {
                report.limit_reached = true;
                break;
            }
            report.matches.push(CorrelatedFrame {
                packet_index: index,
                source_offset: row.offset,
                source_length: row.incl_len,
                ts_sec: row.ts_sec,
                ts_subsec: row.ts_subsec,
                evidence,
            });
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_replies::ProbeTransport;

    fn sample_probe() -> ProbeIdentity {
        ProbeIdentity {
            local: "192.0.2.1".parse().unwrap(),
            target: "192.0.2.2".parse().unwrap(),
            transport: ProbeTransport::TcpSyn,
            local_port: 40000,
            target_port: 443,
            syn_sequence: Some(0x01020304),
            echo_key: None,
        }
    }

    fn frame(is_match: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 14 + 20 + 20];
        bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&40u16.to_be_bytes());
        bytes[23] = 6;
        bytes[26..30].copy_from_slice(&[192, 0, 2, 2]);
        bytes[30..34].copy_from_slice(&[192, 0, 2, 1]);
        bytes[34..36].copy_from_slice(&443u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&40000u16.to_be_bytes());
        bytes[42..46].copy_from_slice(&(0x01020305u32).to_be_bytes());
        bytes[46] = 0x50;
        bytes[47] = if is_match { 0x12 } else { 0x10 };
        bytes
    }

    fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0u8; 24];
        out[0..4].copy_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out[4..6].copy_from_slice(&2u16.to_le_bytes());
        out[6..8].copy_from_slice(&4u16.to_le_bytes());
        out[16..20].copy_from_slice(&65535u32.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes()); // Ethernet
        for (index, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(1700000000u32 + index as u32).to_le_bytes());
            out.extend_from_slice(&12345u32.to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    #[test]
    fn captures_provide_exact_original_frame_offsets_and_timestamps() {
        let f = frame(true);
        let source = pcap(&[frame(false), f.clone()]);
        let report = correlate_capture(&source, &sample_probe(), 10).unwrap();
        assert_eq!(report.frames_inspected, 2);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].packet_index, 1);
        assert_eq!(report.matches[0].source_offset, 24 + 16 + f.len() + 16);
        assert_eq!(report.matches[0].source_length, f.len());
        assert_eq!(report.matches[0].ts_sec, 1700000001);
        assert_eq!(report.matches[0].evidence, ReplyEvidence::TcpSynAck);
        assert!(!report.limit_reached);
    }

    #[test]
    fn matched_results_are_bounded_and_truncation_is_explicit() {
        let source = pcap(&[frame(true), frame(true), frame(true)]);
        let report = correlate_capture(&source, &sample_probe(), 1).unwrap();
        assert_eq!(report.matches.len(), 1);
        assert!(report.limit_reached);
        assert_eq!(report.frames_inspected, 2);
        assert!(correlate_capture(&source, &sample_probe(), 0).is_err());
        assert!(correlate_capture(&source, &sample_probe(), 513).is_err());
    }

    #[test]
    fn malformed_capture_tail_and_non_ethernet_linktype_are_rejected() {
        let mut source = pcap(&[frame(true)]);
        source.pop();
        assert!(correlate_capture(&source, &sample_probe(), 10).is_err());
        let mut source = pcap(&[frame(true)]);
        source[20..24].copy_from_slice(&101u32.to_le_bytes());
        assert!(correlate_capture(&source, &sample_probe(), 10).is_err());
    }
}

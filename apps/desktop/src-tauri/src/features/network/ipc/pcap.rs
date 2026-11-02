//! Capture access: native PCAP/PCAPNG parsing with bounded packet byte views.

use std::sync::Mutex;

#[cfg(test)]
use cyberdeck_packet::{parse_capture, PacketMeta};
use tauri::{AppHandle, State};

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::forensics::ipc::evidence::HexResponse;
use crate::features::shared::session::CaseSessionCtx;

#[path = "../application/capture_cache.rs"]
mod capture_cache;
#[path = "../infrastructure/capture_file.rs"]
mod capture_file;
#[path = "../application/capture_service.rs"]
mod capture_service;
#[path = "hex.rs"]
mod hex_format;
#[path = "pcap_commands.rs"]
mod pcap_commands;
#[path = "pcap_wire.rs"]
mod pcap_wire;
#[path = "saved_capture.rs"]
mod saved_capture;
pub use capture_cache::CachedCapture;
#[cfg(test)]
use pcap_wire::wire_packet;
pub use pcap_wire::{PcapOpenWire, PcapPacketWire};
#[cfg(test)]
pub use pcap_wire::LayerWire;

pub struct PcapCtx {
    pub current: Mutex<Option<CachedCapture>>,
}

/// Decode a bounded native capture frame using the exact offline PCAP parser
/// and packet wire projection, without replacing the offline PCAP cache.
pub(crate) fn original_capture_packet(
    original: &[u8],
    index: usize,
    expected_offset: usize,
) -> Result<PcapPacketWire, String> {
    let parsed = cyberdeck_packet::parse_capture(original)?;
    if parsed.malformed_tail {
        return Err("original native capture has a malformed trailing record".into());
    }
    let meta = parsed
        .packets
        .get(index)
        .ok_or("capture frame index out of range")?;
    if meta.offset != expected_offset {
        return Err("capture frame offset differs from immutable provenance".into());
    }
    Ok(pcap_wire::wire_packet(
        index,
        meta,
        parsed.packets.first(),
        parsed.nanosecond,
    ))
}

#[tauri::command]
pub fn pcap_open_dialog(app: AppHandle, ctx: State<'_, PcapCtx>) -> Result<PcapOpenWire, String> {
    pcap_commands::open_dialog(app, ctx)
}

#[tauri::command]
pub fn pcap_follow_stream(
    ctx: State<'_, PcapCtx>,
    stream_id: String,
) -> Result<cyberdeck_packet::streams::StreamTranscript, String> {
    pcap_commands::follow_stream(ctx, stream_id)
}

#[tauri::command]
pub fn pcap_packet_bytes(
    ctx: State<'_, PcapCtx>,
    index: usize,
    offset: i64,
    len: i64,
) -> Result<HexResponse, String> {
    pcap_commands::packet_bytes(ctx, index, offset, len)
}

/// Case-authorized verified original PCAP reopen: artifact ID only, no path.
#[tauri::command]
pub fn pcap_open_case_v1(
    artifact_id: String,
    evidence: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<PcapOpenWire, String> {
    saved_capture::open(&evidence, &session, &artifact_id)
}

/// Read an original saved frame through Agent5's pinned verified handle.
#[tauri::command]
pub fn pcap_case_packet_bytes_v1(
    artifact_id: String,
    index: usize,
    offset: i64,
    len: i64,
    evidence: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<HexResponse, String> {
    saved_capture::packet_bytes(&evidence, &session, &artifact_id, index, offset, len)
}

#[tauri::command]
pub fn pcap_case_follow_stream_v1(
    artifact_id: String,
    stream_id: String,
    evidence: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<cyberdeck_packet::streams::StreamTranscript, String> {
    saved_capture::follow_stream(&evidence, &session, &artifact_id, &stream_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn open_wire_maps_fields_without_tauri() {
        // build a capture through the parser directly and map to wire packets
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 28]);
        let mut file = Vec::new();
        file.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&0i32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&65535u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&100u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&frame);
        let native = original_capture_packet(&file, 0, 40).unwrap();
        assert_eq!(native.protocol, "ARP");
        assert!(!native.layers.is_empty());
        assert!(original_capture_packet(&file, 0, 41).is_err());
        let parsed = parse_capture(&file).unwrap();
        let wire = wire_packet(
            0,
            &parsed.packets[0],
            parsed.packets.first(),
            parsed.nanosecond,
        );
        assert_eq!(wire.index, 0);
        assert!((wire.time_ms - 0.0).abs() < f64::EPSILON);
        assert_eq!(wire.protocol, "ARP");
        assert!(!wire.layers.is_empty());
    }

    #[test]
    fn timestamp_precision_and_stream_identifiers_reach_the_ui() {
        let frame = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        ];
        let first = PacketMeta {
            offset: 0,
            incl_len: frame.len(),
            orig_len: frame.len(),
            ts_sec: 10,
            ts_subsec: 900_000_000,
            dissected: cyberdeck_packet::dissect(101, &frame),
        };
        let second = PacketMeta {
            ts_sec: 11,
            ts_subsec: 100_000_000,
            ..first.clone()
        };
        let wire = wire_packet(1, &second, Some(&first), true);
        assert!((wire.time_ms - 200.0).abs() < 0.0001);
        let first_micro = PacketMeta {
            ts_subsec: 900_000,
            ..first
        };
        let second_micro = PacketMeta {
            ts_sec: 11,
            ts_subsec: 100_000,
            ..second
        };
        let wire = wire_packet(1, &second_micro, Some(&first_micro), false);
        assert!((wire.time_ms - 200.0).abs() < 0.0001);
    }

    #[test]
    fn ctx_defaults_to_empty() {
        let ctx = PcapCtx {
            current: Mutex::new(None),
        };
        assert!(ctx.current.lock().unwrap().is_none());
    }
}

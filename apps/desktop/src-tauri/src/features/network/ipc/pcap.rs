//! Capture access: native PCAP/PCAPNG parsing with bounded packet byte views.

use std::sync::Mutex;

#[cfg(test)]
use cyberdeck_packet::{parse_capture, PacketMeta};
use tauri::{AppHandle, State};

use crate::features::forensics::ipc::evidence::HexResponse;

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
pub use capture_cache::CachedCapture;
#[cfg(test)]
use pcap_wire::wire_packet;
pub use pcap_wire::{LayerWire, PcapOpenWire, PcapPacketWire};

pub struct PcapCtx {
    pub current: Mutex<Option<CachedCapture>>,
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

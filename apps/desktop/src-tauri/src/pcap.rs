//! Capture file access (Master Plan §5.1). The frontend opens captures
//! through the native dialog; parsed metadata streams to the packet list and
//! raw bytes are served per selection from the cached copy. Classic PCAP
//! only this arc; PCAPNG is rejected with a clear message by the parser.

use std::sync::Mutex;

use hacktool_packet::{parse_pcap, PacketMeta};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::evidence::{HexResponse, HexRow};

const MAX_PCAP_FILE: u64 = 200 * 1024 * 1024;
const MAX_UI_PACKETS: usize = 20_000;

pub struct PcapCtx {
    pub current: Mutex<Option<CachedCapture>>,
}

pub struct CachedCapture {
    pub bytes: Vec<u8>,
    pub linktype: u32,
    pub first_ts: u64,
    pub packets: Vec<PacketMeta>,
}

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
    pub layers: Vec<LayerWire>,
}

#[derive(Debug, Serialize)]
pub struct PcapOpenWire {
    pub linktype: u32,
    pub packet_count: usize,
    pub shown: usize,
    pub malformed_tail: bool,
    pub file_name: String,
    pub packets: Vec<PcapPacketWire>,
}

fn wire_packet(index: usize, meta: &PacketMeta, first_ts: u64) -> PcapPacketWire {
    let ts_ms = (meta.ts_sec.saturating_sub(first_ts)) as f64 * 1000.0 + meta.ts_subsec as f64 / 1000.0;
    PcapPacketWire {
        index,
        time_ms: ts_ms,
        source: meta.dissected.source.clone(),
        destination: meta.dissected.destination.clone(),
        protocol: meta.dissected.protocol.clone(),
        length: meta.orig_len,
        info: meta.dissected.info.clone(),
        color_hint: meta.dissected.color_hint.clone(),
        layers: meta
            .dissected
            .layers
            .iter()
            .map(|l| LayerWire { label: l.label.clone(), value: l.value.clone() })
            .collect(),
    }
}

#[tauri::command]
pub fn pcap_open_dialog(app: AppHandle, ctx: State<'_, PcapCtx>) -> Result<PcapOpenWire, String> {
    let picked = app.dialog().file().blocking_pick_file().ok_or("cancelled")?;
    let path = picked.as_path().ok_or("unsupported file location")?.to_path_buf();
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read capture metadata: {e}"))?;
    if meta.len() > MAX_PCAP_FILE {
        return Err(format!(
            "capture is {} MB; the open limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_PCAP_FILE / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read capture: {e}"))?;
    let parsed = parse_pcap(&bytes)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "capture.pcap".to_string());
    let first_ts = parsed.packets.first().map(|p| p.ts_sec).unwrap_or(0);
    let shown = parsed.packets.len().min(MAX_UI_PACKETS);
    let wire = PcapOpenWire {
        linktype: parsed.linktype,
        packet_count: parsed.packets.len(),
        shown,
        malformed_tail: parsed.malformed_tail,
        file_name,
        packets: (0..shown).map(|i| wire_packet(i, &parsed.packets[i], first_ts)).collect(),
    };
    *ctx.current.lock().expect("pcap cache poisoned") = Some(CachedCapture {
        bytes,
        linktype: parsed.linktype,
        first_ts,
        packets: parsed.packets,
    });
    Ok(wire)
}

#[tauri::command]
pub fn pcap_packet_bytes(ctx: State<'_, PcapCtx>, index: usize, offset: i64, len: i64) -> Result<HexResponse, String> {
    let guard = ctx.current.lock().expect("pcap cache poisoned");
    let capture = guard.as_ref().ok_or("no capture is open")?;
    let meta = capture.packets.get(index).ok_or("packet index out of range")?;
    let frame = capture
        .bytes
        .get(meta.offset..meta.offset + meta.incl_len)
        .ok_or("capture bytes truncated")?;
    let total = frame.len() as i64;
    let start = offset.clamp(0, total.max(0)) as usize;
    let wanted = len.clamp(1, 4096) as usize;
    let end = (start + wanted).min(frame.len());
    let slice = &frame[start..end];
    let mut rows = Vec::with_capacity((slice.len() + 15) / 16);
    for (i, chunk) in slice.chunks(16).enumerate() {
        let hex_str: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect();
        rows.push(HexRow {
            offset: start + i * 16,
            hex: hex_str.trim_end().to_string(),
            ascii,
        });
    }
    Ok(HexResponse {
        rows,
        offset: start as i64,
        total_size: total as u64,
        complete: end >= frame.len(),
    })
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
        let parsed = parse_pcap(&file).unwrap();
        let first_ts = parsed.packets[0].ts_sec;
        let wire = wire_packet(0, &parsed.packets[0], first_ts);
        assert_eq!(wire.index, 0);
        assert!((wire.time_ms - 0.0).abs() < f64::EPSILON);
        assert_eq!(wire.protocol, "ARP");
        assert!(!wire.layers.is_empty());
    }

    #[test]
    fn ctx_defaults_to_empty() {
        let ctx = PcapCtx { current: Mutex::new(None) };
        assert!(ctx.current.lock().unwrap().is_none());
    }
}

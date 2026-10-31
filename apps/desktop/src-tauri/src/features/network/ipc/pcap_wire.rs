//! IPC wire types and packet timestamp/metadata presentation projection.
//! Stable fields and serialized names are shared with the desktop frontend.
use cyberdeck_packet::PacketMeta;
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

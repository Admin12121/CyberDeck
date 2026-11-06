//! IPC wire types and packet timestamp/metadata presentation projection.
//! Stable fields and serialized names are shared with the desktop frontend.
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

//! Packet Studio "export view -> case" command. The currently filtered
//! selection of the opened offline capture is re-serialized as a classic
//! little-endian microsecond PCAP and committed as an immutable case artifact
//! through exactly the path `capture_save_v1` uses (evidence store lock ->
//! publication gate -> original-network-capture importer). The frontend never
//! sees capture bytes, stored paths or case secrets — only a receipt.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::{
    pcap_write, PCAP_MAGIC_BE_NSEC, PCAP_MAGIC_LE_NSEC, MAX_CAPTURE_PACKETS,
};
use cyberdeck_storage::{NetworkCaptureSource, MAX_ORIGINAL_PCAP_BYTES};
use serde::Serialize;
use tauri::State;

use super::pcap::PcapCtx;

/// The case artifact importer this command reuses only accepts Ethernet
/// captures this arc; anything else is refused with a clear message instead
/// of failing deep inside storage validation.
const ETHERNET_LINKTYPE: u32 = 1;
/// Per-frame bound of the evidence importer's original-PCAP validator. The
/// parser accepts larger frames (up to the reader's 256 KiB cap), but an
/// export containing one could never be committed, so it is refused early.
const MAX_EXPORT_FRAME_BYTES: usize = 65_535;
/// Provenance marker for the evidence event description. This export is a
/// derived view of an opened capture, not a live capture session; session 0
/// is the documented sentinel for that.
const EXPORT_PROVENANCE_INTERFACE: &str = "packet-studio-view";
const EXPORT_PROVENANCE_SESSION: u64 = 0;

/// Frontend-safe export receipt: identity and size only. No stored path, no
/// case secrets and no PCAP bytes ever cross the IPC boundary.
#[derive(Debug, Clone, Serialize)]
pub struct ExportReceiptWire {
    pub artifact_id: String,
    pub sha256: String,
    pub byte_len: u64,
    pub packet_count: usize,
    pub file_name: String,
}

/// Same saved-case gating as the scan-depth slice: the export destination is
/// always the backend-selected persistent case, never a client-named one.
fn selected_saved_case(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let id = scope
        .case_id
        .clone()
        .ok_or("saved case selection required")?;
    if id == "scratchpad" || id.is_empty() {
        return Err("pcap export requires a saved selected case".into());
    }
    Ok((scope, id))
}

/// Nanosecond-resolution sources (classic nsec magics, and PCAPNG whose
/// timestamps the parser normalizes to nanoseconds) must be downscaled before
/// microsecond export; microsecond sources pass through unchanged.
fn subsecond_unit_is_nanoseconds(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        return true;
    }
    let Some(chunk) = bytes.get(0..4) else {
        return false;
    };
    let magic = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    matches!(magic, PCAP_MAGIC_LE_NSEC | PCAP_MAGIC_BE_NSEC)
}

#[tauri::command]
pub fn pcap_export_view_v1(
    indices: Vec<u32>,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    ctx: State<'_, PcapCtx>,
) -> Result<ExportReceiptWire, String> {
    let (scope, case_id) = selected_saved_case(&session)?;
    let guard = ctx
        .current
        .lock()
        .map_err(|_| "capture cache unavailable".to_string())?;
    let capture = guard.as_ref().ok_or("no capture is open")?;
    if capture.linktype != ETHERNET_LINKTYPE {
        return Err(
            "only Ethernet captures can be exported as case artifacts this arc".into(),
        );
    }

    // Deduplicate and order the selection so the export is a deterministic,
    // time-ordered capture regardless of how the UI gathered the indices.
    let mut indices = indices;
    indices.sort_unstable();
    indices.dedup();
    if indices.is_empty() {
        return Err("select at least one packet before exporting".into());
    }
    // Reader-mirroring cap: an export can never claim more records than a
    // capture may hold, and every index must address a real cached frame.
    if indices.len() > MAX_CAPTURE_PACKETS {
        return Err(format!(
            "export selection exceeds the {} record capture limit",
            MAX_CAPTURE_PACKETS
        ));
    }

    // First pass: bounds-check every frame against the cached metadata and
    // size the export before any bytes are produced.
    let nanosecond = subsecond_unit_is_nanoseconds(&capture.bytes);
    let mut total = 24usize; // pcap global header
    for index in &indices {
        let meta = capture
            .packets
            .get(*index as usize)
            .ok_or("packet index out of range")?;
        if meta.incl_len == 0 {
            return Err(format!("capture frame {} is empty; export refused", index));
        }
        if meta.incl_len > MAX_EXPORT_FRAME_BYTES {
            return Err(format!(
                "capture frame {} is {} bytes; case artifact export supports frames up to {} bytes",
                index, meta.incl_len, MAX_EXPORT_FRAME_BYTES
            ));
        }
        let record = 16usize
            .checked_add(meta.incl_len)
            .ok_or("export size overflowed the addressable range")?;
        total = total
            .checked_add(record)
            .ok_or("export size overflowed the addressable range")?;
    }
    // Fail before writing rather than after: the importer would refuse the
    // same bytes, so there is no honest artifact to persist.
    if total > MAX_ORIGINAL_PCAP_BYTES {
        return Err(format!(
            "export view is {} bytes; case artifact limit is {} bytes",
            total, MAX_ORIGINAL_PCAP_BYTES
        ));
    }

    // Second pass: borrow the exact original frame bytes for each record.
    // Mirrors capture_service::packet_frame: slice only [offset, offset +
    // incl_len) out of the immutable cached capture bytes, checked, never
    // promoting reassembled datagrams.
    let mut records: Vec<(u32, u32, &[u8])> = Vec::with_capacity(indices.len());
    for index in &indices {
        let meta = &capture.packets[*index as usize];
        let end = meta
            .offset
            .checked_add(meta.incl_len)
            .ok_or("capture bytes truncated")?;
        let frame = capture
            .bytes
            .get(meta.offset..end)
            .ok_or("capture bytes truncated")?;
        // Classic microsecond export: downscale nanosecond sub-seconds
        // (sub-millisecond precision loss is inherent to the target format;
        // frame bytes and ordering stay exact). Seconds beyond 2106 clamp
        // instead of failing the whole export.
        let ts_sec = u32::try_from(meta.ts_sec).unwrap_or(u32::MAX);
        let micro = if nanosecond {
            meta.ts_subsec / 1_000
        } else {
            meta.ts_subsec
        };
        records.push((ts_sec, micro, frame));
    }
    let pcap_bytes = pcap_write::write_pcap(capture.linktype, &records)
        .map_err(|error| format!("pcap export refused: {error}"))?;

    // Frame offsets inside the produced file, in the layout the writer
    // guarantees (24-byte global header, then 16-byte record headers). The
    // importer verifies these against the bytes before anything is indexed.
    let mut frame_offsets: Vec<usize> = Vec::with_capacity(records.len());
    let mut cursor = 24usize;
    for (_, _, frame) in &records {
        cursor = cursor
            .checked_add(16)
            .and_then(|c| c.checked_add(frame.len()))
            .ok_or("export size overflowed the addressable range")?;
        frame_offsets.push(cursor - frame.len());
    }

    let source = NetworkCaptureSource {
        session_id: EXPORT_PROVENANCE_SESSION,
        interface: EXPORT_PROVENANCE_INTERFACE,
        frame_offsets: &frame_offsets,
        bytes: &pcap_bytes,
    };
    // Case-selection IPC locks the store before its publication gate; the
    // same order is required here to avoid a concurrent case-switch deadlock
    // (mirrors save_original_capture in capture.rs).
    let store = evidence
        .store
        .lock()
        .map_err(|_| "case evidence store unavailable")?;
    let record = session.with_current_publication(&scope, || {
        store.import_original_network_capture(&evidence.artifacts_dir, &case_id, &source)
    })?;
    let packet_count = records.len();
    drop(store);
    Ok(ExportReceiptWire {
        artifact_id: record.id,
        sha256: record.sha256,
        byte_len: record.size,
        packet_count,
        file_name: format!("packet-studio-export-{packet_count}.pcap"),
    })
}

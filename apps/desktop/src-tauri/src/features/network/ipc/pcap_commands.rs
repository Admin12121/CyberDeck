//! Capture IPC adapters; stable command macros remain in pcap.rs.
use super::{
    capture_file, capture_service, hex_format, pcap_wire::reassembly_summary, pcap_wire::wire_packet,
    PcapCtx, PcapOpenWire,
};
use crate::features::forensics::ipc::evidence::HexResponse;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

const MAX_UI_PACKETS: usize = 20_000;

pub(super) fn open_dialog(app: AppHandle, ctx: State<'_, PcapCtx>) -> Result<PcapOpenWire, String> {
    let picked = app
        .dialog()
        .file()
        .blocking_pick_file()
        .ok_or("cancelled")?;
    let path = picked
        .as_path()
        .ok_or("unsupported file location")?
        .to_path_buf();
    let bytes = capture_file::read_capture(&path)?;
    let imported = capture_service::import_bytes(bytes)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "capture.pcap".to_string());
    let shown = imported.cache.packets.len().min(MAX_UI_PACKETS);
    let wire = PcapOpenWire {
        format: imported.format.to_string(),
        linktype: imported.cache.linktype,
        packet_count: imported.cache.packets.len(),
        shown,
        malformed_tail: imported.malformed_tail,
        file_name,
        reassembly: reassembly_summary(&imported.reassembly),
        packets: (0..shown)
            .map(|i| {
                wire_packet(
                    i,
                    &imported.cache.packets[i],
                    imported.cache.packets.first(),
                    imported.nanosecond,
                )
            })
            .collect(),
    };
    *ctx.current.lock().expect("pcap cache poisoned") = Some(imported.cache);
    Ok(wire)
}

pub(super) fn follow_stream(
    ctx: State<'_, PcapCtx>,
    stream_id: String,
) -> Result<cyberdeck_packet::streams::StreamTranscript, String> {
    let guard = ctx
        .current
        .lock()
        .map_err(|_| "capture cache unavailable".to_string())?;
    let capture = guard.as_ref().ok_or("no capture is open")?;
    capture_service::follow_stream(capture, &stream_id)
}

pub(super) fn packet_bytes(
    ctx: State<'_, PcapCtx>,
    index: usize,
    offset: i64,
    len: i64,
) -> Result<HexResponse, String> {
    let guard = ctx.current.lock().expect("pcap cache poisoned");
    let capture = guard.as_ref().ok_or("no capture is open")?;
    let frame = capture_service::packet_frame(capture, index)?;
    Ok(hex_format::frame_hex_view(frame, offset, len))
}

//! Capture access: native PCAP/PCAPNG parsing with bounded packet byte views.

use std::sync::Mutex;

#[cfg(test)]
use cyberdeck_packet::{parse_capture, PacketMeta};
use tauri::{AppHandle, State};

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::forensics::ipc::evidence::HexResponse;
use crate::features::shared::session::CaseSessionCtx;
use tauri_plugin_dialog::DialogExt;

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
#[cfg(test)]
pub use pcap_wire::LayerWire;
pub use pcap_wire::{PcapOpenWire, PcapPacketWire};

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
pub fn pcap_open_dialog(
    app: AppHandle,
    ctx: State<'_, PcapCtx>,
    keylog: State<'_, KeylogCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<PcapOpenWire, String> {
    let store = keylog.capture_store_for(&session);
    pcap_commands::open_dialog(app, ctx, store.as_ref())
}

#[tauri::command]
pub fn pcap_follow_stream(
    ctx: State<'_, PcapCtx>,
    keylog: State<'_, KeylogCtx>,
    session: State<'_, CaseSessionCtx>,
    stream_id: String,
) -> Result<cyberdeck_packet::streams::StreamTranscript, String> {
    let transcript = pcap_commands::follow_stream(ctx, stream_id)?;
    Ok(apply_session_keylog(&keylog, &session, transcript))
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
    keylog: State<'_, KeylogCtx>,
) -> Result<PcapOpenWire, String> {
    saved_capture::open(
        &evidence,
        &session,
        &artifact_id,
        keylog.capture_store_for(&session).as_ref(),
    )
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
    keylog: State<'_, KeylogCtx>,
) -> Result<HexResponse, String> {
    saved_capture::packet_bytes(
        &evidence,
        &session,
        &artifact_id,
        index,
        offset,
        len,
        keylog.capture_store_for(&session).as_ref(),
    )
}

#[tauri::command]
pub fn pcap_case_follow_stream_v1(
    artifact_id: String,
    stream_id: String,
    evidence: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
    keylog: State<'_, KeylogCtx>,
) -> Result<cyberdeck_packet::streams::StreamTranscript, String> {
    let store = keylog.capture_store_for(&session);
    let transcript =
        saved_capture::follow_stream(&evidence, &session, &artifact_id, &stream_id, store.as_ref())?;
    Ok(apply_session_keylog(&keylog, &session, transcript))
}

// ------------------------------------------------------------- TLS 1.3 ----
//
// Wireshark-parity passive TLS 1.3 decryption for stream transcripts. A
// keylog is USER-SUPPLIED evidence: nothing here guesses keys, and records
// are decrypted only when the packet crate verifies their GCM tags against
// secrets the imported keylog explicitly carries for the stream's own
// ClientHello random. The attachment is scoped to the case session that was
// selected at import time; a different session keeps the ciphertext view.

/// Wire status of the per-session keylog attachment (no secrets, no paths).
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeylogStatusWire {
    pub attached: bool,
    pub file_name: String,
    /// Accepted TLS 1.3 traffic-secret entries.
    pub entries: usize,
    /// Distinct connections (ClientHello randoms) the keylog covers.
    pub connections: usize,
    /// Collapsed duplicate (random, label) lines.
    pub duplicates: usize,
    /// Recognized-but-ignored lines (TLS 1.2-era labels).
    pub ignored_lines: usize,
    /// True when the attachment's case session matches the caller's.
    pub active_for_session: bool,
}

struct KeylogAttachment {
    scope: crate::features::shared::session::CaseSessionWire,
    store: cyberdeck_packet::crypto::keylog::KeylogStore,
    file_name: String,
}

/// Managed per-session keylog attachment. Held in memory only; it is never
/// persisted, logged, exported, or sent to Recipes.
#[derive(Default)]
pub struct KeylogCtx {
    attachment: Mutex<Option<KeylogAttachment>>,
}

impl KeylogCtx {
    /// The session-scoped keylog store, or None when nothing is attached or
    /// the attachment belongs to a different case session. Shared by the
    /// transcript post-processing path and the capture-parse guard that
    /// enables QUIC Handshake/1-RTT decryption at import time.
    pub(crate) fn capture_store_for(
        &self,
        session: &CaseSessionCtx,
    ) -> Option<cyberdeck_packet::crypto::keylog::KeylogStore> {
        let guard = self.attachment.lock().ok()?;
        let attachment = guard.as_ref()?;
        let current = session.snapshot().ok()?;
        if current.case_id != attachment.scope.case_id || current.revision != attachment.scope.revision
        {
            return None;
        }
        Some(attachment.store.clone())
    }

    fn status_for(&self, session: &CaseSessionCtx) -> Result<KeylogStatusWire, String> {
        let guard = self
            .attachment
            .lock()
            .map_err(|_| "keylog state unavailable".to_string())?;
        let current = session.snapshot().ok();
        let Some(attachment) = guard.as_ref() else {
            return Ok(KeylogStatusWire {
                attached: false,
                file_name: String::new(),
                entries: 0,
                connections: 0,
                duplicates: 0,
                ignored_lines: 0,
                active_for_session: false,
            });
        };
        let active = current.as_ref() == Some(&attachment.scope);
        Ok(KeylogStatusWire {
            attached: true,
            file_name: attachment.file_name.clone(),
            entries: attachment.store.entry_count(),
            connections: attachment.store.connection_count(),
            duplicates: attachment.store.duplicate_count(),
            ignored_lines: attachment.store.ignored_line_count(),
            active_for_session: active,
        })
    }
}

/// Apply the session's keylog attachment to a follow-stream transcript, or
/// return the transcript untouched when nothing is attached or the
/// attachment belongs to a different case session.
fn apply_session_keylog(
    keylog: &KeylogCtx,
    session: &CaseSessionCtx,
    transcript: cyberdeck_packet::streams::StreamTranscript,
) -> cyberdeck_packet::streams::StreamTranscript {
    let guard = match keylog.attachment.lock() {
        Ok(guard) => guard,
        Err(_) => return transcript,
    };
    let Some(attachment) = guard.as_ref() else {
        return transcript;
    };
    let current = match session.snapshot() {
        Ok(scope) => scope,
        Err(_) => return transcript,
    };
    if current.case_id != attachment.scope.case_id || current.revision != attachment.scope.revision
    {
        return transcript;
    }
    cyberdeck_packet::streams::apply_keylog_to_transcript(&transcript, &attachment.store)
}

/// Native-file keylog import: opens the platform file dialog, reads at most
/// the parser's 64 KiB bound, parses strictly, and stores the result
/// per-session (replacing any prior attachment). No keylog bytes ever leave
/// this process.
#[tauri::command]
pub fn packet_stream_keylog_attach_v1(
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    keylog: State<'_, KeylogCtx>,
) -> Result<KeylogStatusWire, String> {
    use cyberdeck_packet::crypto::keylog::{KeylogStore, MAX_KEYLOG_BYTES};
    use std::io::Read;

    let picked = app
        .dialog()
        .file()
        .blocking_pick_file()
        .ok_or("cancelled")?;
    let path = picked
        .as_path()
        .ok_or("unsupported file location")?
        .to_path_buf();
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .and_then(|file| {
            file.take(MAX_KEYLOG_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| format!("keylog could not be read: {error}"))?;
    if bytes.len() > MAX_KEYLOG_BYTES {
        return Err(format!(
            "keylog exceeds the {} KiB import bound",
            MAX_KEYLOG_BYTES / 1024
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| "keylog is not valid UTF-8".to_string())?;
    let store = KeylogStore::parse(&text)?;
    if store.is_empty() {
        return Err(
            "keylog holds no TLS 1.3 traffic secrets (only TLS 1.2-era or unrecognized labels)"
                .to_string(),
        );
    }
    let scope = session.snapshot()?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "keylog.log".to_string());
    let status = KeylogStatusWire {
        attached: true,
        file_name: file_name.clone(),
        entries: store.entry_count(),
        connections: store.connection_count(),
        duplicates: store.duplicate_count(),
        ignored_lines: store.ignored_line_count(),
        active_for_session: true,
    };
    let mut guard = keylog
        .attachment
        .lock()
        .map_err(|_| "keylog state unavailable".to_string())?;
    *guard = Some(KeylogAttachment {
        scope,
        store,
        file_name,
    });
    Ok(status)
}

/// Current keylog attachment status for the selected case session.
#[tauri::command]
pub fn packet_stream_keylog_status_v1(
    session: State<'_, CaseSessionCtx>,
    keylog: State<'_, KeylogCtx>,
) -> Result<KeylogStatusWire, String> {
    keylog.status_for(&session)
}

/// Detach the keylog (the UI's explicit clear affordance).
#[tauri::command]
pub fn packet_stream_keylog_clear_v1(
    session: State<'_, CaseSessionCtx>,
    keylog: State<'_, KeylogCtx>,
) -> Result<KeylogStatusWire, String> {
    {
        let mut guard = keylog
            .attachment
            .lock()
            .map_err(|_| "keylog state unavailable".to_string())?;
        *guard = None;
    }
    keylog.status_for(&session)
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

    #[test]
    fn keylog_attachment_absent_or_out_of_scope_leaves_transcript_untouched() {
        // No case selected at all: snapshot fails, so nothing decrypts.
        let keylog = KeylogCtx::default();
        let session = CaseSessionCtx::default();
        let transcript = cyberdeck_packet::streams::StreamTranscript {
            protocol: "TCP".into(),
            chunks: vec![cyberdeck_packet::streams::StreamChunk {
                dir: "A".into(),
                text: "ciphertext".into(),
                kind: "data".into(),
                hex_data: Some("00ff".into()),
            }],
            gaps: 0,
            retransmissions: 0,
            conflicts: 0,
            truncated: false,
            application_hints: Vec::new(),
        };
        let out = apply_session_keylog(&keylog, &session, transcript.clone());
        assert_eq!(out.chunks.len(), transcript.chunks.len());
        let status = keylog.status_for(&session).unwrap();
        assert!(!status.attached);
        assert!(!status.active_for_session);
    }
}

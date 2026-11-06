//! Case-bound, path-free saved original PCAP consumption.
//! The verified reader reopens the immutable same-handle SHA-256-checked source
//! for each bounded request; no independent cached-case authority is created.
use super::{
    capture_service, hex_format, pcap_wire::reassembly_summary, pcap_wire::wire_packet,
    PcapOpenWire,
};
use crate::features::cases::infrastructure::authorized_transfer::{
    with_verified_artifact, EvidenceConsumer,
};
use crate::features::forensics::ipc::evidence::{EvidenceCtx, HexResponse};
use crate::features::shared::session::CaseSessionCtx;
use cyberdeck_packet::streams::StreamTranscript;

const MAX_UI_PACKETS: usize = 20_000;

pub(super) fn open(
    evidence: &EvidenceCtx,
    selected: &CaseSessionCtx,
    artifact_id: &str,
) -> Result<PcapOpenWire, String> {
    with_verified_artifact(
        evidence,
        selected,
        artifact_id,
        EvidenceConsumer::PacketAnalysis,
        |record, bytes| {
            let source = capture_service::import_bytes(bytes.to_vec())?;
            if source.format != "pcap" || source.malformed_tail {
                return Err("saved original PCAP failed strict format validation".into());
            }
            let shown = source.cache.packets.len().min(MAX_UI_PACKETS);
            Ok(PcapOpenWire {
                format: source.format.into(),
                linktype: source.cache.linktype,
                packet_count: source.cache.packets.len(),
                shown,
                malformed_tail: false,
                file_name: record.name.clone(),
                reassembly: reassembly_summary(&source.reassembly),
                packets: (0..shown)
                    .map(|index| {
                        wire_packet(
                            index,
                            &source.cache.packets[index],
                            source.cache.packets.first(),
                            source.nanosecond,
                        )
                    })
                    .collect(),
            })
        },
    )
}

pub(super) fn packet_bytes(
    evidence: &EvidenceCtx,
    selected: &CaseSessionCtx,
    artifact_id: &str,
    index: usize,
    offset: i64,
    len: i64,
) -> Result<HexResponse, String> {
    // Reject oversized pages before doing any disk I/O.
    if offset < 0 || len < 0 || len > 4_096 {
        return Err("saved capture frame window exceeds bounds".into());
    }
    with_verified_artifact(
        evidence,
        selected,
        artifact_id,
        EvidenceConsumer::PacketAnalysis,
        |_, bytes| {
            let parsed = capture_service::import_bytes(bytes.to_vec())?;
            if parsed.malformed_tail {
                return Err("saved original capture is malformed".into());
            }
            let frame = capture_service::packet_frame(&parsed.cache, index)?;
            Ok(hex_format::frame_hex_view(frame, offset, len))
        },
    )
}

pub(super) fn follow_stream(
    evidence: &EvidenceCtx,
    selected: &CaseSessionCtx,
    artifact_id: &str,
    stream_id: &str,
) -> Result<StreamTranscript, String> {
    if stream_id.is_empty() || stream_id.len() > 256 {
        return Err("invalid saved stream identifier".into());
    }
    with_verified_artifact(
        evidence,
        selected,
        artifact_id,
        EvidenceConsumer::PacketAnalysis,
        |_, bytes| {
            let parsed = capture_service::import_bytes(bytes.to_vec())?;
            if parsed.malformed_tail {
                return Err("saved original capture is malformed".into());
            }
            capture_service::follow_stream(&parsed.cache, stream_id)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_storage::{ArtifactStore, NetworkCaptureSource};
    use std::sync::Mutex;

    #[cfg(unix)]
    #[test]
    fn saved_original_reopens_as_real_dissected_packet_and_denies_case_switch() {
        let temp = tempfile::tempdir().unwrap();
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 28]);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        let offset = bytes.len();
        bytes.extend_from_slice(&frame);

        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let a = store.create_case("A", "").unwrap();
        let b = store.create_case("B", "").unwrap();
        let root = temp.path().join("artifacts");
        let record = store
            .import_original_network_capture(
                &root,
                &a.id,
                &NetworkCaptureSource {
                    session_id: 42,
                    interface: "fixture0",
                    frame_offsets: &[offset],
                    bytes: &bytes,
                },
            )
            .unwrap();
        let evidence = EvidenceCtx {
            store: Mutex::new(store),
            artifacts_dir: root,
        };
        let selected = CaseSessionCtx::default();
        selected
            .select(&evidence.store.lock().unwrap(), &a.id)
            .unwrap();
        let wire = open(&evidence, &selected, &record.id).unwrap();
        assert_eq!(wire.packet_count, 1);
        assert_eq!(wire.packets[0].protocol, "ARP");
        assert_eq!(wire.packets[0].index, 0);
        let saved = packet_bytes(&evidence, &selected, &record.id, 0, 0, 48).unwrap();
        assert!(!saved.rows.is_empty());
        assert!(packet_bytes(&evidence, &selected, &record.id, 0, 0, 4_097).is_err());
        selected
            .select(&evidence.store.lock().unwrap(), &b.id)
            .unwrap();
        assert!(open(&evidence, &selected, &record.id).is_err());
        assert!(packet_bytes(&evidence, &selected, &record.id, 0, 0, 16).is_err());
    }
}

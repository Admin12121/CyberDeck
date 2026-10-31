//! Offline capture orchestration with original-byte ownership and no UI toolkit.
use super::capture_cache::CachedCapture;
use cyberdeck_packet::parse_capture;

pub(super) struct CaptureImport {
    pub(super) cache: CachedCapture,
    pub(super) format: &'static str,
    pub(super) nanosecond: bool,
    pub(super) malformed_tail: bool,
}

/// Keep original bytes exactly as imported; parsed packets refer back to them.
pub(super) fn import_bytes(bytes: Vec<u8>) -> Result<CaptureImport, String> {
    let parsed = parse_capture(&bytes)?;
    let format = if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        "pcapng"
    } else {
        "pcap"
    };
    let first_ts = parsed.packets.first().map(|p| p.ts_sec).unwrap_or(0);
    Ok(CaptureImport {
        cache: CachedCapture {
            bytes,
            linktype: parsed.linktype,
            first_ts,
            packets: parsed.packets,
        },
        format,
        nanosecond: parsed.nanosecond,
        malformed_tail: parsed.malformed_tail,
    })
}

pub(super) fn follow_stream(
    capture: &CachedCapture,
    stream_id: &str,
) -> Result<cyberdeck_packet::streams::StreamTranscript, String> {
    cyberdeck_packet::streams::follow_stream(&capture.packets, stream_id)
}

/// Return only original frame bytes; do not promote reassembled datagrams.
pub(super) fn packet_frame(capture: &CachedCapture, index: usize) -> Result<&[u8], String> {
    let packet = capture
        .packets
        .get(index)
        .ok_or("packet index out of range")?;
    let end = packet
        .offset
        .checked_add(packet.incl_len)
        .ok_or("capture bytes truncated")?;
    capture
        .bytes
        .get(packet.offset..end)
        .ok_or_else(|| "capture bytes truncated".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_keeps_byte_identical_frame_slice_and_original_offset() {
        let frame = [0xff, 0x00, 0xaa, 0x55, 0x00, 0x13];
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&[0u8; 8]);
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes());
        pcap.extend_from_slice(&[0u8; 8]);
        pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&frame);
        let original = pcap.clone();
        let imported = import_bytes(pcap).expect("valid classic pcap");
        assert_eq!(imported.format, "pcap");
        assert_eq!(imported.cache.bytes, original);
        assert_eq!(imported.cache.packets[0].offset, 40);
        assert_eq!(packet_frame(&imported.cache, 0).unwrap(), frame.as_slice());
    }

    #[test]
    fn frame_index_outside_capture_is_rejected() {
        let cache = CachedCapture {
            bytes: vec![],
            linktype: 1,
            first_ts: 0,
            packets: vec![],
        };
        assert_eq!(
            packet_frame(&cache, 0).unwrap_err(),
            "packet index out of range"
        );
    }
}

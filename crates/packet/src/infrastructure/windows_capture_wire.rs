//! CyberDeck-owned Windows kernel capture device wire format, ABI v1.
//! A kernel-side producer must submit EXACT, complete Ethernet frames (DLT 1).
//! A driver is not bundled yet: this decoder never fabricates a packet.
use crate::live::{CaptureError, CaptureErrorCode, MAX_FRAME_BYTES};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAGIC: [u8; 4] = *b"CDCF";
pub const ABI_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 48;
pub const MAX_RECORD_LEN: usize = HEADER_LEN + MAX_FRAME_BYTES;
pub const ETHERNET_DLT: u32 = 1;

#[derive(Debug)]
pub struct OriginalFrame<'a> {
    pub bytes: &'a [u8],
    pub timestamp: SystemTime,
}

fn malformed(reason: &str) -> CaptureError {
    CaptureError {
        code: CaptureErrorCode::Parse,
        message: format!("CyberDeck Windows capture driver record rejected: {reason}"),
    }
}

pub fn decode_original_frame(
    record: &[u8],
    expected_index: u32,
    expected_luid: u64,
) -> Result<OriginalFrame<'_>, CaptureError> {
    if record.len() < HEADER_LEN || record.len() > MAX_RECORD_LEN {
        return Err(malformed("record length outside fixed driver ABI bounds"));
    }
    if record[..4] != MAGIC
        || u16::from_le_bytes([record[4], record[5]]) != ABI_VERSION
        || usize::from(u16::from_le_bytes([record[6], record[7]])) != HEADER_LEN
    {
        return Err(malformed("unknown driver ABI version or record header"));
    }
    let index = u32::from_le_bytes(record[8..12].try_into().unwrap());
    let dlt = u32::from_le_bytes(record[12..16].try_into().unwrap());
    let luid = u64::from_le_bytes(record[16..24].try_into().unwrap());
    let micros = u64::from_le_bytes(record[24..32].try_into().unwrap());
    let cap_len = u32::from_le_bytes(record[32..36].try_into().unwrap()) as usize;
    let wire_len = u32::from_le_bytes(record[36..40].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(record[40..44].try_into().unwrap());
    let reserved = u32::from_le_bytes(record[44..48].try_into().unwrap());
    if index != expected_index || luid != expected_luid || index == 0 || luid == 0 {
        return Err(malformed(
            "record belongs to another selected adapter identity",
        ));
    }
    if dlt != ETHERNET_DLT {
        return Err(malformed("original Ethernet link type is required"));
    }
    if flags != 0 || reserved != 0 {
        return Err(malformed(
            "driver marked frame incomplete or reported unknown flags",
        ));
    }
    if !(14..=MAX_FRAME_BYTES).contains(&cap_len)
        || wire_len != cap_len
        || record.len() != HEADER_LEN + cap_len
    {
        return Err(malformed(
            "truncated, padded or invalid original frame length",
        ));
    }
    // Windows driver must stamp UNIX microseconds from its receive path; no
    // userspace SystemTime::now fallback and no synthetic Ethernet headers.
    let timestamp = UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .ok_or_else(|| malformed("timestamp outside supported clock range"))?;
    // Classic PCAP timestamp field uses unsigned seconds, so prevent
    // readback parse failures or falsely retained captures past year 2106.
    if micros / 1_000_000 > u32::MAX as u64 {
        return Err(malformed("driver timestamp exceeds classic PCAP bounds"));
    }
    Ok(OriginalFrame {
        bytes: &record[HEADER_LEN..],
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + bytes.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&ABI_VERSION.to_le_bytes());
        out.extend_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        out.extend_from_slice(&7u32.to_le_bytes());
        out.extend_from_slice(&ETHERNET_DLT.to_le_bytes());
        out.extend_from_slice(&0x11_22_33_44_55_66_77_88u64.to_le_bytes());
        out.extend_from_slice(&1_700_000_000_123_456u64.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(bytes);
        out
    }
    const LUID: u64 = 0x11_22_33_44_55_66_77_88;
    #[test]
    fn record_keeps_exact_original_frame_and_timestamp() {
        let mut frame = [0u8; 46];
        frame[..6].fill(0xff);
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let data = record(&frame);
        let original = decode_original_frame(&data, 7, LUID).unwrap();
        assert_eq!(original.bytes, frame);
        assert_eq!(
            original.timestamp.duration_since(UNIX_EPOCH).unwrap(),
            Duration::from_micros(1_700_000_000_123_456)
        );
    }
    #[test]
    fn deny_invented_truncated_or_wrong_interface_frames() {
        let r = record(&[0x44u8; 60]);
        assert!(decode_original_frame(&r, 8, LUID).is_err());
        assert!(decode_original_frame(&r, 7, LUID + 1).is_err());
        for n in [0, 1, 13, 47, 48, 49, r.len() - 1] {
            assert!(
                decode_original_frame(&r[..n], 7, LUID).is_err(),
                "truncation {n}"
            );
        }
        let mut wrong = r.clone();
        wrong[12..16].copy_from_slice(&101u32.to_le_bytes());
        assert!(decode_original_frame(&wrong, 7, LUID).is_err());
        wrong = r.clone();
        wrong[32..36].copy_from_slice(&999u32.to_le_bytes());
        assert!(decode_original_frame(&wrong, 7, LUID).is_err());
        wrong = r.clone();
        wrong[36..40].copy_from_slice(&61u32.to_le_bytes());
        assert!(decode_original_frame(&wrong, 7, LUID).is_err());
        wrong = r.clone();
        wrong[40..44].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode_original_frame(&wrong, 7, LUID).is_err());
        wrong = r.clone();
        wrong[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(decode_original_frame(&wrong, 7, LUID).is_err());
        wrong = r.clone();
        wrong.push(0);
        assert!(decode_original_frame(&wrong, 7, LUID).is_err());
    }
    #[test]
    fn reject_timestamp_overflow_and_maximum_frame_overflow() {
        let mut r = record(&[0x44u8; 60]);
        r[24..32].copy_from_slice(&(u64::MAX).to_le_bytes());
        assert!(decode_original_frame(&r, 7, LUID).is_err());
        let oversized = record(&vec![0x55; MAX_FRAME_BYTES + 1]);
        assert!(decode_original_frame(&oversized, 7, LUID).is_err());
        let short = record(&[0x55; 13]);
        assert!(decode_original_frame(&short, 7, LUID).is_err());
    }
    #[test]
    fn native_driver_frame_can_enter_existing_pcap_and_provenance_pipeline() {
        use crate::{
            live::{
                self, CaptureError, CaptureInterface, CaptureLimits, FrameSource, ReceivedFrame,
            },
            parse_capture,
        };
        use std::sync::atomic::AtomicBool;
        struct Fixture(Option<Vec<u8>>);
        impl FrameSource for Fixture {
            fn receive(
                &mut self,
                out: &mut [u8],
                _: Duration,
            ) -> Result<Option<ReceivedFrame>, CaptureError> {
                let Some(record) = self.0.take() else {
                    return Ok(None);
                };
                let frame = decode_original_frame(&record, 7, LUID)?;
                out[..frame.bytes.len()].copy_from_slice(frame.bytes);
                Ok(Some(ReceivedFrame {
                    length: frame.bytes.len(),
                    timestamp: frame.timestamp,
                }))
            }
        }
        let mut original = vec![0xff; 6];
        original.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        original.extend_from_slice(&0x0806u16.to_be_bytes());
        original.extend_from_slice(&[0u8; 28]);
        let mut fixture = Fixture(Some(record(&original)));
        let result = live::capture_from(
            &mut fixture,
            CaptureInterface {
                name: "win7".into(),
                index: 7,
                ethernet: true,
                up: true,
                loopback: false,
            },
            &CaptureLimits {
                max_packets: 1,
                ..CaptureLimits::default()
            },
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(result.frame_provenance.len(), 1);
        assert_eq!(result.original_frame(0).unwrap(), &original);
        let parsed = parse_capture(&result.pcap_bytes).unwrap();
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(
            parsed.packets[0].offset,
            result.frame_provenance[0].pcap_frame_offset
        );
        assert_eq!(parsed.packets[0].incl_len, original.len());
        let original_time = UNIX_EPOCH + Duration::from_micros(1_700_000_000_123_456);
        let captured_secs = u32::from_le_bytes(result.pcap_bytes[24..28].try_into().unwrap());
        let captured_micros = u32::from_le_bytes(result.pcap_bytes[28..32].try_into().unwrap());
        assert_eq!(
            (captured_secs, captured_micros),
            (
                original_time.duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
                123_456
            )
        );
    }
    #[test]
    fn driver_records_cannot_bypass_capture_stop_and_byte_caps() {
        use crate::live::{
            self, CaptureError, CaptureInterface, CaptureLimits, FrameSource, ReceivedFrame,
        };
        use std::sync::atomic::AtomicBool;
        struct Fixture(u32);
        impl FrameSource for Fixture {
            fn receive(
                &mut self,
                out: &mut [u8],
                _: Duration,
            ) -> Result<Option<ReceivedFrame>, CaptureError> {
                self.0 += 1;
                let record = record(&[0x44u8; 60]);
                let frame = decode_original_frame(&record, 7, LUID)?;
                out[..frame.bytes.len()].copy_from_slice(frame.bytes);
                Ok(Some(ReceivedFrame {
                    length: frame.bytes.len(),
                    timestamp: frame.timestamp,
                }))
            }
        }
        let nic = || CaptureInterface {
            name: "win7".into(),
            index: 7,
            ethernet: true,
            up: true,
            loopback: false,
        };
        let mut source = Fixture(0);
        let output = live::capture_from(
            &mut source,
            nic(),
            &CaptureLimits {
                max_packets: 2,
                max_bytes: 1024,
                ..CaptureLimits::default()
            },
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(output.frame_provenance.len(), 2);
        assert_eq!(source.0, 2);
        let mut source = Fixture(0);
        let output = live::capture_from(
            &mut source,
            nic(),
            &CaptureLimits {
                max_packets: 5,
                max_bytes: 40 + 60 + 16,
                ..CaptureLimits::default()
            },
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(output.frame_provenance.len(), 1);
        let mut source = Fixture(0);
        let output = live::capture_from(
            &mut source,
            nic(),
            &CaptureLimits::default(),
            &AtomicBool::new(true),
        )
        .unwrap();
        assert_eq!(source.0, 0);
        assert!(output.frame_provenance.is_empty());
    }

    #[test]
    fn adversarial_small_mutations_never_escape_bounded_frame() {
        let original = record(&[0x23; 64]);
        for byte_index in 0..HEADER_LEN {
            let mut tampered = original.clone();
            tampered[byte_index] ^= 0xff;
            if let Ok(parsed) = decode_original_frame(&tampered, 7, LUID) {
                assert_eq!(parsed.bytes.len(), 64);
                assert_eq!(parsed.bytes, &tampered[HEADER_LEN..]);
            }
        }
    }
}

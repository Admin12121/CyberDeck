//! Classic PCAP writer for exporting packet selections. Emits the
//! little-endian microsecond variant — the baseline classic format the
//! bundled reader accepts and the case evidence importer validates — so an
//! export can always be re-opened by the same parser that read the source.
//! Frame bytes are written verbatim; no dissection or reassembly output is
//! ever substituted for original evidence.

use crate::{MAX_CAPTURE_PACKETS, MAX_PACKET_BYTES, PCAP_MAGIC_LE_USEC};

const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;
/// The writer only ever emits the microsecond variant, so a larger sub-second
/// value would be a unit mistake by the caller, not a formatting choice.
const MAX_USEC_SUBSECOND: u32 = 1_000_000;

/// Refusals are typed instead of `String` so callers can branch on policy
/// violations without parsing messages. No variant carries untrusted payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapWriteError {
    /// More records than one capture may contain.
    TooManyRecords,
    /// A frame exceeds the reader's per-record cap.
    RecordTooLarge,
    /// Zero-length frames carry no evidence and the case artifact importer
    /// refuses them, so exporting one would only fail later.
    EmptyRecord,
    /// Sub-second timestamp does not fit the microsecond resolution.
    SubsecondOutOfRange,
    /// Total output size could not be addressed on this platform.
    LengthOverflow,
}

impl std::fmt::Display for PcapWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            PcapWriteError::TooManyRecords => "selection exceeds the capture record limit",
            PcapWriteError::RecordTooLarge => "a frame exceeds the per-record capture limit",
            PcapWriteError::EmptyRecord => "a frame contains no bytes",
            PcapWriteError::SubsecondOutOfRange => {
                "a timestamp sub-second value exceeds microsecond resolution"
            }
            PcapWriteError::LengthOverflow => "export size overflowed the addressable range",
        };
        f.write_str(message)
    }
}

impl std::error::Error for PcapWriteError {}

/// Write a classic little-endian microsecond PCAP file.
///
/// `records` holds `(ts_sec, ts_subsec, frame)` in capture order. Caps mirror
/// the reader (`MAX_CAPTURE_PACKETS` records, `MAX_PACKET_BYTES` per frame)
/// so untrusted metadata can never inflate the output, and the result always
/// round-trips through [`crate::parse_pcap`]. The original length field is
/// written equal to the captured length: the export persists exactly the
/// bytes it was given and never claims evidence it does not hold.
pub fn write_pcap(linktype: u32, records: &[(u32, u32, &[u8])]) -> Result<Vec<u8>, PcapWriteError> {
    if records.len() > MAX_CAPTURE_PACKETS {
        return Err(PcapWriteError::TooManyRecords);
    }
    // Validate and size in one pass before allocating, so a refused export
    // never produces partial bytes.
    let mut total = GLOBAL_HEADER_LEN;
    for (_, _, frame) in records {
        if frame.is_empty() {
            return Err(PcapWriteError::EmptyRecord);
        }
        if frame.len() > MAX_PACKET_BYTES {
            return Err(PcapWriteError::RecordTooLarge);
        }
        let record_len = RECORD_HEADER_LEN
            .checked_add(frame.len())
            .ok_or(PcapWriteError::LengthOverflow)?;
        total = total
            .checked_add(record_len)
            .ok_or(PcapWriteError::LengthOverflow)?;
    }
    for (_, subsecond, _) in records {
        if *subsecond >= MAX_USEC_SUBSECOND {
            return Err(PcapWriteError::SubsecondOutOfRange);
        }
    }

    // Snaplen advertises the per-record cap the writer enforces; the reader
    // only consults it when non-zero, and 0 would disable that check.
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&PCAP_MAGIC_LE_USEC.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&(MAX_PACKET_BYTES as u32).to_le_bytes());
    out.extend_from_slice(&linktype.to_le_bytes());
    for (ts_sec, subsecond, frame) in records {
        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&subsecond.to_le_bytes());
        let len = frame.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(frame);
    }
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_pcap;

    /// A minimal 42-byte Ethernet ARP request, the kind of frame the offline
    /// studio exports back into a case.
    fn arp_frame() -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 28]);
        frame
    }

    #[test]
    fn write_then_parse_round_trips_linktype_timestamps_and_bytes() {
        let first = arp_frame();
        let second = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        ];
        let records = [
            (1_700_000_000u32, 0u32, first.as_slice()),
            (1_700_000_001, 123_456, second.as_slice()),
        ];
        let bytes = write_pcap(1, &records).expect("valid export");
        let parsed = parse_pcap(&bytes).expect("writer output must re-read");
        assert_eq!(parsed.linktype, 1);
        assert_eq!(parsed.endianness, crate::Endianness::Little);
        assert!(!parsed.nanosecond);
        assert!(!parsed.malformed_tail);
        assert_eq!(parsed.packets.len(), records.len());
        for (meta, (ts_sec, subsecond, frame)) in parsed.packets.iter().zip(records.iter()) {
            assert_eq!(meta.ts_sec, *ts_sec as u64);
            assert_eq!(meta.ts_subsec, *subsecond);
            assert_eq!(meta.incl_len, frame.len());
            assert_eq!(meta.orig_len, frame.len());
            assert_eq!(&bytes[meta.offset..meta.offset + meta.incl_len], *frame);
        }
        assert_eq!(parsed.packets[0].dissected.protocol, "ARP");
    }

    #[test]
    fn empty_selection_writes_only_a_re_readable_header() {
        let bytes = write_pcap(101, &[]).expect("empty export is a valid capture");
        assert_eq!(bytes.len(), GLOBAL_HEADER_LEN);
        let parsed = parse_pcap(&bytes).expect("header-only export must re-read");
        assert_eq!(parsed.linktype, 101);
        assert!(parsed.packets.is_empty());
    }

    #[test]
    fn selections_above_the_reader_record_cap_are_refused() {
        let records = vec![(0u32, 0u32, &b"x"[..]); MAX_CAPTURE_PACKETS + 1];
        assert_eq!(write_pcap(1, &records), Err(PcapWriteError::TooManyRecords));
    }

    #[test]
    fn frames_above_the_reader_record_cap_are_refused() {
        let oversized = vec![0u8; MAX_PACKET_BYTES + 1];
        let records = [(0u32, 0u32, oversized.as_slice())];
        assert_eq!(write_pcap(1, &records), Err(PcapWriteError::RecordTooLarge));
    }

    #[test]
    fn zero_length_frames_and_bad_subsecond_values_are_refused() {
        let empty: Vec<u8> = Vec::new();
        assert_eq!(
            write_pcap(1, &[(0, 0, empty.as_slice())]),
            Err(PcapWriteError::EmptyRecord)
        );
        let frame = arp_frame();
        assert_eq!(
            write_pcap(1, &[(0, MAX_USEC_SUBSECOND, frame.as_slice())]),
            Err(PcapWriteError::SubsecondOutOfRange)
        );
    }

    #[test]
    fn error_messages_are_non_empty_and_stable() {
        for error in [
            PcapWriteError::TooManyRecords,
            PcapWriteError::RecordTooLarge,
            PcapWriteError::EmptyRecord,
            PcapWriteError::SubsecondOutOfRange,
            PcapWriteError::LengthOverflow,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}

//! PCAPNG writer for exporting packet selections. Emits a single
//! little-endian section: SHB + one Interface Description Block (microsecond
//! `if_tsresol`) + one Enhanced Packet Block per record — exactly the block
//! set the bundled reader parses, so an export always round-trips through
//! [`crate::infrastructure::pcapng::parse_pcapng`]. Frame bytes are written
//! verbatim; no dissection or reassembly output is ever substituted for
//! original evidence.

use crate::pcap_write::PcapWriteError;
use crate::{MAX_CAPTURE_PACKETS, MAX_PACKET_BYTES};

const SHB_BLOCK_TYPE: u32 = 0x0a0d_0d0a;
const IDB_BLOCK_TYPE: u32 = 1;
const EPB_BLOCK_TYPE: u32 = 6;
/// Byte-order magic in the section header; written little-endian it reads
/// back as 0x1a2b3c4d, which the reader treats as little-endian.
const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
/// PCAPNG major/minor version the reader accepts (1.0).
const VERSION_MAJOR: u16 = 1;
const VERSION_MINOR: u16 = 0;
/// Microsecond timestamp resolution, encoded as decimal 6 per the spec and
/// matching the classic export's (ts_sec, micro) record shape.
const TSRESOL_MICROSECOND: u8 = 6;
const MICROSECOND_RATE: u64 = 1_000_000;
/// Sub-second values are microseconds, so anything above one million would
/// be a caller unit mistake, not a formatting choice.
const MAX_USEC_SUBSECOND: u32 = 1_000_000;

const SHB_LEN: usize = 28;
const IDB_LEN: usize = 32;
const EPB_HEADER_LEN: usize = 28;
/// if_tsresol option: kind(2) + length(2) + value(1) + padding(3).
const TSRESOL_OPTION_LEN: usize = 8;
/// opt_endofopt: kind(2) + length(2).
const OPT_ENDOFOPT_LEN: usize = 4;

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Write a minimal little-endian PCAPNG file.
///
/// `records` holds `(ts_sec, ts_subsec_micro, frame)` in capture order. Caps
/// mirror the reader (`MAX_CAPTURE_PACKETS` records, `MAX_PACKET_BYTES` per
/// frame) so untrusted metadata can never inflate the output. The original
/// length field is written equal to the captured length: the export persists
/// exactly the bytes it was given and never claims evidence it does not hold.
pub fn write_pcapng(linktype: u32, records: &[(u32, u32, &[u8])]) -> Result<Vec<u8>, PcapWriteError> {
    if records.len() > MAX_CAPTURE_PACKETS {
        return Err(PcapWriteError::TooManyRecords);
    }
    // Validate and size in one pass before allocating, so a refused export
    // never produces partial bytes.
    let mut total = SHB_LEN + IDB_LEN;
    for (_, subsecond, frame) in records {
        if *subsecond >= MAX_USEC_SUBSECOND {
            return Err(PcapWriteError::SubsecondOutOfRange);
        }
        if frame.is_empty() {
            return Err(PcapWriteError::EmptyRecord);
        }
        if frame.len() > MAX_PACKET_BYTES {
            return Err(PcapWriteError::RecordTooLarge);
        }
        let padded = frame.len().saturating_add(3) & !3;
        let block_len = EPB_HEADER_LEN
            .checked_add(padded)
            .and_then(|len| len.checked_add(4))
            .ok_or(PcapWriteError::LengthOverflow)?;
        total = total.checked_add(block_len).ok_or(PcapWriteError::LengthOverflow)?;
    }
    let mut out = Vec::with_capacity(total);

    // Section Header Block: 28 bytes, unspecified section length (u64::MAX).
    let shb_start = out.len();
    push_u32(&mut out, SHB_BLOCK_TYPE);
    push_u32(&mut out, SHB_LEN as u32);
    push_u32(&mut out, BYTE_ORDER_MAGIC);
    push_u16(&mut out, VERSION_MAJOR);
    push_u16(&mut out, VERSION_MINOR);
    push_u64(&mut out, u64::MAX);
    push_u32(&mut out, SHB_LEN as u32);
    debug_assert_eq!(out.len() - shb_start, SHB_LEN);

    // Interface Description Block: linktype, snaplen, microsecond tsresol.
    let idb_start = out.len();
    push_u32(&mut out, IDB_BLOCK_TYPE);
    push_u32(&mut out, IDB_LEN as u32);
    push_u16(&mut out, u16::try_from(linktype).map_err(|_| PcapWriteError::LengthOverflow)?);
    push_u16(&mut out, 0); // reserved
    push_u32(&mut out, MAX_PACKET_BYTES as u32); // snapshot length
    push_u16(&mut out, 9); // if_tsresol
    push_u16(&mut out, 1);
    out.push(TSRESOL_MICROSECOND);
    out.extend_from_slice(&[0, 0, 0]); // option padding
    push_u16(&mut out, 0); // opt_endofopt
    push_u16(&mut out, 0);
    push_u32(&mut out, IDB_LEN as u32);
    debug_assert_eq!(out.len() - idb_start, IDB_LEN);

    for (second, subsecond, frame) in records {
        let ticks = (*second as u64)
            .checked_mul(MICROSECOND_RATE)
            .and_then(|base| base.checked_add(*subsecond as u64))
            .ok_or(PcapWriteError::LengthOverflow)?;
        let padded_len = frame.len().saturating_add(3) & !3;
        // Block total covers type + length + the 20 fixed EPB bytes + the
        // padded frame + the trailing length copy (32 + padded in total).
        let block_len = (EPB_HEADER_LEN + padded_len + 4) as u32;
        let epb_start = out.len();
        push_u32(&mut out, EPB_BLOCK_TYPE);
        push_u32(&mut out, block_len);
        push_u32(&mut out, 0); // interface id: the single IDB above
        push_u32(&mut out, (ticks >> 32) as u32);
        push_u32(&mut out, (ticks & 0xffff_ffff) as u32);
        push_u32(&mut out, frame.len() as u32); // captured
        push_u32(&mut out, frame.len() as u32); // original: export holds what it was given
        out.extend_from_slice(frame);
        out.resize(epb_start + EPB_HEADER_LEN + padded_len, 0); // block padding
        push_u32(&mut out, block_len);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::pcapng::parse_pcapng;

    fn ethernet_frame() -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        ]);
        frame
    }

    #[test]
    fn round_trips_through_the_bundled_reader() {
        let frame = ethernet_frame();
        let records: Vec<(u32, u32, &[u8])> = vec![
            (1_700_000_000, 0, &frame),
            (1_700_000_001, 500_000, &frame),
            (1_700_000_002, 999_999, &frame),
        ];
        let bytes = write_pcapng(1, &records).unwrap();
        let parsed = parse_pcapng(&bytes).unwrap();
        assert_eq!(parsed.linktype, 1);
        assert_eq!(parsed.packets.len(), 3);
        assert!(!parsed.malformed_tail);
        assert_eq!(parsed.packets[0].ts_sec, 1_700_000_000);
        // The reader normalizes microsecond fractions to nanoseconds.
        assert_eq!(parsed.packets[1].ts_sec, 1_700_000_001);
        assert_eq!(parsed.packets[1].ts_subsec, 500_000_000);
        assert_eq!(parsed.packets[2].ts_subsec, 999_999_000);
        for (packet, (_, _, frame)) in parsed.packets.iter().zip(records.iter()) {
            assert_eq!(&bytes[packet.offset..packet.offset + frame.len()], *frame);
            assert_eq!(packet.incl_len, frame.len());
            assert_eq!(packet.orig_len, frame.len());
            assert_eq!(packet.dissected.protocol, "ICMP");
        }
    }

    #[test]
    fn refusals_mirror_the_reader_caps_before_any_allocation() {
        let frame = ethernet_frame();
        let too_many: Vec<(u32, u32, &[u8])> = (0..=MAX_CAPTURE_PACKETS)
            .map(|i| (i as u32, 0, frame.as_slice()))
            .collect();
        assert_eq!(write_pcapng(1, &too_many), Err(PcapWriteError::TooManyRecords));
        let oversized = vec![0u8; MAX_PACKET_BYTES + 1];
        assert_eq!(
            write_pcapng(1, &[(0, 0, oversized.as_slice())]),
            Err(PcapWriteError::RecordTooLarge)
        );
        assert_eq!(write_pcapng(1, &[(0, 0, &[])]), Err(PcapWriteError::EmptyRecord));
        assert_eq!(
            write_pcapng(1, &[(0, MAX_USEC_SUBSECOND, frame.as_slice())]),
            Err(PcapWriteError::SubsecondOutOfRange)
        );
    }

    #[test]
    fn block_lengths_stay_four_byte_aligned_with_padding() {
        // A frame whose length is not a multiple of four must still produce
        // aligned blocks the reader accepts (it enforces total % 4 == 0).
        let odd_frame = vec![7u8; 41];
        let bytes = write_pcapng(1, &[(5, 123_456, odd_frame.as_slice())]).unwrap();
        let parsed = parse_pcapng(&bytes).unwrap();
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(parsed.packets[0].incl_len, 41);
        assert_eq!(parsed.packets[0].ts_sec, 5);
        assert_eq!(parsed.packets[0].ts_subsec, 123_456_000);
        assert!(!parsed.malformed_tail);
    }

    #[test]
    fn non_ethernet_linktype_round_trips() {
        let raw_ip = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2];
        let bytes = write_pcapng(101, &[(9, 1, raw_ip.as_slice())]).unwrap();
        let parsed = parse_pcapng(&bytes).unwrap();
        assert_eq!(parsed.linktype, 101);
        assert_eq!(parsed.packets[0].dissected.protocol, "ICMP");
    }
}

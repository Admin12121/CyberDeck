//! Native PCAPNG section/interface/packet parser.
//! The parser never follows paths, executes commands, or allocates from untrusted
//! captured length fields. Original packet offsets point into the input capture.

use crate::{dissect, Endianness, PacketMeta, PcapFile, MAX_CAPTURE_PACKETS, MAX_PACKET_BYTES};

const SHB: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const MAX_INTERFACES: usize = 256;
const MAX_PACKETS: usize = MAX_CAPTURE_PACKETS;

#[derive(Clone, Copy)]
struct Interface {
    linktype: u32,
    snaplen: usize,
    ticks_per_second: u64,
    time_offset: i64,
}

fn u16_at(data: &[u8], at: usize, big: bool) -> Option<u16> {
    let bytes: [u8; 2] = data.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(if big {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    })
}

fn u32_at(data: &[u8], at: usize, big: bool) -> Option<u32> {
    let bytes: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

fn u64_at(data: &[u8], at: usize, big: bool) -> Option<u64> {
    let bytes: [u8; 8] = data.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(if big {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    })
}

fn parse_interface_options(options: &[u8], big: bool, iface: &mut Interface) -> bool {
    let mut pos = 0usize;
    while pos < options.len() {
        if options.len() - pos < 4 {
            return false;
        }
        let kind = match u16_at(options, pos, big) {
            Some(x) => x,
            None => return false,
        };
        let len = match u16_at(options, pos + 2, big) {
            Some(x) => x as usize,
            None => return false,
        };
        pos += 4;
        let padded = match len.checked_add(3) {
            Some(x) => x & !3,
            None => return false,
        };
        let Some(val) = options.get(pos..pos.saturating_add(len)) else {
            return false;
        };
        let Some(end) = pos.checked_add(padded) else {
            return false;
        };
        if end > options.len() {
            return false;
        }
        if kind == 0 {
            return len == 0;
        }
        if kind == 9 && len == 1 {
            let resolution = val[0];
            let rate = if resolution & 0x80 == 0 {
                10u64.checked_pow(resolution as u32)
            } else {
                2u64.checked_pow((resolution & 0x7f) as u32)
            };
            // Unrepresentable resolutions are not silently interpreted as usec.
            let Some(rate) = rate else { return false };
            iface.ticks_per_second = rate;
        } else if kind == 14 && len == 8 {
            let Some(raw) = u64_at(val, 0, big) else {
                return false;
            };
            iface.time_offset = raw as i64;
        }
        pos = end;
    }
    true
}

fn push_packet(
    packets: &mut Vec<PacketMeta>,
    assembler: &mut crate::fragments::FragmentReassembler,
    data: &[u8],
    payload_offset: usize,
    captured: usize,
    original: usize,
    iface: Interface,
    ticks: u64,
) -> bool {
    if captured > MAX_PACKET_BYTES || captured > iface.snaplen || captured > original {
        return false;
    }
    let Some(payload) = data.get(payload_offset..payload_offset.saturating_add(captured)) else {
        return false;
    };
    let rate = iface.ticks_per_second.max(1);
    let seconds = ticks / rate;
    let fraction = ((ticks % rate) as u128 * 1_000_000_000u128 / rate as u128) as u32;
    let shifted = seconds as i128 + iface.time_offset as i128;
    // if_tsoffset is signed whole seconds; clamp the fractional component
    // along with the whole seconds when the adjusted time is negative.
    let (sec, fraction) = if shifted < 0 {
        (0, 0)
    } else {
        (shifted.min(u64::MAX as i128) as u64, fraction)
    };
    assembler.push_frame(iface.linktype, payload, packets.len());
    packets.push(PacketMeta {
        offset: payload_offset,
        incl_len: captured,
        orig_len: original,
        ts_sec: sec,
        ts_subsec: fraction,
        dissected: dissect(iface.linktype, payload),
    });
    true
}

/// Parse sections of either endianness, per-interface link types, enhanced
/// packet blocks, obsolete Packet Blocks and Simple Packet Blocks. Unknown blocks skip
/// only after verifying their lengths, trailer and four-byte alignment.
///
/// PCAPNG timestamp fractions are normalized to nanoseconds.
pub fn parse_pcapng(data: &[u8]) -> Result<PcapFile, String> {
    if data.len() < 28 || !data.starts_with(&SHB) {
        return Err("not a PCAPNG section header".into());
    }
    let mut pos = 0usize;
    let mut big = false;
    let mut saw_section = false;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut packets: Vec<PacketMeta> = Vec::new();
    let mut assembler = crate::fragments::FragmentReassembler::new();
    let mut malformed_tail = false;
    let mut first_linktype = None;
    let mut first_endian = Endianness::Little;

    while pos < data.len() {
        if data.len() - pos < 12 {
            malformed_tail = true;
            break;
        }
        let section_start = data.get(pos..pos + 4) == Some(&SHB);
        if section_start {
            match data.get(pos + 8..pos + 12) {
                Some([0x4d, 0x3c, 0x2b, 0x1a]) => big = false,
                Some([0x1a, 0x2b, 0x3c, 0x4d]) => big = true,
                _ => {
                    if !saw_section {
                        return Err("invalid PCAPNG byte-order magic".into());
                    }
                    malformed_tail = true;
                    break;
                }
            }
        } else if !saw_section {
            return Err("PCAPNG capture does not begin with a section header".into());
        }
        let Some(block_type) = u32_at(data, pos, big) else {
            malformed_tail = true;
            break;
        };
        let Some(total) = u32_at(data, pos + 4, big).map(|n| n as usize) else {
            malformed_tail = true;
            break;
        };
        let min_len = if section_start { 28 } else { 12 };
        let Some(block_end) = pos.checked_add(total) else {
            malformed_tail = true;
            break;
        };
        if total < min_len
            || total % 4 != 0
            || block_end > data.len()
            || u32_at(data, block_end - 4, big) != Some(total as u32)
        {
            if !saw_section {
                return Err("invalid PCAPNG section length or trailer".into());
            }
            malformed_tail = true;
            break;
        }
        if section_start {
            if saw_section {
                assembler.reset_section();
            }
            saw_section = true;
            if u16_at(data, pos + 12, big) != Some(1) {
                return Err("unsupported PCAPNG major version".into());
            }
            if first_linktype.is_none() {
                first_endian = if big {
                    Endianness::Big
                } else {
                    Endianness::Little
                };
            }
            interfaces.clear();
        } else if block_type == 1 {
            if total < 20 || interfaces.len() >= MAX_INTERFACES {
                malformed_tail = true;
                break;
            }
            let Some(linktype) = u16_at(data, pos + 8, big).map(u32::from) else {
                malformed_tail = true;
                break;
            };
            let snaplen = u32_at(data, pos + 12, big).unwrap_or(0) as usize;
            let mut iface = Interface {
                linktype,
                snaplen: if snaplen == 0 {
                    MAX_PACKET_BYTES
                } else {
                    snaplen
                },
                ticks_per_second: 1_000_000,
                time_offset: 0,
            };
            if !parse_interface_options(&data[pos + 16..block_end - 4], big, &mut iface) {
                malformed_tail = true;
                break;
            }
            first_linktype.get_or_insert(linktype);
            interfaces.push(iface);
        } else if block_type == 6 || block_type == 2 {
            // Obsolete Packet Block (2) uses a u16 interface ID and u16
            // drop count. The subsequent fields match the Enhanced Block.
            if total < 32 || packets.len() >= MAX_PACKETS {
                malformed_tail = true;
                break;
            }
            let iface_id = if block_type == 2 {
                u16_at(data, pos + 8, big).unwrap_or(u16::MAX) as usize
            } else {
                u32_at(data, pos + 8, big).unwrap_or(u32::MAX) as usize
            };
            let Some(iface) = interfaces.get(iface_id).copied() else {
                malformed_tail = true;
                break;
            };
            let ticks = ((u32_at(data, pos + 12, big).unwrap_or(0) as u64) << 32)
                | u32_at(data, pos + 16, big).unwrap_or(0) as u64;
            let captured = u32_at(data, pos + 20, big).unwrap_or(u32::MAX) as usize;
            let original = u32_at(data, pos + 24, big).unwrap_or(u32::MAX) as usize;
            let padded = captured.saturating_add(3) & !3;
            if captured > MAX_PACKET_BYTES
                || 28usize.saturating_add(padded).saturating_add(4) > total
                || !push_packet(
                    &mut packets,
                    &mut assembler,
                    data,
                    pos + 28,
                    captured,
                    original,
                    iface,
                    ticks,
                )
            {
                malformed_tail = true;
                break;
            }
        } else if block_type == 3 {
            if total < 16 || packets.len() >= MAX_PACKETS {
                malformed_tail = true;
                break;
            }
            let Some(iface) = interfaces.first().copied() else {
                malformed_tail = true;
                break;
            };
            let original = u32_at(data, pos + 8, big).unwrap_or(u32::MAX) as usize;
            let body_len = total - 16;
            let captured = original.min(iface.snaplen).min(body_len);
            if captured > MAX_PACKET_BYTES
                || !push_packet(
                    &mut packets,
                    &mut assembler,
                    data,
                    pos + 12,
                    captured,
                    original,
                    iface,
                    0,
                )
            {
                malformed_tail = true;
                break;
            }
        }
        pos = block_end;
    }
    Ok(PcapFile {
        linktype: first_linktype.unwrap_or(1),
        endianness: first_endian,
        nanosecond: true,
        packets,
        reassembly: assembler.finish(),
        malformed_tail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn write_u32(out: &mut Vec<u8>, n: u32, big: bool) {
        out.extend_from_slice(&if big {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        });
    }
    fn write_u16(out: &mut Vec<u8>, n: u16, big: bool) {
        out.extend_from_slice(&if big {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        });
    }
    fn block(kind: u32, body: &[u8], big: bool) -> Vec<u8> {
        let mut ret = Vec::new();
        write_u32(&mut ret, kind, big);
        let len = (body.len() + 12) as u32;
        write_u32(&mut ret, len, big);
        ret.extend_from_slice(body);
        write_u32(&mut ret, len, big);
        ret
    }
    fn shb(big: bool) -> Vec<u8> {
        let mut body = Vec::new();
        write_u32(&mut body, 0x1a2b3c4d, big);
        write_u16(&mut body, 1, big);
        write_u16(&mut body, 0, big);
        body.extend_from_slice(&[0xff; 8]);
        block(0x0a0d0d0a, &body, big)
    }
    fn idb(big: bool, link: u16, res: u8) -> Vec<u8> {
        let mut body = Vec::new();
        write_u16(&mut body, link, big);
        write_u16(&mut body, 0, big);
        write_u32(&mut body, 65535, big);
        write_u16(&mut body, 9, big);
        write_u16(&mut body, 1, big);
        body.extend_from_slice(&[res, 0, 0, 0]);
        block(1, &body, big)
    }
    fn epb(big: bool, interface: u32, ticks: u64, frame: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        write_u32(&mut body, interface, big);
        write_u32(&mut body, (ticks >> 32) as u32, big);
        write_u32(&mut body, ticks as u32, big);
        write_u32(&mut body, frame.len() as u32, big);
        write_u32(&mut body, frame.len() as u32, big);
        body.extend_from_slice(frame);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        block(6, &body, big)
    }

    #[test]
    fn reads_both_endianness_and_timestamp_resolution() {
        for big in [false, true] {
            let mut input = shb(big);
            input.extend(idb(big, 101, 9));
            let frame = [
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
            ];
            input.extend(epb(big, 0, 1_500_000_123, &frame));
            let capture = parse_pcapng(&input).unwrap();
            assert_eq!(capture.packets.len(), 1);
            assert_eq!(capture.linktype, 101);
            assert_eq!(capture.packets[0].ts_sec, 1);
            assert_eq!(capture.packets[0].ts_subsec, 500_000_123);
            assert_eq!(
                &input[capture.packets[0].offset..capture.packets[0].offset + frame.len()],
                &frame
            );
            assert_eq!(capture.packets[0].dissected.protocol, "ICMP");
            assert!(!capture.malformed_tail);
        }
    }
    #[test]
    fn per_interface_linktype_and_multi_sections() {
        let mut input = shb(false);
        input.extend(idb(false, 1, 6));
        input.extend(idb(false, 101, 6));
        input.extend(epb(
            false,
            1,
            1234567,
            &[
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
            ],
        ));
        input.extend(shb(true));
        input.extend(idb(true, 101, 6));
        input.extend(epb(
            true,
            0,
            0,
            &[
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
            ],
        ));
        let parsed = parse_pcapng(&input).unwrap();
        assert_eq!(parsed.packets.len(), 2);
        assert_eq!(parsed.packets[0].ts_sec, 1);
        assert_eq!(parsed.packets[0].ts_subsec, 234_567_000);
        assert!(!parsed.malformed_tail);
    }
    #[test]
    fn malformed_block_length_and_packet_are_bounded() {
        let mut input = shb(false);
        input.extend(idb(false, 1, 6));
        input.extend(epb(false, 0, 10, &[1, 2, 3, 4]));
        let mut bad = epb(false, 0, 11, &[5, 6, 7, 8]);
        bad[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        input.extend(bad);
        let parsed = parse_pcapng(&input).unwrap();
        assert_eq!(parsed.packets.len(), 1);
        assert!(parsed.malformed_tail);
        assert!(parse_pcapng(&[0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]).is_err());
    }
    #[test]
    fn handles_unknown_blocks_and_simple_packets() {
        let mut input = shb(false);
        input.extend(idb(false, 101, 6));
        input.extend(block(0x1234, &[], false));
        let mut data = Vec::new();
        write_u32(&mut data, 4, false);
        data.extend_from_slice(&[1, 2, 3, 4]);
        input.extend(block(3, &data, false));
        let p = parse_pcapng(&input).unwrap();
        assert_eq!(p.packets.len(), 1);
        assert_eq!(p.packets[0].incl_len, 4);
        assert!(!p.malformed_tail);
    }
    #[test]
    fn rejects_invalid_byte_order_and_missing_interface() {
        let mut bad = shb(false);
        bad[8..12].copy_from_slice(&[1, 2, 3, 4]);
        assert!(parse_pcapng(&bad).is_err());
        let mut absent = shb(false);
        absent.extend(epb(false, 0, 0, &[1, 2, 3, 4]));
        assert!(parse_pcapng(&absent).unwrap().malformed_tail);
    }

    fn old_packet_block(big: bool, iface_id: u16, ticks: u64, frame: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        write_u16(&mut body, iface_id, big);
        write_u16(&mut body, 2, big); // dropped packets counter
        write_u32(&mut body, (ticks >> 32) as u32, big);
        write_u32(&mut body, ticks as u32, big);
        write_u32(&mut body, frame.len() as u32, big);
        write_u32(&mut body, frame.len() as u32, big);
        body.extend_from_slice(frame);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        block(2, &body, big)
    }

    fn idb_with_offset(big: bool, offset: i64, resolution: u8) -> Vec<u8> {
        let mut body = Vec::new();
        write_u16(&mut body, 101, big);
        write_u16(&mut body, 0, big);
        write_u32(&mut body, 65535, big);
        write_u16(&mut body, 9, big); // if_tsresol
        write_u16(&mut body, 1, big);
        body.extend_from_slice(&[resolution, 0, 0, 0]);
        write_u16(&mut body, 14, big); // if_tsoffset, signed seconds
        write_u16(&mut body, 8, big);
        body.extend_from_slice(&if big {
            offset.to_be_bytes()
        } else {
            offset.to_le_bytes()
        });
        block(1, &body, big)
    }

    #[test]
    fn obsolete_packet_blocks_decode_both_endiannesses_and_keep_payload_offsets() {
        for big in [false, true] {
            let mut capture = shb(big);
            capture.extend(idb(big, 101, 6));
            let frame = [
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
            ];
            capture.extend(old_packet_block(big, 0, 3_125_000, &frame));
            let parsed = parse_pcapng(&capture).unwrap();
            assert_eq!(parsed.packets.len(), 1);
            assert_eq!(parsed.packets[0].ts_sec, 3);
            assert_eq!(parsed.packets[0].ts_subsec, 125_000_000);
            assert_eq!(parsed.packets[0].dissected.protocol, "ICMP");
            assert_eq!(
                &capture[parsed.packets[0].offset..parsed.packets[0].offset + frame.len()],
                &frame
            );
            assert!(!parsed.malformed_tail);
        }
    }

    #[test]
    fn signed_timestamp_offsets_and_binary_resolutions_are_correct() {
        for big in [false, true] {
            let mut positive = shb(big);
            positive.extend(idb_with_offset(big, 2, 0x8a)); // 2^10 ticks/s
            positive.extend(epb(big, 0, 1_536, &[0; 4]));
            let first = parse_pcapng(&positive).unwrap();
            assert_eq!(first.packets[0].ts_sec, 3);
            assert_eq!(first.packets[0].ts_subsec, 500_000_000);

            let mut negative = shb(big);
            negative.extend(idb_with_offset(big, -2, 0x8a));
            negative.extend(epb(big, 0, 512, &[0; 4]));
            let second = parse_pcapng(&negative).unwrap();
            assert_eq!(second.packets[0].ts_sec, 0);
            assert_eq!(second.packets[0].ts_subsec, 0);
        }
    }

    #[test]
    fn obsolete_packet_block_rejects_invalid_interface_and_length() {
        let mut capture = shb(false);
        capture.extend(idb(false, 101, 6));
        capture.extend(old_packet_block(false, 77, 1_000, &[1, 2, 3, 4]));
        assert!(parse_pcapng(&capture).unwrap().malformed_tail);

        let mut capture = shb(false);
        capture.extend(idb(false, 101, 6));
        let mut invalid = old_packet_block(false, 0, 1_000, &[1, 2, 3, 4]);
        // Original length must not be less than captured length.
        invalid[24..28].copy_from_slice(&1u32.to_le_bytes());
        capture.extend(invalid);
        assert!(parse_pcapng(&capture).unwrap().malformed_tail);
    }

    #[test]
    fn pcapng_fragment_reassembly_obeys_interface_linktype_and_section_boundary() {
        fn ipv4(id: u16, offset: usize, more: bool, part: &[u8]) -> Vec<u8> {
            let mut ip = vec![0x45, 0];
            ip.extend_from_slice(&((20 + part.len()) as u16).to_be_bytes());
            ip.extend_from_slice(&id.to_be_bytes());
            ip.extend_from_slice(
                &(((offset / 8) as u16) | if more { 0x2000 } else { 0 }).to_be_bytes(),
            );
            ip.extend_from_slice(&[64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
            ip.extend_from_slice(part);
            ip
        }
        let mut udp = vec![0x04, 0xd2, 0, 53, 0, 24, 0, 0];
        udp.extend_from_slice(&[0x42; 16]);
        let first = ipv4(100, 0, true, &udp[..16]);
        let last = ipv4(100, 16, false, &udp[16..]);

        let mut capture = shb(false);
        capture.extend(idb(false, 1, 6)); // Ethernet interface 0
        capture.extend(idb(false, 101, 6)); // RAW interface 1
        capture.extend(epb(false, 1, 0, &last));
        capture.extend(epb(false, 1, 1, &first));
        let parsed = parse_pcapng(&capture).unwrap();
        assert_eq!(parsed.reassembly.completed.len(), 1);
        assert_eq!(parsed.reassembly.completed[0].dissected.protocol, "DNS");
        assert_eq!(parsed.reassembly.completed[0].ip_packet[20..], udp);

        // A new SHB begins a new fragment namespace; identical IDs in
        // distinct sections must not be combined.
        let mut split = shb(false);
        split.extend(idb(false, 101, 6));
        split.extend(epb(false, 0, 0, &first));
        split.extend(shb(true));
        split.extend(idb(true, 101, 6));
        split.extend(epb(true, 0, 1, &last));
        let parsed = parse_pcapng(&split).unwrap();
        assert!(parsed.reassembly.completed.is_empty());
        assert_eq!(parsed.reassembly.incomplete, 2);
    }
}

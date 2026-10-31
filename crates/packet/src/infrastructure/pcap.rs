//! Classic PCAP file-format adapter. Input remains borrowed and evidence offsets
//! continue to refer to the unmodified original capture buffer.
use crate::{
    dissect, fragments, Endianness, PacketMeta, PcapFile, MAX_CAPTURE_PACKETS, MAX_PACKET_BYTES,
    PCAP_MAGIC_BE_NSEC, PCAP_MAGIC_BE_USEC, PCAP_MAGIC_LE_NSEC, PCAP_MAGIC_LE_USEC,
};

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn u16(&mut self) -> Option<u16> {
        let b = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(if self.big_endian {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(if self.big_endian {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.data.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(b)
    }
}

/// Parse a classic PCAP capture. PCAPNG is intentionally rejected with a
/// clear message until that parser lands.
pub fn parse_pcap(data: &[u8]) -> Result<PcapFile, String> {
    if data.len() < 24 {
        return Err("file is too small to be a pcap capture".to_string());
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if matches!(magic, 0x0a0d_0d0a) {
        return Err("pcapng captures arrive in a later arc; save as classic pcap".to_string());
    }
    let (big_endian, nanosecond, linktype) = match magic {
        PCAP_MAGIC_LE_USEC => (
            false,
            false,
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        ),
        PCAP_MAGIC_BE_USEC => (
            true,
            false,
            u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        ),
        PCAP_MAGIC_LE_NSEC => (
            false,
            true,
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        ),
        PCAP_MAGIC_BE_NSEC => (
            true,
            true,
            u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        ),
        other => return Err(format!("not a pcap capture (magic 0x{other:08x})")),
    };

    let snaplen = if big_endian {
        u32::from_be_bytes([data[16], data[17], data[18], data[19]])
    } else {
        u32::from_le_bytes([data[16], data[17], data[18], data[19]])
    };
    let mut reader = Reader {
        data,
        pos: 24,
        big_endian,
    };
    let mut packets = Vec::new();
    let mut assembler = fragments::FragmentReassembler::new();
    let mut malformed_tail = false;
    while reader.pos < data.len() {
        if packets.len() >= MAX_CAPTURE_PACKETS {
            malformed_tail = true;
            break;
        }
        let Some(ts_sec) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        let Some(ts_subsec) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        let Some(incl_len) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        let Some(orig_len) = reader.u32() else {
            malformed_tail = true;
            break;
        };
        // The capture cannot contain more bytes than existed on the wire.
        // Reject inconsistent evidence length metadata before dissection.
        if incl_len > orig_len
            || (snaplen != 0 && incl_len > snaplen)
            || incl_len as usize > MAX_PACKET_BYTES
            || reader.pos + incl_len as usize > data.len()
        {
            malformed_tail = true;
            break;
        }
        let offset = reader.pos;
        let bytes = reader.bytes(incl_len as usize).unwrap_or(&[]);
        let dissected = dissect(linktype, bytes);
        assembler.push_frame(linktype, bytes, packets.len());
        packets.push(PacketMeta {
            offset,
            incl_len: incl_len as usize,
            orig_len: orig_len as usize,
            ts_sec: ts_sec as u64,
            ts_subsec,
            dissected,
        });
    }
    Ok(PcapFile {
        linktype,
        endianness: if big_endian {
            Endianness::Big
        } else {
            Endianness::Little
        },
        nanosecond,
        packets,
        reassembly: assembler.finish(),
        malformed_tail,
    })
}

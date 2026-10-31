//! Stable packet, capture, and protocol metadata used by the native packet core.
//! Data types remain serialized identically and re-exported at the crate root.
use crate::fragments;
use serde::Serialize;

pub const MAX_PACKET_BYTES: usize = 262_144;
/// Avoid unbounded metadata allocation for captures full of tiny/empty records.
pub const MAX_CAPTURE_PACKETS: usize = 200_000;
pub const PCAP_MAGIC_LE_USEC: u32 = 0xa1b2_c3d4;
pub const PCAP_MAGIC_BE_USEC: u32 = 0xd4c3_b2a1;
pub const PCAP_MAGIC_LE_NSEC: u32 = 0xa1b2_3c4d;
pub const PCAP_MAGIC_BE_NSEC: u32 = 0x4d3c_b2a1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Serialize)]
pub struct Layer {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpMeta {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub flags: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dissected {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub info: String,
    pub color_hint: String,
    pub layers: Vec<Layer>,
    /// Canonical "endpointA|endpointB" for TCP/UDP streams.
    pub stream_id: Option<String>,
    pub tcp: Option<TcpMeta>,
    /// Transport payload bytes for TCP/UDP (bounded).
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketMeta {
    pub offset: usize,
    pub incl_len: usize,
    pub orig_len: usize,
    pub ts_sec: u64,
    pub ts_subsec: u32,
    #[serde(skip)]
    pub dissected: Dissected,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapFile {
    pub linktype: u32,
    pub endianness: Endianness,
    pub nanosecond: bool,
    pub packets: Vec<PacketMeta>,
    /// Derived, bounded IP fragment results; original frames are never rewritten.
    pub reassembly: fragments::ReassemblyReport,
    /// Records skipped because their length fields were implausible.
    pub malformed_tail: bool,
}

//! Cached evidence-backed capture for a single active capture session.
use cyberdeck_packet::PacketMeta;

pub struct CachedCapture {
    pub bytes: Vec<u8>,
    /// Kept for future protocol-hierarchy stats; unused this arc.
    #[allow(dead_code)]
    pub linktype: u32,
    #[allow(dead_code)]
    pub first_ts: u64,
    /// Timestamp subsecond scale of the source file (ns vs µs). Capture-wide
    /// statistics need the exact scale for honest time bucketing.
    pub nanosecond: bool,
    pub packets: Vec<PacketMeta>,
}

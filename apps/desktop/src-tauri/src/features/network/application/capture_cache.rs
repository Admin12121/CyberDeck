//! Cached evidence-backed capture for a single active capture session.
use cyberdeck_packet::PacketMeta;

pub struct CachedCapture {
    pub bytes: Vec<u8>,
    /// Kept for future protocol-hierarchy stats; unused this arc.
    #[allow(dead_code)]
    pub linktype: u32,
    #[allow(dead_code)]
    pub first_ts: u64,
    pub packets: Vec<PacketMeta>,
}

//! Offline capture import orchestration; no filesystem or live capture side effects.
use crate::{parse_pcap, pcapng, streams, PcapFile};

/// Detect either classic PCAP or PCAPNG without invoking external tools.
pub fn parse_capture(data: &[u8]) -> Result<PcapFile, String> {
    let mut capture = if data.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        pcapng::parse_pcapng(data)?
    } else {
        parse_pcap(data)?
    };
    streams::assign_tcp_sessions(&mut capture.packets);
    Ok(capture)
}

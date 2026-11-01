//! Classic PCAP parsing + Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP dissection.
//! Guard rails: length fields validated, malformed tails flagged.

pub mod application;
pub mod dns;
pub mod domain;
pub mod fragments;
pub mod infrastructure;
pub mod inventory;
pub mod live;
pub mod streams;

pub use application::capture::parse_capture;
pub use domain::dissection::dissect;
pub use infrastructure::pcap::parse_pcap;
pub use infrastructure::pcapng;

pub use domain::{
    Dissected, Endianness, Layer, PacketMeta, PcapFile, TcpMeta, MAX_CAPTURE_PACKETS,
    MAX_PACKET_BYTES, PCAP_MAGIC_BE_NSEC, PCAP_MAGIC_BE_USEC, PCAP_MAGIC_LE_NSEC,
    PCAP_MAGIC_LE_USEC,
};

#[cfg(test)]
mod tests;

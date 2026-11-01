//! File-format adapters; packet algorithms and domain types live outside this layer.
pub mod pcap;
pub mod pcapng;

#[cfg(target_os = "windows")]
pub mod windows_interfaces;

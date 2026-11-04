//! File-format adapters; packet algorithms and domain types live outside this layer.
pub mod pcap;
pub mod pcapng;

#[cfg(target_os = "windows")]
pub mod windows_capture;
#[cfg(target_os = "windows")]
pub mod windows_interfaces;
// Versioned native receive protocol remains platform-neutral for hostile-record fixtures.
pub mod windows_capture_wire;
pub mod bpf_capture;

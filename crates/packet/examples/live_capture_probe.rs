//! Explicit Linux N2 capture smoke probe; no implicit capture or privilege escalation.
//! Usage: cargo run -p cyberdeck-packet --example live_capture_probe -- eth0
use cyberdeck_packet::live::{capture_linux, discover_interfaces, CaptureLimits};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn main() {
    let interfaces = match discover_interfaces() {
        Ok(interfaces) => interfaces,
        Err(error) => {
            eprintln!(
                "Interface discovery failed: {:?}: {}",
                error.code, error.message
            );
            std::process::exit(2);
        }
    };
    for interface in &interfaces {
        println!(
            "{} index={} ethernet={} up={} loopback={}",
            interface.name, interface.index, interface.ethernet, interface.up, interface.loopback
        );
    }
    let Some(name) = std::env::args().nth(1) else {
        println!("No interface selected. Pass one exact interface name to explicitly start a bounded capture.");
        return;
    };
    let limits = CaptureLimits {
        max_packets: 4,
        max_bytes: 256 * 1024,
        duration: Duration::from_secs(1),
        poll_interval: Duration::from_millis(100),
    };
    match capture_linux(&name, &limits, &AtomicBool::new(false)) {
        Ok(result) => println!(
            "Captured {} original Ethernet frames, {} hosts, {} flows, reason={:?}; PCAP bytes={} (not saved to disk)",
            result.frame_provenance.len(),
            result.inventory.hosts.len(),
            result.inventory.flows.len(),
            result.stop_reason,
            result.pcap_bytes.len()
        ),
        Err(error) => {
            eprintln!("Capture rejected: {:?}: {}", error.code, error.message);
            std::process::exit(3);
        }
    }
}

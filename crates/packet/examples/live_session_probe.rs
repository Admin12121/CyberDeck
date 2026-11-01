//! Explicit Linux application-session smoke test, not a case import.
//! No interface argument => list only, no socket opened.
//! Usage: cargo run -p cyberdeck-packet --example live_session_probe -- eth0
//! Uses a local probe label, NOT an authorized case in the real application.
use cyberdeck_packet::application::live_session::{CaptureSessionManager, Phase};
use cyberdeck_packet::live::{discover_interfaces, CaptureLimits};
use std::time::{Duration, Instant};

fn main() {
    let interfaces = match discover_interfaces() {
        Ok(values) => values,
        Err(err) => {
            eprintln!("Interface discovery: {:?}: {}", err.code, err.message);
            std::process::exit(2);
        }
    };
    for item in &interfaces {
        println!(
            "{} index={} ethernet={} up={}",
            item.name, item.index, item.ethernet, item.up
        );
    }
    let Some(interface) = std::env::args().nth(1) else {
        println!("No interface selected; no capture attempted.");
        return;
    };
    let manager = CaptureSessionManager::new();
    let limits = CaptureLimits {
        max_packets: 4,
        max_bytes: 256 * 1024,
        duration: Duration::from_secs(1),
        poll_interval: Duration::from_millis(100),
    };
    // This CLI-only local label is never an authorization or evidence case.
    let start = match manager.start_linux("local-probe-not-a-case", &interface, limits) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("Cannot start: {:?}: {}", err.code, err.message);
            std::process::exit(3);
        }
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let state = manager
            .status("local-probe-not-a-case", start.session_id)
            .expect("probe can read its own session");
        if matches!(state.phase, Phase::Completed | Phase::Failed) {
            if let Some(error) = state.error {
                eprintln!("Native capture failed: {:?}: {}", error.code, error.message);
                manager.shutdown();
                std::process::exit(4);
            }
            println!(
                "Capture stopped {:?}, frames={}, bytes={} (not saved or imported)",
                state.stop_reason, state.progress.packets, state.progress.stored_pcap_bytes
            );
            break;
        }
        if Instant::now() >= deadline {
            let _ = manager.stop("local-probe-not-a-case", start.session_id);
            manager.shutdown();
            eprintln!("Probe deadline exceeded; capture cancelled.");
            std::process::exit(5);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    manager.shutdown();
}

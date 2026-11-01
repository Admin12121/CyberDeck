//! Explicit N2 Linux host acceptance. Never escalates privileges or sends traffic.
//! Run only on an authorized interface with CAP_NET_RAW:
//! cargo run -p cyberdeck-packet --example live_host_acceptance -- eth0 --accept-live
//! This validates transient memory results; case import still requires desktop approval.
use cyberdeck_packet::application::live_session::{CaptureSessionManager, Phase};
use cyberdeck_packet::live::{discover_interfaces, select_interface, CaptureLimits, StopReason};
use cyberdeck_packet::parse_capture;
use std::time::{Duration, Instant};

fn interface_flags(name: &str) -> Result<u32, String> {
    #[cfg(target_os = "linux")]
    {
        let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
            .map_err(|e| format!("read kernel interface flags: {e}"))?;
        u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
            .map_err(|e| format!("decode kernel interface flags: {e}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err("live capture acceptance is supported on Linux only".into())
    }
}

fn acceptance(interface: &str) -> Result<(), String> {
    let selected = select_interface(&discover_interfaces().map_err(|e| e.message)?, interface)
        .map_err(|e| e.message)?;
    let promisc_before = interface_flags(&selected.name)? & 0x100 != 0; // IFF_PROMISC
    let manager = CaptureSessionManager::new();
    let limits = CaptureLimits {
        max_packets: 64,
        max_bytes: 1024 * 1024,
        duration: Duration::from_secs(5),
        poll_interval: Duration::from_millis(100),
    };
    let started_at = Instant::now();
    let session = manager
        .start_linux("explicit-host-probe-not-case", &selected.name, limits)
        .map_err(|e| e.message)?;
    let runtime = Duration::from_millis(750);
    while started_at.elapsed() < runtime {
        let current = manager
            .status("explicit-host-probe-not-case", session.session_id)
            .map_err(|e| e.message)?;
        if current.phase != Phase::Running {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let stop_requested_at = Instant::now();
    manager
        .stop("explicit-host-probe-not-case", session.session_id)
        .map_err(|e| e.message)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let final_status = loop {
        let current = manager
            .status("explicit-host-probe-not-case", session.session_id)
            .map_err(|e| e.message)?;
        if matches!(current.phase, Phase::Completed | Phase::Failed) {
            break current;
        }
        if Instant::now() > deadline {
            manager.shutdown();
            return Err("capture did not stop within 3s after cancellation".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stop_latency = stop_requested_at.elapsed();
    if let Some(error) = final_status.error {
        return Err(format!("{:?}: {}", error.code, error.message));
    }
    let result = manager
        .completed_for_case("explicit-host-probe-not-case", session.session_id)
        .map_err(|e| e.message)?;
    let parsed = parse_capture(&result.pcap_bytes)?;
    if parsed.malformed_tail || parsed.packets.len() != result.frame_provenance.len() {
        return Err("PCAP parser reports an incomplete/mismatched captured frame".into());
    }
    for (index, (meta, span)) in parsed
        .packets
        .iter()
        .zip(&result.frame_provenance)
        .enumerate()
    {
        let frame = result
            .original_frame(index)
            .ok_or("original frame missing")?;
        if span.packet_index != index
            || meta.offset != span.pcap_frame_offset
            || frame.len() != meta.incl_len
            || span.captured_length != frame.len()
            || result
                .pcap_bytes
                .get(meta.offset..meta.offset + meta.incl_len)
                != Some(frame)
        {
            return Err(format!(
                "original frame offset/byte identity failed at index {index}"
            ));
        }
    }
    if result.pcap_bytes.len() > 1024 * 1024 || parsed.packets.len() > 64 {
        return Err("capture exceeded the configured memory/packet bounds".into());
    }
    if result.inventory.packets_scanned != parsed.packets.len()
        || result
            .inventory
            .hosts
            .iter()
            .any(|h| h.last_packet_index >= parsed.packets.len())
        || result
            .inventory
            .flows
            .iter()
            .any(|f| f.last_packet_index >= parsed.packets.len())
    {
        return Err("passive inventory references frames outside original evidence".into());
    }
    let promisc_after = interface_flags(&selected.name)? & 0x100 != 0;
    if promisc_before != promisc_after {
        return Err("promiscuous-mode flag changed during passive capture acceptance".into());
    }
    let complete_reason = result.stop_reason;
    let count = parsed.packets.len();
    println!("interface={} packets={} hosts={} flows={} pcap_bytes={} stop_latency_ms={} stop_reason={complete_reason:?} promisc_before={} promisc_after={}",
        selected.name, count, result.inventory.hosts.len(), result.inventory.flows.len(),
        result.pcap_bytes.len(), stop_latency.as_millis(), promisc_before, promisc_after);
    manager.shutdown();
    if count == 0 {
        return Err("no live frames received: test inconclusive; generate authorized background traffic and retry".into());
    }
    if stop_latency > Duration::from_secs(2)
        || !matches!(
            complete_reason,
            StopReason::Cancelled | StopReason::PacketLimit | StopReason::ByteLimit
        )
    {
        return Err(
            "capture stop latency or terminal reason did not meet acceptance criteria".into(),
        );
    }
    println!(
        "N2_LINUX_HOST_CAPTURE_ACCEPTANCE_PASS (transient bytes only; case import NOT tested)"
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[1] != "--accept-live" {
        eprintln!("Usage: live_host_acceptance <authorized-ethernet-interface> --accept-live");
        eprintln!("No capture performed. Requires explicit authorization and Linux CAP_NET_RAW.");
        std::process::exit(2);
    }
    if let Err(error) = acceptance(&args[0]) {
        eprintln!("N2_LINUX_HOST_CAPTURE_ACCEPTANCE_NOT_VERIFIED: {error}");
        std::process::exit(3);
    }
}

//! Repeatable synthetic PCAP parsing benchmark, no real network or retained evidence.
//! Run: cargo run -p cyberdeck-packet --example packet_throughput --release -- 25000
use cyberdeck_packet::{parse_capture, PCAP_MAGIC_LE_USEC};
use std::{hint::black_box, time::Instant};

fn ipv4_udp_frame() -> Vec<u8> {
    let mut frame = vec![0u8; 14];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let udp_payload = [0x61u8; 64];
    let ip_len = 20 + 8 + udp_payload.len();
    frame.extend_from_slice(&[
        0x45,
        0,
        (ip_len >> 8) as u8,
        ip_len as u8,
        0,
        0,
        0,
        0,
        64,
        17,
        0,
        0,
        192,
        0,
        2,
        1,
        192,
        0,
        2,
        2,
    ]);
    frame.extend_from_slice(&50_000u16.to_be_bytes());
    frame.extend_from_slice(&50_001u16.to_be_bytes());
    frame.extend_from_slice(&((8 + udp_payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&udp_payload);
    frame
}

fn synthetic_capture(frames: usize) -> Vec<u8> {
    let frame = ipv4_udp_frame();
    let mut capture = Vec::with_capacity(24 + frames * (16 + frame.len()));
    capture.extend_from_slice(&PCAP_MAGIC_LE_USEC.to_le_bytes());
    capture.extend_from_slice(&2u16.to_le_bytes());
    capture.extend_from_slice(&4u16.to_le_bytes());
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535u32.to_le_bytes());
    capture.extend_from_slice(&1u32.to_le_bytes());
    for i in 0..frames {
        capture.extend_from_slice(&(i as u32).to_le_bytes());
        capture.extend_from_slice(&0u32.to_le_bytes());
        capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        capture.extend_from_slice(&frame);
    }
    capture
}

#[cfg(target_os = "linux")]
fn rss_kib() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse::<usize>()
                .ok()
        })
}

#[cfg(not(target_os = "linux"))]
fn rss_kib() -> Option<usize> {
    None
}

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "25000".into())
        .parse()
        .expect("expected integer frame count");
    assert!(
        (1..=50_000).contains(&count),
        "frame count must be 1..=50000"
    );
    let capture = synthetic_capture(count);
    let mut samples = Vec::new();
    let before_rss = rss_kib();
    let mut observed_rss = before_rss;
    for _ in 0..5 {
        let start = Instant::now();
        let parsed = parse_capture(black_box(&capture)).expect("generated capture should parse");
        let elapsed = start.elapsed().as_secs_f64();
        assert_eq!(parsed.packets.len(), count);
        assert!(!parsed.malformed_tail);
        assert_eq!(parsed.packets[0].dissected.protocol, "UDP");
        observed_rss = rss_kib().or(observed_rss);
        samples.push(elapsed);
        black_box(parsed);
    }
    samples.sort_by(f64::total_cmp);
    let median = samples[samples.len() / 2];
    let mb = capture.len() as f64 / 1_000_000.0;
    println!("fixture: synthetic classic PCAP, UDP/IPv4 Ethernet, fixed payload 64B");
    println!("frames={} input_bytes={} runs=5", count, capture.len());
    println!(
        "median_parse_seconds={median:.6} throughput_MB_per_second={:.2}",
        mb / median
    );
    println!("rss_before_kib={before_rss:?} rss_after_parse_kib={observed_rss:?}");
    println!(
        "scope: parse + dissection + session assignment; no disk I/O, GUI, capture or filtering"
    );
}

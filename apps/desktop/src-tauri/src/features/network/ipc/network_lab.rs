//! Network Lab (Ettercap-mode) commands, passive/defensive only: run the
//! arp_watch analyzer over the currently opened capture and hold a
//! memory-only lab scope (Target 1 / Target 2, ettercap's two-group model).
//! This arc never transmits a packet, poisons ARP caches, or injects frames.

use std::net::IpAddr;
use std::sync::Mutex;

use cyberdeck_packet::arp_watch::{
    analyze_arp, host_inventory, ArpFinding, ArpHost, ArpObservation, ArpOperation,
    MAX_INVENTORY_HOSTS,
};
use cyberdeck_packet::{Dissected, PacketMeta, PCAP_MAGIC_BE_NSEC, PCAP_MAGIC_LE_NSEC};
use serde::Serialize;
use tauri::State;

use super::pcap::{CachedCapture, PcapCtx};

/// Scope entries are IP or CIDR strings, never hostnames: unlike scan targets
/// there is no reason to resolve names for a memory-only lab scope, and
/// skipping resolution keeps the scope free of implicit network traffic.
const MAX_SCOPE_ENTRIES: usize = 64;
/// IPv6 text form tops out around 45 chars; 64 rejects garbage without
/// rejecting any legitimate address or prefix.
const MAX_SCOPE_ENTRY_LEN: usize = 64;
/// Defensive observation cap: the capture parser already bounds frames at
/// MAX_CAPTURE_PACKETS, this mirrors that ceiling so a future cache source
/// cannot push an unbounded observation list into the analyzer.
const MAX_LAB_OBSERVATIONS: usize = cyberdeck_packet::MAX_CAPTURE_PACKETS;

/// Memory-only lab scope. Nothing here is persisted to disk: authorization
/// and targets intentionally die with the process (Master Plan 5.1 gate).
#[derive(Default)]
pub struct NetworkLabCtx {
    scope: Mutex<Option<NetworkLabScope>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLabScope {
    pub targets_t1: Vec<String>,
    pub targets_t2: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NetworkLabScopeWire {
    pub targets_t1: Vec<String>,
    pub targets_t2: Vec<String>,
    pub authorized: bool,
}

#[derive(Debug, Serialize)]
pub struct NetworkLabAnalysisWire {
    /// ARP frames seen in the opened capture (before operation filtering).
    pub arp_frame_count: usize,
    /// Frames reduced into analyzer observations (attributable claims).
    pub observation_count: usize,
    pub router_ip: Option<String>,
    pub findings: Vec<ArpFinding>,
    pub hosts: Vec<ArpHost>,
}

/// Mirror the capture parser's timestamp normalization: classic pcap subsec
/// fields are native (us or ns per magic), pcapng fractions are normalized
/// to nanoseconds by the pcapng parser.
fn capture_nanosecond(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        return true;
    }
    let mut magic = [0u8; 4];
    if bytes.len() >= 4 {
        magic.copy_from_slice(&bytes[0..4]);
    }
    matches!(
        u32::from_le_bytes(magic),
        PCAP_MAGIC_LE_NSEC | PCAP_MAGIC_BE_NSEC
    )
}

fn frame_timestamp_ms(meta: &PacketMeta, nanosecond: bool) -> u64 {
    let sub_ms: u32 = if nanosecond {
        meta.ts_subsec / 1_000_000
    } else {
        meta.ts_subsec / 1_000
    };
    meta.ts_sec
        .saturating_mul(1000)
        .saturating_add(u64::from(sub_ms))
}

fn looks_like_mac(value: &str) -> bool {
    let mut groups = value.split(':');
    let matched = groups
        .by_ref()
        .take(7)
        .filter(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()))
        .count();
    matched == 6 && groups.next().is_none()
}

fn layer_value<'a>(dissected: &'a Dissected, label: &str) -> Option<&'a str> {
    dissected
        .layers
        .iter()
        .find(|l| l.label == label)
        .map(|l| l.value.as_str())
}

/// Reduce one dissected frame to an analyzer observation. Returns None for
/// frames that cannot yield an attributable claim:
///   - non-ARP protocols;
///   - operations other than request/reply (the info line does not expose
///     their sender binding);
///   - requests without an Ethernet header (Linux SLL/raw captures), where
///     the sender MAC is not recoverable from the dissection.
fn observation_from_dissected(dissected: &Dissected, timestamp_ms: u64) -> Option<ArpObservation> {
    if dissected.protocol != "ARP" {
        return None;
    }
    let sender_ip = layer_value(dissected, "sender IP")?.to_string();
    let target_ip = layer_value(dissected, "target IP")?.to_string();
    let (operation, sender_mac) = if dissected.info.starts_with("Who has ") {
        // "Who has X? Tell Y" -> request; the sender MAC rides in the
        // Ethernet II layer as "{src} -> {dst}" (unicode arrow separator).
        let src = layer_value(dissected, "Ethernet II")
            .and_then(|v| v.split_once(" → "))
            .map(|(src, _)| src)?;
        if !looks_like_mac(src) {
            return None;
        }
        (ArpOperation::Request, src.to_string())
    } else if let Some((_, mac)) = dissected.info.rsplit_once(" is at ") {
        // "{ip} is at {mac}" -> reply; the claimed MAC is the payload here.
        if !looks_like_mac(mac) {
            return None;
        }
        (ArpOperation::Reply, mac.to_string())
    } else {
        return None;
    };
    // Gratuitous = a reply announcing the sender's own address (sender ==
    // target): the packet shape used for cache updates and, in bursts,
    // for cache-poison sweeps.
    let is_gratuitous = operation == ArpOperation::Reply && sender_ip == target_ip;
    Some(ArpObservation {
        sender_ip,
        sender_mac,
        operation,
        is_gratuitous,
        timestamp_ms,
    })
}

/// Pure analysis core over a cached capture (no Tauri types): the command is
/// a thin lock-and-forward around this.
fn analyze_capture(
    capture: &CachedCapture,
    router_ip: Option<&str>,
) -> Result<NetworkLabAnalysisWire, String> {
    let router_ip = match router_ip.map(str::trim).filter(|ip| !ip.is_empty()) {
        Some(ip) => {
            let parsed: IpAddr = ip
                .parse()
                .map_err(|_| format!("router IP is not a valid address: {ip}"))?;
            Some(parsed.to_string())
        }
        None => None,
    };
    let nanosecond = capture_nanosecond(&capture.bytes);
    let mut observations: Vec<ArpObservation> = Vec::new();
    let mut arp_frame_count = 0usize;
    for meta in &capture.packets {
        if meta.dissected.protocol != "ARP" {
            continue;
        }
        arp_frame_count += 1;
        // The cap mirrors the capture parser's own bound; reached only if a
        // future cache source stops enforcing it.
        if observations.len() >= MAX_LAB_OBSERVATIONS {
            break;
        }
        if let Some(obs) = observation_from_dissected(&meta.dissected, frame_timestamp_ms(meta, nanosecond)) {
            observations.push(obs);
        }
    }
    let findings = analyze_arp(&observations, router_ip.as_deref());
    let mut hosts = host_inventory(&observations);
    // The analyzer already bounds at MAX_INVENTORY_HOSTS; enforce the same
    // cap here so the wire contract holds even if the constant changes.
    hosts.truncate(MAX_INVENTORY_HOSTS);
    Ok(NetworkLabAnalysisWire {
        arp_frame_count,
        observation_count: observations.len(),
        router_ip,
        findings,
        hosts,
    })
}

/// Passive ARP anomaly analysis over the currently opened capture. Read-only:
/// no frames are transmitted and no authorization is required, matching the
/// other offline capture-read commands.
#[tauri::command]
pub fn network_lab_analyze_pcap_v1(
    ctx: State<'_, PcapCtx>,
    router_ip: Option<String>,
) -> Result<NetworkLabAnalysisWire, String> {
    let guard = ctx
        .current
        .lock()
        .map_err(|_| "capture cache unavailable".to_string())?;
    let capture = guard.as_ref().ok_or("no capture is open")?;
    analyze_capture(capture, router_ip.as_deref())
}

fn validate_scope_entry(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("lab scope contains an empty entry".to_string());
    }
    if value.len() > MAX_SCOPE_ENTRY_LEN {
        return Err(format!(
            "lab scope entry exceeds {MAX_SCOPE_ENTRY_LEN} characters"
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("lab scope entry contains whitespace: {value}"));
    }
    if let Some((addr, prefix)) = value.split_once('/') {
        let address: IpAddr = addr
            .parse()
            .map_err(|_| format!("bad CIDR address in lab scope: {addr}"))?;
        let width = if address.is_ipv4() { 32u8 } else { 128 };
        let bits: u8 = prefix
            .parse()
            .map_err(|_| format!("bad CIDR prefix in lab scope: {prefix}"))?;
        if bits > width {
            return Err(format!("invalid /{bits} prefix for {address}"));
        }
    } else if value.parse::<IpAddr>().is_err() {
        return Err(format!("lab scope entry must be an IP or CIDR: {value}"));
    }
    Ok(value.to_string())
}

/// Validate a whole list, dedup preserving first-seen order, cap at 64.
fn normalize_scope_entries(list: &[String], group: &str) -> Result<Vec<String>, String> {
    let mut normalized: Vec<String> = Vec::with_capacity(list.len());
    for entry in list {
        if normalized.len() >= MAX_SCOPE_ENTRIES {
            return Err(format!("{group} exceeds the {MAX_SCOPE_ENTRIES}-entry lab scope cap"));
        }
        let value = validate_scope_entry(entry)?;
        if !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

/// Persist the lab scope (Target 1 / Target 2) in memory. Requires explicit
/// operator authorization; the flag mirrors ScanView's gating language so
/// the lab cannot accumulate targets silently.
#[tauri::command]
pub fn network_lab_set_scope_v1(
    targets_t1: Vec<String>,
    targets_t2: Vec<String>,
    authorized: bool,
    ctx: State<'_, NetworkLabCtx>,
) -> Result<NetworkLabScopeWire, String> {
    if !authorized {
        return Err("lab scope requires the explicit authorization checkbox".to_string());
    }
    let targets_t1 = normalize_scope_entries(&targets_t1, "Target 1")?;
    let targets_t2 = normalize_scope_entries(&targets_t2, "Target 2")?;
    let mut guard = ctx
        .scope
        .lock()
        .map_err(|_| "lab scope unavailable".to_string())?;
    *guard = Some(NetworkLabScope { targets_t1, targets_t2 });
    Ok(scope_wire(guard.as_ref()))
}

/// Read back the lab scope; an untouched process reports an empty scope.
#[tauri::command]
pub fn network_lab_scope_v1(ctx: State<'_, NetworkLabCtx>) -> Result<NetworkLabScopeWire, String> {
    let guard = ctx
        .scope
        .lock()
        .map_err(|_| "lab scope unavailable".to_string())?;
    Ok(scope_wire(guard.as_ref()))
}

fn scope_wire(scope: Option<&NetworkLabScope>) -> NetworkLabScopeWire {
    match scope {
        Some(scope) => NetworkLabScopeWire {
            targets_t1: scope.targets_t1.clone(),
            targets_t2: scope.targets_t2.clone(),
            authorized: true,
        },
        None => NetworkLabScopeWire {
            targets_t1: Vec::new(),
            targets_t2: Vec::new(),
            authorized: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_packet::arp_watch::ArpFindingKind;
    use cyberdeck_packet::dissect;

    fn arp_frame(
        eth_src: [u8; 6],
        op: u16,
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        // Broadcast-shaped destination keeps the Ethernet layer realistic.
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        frame.extend_from_slice(&eth_src);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes()); // hardware type: ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol: IPv4
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&op.to_be_bytes());
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&sender_ip);
        frame.extend_from_slice(&[0; 6]); // target MAC (unused on requests)
        frame.extend_from_slice(&target_ip);
        frame
    }

    fn meta(ts_ms: u64, frame: &[u8]) -> PacketMeta {
        PacketMeta {
            offset: 0,
            incl_len: frame.len(),
            orig_len: frame.len(),
            ts_sec: ts_ms / 1000,
            ts_subsec: ((ts_ms % 1000) * 1000) as u32, // microsecond capture
            dissected: dissect(1, frame),
        }
    }

    fn capture_with(packets: Vec<PacketMeta>) -> CachedCapture {
        // Classic pcap LE usec magic so the nanosecond probe stays false.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        bytes.resize(24, 0);
        CachedCapture {
            bytes,
            linktype: 1,
            first_ts: 0,
            packets,
        }
    }

    #[test]
    fn duplicate_mac_claims_across_a_capture_produce_findings_and_host_rows() {
        let frames = vec![
            meta(
                1_000,
                &arp_frame(
                    [0xaa; 6],
                    2,
                    [0xaa; 6],
                    [10, 0, 0, 9],
                    [10, 0, 0, 2],
                ),
            ),
            meta(
                2_000,
                &arp_frame(
                    [0xbb; 6],
                    2,
                    [0xbb; 6],
                    [10, 0, 0, 9],
                    [10, 0, 0, 3],
                ),
            ),
            meta(3_000, &arp_frame([0xaa; 6], 1, [0xaa; 6], [10, 0, 0, 9], [10, 0, 0, 1])),
        ];
        let wire = analyze_capture(&capture_with(frames), None).expect("analysis succeeds");
        assert_eq!(wire.arp_frame_count, 3);
        assert_eq!(wire.observation_count, 3);
        let finding = wire
            .findings
            .iter()
            .find(|f| f.kind == ArpFindingKind::IpImpersonation)
            .expect("impersonation finding present");
        assert_eq!(finding.ip, "10.0.0.9");
        assert_eq!(finding.macs.len(), 2);
        let host = wire
            .hosts
            .iter()
            .find(|h| h.ip == "10.0.0.9")
            .expect("host row present");
        assert!(host.impersonated);
        assert_eq!(host.mac_claims.len(), 2);
        assert_eq!(host.first_seen_ms, 1_000);
        assert_eq!(host.last_seen_ms, 3_000);
    }

    #[test]
    fn gratuitous_reply_bursts_are_detected_from_capture_frames() {
        let mut frames = Vec::new();
        for i in 0..12u64 {
            frames.push(meta(
                i * 2_000,
                &arp_frame(
                    [0xcc; 6],
                    2,
                    [0xcc; 6],
                    [10, 0, 0, 4],
                    [10, 0, 0, 4],
                ),
            ));
        }
        let wire = analyze_capture(&capture_with(frames), None).expect("analysis succeeds");
        assert_eq!(wire.observation_count, 12);
        let burst = wire
            .findings
            .iter()
            .find(|f| f.kind == ArpFindingKind::GratuitousBurst)
            .expect("burst finding present");
        assert_eq!(burst.ip, "10.0.0.4");
        assert!(burst.detail.contains("12"));
    }

    #[test]
    fn router_ip_is_validated_and_gateway_findings_are_relabeled() {
        let frames = vec![
            meta(
                100,
                &arp_frame([0xaa; 6], 2, [0xaa; 6], [192, 168, 1, 1], [192, 168, 1, 5]),
            ),
            meta(
                200,
                &arp_frame([0xdd; 6], 2, [0xdd; 6], [192, 168, 1, 1], [192, 168, 1, 6]),
            ),
        ];
        let capture = capture_with(frames);
        let wire = analyze_capture(&capture, Some("192.168.1.1")).expect("analysis succeeds");
        let finding = wire.findings.first().expect("gateway finding present");
        assert_eq!(finding.kind, ArpFindingKind::GatewayImpersonation);
        assert_eq!(wire.router_ip.as_deref(), Some("192.168.1.1"));
        assert!(analyze_capture(&capture, Some("not-an-ip")).is_err());
    }

    #[test]
    fn non_arp_and_unattributable_frames_are_skipped() {
        let mut truncated = arp_frame([0xaa; 6], 2, [0xaa; 6], [10, 0, 0, 9], [10, 0, 0, 2]);
        truncated.truncate(20); // malformed ARP: dissect marks it MALFORMED
        let frames = vec![meta(1_000, &truncated), meta(2_000, &[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2])];
        let wire = analyze_capture(&capture_with(frames), None).expect("analysis succeeds");
        assert_eq!(wire.arp_frame_count, 0);
        assert_eq!(wire.observation_count, 0);
        assert!(wire.findings.is_empty());
        assert!(wire.hosts.is_empty());
    }

    #[test]
    fn timestamps_scale_microsecond_and_nanosecond_captures() {
        let mut meta_us = PacketMeta {
            offset: 0,
            incl_len: 0,
            orig_len: 0,
            ts_sec: 1_700_000_000,
            ts_subsec: 500_000,
            dissected: dissect(1, &[]),
        };
        assert_eq!(frame_timestamp_ms(&meta_us, false), 1_700_000_000_500);
        meta_us.ts_subsec = 999_999_999;
        assert_eq!(frame_timestamp_ms(&meta_us, true), 1_700_000_000_999);
        // Overflowing seconds saturate instead of wrapping.
        meta_us.ts_sec = u64::MAX;
        assert_eq!(frame_timestamp_ms(&meta_us, false), u64::MAX);
    }

    #[test]
    fn mac_shape_check_accepts_dissection_output_only() {
        assert!(looks_like_mac("aa:0a:10:ff:80:01"));
        assert!(!looks_like_mac("aa:0a:10:ff:80"));
        assert!(!looks_like_mac("aa:0a:10:ff:80:0"));
        assert!(!looks_like_mac("aa:0a:10:ff:80:zz"));
        assert!(!looks_like_mac(""));
    }

    #[test]
    fn scope_entries_validate_ips_and_cidrs_only() {
        assert_eq!(
            validate_scope_entry(" 192.168.1.0/24 ").as_deref(),
            Ok("192.168.1.0/24")
        );
        assert_eq!(validate_scope_entry("2001:db8::1").as_deref(), Ok("2001:db8::1"));
        assert!(validate_scope_entry("router.local").is_err());
        assert!(validate_scope_entry("10.0.0.0/33").is_err());
        assert!(validate_scope_entry("10.0.0.1 /24").is_err());
        assert!(validate_scope_entry("").is_err());
        assert!(validate_scope_entry(&"a".repeat(65)).is_err());
    }

    #[test]
    fn scope_lists_dedup_and_cap_at_64() {
        let ok: Vec<String> = (0..64).map(|i| format!("10.0.0.{i}")).collect();
        assert_eq!(normalize_scope_entries(&ok, "T1").unwrap().len(), 64);
        let over: Vec<String> = (0..65).map(|i| format!("10.0.0.{i}")).collect();
        assert!(normalize_scope_entries(&over, "T1").is_err());
        let duped = vec!["10.0.0.1".to_string(), "10.0.0.1".to_string()];
        assert_eq!(normalize_scope_entries(&duped, "T1").unwrap().len(), 1);
    }

    #[test]
    fn nanosecond_probe_matches_parser_magic_handling() {
        let mut usec = Vec::new();
        usec.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        assert!(!capture_nanosecond(&usec));
        let mut nsec = Vec::new();
        nsec.extend_from_slice(&0xa1b23c4du32.to_le_bytes());
        assert!(capture_nanosecond(&nsec));
        let mut be_nsec = Vec::new();
        be_nsec.extend_from_slice(&0x4d3cb2a1u32.to_be_bytes());
        assert!(capture_nanosecond(&be_nsec));
        assert!(capture_nanosecond(&[0x0a, 0x0d, 0x0d, 0x0a]));
        assert!(!capture_nanosecond(&[]));
    }
}

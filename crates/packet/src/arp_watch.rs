//! Pure passive ARP observation analysis for the Network Lab (defensive arc).
//!
//! Inspired by ettercap's host-list bookkeeping (IP <-> MAC per host) and the
//! classic arpwatch duplicate-address heuristic, re-derived here from first
//! principles: a healthy IPv4 segment keeps a stable one-to-one IP -> MAC map,
//! so *claims* (replies, gratuitous announcements, and even requests which
//! carry the sender's binding) are the only signal needed to spot:
//!   1. IP impersonation: one IP claimed by >= 2 distinct MACs;
//!   2. gratuitous-ARP burst rate anomalies (cache-poison sweeps, IP conflict
//!      flapping, or misbehaving HA pairs);
//!   3. gateway-IP impersonation when a router address is supplied.
//!
//! This module never emits or mutates packets; it only reads observations.

use serde::Serialize;
use std::collections::BTreeMap;

/// Findings are bounded so a pathological capture cannot flood the UI or IPC.
pub const MAX_FINDINGS: usize = 256;
/// Host inventory rows are bounded for the same reason (matches the netscan
/// host cap so both tables behave predictably).
pub const MAX_INVENTORY_HOSTS: usize = 4096;
/// Default anomaly threshold: strictly more than 10 gratuitous ARP frames per
/// rolling minute from one address. Normal hosts announce a handful of times;
/// poisoning sweeps and conflict flapping far exceed this.
pub const DEFAULT_GRATUITOUS_BURST_PER_MINUTE: u32 = 10;
/// Rolling window used for burst-rate evaluation (60s, matching "per minute").
pub const GRATUITOUS_BURST_WINDOW_MS: u64 = 60_000;

/// One observed ARP frame reduced to the fields the analyzer needs.
/// `is_gratuitous` is decided by the caller (reply where sender == target);
/// the analyzer trusts the flag so packet-format knowledge stays out of here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArpObservation {
    pub sender_ip: String,
    pub sender_mac: String,
    pub operation: ArpOperation,
    pub is_gratuitous: bool,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArpOperation {
    Request,
    Reply,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArpSeverity {
    /// Gateway claims are the crown jewels: a changed router MAC redirects
    /// every host on the segment, so they outrank ordinary conflicts.
    Critical,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArpFindingKind {
    IpImpersonation,
    GatewayImpersonation,
    GratuitousBurst,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArpMacClaim {
    pub mac: String,
    pub claims: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArpFinding {
    pub kind: ArpFindingKind,
    pub ip: String,
    pub macs: Vec<ArpMacClaim>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub severity: ArpSeverity,
    /// Human-readable explanation; the UI shows it alongside the chip.
    pub detail: String,
}

/// Unified host inventory row: every IP seen in ARP traffic with the MACs
/// that claimed it. `impersonated` mirrors the analyzer verdict for the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArpHost {
    pub ip: String,
    pub mac_claims: Vec<ArpMacClaim>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub impersonated: bool,
}

/// Per-IP claim tracking. BTreeMap keeps every output deterministic
/// regardless of hash seeds, which makes the UI table order stable across
/// runs on the same capture.
#[derive(Default)]
struct HostBook {
    hosts: BTreeMap<String, BTreeMap<String, MacTrack>>,
}

#[derive(Default, Clone)]
struct MacTrack {
    claims: u32,
    first_seen_ms: u64,
    last_seen_ms: u64,
}

impl HostBook {
    fn record(&mut self, obs: &ArpObservation) {
        // A claim without an attributable MAC cannot be acted on, and
        // unroutable sender addresses (DHCP probes, broadcast sends) would
        // manufacture phantom hosts; both are skipped.
        if obs.sender_mac.is_empty()
            || obs.sender_ip.is_empty()
            || obs.sender_ip == "0.0.0.0"
            || obs.sender_ip == "255.255.255.255"
        {
            return;
        }
        let macs = self.hosts.entry(obs.sender_ip.clone()).or_default();
        let track = macs.entry(obs.sender_mac.clone()).or_default();
        track.claims = track.claims.saturating_add(1);
        // claims == 1 means this MAC is new to the book: it starts its own
        // window instead of inheriting a previously tracked MAC's timeline.
        if track.claims == 1 {
            track.first_seen_ms = obs.timestamp_ms;
        }
        track.last_seen_ms = track.last_seen_ms.max(obs.timestamp_ms);
    }
}

fn mac_claims(macs: &BTreeMap<String, MacTrack>) -> Vec<ArpMacClaim> {
    let mut claims: Vec<ArpMacClaim> = macs
        .iter()
        .map(|(mac, t)| ArpMacClaim {
            mac: mac.clone(),
            claims: t.claims,
            first_seen_ms: t.first_seen_ms,
            last_seen_ms: t.last_seen_ms,
        })
        .collect();
    // Most-claimed MAC first: the incumbent binding, then the challengers.
    claims.sort_by(|a, b| b.claims.cmp(&a.claims).then_with(|| a.mac.cmp(&b.mac)));
    claims
}

fn window_span(macs: &[ArpMacClaim]) -> (u64, u64) {
    let first = macs.iter().map(|m| m.first_seen_ms).min().unwrap_or(0);
    let last = macs.iter().map(|m| m.last_seen_ms).max().unwrap_or(0);
    (first, last)
}

/// Peak count inside any rolling `GRATUITOUS_BURST_WINDOW_MS` window.
/// Two-pointer over sorted stamps keeps this O(n log n) per host even for
/// burst-heavy captures.
fn peak_burst_window(timestamps: &mut [u64]) -> (u32, u64, u64) {
    timestamps.sort_unstable();
    let mut best: (u32, u64, u64) = (0, 0, 0);
    let mut start = 0usize;
    for end in 0..timestamps.len() {
        while timestamps[end] - timestamps[start] > GRATUITOUS_BURST_WINDOW_MS {
            start += 1;
        }
        let count = (end - start + 1) as u32;
        if count > best.0 {
            best = (count, timestamps[start], timestamps[end]);
        }
    }
    best
}

/// Analyze an observation list and return at most `MAX_FINDINGS` anomalies,
/// ordered critical-first then by IP so the UI can render rows without
/// re-sorting.
pub fn analyze_arp(observations: &[ArpObservation], router_ip: Option<&str>) -> Vec<ArpFinding> {
    let mut book = HostBook::default();
    let mut gratuitous: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for obs in observations {
        book.record(obs);
        if obs.is_gratuitous && !obs.sender_mac.is_empty() {
            gratuitous
                .entry(obs.sender_ip.clone())
                .or_default()
                .push(obs.timestamp_ms);
        }
    }

    let mut findings: Vec<ArpFinding> = Vec::new();
    for (ip, macs) in &book.hosts {
        if macs.len() < 2 {
            continue;
        }
        let claims = mac_claims(macs);
        let (first, last) = window_span(&claims);
        let challenger_count = macs.len().saturating_sub(1);
        // The gateway case is both a distinct kind and a higher severity: a
        // router MAC flip means every host's default route is being contested.
        let (kind, severity) = if router_ip == Some(ip.as_str()) {
            (ArpFindingKind::GatewayImpersonation, ArpSeverity::Critical)
        } else {
            (ArpFindingKind::IpImpersonation, ArpSeverity::Warning)
        };
        let incumbent = claims.first().map(|m| m.mac.as_str()).unwrap_or("the first");
        let detail = format!(
            "{challenger_count} additional MAC{} claim{} {ip} after {incumbent}",
            if challenger_count == 1 { "" } else { "es" },
            if challenger_count == 1 { "s" } else { "" },
        );
        findings.push(ArpFinding {
            kind,
            ip: ip.clone(),
            macs: claims,
            first_seen_ms: first,
            last_seen_ms: last,
            severity,
            detail,
        });
    }

    for (ip, stamps) in &mut gratuitous {
        let (peak, win_start, win_end) = peak_burst_window(stamps);
        if peak <= DEFAULT_GRATUITOUS_BURST_PER_MINUTE {
            continue;
        }
        // One burst finding per source IP: the peak window carries the story;
        // emitting every overlapping window would drown the operator.
        let mac = book
            .hosts
            .get(ip)
            .and_then(|macs| macs.keys().next().cloned())
            .unwrap_or_default();
        findings.push(ArpFinding {
            kind: ArpFindingKind::GratuitousBurst,
            ip: ip.clone(),
            macs: vec![ArpMacClaim {
                mac,
                claims: peak,
                first_seen_ms: win_start,
                last_seen_ms: win_end,
            }],
            first_seen_ms: win_start,
            last_seen_ms: win_end,
            severity: ArpSeverity::Warning,
            detail: format!(
                "{peak} gratuitous ARP within 60s (threshold {DEFAULT_GRATUITOUS_BURST_PER_MINUTE}/min)"
            ),
        });
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.ip.cmp(&b.ip)));
    findings.truncate(MAX_FINDINGS);
    findings
}

/// Build the unified host inventory (bounded) from the same observations.
pub fn host_inventory(observations: &[ArpObservation]) -> Vec<ArpHost> {
    let mut book = HostBook::default();
    for obs in observations {
        book.record(obs);
    }
    let mut hosts: Vec<ArpHost> = Vec::new();
    for (ip, macs) in &book.hosts {
        if hosts.len() >= MAX_INVENTORY_HOSTS {
            // Later addresses are dropped rather than truncating the map
            // mid-stream: inventory rows are display aids, and first-come
            // retention keeps the output deterministic (BTreeMap order).
            break;
        }
        let claims = mac_claims(macs);
        let (first, last) = window_span(&claims);
        hosts.push(ArpHost {
            ip: ip.clone(),
            impersonated: claims.len() > 1,
            mac_claims: claims,
            first_seen_ms: first,
            last_seen_ms: last,
        });
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(
        sender_ip: &str,
        sender_mac: &str,
        op: ArpOperation,
        gratuitous: bool,
        ts: u64,
    ) -> ArpObservation {
        ArpObservation {
            sender_ip: sender_ip.to_string(),
            sender_mac: sender_mac.to_string(),
            operation: op,
            is_gratuitous: gratuitous,
            timestamp_ms: ts,
        }
    }

    #[test]
    fn clean_capture_produces_no_findings_and_one_mac_per_host() {
        let mut obs_list = Vec::new();
        // A calm segment: requests and matching replies over two minutes.
        for minute in 0..2u64 {
            let base = minute * 60_000;
            obs_list.push(obs("10.0.0.5", "aa:aa:aa:aa:aa:05", ArpOperation::Request, false, base + 1_000));
            obs_list.push(obs("10.0.0.1", "aa:aa:aa:aa:aa:01", ArpOperation::Reply, false, base + 2_000));
            obs_list.push(obs("10.0.0.7", "aa:aa:aa:aa:aa:07", ArpOperation::Reply, false, base + 3_000));
            // Regular gratuitous refreshes well under the rate threshold.
            obs_list.push(obs("10.0.0.1", "aa:aa:aa:aa:aa:01", ArpOperation::Reply, true, base + 30_000));
        }
        let findings = analyze_arp(&obs_list, Some("10.0.0.1"));
        assert!(findings.is_empty(), "expected no findings, got {findings:?}");
        let hosts = host_inventory(&obs_list);
        assert_eq!(hosts.len(), 3);
        let router = hosts.iter().find(|h| h.ip == "10.0.0.1").unwrap();
        assert_eq!(router.mac_claims.len(), 1);
        assert!(!router.impersonated);
        assert_eq!(router.mac_claims[0].claims, 4);
    }

    #[test]
    fn ip_claimed_by_two_macs_is_flagged_with_counts_and_window() {
        let obs_list = vec![
            obs("10.0.0.9", "aa:aa:aa:aa:aa:09", ArpOperation::Reply, false, 1_000),
            obs("10.0.0.9", "aa:aa:aa:aa:aa:09", ArpOperation::Reply, false, 2_000),
            obs("10.0.0.9", "bb:bb:bb:bb:bb:0b", ArpOperation::Reply, false, 5_000),
            obs("10.0.0.9", "bb:bb:bb:bb:bb:0b", ArpOperation::Reply, false, 7_500),
            obs("10.0.0.9", "aa:aa:aa:aa:aa:09", ArpOperation::Request, false, 9_000),
        ];
        let findings = analyze_arp(&obs_list, None);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, ArpFindingKind::IpImpersonation);
        assert_eq!(f.severity, ArpSeverity::Warning);
        assert_eq!(f.macs.len(), 2);
        assert_eq!(f.macs[0].mac, "aa:aa:aa:aa:aa:09");
        assert_eq!(f.macs[0].claims, 3);
        assert_eq!(f.macs[1].mac, "bb:bb:bb:bb:bb:0b");
        assert_eq!(f.macs[1].claims, 2);
        assert_eq!(f.first_seen_ms, 1_000);
        assert_eq!(f.last_seen_ms, 9_000);
        let host = host_inventory(&obs_list).remove(0);
        assert!(host.impersonated);
        assert_eq!(host.mac_claims.len(), 2);
    }

    #[test]
    fn gratuitous_burst_over_threshold_is_flagged_under_the_threshold_is_not() {
        // 12 announcements in 30 seconds: a poisoning-style sweep.
        let burst: Vec<ArpObservation> = (0..12)
            .map(|i| obs("10.0.0.4", "cc:cc:cc:cc:cc:04", ArpOperation::Reply, true, i * 2_500))
            .collect();
        let findings = analyze_arp(&burst, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, ArpFindingKind::GratuitousBurst);
        assert_eq!(findings[0].macs[0].claims, 12);
        assert_eq!(findings[0].first_seen_ms, 0);
        assert_eq!(findings[0].last_seen_ms, 27_500);

        // The same 12 announcements spread over 12 minutes stay silent.
        let calm: Vec<ArpObservation> = (0..12)
            .map(|i| obs("10.0.0.4", "cc:cc:cc:cc:cc:04", ArpOperation::Reply, true, i * 60_000 + 1_000))
            .collect();
        assert!(analyze_arp(&calm, None).is_empty());

        // Exactly at the threshold is not an anomaly (strictly greater than).
        let at_limit: Vec<ArpObservation> = (0..10)
            .map(|i| obs("10.0.0.4", "cc:cc:cc:cc:cc:04", ArpOperation::Reply, true, i * 5_000))
            .collect();
        assert!(analyze_arp(&at_limit, None).is_empty());
    }

    #[test]
    fn gateway_impersonation_is_relabeled_and_outranks() {
        let obs_list = vec![
            obs("192.168.1.1", "aa:aa:aa:aa:aa:01", ArpOperation::Reply, false, 100),
            obs("192.168.1.1", "dd:dd:dd:dd:dd:dd", ArpOperation::Reply, false, 400),
        ];
        let without_router = analyze_arp(&obs_list, None);
        assert_eq!(without_router[0].kind, ArpFindingKind::IpImpersonation);
        assert_eq!(without_router[0].severity, ArpSeverity::Warning);

        let with_router = analyze_arp(&obs_list, Some("192.168.1.1"));
        assert_eq!(with_router[0].kind, ArpFindingKind::GatewayImpersonation);
        assert_eq!(with_router[0].severity, ArpSeverity::Critical);
    }

    #[test]
    fn findings_and_inventory_stay_bounded() {
        // 300 conflicting addresses would naively yield 300 findings.
        let mut obs_list = Vec::new();
        for i in 0..300u32 {
            let ip = format!("10.1.{i}.1");
            obs_list.push(obs(&ip, "aa:aa:aa:aa:aa:01", ArpOperation::Reply, false, 1_000));
            obs_list.push(obs(&ip, "bb:bb:bb:bb:bb:02", ArpOperation::Reply, false, 2_000));
        }
        let findings = analyze_arp(&obs_list, None);
        assert_eq!(findings.len(), MAX_FINDINGS);
        let hosts = host_inventory(&obs_list);
        assert_eq!(hosts.len(), MAX_INVENTORY_HOSTS.min(300));
        // 5000 distinct addresses: inventory retains the first 4096 only.
        let mut wide = Vec::new();
        for i in 0..5000u32 {
            let ip = format!("10.2.{i}.1");
            wide.push(obs(&ip, "aa:aa:aa:aa:aa:01", ArpOperation::Request, false, 1_000));
        }
        assert_eq!(host_inventory(&wide).len(), MAX_INVENTORY_HOSTS);
    }

    #[test]
    fn empty_or_broadcast_sender_data_is_ignored() {
        let obs_list = vec![
            obs("0.0.0.0", "aa:aa:aa:aa:aa:01", ArpOperation::Request, false, 100),
            obs("10.0.0.3", "", ArpOperation::Request, false, 200),
            obs("255.255.255.255", "bb:bb:bb:bb:bb:02", ArpOperation::Reply, true, 300),
        ];
        assert!(analyze_arp(&obs_list, None).is_empty());
        assert!(host_inventory(&obs_list).is_empty());
    }

    #[test]
    fn unsorted_timestamps_still_find_the_peak_window() {
        let stamps = [80_000u64, 10_000, 70_000, 30_000, 90_000];
        let (peak, first, last) = peak_burst_window(&mut stamps.clone());
        assert_eq!(peak, 4);
        assert_eq!(first, 30_000);
        assert_eq!(last, 90_000);
    }
}

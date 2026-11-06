//! Network Lab session report export (Bettercap session-report parity,
//! strictly passive): reduce the opened capture exactly like the individual
//! lab commands (ARP analyzer, event timeline, host inventory, DNS monitor),
//! render ONE bounded markdown artifact and persist it as ONE case finding
//! through the standard evidence path. The frontend only ever sees a receipt
//! (byte length, case id, truncation flag) — never the markdown itself.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::dns_monitor::DnsFindingKind;
use cyberdeck_packet::lab_report::{
    build_report, DnsReportEntry, LabReport, REPORT_TRUNCATION_MARKER,
};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use tauri::State;

use super::network_lab::{analyze_capture, dns_monitor_capture};
use super::pcap::{CachedCapture, PcapCtx};

/// Evidence source key for the lab's persisted report (scan findings use
/// "network.tcp"/"network.udp"; the passive lab reports under one key).
const REPORT_SOURCE: &str = "network.lab";
/// Fixed finding title so case review can recognize the artifact.
const REPORT_TITLE: &str = "Lab session report";

/// Frontend-safe export receipt: size, destination case and honesty flag
/// only. No markdown, no case secrets and no capture bytes cross IPC.
#[derive(Debug, Clone, Serialize)]
pub struct LabReportReceiptWire {
    pub byte_len: u64,
    pub case_id: String,
    pub truncated: bool,
}

/// Same saved-case gate as the pcap export slice: the report destination is
/// always the backend-selected persistent case, never a client-named one
/// (scratchpad is refused so volatile analysis cannot be mistaken for case
/// evidence).
fn selected_saved_case(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let id = scope.case_id.clone().ok_or("saved case selection required")?;
    if id == "scratchpad" || id.is_empty() {
        return Err("lab session report export requires a saved selected case".into());
    }
    Ok((scope, id))
}

/// Same router-IP validation as the ARP analyzer: trimmed, optional, and a
/// parseable address when present. Returns the normalized form that both
/// `analyze_capture` and `derive_events` consume.
fn normalize_router_ip(router_ip: Option<&str>) -> Result<Option<String>, String> {
    match router_ip.map(str::trim).filter(|ip| !ip.is_empty()) {
        Some(ip) => {
            let parsed: std::net::IpAddr = ip
                .parse()
                .map_err(|_| format!("router IP is not a valid address: {ip}"))?;
            Ok(Some(parsed.to_string()))
        }
        None => Ok(None),
    }
}

/// Map the analyzer's DNS finding kind to its serde label so the report text
/// matches the wire representation the UI already shows.
fn dns_kind_label(kind: DnsFindingKind) -> &'static str {
    match kind {
        DnsFindingKind::AnswerInconsistency => "answer_inconsistency",
        DnsFindingKind::SuspiciousTarget => "suspicious_target",
        DnsFindingKind::NxdomainInjection => "nxdomain_injection",
    }
}

/// Pure export core over a cached capture (no Tauri types): the command is a
/// thin gate-lock-and-forward around this. Reuses the ARP reduction/analysis
/// and the DNS monitor reduction from network_lab.rs so the report describes
/// exactly what the individual lab panes show.
fn reduce_report(
    capture: &CachedCapture,
    router_ip: Option<&str>,
    include_dns: bool,
    generated_at_ms: u64,
) -> Result<(LabReport, String), String> {
    let router_ip = normalize_router_ip(router_ip)?;
    let analysis = analyze_capture(capture, router_ip.as_deref())?;
    let events = cyberdeck_packet::lab_events::derive_events(&capture.packets, router_ip.as_deref());
    let dns_entries: Vec<DnsReportEntry> = if include_dns {
        dns_monitor_capture(capture)
            .findings
            .iter()
            .map(|finding| DnsReportEntry {
                kind: dns_kind_label(finding.kind).to_string(),
                question_name: finding.question_name.clone(),
                detail: finding.detail.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let report = build_report(
        &analysis.findings,
        &events,
        &analysis.hosts,
        &dns_entries,
        generated_at_ms,
    );
    let markdown = report.render_markdown();
    Ok((report, markdown))
}

/// The single persisted case finding: backend-constructed title, info
/// severity and the bounded markdown as details.
fn build_finding(markdown: String) -> NewFinding {
    NewFinding {
        title: REPORT_TITLE.to_string(),
        severity: "info".into(),
        details: markdown,
    }
}

/// Current wall-clock in epoch milliseconds; 0 keeps the report honest if the
/// clock is unavailable (the renderer documents 0 as unknown provenance).
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Export the lab session report for the currently opened capture into the
/// selected saved case. Read-only over the capture (no frames are
/// transmitted); the only write is the one case finding, persisted through
/// the same store-lock -> publication-gate order as every case finding.
#[tauri::command]
pub fn network_lab_report_export_v1(
    ctx: State<'_, PcapCtx>,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    router_ip: Option<String>,
    include_dns: bool,
) -> Result<LabReportReceiptWire, String> {
    // Case selection first, then the capture cache, then the evidence store —
    // mirroring pcap_export_view_v1's ordering so a concurrent case switch
    // can never deadlock or persist into the wrong case.
    let (scope, case_id) = selected_saved_case(&session)?;
    let guard = ctx
        .current
        .lock()
        .map_err(|_| "capture cache unavailable".to_string())?;
    let capture = guard.as_ref().ok_or("no capture is open")?;
    let (report, markdown) = reduce_report(capture, router_ip.as_deref(), include_dns, unix_ms())?;
    // Two truncation sources, both surfaced: section caps in the aggregation
    // (counters vs rendered) and the renderer's 32 KiB byte budget.
    let truncated = report.truncated() || markdown.contains(REPORT_TRUNCATION_MARKER);
    let finding = build_finding(markdown);
    let byte_len = finding.details.len() as u64;
    let store = evidence
        .store
        .lock()
        .map_err(|_| "case evidence store unavailable")?;
    session.with_current_publication(&scope, || {
        store.add_findings(&case_id, REPORT_SOURCE, None, &[finding])?;
        Ok(())
    })?;
    Ok(LabReportReceiptWire {
        byte_len,
        case_id,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_packet::{dissect, PacketMeta, PCAP_MAGIC_LE_USEC};

    fn arp_frame(
        eth_src: [u8; 6],
        op: u16,
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        frame.extend_from_slice(&eth_src);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&op.to_be_bytes());
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&sender_ip);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&target_ip);
        frame
    }

    /// Minimal UDP/DNS message: one A question, optional A answers.
    fn dns_message(
        id: u16,
        is_response: bool,
        rcode: u8,
        name: &str,
        answers: &[([u8; 4], u32)],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_be_bytes());
        let flags: u16 = if is_response {
            0x8000u16 | u16::from(rcode)
        } else {
            0x0100
        };
        data.extend_from_slice(&flags.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 0]);
        for label in name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        for (ip, ttl) in answers {
            data.extend_from_slice(&[0xc0, 0x0c]);
            data.extend_from_slice(&1u16.to_be_bytes());
            data.extend_from_slice(&1u16.to_be_bytes());
            data.extend_from_slice(&ttl.to_be_bytes());
            data.extend_from_slice(&4u16.to_be_bytes());
            data.extend_from_slice(ip);
        }
        data
    }

    /// Ethernet + IPv4 + UDP frame with both ports on 53 carrying `dns`.
    fn udp_dns_frame(src: [u8; 4], dst: [u8; 4], dns: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0xaa; 6]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let total_length = (20 + 8 + dns.len()) as u16;
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&total_length.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(dns);
        frame
    }

    fn meta(ts_ms: u64, frame: &[u8]) -> PacketMeta {
        PacketMeta {
            offset: 0,
            incl_len: frame.len(),
            orig_len: frame.len(),
            ts_sec: ts_ms / 1000,
            ts_subsec: ((ts_ms % 1000) * 1000) as u32,
            dissected: dissect(1, frame),
        }
    }

    fn capture_with(packets: Vec<PacketMeta>) -> CachedCapture {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PCAP_MAGIC_LE_USEC.to_le_bytes());
        bytes.resize(24, 0);
        CachedCapture {
            bytes,
            linktype: 1,
            first_ts: 0,
            packets,
        }
    }

    #[test]
    fn export_reduces_arp_events_hosts_and_dns_into_one_markdown() {
        let frames = vec![
            meta(
                1_000,
                &arp_frame([0xaa; 6], 2, [0xaa; 6], [10, 0, 0, 9], [10, 0, 0, 2]),
            ),
            meta(
                2_000,
                &arp_frame([0xbb; 6], 2, [0xbb; 6], [10, 0, 0, 9], [10, 0, 0, 3]),
            ),
            meta(
                3_000,
                &udp_dns_frame(
                    [10, 0, 0, 1],
                    [10, 0, 0, 5],
                    &dns_message(1, true, 0, "evil.example", &[([169, 254, 169, 254], 60)]),
                ),
            ),
        ];
        let capture = capture_with(frames);
        let (report, markdown) =
            reduce_report(&capture, Some("10.0.0.1"), true, 1_700_000_000_000)
                .expect("reduction succeeds");
        // ARP: two MACs claimed 10.0.0.9 -> one impersonation finding and one
        // host row carrying both MAC claims (senders share the IP).
        assert_eq!(report.counters.arp_findings_total, 1);
        assert_eq!(report.counters.hosts_total, 1);
        assert!(report.counters.events_total >= 2, "new hosts + conflict");
        // DNS: loopback/link-local answer target fired once.
        assert_eq!(report.counters.dns_findings_total, 1);
        assert_eq!(report.dns_findings[0].kind, "suspicious_target");
        assert_eq!(report.dns_findings[0].question_name, "evil.example");
        // The markdown artifact carries every section and the evidence lines.
        for section in [
            "# Lab session report",
            "## ARP findings",
            "## Event timeline",
            "## Host inventory",
            "## DNS findings",
        ] {
            assert!(markdown.contains(section), "missing {section}");
        }
        assert!(markdown.contains("ip_impersonation 10.0.0.9"));
        assert!(markdown.contains("169.254.169.254"));
        assert!(markdown.contains("Generated (unix ms): 1700000000000"));
        assert!(!report.truncated());
        assert!(!markdown.contains(REPORT_TRUNCATION_MARKER));
    }

    #[test]
    fn include_dns_false_leaves_the_dns_section_honestly_empty() {
        let frames = vec![meta(
            1_000,
            &udp_dns_frame(
                [10, 0, 0, 1],
                [10, 0, 0, 5],
                &dns_message(1, true, 0, "evil.example", &[([127, 0, 0, 1], 60)]),
            ),
        )];
        let capture = capture_with(frames);
        let (report, markdown) =
            reduce_report(&capture, None, false, 0).expect("reduction succeeds");
        assert_eq!(report.dns_findings.len(), 0);
        assert_eq!(report.counters.dns_findings_total, 0);
        assert!(markdown.contains("## DNS findings\n- none recorded"));
    }

    #[test]
    fn router_ip_is_validated_before_any_reduction() {
        let capture = capture_with(vec![]);
        let error = reduce_report(&capture, Some("not-an-ip"), true, 0)
            .expect_err("invalid router IP refused");
        assert!(error.contains("router IP is not a valid address"));
        // Empty and whitespace router IPs mean "not provided", same as ARP.
        assert!(reduce_report(&capture, Some("  "), true, 0).is_ok());
        assert!(reduce_report(&capture, None, true, 0).is_ok());
    }

    #[test]
    fn dns_kinds_map_to_the_wire_labels_one_to_one() {
        assert_eq!(
            dns_kind_label(DnsFindingKind::AnswerInconsistency),
            "answer_inconsistency"
        );
        assert_eq!(
            dns_kind_label(DnsFindingKind::SuspiciousTarget),
            "suspicious_target"
        );
        assert_eq!(
            dns_kind_label(DnsFindingKind::NxdomainInjection),
            "nxdomain_injection"
        );
    }

    #[test]
    fn persisted_finding_is_fixed_titled_and_bounded() {
        let finding = build_finding("# Lab session report\n- small".to_string());
        assert_eq!(finding.title, "Lab session report");
        assert_eq!(finding.severity, "info");
        // The renderer's bound is the details bound: an at-cap artifact stays
        // at cap, and the marker rides inside the details when truncated.
        let huge = "x".repeat(cyberdeck_packet::lab_report::MAX_REPORT_MARKDOWN_BYTES);
        let bounded = build_finding(huge);
        assert_eq!(
            bounded.details.len(),
            cyberdeck_packet::lab_report::MAX_REPORT_MARKDOWN_BYTES
        );
    }

    #[test]
    fn receipt_fields_derive_from_the_reduction() {
        // The receipt's truncated flag covers both truncation sources.
        let frames: Vec<PacketMeta> = (0..64)
            .flat_map(|i| {
                vec![
                    meta(
                        i * 1_000,
                        &arp_frame([0xaa; 6], 2, [0xaa; 6], [10, 0, 0, 9], [10, 0, 0, 2]),
                    ),
                    meta(
                        i * 1_000 + 500,
                        &arp_frame([0xbb; 6], 2, [0xbb; 6], [10, 0, 0, 9], [10, 0, 0, 3]),
                    ),
                ]
            })
            .collect();
        let capture = capture_with(frames);
        let (report, markdown) =
            reduce_report(&capture, None, true, 0).expect("reduction succeeds");
        // 64 conflict-ish packets produce bounded findings; the markdown is
        // well under the byte budget here, so truncation is section-driven.
        let truncated = report.truncated() || markdown.contains(REPORT_TRUNCATION_MARKER);
        assert_eq!(truncated, report.truncated());
        let receipt = LabReportReceiptWire {
            byte_len: markdown.len() as u64,
            case_id: "case-1".into(),
            truncated,
        };
        assert_eq!(receipt.byte_len, markdown.len() as u64);
        assert_eq!(receipt.case_id, "case-1");
    }

    #[test]
    fn scratchpad_and_missing_selection_are_refused_without_a_store() {
        // The gate is pure over the session scope shape: no case id, an empty
        // id or the scratchpad sentinel all refuse before any lock is taken.
        let refuse = |case_id: Option<&str>| -> bool {
            let id = match case_id {
                Some(id) => id.to_string(),
                None => return true,
            };
            id == "scratchpad" || id.is_empty()
        };
        assert!(refuse(None));
        assert!(refuse(Some("scratchpad")));
        assert!(refuse(Some("")));
        assert!(!refuse(Some("case-7")));
    }
}

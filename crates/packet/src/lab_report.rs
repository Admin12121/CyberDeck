//! Lab session report: one structured artifact summarizing a Network Lab
//! analysis pass — ARP findings, the derived event timeline, the unified host
//! inventory and the passive DNS-response findings — rendered as bounded
//! markdown for case evidence persistence (Bettercap's session-report parity,
//! strictly passive).
//!
//! Pure and deterministic by construction: [`build_report`] accepts
//! already-reduced inputs (the IPC layer owns capture walking) and
//! [`LabReport::render_markdown`] renders them without I/O, clocks or
//! formatting dependencies beyond string building. Every section is capped
//! and the rendered artifact is hard-bounded at 32 KiB so a pathological
//! capture can never inflate the evidence store; truncation is always marked,
//! never silent.

use crate::arp_watch::{ArpFinding, ArpFindingKind, ArpHost, ArpSeverity};
use crate::lab_events::{LabEvent, LabEventKind};
use serde::Serialize;

/// Rendered per-section caps. Inputs above these are counted in
/// [`LabReportCounters`] and marked with a per-section truncation line.
pub const MAX_REPORT_ARP_FINDINGS: usize = 64;
pub const MAX_REPORT_EVENTS: usize = 128;
pub const MAX_REPORT_HOSTS: usize = 128;
pub const MAX_REPORT_DNS_FINDINGS: usize = 64;
/// Hard output bound of the markdown renderer. The case-finding details
/// column must stay small enough to be reviewable; 32 KiB is the contract.
pub const MAX_REPORT_MARKDOWN_BYTES: usize = 32 * 1024;
/// Marker appended when the byte bound (not a section cap) ended the render.
/// The IPC layer checks for it so the export receipt can report truncation
/// honestly even when no section cap was exceeded.
pub const REPORT_TRUNCATION_MARKER: &str =
    "report truncated: the 32 KiB evidence bound was reached";

/// Per-field clamp for renderer lines: a detail that long stays readable and
/// bounds every line's worst-case size independently of the byte budget.
const MAX_DETAIL_CHARS: usize = 120;
/// Per-field clamp for subject/address text (IPv6 text form tops out at 45).
const MAX_SUBJECT_CHARS: usize = 64;

/// DNS finding entry reduced to the fields a report needs. A mirror of
/// `dns_monitor::DnsFinding`'s essential text fields with `kind` flattened to
/// its serde label: owning the struct keeps this module free of a dependency
/// wedge (the analyzer's rich baseline/later answer sets stay in the UI) and
/// the crate zero-dep beyond serde.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsReportEntry {
    pub kind: String,
    pub question_name: String,
    pub detail: String,
}

/// Input totals as received by [`build_report`], before per-section capping.
/// The report shows the rendered subset and these totals, so truncation is
/// arithmetic the reviewer can check, not a silent drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LabReportCounters {
    pub arp_findings_total: usize,
    pub events_total: usize,
    pub hosts_total: usize,
    pub dns_findings_total: usize,
}

/// One lab session report: the reduced analysis inputs, when it was produced,
/// and the counters that make any cap honest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LabReport {
    /// Epoch milliseconds of report generation; 0 means unknown provenance.
    pub generated_at_ms: u64,
    pub arp_findings: Vec<ArpFinding>,
    pub events: Vec<LabEvent>,
    pub hosts: Vec<ArpHost>,
    pub dns_findings: Vec<DnsReportEntry>,
    pub counters: LabReportCounters,
}

/// Aggregate already-reduced lab inputs into one report. Pure: the caller
/// keeps ownership of the inputs; each section is capped to its render bound
/// and the full input sizes are recorded in the counters.
pub fn build_report(
    arp_findings: &[ArpFinding],
    events: &[LabEvent],
    hosts: &[ArpHost],
    dns_findings: &[DnsReportEntry],
    generated_at_ms: u64,
) -> LabReport {
    LabReport {
        generated_at_ms,
        arp_findings: arp_findings
            .iter()
            .take(MAX_REPORT_ARP_FINDINGS)
            .cloned()
            .collect(),
        events: events.iter().take(MAX_REPORT_EVENTS).cloned().collect(),
        hosts: hosts.iter().take(MAX_REPORT_HOSTS).cloned().collect(),
        dns_findings: dns_findings
            .iter()
            .take(MAX_REPORT_DNS_FINDINGS)
            .cloned()
            .collect(),
        counters: LabReportCounters {
            arp_findings_total: arp_findings.len(),
            events_total: events.len(),
            hosts_total: hosts.len(),
            dns_findings_total: dns_findings.len(),
        },
    }
}

impl LabReport {
    /// True when any input list exceeded its rendered section cap. Byte-budget
    /// truncation inside [`Self::render_markdown`] is reported through
    /// [`REPORT_TRUNCATION_MARKER`] in the output instead, because the render
    /// happens after aggregation.
    pub fn truncated(&self) -> bool {
        self.counters.arp_findings_total > self.arp_findings.len()
            || self.counters.events_total > self.events.len()
            || self.counters.hosts_total > self.hosts.len()
            || self.counters.dns_findings_total > self.dns_findings.len()
    }

    /// Render the report as bounded markdown (at most
    /// [`MAX_REPORT_MARKDOWN_BYTES`] bytes, marker included). Deterministic:
    /// the same report always renders byte-for-byte identically.
    pub fn render_markdown(&self) -> String {
        let mut writer = BoundedWriter::new(MAX_REPORT_MARKDOWN_BYTES);
        writer.line("# Lab session report");
        writer.line("");
        writer.line(&format!(
            "- Generated (unix ms): {}",
            self.generated_at_ms
        ));
        writer.line(
            "- Scope: passive Network Lab analysis over one opened capture (ARP findings, event timeline, host inventory, DNS findings); never transmits packets",
        );
        writer.line(&format!(
            "- Rendered caps: {MAX_REPORT_ARP_FINDINGS} ARP findings, {MAX_REPORT_EVENTS} timeline events, {MAX_REPORT_HOSTS} hosts, {MAX_REPORT_DNS_FINDINGS} DNS findings"
        ));
        writer.line("");

        writer.line("## Summary");
        writer.line(&format!(
            "- ARP findings: {} of {} rendered",
            self.arp_findings.len(),
            self.counters.arp_findings_total
        ));
        writer.line(&format!(
            "- Timeline events: {} of {} rendered",
            self.events.len(),
            self.counters.events_total
        ));
        writer.line(&format!(
            "- Host inventory: {} of {} rendered",
            self.hosts.len(),
            self.counters.hosts_total
        ));
        writer.line(&format!(
            "- DNS findings: {} of {} rendered",
            self.dns_findings.len(),
            self.counters.dns_findings_total
        ));
        writer.line("");

        writer.line("## ARP findings");
        if self.arp_findings.is_empty() {
            writer.line("- none recorded");
        }
        for finding in &self.arp_findings {
            let claims = finding
                .macs
                .iter()
                .map(|claim| format!("{} ({})", sanitize(&claim.mac, MAX_SUBJECT_CHARS), claim.claims))
                .collect::<Vec<_>>()
                .join(", ");
            writer.line(&format!(
                "- [{}] {} {} — {} · MACs: {} · first {} · last {}",
                severity_label(finding.severity),
                kind_label(finding.kind),
                sanitize(&finding.ip, MAX_SUBJECT_CHARS),
                sanitize(&finding.detail, MAX_DETAIL_CHARS),
                claims,
                finding.first_seen_ms,
                finding.last_seen_ms,
            ));
        }
        self.overflow_line(
            &mut writer,
            self.counters.arp_findings_total,
            self.arp_findings.len(),
            MAX_REPORT_ARP_FINDINGS,
            "ARP findings",
        );
        writer.line("");

        writer.line("## Event timeline");
        if self.events.is_empty() {
            writer.line("- none recorded");
        }
        for event in &self.events {
            writer.line(&format!(
                "- [{}] {}ms {} — {}",
                event_kind_label(event.kind),
                event.timestamp_ms,
                sanitize(&event.subject, MAX_SUBJECT_CHARS),
                sanitize(&event.detail, MAX_DETAIL_CHARS),
            ));
        }
        self.overflow_line(
            &mut writer,
            self.counters.events_total,
            self.events.len(),
            MAX_REPORT_EVENTS,
            "timeline events",
        );
        writer.line("");

        writer.line("## Host inventory");
        if self.hosts.is_empty() {
            writer.line("- none recorded");
        }
        for host in &self.hosts {
            let claims = host
                .mac_claims
                .iter()
                .map(|claim| format!("{} ({})", sanitize(&claim.mac, MAX_SUBJECT_CHARS), claim.claims))
                .collect::<Vec<_>>()
                .join(", ");
            writer.line(&format!(
                "- {} — {} · first {} · last {} · {}",
                sanitize(&host.ip, MAX_SUBJECT_CHARS),
                if claims.is_empty() { "no attributable MAC" } else { &claims },
                host.first_seen_ms,
                host.last_seen_ms,
                if host.impersonated { "CONFLICT" } else { "stable" },
            ));
        }
        self.overflow_line(
            &mut writer,
            self.counters.hosts_total,
            self.hosts.len(),
            MAX_REPORT_HOSTS,
            "hosts",
        );
        writer.line("");

        writer.line("## DNS findings");
        if self.dns_findings.is_empty() {
            writer.line("- none recorded");
        }
        for finding in &self.dns_findings {
            writer.line(&format!(
                "- {} {} — {}",
                sanitize(&finding.kind, MAX_SUBJECT_CHARS),
                sanitize(&finding.question_name, MAX_SUBJECT_CHARS),
                sanitize(&finding.detail, MAX_DETAIL_CHARS),
            ));
        }
        self.overflow_line(
            &mut writer,
            self.counters.dns_findings_total,
            self.dns_findings.len(),
            MAX_REPORT_DNS_FINDINGS,
            "DNS findings",
        );
        writer.line("");

        writer.line("## Notes");
        writer.line(
            "- Timestamps are epoch milliseconds from the capture; 0 means unknown provenance.",
        );
        writer.line(
            "- Passive observation summary only: nothing in this report transmits, injects or alters packets.",
        );
        writer.finish()
    }

    /// Per-section truncation marker when the input list exceeded the cap.
    fn overflow_line(
        &self,
        writer: &mut BoundedWriter,
        total: usize,
        rendered: usize,
        cap: usize,
        section: &str,
    ) {
        if total > rendered {
            writer.line(&format!(
                "- … {} more {section} not rendered (input cap {cap})",
                total - rendered
            ));
        }
    }
}

/// Byte-budgeted line writer: every accepted line counts its bytes against
/// the remaining budget; the first line that would not fit stops the render
/// (dropping at most that one line) and the finish() call appends the
/// reserved truncation marker, which is why the marker always fits.
struct BoundedWriter {
    out: String,
    remaining: usize,
    truncated: bool,
}

impl BoundedWriter {
    fn new(capacity: usize) -> Self {
        // Reserve the marker + newline up front so it survives a full budget.
        let reserved = REPORT_TRUNCATION_MARKER.len() + 1;
        BoundedWriter {
            out: String::new(),
            remaining: capacity.saturating_sub(reserved),
            truncated: false,
        }
    }

    fn line(&mut self, text: &str) {
        if self.truncated {
            return;
        }
        let needed = text.len() + 1; // line + newline
        if needed > self.remaining {
            self.truncated = true;
            return;
        }
        self.remaining -= needed;
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn finish(mut self) -> String {
        if self.truncated {
            self.out.push_str(REPORT_TRUNCATION_MARKER);
            self.out.push('\n');
        }
        self.out
    }
}

/// Clamp text to `max_chars` characters and flatten it to a single markdown
/// line: control characters (newlines, carriage returns, tabs) become spaces
/// so finding details can never break the report's structure. Operates on
/// chars, never byte slices, so multi-byte details cannot panic.
fn sanitize(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_chars * 2));
    for (index, c) in text.chars().enumerate() {
        if index >= max_chars {
            out.push('…');
            break;
        }
        if c.is_control() {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn severity_label(severity: ArpSeverity) -> &'static str {
    match severity {
        ArpSeverity::Critical => "critical",
        ArpSeverity::Warning => "warning",
    }
}

fn kind_label(kind: ArpFindingKind) -> &'static str {
    match kind {
        ArpFindingKind::IpImpersonation => "ip_impersonation",
        ArpFindingKind::GatewayImpersonation => "gateway_impersonation",
        ArpFindingKind::GratuitousBurst => "gratuitous_burst",
    }
}

fn event_kind_label(kind: LabEventKind) -> &'static str {
    match kind {
        LabEventKind::NewHost => "new_host",
        LabEventKind::NewService => "new_service",
        LabEventKind::ArpConflict => "arp_conflict",
        LabEventKind::GatewayChanged => "gateway_changed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arp_watch::{ArpMacClaim, ArpOperation};

    fn claim(mac: &str, claims: u32) -> ArpMacClaim {
        ArpMacClaim {
            mac: mac.to_string(),
            claims,
            first_seen_ms: 1_000,
            last_seen_ms: 2_000,
        }
    }

    fn finding(ip: &str, macs: Vec<ArpMacClaim>) -> ArpFinding {
        ArpFinding {
            kind: ArpFindingKind::IpImpersonation,
            ip: ip.to_string(),
            macs,
            first_seen_ms: 1_000,
            last_seen_ms: 9_000,
            severity: ArpSeverity::Warning,
            detail: format!("1 additional MAC claims {ip}"),
        }
    }

    fn event(ts: u64, subject: &str, detail: &str) -> LabEvent {
        LabEvent {
            timestamp_ms: ts,
            kind: LabEventKind::NewHost,
            subject: subject.to_string(),
            detail: detail.to_string(),
        }
    }

    fn host(ip: &str, impersonated: bool) -> ArpHost {
        ArpHost {
            ip: ip.to_string(),
            mac_claims: vec![claim("aa:aa:aa:aa:aa:01", 3)],
            first_seen_ms: 1_000,
            last_seen_ms: 2_000,
            impersonated,
        }
    }

    fn dns(kind: &str, name: &str) -> DnsReportEntry {
        DnsReportEntry {
            kind: kind.to_string(),
            question_name: name.to_string(),
            detail: format!("{kind} evidence for {name}"),
        }
    }

    #[test]
    fn markdown_contains_all_sections_and_honest_empty_shape() {
        let report = build_report(&[], &[], &[], &[], 1_700_000_000_000);
        let markdown = report.render_markdown();
        for section in [
            "# Lab session report",
            "## Summary",
            "## ARP findings",
            "## Event timeline",
            "## Host inventory",
            "## DNS findings",
            "## Notes",
        ] {
            assert!(markdown.contains(section), "missing section: {section}");
        }
        // Empty inputs say so instead of leaving blank sections.
        assert_eq!(markdown.matches("- none recorded").count(), 4);
        assert!(markdown.contains("Generated (unix ms): 1700000000000"));
        assert!(!report.truncated());
        assert!(!markdown.contains(REPORT_TRUNCATION_MARKER));
        assert!(markdown.len() <= MAX_REPORT_MARKDOWN_BYTES);
    }

    #[test]
    fn populated_report_renders_findings_events_hosts_and_dns_details() {
        let arp = vec![finding(
            "10.0.0.9",
            vec![claim("aa:aa:aa:aa:aa:01", 3), claim("bb:bb:bb:bb:bb:02", 2)],
        )];
        let events = vec![event(5_000, "10.0.0.9", "host 10.0.0.9 first seen")];
        let hosts = vec![host("10.0.0.9", true)];
        let dns_entries = vec![dns("answer_inconsistency", "bank.example")];
        let report = build_report(&arp, &events, &hosts, &dns_entries, 42);
        let markdown = report.render_markdown();
        assert!(markdown.contains("ip_impersonation 10.0.0.9 — 1 additional MAC claims 10.0.0.9"));
        assert!(markdown.contains("aa:aa:aa:aa:aa:01 (3), bb:bb:bb:bb:bb:02 (2)"));
        assert!(markdown.contains("- [new_host] 5000ms 10.0.0.9 — host 10.0.0.9 first seen"));
        assert!(markdown.contains("- 10.0.0.9 — aa:aa:aa:aa:aa:01 (3) · first 1000 · last 2000 · CONFLICT"));
        assert!(markdown.contains("- answer_inconsistency bank.example — answer_inconsistency evidence for bank.example"));
        assert!(markdown.contains("- ARP findings: 1 of 1 rendered"));
        assert!(markdown.contains("- Timeline events: 1 of 1 rendered"));
        assert!(markdown.contains("- Host inventory: 1 of 1 rendered"));
        assert!(markdown.contains("- DNS findings: 1 of 1 rendered"));
        assert!(!report.truncated());
    }

    #[test]
    fn inputs_over_caps_keep_totals_and_mark_the_overflow() {
        let arp: Vec<ArpFinding> = (0..MAX_REPORT_ARP_FINDINGS + 10)
            .map(|i| finding(&format!("10.1.{i}.1"), vec![claim("aa:aa:aa:aa:aa:01", 1)]))
            .collect();
        let events: Vec<LabEvent> = (0..MAX_REPORT_EVENTS + 10)
            .map(|i| event(i as u64, &format!("10.2.{i}.1"), "first seen"))
            .collect();
        let hosts: Vec<ArpHost> = (0..MAX_REPORT_HOSTS + 10)
            .map(|i| host(&format!("10.3.{i}.1"), false))
            .collect();
        let dns_entries: Vec<DnsReportEntry> = (0..MAX_REPORT_DNS_FINDINGS + 10)
            .map(|i| dns("suspicious_target", &format!("host{i}.example")))
            .collect();
        let report = build_report(&arp, &events, &hosts, &dns_entries, 7);
        assert_eq!(report.arp_findings.len(), MAX_REPORT_ARP_FINDINGS);
        assert_eq!(report.events.len(), MAX_REPORT_EVENTS);
        assert_eq!(report.hosts.len(), MAX_REPORT_HOSTS);
        assert_eq!(report.dns_findings.len(), MAX_REPORT_DNS_FINDINGS);
        assert_eq!(report.counters.arp_findings_total, MAX_REPORT_ARP_FINDINGS + 10);
        assert_eq!(report.counters.events_total, MAX_REPORT_EVENTS + 10);
        assert!(report.truncated());
        let markdown = report.render_markdown();
        assert!(markdown.contains(&format!(
            "… 10 more ARP findings not rendered (input cap {MAX_REPORT_ARP_FINDINGS})"
        )));
        assert!(markdown.contains(&format!(
            "… 10 more timeline events not rendered (input cap {MAX_REPORT_EVENTS})"
        )));
        assert!(markdown.contains("… 10 more hosts not rendered"));
        assert!(markdown.contains("… 10 more DNS findings not rendered"));
        assert!(markdown.contains("- ARP findings: 64 of 74 rendered"));
        assert!(markdown.len() <= MAX_REPORT_MARKDOWN_BYTES);
    }

    #[test]
    fn byte_budget_hard_bounds_the_output_and_appends_the_marker() {
        // Long details on the maximum event + host counts force the byte
        // budget, not a section cap, to end the render.
        let long_detail = "e".repeat(4_000);
        let events: Vec<LabEvent> = (0..MAX_REPORT_EVENTS)
            .map(|i| event(i as u64, &format!("10.0.{i}.1"), &long_detail))
            .collect();
        let hosts: Vec<ArpHost> = (0..MAX_REPORT_HOSTS)
            .map(|i| host(&format!("10.1.{i}.1"), false))
            .collect();
        let report = build_report(&[], &events, &hosts, &[], 0);
        let markdown = report.render_markdown();
        assert!(markdown.len() <= MAX_REPORT_MARKDOWN_BYTES);
        assert!(markdown.ends_with(REPORT_TRUNCATION_MARKER));
        // The budget marker is the global signal the IPC receipt checks.
        assert!(markdown.contains(REPORT_TRUNCATION_MARKER));
    }

    #[test]
    fn details_are_sanitized_to_single_bounded_lines() {
        let hostile = event(
            1,
            "10.0.0.9",
            "injected\r\n## forged heading\twith tab and é",
        );
        let report = build_report(&[], &[hostile], &[], &[], 0);
        let markdown = report.render_markdown();
        // The control characters never reach the output as line breaks.
        assert!(!markdown.contains("injected\r"));
        assert!(!markdown.contains("\n## forged"));
        assert!(markdown.contains("injected  forged heading with tab and é"));
        // Over-long details clamp with an ellipsis instead of eating budget.
        let long = event(2, "10.0.0.9", &"x".repeat(500));
        let report = build_report(&[], &[long], &[], &[], 0);
        let markdown = report.render_markdown();
        let line = markdown
            .lines()
            .find(|l| l.starts_with("- [new_host] 2ms"))
            .expect("event line present");
        assert!(line.chars().count() < 200);
        assert!(line.ends_with('…'));
    }

    #[test]
    fn rendering_is_deterministic_for_the_same_inputs() {
        let arp = vec![finding("10.0.0.9", vec![claim("aa:aa:aa:aa:aa:01", 3)])];
        let events = vec![event(1, "10.0.0.9", "first seen")];
        let one = build_report(&arp, &events, &[], &[], 5).render_markdown();
        let two = build_report(&arp, &events, &[], &[], 5).render_markdown();
        assert_eq!(one, two, "same capture, same report");
    }

    #[test]
    fn observation_helpers_keep_arp_shapes_round_trippable() {
        // The report accepts the exact analyzer output types: an operation
        // enum and a finding built the way arp_watch builds them survive a
        // build/render round trip with their detail intact.
        let _ = ArpOperation::Reply; // type-shape guard for the test imports
        let arp = vec![finding("10.0.0.9", vec![claim("aa:aa:aa:aa:aa:01", 3)])];
        let report = build_report(&arp, &[], &[], &[], 0);
        assert_eq!(report.arp_findings[0].macs[0].mac, "aa:aa:aa:aa:aa:01");
        assert!(report
            .render_markdown()
            .contains("1 additional MAC claims 10.0.0.9"));
    }
}

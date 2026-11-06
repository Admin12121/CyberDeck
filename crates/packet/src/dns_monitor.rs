//! Passive DNS-response monitoring for the Network Lab: query/answer
//! correlation and interception indicators over an ordered stream of DNS
//! summaries — the dns-spoofing detection counterpart, strictly passive.
//!
//! Re-derived from first principles: a healthy resolver keeps one stable
//! answer per (question name, record type) and never steers ordinary names
//! into loopback or link-local space, so three bounded indicators cover the
//! passive spoofing/hijack surface:
//!   1. answer inconsistency: the same question answered with a materially
//!      different A/AAAA set than an earlier response (the first observed set
//!      is the baseline; a LATER differing set is the finding — the classic
//!      passive spoofing/rebinding indicator);
//!   2. suspicious answer targets: an A/AAAA record whose value is a
//!      loopback or link-local address for a non-localhost question name
//!      (local-service redirection, DNS rebinding staging, metadata probes);
//!   3. NXDOMAIN injection: a name that resolved successfully earlier starts
//!      returning NXDOMAIN (censorship or resolver hijack indicator).
//!
//! Honest by construction: one query seen once produces nothing, findings
//! fire once per subject, and everything is chronological and deterministic.
//! This module never emits or mutates packets; it only reads observations.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Findings are bounded so a pathological capture cannot flood the UI or IPC.
pub const MAX_DNS_FINDINGS: usize = 128;
/// Distinct question names tracked for the wire counter and NXDOMAIN
/// correlation; mirrors the arp_watch inventory scale.
pub const MAX_TRACKED_NAMES: usize = 512;
/// Distinct (name, question type) A/AAAA baselines tracked for inconsistency.
pub const MAX_TRACKED_BASELINES: usize = 512;
/// Values stored per baseline answer set (the DNS decoder caps answers at 16).
pub const MAX_BASELINE_VALUES: usize = 16;
/// NXDOMAIN response code (RCODE 3) per RFC 1035.
const RCODE_NXDOMAIN: u8 = 3;

/// One observed DNS message reduced to the fields the analyzer needs.
/// `answers` carries (rdata value, record-type label) pairs exactly as the
/// dissector decoded them; the analyzer trusts the reduction so packet-format
/// knowledge stays out of here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsObservation {
    pub timestamp_ms: u64,
    pub is_response: bool,
    pub question_name: String,
    pub question_type: u16,
    pub answers: Vec<(String, String)>,
    pub response_code: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFindingKind {
    AnswerInconsistency,
    SuspiciousTarget,
    NxdomainInjection,
}

/// One answer-set snapshot: the normalized A/AAAA values plus when that set
/// was observed. `values` is sorted and deduplicated so comparison is
/// order-insensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsAnswerSet {
    pub values: Vec<String>,
    pub seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsFinding {
    pub kind: DnsFindingKind,
    pub question_name: String,
    pub question_type: u16,
    /// Baseline (first-observed) answer set — inconsistency findings only.
    pub baseline: Option<DnsAnswerSet>,
    /// The later, differing answer set — inconsistency findings only.
    pub later: Option<DnsAnswerSet>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Human-readable evidence; the UI shows it alongside the chip.
    pub detail: String,
}

/// Analysis result: the bounded finding list plus the distinct-question-name
/// counter the UI shows next to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsMonitorReport {
    pub findings: Vec<DnsFinding>,
    /// Distinct lowercased question names seen, capped at MAX_TRACKED_NAMES.
    pub queried_names: usize,
}

/// Mutable correlation state across the observation walk. BTreeMaps/Sets keep
/// every output deterministic regardless of iteration order.
#[derive(Default)]
struct DnsState {
    /// (lowercased name, question type) -> first A/AAAA answer set.
    baselines: BTreeMap<(String, u16), DnsAnswerSet>,
    /// Lowercased name -> first successful (rcode 0, answered) response.
    resolved: BTreeMap<String, u64>,
    /// Subjects that already fired, so a long capture raises one indicator
    /// per (name, type), per name, and per (name, value) — never per repeat.
    inconsistent_fired: BTreeSet<(String, u16)>,
    nxdomain_fired: BTreeSet<String>,
    suspicious_fired: BTreeSet<(String, String)>,
    /// Every distinct question name seen (queries included), for the counter.
    queried: BTreeSet<String>,
}

/// DNS names are case-insensitive; normalization keeps correlation stable
/// without touching the wire bytes.
fn normalize_name(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// The A/AAAA subset of one response, sorted and deduplicated: the
/// "materially different" comparison set. Empty when the response carries no
/// address answers (CNAME-only, MX, NODATA), which never establishes or
/// challenges a baseline.
fn addr_answer_set(answers: &[(String, String)]) -> Vec<String> {
    let mut values: BTreeSet<String> = BTreeSet::new();
    for (value, label) in answers {
        if label == "A" || label == "AAAA" {
            values.insert(value.clone());
            if values.len() >= MAX_BASELINE_VALUES {
                break;
            }
        }
    }
    values.into_iter().collect()
}

/// Loopback/link-local detection over the decoded address text. Values that
/// are not addresses (CNAME targets, MX priorities, TXT) simply never match.
fn is_suspicious_value(value: &str) -> bool {
    if let Ok(v4) = value.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback() || v4.is_link_local();
    }
    if let Ok(v6) = value.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() {
            return true;
        }
        // fe80::/10: the first ten bits are 1111111010. Checked by hand so
        // the analyzer does not depend on a recent std API.
        let segments = v6.segments();
        return (segments[0] & 0xffc0) == 0xfe80;
    }
    false
}

/// Only genuinely local names may legitimately answer with local addresses;
/// anything else pointing there is an indicator.
fn is_localhost_name(name: &str) -> bool {
    name.is_empty() || name == "." || name == "localhost" || name.ends_with(".localhost")
}

fn type_label(question_type: u16) -> String {
    crate::dns::record_type_label(question_type)
}

/// Correlate one ordered observation stream into findings, oldest first.
/// The same capture always produces the same report.
pub fn analyze_dns(observations: &[DnsObservation]) -> DnsMonitorReport {
    let mut state = DnsState::default();
    let mut findings: Vec<DnsFinding> = Vec::new();

    for obs in observations {
        if findings.len() >= MAX_DNS_FINDINGS {
            break;
        }
        let name = normalize_name(&obs.question_name);
        if state.queried.len() < MAX_TRACKED_NAMES {
            state.queried.insert(name.clone());
        }
        // Queries establish nothing: baselines, resolution history and
        // findings all come from responses only.
        if !obs.is_response {
            continue;
        }

        // 1. Answer inconsistency: a later A/AAAA set differing from the
        //    first-observed baseline for the same (name, question type).
        let key = (name.clone(), obs.question_type);
        let addr_set = addr_answer_set(&obs.answers);
        if !addr_set.is_empty() {
            let baseline = state.baselines.get(&key).cloned();
            match baseline {
                None => {
                    if state.baselines.len() < MAX_TRACKED_BASELINES {
                        state.baselines.insert(
                            key.clone(),
                            DnsAnswerSet {
                                values: addr_set,
                                seen_ms: obs.timestamp_ms,
                            },
                        );
                    }
                }
                Some(baseline) => {
                    if baseline.values != addr_set
                        && !state.inconsistent_fired.contains(&key)
                        && findings.len() < MAX_DNS_FINDINGS
                    {
                        state.inconsistent_fired.insert(key.clone());
                        findings.push(DnsFinding {
                            kind: DnsFindingKind::AnswerInconsistency,
                            question_name: name.clone(),
                            question_type: obs.question_type,
                            baseline: Some(baseline.clone()),
                            later: Some(DnsAnswerSet {
                                values: addr_set.clone(),
                                seen_ms: obs.timestamp_ms,
                            }),
                            first_seen_ms: baseline.seen_ms,
                            last_seen_ms: obs.timestamp_ms,
                            detail: format!(
                                "{} {} answered with {} at {} but with {} at {} — changed answer set for the same question (possible spoofing or rebinding)",
                                name,
                                type_label(obs.question_type),
                                baseline.values.join(", "),
                                baseline.seen_ms,
                                addr_set.join(", "),
                                obs.timestamp_ms
                            ),
                        });
                    }
                }
            }
        }

        // 2. NXDOMAIN injection: a name that resolved successfully earlier
        //    starts returning NXDOMAIN.
        if obs.response_code == RCODE_NXDOMAIN {
            if let Some(&resolved_ms) = state.resolved.get(&name) {
                if !state.nxdomain_fired.contains(&name) && findings.len() < MAX_DNS_FINDINGS {
                    state.nxdomain_fired.insert(name.clone());
                    findings.push(DnsFinding {
                        kind: DnsFindingKind::NxdomainInjection,
                        question_name: name.clone(),
                        question_type: obs.question_type,
                        baseline: None,
                        later: None,
                        first_seen_ms: resolved_ms,
                        last_seen_ms: obs.timestamp_ms,
                        detail: format!(
                            "{} resolved successfully at {} but returns NXDOMAIN (rcode 3) now — possible censorship or resolver hijack",
                            name, resolved_ms
                        ),
                    });
                }
            }
        } else if obs.response_code == 0 && !obs.answers.is_empty() {
            if state.resolved.len() < MAX_TRACKED_NAMES {
                state.resolved.insert(name.clone(), obs.timestamp_ms);
            }
        }

        // 3. Suspicious answer targets: loopback/link-local addresses for
        //    non-localhost names. Sorted for a deterministic finding order.
        if !is_localhost_name(&name) {
            let mut suspicious: Vec<&(String, String)> = obs
                .answers
                .iter()
                .filter(|(value, _)| is_suspicious_value(value))
                .collect();
            suspicious.sort();
            for (value, label) in suspicious {
                if findings.len() >= MAX_DNS_FINDINGS {
                    break;
                }
                let fired_key = (name.clone(), value.clone());
                if state.suspicious_fired.contains(&fired_key) {
                    continue;
                }
                state.suspicious_fired.insert(fired_key);
                findings.push(DnsFinding {
                    kind: DnsFindingKind::SuspiciousTarget,
                    question_name: name.clone(),
                    question_type: obs.question_type,
                    baseline: None,
                    later: None,
                    first_seen_ms: obs.timestamp_ms,
                    last_seen_ms: obs.timestamp_ms,
                    detail: format!(
                        "{} {} answer points at {} — loopback/link-local target for a non-local name (possible spoofing or rebinding)",
                        name, label, value
                    ),
                });
            }
        }
    }

    DnsMonitorReport {
        queried_names: state.queried.len(),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(
        timestamp_ms: u64,
        is_response: bool,
        name: &str,
        answers: Vec<(&str, &str)>,
    ) -> DnsObservation {
        DnsObservation {
            timestamp_ms,
            is_response,
            question_name: name.into(),
            question_type: 1, // A
            answers: answers
                .into_iter()
                .map(|(value, label)| (value.to_string(), label.to_string()))
                .collect(),
            response_code: 0,
        }
    }

    fn response(timestamp_ms: u64, name: &str, answers: Vec<(&str, &str)>) -> DnsObservation {
        obs(timestamp_ms, true, name, answers)
    }

    #[test]
    fn one_query_seen_once_produces_nothing() {
        // A single ordinary exchange (query + response) must stay silent:
        // every indicator requires either a second, differing response or a
        // prior successful resolution.
        let observations = vec![
            obs(100, false, "example.com", vec![]),
            response(200, "example.com", vec![("93.184.216.34", "A")]),
        ];
        let report = analyze_dns(&observations);
        assert!(report.findings.is_empty());
        assert_eq!(report.queried_names, 1);
        // And a lone query with no response at all also produces nothing.
        assert!(analyze_dns(&[obs(100, false, "example.com", vec![])])
            .findings
            .is_empty());
    }

    #[test]
    fn answer_inconsistency_fires_on_a_later_differing_set() {
        let observations = vec![
            response(1_000, "bank.example", vec![("203.0.113.10", "A")]),
            response(2_000, "bank.example", vec![("203.0.113.10", "A")]), // repeat: silent
            response(3_000, "bank.example", vec![("198.51.100.66", "A")]), // deviation: fires
            response(4_000, "bank.example", vec![("198.51.100.66", "A")]), // stays fired
        ];
        let report = analyze_dns(&observations);
        let inconsistencies: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.kind == DnsFindingKind::AnswerInconsistency)
            .collect();
        assert_eq!(inconsistencies.len(), 1, "fires once, not per repeat");
        let finding = inconsistencies[0];
        assert_eq!(finding.question_name, "bank.example");
        let baseline = finding.baseline.as_ref().unwrap();
        assert_eq!(baseline.values, vec!["203.0.113.10"]);
        assert_eq!(baseline.seen_ms, 1_000);
        let later = finding.later.as_ref().unwrap();
        assert_eq!(later.values, vec!["198.51.100.66"]);
        assert_eq!(later.seen_ms, 3_000);
        assert_eq!(finding.first_seen_ms, 1_000);
        assert_eq!(finding.last_seen_ms, 3_000);
        assert!(finding.detail.contains("203.0.113.10"));
        assert!(finding.detail.contains("198.51.100.66"));
    }

    #[test]
    fn answer_set_comparison_is_order_insensitive_and_type_scoped() {
        // Same addresses in a different order are not a "different set".
        let observations = vec![
            response(
                1_000,
                "cdn.example",
                vec![("203.0.113.1", "A"), ("203.0.113.2", "A")],
            ),
            response(
                2_000,
                "cdn.example",
                vec![("203.0.113.2", "A"), ("203.0.113.1", "A")],
            ),
        ];
        assert!(analyze_dns(&observations).findings.is_empty());
        // The same name asked as a different question type is a different key.
        let mut aaaa = response(3_000, "cdn.example", vec![("2001:db8::1", "AAAA")]);
        aaaa.question_type = 28;
        let observations = vec![
            response(1_000, "cdn.example", vec![("203.0.113.1", "A")]),
            aaaa,
        ];
        assert!(analyze_dns(&observations).findings.is_empty());
        // Non-address answers never establish or challenge a baseline.
        let observations = vec![
            response(1_000, "mail.example", vec![("10 mail.example", "MX")]),
            response(2_000, "mail.example", vec![("203.0.113.9", "A")]),
        ];
        assert!(analyze_dns(&observations).findings.is_empty());
    }

    #[test]
    fn suspicious_targets_fire_for_link_local_and_loopback_only_off_localhost() {
        let observations = vec![
            // Metadata-style link-local target for an ordinary name: fires.
            response(1_000, "evil.example", vec![("169.254.169.254", "A")]),
            // Loopback target: fires.
            response(2_000, "rebind.example", vec![("127.0.0.1", "A")]),
            // IPv6 link-local and loopback targets: fire.
            response(3_000, "v6.example", vec![("fe80::1", "AAAA")]),
            response(4_000, "v6loop.example", vec![("::1", "AAAA")]),
            // fe80::/10 boundary: fb80:: is NOT link-local, stays silent.
            response(5_000, "quiet.example", vec![("fb80::1", "AAAA")]),
            // localhost names are exempt from the local-address indicator.
            response(6_000, "localhost", vec![("127.0.0.1", "A")]),
            response(7_000, "api.localhost", vec![("127.0.0.1", "A")]),
        ];
        let report = analyze_dns(&observations);
        let suspicious: Vec<&DnsFinding> = report
            .findings
            .iter()
            .filter(|f| f.kind == DnsFindingKind::SuspiciousTarget)
            .collect();
        let names: Vec<&str> = suspicious
            .iter()
            .map(|f| f.question_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "evil.example",
                "rebind.example",
                "v6.example",
                "v6loop.example"
            ]
        );
        assert!(suspicious[0].detail.contains("169.254.169.254"));
        // A repeat of the same poisoned answer does not spam a second finding.
        let repeated = vec![
            response(1_000, "evil.example", vec![("169.254.169.254", "A")]),
            response(2_000, "evil.example", vec![("169.254.169.254", "A")]),
        ];
        assert_eq!(
            analyze_dns(&repeated)
                .findings
                .iter()
                .filter(|f| f.kind == DnsFindingKind::SuspiciousTarget)
                .count(),
            1
        );
    }

    #[test]
    fn nxdomain_injection_requires_a_prior_successful_resolution() {
        let observations = vec![
            response(1_000, "news.example", vec![("203.0.113.7", "A")]),
            response(2_000, "news.example", vec![]), // NODATA: not NXDOMAIN
        ];
        // A response that simply has no answers is rcode 0, never NXDOMAIN.
        assert!(analyze_dns(&observations).findings.is_empty());
        let mut nxdomain = response(3_000, "never-seen.example", vec![]);
        nxdomain.response_code = RCODE_NXDOMAIN;
        // NXDOMAIN for a name that never resolved here: nothing to inject over.
        assert!(analyze_dns(&[nxdomain.clone()]).findings.is_empty());
        // Resolved first, NXDOMAIN later: the injection indicator fires once.
        let observations = vec![
            response(1_000, "news.example", vec![("203.0.113.7", "A")]),
            nxdomain2(2_000, "news.example"),
            nxdomain2(3_000, "news.example"),
        ];
        let report = analyze_dns(&observations);
        let injections: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.kind == DnsFindingKind::NxdomainInjection)
            .collect();
        assert_eq!(injections.len(), 1);
        assert_eq!(injections[0].question_name, "news.example");
        assert_eq!(injections[0].first_seen_ms, 1_000);
        assert_eq!(injections[0].last_seen_ms, 2_000);
        assert!(injections[0].detail.contains("NXDOMAIN"));
    }

    fn nxdomain2(timestamp_ms: u64, name: &str) -> DnsObservation {
        let mut observation = obs(timestamp_ms, true, name, vec![]);
        observation.response_code = RCODE_NXDOMAIN;
        observation
    }

    #[test]
    fn queries_and_findings_stay_chronological_and_deterministic() {
        let observations = vec![
            obs(100, false, "bank.example", vec![]),
            response(200, "bank.example", vec![("203.0.113.10", "A")]),
            response(300, "rebind.example", vec![("127.0.0.1", "A")]),
            response(400, "bank.example", vec![("198.51.100.66", "A")]),
        ];
        let first = analyze_dns(&observations);
        let second = analyze_dns(&observations);
        assert_eq!(first, second, "same capture, same report");
        let stamps: Vec<u64> = first.findings.iter().map(|f| f.last_seen_ms).collect();
        let mut sorted = stamps.clone();
        sorted.sort();
        assert_eq!(stamps, sorted, "findings come out oldest first");
        assert_eq!(first.findings[0].kind, DnsFindingKind::SuspiciousTarget);
        assert_eq!(first.findings[1].kind, DnsFindingKind::AnswerInconsistency);
    }

    #[test]
    fn finding_list_is_bounded_no_matter_how_many_observations() {
        let mut observations = Vec::new();
        // 300 names, each with an inconsistency + a suspicious answer: the
        // list must stop at MAX_DNS_FINDINGS instead of flooding the UI.
        for i in 0..300u64 {
            let name = format!("host{i}.example");
            observations.push(response(1_000 + i, &name, vec![("203.0.113.1", "A")]));
            observations.push(response(2_000 + i, &name, vec![("127.0.0.1", "A")]));
        }
        let report = analyze_dns(&observations);
        assert_eq!(report.findings.len(), MAX_DNS_FINDINGS);
        assert!(report.findings.len() <= 128);
        // Distinct-name tracking is capped as well.
        assert!(report.queried_names <= MAX_TRACKED_NAMES);
    }

    #[test]
    fn name_normalization_makes_correlation_case_insensitive() {
        let observations = vec![
            response(1_000, "Bank.Example", vec![("203.0.113.10", "A")]),
            response(2_000, "bank.example", vec![("198.51.100.66", "A")]),
        ];
        let report = analyze_dns(&observations);
        assert_eq!(report.queried_names, 1, "same name, different case");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].question_name, "bank.example");
    }
}

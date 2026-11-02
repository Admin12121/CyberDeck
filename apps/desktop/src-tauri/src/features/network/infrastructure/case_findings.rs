//! Persist authorized TCP scan observations into the selected evidence case.
use super::{ScanEntry, ScanObservation};
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_storage::NewFinding;
use tauri::{AppHandle, Manager};

/// Preserve original bounded findings (256 open services plus one overflow record).
pub(super) fn save_scan(
    app: &AppHandle,
    case_id: &str,
    expected: &CaseSessionWire,
    scan_id: u64,
    entries: &[ScanEntry],
    observations: &[ScanObservation],
) -> Result<usize, String> {
    if entries.is_empty() && observations.is_empty() {
        return Ok(0);
    }
    let findings = if observations.is_empty() {
        build_findings(entries, scan_id)
    } else {
        build_observation_findings(observations, scan_id)
    };
    let tool_key = if observations
        .first()
        .is_some_and(|row| row.protocol == "udp")
    {
        "network.udp"
    } else {
        "network.tcp"
    };
    let context = app.state::<EvidenceCtx>();
    let store = context.store.lock().map_err(|_| "case store unavailable")?;
    let case_selection = app.state::<CaseSessionCtx>();
    case_selection.with_current_publication(expected, || {
        // The store mutex was acquired first, matching case_session_select.
        // A stale worker cannot add findings after a case switch/reselection.
        let mut count = 0;
        for batch in findings.chunks(128) {
            count += store.add_findings(case_id, tool_key, None, batch)?;
        }
        Ok(count)
    })
}

/// Persist only short, backend-constructed, read-only probe evidence. Do
/// not store arbitrary service banners: they may include cookies, credentials
/// or attacker-supplied controls. STUN's network-reported endpoint is expressly
/// unverified and retained only within the authorized case.
fn bounded_protocol_evidence(observation: &ScanObservation) -> Option<&str> {
    if observation.service_basis != "observed_response"
        || !matches!(
            observation.service.as_str(),
            "stun" | "redis" | "postgresql" | "socks5" | "memcached" | "imap" | "pop3"
        )
    {
        return None;
    }
    let banner = observation.banner.as_str();
    let recognized = match observation.service.as_str() {
        "stun" => banner.starts_with("STUN Binding response, unverified mapped endpoint "),
        "redis" => banner.starts_with("RESP PING confirmed "),
        "postgresql" => banner.starts_with("PostgreSQL SSLRequest returned "),
        "socks5" => banner.starts_with("SOCKS5 method negotiation "),
        "memcached" => banner.starts_with("Memcached "),
        "imap" => banner == "IMAP CAPABILITY returned a complete tagged OK reply",
        "pop3" => banner == "POP3 CAPA returned a complete terminated capability list",
        _ => false,
    };
    if recognized
        && banner.len() <= 160
        && banner.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    {
        Some(banner)
    } else {
        None
    }
}

fn build_observation_findings(observations: &[ScanObservation], scan_id: u64) -> Vec<NewFinding> {
    let mut findings = observations.iter().take(256).map(|observation| NewFinding {
        title: format!("{} {} {}:{}", observation.protocol.to_ascii_uppercase(), observation.state, observation.host, observation.port),
        severity: "info".into(),
        details: format!(
            "Authorized {} scan #{scan_id}\nHost: {}\nPort: {}\nState: {}\nReason: {}\nMethod: {}\nService: {}\nService evidence: {}\nObserved unix ms: {}\nElapsed ms: {}\nAttempts: {}\nRetries: {}\nRemote-claimed identity (unverified): {}\nBounded protocol evidence (unverified remote claim): {}",
            observation.protocol.to_ascii_uppercase(), observation.host, observation.port, observation.state, observation.reason,
            observation.method, observation.service, observation.service_basis,
            observation.started_at_ms, observation.elapsed_ms,
            observation.attempts, observation.retries,
            observation.remote_software_claim.as_deref().unwrap_or("none"),
            bounded_protocol_evidence(observation).unwrap_or("none"),
        ),
    }).collect::<Vec<_>>();
    if observations.len() > 256 {
        findings.push(NewFinding {
            title: format!("Additional {} scan observations not indexed", observations[0].protocol.to_ascii_uppercase()),
            severity: "info".into(),
            details: format!("Scan #{scan_id}: {} total observations; first 256 persisted in this case. The remaining volatile observations are accessible only during the selected scan session.", observations.len()),
        });
    }
    findings
}

fn build_findings(entries: &[ScanEntry], scan_id: u64) -> Vec<NewFinding> {
    let mut findings = entries
        .iter()
        .take(256)
        .map(|entry| NewFinding {
            title: format!("Open TCP {}:{}", entry.host, entry.port),
            severity: "info".into(),
            details: format!(
                "Authorized TCP scan #{scan_id}\nHost: {}\nPort: {}\nService: {}\nState: {}",
                entry.host, entry.port, entry.service, entry.state
            ),
        })
        .collect::<Vec<_>>();
    if entries.len() > 256 {
        findings.push(NewFinding {
            title: "Additional open services not indexed".into(),
            severity: "info".into(),
            details: format!(
                "Scan #{scan_id} discovered {} open services; first 256 saved in the case. Full scan remains in the scan results.",
                entries.len()
            ),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(port: u16) -> ScanEntry {
        ScanEntry {
            host: "192.0.2.10".to_string(),
            port,
            state: "open".to_string(),
            service: "http".to_string(),
            banner: "Server: sample".to_string(),
        }
    }

    #[test]
    fn imap_pop3_case_findings_require_exact_backend_generated_proof() {
        let mut entry = ScanObservation {
            host: "192.0.2.8".into(),
            port: 143,
            protocol: "tcp".into(),
            state: "open".into(),
            reason: "tcp_connect_accepted".into(),
            method: "tcp_connect".into(),
            service: "imap".into(),
            service_basis: "observed_response".into(),
            remote_software_claim: None,
            banner: "IMAP CAPABILITY returned a complete tagged OK reply".into(),
            started_at_ms: 1,
            elapsed_ms: 3,
            attempts: 1,
            retries: 0,
            os_error_code: None,
        };
        assert_eq!(
            bounded_protocol_evidence(&entry),
            Some("IMAP CAPABILITY returned a complete tagged OK reply")
        );
        entry.banner.push_str(" SECRET");
        assert_eq!(bounded_protocol_evidence(&entry), None);
        entry.service = "pop3".into();
        entry.banner = "POP3 CAPA returned a complete terminated capability list".into();
        assert!(bounded_protocol_evidence(&entry).is_some());
        entry.service_basis = "port_hint_only".into();
        assert_eq!(bounded_protocol_evidence(&entry), None);
    }

    #[test]
    fn case_findings_store_only_bounded_safe_read_only_probe_evidence() {
        let mut sample = ScanObservation {
            host: "192.0.2.5".into(),
            port: 3478,
            protocol: "udp".into(),
            state: "open".into(),
            reason: "udp_correlated_response".into(),
            method: "udp_connected_socket".into(),
            service: "stun".into(),
            service_basis: "observed_response".into(),
            remote_software_claim: None,
            banner: "STUN Binding response, unverified mapped endpoint 203.0.113.10:45678".into(),
            started_at_ms: 1,
            elapsed_ms: 42,
            attempts: 1,
            retries: 0,
            os_error_code: None,
        };
        let rendered = build_observation_findings(&[sample.clone()], 42);
        assert!(rendered[0]
            .details
            .contains("unverified mapped endpoint 203.0.113.10:45678"));
        sample.banner =
            "STUN Binding response, unverified mapped endpoint X\r\nAuthorization: secret".into();
        let rendered = build_observation_findings(&[sample.clone()], 42);
        assert!(rendered[0]
            .details
            .contains("Bounded protocol evidence (unverified remote claim): none"));
        assert!(!rendered[0].details.contains("Authorization: secret"));
        sample.banner =
            "STUN Binding response, unverified mapped endpoint ".to_string() + &"X".repeat(300);
        assert_eq!(bounded_protocol_evidence(&sample), None);
        sample.service_basis = "port_hint_only".into();
        sample.banner =
            "STUN Binding response, unverified mapped endpoint 203.0.113.10:45678".into();
        assert_eq!(bounded_protocol_evidence(&sample), None);
        sample.service_basis = "observed_response".into();
        sample.service = "http".into();
        sample.banner = "Server: imaginary_secret".into();
        assert_eq!(bounded_protocol_evidence(&sample), None);
    }

    #[test]
    fn refused_timeout_and_service_evidence_persist_as_bounded_case_findings() {
        let make = |port, state: &str, reason: &str| ScanObservation {
            host: "127.0.0.1".into(),
            port,
            protocol: "tcp".into(),
            state: state.into(),
            reason: reason.into(),
            method: "tcp_connect".into(),
            service: "unknown".into(),
            service_basis: "none".into(),
            remote_software_claim: None,
            banner: String::new(),
            started_at_ms: 1_700_000,
            elapsed_ms: 10,
            attempts: 1,
            retries: 0,
            os_error_code: None,
        };
        let observations = vec![
            make(22, "closed", "tcp_connect_refused"),
            make(23, "inconclusive", "connect_timeout_no_response"),
        ];
        let findings = build_observation_findings(&observations, 77);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("closed"));
        assert!(findings[0].details.contains("tcp_connect_refused"));
        assert!(findings[1].details.contains("connect_timeout_no_response"));
        assert!(findings[1].details.contains("Observed unix ms: 1700000"));
        let mut claimed = make(80, "open", "tcp_connect_accepted");
        claimed.remote_software_claim = Some("nginx/1.25.3".into());
        let supported = build_observation_findings(&[claimed], 77);
        assert!(supported[0]
            .details
            .contains("Remote-claimed identity (unverified): nginx/1.25.3"));
        assert!(!supported[0].details.contains("Server: ")); // no raw response persisted

        let many = vec![make(1234, "closed", "tcp_connect_refused"); 300];
        let capped = build_observation_findings(&many, 77);
        assert_eq!(capped.len(), 257);
        assert!(capped[256].details.contains("300 total observations"));
    }

    #[test]
    fn udp_observation_finding_preserves_transport_and_uncertainty() {
        let entry = ScanObservation {
            host: "127.0.0.1".into(),
            port: 123,
            protocol: "udp".into(),
            state: "inconclusive".into(),
            reason: "udp_no_response".into(),
            method: "udp_connected_socket".into(),
            service: "unknown".into(),
            service_basis: "none".into(),
            remote_software_claim: None,
            banner: String::new(),
            started_at_ms: 42,
            elapsed_ms: 1200,
            attempts: 2,
            retries: 1,
            os_error_code: None,
        };
        let records = build_observation_findings(&[entry.clone()], 11);
        assert_eq!(records.len(), 1);
        assert!(records[0].title.starts_with("UDP inconclusive"));
        assert!(records[0].details.contains("Authorized UDP scan #11"));
        assert!(records[0].details.contains("Reason: udp_no_response"));
        assert!(records[0].details.contains("Attempts: 2"));
        assert!(records[0].details.contains("Retries: 1"));
        let capped = build_observation_findings(&vec![entry; 257], 11);
        assert_eq!(capped.len(), 257);
        assert_eq!(
            capped[256].title,
            "Additional UDP scan observations not indexed"
        );
    }

    #[test]
    fn case_findings_are_bounded_and_preserve_scan_provenance() {
        assert!(build_findings(&[], 8).is_empty());
        let few = build_findings(&[service(443)], 8);
        assert_eq!(few.len(), 1);
        assert_eq!(few[0].title, "Open TCP 192.0.2.10:443");
        assert_eq!(few[0].severity, "info");
        assert!(few[0].details.contains("Authorized TCP scan #8"));
        assert!(few[0].details.contains("Port: 443"));
        let entries: Vec<_> = (0..258).map(|i| service(1000 + i)).collect();
        let bounded = build_findings(&entries, 9);
        assert_eq!(bounded.len(), 257);
        assert_eq!(bounded[0].title, "Open TCP 192.0.2.10:1000");
        assert_eq!(bounded[255].title, "Open TCP 192.0.2.10:1255");
        assert_eq!(bounded[256].title, "Additional open services not indexed");
        assert!(bounded[256].details.contains("258 open services"));
    }
}

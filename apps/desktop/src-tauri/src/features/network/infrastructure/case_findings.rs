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

fn build_observation_findings(observations: &[ScanObservation], scan_id: u64) -> Vec<NewFinding> {
    let mut findings = observations.iter().take(256).map(|observation| NewFinding {
        title: format!("{} {} {}:{}", observation.protocol.to_ascii_uppercase(), observation.state, observation.host, observation.port),
        severity: "info".into(),
        details: format!(
            "Authorized {} scan #{scan_id}\nHost: {}\nPort: {}\nState: {}\nReason: {}\nMethod: {}\nService: {}\nService evidence: {}\nObserved unix ms: {}\nElapsed ms: {}\nAttempts: {}\nRetries: {}\nRemote-claimed identity (unverified): {}",
            observation.protocol.to_ascii_uppercase(), observation.host, observation.port, observation.state, observation.reason,
            observation.method, observation.service, observation.service_basis,
            observation.started_at_ms, observation.elapsed_ms,
            observation.attempts, observation.retries,
            observation.remote_software_claim.as_deref().unwrap_or("none"),
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

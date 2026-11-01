//! Persist authorized TCP scan observations into the selected evidence case.
use super::ScanEntry;
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use cyberdeck_storage::NewFinding;
use tauri::{AppHandle, Manager};

/// Preserve original bounded findings (256 open services plus one overflow record).
pub(super) fn save_scan(
    app: &AppHandle,
    case_id: &str,
    scan_id: u64,
    entries: &[ScanEntry],
) -> Result<usize, String> {
    if entries.is_empty() {
        return Ok(0);
    }
    let findings = build_findings(entries, scan_id);
    let context = app.state::<EvidenceCtx>();
    let store = context.store.lock().map_err(|_| "case store unavailable")?;
    let mut count = 0;
    for batch in findings.chunks(128) {
        count += store.add_findings(case_id, "network.tcp", None, batch)?;
    }
    Ok(count)
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

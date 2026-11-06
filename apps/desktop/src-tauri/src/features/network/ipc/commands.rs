//! Network Tauri command handlers and DTO projection.
//! `netscan.rs` retains stable command macro wrappers for existing registration.
use std::sync::atomic::Ordering;

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use std::sync::Arc;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use super::scan_service::ScanTransport;
use super::{
    case_findings, file_export, host_discovery, parse_ports, parse_targets, scan_export, session,
    NetscanStatusWire, ScanCtx, ScanEntry, ScanHistoryItem, ScanProgress, ScanSummaryWire,
};

/// The frontend-provided case ID is a compatibility parameter, not authority.
fn selected_scan_scope(
    selected: &CaseSessionCtx,
    case_id: &str,
) -> Result<CaseSessionWire, String> {
    let scope = selected.selected()?;
    if scope.case_id.as_deref() != Some(case_id) || case_id == "scratchpad" {
        return Err("scan requires the backend-selected saved case and current revision".into());
    }
    Ok(scope)
}

pub(super) fn status(
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> NetscanStatusWire {
    if !ctx.visible_for(&selected) {
        return NetscanStatusWire {
            running: false,
            results: 0,
            saved_findings: 0,
            save_error: None,
        };
    }
    NetscanStatusWire {
        running: ctx.running.load(Ordering::Relaxed),
        results: ctx.results.lock().expect("scan results poisoned").len(),
        saved_findings: ctx.saved_findings.load(Ordering::Relaxed) as usize,
        save_error: ctx
            .last_save_error
            .lock()
            .expect("scan error state poisoned")
            .clone(),
    }
}

pub(super) async fn start(
    targets: String,
    ports: String,
    on_progress: Channel<ScanProgress>,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    evidence: State<'_, EvidenceCtx>,
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, ScanCtx>,
) -> Result<ScanSummaryWire, String> {
    start_for_transport(
        ScanTransport::Tcp,
        targets,
        ports,
        on_progress,
        authorized,
        case_id,
        app,
        evidence,
        selected,
        ctx,
    )
    .await
}

/// Additive, explicitly authorized UDP scan. Legacy netscan_start stays TCP.
pub(super) async fn start_udp(
    targets: String,
    ports: String,
    on_progress: Channel<ScanProgress>,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    evidence: State<'_, EvidenceCtx>,
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, ScanCtx>,
) -> Result<ScanSummaryWire, String> {
    start_for_transport(
        ScanTransport::Udp,
        targets,
        ports,
        on_progress,
        authorized,
        case_id,
        app,
        evidence,
        selected,
        ctx,
    )
    .await
}

async fn start_for_transport(
    transport: ScanTransport,
    targets: String,
    ports: String,
    on_progress: Channel<ScanProgress>,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    evidence: State<'_, EvidenceCtx>,
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, ScanCtx>,
) -> Result<ScanSummaryWire, String> {
    if !authorized {
        return Err("explicit scan authorization acknowledgment required".to_string());
    }
    if app
        .state::<Arc<crate::features::network::ipc::arp_discovery::ArpDiscoveryCtx>>()
        .is_running()
    {
        return Err("an on-link ARP discovery is active; stop it before TCP/UDP scanning".into());
    }
    if app
        .state::<Arc<crate::features::network::ipc::syn_scan::SynScanCtx>>()
        .is_running()
    {
        return Err("a native SYN scan is running; stop it first".into());
    }
    if app
        .state::<Arc<crate::features::network::ipc::icmp_echo::EchoCtx>>()
        .is_running()
    {
        return Err("native ICMP discovery is active; stop it before TCP/UDP scanning".into());
    }
    let scope = selected_scan_scope(&selected, &case_id)?;
    if !evidence
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .case_exists(&case_id)?
    {
        return Err("selected case does not exist".into());
    }
    let hosts = parse_targets(&targets)?;
    let host_count = hosts.len();
    let port_list = parse_ports(&ports)?;
    if transport == ScanTransport::Udp && (host_count > 512 || port_list.len() > 128) {
        return Err("UDP scan limit is 512 targets and 128 ports per run".into());
    }
    let transport_name = if transport == ScanTransport::Udp {
        "UDP datagram"
    } else {
        "TCP connect"
    };
    let uncertainty = if transport == ScanTransport::Udp {
        " UDP silence is inconclusive, not proof of filtering."
    } else {
        ""
    };
    // Run the native Yes/No confirmation off the IPC/UI dispatcher.
    let prompt = format!(
        "Authorize {transport_name} probes of {host_count} parsed hosts and {} ports in this saved case? An uncertain timeout may be retried once (maximum two attempts per host and port). Only test systems you are permitted to assess.{uncertainty}",
        port_list.len(),
    );
    let dialog = app.clone();
    let approved = tokio::task::spawn_blocking(move || {
        dialog
            .dialog()
            .message(prompt)
            .title("Confirm scoped network scan")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "scan confirmation dialog unavailable")?;
    if !approved {
        return Err("scan cancelled by operator".into());
    }
    selected.ensure(&scope)?;
    let permit = app
        .state::<Arc<crate::features::network::ipc::operation_gate::NetworkOperationGate>>()
        .acquire(crate::features::network::ipc::operation_gate::ActiveOperation::TcpUdp)?;
    let worker_app = app.clone();
    let worker_scope = scope.clone();
    let probe_app = app.clone();
    let probe_scope = scope.clone();
    let stop_on_revoke = Arc::clone(&ctx.stop);
    let save_scope = scope.clone();
    let id = session::start_with_transport_guarded(
        &ctx,
        transport,
        scope,
        hosts,
        port_list,
        targets.clone(),
        ports.clone(),
        move |progress| {
            if worker_app
                .state::<CaseSessionCtx>()
                .ensure(&worker_scope)
                .is_err()
            {
                stop_on_revoke.store(true, Ordering::Release);
            } else {
                let _ = on_progress.send(progress);
            }
        },
        move || {
            probe_app
                .state::<CaseSessionCtx>()
                .ensure(&probe_scope)
                .is_ok()
        },
        move |scan_id, entries, observations| {
            case_findings::save_scan(&app, &case_id, &save_scope, scan_id, entries, observations)
        },
        Some(permit),
    )?;
    Ok(ScanSummaryWire {
        id,
        targets,
        ports,
        hosts_scanned: host_count,
        open_ports: 0,
        duration_ms: 0,
        at_ms: session::now_ms(),
    })
}

pub(super) fn results(
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Vec<ScanEntry> {
    if !ctx.visible_for(&selected) {
        return Vec::new();
    }
    ctx.results.lock().expect("scan results poisoned").clone()
}

/// Additive pagination; never transmit all original probe results unchecked.
/// Case authorization is verified both before and after reading the page.
pub(super) fn observation_page(
    offset: usize,
    limit: usize,
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Result<super::scan_wire::ScanObservationPage, String> {
    if !(1..=100).contains(&limit) || offset > 20_000 {
        return Err("scan observation page outside 0..=20000 and limit 1..=100".into());
    }
    let scope = selected.selected()?;
    if !ctx.visible_for(&selected) {
        return Err("no observations authorized for current case revision".into());
    }
    let rows = ctx
        .observations
        .lock()
        .map_err(|_| "observations unavailable")?;
    let page = paginate_scan_observations(&rows, offset, limit)?;
    drop(rows);
    selected.ensure(&scope)?;
    if !ctx.visible_for(&selected) {
        return Err("scan session was revoked during observation read".into());
    }
    Ok(page)
}

fn paginate_scan_observations(
    rows: &[super::ScanObservation],
    offset: usize,
    limit: usize,
) -> Result<super::scan_wire::ScanObservationPage, String> {
    if !(1..=100).contains(&limit) || offset > 20_000 {
        return Err("invalid observation offset or page size".into());
    }
    let total = rows.len();
    let entries = rows
        .get(offset.min(total)..(offset.saturating_add(limit)).min(total))
        .ok_or("observation page invalid")?
        .to_vec();
    let mut page = super::scan_wire::ScanObservationPage {
        offset,
        total,
        shown: entries.len(),
        open: 0,
        closed: 0,
        filtered: 0,
        unreachable: 0,
        inconclusive: 0,
        entries,
    };
    for observation in rows.iter() {
        match observation.state.as_str() {
            "open" => page.open += 1,
            "closed" => page.closed += 1,
            "filtered" => page.filtered += 1,
            "unreachable" => page.unreachable += 1,
            _ => page.inconclusive += 1,
        }
    }
    Ok(page)
}

pub(super) fn stop(ctx: State<'_, ScanCtx>) {
    ctx.stop.store(true, Ordering::Relaxed);
}

pub(super) fn history(
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
) -> Vec<ScanHistoryItem> {
    if !ctx.visible_for(&selected) {
        return Vec::new();
    }
    let memory = ctx.history.lock().expect("scan history poisoned").clone();
    if !memory.is_empty() {
        return memory;
    }
    // Session memory is process-lifetime only. When it is empty (fresh app
    // start, case re-selected) the history rebuilds from the scan findings
    // this case already persisted, so completed scans stay visible across
    // restarts. Hydrated sessions are capped and never re-scan.
    match hydrate_history(&selected, &evidence) {
        Ok(hydrated) if !hydrated.is_empty() => {
            // Keep future in-memory scan ids unique against the restored ones.
            if let Some(max_id) = hydrated.iter().map(|item| item.id).max() {
                ctx.next_id.fetch_max(max_id + 1, Ordering::Relaxed);
            }
            ctx.history
                .lock()
                .expect("scan history poisoned")
                .extend(hydrated);
            ctx.history.lock().expect("scan history poisoned").clone()
        }
        _ => memory,
    }
}

/// Rebuild bounded scan sessions from persisted network findings. Findings
/// carry "Scan #{scan_id}" in their details, so grouping by that number and
/// counting distinct hosts/open states reconstructs the summary lines the
/// in-memory history would have shown. Bounded: latest 64 sessions, at most
/// 2048 findings read per source.
fn hydrate_history(
    selected: &CaseSessionCtx,
    evidence: &EvidenceCtx,
) -> Result<Vec<ScanHistoryItem>, String> {
    let scope = selected.selected()?;
    let Some(case_id) = scope.case_id.clone() else {
        return Ok(Vec::new());
    };
    if case_id == "scratchpad" || case_id.is_empty() {
        return Ok(Vec::new());
    }
    let store = evidence
        .store
        .lock()
        .map_err(|_| "case store unavailable")?;
    let findings = store.list_findings(&case_id)?;
    drop(store);
    let mut sessions: std::collections::BTreeMap<u64, ScanHistoryItem> =
        std::collections::BTreeMap::new();
    let mut hosts_seen: std::collections::HashMap<u64, std::collections::BTreeSet<String>> =
        std::collections::HashMap::new();
    let mut open_ports: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    let mut read = 0usize;
    for finding in findings.iter().rev() {
        if read >= 2048 || sessions.len() >= 64 {
            break;
        }
        if finding.source != "network.tcp" && finding.source != "network.udp" {
            continue;
        }
        let Some(id) = parse_scan_id(&finding.details) else {
            continue;
        };
        read += 1;
        let entry = sessions.entry(id).or_insert_with(|| ScanHistoryItem {
            id,
            targets: "hydrated from case findings".into(),
            ports: if finding.source == "network.udp" {
                "udp"
            } else {
                "tcp"
            }
            .into(),
            hosts_scanned: 0,
            open_ports: 0,
            duration_ms: 0,
            at_ms: finding.created_ms.max(0) as u64,
        });
        // Observation findings: "<PROTO> <STATE> <host>:<port>"
        let mut parts = finding.title.split_whitespace();
        if let (Some(_proto), Some(state), Some(hostport)) =
            (parts.next(), parts.next(), parts.next())
        {
            let seen = hosts_seen.entry(id).or_default();
            if let Some((host, _port)) = hostport.split_once(':') {
                seen.insert(host.to_string());
            }
            if state == "Open" {
                *open_ports.entry(id).or_insert(0) += 1;
            }
            entry.hosts_scanned = seen.len();
            entry.open_ports = open_ports.get(&id).copied().unwrap_or(0);
        }
    }
    let mut hydrated: Vec<ScanHistoryItem> = sessions.into_values().collect();
    hydrated.sort_by(|a, b| b.at_ms.cmp(&a.at_ms));
    Ok(hydrated)
}

pub(super) fn export(
    app: AppHandle,
    format: String,
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Result<String, String> {
    if !ctx.visible_for(&selected) {
        return Err("scan results belong to another selected case revision".into());
    }
    let results = ctx.results.lock().expect("scan results poisoned").clone();
    if results.is_empty() {
        return Err("no results to export".to_string());
    }
    let ext = if format == "csv" { "csv" } else { "json" };
    let picked = app
        .dialog()
        .file()
        .add_filter("Scan export", &[ext])
        .blocking_save_file()
        .ok_or("cancelled")?;
    let path = picked
        .as_path()
        .ok_or("unsupported file location")?
        .to_path_buf();
    let content = scan_export::render_results(&results, &format)?;
    file_export::write_export(&path, &content)?;
    Ok(path.to_string_lossy().to_string())
}

pub(super) async fn discover_hosts(
    targets: String,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, ScanCtx>,
) -> Result<Vec<String>, String> {
    if !authorized {
        return Err("explicit scan authorization acknowledgment required".to_string());
    }
    let scope = selected.selected()?;
    if scope.case_id.as_deref() == Some("scratchpad") {
        return Err("host discovery requires a saved backend-selected case".into());
    }
    let hosts = parse_targets(&targets)?;
    if hosts.len() > host_discovery::MAX_DISCOVERY_HOSTS {
        return Err(format!(
            "host discovery is bounded to {} addresses per run",
            host_discovery::MAX_DISCOVERY_HOSTS
        ));
    }
    let prompt = format!(
        "Authorize bounded TCP reachability probes of {} hosts (maximum 30-second run) in this selected case?",
        hosts.len()
    );
    let dialog = app.clone();
    let approved = tokio::task::spawn_blocking(move || {
        dialog
            .dialog()
            .message(prompt)
            .title("Confirm network discovery")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "host discovery confirmation unavailable")?;
    if !approved {
        return Err("host discovery cancelled by operator".into());
    }
    selected.ensure(&scope)?;
    let permit = app
        .state::<Arc<crate::features::network::ipc::operation_gate::NetworkOperationGate>>()
        .acquire(crate::features::network::ipc::operation_gate::ActiveOperation::TcpDiscovery)?;
    // Worker holds the global permit and verifies backend case revision before
    // each probe. The network loop never blocks Tauri's command dispatcher.
    ctx.stop.store(false, Ordering::Release);
    let stop = Arc::clone(&ctx.stop);
    let worker_app = app.clone();
    let worker_scope = scope.clone();
    let found = tokio::task::spawn_blocking(move || {
        let _active_operation = permit;
        host_discovery::responding_hosts_scoped(hosts, &|| {
            !stop.load(Ordering::Acquire)
                && worker_app
                    .state::<CaseSessionCtx>()
                    .ensure(&worker_scope)
                    .is_ok()
        })
    })
    .await
    .map_err(|_| "host discovery worker unavailable")??;
    selected.ensure(&scope)?;
    Ok(found)
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use cyberdeck_storage::ArtifactStore;
    use std::sync::atomic::Ordering;

    #[test]
    fn paginated_tcp_outcomes_keep_reasons_and_full_state_counts() {
        let sample = |port: u16, state: &str, reason: &str| super::super::ScanObservation {
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
            started_at_ms: 100,
            elapsed_ms: 13,
            attempts: 1,
            retries: 0,
            os_error_code: None,
        };
        let records = vec![
            sample(22, "open", "tcp_connect_accepted"),
            sample(23, "closed", "tcp_connect_refused"),
            sample(24, "inconclusive", "connect_timeout_no_response"),
            sample(25, "unreachable", "host_unreachable"),
        ];
        let page = paginate_scan_observations(&records, 1, 2).unwrap();
        assert_eq!((page.total, page.shown, page.offset), (4, 2, 1));
        assert_eq!(
            (
                page.open,
                page.closed,
                page.inconclusive,
                page.unreachable,
                page.filtered
            ),
            (1, 1, 1, 1, 0)
        );
        assert_eq!(page.entries[0].reason, "tcp_connect_refused");
        assert_eq!(page.entries[1].reason, "connect_timeout_no_response");
        assert!(paginate_scan_observations(&records, 0, 0).is_err());
        assert!(paginate_scan_observations(&records, 0, 101).is_err());
        assert!(paginate_scan_observations(&records, 20_001, 100).is_err());
        assert_eq!(
            paginate_scan_observations(&records, 4, 100).unwrap().shown,
            0
        );
    }

    #[test]
    fn scanner_scope_never_accepts_client_case_or_stale_revision_as_authority() {
        let root = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&root.path().join("cases.sqlite")).unwrap();
        let first = store.create_case("First scan", "").unwrap();
        let second = store.create_case("Second scan", "").unwrap();
        let selected = CaseSessionCtx::default();
        let ctx = ScanCtx::default();
        assert!(selected_scan_scope(&selected, &first.id).is_err());
        let scope = selected.select(&store, &first.id).unwrap();
        assert!(selected_scan_scope(&selected, &second.id).is_err());
        assert_eq!(selected_scan_scope(&selected, &first.id).unwrap(), scope);
        *ctx.active_scope.lock().unwrap() = Some(scope.clone());
        assert!(ctx.visible_for(&selected));
        selected.select(&store, &second.id).unwrap();
        assert!(!ctx.visible_for(&selected));
        assert!(selected_scan_scope(&selected, &first.id).is_err());
        selected.select(&store, &first.id).unwrap();
        assert!(
            !ctx.visible_for(&selected),
            "reselecting same case revokes old scan results"
        );
        ctx.on_case_changed();
        assert!(ctx.stop.load(Ordering::Acquire));
        assert!(ctx.active_scope.lock().unwrap().is_none());
    }
    #[test]
    fn temporary_workspace_is_not_active_scan_authority() {
        let root = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&root.path().join("cases.sqlite")).unwrap();
        let selected = CaseSessionCtx::default();
        selected.select(&store, "scratchpad").unwrap();
        assert!(selected_scan_scope(&selected, "scratchpad").is_err());
    }
}

/// Extract the scan session number from an observation finding's details
/// ("Authorized TCP scan #12\nHost: ..."). Pure so hydration rules are
/// testable without a store.
fn parse_scan_id(details: &str) -> Option<u64> {
    let rest = details.split("Scan #").nth(1)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

#[cfg(test)]
mod history_hydration_tests {
    use super::parse_scan_id;

    #[test]
    fn scan_id_parses_from_observation_details_and_refuses_noise() {
        let details = "Authorized TCP scan #42\nHost: 10.0.0.1\nPort: 443";
        assert_eq!(parse_scan_id(details), Some(42));
        assert_eq!(parse_scan_id("Authorized UDP scan #7: summary"), Some(7));
        assert_eq!(parse_scan_id("no session marker here"), None);
        assert_eq!(parse_scan_id("Scan #"), None);
        // A finding whose first "Scan #" match is not numeric still yields None.
        assert_eq!(parse_scan_id("Scan #abc and later Scan #9"), None);
    }
}

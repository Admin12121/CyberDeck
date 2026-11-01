//! Network Tauri command handlers and DTO projection.
//! `netscan.rs` retains stable command macro wrappers for existing registration.
use std::sync::atomic::Ordering;

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use std::sync::Arc;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

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

pub(super) fn start(
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
    // A frontend acknowledgment alone does not authorize active network probes.
    let approved = app.dialog().message(format!(
        "Authorize TCP connect probes of {host_count} parsed hosts and {} ports in this saved case? Only test systems you are permitted to assess.",
        port_list.len(),
    )).title("Confirm scoped network scan")
        .buttons(MessageDialogButtons::YesNo).blocking_show();
    if !approved {
        return Err("scan cancelled by operator".into());
    }
    selected.ensure(&scope)?;
    let worker_app = app.clone();
    let worker_scope = scope.clone();
    let probe_app = app.clone();
    let probe_scope = scope.clone();
    let stop_on_revoke = Arc::clone(&ctx.stop);
    let save_scope = scope.clone();
    let id = session::start(
        &ctx,
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
) -> Vec<ScanHistoryItem> {
    if !ctx.visible_for(&selected) {
        return Vec::new();
    }
    ctx.history.lock().expect("scan history poisoned").clone()
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

pub(super) fn discover_hosts(
    targets: String,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
) -> Result<Vec<String>, String> {
    if !authorized {
        return Err("explicit scan authorization acknowledgment required".to_string());
    }
    let scope = selected.selected()?;
    if scope.case_id.as_deref() == Some("scratchpad") {
        return Err("host discovery requires a saved backend-selected case".into());
    }
    let hosts = parse_targets(&targets)?;
    let approved = app
        .dialog()
        .message(format!(
            "Authorize TCP reachability probes of {} hosts in the selected case?",
            hosts.len()
        ))
        .title("Confirm network discovery")
        .buttons(MessageDialogButtons::YesNo)
        .blocking_show();
    if !approved {
        return Err("host discovery cancelled by operator".into());
    }
    selected.ensure(&scope)?;
    Ok(host_discovery::responding_hosts(hosts))
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use cyberdeck_storage::ArtifactStore;
    use std::sync::atomic::Ordering;

    #[test]
    fn paginated_tcp_outcomes_keep_reasons_and_full_state_counts() {
        let sample = |port: u16, state: &str, reason: &str| super::super::ScanObservation {
            host: "127.0.0.1".into(), port, protocol: "tcp".into(),
            state: state.into(), reason: reason.into(), method: "tcp_connect".into(),
            service: "unknown".into(), service_basis: "none".into(), banner: String::new(),
            started_at_ms: 100, elapsed_ms: 13, attempts: 1, retries: 0,
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
        assert_eq!((page.open, page.closed, page.inconclusive, page.unreachable, page.filtered), (1, 1, 1, 1, 0));
        assert_eq!(page.entries[0].reason, "tcp_connect_refused");
        assert_eq!(page.entries[1].reason, "connect_timeout_no_response");
        assert!(paginate_scan_observations(&records, 0, 0).is_err());
        assert!(paginate_scan_observations(&records, 0, 101).is_err());
        assert!(paginate_scan_observations(&records, 20_001, 100).is_err());
        assert_eq!(paginate_scan_observations(&records, 4, 100).unwrap().shown, 0);
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

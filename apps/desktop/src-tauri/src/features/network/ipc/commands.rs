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
        move |scan_id, entries| {
            case_findings::save_scan(&app, &case_id, &save_scope, scan_id, entries)
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

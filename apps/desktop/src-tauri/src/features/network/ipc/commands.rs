//! Network Tauri command handlers and DTO projection.
//! `netscan.rs` retains stable command macro wrappers for existing registration.
use std::sync::atomic::Ordering;

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use tauri::ipc::Channel;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use super::{
    case_findings, file_export, host_discovery, parse_ports, parse_targets, scan_export, session,
    NetscanStatusWire, ScanCtx, ScanEntry, ScanHistoryItem, ScanProgress, ScanSummaryWire,
};

pub(super) fn status(ctx: State<'_, ScanCtx>) -> NetscanStatusWire {
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
    ctx: State<'_, ScanCtx>,
) -> Result<ScanSummaryWire, String> {
    if !authorized {
        return Err("explicit scan authorization acknowledgment required".to_string());
    }
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
    let id = session::start(
        &ctx,
        hosts,
        port_list,
        targets.clone(),
        ports.clone(),
        move |progress| {
            let _ = on_progress.send(progress);
        },
        move |scan_id, entries| case_findings::save_scan(&app, &case_id, scan_id, entries),
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

pub(super) fn results(ctx: State<'_, ScanCtx>) -> Vec<ScanEntry> {
    ctx.results.lock().expect("scan results poisoned").clone()
}

pub(super) fn stop(ctx: State<'_, ScanCtx>) {
    ctx.stop.store(true, Ordering::Relaxed);
}

pub(super) fn history(ctx: State<'_, ScanCtx>) -> Vec<ScanHistoryItem> {
    ctx.history.lock().expect("scan history poisoned").clone()
}

pub(super) fn export(
    app: AppHandle,
    format: String,
    ctx: State<'_, ScanCtx>,
) -> Result<String, String> {
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

pub(super) fn discover_hosts(targets: String, authorized: bool) -> Result<Vec<String>, String> {
    if !authorized {
        return Err("explicit scan authorization acknowledgment required".to_string());
    }
    Ok(host_discovery::responding_hosts(parse_targets(&targets)?))
}

//! Native Network scanner IPC: stable Tauri commands and compatibility exports.
//! Pure policies, scan orchestration and adapters live under features/network/.

use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::CaseSessionCtx;
use tauri::ipc::Channel;
use tauri::{AppHandle, State};

#[path = "../infrastructure/case_findings.rs"]
mod case_findings;
#[path = "../infrastructure/file_export.rs"]
mod file_export;
#[path = "../infrastructure/discovery.rs"]
mod host_discovery;
#[path = "../infrastructure/targets.rs"]
mod host_targets;
#[path = "../domain/ports.rs"]
mod port_rules;
#[path = "commands.rs"]
mod scan_commands;
#[path = "../application/export.rs"]
mod scan_export;
#[path = "../domain/models.rs"]
mod scan_models;
#[path = "../application/scanner.rs"]
mod scan_service;
#[path = "../application/state.rs"]
mod scan_state;
#[path = "scan_wire.rs"]
mod scan_wire;
#[path = "../application/session.rs"]
mod session;
#[path = "../infrastructure/probe.rs"]
mod tcp_probe;
#[path = "../infrastructure/udp_probe.rs"]
mod udp_probe;

pub use host_targets::parse_targets;
pub use port_rules::{parse_ports, TOP_PORTS_100};
pub use scan_models::{ScanEntry, ScanHistoryItem, ScanObservation, ScanProgress};
#[cfg(test)]
use scan_service::scan_probe_count;
pub use scan_state::ScanCtx;
pub use scan_wire::{NetscanStatusWire, ScanObservationPage, ScanSummaryWire};
#[cfg(test)]
use tcp_probe::{classify_connect_error, summarize_banner};

/// Retained for existing internal Rust consumers.
pub fn run_scan(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    stop: &std::sync::atomic::AtomicBool,
    on_progress: &Channel<ScanProgress>,
) -> Vec<ScanEntry> {
    let results = Arc::new(StdMutex::new(Vec::new()));
    scan_service::run_scan_into(
        hosts,
        ports,
        stop,
        &|progress| {
            let _ = on_progress.send(progress);
        },
        &results,
    )
}

#[tauri::command]
pub fn netscan_status(
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> NetscanStatusWire {
    scan_commands::status(ctx, selected)
}

#[tauri::command]
pub fn netscan_start(
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
    scan_commands::start(
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
}

/// Additive UDP method: user-mode connected datagrams with conservative
/// response evidence; the original seven netscan_* calls remain unchanged.
#[tauri::command]
pub fn netscan_udp_start_v1(
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
    scan_commands::start_udp(
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
}

#[tauri::command]
pub fn netscan_results(
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Vec<ScanEntry> {
    scan_commands::results(ctx, selected)
}

#[tauri::command]
pub fn netscan_observations_v1(
    offset: usize,
    limit: usize,
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Result<ScanObservationPage, String> {
    scan_commands::observation_page(offset, limit, ctx, selected)
}

#[tauri::command]
pub fn netscan_stop(ctx: State<'_, ScanCtx>) {
    scan_commands::stop(ctx)
}

#[tauri::command]
pub fn netscan_history(
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Vec<ScanHistoryItem> {
    scan_commands::history(ctx, selected)
}

#[tauri::command]
pub fn netscan_export(
    app: AppHandle,
    format: String,
    ctx: State<'_, ScanCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Result<String, String> {
    scan_commands::export(app, format, ctx, selected)
}

#[tauri::command]
pub fn netscan_discover_hosts(
    targets: String,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
) -> Result<Vec<String>, String> {
    scan_commands::discover_hosts(targets, authorized, app, selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidr_and_single_hosts() {
        assert_eq!(parse_targets("127.0.0.1").unwrap().len(), 1);
        assert_eq!(parse_targets("192.168.1.0/30").unwrap().len(), 4);
    }

    #[test]
    fn cidr_cap_enforced() {
        assert!(parse_targets("10.0.0.0/8").is_err());
    }

    #[test]
    fn preset_port_counts_are_truthful_and_unique() {
        assert_eq!(TOP_PORTS_100.len(), 100);
        let unique = TOP_PORTS_100
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), 100);
        assert_eq!(parse_ports("top25").unwrap().len(), 25);
        assert_eq!(parse_ports("top100").unwrap().len(), 100);
    }

    #[test]
    fn ipv4_slash_zero_is_a_bounded_error_not_a_shift_panic() {
        assert!(parse_targets("192.0.2.1/0").is_err());
    }

    #[test]
    fn connect_error_states_are_distinct() {
        use std::io::ErrorKind;
        assert_eq!(
            classify_connect_error(ErrorKind::ConnectionRefused),
            "closed"
        );
        assert_eq!(classify_connect_error(ErrorKind::TimedOut), "no-response");
        assert_eq!(
            classify_connect_error(ErrorKind::NetworkUnreachable),
            "unreachable"
        );
    }

    #[test]
    fn parses_port_specs() {
        assert_eq!(parse_ports("top25").unwrap().len(), 25);
        let ports = parse_ports("80,443,8000-8002").unwrap();
        assert_eq!(ports, vec![80, 443, 8000, 8001, 8002]);
        assert!(parse_ports("9000-99999").is_err());
    }

    #[test]
    fn scan_probe_budget_rejects_excessive_work_without_allocating_jobs() {
        assert_eq!(scan_probe_count(2, 100).unwrap(), 200);
        assert!(scan_probe_count(4096, 1024).is_err());
        assert_eq!(scan_probe_count(0, 0).unwrap(), 0);
    }

    #[test]
    fn repeated_host_targets_are_deduplicated() {
        let targets = parse_targets("127.0.0.1,127.0.0.1,127.0.0.2").unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn banner_summary_pulls_server_header() {
        let raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\nbody";
        assert!(summarize_banner(raw).contains("nginx"));
    }

    #[test]
    fn banner_summary_keeps_first_line_for_non_http() {
        assert_eq!(
            summarize_banner("SSH-2.0-OpenSSH_9.6\r\n"),
            "SSH-2.0-OpenSSH_9.6"
        );
    }
}

//! Additive operator-confirmed, saved-case-scoped native IPv4 SYN scanner.
//! Raw Linux socket permissions are mandatory; no external Nmap executable.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::active_syn::{scan_ipv4_syn, SynState, MAX_SYN_HOSTS, MAX_SYN_PORTS};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use super::netscan::{ScanCtx, ScanProgress};

#[derive(Default)]
pub struct SynScanCtx {
    running: AtomicBool,
    stop: AtomicBool,
    owner: Mutex<Option<CaseSessionWire>>,
}
impl SynScanCtx {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }
}
struct SynRunGuard(Arc<SynScanCtx>);
impl Drop for SynRunGuard {
    fn drop(&mut self) {
        // Clear ownership before publishing idle: a newly started operation
        // must never have its scope erased by a previous worker's destructor.
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SynFindingWire {
    host: String,
    port: u16,
    state: &'static str,
    reason: &'static str,
    elapsed_ms: u64,
}
fn scoped_case(ctx: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = ctx.selected()?;
    let id = scope
        .case_id
        .clone()
        .ok_or("saved case selection required")?;
    if id == "scratchpad" || id.is_empty() {
        return Err("native SYN scans require a saved selected case".into());
    }
    Ok((scope, id))
}

#[tauri::command]
pub async fn netscan_syn_start_v1(
    targets: String,
    ports: String,
    interface_name: String,
    authorized: bool,
    on_progress: Channel<ScanProgress>,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    tcp: State<'_, ScanCtx>,
    arp: State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
    ctx: State<'_, Arc<SynScanCtx>>,
) -> Result<Vec<SynFindingWire>, String> {
    if !authorized {
        return Err("explicit network scan authorization acknowledgment required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            targets,
            ports,
            interface_name,
            on_progress,
            app,
            session,
            evidence,
            tcp,
            arp,
            ctx,
        );
        return Err("native raw IPv4 SYN currently requires Linux CAP_NET_RAW".into());
    }
    #[cfg(target_os = "linux")]
    {
        let (scope, case_id) = scoped_case(&session)?;
        if tcp.running.load(Ordering::Acquire)
            || arp.is_running()
            || app.state::<Arc<super::icmp_echo::EchoCtx>>().is_running()
        {
            return Err("stop other active network scans before starting raw SYN".into());
        }
        let target_list = super::netscan::parse_targets(&targets)?;
        let port_list = super::netscan::parse_ports(&ports)?;
        if target_list.is_empty()
            || target_list.len() > MAX_SYN_HOSTS
            || port_list.is_empty()
            || port_list.len() > MAX_SYN_PORTS
            || target_list.len().saturating_mul(port_list.len()) > 2048
        {
            return Err("native SYN scanner limits: <=32 hosts, <=128 ports, <=2048 probes".into());
        }
        let hosts: Vec<Ipv4Addr> = target_list
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V4(address) => Ok(address),
                IpAddr::V6(_) => {
                    Err("IPv6 SYN live backend not yet available; select IPv4 targets".into())
                }
            })
            .collect::<Result<_, String>>()?;
        {
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            if !store.case_exists(&case_id)? {
                return Err("selected saved case does not exist".into());
            }
        }
        let prompt=format!(
            "Authorize native Linux raw TCP SYN scan on interface '{}' of {} IPv4 hosts and {} ports (max 2048 probes), in saved case '{}'? No stealth or anonymity guarantees. OS CAP_NET_RAW is required; each response is matched to a single backend-generated source port and sequence. Only assess systems you are authorized to test.",
            interface_name,hosts.len(),port_list.len(),case_id
        );
        let dialog = app.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            dialog
                .dialog()
                .message(prompt)
                .title("Confirm native raw SYN scan")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "native scan confirmation failed")?;
        if !accepted {
            return Err("SYN scan declined by operator".into());
        }
        session.ensure(&scope)?;
        if tcp.running.load(Ordering::Acquire)
            || arp.is_running()
            || app.state::<Arc<super::icmp_echo::EchoCtx>>().is_running()
        {
            return Err("another scan became active during native confirmation".into());
        }
        let shared = Arc::clone(&*ctx);
        if shared.running.swap(true, Ordering::AcqRel) {
            return Err("native raw SYN scan is already running".into());
        }
        shared.stop.store(false, Ordering::Release);
        {
            let mut owner = match shared.owner.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    shared.running.store(false, Ordering::Release);
                    return Err("native scan registry unavailable".into());
                }
            };
            *owner = Some(scope.clone());
        }
        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let worker_device = interface_name.clone();
        let worker = Arc::clone(&shared);
        let matches = tokio::task::spawn_blocking(move || {
            let _guard = SynRunGuard(Arc::clone(&worker));
            scan_ipv4_syn(
                &worker_device,
                &hosts,
                &port_list,
                &worker.stop,
                &|| {
                    worker_app
                        .state::<CaseSessionCtx>()
                        .ensure(&worker_scope)
                        .is_ok()
                },
                &|tried, total| {
                    if worker_app
                        .state::<CaseSessionCtx>()
                        .ensure(&worker_scope)
                        .is_ok()
                    {
                        let _ = on_progress.send(ScanProgress {
                            tried: tried as u64,
                            total: total as u64,
                            percent: if total == 0 {
                                0
                            } else {
                                ((tried * 100) / total) as u32
                            },
                        });
                    }
                },
            )
            .map_err(|e| format!("{:?}: {}", e.code, e.message))
        })
        .await
        .map_err(|_| "native SYN worker unavailable")??;
        session.ensure(&scope)?;
        let rows: Vec<SynFindingWire> = matches
            .into_iter()
            .map(|entry| SynFindingWire {
                host: entry.host.to_string(),
                port: entry.port,
                state: match entry.state {
                    SynState::Open => "open",
                    SynState::Closed => "closed",
                    SynState::Unreachable => "unreachable",
                    SynState::Inconclusive => "inconclusive",
                },
                reason: entry.reason,
                elapsed_ms: entry.elapsed_ms,
            })
            .collect();
        if !rows.is_empty() {
            let findings:Vec<NewFinding>=rows.iter().take(256).map(|entry|NewFinding {
                title:format!("TCP SYN {} {}:{}",entry.state,entry.host,entry.port),
                severity:"info".into(),
                details:format!(
                    "Authorized native TCP SYN scan\nInterface: {}\nHost: {}\nPort: {}\nState: {}\nReason: {}\nElapsed milliseconds: {}\nEvidence: matching TCP SYN-ACK/RST or scoped ICMP response; silence remains inconclusive, not filtered",
                    interface_name,entry.host,entry.port,entry.state,entry.reason,entry.elapsed_ms,
                ),
            }).collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            session.with_current_publication(&scope, || {
                store.add_findings(&case_id, "network.syn", None, &findings)
            })?;
        }
        session.ensure(&scope)?;
        Ok(rows)
    }
}
#[tauri::command]
pub fn netscan_syn_stop_v1(
    session: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<SynScanCtx>>,
) -> Result<bool, String> {
    let (scope, _) = scoped_case(&session)?;
    let owner = ctx.owner.lock().map_err(|_| "SYN scan owner unavailable")?;
    if owner.as_ref() != Some(&scope) {
        return Err("SYN scan belongs to another case revision".into());
    }
    ctx.stop.store(true, Ordering::Release);
    Ok(true)
}
#[tauri::command]
pub fn netscan_syn_status_v1(
    session: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<SynScanCtx>>,
) -> Result<bool, String> {
    let (scope, _) = scoped_case(&session)?;
    let owner = ctx.owner.lock().map_err(|_| "SYN scan owner unavailable")?;
    Ok(owner.as_ref() == Some(&scope) && ctx.is_running())
}

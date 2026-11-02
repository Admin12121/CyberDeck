//! Additive, case-authorized native Linux ARP discovery IPC.
//! Does not alter legacy TCP/UDP scanner signatures or require a second tool.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::active_arp::{discover_on_link_arp, MAX_ARP_TARGETS};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use super::netscan::ScanCtx;

#[derive(Default)]
pub struct ArpDiscoveryCtx {
    running: AtomicBool,
    stop: AtomicBool,
    owner: Mutex<Option<CaseSessionWire>>,
}

impl ArpDiscoveryCtx {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    /// Optional immediate case-change hook. Scope checks in the native worker
    /// remain authoritative even when a caller cannot invoke this hook.
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

struct RunGuard(Arc<ArpDiscoveryCtx>);
impl Drop for RunGuard {
    fn drop(&mut self) {
        // Clear ownership before publishing idle: a newly started operation
        // must never have its scope erased by a previous worker's destructor.
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ArpNeighborWire {
    pub host: String,
    pub mac: String,
    pub elapsed_ms: u64,
}

fn saved_scope(selected: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = selected.selected()?;
    let case_id = scope
        .case_id
        .clone()
        .ok_or("a saved case must be selected")?;
    if case_id == "scratchpad" || case_id.trim().is_empty() {
        return Err("ARP discovery requires a saved, backend-selected case".into());
    }
    Ok((scope, case_id))
}

/// Explicit interface, bounded on-link target set, backend case revision,
/// native confirmation and OS raw socket privileges are all required.
#[tauri::command]
pub async fn netscan_arp_discover_v1(
    targets: String,
    interface_name: String,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    scanner: State<'_, ScanCtx>,
    syn: State<'_, Arc<super::syn_scan::SynScanCtx>>,
    ctx: State<'_, Arc<ArpDiscoveryCtx>>,
) -> Result<Vec<ArpNeighborWire>, String> {
    if !authorized {
        return Err("explicit ARP discovery authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            targets,
            interface_name,
            app,
            selected,
            evidence,
            scanner,
            syn,
            ctx,
        );
        return Err("native ARP discovery is currently supported only on Linux".into());
    }
    #[cfg(target_os = "linux")]
    {
        let (scope, case_id) = saved_scope(&selected)?;
        if scanner.running.load(Ordering::Acquire)
            || syn.is_running()
            || app.state::<Arc<super::icmp_echo::EchoCtx>>().is_running()
        {
            return Err("stop the active TCP/UDP scan before starting ARP discovery".into());
        }
        let targets = super::netscan::parse_targets(&targets)?;
        if targets.is_empty() || targets.len() > MAX_ARP_TARGETS {
            return Err(format!(
                "ARP discovery accepts 1..={MAX_ARP_TARGETS} target IPs"
            ));
        }
        let hosts: Vec<Ipv4Addr> = targets
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => Ok(v4),
                IpAddr::V6(_) => Err("IPv6 requires Neighbor Discovery, not ARP".to_string()),
            })
            .collect::<Result<_, _>>()?;
        if !evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?
            .case_exists(&case_id)?
        {
            return Err("selected case does not exist".into());
        }

        // Backend confirmation is independent of the frontend checkbox.
        let question = format!(
            "Send a maximum of {} ARP requests on Linux Ethernet interface '{}' to verified on-link IPv4 targets, in saved case '{}'? At most 10 probes/s, no retries, 500ms response deadline per host. Requires CAP_NET_RAW and permission to test this network.",
            hosts.len(), interface_name, case_id,
        );
        let dialog_app = app.clone();
        let agreed = tokio::task::spawn_blocking(move || {
            dialog_app
                .dialog()
                .message(question)
                .title("Authorize native on-link ARP discovery")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "native ARP confirmation unavailable")?;
        if !agreed {
            return Err("ARP discovery cancelled by operator".into());
        }
        selected.ensure(&scope)?;
        if scanner.running.load(Ordering::Acquire)
            || syn.is_running()
            || app.state::<Arc<super::icmp_echo::EchoCtx>>().is_running()
        {
            return Err("the TCP/UDP scanner became active while confirming ARP discovery".into());
        }
        let permit = app
            .state::<Arc<super::operation_gate::NetworkOperationGate>>()
            .acquire(super::operation_gate::ActiveOperation::LinkNeighbor)?;
        let state = Arc::clone(&*ctx);
        if state.running.swap(true, Ordering::AcqRel) {
            return Err("an ARP discovery operation is already active".into());
        }
        state.stop.store(false, Ordering::Release);
        if let Ok(mut owner) = state.owner.lock() {
            *owner = Some(scope.clone());
        } else {
            state.running.store(false, Ordering::Release);
            return Err("ARP operation owner registry unavailable".into());
        }
        let run_app = app.clone();
        let run_scope = scope.clone();
        let native_iface = interface_name.clone();
        let native_ctx = Arc::clone(&state);
        let found = tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = RunGuard(Arc::clone(&native_ctx));
            discover_on_link_arp(&native_iface, &hosts, &native_ctx.stop, &|| {
                run_app.state::<CaseSessionCtx>().ensure(&run_scope).is_ok()
            })
            .map_err(|err| format!("{:?}: {}", err.code, err.message))
        })
        .await
        .map_err(|_| "native ARP discovery worker unavailable")??;
        selected.ensure(&scope)?;

        let rows: Vec<ArpNeighborWire> = found
            .into_iter()
            .map(|entry| ArpNeighborWire {
                host: entry.address.to_string(),
                mac: entry
                    .mac
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                elapsed_ms: entry.elapsed_ms,
            })
            .collect();
        if !rows.is_empty() {
            let findings: Vec<NewFinding> = rows.iter().map(|item| NewFinding {
                title: format!("ARP on-link host {}", item.host),
                severity: "info".into(),
                details: format!(
                    "Authorized native ARP discovery\nInterface: {}\nTarget: {}\nObserved responder MAC: {}\nResponse latency ms: {}\nEvidence: correlated Ethernet ARP reply; not cryptographic host authentication",
                    interface_name, item.host, item.mac, item.elapsed_ms
                ),
            }).collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            selected.with_current_publication(&scope, || {
                store.add_findings(&case_id, "network.arp", None, &findings)
            })?;
        }
        selected.ensure(&scope)?;
        Ok(rows)
    }
}

/// Stop only the operation owned by the currently selected case revision.
/// Cancellation is checked before every raw send and during <=50ms receive polls.
#[tauri::command]
pub fn netscan_arp_stop_v1(
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<ArpDiscoveryCtx>>,
) -> Result<bool, String> {
    let (scope, _) = saved_scope(&selected)?;
    let owner = ctx
        .owner
        .lock()
        .map_err(|_| "ARP operation owner unavailable")?;
    if owner.as_ref() != Some(&scope) {
        return Err("ARP operation does not belong to the selected case revision".into());
    }
    ctx.stop.store(true, Ordering::Release);
    Ok(true)
}

#[tauri::command]
pub fn netscan_arp_status_v1(
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<ArpDiscoveryCtx>>,
) -> Result<bool, String> {
    let (scope, _) = saved_scope(&selected)?;
    let owner = ctx
        .owner
        .lock()
        .map_err(|_| "ARP operation owner unavailable")?;
    Ok(owner.as_ref() == Some(&scope) && ctx.running.load(Ordering::Acquire))
}

/// Linux-only IPv6 Neighbor Solicitation. Reuses the same backend-owned
/// link-discovery operation slot as ARP so IPv4/IPv6 link probes cannot overlap.
#[tauri::command]
pub async fn netscan_ndp_discover_v1(
    targets: String,
    interface_name: String,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    scanner: State<'_, ScanCtx>,
    syn: State<'_, Arc<super::syn_scan::SynScanCtx>>,
    ctx: State<'_, Arc<ArpDiscoveryCtx>>,
) -> Result<Vec<ArpNeighborWire>, String> {
    if !authorized {
        return Err("explicit IPv6 Neighbor Discovery authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            targets,
            interface_name,
            app,
            selected,
            evidence,
            scanner,
            syn,
            ctx,
        );
        return Err("native IPv6 Neighbor Discovery currently requires Linux CAP_NET_RAW".into());
    }
    #[cfg(target_os = "linux")]
    {
        use cyberdeck_packet::active_ndp::{discover_ndp, MAX_NDP_TARGETS};
        use std::net::Ipv6Addr;
        let (scope, case_id) = saved_scope(&selected)?;
        if scanner.running.load(Ordering::Acquire)
            || syn.is_running()
            || app.state::<Arc<super::icmp_echo::EchoCtx>>().is_running()
        {
            return Err("stop the active scan before IPv6 Neighbor Discovery".into());
        }
        let parsed = super::netscan::parse_targets(&targets)?;
        if parsed.is_empty() || parsed.len() > MAX_NDP_TARGETS {
            return Err(format!(
                "IPv6 Neighbor Discovery accepts 1..={MAX_NDP_TARGETS} targets"
            ));
        }
        let hosts: Vec<Ipv6Addr> = parsed
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V6(v6) if v6.is_unicast_link_local() => Ok(v6),
                IpAddr::V6(_) => Err(
                    "IPv6 Neighbor Discovery only permits link-local fe80::/10 addresses"
                        .to_string(),
                ),
                IpAddr::V4(_) => {
                    Err("IPv4 targets require ARP, not IPv6 Neighbor Discovery".to_string())
                }
            })
            .collect::<Result<_, _>>()?;
        {
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            if !store.case_exists(&case_id)? {
                return Err("selected case does not exist".into());
            }
        }
        let prompt = format!(
            "Authorize up to {} IPv6 Neighbor Solicitations on selected Ethernet interface '{}' in saved case '{}'? Only link-local IPv6 targets, at most 10/s, no retries, max 600ms/host, requiring Linux CAP_NET_RAW. Scan only systems on a network you are authorized to assess.",
            hosts.len(), interface_name, case_id
        );
        let dialog = app.clone();
        let confirmed = tokio::task::spawn_blocking(move || {
            dialog
                .dialog()
                .message(prompt)
                .title("Confirm native IPv6 Neighbor Discovery")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "native IPv6 neighbor confirmation unavailable")?;
        if !confirmed {
            return Err("IPv6 Neighbor Discovery declined".into());
        }
        selected.ensure(&scope)?;
        if scanner.running.load(Ordering::Acquire)
            || syn.is_running()
            || app.state::<Arc<super::icmp_echo::EchoCtx>>().is_running()
        {
            return Err("another network scan became active during confirmation".into());
        }
        let permit = app
            .state::<Arc<super::operation_gate::NetworkOperationGate>>()
            .acquire(super::operation_gate::ActiveOperation::LinkNeighbor)?;
        let shared = Arc::clone(&*ctx);
        if shared.running.swap(true, Ordering::AcqRel) {
            return Err("a native link discovery operation is already running".into());
        }
        shared.stop.store(false, Ordering::Release);
        if let Ok(mut owner) = shared.owner.lock() {
            *owner = Some(scope.clone());
        } else {
            shared.running.store(false, Ordering::Release);
            return Err("link discovery owner registry unavailable".into());
        }
        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let worker_device = interface_name.clone();
        let worker = Arc::clone(&shared);
        let found = tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = RunGuard(Arc::clone(&worker));
            discover_ndp(&worker_device, &hosts, &worker.stop, &|| {
                worker_app
                    .state::<CaseSessionCtx>()
                    .ensure(&worker_scope)
                    .is_ok()
            })
            .map_err(|e| format!("{:?}: {}", e.code, e.message))
        })
        .await
        .map_err(|_| "native IPv6 Neighbor Discovery worker unavailable")??;
        selected.ensure(&scope)?;
        let rows: Vec<ArpNeighborWire> = found
            .into_iter()
            .map(|entry| ArpNeighborWire {
                host: entry.address.to_string(),
                mac: entry
                    .mac
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                elapsed_ms: entry.elapsed_ms,
            })
            .collect();
        if !rows.is_empty() {
            let findings: Vec<NewFinding> = rows.iter().map(|entry| NewFinding {
                title: format!("NDP on-link IPv6 host {}", entry.host),
                severity: "info".into(),
                details: format!(
                    "Authorized native IPv6 Neighbor Discovery\nInterface: {}\nTarget: {}\nObserved link-layer MAC: {}\nResponse latency ms: {}\nEvidence: matched ICMPv6 Neighbor Advertisement (hop limit 255, target, MAC, and checksum); not cryptographic authentication",
                    interface_name, entry.host, entry.mac, entry.elapsed_ms,
                ),
            }).collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            selected.with_current_publication(&scope, || {
                store.add_findings(&case_id, "network.ndp", None, &findings)
            })?;
        }
        selected.ensure(&scope)?;
        Ok(rows)
    }
}

/// Both IPv4 ARP and IPv6 NDP use one backend-owned native link-discovery
/// slot. A stop issued for the currently selected scope cancels either one.
#[tauri::command]
pub fn netscan_ndp_stop_v1(
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<ArpDiscoveryCtx>>,
) -> Result<bool, String> {
    netscan_arp_stop_v1(selected, ctx)
}

#[tauri::command]
pub fn netscan_ndp_status_v1(
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<ArpDiscoveryCtx>>,
) -> Result<bool, String> {
    netscan_arp_status_v1(selected, ctx)
}

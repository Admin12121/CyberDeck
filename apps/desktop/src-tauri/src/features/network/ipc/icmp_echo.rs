//! Saved-case scoped Linux native ICMPv4 echo discovery. No shell utilities,
//! implicit privilege escalation or client-defined case authority.
use super::netscan::ScanCtx;
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::active_echo::{discover_ipv4_echo, EchoState, MAX_ECHO_HOSTS};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

#[derive(Default)]
pub struct EchoCtx {
    running: AtomicBool,
    stop: AtomicBool,
    owner: Mutex<Option<CaseSessionWire>>,
}
impl EchoCtx {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }
}
struct RunGuard(Arc<EchoCtx>);
impl Drop for RunGuard {
    fn drop(&mut self) {
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct EchoObservationWire {
    pub host: String,
    pub state: &'static str,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}
fn saved_scope(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let case = scope.case_id.clone().ok_or("select a saved case first")?;
    if case == "scratchpad" || case.is_empty() {
        return Err("native ICMPv4 requires a saved backend-selected case".into());
    }
    Ok((scope, case))
}
#[tauri::command]
pub async fn netscan_icmp_discover_v1(
    targets: String,
    interface_name: String,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    scanner: State<'_, ScanCtx>,
    arp: State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
    syn: State<'_, Arc<super::syn_scan::SynScanCtx>>,
    ctx: State<'_, Arc<EchoCtx>>,
) -> Result<Vec<EchoObservationWire>, String> {
    if !authorized {
        return Err("explicit ICMPv4 authorization acknowledgment required".into());
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
            arp,
            syn,
            ctx,
        );
        return Err("native ICMPv4 discovery requires Linux CAP_NET_RAW".into());
    }
    #[cfg(target_os = "linux")]
    {
        let (scope, case) = saved_scope(&selected)?;
        if scanner.running.load(Ordering::Acquire) || arp.is_running() || syn.is_running() {
            return Err("another active network probe operation is running".into());
        }
        let parsed = super::netscan::parse_targets(&targets)?;
        if parsed.is_empty() || parsed.len() > MAX_ECHO_HOSTS {
            return Err(format!(
                "ICMP echo requires 1..={MAX_ECHO_HOSTS} IPv4 hosts"
            ));
        }
        let hosts: Vec<Ipv4Addr> = parsed
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => Ok(v4),
                IpAddr::V6(_) => {
                    Err("this native ICMP echo command supports IPv4 only".to_string())
                }
            })
            .collect::<Result<_, _>>()?;
        let exists = evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?
            .case_exists(&case)?;
        if !exists {
            return Err("selected saved case does not exist".into());
        }
        let message = format!(
            "Authorize up to {} native ICMPv4 echo requests on Ethernet interface '{}' in case '{}'? The backend uses its actual interface source address and random echo IDs, at most 20 probes/s, no retries, 600ms per host. Linux CAP_NET_RAW and permission to assess this network are required.",
            hosts.len(), interface_name, case
        );
        let dialog = app.clone();
        let confirmed = tokio::task::spawn_blocking(move || {
            dialog
                .dialog()
                .message(message)
                .title("Confirm native ICMPv4 discovery")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "native ICMP confirmation unavailable")?;
        if !confirmed {
            return Err("ICMP discovery declined".into());
        }
        selected.ensure(&scope)?;
        if scanner.running.load(Ordering::Acquire) || arp.is_running() || syn.is_running() {
            return Err("another scan started during ICMP confirmation".into());
        }
        let permit = app
            .state::<Arc<super::operation_gate::NetworkOperationGate>>()
            .acquire(super::operation_gate::ActiveOperation::IcmpEcho)?;
        let state = Arc::clone(&*ctx);
        if state.running.swap(true, Ordering::AcqRel) {
            return Err("ICMP discovery already running".into());
        }
        state.stop.store(false, Ordering::Release);
        if let Ok(mut owner) = state.owner.lock() {
            *owner = Some(scope.clone());
        } else {
            state.running.store(false, Ordering::Release);
            return Err("ICMP owner registry unavailable".into());
        }
        let app_for_worker = app.clone();
        let scope_for_worker = scope.clone();
        let device = interface_name.clone();
        let state_for_worker = Arc::clone(&state);
        let observations = tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = RunGuard(Arc::clone(&state_for_worker));
            discover_ipv4_echo(&device, &hosts, &state_for_worker.stop, &|| {
                app_for_worker
                    .state::<CaseSessionCtx>()
                    .ensure(&scope_for_worker)
                    .is_ok()
            })
            .map_err(|error| format!("{:?}: {}", error.code, error.message))
        })
        .await
        .map_err(|_| "ICMP discovery worker unavailable")??;
        selected.ensure(&scope)?;
        let rows: Vec<EchoObservationWire> = observations
            .into_iter()
            .map(|result| EchoObservationWire {
                host: result.target.to_string(),
                state: match result.state {
                    EchoState::Responded => "responded",
                    EchoState::Unreachable => "unreachable",
                    EchoState::Inconclusive => "inconclusive",
                },
                reason: result.reason,
                elapsed_ms: result.elapsed_ms,
            })
            .collect();
        if !rows.is_empty() {
            let findings: Vec<NewFinding> = rows.iter().map(|row| NewFinding {
                title: format!("ICMPv4 {} {}", row.state, row.host),
                severity: "info".into(),
                details: format!(
                    "Authorized native ICMPv4 echo discovery\nInterface: {}\nHost: {}\nState: {}\nReason: {}\nElapsed ms: {}\nEvidence: matched echo ID/sequence or scoped quoted network error. Silence remains inconclusive.",
                    interface_name, row.host, row.state, row.reason, row.elapsed_ms
                ),
            }).collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            selected.with_current_publication(&scope, || {
                store.add_findings(&case, "network.icmp", None, &findings)
            })?;
        }
        selected.ensure(&scope)?;
        Ok(rows)
    }
}
#[tauri::command]
pub fn netscan_icmp_stop_v1(
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<EchoCtx>>,
) -> Result<bool, String> {
    let (scope, _) = saved_scope(&selected)?;
    let owner = ctx
        .owner
        .lock()
        .map_err(|_| "ICMP owner registry unavailable")?;
    if owner.as_ref() != Some(&scope) {
        return Err("ICMP operation belongs to another case revision".into());
    }
    ctx.stop.store(true, Ordering::Release);
    Ok(true)
}
#[tauri::command]
pub fn netscan_icmp_status_v1(
    selected: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<EchoCtx>>,
) -> Result<bool, String> {
    let (scope, _) = saved_scope(&selected)?;
    let owner = ctx
        .owner
        .lock()
        .map_err(|_| "ICMP owner registry unavailable")?;
    Ok(owner.as_ref() == Some(&scope) && ctx.is_running())
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceHopWire {
    pub ttl: u8,
    pub responder: Option<String>,
    pub reached: bool,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}

/// Scoped, operator-confirmed IPv4 ICMP traceroute. Reuses the ICMP job and
/// stop command, and the global exclusive Network operation permit.
#[tauri::command]
pub async fn netscan_trace_ipv4_v1(
    target: String,
    interface_name: String,
    max_hops: u8,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    scanner: State<'_, ScanCtx>,
    arp: State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
    syn: State<'_, Arc<super::syn_scan::SynScanCtx>>,
    ctx: State<'_, Arc<EchoCtx>>,
) -> Result<Vec<TraceHopWire>, String> {
    if !authorized {
        return Err("explicit route-tracing authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            target,
            interface_name,
            max_hops,
            app,
            selected,
            evidence,
            scanner,
            arp,
            syn,
            ctx,
        );
        return Err("native IPv4 traceroute currently requires Linux CAP_NET_RAW".into());
    }
    #[cfg(target_os = "linux")]
    {
        use cyberdeck_packet::active_echo::{trace_ipv4_echo, MAX_TRACE_HOPS};
        if max_hops == 0 || max_hops > MAX_TRACE_HOPS {
            return Err("traceroute max_hops must be between 1 and 16".into());
        }
        let (scope, case) = saved_scope(&selected)?;
        if scanner.running.load(Ordering::Acquire) || arp.is_running() || syn.is_running() {
            return Err("stop other Network operations before route tracing".into());
        }
        let parsed = super::netscan::parse_targets(&target)?;
        let [IpAddr::V4(host)] = parsed.as_slice() else {
            return Err("traceroute requires exactly one IPv4 unicast target".into());
        };
        let host = *host;
        if host.is_multicast() || host.is_unspecified() || host.is_broadcast() {
            return Err("traceroute requires a unicast IPv4 target".into());
        }
        if !evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?
            .case_exists(&case)?
        {
            return Err("saved case does not exist".into());
        }
        let prompt=format!(
            "Authorize native IPv4 route tracing to {} using selected interface '{}' in saved case '{}'? At most {} TTL-limited ICMP probes, 600ms each, no retries. Router responses may be absent or altered; all active probes require permission and Linux CAP_NET_RAW.",
            host,interface_name,case,max_hops
        );
        let dialog = app.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            dialog
                .dialog()
                .message(prompt)
                .title("Confirm native IPv4 route trace")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "route trace confirmation unavailable")?;
        if !accepted {
            return Err("route tracing declined".into());
        }
        selected.ensure(&scope)?;
        if scanner.running.load(Ordering::Acquire) || arp.is_running() || syn.is_running() {
            return Err("another scan became active during route trace confirmation".into());
        }
        let permit = app
            .state::<Arc<super::operation_gate::NetworkOperationGate>>()
            .acquire(super::operation_gate::ActiveOperation::IcmpEcho)?;
        let state = Arc::clone(&*ctx);
        if state.running.swap(true, Ordering::AcqRel) {
            return Err("an ICMP Echo or route trace is already active".into());
        }
        state.stop.store(false, Ordering::Release);
        if let Ok(mut owner) = state.owner.lock() {
            *owner = Some(scope.clone());
        } else {
            state.running.store(false, Ordering::Release);
            return Err("ICMP operation owner registry unavailable".into());
        }
        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let device = interface_name.clone();
        let state_worker = Arc::clone(&state);
        let hops = tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = RunGuard(Arc::clone(&state_worker));
            trace_ipv4_echo(&device, host, max_hops, &state_worker.stop, &|| {
                worker_app
                    .state::<CaseSessionCtx>()
                    .ensure(&worker_scope)
                    .is_ok()
            })
            .map_err(|err| format!("{:?}: {}", err.code, err.message))
        })
        .await
        .map_err(|_| "route trace worker unavailable")??;
        selected.ensure(&scope)?;
        let rows: Vec<TraceHopWire> = hops
            .into_iter()
            .map(|hop| TraceHopWire {
                ttl: hop.ttl,
                responder: hop.responder.map(|address| address.to_string()),
                reached: hop.reached,
                reason: hop.reason,
                elapsed_ms: hop.elapsed_ms,
            })
            .collect();
        if !rows.is_empty() {
            let findings:Vec<NewFinding>=rows.iter().map(|hop|NewFinding {
                title:format!("IPv4 route trace hop {} toward {}",hop.ttl,host),
                severity:"info".into(),
                details:format!(
                    "Authorized IPv4 ICMP traceroute\nInterface: {}\nDestination: {}\nTTL: {}\nObserved responder: {}\nReached destination: {}\nReason: {}\nElapsed ms: {}\nEvidence: backend-matched ICMP echo identifier/sequence; intermediate-router addresses are unverified network claims; silence is inconclusive",
                    interface_name,host,hop.ttl,hop.responder.as_deref().unwrap_or("no response"),
                    hop.reached,hop.reason,hop.elapsed_ms,
                ),
            }).collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            selected.with_current_publication(&scope, || {
                store.add_findings(&case, "network.traceroute", None, &findings)
            })?;
        }
        selected.ensure(&scope)?;
        Ok(rows)
    }
}

/// Linux IPv6 Echo discovery reuses the existing ICMP exclusive job slot,
/// native Stop command and backend-owned selected case revision.
#[tauri::command]
pub async fn netscan_icmp6_discover_v1(
    targets: String,
    interface_name: String,
    authorized: bool,
    app: AppHandle,
    selected: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    scanner: State<'_, ScanCtx>,
    arp: State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
    syn: State<'_, Arc<super::syn_scan::SynScanCtx>>,
    ctx: State<'_, Arc<EchoCtx>>,
) -> Result<Vec<EchoObservationWire>, String> {
    if !authorized {
        return Err("explicit native IPv6 Echo authorization required".into());
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
            arp,
            syn,
            ctx,
        );
        return Err("native IPv6 Echo currently requires Linux CAP_NET_RAW".into());
    }
    #[cfg(target_os = "linux")]
    {
        use cyberdeck_packet::active_echo6::{
            discover_ipv6_echo, validate_hosts, Echo6State, MAX_ICMP6_HOSTS,
        };
        let (scope, case) = saved_scope(&selected)?;
        if scanner.running.load(Ordering::Acquire) || arp.is_running() || syn.is_running() {
            return Err("stop active Network scans before IPv6 Echo discovery".into());
        }
        let parsed = super::netscan::parse_targets(&targets)?;
        if parsed.is_empty() || parsed.len() > MAX_ICMP6_HOSTS {
            return Err(format!("IPv6 Echo allows at most {MAX_ICMP6_HOSTS} hosts"));
        }
        let hosts: Vec<std::net::Ipv6Addr> = parsed
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V6(v6) => Ok(v6),
                IpAddr::V4(_) => {
                    Err("native IPv6 Echo requires fe80::/10 IPv6 targets".to_string())
                }
            })
            .collect::<Result<_, _>>()?;
        validate_hosts(&hosts).map_err(|e| e.message)?;
        if !evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?
            .case_exists(&case)?
        {
            return Err("backend selected case does not exist".into());
        }
        let prompt=format!(
            "Authorize native ICMPv6 Echo discovery of {} link-local IPv6 targets on interface '{}' in saved case '{}'? A maximum of 20 requests/s, one request per host and <=600ms per reply. Only test networks you may assess. Linux CAP_NET_RAW is required.",
            hosts.len(),interface_name,case
        );
        let dialog = app.clone();
        let confirmed = tokio::task::spawn_blocking(move || {
            dialog
                .dialog()
                .message(prompt)
                .title("Confirm native IPv6 Echo")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "native IPv6 confirmation unavailable")?;
        if !confirmed {
            return Err("IPv6 Echo discovery declined".into());
        }
        selected.ensure(&scope)?;
        if scanner.running.load(Ordering::Acquire) || arp.is_running() || syn.is_running() {
            return Err("another scan began during IPv6 confirmation".into());
        }
        let permit = app
            .state::<Arc<super::operation_gate::NetworkOperationGate>>()
            .acquire(super::operation_gate::ActiveOperation::IcmpEcho)?;
        let state = Arc::clone(&*ctx);
        if state.running.swap(true, Ordering::AcqRel) {
            return Err("an ICMP scan or traceroute is already active".into());
        }
        state.stop.store(false, Ordering::Release);
        if let Ok(mut owner) = state.owner.lock() {
            *owner = Some(scope.clone());
        } else {
            state.running.store(false, Ordering::Release);
            return Err("native ICMP owner registry unavailable".into());
        }
        let app_for_worker = app.clone();
        let scope_for_worker = scope.clone();
        let worker_device = interface_name.clone();
        let worker = Arc::clone(&state);
        let observed = tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = RunGuard(Arc::clone(&worker));
            discover_ipv6_echo(&worker_device, &hosts, &worker.stop, &|| {
                app_for_worker
                    .state::<CaseSessionCtx>()
                    .ensure(&scope_for_worker)
                    .is_ok()
            })
            .map_err(|e| format!("{:?}: {}", e.code, e.message))
        })
        .await
        .map_err(|_| "native ICMPv6 worker unavailable")??;
        selected.ensure(&scope)?;
        let rows: Vec<EchoObservationWire> = observed
            .into_iter()
            .map(|entry| EchoObservationWire {
                host: entry.target.to_string(),
                state: match entry.state {
                    Echo6State::Responded => "responded",
                    Echo6State::Inconclusive => "inconclusive",
                },
                reason: entry.reason,
                elapsed_ms: entry.elapsed_ms,
            })
            .collect();
        if !rows.is_empty() {
            let findings:Vec<NewFinding>=rows.iter().map(|r|NewFinding{
                title:format!("ICMPv6 {} {}",r.state,r.host),
                severity:"info".into(),
                details:format!(
                    "Authorized native ICMPv6 Echo discovery\nSelected interface: {}\nLink-local target: {}\nState: {}\nReason: {}\nElapsed ms: {}\nEvidence: exact ICMPv6 Echo identifier and sequence reply matching; silence is inconclusive and link-local scope is interface-specific.",
                    interface_name,r.host,r.state,r.reason,r.elapsed_ms,
                ),
            }).collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            selected.with_current_publication(&scope, || {
                store.add_findings(&case, "network.icmp6", None, &findings)
            })?;
        }
        selected.ensure(&scope)?;
        Ok(rows)
    }
}

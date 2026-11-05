//! Scan-type + service-version commands (scan-depth slice). Two bounded
//! additive operations on top of the existing Network feature:
//!
//! - Raw TCP flag scans (FIN/NULL/Xmas/ACK/Window) with the same operator
//!   confirmation, saved-case scoping, mutual exclusion and native-confirmation
//!   dialog pattern as the SYN backend in `syn_scan.rs`. Linux only.
//! - A user-mode service probe (`std::net::TcpStream`) that runs a bounded,
//!   port-directed registry of protocol probes against ONE already-known
//!   open port. Every claim is an unverified remote assertion and is labeled
//!   with its evidence basis, mirroring the honest `remote_software_claim`
//!   handling of the connect scanner.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::active_scan_types::{
    classify_service_response, probe_payload, probe_registry_for_port, sanitize_excerpt,
    ServiceMatch, ServiceProbe, MAX_SERVICE_RESPONSE_BYTES,
};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use super::netscan::{parse_ports, parse_targets, ScanProgress};

/// Bounded probe parameters. Connection setup gets one polite timeout; each
/// probe read/write is capped so a silent or slow target cannot stall the UI.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const FIRST_READ_TIMEOUT: Duration = Duration::from_millis(2500);
const TAIL_READ_TIMEOUT: Duration = Duration::from_millis(400);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounded recent-result history per desktop session.
const PROBE_HISTORY_LIMIT: usize = 32;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct StealthScanCtx {
    running: AtomicBool,
    stop: AtomicBool,
    owner: Mutex<Option<CaseSessionWire>>,
}
impl StealthScanCtx {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }
}
struct StealthRunGuard(Arc<StealthScanCtx>);
impl Drop for StealthRunGuard {
    fn drop(&mut self) {
        // Clear ownership before publishing idle: a newly started operation
        // must never have its scope erased by a previous worker's destructor.
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
    }
}

/// Bounded in-memory history of service-probe results for the current desktop
/// session. Purely advisory (the case store is the record of truth); capped so
/// a long session cannot accumulate unbounded state.
#[derive(Default)]
pub struct ProbeCtx {
    recent: Mutex<VecDeque<ServiceProbeResultWire>>,
}
impl ProbeCtx {
    pub fn record(&self, result: ServiceProbeResultWire) {
        if let Ok(mut recent) = self.recent.lock() {
            if recent.len() >= PROBE_HISTORY_LIMIT {
                recent.pop_front();
            }
            recent.push_back(result);
        }
    }
    pub fn recent(&self) -> Vec<ServiceProbeResultWire> {
        self.recent
            .lock()
            .map(|recent| recent.iter().rev().cloned().collect())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Wire payloads
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct StealthFindingWire {
    host: String,
    port: u16,
    scan: &'static str,
    state: &'static str,
    reason: &'static str,
    elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceProbeResultWire {
    host: String,
    port: u16,
    /// Service identity claimed by the observed protocol behavior, or an empty
    /// string when nothing defensible was observed.
    service_claim: String,
    /// "banner" (service greeted on connect), "probe_response" (a protocol
    /// payload we sent was answered) or "none".
    basis: &'static str,
    /// "high" (full protocol match), "medium" (softmatch), "low" (no match).
    confidence: &'static str,
    probe_used: &'static str,
    soft_match: bool,
    /// Bounded, control-byte-sanitized excerpt of the remote response.
    raw_excerpt_trimmed: String,
    /// Unverified remote software/version assertion extracted from the
    /// response; never treated as an authenticated identity.
    remote_software_claim: Option<String>,
    elapsed_ms: u64,
}

fn selected_saved_case(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let id = scope
        .case_id
        .clone()
        .ok_or("saved case selection required")?;
    if id == "scratchpad" || id.is_empty() {
        return Err("scan-depth operations require a saved selected case".into());
    }
    Ok((scope, id))
}

fn scoped_case(
    session: &CaseSessionCtx,
    requested_case_id: &str,
) -> Result<(CaseSessionWire, String), String> {
    let (scope, id) = selected_saved_case(session)?;
    // The client-provided case id must agree with the backend-selected case:
    // stale UI state can never widen the evidence destination.
    if requested_case_id != id {
        return Err("request case id does not match the backend-selected case".into());
    }
    Ok((scope, id))
}

fn other_scan_active(
    app: &AppHandle,
    tcp: &State<'_, super::netscan::ScanCtx>,
    arp: &State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
) -> bool {
    tcp.running.load(Ordering::Acquire)
        || arp.is_running()
        || app
            .state::<Arc<super::icmp_echo::EchoCtx>>()
            .is_running()
}

// ---------------------------------------------------------------------------
// Raw scan-type command family
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn netscan_stealth_start_v1(
    scan_type: String,
    targets: String,
    ports: String,
    authorized: bool,
    case_id: String,
    interface_name: String,
    on_progress: Channel<ScanProgress>,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    tcp: State<'_, super::netscan::ScanCtx>,
    arp: State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
    ctx: State<'_, Arc<StealthScanCtx>>,
) -> Result<Vec<StealthFindingWire>, String> {
    if !authorized {
        return Err("explicit raw scan-type authorization acknowledgment required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            scan_type, targets, ports, case_id, interface_name, on_progress, app, session,
            evidence, tcp, arp, ctx,
        );
        return Err("raw FIN/NULL/Xmas/ACK/Window scan types require Linux CAP_NET_RAW".into());
    }
    #[cfg(target_os = "linux")]
    {
        use cyberdeck_packet::active_scan_types::{
            scan_ipv4_depth, DepthErrorCode, ScanKind, MAX_DEPTH_HOSTS, MAX_DEPTH_PORTS,
            MAX_DEPTH_PROBES,
        };
        let kind = ScanKind::parse(scan_type.trim().to_ascii_lowercase().as_str()).ok_or_else(|| {
            "scan_type must be one of: fin, null, xmas, ack, window".to_string()
        })?;
        let (scope, verified_case) = scoped_case(&session, &case_id)?;
        if other_scan_active(&app, &tcp, &arp) {
            return Err("stop other active network scans before starting a raw scan type".into());
        }
        let target_list = parse_targets(&targets)?;
        let port_list = parse_ports(&ports)?;
        if target_list.is_empty()
            || target_list.len() > MAX_DEPTH_HOSTS
            || port_list.is_empty()
            || port_list.len() > MAX_DEPTH_PORTS
            || target_list.len().saturating_mul(port_list.len()) > MAX_DEPTH_PROBES
        {
            return Err(format!(
                "raw scan-type limits: <={MAX_DEPTH_HOSTS} hosts, <={MAX_DEPTH_PORTS} ports, <={MAX_DEPTH_PROBES} probes"
            ));
        }
        let hosts: Vec<std::net::Ipv4Addr> = target_list
            .into_iter()
            .map(|ip| match ip {
                IpAddr::V4(address) => Ok(address),
                IpAddr::V6(_) => {
                    Err("raw scan types support IPv4 targets only; select IPv4 hosts".to_string())
                }
            })
            .collect::<Result<_, String>>()?;
        {
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            if !store.case_exists(&verified_case)? {
                return Err("selected saved case does not exist".into());
            }
        }
        let prompt = format!(
            "Authorize native Linux raw TCP {} scan on interface '{}' of {} IPv4 hosts and {} ports (max {} probes), in saved case '{}'? Reply classification follows documented scan semantics: silence is the scan type's default state (open|filtered for fin/null/xmas, filtered for ack/window), never affirmative evidence. OS CAP_NET_RAW is required; only assess systems you are authorized to test.",
            kind.label(),
            interface_name,
            hosts.len(),
            port_list.len(),
            MAX_DEPTH_PROBES,
            verified_case
        );
        let dialog = app.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            dialog
                .dialog()
                .message(prompt)
                .title("Confirm raw TCP scan type")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "raw scan confirmation failed")?;
        if !accepted {
            return Err("raw scan declined by operator".into());
        }
        session.ensure(&scope)?;
        if other_scan_active(&app, &tcp, &arp) {
            return Err("another scan became active during native confirmation".into());
        }
        let permit = app
            .state::<Arc<super::operation_gate::NetworkOperationGate>>()
            .acquire(super::operation_gate::ActiveOperation::RawSyn)?;
        let shared = Arc::clone(&*ctx);
        if shared.running.swap(true, Ordering::AcqRel) {
            return Err("a raw scan-type operation is already running".into());
        }
        shared.stop.store(false, Ordering::Release);
        {
            let mut owner = match shared.owner.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    shared.running.store(false, Ordering::Release);
                    return Err("raw scan registry unavailable".into());
                }
            };
            *owner = Some(scope.clone());
        }
        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let worker_device = interface_name.clone();
        let worker = Arc::clone(&shared);
        let findings = tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = StealthRunGuard(Arc::clone(&worker));
            scan_ipv4_depth(
                &worker_device,
                kind,
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
        .map_err(|_| "raw scan-type worker unavailable")??;
        session.ensure(&scope)?;
        let rows: Vec<StealthFindingWire> = findings
            .into_iter()
            .map(|entry| StealthFindingWire {
                host: entry.host.to_string(),
                port: entry.port,
                scan: kind.label(),
                state: entry.state.as_str(),
                reason: entry.reason,
                elapsed_ms: entry.elapsed_ms,
            })
            .collect();
        if !rows.is_empty() {
            let evidence_rows: Vec<NewFinding> = rows
                .iter()
                .take(256)
                .map(|entry| NewFinding {
                    title: format!(
                        "TCP {} {} {}:{}",
                        entry.scan, entry.state, entry.host, entry.port
                    ),
                    severity: "info".into(),
                    details: format!(
                        "Authorized native raw TCP flag scan\nInterface: {}\nHost: {}\nPort: {}\nState: {}\nReason: {}\nElapsed milliseconds: {}\nEvidence: correlated TCP RST / scoped ICMP error, or the scan type's documented silence default; not an authenticated host identity",
                        interface_name, entry.host, entry.port, entry.state, entry.reason, entry.elapsed_ms,
                    ),
                })
                .collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            session.with_current_publication(&scope, || {
                store.add_findings(&verified_case, "network.scan_depth", None, &evidence_rows)
            })?;
        }
        session.ensure(&scope)?;
        Ok(rows)
    }
}

#[tauri::command]
pub fn netscan_stealth_stop_v1(
    session: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<StealthScanCtx>>,
) -> Result<bool, String> {
    let (scope, _) = selected_saved_case(&session)?;
    let owner = ctx
        .owner
        .lock()
        .map_err(|_| "raw scan owner unavailable")?;
    if owner.as_ref() != Some(&scope) {
        return Err("raw scan belongs to another case revision".into());
    }
    ctx.stop.store(true, Ordering::Release);
    Ok(true)
}

#[tauri::command]
pub fn netscan_stealth_status_v1(
    session: State<'_, CaseSessionCtx>,
    ctx: State<'_, Arc<StealthScanCtx>>,
) -> Result<bool, String> {
    let (scope, _) = selected_saved_case(&session)?;
    let owner = ctx
        .owner
        .lock()
        .map_err(|_| "raw scan owner unavailable")?;
    Ok(owner.as_ref() == Some(&scope) && ctx.is_running())
}

// ---------------------------------------------------------------------------
// Service probe command (user-mode TCP, all platforms)
// ---------------------------------------------------------------------------

/// Read response bytes up to the bounded cap. The first read waits the full
/// greeting timeout so a slow-to-greet service is still observed; once data
/// has arrived the tail timeout keeps laggards from stalling the call.
fn read_bounded(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut got_data = false;
    loop {
        if data.len() >= MAX_SERVICE_RESPONSE_BYTES {
            break;
        }
        let timeout = if got_data {
            TAIL_READ_TIMEOUT
        } else {
            FIRST_READ_TIMEOUT
        };
        let _ = stream.set_read_timeout(Some(timeout));
        match stream.read(&mut chunk) {
            Ok(0) => break, // orderly close: no more banner is coming
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                got_data = true;
            }
            // WouldBlock/TimedOut: the service sent everything it will for now.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock
                        | ErrorKind::TimedOut
                        | ErrorKind::Interrupted
                        | ErrorKind::ConnectionReset
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    data
}

fn probe_once(
    address: SocketAddr,
    probe: ServiceProbe,
    nonce: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    if probe.needs_payload() {
        let payload = probe_payload(probe, nonce);
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
        stream
            .write_all(&payload)
            .map_err(|e| format!("probe write failed: {e}"))?;
    }
    Ok(read_bounded(&mut stream))
}

/// Map the best classification over the port-directed registry to the wire
/// result with an honest basis label. Full matches stop the registry early; a
/// softmatch is remembered but later probes may still upgrade it. Probe
/// payloads use OS-random nonces; if the CSPRNG is unavailable the command
/// fails rather than sending a constant, fingerprintable ClientHello.
fn run_registry(
    address: SocketAddr,
    host: String,
    port: u16,
) -> Result<ServiceProbeResultWire, String> {
    let started = Instant::now();
    let mut nonce = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut r| r.read_exact(&mut nonce))
        .map_err(|e| format!("OS random probe nonce unavailable: {e}"))?;
    let registry = probe_registry_for_port(port);
    let mut best: Option<(ServiceProbe, ServiceMatch, String)> = None;
    for probe in registry {
        // A connect failure or an empty reply simply means this probe produced
        // no evidence; the registry continues and silence degrades honestly to
        // basis "none" instead of an invented verdict.
        let Ok(response) = probe_once(address, *probe, &nonce) else {
            continue;
        };
        if response.is_empty() {
            continue;
        }
        let excerpt = sanitize_excerpt(&response);
        if let Some(found) = classify_service_response(*probe, &response) {
            let full = !found.soft;
            if best
                .as_ref()
                .is_none_or(|(_, prior, _)| prior.soft && full)
            {
                best = Some((*probe, found, excerpt));
            }
            if full {
                break;
            }
        }
    }
    let (basis, confidence): (&'static str, &'static str) = match &best {
        Some((probe, found, _)) => {
            let basis: &'static str = if matches!(probe, ServiceProbe::Banner) {
                "banner"
            } else {
                "probe_response"
            };
            let confidence: &'static str = if found.soft { "medium" } else { "high" };
            (basis, confidence)
        }
        None => ("none", "low"),
    };
    Ok(ServiceProbeResultWire {
        host,
        port,
        service_claim: best
            .as_ref()
            .map(|(_, found, _)| found.service.to_string())
            .unwrap_or_default(),
        basis,
        confidence,
        probe_used: best
            .as_ref()
            .map(|(probe, _, _)| probe.label())
            .unwrap_or("none"),
        soft_match: best.as_ref().is_some_and(|(_, found, _)| found.soft),
        raw_excerpt_trimmed: best
            .as_ref()
            .map(|(_, _, excerpt)| excerpt.clone())
            .unwrap_or_default(),
        remote_software_claim: best.as_ref().and_then(|(_, found, _)| found.claim.clone()),
        // Connect failures are surfaced through the claim fields being empty;
        // the elapsed time still reflects the bounded attempts.
        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

/// Probe ONE host:port with the bounded port-directed registry. The host must
/// be an IP literal: the frontend passes backend-observed hosts, and silently
/// resolving attacker-supplied hostnames from a desktop app would turn this
/// command into an unintended DNS-based discovery primitive.
#[tauri::command]
pub async fn netscan_service_probe_v1(
    host: String,
    port: u16,
    authorized: bool,
    case_id: String,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    ctx: State<'_, Arc<ProbeCtx>>,
) -> Result<ServiceProbeResultWire, String> {
    if !authorized {
        return Err("explicit service-probe authorization acknowledgment required".into());
    }
    let address: IpAddr = host
        .trim()
        .parse()
        .map_err(|_| "host must be an IP literal observed by a prior scan".to_string())?;
    if port == 0 {
        return Err("port must be nonzero".into());
    }
    let (scope, verified_case) = scoped_case(&session, &case_id)?;
    {
        let store = evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?;
        if !store.case_exists(&verified_case)? {
            return Err("selected saved case does not exist".into());
        }
    }
    // One bounded TCP connection family at a time, shared with connect scans.
    let permit = gate.acquire(super::operation_gate::ActiveOperation::TcpUdp)?;
    let result = tokio::task::spawn_blocking(move || {
        let _active_operation = permit;
        run_registry(SocketAddr::new(address, port), host, port)
    })
    .await
    .map_err(|_| "service probe worker unavailable")??;
    if !result.service_claim.is_empty() {
        let finding = NewFinding {
            title: format!(
                "Service claim {} {}:{} ({})",
                result.service_claim, result.host, result.port, result.basis
            ),
            severity: "info".into(),
            details: format!(
                "Authorized bounded service probe\nHost: {}\nPort: {}\nProbe: {}\nBasis: {}\nConfidence: {}\nSoft match: {}\nUnverified software claim: {}\nExcerpt: {}\nClaims are remote assertions, never authenticated identities.",
                result.host,
                result.port,
                result.probe_used,
                result.basis,
                result.confidence,
                result.soft_match,
                result.remote_software_claim.as_deref().unwrap_or("none"),
                result.raw_excerpt_trimmed,
            ),
        };
        let store = evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?;
        session.with_current_publication(&scope, || {
            store.add_findings(&verified_case, "network.service_probe", None, &[finding])
        })?;
    }
    ctx.record(result.clone());
    Ok(result)
}

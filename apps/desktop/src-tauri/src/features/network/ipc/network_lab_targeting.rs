//! Lab-scope-targeted ARP sweeps (Ettercap-style host targeting). The ONLY
//! active command in the Network Lab arc: an authorized ARP sweep whose
//! targets are resolved exclusively from the saved, memory-only lab scope
//! (Target 1 ∪ Target 2) held by `NetworkLabCtx`. A sweep can never probe an
//! address outside the declared scope: candidates are enumerated FROM the
//! scope entries, re-validated against the parsed scope by CIDR membership,
//! capped at `MAX_ARP_TARGETS`, and refused outright when no scope is set or
//! when the scope resolves to no probeable IPv4 target.
//!
//! Authorization and worker model mirror `arp_discovery.rs` exactly: saved
//! backend case, native Yes/No confirmation dialog, the shared
//! `NetworkOperationGate` lease (`ActiveOperation::LinkNeighbor` — the same
//! slot the netscan ARP/NDP discovery pair leases, so an ARP discovery and a
//! lab sweep can never run concurrently), exclusivity against the
//! `ArpDiscoveryCtx`, one sweep per process, case-revision revalidation
//! inside the worker closure, and the SAME underlying native worker
//! (`discover_on_link_arp`); no socket code is duplicated here.

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::active_arp::MAX_ARP_TARGETS;
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use super::arp_discovery::ArpNeighborWire;
use super::network_lab::NetworkLabCtx;

/// Single-operation registry for the lab ARP sweep, mirroring
/// `StealthScanCtx`/`ArpDiscoveryCtx`: at most one sweep per process, owned
/// by the case revision that started it, cancellable between probes (the
/// native worker checks `stop` before every raw send and during receive
/// polls).
#[derive(Default)]
pub struct LabTargetingCtx {
    running: AtomicBool,
    stop: AtomicBool,
    owner: Mutex<Option<CaseSessionWire>>,
}

impl LabTargetingCtx {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    /// Optional immediate case-change hook. Scope checks in the native worker
    /// remain authoritative even when a caller cannot invoke this hook.
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

struct SweepRunGuard(Arc<LabTargetingCtx>);
impl Drop for SweepRunGuard {
    fn drop(&mut self) {
        // Clear ownership before publishing idle: a newly started sweep must
        // never have its scope erased by a previous worker's destructor.
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
    }
}

/// Progress event for the sweep channel. Honest about what the native worker
/// can know: target totals and real elapsed wall-clock time only — the
/// underlying `discover_on_link_arp` worker exposes no per-host progress
/// hook, so no per-target counter is ever fabricated.
#[derive(Clone, Debug, Serialize)]
pub struct LabSweepProgressWire {
    /// "running" while the native worker probes, "done" after it settles.
    pub phase: String,
    /// Probeable IPv4 targets resolved from the saved lab scope.
    pub total_targets: usize,
    /// Elapsed wall-clock milliseconds since the worker started.
    pub elapsed_ms: u64,
    /// Hosts that answered; populated only on the "done" event.
    pub answered: Option<usize>,
}

// ---------------------------------------------------------------------------
// Pure scope resolution (no Tauri types): enumerated FROM the saved scope and
// re-validated against it, so a sweep can never widen the operator's target
// set beyond Target 1 ∪ Target 2.
// ---------------------------------------------------------------------------

/// One parsed lab-scope entry: a pinned address or a CIDR network. Scope
/// entries are IP/CIDR strings only (`network_lab.rs` validates at set time);
/// re-parsing here is defense in depth, never hostname resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeSelector {
    Single(IpAddr),
    Network(IpAddr, u8),
}

impl ScopeSelector {
    fn parse(entry: &str, group: &str) -> Result<Self, String> {
        let value = entry.trim();
        if let Some((addr, prefix)) = value.split_once('/') {
            let address: IpAddr = addr
                .parse()
                .map_err(|_| format!("bad CIDR address in lab scope {group}: {addr}"))?;
            let bits: u8 = prefix
                .parse()
                .map_err(|_| format!("bad CIDR prefix in lab scope {group}: {prefix}"))?;
            let width = if address.is_ipv4() { 32u8 } else { 128 };
            if bits > width {
                return Err(format!(
                    "invalid /{bits} prefix for {address} in lab scope {group}"
                ));
            }
            return Ok(Self::Network(address, bits));
        }
        let address: IpAddr = value
            .parse()
            .map_err(|_| format!("lab scope entry must be an IP or CIDR: {value}"))?;
        Ok(Self::Single(address))
    }

    /// CIDR membership, mirroring the shift-based matcher the netscan target
    /// planner uses (`features/network/infrastructure/targets.rs`).
    fn contains(self, candidate: IpAddr) -> bool {
        match self {
            Self::Single(ip) => ip == candidate,
            Self::Network(IpAddr::V4(ip), prefix) => {
                let IpAddr::V4(other) = candidate else {
                    return false;
                };
                let shift = 32u32 - u32::from(prefix);
                if shift == 32 {
                    return true;
                }
                (u32::from(ip) >> shift) == (u32::from(other) >> shift)
            }
            Self::Network(IpAddr::V6(ip), prefix) => {
                let IpAddr::V6(other) = candidate else {
                    return false;
                };
                let shift = 128u32 - u32::from(prefix);
                if shift == 128 {
                    return true;
                }
                (u128::from(ip) >> shift) == (u128::from(other) >> shift)
            }
        }
    }
}

fn parse_scope_selectors(entries: &[String], group: &str) -> Result<Vec<ScopeSelector>, String> {
    entries
        .iter()
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| ScopeSelector::parse(entry, group))
        .collect()
}

/// Refuse any candidate outside the parsed scope. The sweep's candidates are
/// enumerated from the scope itself, so this always holds today; keeping it
/// as an explicit gate means a future candidate source (or a resolution bug)
/// can never widen the probe set beyond Target 1 ∪ Target 2.
fn ensure_all_in_scope(selectors: &[ScopeSelector], targets: &[Ipv4Addr]) -> Result<(), String> {
    for target in targets {
        let inside = selectors
            .iter()
            .any(|selector| selector.contains(IpAddr::V4(*target)));
        if !inside {
            return Err(format!(
                "refusing to probe {target}: outside the saved lab scope (Target 1 ∪ Target 2)"
            ));
        }
    }
    Ok(())
}

/// Expand one scope entry into its probeable IPv4 hosts, appending distinct
/// addresses in first-seen order. IPv4 CIDRs enumerate usable hosts (network
/// and broadcast excluded for prefixes <= /30; /31 keeps both per RFC 3021;
/// /32 pins the one address); IPv6 entries are not ARP-probeable and are
/// skipped honestly (the empty-result error says so). Pushing a DISTINCT host
/// past the cap refuses with the narrowing guidance — never truncation; the
/// in-loop bound also keeps a huge CIDR from enumerating more than
/// cap + 1 candidates before refusing.
fn expand_scope_entry(
    selector: ScopeSelector,
    into: &mut Vec<Ipv4Addr>,
    cap: usize,
) -> Result<(), String> {
    let cap_error = || {
        format!(
            "the saved lab scope resolves to more than {cap} probeable IPv4 targets \
             (Target 1 ∪ Target 2); the ARP sweep accepts at most {MAX_ARP_TARGETS} — \
             narrow the scope"
        )
    };
    let (address, prefix) = match selector {
        ScopeSelector::Single(IpAddr::V4(ip)) => {
            if into.contains(&ip) {
                return Ok(());
            }
            if into.len() >= cap {
                return Err(cap_error());
            }
            into.push(ip);
            return Ok(());
        }
        // IPv6 needs Neighbor Discovery, not ARP; skipped, never half-probed.
        ScopeSelector::Single(IpAddr::V6(_)) | ScopeSelector::Network(IpAddr::V6(_), _) => {
            return Ok(());
        }
        ScopeSelector::Network(IpAddr::V4(ip), prefix) => (ip, prefix),
    };
    let host_bits = 32u32 - u32::from(prefix);
    let count = 1u64 << host_bits;
    let mask = if host_bits == 0 {
        u32::MAX
    } else {
        u32::MAX << host_bits
    };
    let base = u32::from(address) & mask;
    for i in 0..count {
        if prefix < 31 && (i == 0 || i == count - 1) {
            continue; // network and broadcast addresses are never hosts
        }
        let host = Ipv4Addr::from(base + i as u32);
        if into.contains(&host) {
            continue;
        }
        if into.len() >= cap {
            return Err(cap_error());
        }
        into.push(host);
    }
    Ok(())
}

/// Resolve the sweep target set from the saved lab scope: Target 1 entries
/// then Target 2 entries, deduplicated preserving first-seen order, IPv4
/// only, capped at `MAX_ARP_TARGETS` like the netscan ARP discovery pair.
/// Refuses with a clear error when the scope resolves to no probeable IPv4
/// target (the intersection with Target 1 ∪ Target 2 is empty) or when the
/// expansion would exceed the cap.
fn resolve_sweep_targets(
    targets_t1: &[String],
    targets_t2: &[String],
    cap: usize,
) -> Result<Vec<Ipv4Addr>, String> {
    let mut selectors = parse_scope_selectors(targets_t1, "Target 1")?;
    selectors.extend(parse_scope_selectors(targets_t2, "Target 2")?);
    let mut hosts: Vec<Ipv4Addr> = Vec::new();
    for selector in &selectors {
        expand_scope_entry(*selector, &mut hosts, cap)?;
    }
    if hosts.is_empty() {
        return Err(
            "the saved lab scope resolves to no probeable IPv4 targets — the ARP sweep \
             cannot start (IPv6 entries need Neighbor Discovery, not ARP; add IPv4 or \
             IPv4 CIDR entries to Target 1 or Target 2)"
                .to_string(),
        );
    }
    ensure_all_in_scope(&selectors, &hosts)?;
    Ok(hosts)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn selected_saved_case(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let case_id = scope
        .case_id
        .clone()
        .ok_or("a saved case must be selected")?;
    if case_id == "scratchpad" || case_id.trim().is_empty() {
        return Err("lab ARP sweeps require a saved, backend-selected case".into());
    }
    Ok((scope, case_id))
}

/// The client-provided case id must agree with the backend-selected case:
/// stale UI state can never widen the evidence destination.
fn scoped_case(
    session: &CaseSessionCtx,
    requested_case_id: &str,
) -> Result<(CaseSessionWire, String), String> {
    let (scope, id) = selected_saved_case(session)?;
    if requested_case_id != id {
        return Err("request case id does not match the backend-selected case".into());
    }
    Ok((scope, id))
}

/// Sweep ONLY the IPv4 targets resolved from the saved Network Lab scope
/// (Target 1 ∪ Target 2) on the selected Ethernet interface. Refuses without
/// a set scope, an empty/IPv6-only intersection, out-of-scope candidates, a
/// target set past the 32-target cap, an unsaved case, or a declined native
/// confirmation. Shares the `LinkNeighbor` gate lease with the netscan
/// ARP/NDP discovery pair so the two can never run concurrently.
#[tauri::command]
pub async fn network_lab_arp_sweep_v1(
    interface_name: String,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    arp: State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
    lab: State<'_, NetworkLabCtx>,
    targeting: State<'_, Arc<LabTargetingCtx>>,
    on_progress: Channel<LabSweepProgressWire>,
) -> Result<Vec<ArpNeighborWire>, String> {
    if !authorized {
        return Err("explicit lab ARP sweep authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            interface_name,
            case_id,
            app,
            session,
            evidence,
            gate,
            arp,
            lab,
            targeting,
            on_progress,
        );
        return Err("lab ARP sweeps use the native ARP worker and currently require Linux".into());
    }
    #[cfg(target_os = "linux")]
    {
        let (scope, verified_case) = scoped_case(&session, &case_id)?;
        // The saved lab scope is the ONLY target source; no scope, no sweep.
        let lab_scope = super::network_lab::network_lab_scope_v1(lab)?;
        if !lab_scope.authorized {
            return Err(
                "no lab scope is set — set Target 1 / Target 2 with the authorization \
                 checkbox before starting an ARP sweep"
                    .into(),
            );
        }
        if arp.is_running() || gate.is_active() {
            return Err("stop other active network scans before starting the lab ARP sweep".into());
        }
        let hosts = resolve_sweep_targets(
            &lab_scope.targets_t1,
            &lab_scope.targets_t2,
            MAX_ARP_TARGETS,
        )?;
        {
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            if !store.case_exists(&verified_case)? {
                return Err("selected case does not exist".into());
            }
        }

        // Backend confirmation is independent of the frontend checkbox.
        let question = format!(
            "Send a maximum of {} ARP requests on Linux Ethernet interface '{}' to the {} \
             IPv4 targets resolved from the saved Network Lab scope (Target 1 ∪ Target 2), \
             in saved case '{}'? At most 10 probes/s, no retries, 500ms response deadline \
             per host. Requires CAP_NET_RAW and permission to test this network.",
            hosts.len(),
            interface_name,
            hosts.len(),
            verified_case,
        );
        let dialog_app = app.clone();
        let agreed = tokio::task::spawn_blocking(move || {
            dialog_app
                .dialog()
                .message(question)
                .title("Authorize lab-scope ARP sweep")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "lab ARP sweep confirmation unavailable")?;
        if !agreed {
            return Err("lab ARP sweep cancelled by operator".into());
        }
        session.ensure(&scope)?;
        if arp.is_running() || gate.is_active() {
            return Err(
                "another network operation became active while confirming the lab ARP sweep".into(),
            );
        }
        let permit = gate.acquire(super::operation_gate::ActiveOperation::LinkNeighbor)?;
        let shared = Arc::clone(&*targeting);
        if shared.running.swap(true, Ordering::AcqRel) {
            return Err("a lab ARP sweep operation is already active".into());
        }
        shared.stop.store(false, Ordering::Release);
        if let Ok(mut owner) = shared.owner.lock() {
            *owner = Some(scope.clone());
        } else {
            shared.running.store(false, Ordering::Release);
            return Err("lab ARP sweep owner registry unavailable".into());
        }
        let total_targets = hosts.len();
        let _ = on_progress.send(LabSweepProgressWire {
            phase: "running".into(),
            total_targets,
            elapsed_ms: 0,
            answered: None,
        });
        // Elapsed-time ticker: the native worker has no per-host progress
        // hook, so the channel carries honest wall-clock time while it runs.
        let ticker = tokio::spawn({
            let on_progress = on_progress.clone();
            async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tick.tick().await; // the first tick completes immediately
                let started = std::time::Instant::now();
                loop {
                    tick.tick().await;
                    let _ = on_progress.send(LabSweepProgressWire {
                        phase: "running".into(),
                        total_targets,
                        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                        answered: None,
                    });
                }
            }
        });
        let started = std::time::Instant::now();
        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let worker_device = interface_name.clone();
        let worker = Arc::clone(&shared);
        let joined = tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = SweepRunGuard(Arc::clone(&worker));
            cyberdeck_packet::active_arp::discover_on_link_arp(
                &worker_device,
                &hosts,
                &worker.stop,
                &|| {
                    worker_app
                        .state::<CaseSessionCtx>()
                        .ensure(&worker_scope)
                        .is_ok()
                },
            )
            .map_err(|err| format!("{:?}: {}", err.code, err.message))
        })
        .await;
        // The ticker must die even when the worker failed, or it would spin
        // forever on a dead channel.
        ticker.abort();
        let found = joined.map_err(|_| "lab ARP sweep worker unavailable")??;
        let _ = on_progress.send(LabSweepProgressWire {
            phase: "done".into(),
            total_targets,
            elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            answered: Some(found.len()),
        });
        session.ensure(&scope)?;

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
                title: format!("Lab ARP sweep host {}", item.host),
                severity: "info".into(),
                details: format!(
                    "Authorized lab-scope ARP sweep (Target 1 ∪ Target 2)\nInterface: {}\nTarget: {}\nObserved responder MAC: {}\nResponse latency ms: {}\nEvidence: correlated Ethernet ARP reply; not cryptographic host authentication",
                    interface_name, item.host, item.mac, item.elapsed_ms
                ),
            }).collect();
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            session.with_current_publication(&scope, || {
                store.add_findings(&verified_case, "network.lab_arp_sweep", None, &findings)
            })?;
        }
        session.ensure(&scope)?;
        Ok(rows)
    }
}

/// Stop only the sweep owned by the currently selected case revision.
#[tauri::command]
pub fn network_lab_arp_sweep_stop_v1(
    session: State<'_, CaseSessionCtx>,
    targeting: State<'_, Arc<LabTargetingCtx>>,
) -> Result<bool, String> {
    let (scope, _) = selected_saved_case(&session)?;
    let owner = targeting
        .owner
        .lock()
        .map_err(|_| "lab ARP sweep owner unavailable")?;
    if owner.as_ref() != Some(&scope) {
        return Err("lab ARP sweep does not belong to the selected case revision".into());
    }
    targeting.stop.store(true, Ordering::Release);
    Ok(true)
}

#[tauri::command]
pub fn network_lab_arp_sweep_status_v1(
    session: State<'_, CaseSessionCtx>,
    targeting: State<'_, Arc<LabTargetingCtx>>,
) -> Result<bool, String> {
    let (scope, _) = selected_saved_case(&session)?;
    let owner = targeting
        .owner
        .lock()
        .map_err(|_| "lab ARP sweep owner unavailable")?;
    Ok(owner.as_ref() == Some(&scope) && targeting.is_running())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn ipv4(value: &str) -> Ipv4Addr {
        value.parse().expect("valid IPv4 literal")
    }

    #[test]
    fn in_scope_addresses_resolve_and_pass_membership() {
        let hosts = resolve_sweep_targets(
            &entries(&["10.0.0.5"]),
            &entries(&["10.0.0.9"]),
            MAX_ARP_TARGETS,
        )
        .expect("in-scope targets resolve");
        assert_eq!(hosts, vec![ipv4("10.0.0.5"), ipv4("10.0.0.9")]);
        let selectors =
            parse_scope_selectors(&entries(&["10.0.0.5", "10.0.0.9"]), "Target 1").unwrap();
        assert!(ensure_all_in_scope(&selectors, &hosts).is_ok());
    }

    #[test]
    fn cidr_boundaries_enumerate_usable_hosts_only() {
        // /30: network (.4) and broadcast (.7) are never probed.
        let hosts = resolve_sweep_targets(&entries(&["192.168.1.4/30"]), &[], MAX_ARP_TARGETS)
            .expect("a /30 fits the cap");
        assert_eq!(hosts, vec![ipv4("192.168.1.5"), ipv4("192.168.1.6")]);
        // /31 keeps both addresses (RFC 3021); /32 pins exactly one.
        let pair = resolve_sweep_targets(&entries(&["10.0.0.0/31"]), &[], MAX_ARP_TARGETS).unwrap();
        assert_eq!(pair, vec![ipv4("10.0.0.0"), ipv4("10.0.0.1")]);
        let pinned =
            resolve_sweep_targets(&entries(&["10.0.0.7/32"]), &[], MAX_ARP_TARGETS).unwrap();
        assert_eq!(pinned, vec![ipv4("10.0.0.7")]);
        // Membership at the CIDR edge: the last /24 address is inside, the
        // very next address outside it is not.
        let selectors = parse_scope_selectors(&entries(&["10.0.0.0/24"]), "Target 1").unwrap();
        assert!(ensure_all_in_scope(&selectors, &[ipv4("10.0.0.255")]).is_ok());
        assert!(ensure_all_in_scope(&selectors, &[ipv4("10.0.1.0")]).is_err());
        assert!(ensure_all_in_scope(&selectors, &[ipv4("10.0.1.5")]).is_err());
    }

    #[test]
    fn out_of_scope_candidates_are_refused_before_any_probe() {
        let selectors = parse_scope_selectors(&entries(&["10.0.0.0/24"]), "Target 1").unwrap();
        let outsider = ipv4("192.168.5.5");
        let err = ensure_all_in_scope(&selectors, &[outsider]).unwrap_err();
        assert!(err.contains("outside the saved lab scope"), "{err}");
        // The refusal text never reaches the worker: resolution itself
        // refuses anything not contained in the parsed scope.
        assert!(resolve_sweep_targets(&entries(&["10.0.0.5"]), &[], MAX_ARP_TARGETS).is_ok());
    }

    #[test]
    fn missing_empty_or_non_ipv4_scope_is_refused_with_clear_errors() {
        // No scope content at all.
        let empty = resolve_sweep_targets(&[], &[], MAX_ARP_TARGETS).unwrap_err();
        assert!(empty.contains("no probeable IPv4 targets"), "{empty}");
        // IPv6-only scope: ARP cannot probe it (needs Neighbor Discovery).
        let v6_only =
            resolve_sweep_targets(&entries(&["2001:db8::/64"]), &[], MAX_ARP_TARGETS).unwrap_err();
        assert!(v6_only.contains("no probeable IPv4 targets"), "{v6_only}");
        // Malformed entries never silently become targets (the scope setter
        // validates too; this is the defense-in-depth layer).
        assert!(resolve_sweep_targets(&entries(&["router.local"]), &[], MAX_ARP_TARGETS).is_err());
        assert!(resolve_sweep_targets(&entries(&["10.0.0.0/33"]), &[], MAX_ARP_TARGETS).is_err());
    }

    #[test]
    fn scopes_past_the_target_cap_are_refused_never_truncated() {
        // Exactly the cap is accepted (32 distinct pinned hosts).
        let at_cap: Vec<String> = (0..MAX_ARP_TARGETS)
            .map(|i| format!("10.0.0.{}", i + 1))
            .collect();
        assert_eq!(
            resolve_sweep_targets(&at_cap, &[], MAX_ARP_TARGETS)
                .expect("cap-sized scope resolves")
                .len(),
            MAX_ARP_TARGETS
        );
        // One more pinned host refuses with the narrowing guidance.
        let mut over_cap = at_cap.clone();
        over_cap.push("10.0.0.200".to_string());
        let err = resolve_sweep_targets(&over_cap, &[], MAX_ARP_TARGETS).unwrap_err();
        assert!(err.contains("narrow the scope"), "{err}");
        // A /27 expands to exactly 30 usable hosts and fits; a /26 (62)
        // refuses instead of silently scanning a fraction of the scope.
        let fits = resolve_sweep_targets(&entries(&["192.0.2.0/27"]), &[], MAX_ARP_TARGETS)
            .expect("a /27 fits the cap");
        assert_eq!(fits.len(), 30);
        assert!(resolve_sweep_targets(&entries(&["192.0.2.0/26"]), &[], MAX_ARP_TARGETS).is_err());
    }

    #[test]
    fn duplicate_entries_dedup_preserving_first_seen_order() {
        let hosts = resolve_sweep_targets(
            &entries(&["10.0.0.5", "10.0.0.6"]),
            &entries(&["10.0.0.5"]),
            MAX_ARP_TARGETS,
        )
        .unwrap();
        assert_eq!(hosts, vec![ipv4("10.0.0.5"), ipv4("10.0.0.6")]);
        // An expanded CIDR plus its own member dedupes to the CIDR set.
        let mixed = resolve_sweep_targets(
            &entries(&["192.168.1.4/30"]),
            &entries(&["192.168.1.5"]),
            MAX_ARP_TARGETS,
        )
        .unwrap();
        assert_eq!(mixed, vec![ipv4("192.168.1.5"), ipv4("192.168.1.6")]);
    }

    #[test]
    fn the_run_guard_publishes_idle_and_clears_ownership() {
        let ctx = Arc::new(LabTargetingCtx::default());
        ctx.running.store(true, Ordering::Release);
        ctx.owner.lock().unwrap().replace(CaseSessionWire {
            case_id: Some("case".into()),
            revision: 1,
        });
        drop(SweepRunGuard(Arc::clone(&ctx)));
        assert!(!ctx.is_running());
        assert!(ctx.owner.lock().unwrap().is_none());
        // The case-change hook arms the stop flag the worker polls.
        ctx.on_case_changed();
        assert!(ctx.stop.load(Ordering::Acquire));
    }
}

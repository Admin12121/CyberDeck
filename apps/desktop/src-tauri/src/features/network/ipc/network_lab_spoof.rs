//! Bettercap-parity full-duplex ARP spoofing IPC for the Network Lab arc.
//! AUTHORIZED LAB USE ONLY, gated like the lab ARP sweep
//! (`network_lab_targeting.rs`): saved backend case, saved memory-only lab
//! scope as the ONLY address source, shared `NetworkOperationGate` lease
//! (`ActiveOperation::LinkNeighbor` — the same slot ARP discovery and the lab
//! sweep lease, so a spoof can never run next to another active network
//! operation), native Yes/No confirmation dialog naming exactly what will be
//! sent, Linux-only native worker, one spoof per process, and a stop command
//! that is never refused. The socket layer is NOT duplicated here: the pure
//! spoofer core lives in `features/network/infrastructure/arp_spoof.rs`
//! (`arp_spoof::run_arp_spoof`), which validates scope membership, paces
//! rounds at 1..=10/s, hard-caps the run at 30 minutes and ALWAYS runs the
//! restoration pass (real MACs re-announced in both directions, unknowns
//! reported) before the outcome is published.
//!
//! The spoof's own frames are ARP replies and therefore show up in the
//! passive lab timeline (`arp_watch` conflicts / `lab_events` `arp_conflict`)
//! — that visibility is intended and needs no analyzer change.

#[path = "../infrastructure/arp_spoof.rs"]
pub mod arp_spoof;

use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[cfg(target_os = "linux")]
use tauri::Manager;
use tauri::{AppHandle, State};
#[cfg(target_os = "linux")]
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use super::network_lab::NetworkLabCtx;

/// Managed per-process spoof registry, mirroring `LabTargetingCtx`/`ArpDiscoveryCtx`.
#[derive(Default)]
pub struct NetworkLabSpoofCtx {
    running: AtomicBool,
    stop: AtomicBool,
    phase: Mutex<SpoofPhase>,
    /// Live count of EVERY transmitted frame (poison + restoration), updated
    /// by the worker so `status` can poll honest numbers mid-run.
    packets_sent: AtomicU64,
    pairs: AtomicUsize,
    started_at: Mutex<Option<Instant>>,
    final_elapsed_ms: AtomicU64,
    restored_targets: AtomicUsize,
    restoration_note: Mutex<Option<String>>,
    last_error: Mutex<Option<String>>,
    owner: Mutex<Option<CaseSessionWire>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SpoofPhase {
    #[default]
    Idle,
    Starting,
    Spoofing,
    Stopping,
    Stopped,
}
impl SpoofPhase {
    fn as_str(self) -> &'static str {
        match self {
            SpoofPhase::Idle => "idle",
            SpoofPhase::Starting => "starting",
            SpoofPhase::Spoofing => "spoofing",
            SpoofPhase::Stopping => "stopping",
            SpoofPhase::Stopped => "stopped",
        }
    }
}

impl NetworkLabSpoofCtx {
    /// Immediate case-change hook; the worker's scope closure stays
    /// authoritative even when a caller cannot invoke this.
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }

    fn set_phase(&self, phase: SpoofPhase) {
        if let Ok(mut guard) = self.phase.lock() {
            *guard = phase;
        }
    }

    fn phase(&self) -> SpoofPhase {
        self.phase.lock().map(|g| *g).unwrap_or(SpoofPhase::Idle)
    }

    fn status_wire(&self) -> SpoofStatusWire {
        let started = self.started_at.lock().ok().and_then(|guard| *guard);
        let elapsed = if started.is_some() && self.running.load(Ordering::Acquire) {
            started
                .map(|s| s.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0)
        } else {
            self.final_elapsed_ms.load(Ordering::Acquire)
        };
        SpoofStatusWire {
            state: self.phase().as_str().to_string(),
            packets_sent: self.packets_sent.load(Ordering::Acquire),
            pairs: self.pairs.load(Ordering::Acquire),
            elapsed_ms: elapsed,
            restored_targets: self.restored_targets.load(Ordering::Acquire),
            restoration_note: self.restoration_note.lock().ok().and_then(|g| g.clone()),
            last_error: self.last_error.lock().ok().and_then(|g| g.clone()),
        }
    }
}

/// Runs for the whole worker lifetime; clears ownership and publishes the
/// final phase even when the worker panicked or the runtime dropped it.
struct SpoofRunGuard(Arc<NetworkLabSpoofCtx>);
impl Drop for SpoofRunGuard {
    fn drop(&mut self) {
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
        self.0.set_phase(SpoofPhase::Stopped);
    }
}

/// Wire status for `network_lab_spoof_status_v1`; snake_case field names are
/// the serde names and are mirrored verbatim by the typed frontend client.
#[derive(Debug, Clone, Serialize)]
pub struct SpoofStatusWire {
    /// idle | starting | spoofing | stopping | stopped.
    pub state: String,
    /// Every transmitted frame of the run (poison rounds + restoration).
    pub packets_sent: u64,
    /// Authorized (target, gateway) pairs poisoning this run.
    pub pairs: usize,
    /// Elapsed wall-clock milliseconds.
    pub elapsed_ms: u64,
    /// Targets that received a reply re-announcing the gateway's REAL MAC.
    pub restored_targets: usize,
    /// Backend-rendered honest restoration summary (what was restored and
    /// what stayed unknown); present once the run has ended.
    pub restoration_note: Option<String>,
    pub last_error: Option<String>,
}

/// Start response: the exact gateway/targets the backend authorized (the UI
/// never widens or re-derives them) plus the initial status.
#[derive(Debug, Clone, Serialize)]
pub struct SpoofStartWire {
    pub gateway: String,
    pub targets: Vec<String>,
    pub rate_per_sec: u32,
    pub runtime_cap_minutes: u32,
    pub status: SpoofStatusWire,
}

fn selected_saved_case(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let case_id = scope
        .case_id
        .clone()
        .ok_or("a saved case must be selected")?;
    if case_id == "scratchpad" || case_id.trim().is_empty() {
        return Err("lab ARP spoofing requires a saved, backend-selected case".into());
    }
    Ok((scope, case_id))
}

/// Flatten the pure core's typed error into the command's honest String wire
/// error (code discriminator + message, mirroring the ARP discovery pair).
fn spoof_err(err: arp_spoof::SpoofError) -> String {
    format!("{:?}: {}", err.code, err.message)
}

/// Honest one-line restoration summary rendered on the backend so the UI can
/// only ever repeat truth, never recompute it.
fn restoration_note_text(report: &arp_spoof::RestorationReport, total_pairs: usize) -> String {
    let unknown = if report.unknown_target_macs.is_empty() {
        "none".to_string()
    } else {
        report
            .unknown_target_macs
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "restored {}/{} targets with the gateway's real MAC (gateway MAC known: {}); \
         gateway cache entries re-armed: {}/{}; unknown target MACs: {}; \
         restoration frames sent: {}",
        report.targets_restored,
        total_pairs,
        report.gateway_mac_known,
        report.gateway_entries_restored,
        total_pairs,
        unknown,
        report.packets_sent,
    )
}

/// Start a full-duplex ARP spoof against the saved lab scope ONLY: targets
/// are resolved from Target 1 ∪ Target 2 on the backend, the gateway must be
/// an IPv4 entry INSIDE that scope, and `target_count` picks the first N
/// resolved hosts (bounded by the 32-pair cap). Refuses without a saved
/// case, a set scope, in-scope addresses, a free gate lease or a declined
/// native confirmation.
#[tauri::command]
pub async fn network_lab_spoof_start_v1(
    interface_name: String,
    gateway: String,
    target_count: u32,
    rate_per_sec: u32,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    arp: State<'_, Arc<super::arp_discovery::ArpDiscoveryCtx>>,
    lab: State<'_, NetworkLabCtx>,
    spoof: State<'_, Arc<NetworkLabSpoofCtx>>,
) -> Result<SpoofStartWire, String> {
    if !authorized {
        return Err("explicit lab ARP spoofing authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            interface_name,
            gateway,
            target_count,
            rate_per_sec,
            case_id,
            app,
            session,
            evidence,
            gate,
            arp,
            lab,
            spoof,
        );
        return Err(
            "lab ARP spoofing uses the native ARP worker and currently requires Linux".into(),
        );
    }
    #[cfg(target_os = "linux")]
    {
        let (scope, verified_case) = selected_saved_case(&session)?;
        if case_id != verified_case {
            return Err("request case id does not match the backend-selected case".into());
        }
        if arp.is_running() || gate.is_active() {
            return Err("stop other active network scans before starting lab ARP spoofing".into());
        }
        // The saved lab scope is the ONLY address source; no scope, no spoof.
        let lab_scope = super::network_lab::network_lab_scope_v1(lab)?;
        if !lab_scope.authorized {
            return Err(
                "no lab scope is set — set Target 1 / Target 2 with the authorization \
                 checkbox before starting ARP spoofing"
                    .into(),
            );
        }
        let set = arp_spoof::build_scope_set(
            &lab_scope.targets_t1,
            &lab_scope.targets_t2,
            arp_spoof::MAX_SPOOF_PAIRS,
        )
        .map_err(spoof_err)?;
        let gateway_ip: std::net::Ipv4Addr = gateway.trim().parse().map_err(|_| {
            format!("gateway must be an IPv4 address from the saved lab scope: {gateway}")
        })?;
        let pairs = arp_spoof::build_spoof_pairs(&set, gateway_ip, target_count as usize)
            .map_err(spoof_err)?;
        arp_spoof::validate_rate(rate_per_sec).map_err(spoof_err)?;
        arp_spoof::validate_pairs(&pairs).map_err(spoof_err)?;
        let target_list: Vec<String> = pairs.iter().map(|p| p.target.to_string()).collect();
        {
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            if !store.case_exists(&verified_case)? {
                return Err("selected case does not exist".into());
            }
        }

        // Backend confirmation is independent of the frontend checkbox: it
        // names EXACTLY what will be sent, both directions, before the first
        // frame leaves the machine.
        let question = format!(
            "Authorize full-duplex ARP spoofing on Linux interface '{}' in saved case '{}'? \
             {} unsolicited ARP replies per round: to {} target(s) claiming gateway {} with \
             this machine's MAC, and to the gateway claiming each target's IPv4 with this \
             machine's MAC — {} round(s)/s, {} (target, gateway) pairs, hard 30-minute \
             runtime cap. On stop a restoration pass re-announces the gateway's real MAC to \
             the targets and the targets' real MACs to the gateway (learned passively or via \
             solicited requests; anything unknown is reported). Requires CAP_NET_RAW and \
             permission to test this network.",
            interface_name,
            verified_case,
            pairs.len() * 2,
            pairs.len(),
            gateway_ip,
            rate_per_sec,
            pairs.len(),
        );
        let dialog_app = app.clone();
        let agreed = tokio::task::spawn_blocking(move || {
            dialog_app
                .dialog()
                .message(question)
                .title("Authorize lab ARP spoofing")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "lab ARP spoofing confirmation unavailable")?;
        if !agreed {
            return Err("lab ARP spoofing cancelled by operator".into());
        }
        session.ensure(&scope)?;
        if arp.is_running() || gate.is_active() {
            return Err(
                "another network operation became active while confirming the ARP spoof".into(),
            );
        }
        let permit = gate.acquire(super::operation_gate::ActiveOperation::LinkNeighbor)?;
        if spoof.running.swap(true, Ordering::AcqRel) {
            return Err("a lab ARP spoofing operation is already active".into());
        }
        spoof.stop.store(false, Ordering::Release);
        spoof.packets_sent.store(0, Ordering::Release);
        spoof.pairs.store(pairs.len(), Ordering::Release);
        spoof.restored_targets.store(0, Ordering::Release);
        spoof.final_elapsed_ms.store(0, Ordering::Release);
        if let Ok(mut note) = spoof.restoration_note.lock() {
            *note = None;
        }
        if let Ok(mut err) = spoof.last_error.lock() {
            *err = None;
        }
        if let Ok(mut started) = spoof.started_at.lock() {
            *started = Some(Instant::now());
        } else {
            spoof.running.store(false, Ordering::Release);
            return Err("lab ARP spoofing state registry unavailable".into());
        }
        if let Ok(mut owner) = spoof.owner.lock() {
            *owner = Some(scope.clone());
        }
        spoof.set_phase(SpoofPhase::Starting);

        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let worker_device = interface_name.clone();
        let worker_pairs = pairs.clone();
        let worker_ctx = Arc::clone(&*spoof);
        let worker_rate = rate_per_sec;
        tokio::task::spawn_blocking(move || {
            let _active_operation = permit;
            let _guard = SpoofRunGuard(Arc::clone(&worker_ctx));
            if worker_ctx.stop.load(Ordering::Acquire) {
                return;
            }
            worker_ctx.set_phase(SpoofPhase::Spoofing);
            let outcome = arp_spoof::run_arp_spoof(
                &worker_device,
                &worker_pairs,
                worker_rate,
                &worker_ctx.stop,
                &|| {
                    worker_app
                        .state::<CaseSessionCtx>()
                        .ensure(&worker_scope)
                        .is_ok()
                },
                &worker_ctx.packets_sent,
            );
            worker_ctx.final_elapsed_ms.store(
                worker_ctx
                    .started_at
                    .lock()
                    .ok()
                    .and_then(|g| *g)
                    .map(|s| s.elapsed().as_millis().min(u64::MAX as u128) as u64)
                    .unwrap_or(0),
                Ordering::Release,
            );
            match outcome {
                Ok(outcome) => {
                    worker_ctx
                        .restored_targets
                        .store(outcome.restoration.targets_restored, Ordering::Release);
                    if let Ok(mut note) = worker_ctx.restoration_note.lock() {
                        *note = Some(restoration_note_text(
                            &outcome.restoration,
                            worker_pairs.len(),
                        ));
                    }
                    if let Some(err) = outcome.error {
                        if let Ok(mut slot) = worker_ctx.last_error.lock() {
                            *slot = Some(format!("{:?}: {}", err.code, err.message));
                        }
                    }
                }
                Err(err) => {
                    if let Ok(mut slot) = worker_ctx.last_error.lock() {
                        *slot = Some(format!("{:?}: {}", err.code, err.message));
                    }
                }
            }
        });
        Ok(SpoofStartWire {
            gateway: gateway_ip.to_string(),
            targets: target_list,
            rate_per_sec,
            runtime_cap_minutes: (arp_spoof::MAX_SPOOF_RUNTIME_MS / 60_000) as u32,
            status: spoof.status_wire(),
        })
    }
}

/// Stop the running spoof. Cancellation is NEVER refused: the flag is set
/// regardless of the selected case revision, and the backend finishes with
/// the restoration pass before reporting. Returns true when a run existed.
#[tauri::command]
pub fn network_lab_spoof_stop_v1(
    spoof: State<'_, Arc<NetworkLabSpoofCtx>>,
) -> Result<bool, String> {
    if !spoof.running.load(Ordering::Acquire) {
        return Ok(false);
    }
    spoof.stop.store(true, Ordering::Release);
    // The worker owns the real transition; "stopping" keeps the UI honest
    // while restoration is still pending.
    if spoof.phase() == SpoofPhase::Spoofing || spoof.phase() == SpoofPhase::Starting {
        spoof.set_phase(SpoofPhase::Stopping);
    }
    Ok(true)
}

/// Poll the spoof's live state: honest counters only, no invented progress.
#[tauri::command]
pub fn network_lab_spoof_status_v1(
    spoof: State<'_, Arc<NetworkLabSpoofCtx>>,
) -> Result<SpoofStatusWire, String> {
    Ok(spoof.status_wire())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn report(
        gateway_known: bool,
        restored: usize,
        entries: usize,
        unknown: &[Ipv4Addr],
        packets: u64,
    ) -> arp_spoof::RestorationReport {
        arp_spoof::RestorationReport {
            packets_sent: packets,
            gateway_mac_known: gateway_known,
            targets_restored: restored,
            gateway_entries_restored: entries,
            unknown_target_macs: unknown.to_vec(),
        }
    }

    #[test]
    fn restoration_note_reports_exactly_what_was_restored_and_what_is_unknown() {
        let full = restoration_note_text(&report(true, 2, 2, &[], 4), 2);
        assert!(full.contains("restored 2/2 targets"), "{full}");
        assert!(
            full.contains("gateway cache entries re-armed: 2/2"),
            "{full}"
        );
        assert!(full.contains("unknown target MACs: none"), "{full}");
        assert!(full.contains("restoration frames sent: 4"), "{full}");
        let partial =
            restoration_note_text(&report(false, 0, 1, &[Ipv4Addr::new(10, 0, 0, 5)], 4), 2);
        assert!(partial.contains("restored 0/2 targets"), "{partial}");
        assert!(partial.contains("gateway MAC known: false"), "{partial}");
        assert!(
            partial.contains("unknown target MACs: 10.0.0.5"),
            "{partial}"
        );
    }

    #[test]
    fn phase_labels_cover_the_whole_lifecycle_in_snake_case() {
        assert_eq!(SpoofPhase::Idle.as_str(), "idle");
        assert_eq!(SpoofPhase::Starting.as_str(), "starting");
        assert_eq!(SpoofPhase::Spoofing.as_str(), "spoofing");
        assert_eq!(SpoofPhase::Stopping.as_str(), "stopping");
        assert_eq!(SpoofPhase::Stopped.as_str(), "stopped");
    }

    #[test]
    fn status_wire_starts_honest_at_zero_and_reports_after_a_run() {
        let ctx = NetworkLabSpoofCtx::default();
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "idle");
        assert_eq!(wire.packets_sent, 0);
        assert_eq!(wire.pairs, 0);
        assert_eq!(wire.elapsed_ms, 0);
        assert_eq!(wire.restored_targets, 0);
        assert!(wire.restoration_note.is_none());
        assert!(wire.last_error.is_none());
        // A finished run keeps its counters readable through the same wire.
        ctx.packets_sent.store(84, Ordering::Release);
        ctx.pairs.store(2, Ordering::Release);
        ctx.final_elapsed_ms.store(1500, Ordering::Release);
        ctx.restored_targets.store(2, Ordering::Release);
        ctx.set_phase(SpoofPhase::Stopped);
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "stopped");
        assert_eq!(wire.packets_sent, 84);
        assert_eq!(wire.pairs, 2);
        assert_eq!(wire.elapsed_ms, 1500);
        assert_eq!(wire.restored_targets, 2);
    }

    #[test]
    fn the_run_guard_publishes_stopped_and_clears_ownership() {
        let ctx = Arc::new(NetworkLabSpoofCtx::default());
        ctx.running.store(true, Ordering::Release);
        ctx.set_phase(SpoofPhase::Spoofing);
        drop(SpoofRunGuard(Arc::clone(&ctx)));
        assert!(!ctx.running.load(Ordering::Acquire));
        assert_eq!(ctx.phase(), SpoofPhase::Stopped);
        assert!(ctx.owner.lock().unwrap().is_none());
        // The case-change hook arms the flag the worker polls.
        ctx.on_case_changed();
        assert!(ctx.stop.load(Ordering::Acquire));
    }
}

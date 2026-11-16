//! Bettercap-parity DNS spoofing IPC for the Network Lab arc.
//! AUTHORIZED LAB USE ONLY, gated like the lab ARP spoof
//! (`network_lab_spoof.rs`): saved backend case, explicit operator
//! authorization, shared `NetworkOperationGate` lease (the `TcpUdp` slot —
//! DNS answering is an active UDP service, so it can never run next to
//! another active network operation), a native Yes/No confirmation dialog
//! naming EXACTLY which domains will be answered and with what address, one
//! responder per process, and a stop command that is never refused.
//!
//! The socket layer is NOT duplicated here: the pure UDP responder core
//! lives in `features/network/infrastructure/dns_spoof.rs`
//! (`dns_spoof::run_responder`), which answers ONLY the authorized domain
//! allowlist (exact + bounded `*.domain` wildcards, ≤ 16 domains) with the
//! authorized IPv4, forwards every other query to the system resolver
//! (bounded 3 s timeout, ≤ 64 concurrent forwards — a resolver, NOT a
//! transparent interceptor), rate-limits to ≤ 32 requests/s, hard-caps the
//! session at 30 minutes and keeps a bounded 512-entry request/answer log
//! that is flushed and readable on stop. Unlike the ARP spoof this module is
//! cross-platform: plain UDP needs no raw sockets, so the responder runs
//! wherever the desktop runs, and a refused bind (privileged port without
//! elevation) surfaces as an honest error instead of a platform refusal.
//!
//! Evidence persistence follows the ONE-bounded-finding-per-session pattern
//! (`network_wifi_monitor.rs`): `network_dns_spoof_evidence_save_v1` renders
//! the session header, counters and query log into one 32 KiB-bounded case
//! finding under the source tag "network.dns_spoof"; a second save refuses
//! honestly instead of duplicating case evidence.

#![allow(dead_code)] // commands are wired by the coordinator-insert main.rs registration

#[path = "../infrastructure/dns_spoof.rs"]
pub mod dns_spoof;

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

/// Evidence source key for the responder's persisted finding (the wifi
/// monitor uses "network.wifi"; the lab report uses "network.lab").
const DNS_EVIDENCE_SOURCE: &str = "network.dns_spoof";
/// Fixed finding title so case review can recognize the artifact.
const DNS_EVIDENCE_TITLE: &str = "DNS spoof responder session log";
/// The persisted finding is ONE bounded artifact per responder session.
const MAX_DNS_EVIDENCE_BYTES: usize = 32 * 1024;
const DNS_EVIDENCE_TRUNCATION_MARKER: &str =
    "\n...[truncated at the 32 KiB evidence bound]";

/// Managed per-process responder registry, mirroring `NetworkLabSpoofCtx`.
#[derive(Default)]
pub struct DnsSpoofCtx {
    running: AtomicBool,
    stop: Arc<AtomicBool>,
    phase: Mutex<DnsPhase>,
    /// One bounded evidence finding per responder session; the slot is
    /// reserved by the first save and a second save refuses.
    evidence_saved: AtomicBool,
    started_at: Mutex<Option<Instant>>,
    final_elapsed_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    owner: Mutex<Option<CaseSessionWire>>,
    /// The authorized configuration the backend validated (the UI renders it
    /// verbatim; it never re-derives the allowlist).
    config: Mutex<Option<DnsConfigSnapshot>>,
    /// Live counters + bounded log ring, updated in place by the worker.
    telemetry: Arc<dns_spoof::ResponderTelemetry>,
}

/// The backend-authorized responder configuration, snapshot for the wire.
#[derive(Debug, Clone)]
pub struct DnsConfigSnapshot {
    port: u16,
    domains: Vec<String>,
    answer_ip: String,
    upstream: String,
    rate_limit_per_sec: u32,
    runtime_cap_minutes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DnsPhase {
    #[default]
    Idle,
    Starting,
    Answering,
    Stopping,
    Stopped,
}
impl DnsPhase {
    fn as_str(self) -> &'static str {
        match self {
            DnsPhase::Idle => "idle",
            DnsPhase::Starting => "starting",
            DnsPhase::Answering => "answering",
            DnsPhase::Stopping => "stopping",
            DnsPhase::Stopped => "stopped",
        }
    }
}

impl DnsSpoofCtx {
    /// Immediate case-change hook; the worker's scope closure stays
    /// authoritative even when a caller cannot invoke this.
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// One bounded evidence finding per session: reserves the save slot
    /// (Ok exactly once) so a second save refuses honestly.
    fn reserve_evidence_slot(&self) -> Result<(), String> {
        if self.evidence_saved.swap(true, Ordering::AcqRel) {
            return Err(
                "this responder session already saved its one bounded evidence finding"
                    .into(),
            );
        }
        Ok(())
    }

    fn set_phase(&self, phase: DnsPhase) {
        if let Ok(mut guard) = self.phase.lock() {
            *guard = phase;
        }
    }

    fn phase(&self) -> DnsPhase {
        self.phase.lock().map(|g| *g).unwrap_or(DnsPhase::Idle)
    }

    fn status_wire(&self) -> DnsSpoofStatusWire {
        let config = self.config.lock().ok().and_then(|guard| guard.clone());
        let started = self.started_at.lock().ok().and_then(|guard| *guard);
        let elapsed = if started.is_some() && self.running.load(Ordering::Acquire) {
            started
                .map(|s| s.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0)
        } else {
            self.final_elapsed_ms.load(Ordering::Acquire)
        };
        let telemetry = &self.telemetry;
        DnsSpoofStatusWire {
            state: self.phase().as_str().to_string(),
            port: config.as_ref().map(|c| c.port).unwrap_or(0),
            domains: config
                .as_ref()
                .map(|c| c.domains.clone())
                .unwrap_or_default(),
            answer_ip: config
                .as_ref()
                .map(|c| c.answer_ip.clone())
                .unwrap_or_default(),
            upstream: config
                .as_ref()
                .map(|c| c.upstream.clone())
                .unwrap_or_default(),
            rate_limit_per_sec: config
                .as_ref()
                .map(|c| c.rate_limit_per_sec)
                .unwrap_or(0),
            runtime_cap_minutes: config
                .as_ref()
                .map(|c| c.runtime_cap_minutes)
                .unwrap_or(0),
            queries_seen: telemetry.queries_seen(),
            spoofed_count: telemetry.spoofed_count(),
            forwarded_count: telemetry.forwarded_count(),
            refused_count: telemetry.refused_count(),
            rate_limited_count: telemetry.rate_limited_count(),
            clients_seen: telemetry.clients_seen(),
            elapsed_ms: elapsed,
            log_entries: telemetry.log_snapshot(),
            log_dropped: telemetry.ring_dropped(),
            log_flushed: telemetry.is_flushed(),
            last_error: self.last_error.lock().ok().and_then(|guard| guard.clone()),
        }
    }
}

/// Runs for the whole worker lifetime; clears ownership and publishes the
/// final phase even when the worker panicked or the runtime dropped it.
struct DnsRunGuard(Arc<DnsSpoofCtx>);
impl Drop for DnsRunGuard {
    fn drop(&mut self) {
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
        self.0.set_phase(DnsPhase::Stopped);
    }
}

/// Wire status for `network_dns_spoof_status_v1`; snake_case field names are
/// the serde names and are mirrored verbatim by the typed frontend client.
#[derive(Debug, Clone, Serialize)]
pub struct DnsSpoofStatusWire {
    /// idle | starting | answering | stopping | stopped.
    pub state: String,
    /// The authorized UDP port (0 while idle).
    pub port: u16,
    /// The authorized allowlist (normalized lowercase; empty while idle).
    pub domains: Vec<String>,
    /// The authorized A-record answer address.
    pub answer_ip: String,
    /// The system resolver non-allowlisted queries are forwarded to.
    pub upstream: String,
    pub rate_limit_per_sec: u32,
    pub runtime_cap_minutes: u32,
    /// Every parsed query the responder saw (spoofed + forwarded inputs).
    pub queries_seen: u64,
    /// Allowlisted queries answered by THIS responder (A answers + NODATA).
    pub spoofed_count: u64,
    /// Non-allowlisted queries relayed from the upstream resolver.
    pub forwarded_count: u64,
    /// Malformed/undecodable/refused inputs (never answered or forwarded).
    pub refused_count: u64,
    /// Requests dropped by the ≤ 32/s rate limit.
    pub rate_limited_count: u64,
    /// Distinct client addresses seen this session (bounded tracking).
    pub clients_seen: usize,
    /// Elapsed wall-clock milliseconds.
    pub elapsed_ms: u64,
    /// The bounded request/answer log (oldest first, ≤ 512 entries).
    pub log_entries: Vec<dns_spoof::QueryLogEntry>,
    /// Oldest entries dropped once the ring overflowed (honest truncation).
    pub log_dropped: u64,
    /// True once the run ended and the final log flush completed.
    pub log_flushed: bool,
    pub last_error: Option<String>,
}

/// Start response: the exact allowlist/answer the backend authorized (the UI
/// never widens or re-derives them) plus the initial status.
#[derive(Debug, Clone, Serialize)]
pub struct DnsSpoofStartWire {
    pub port: u16,
    pub domains: Vec<String>,
    pub answer_ip: String,
    pub upstream: String,
    pub rate_limit_per_sec: u32,
    pub runtime_cap_minutes: u32,
    pub status: DnsSpoofStatusWire,
}

/// Receipt for `network_dns_spoof_evidence_save_v1`.
#[derive(Debug, Clone, Serialize)]
pub struct DnsSpoofEvidenceReceiptWire {
    pub case_id: String,
    pub entry_count: usize,
    pub byte_len: u64,
    pub truncated: bool,
}

fn selected_saved_case(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let case_id = scope
        .case_id
        .clone()
        .ok_or("a saved case must be selected")?;
    if case_id == "scratchpad" || case_id.trim().is_empty() {
        return Err("DNS spoof answering requires a saved, backend-selected case".into());
    }
    Ok((scope, case_id))
}

/// Flatten the pure core's typed error into the command's honest String wire
/// error (code discriminator + message, mirroring the ARP spoof pair).
fn dns_err(err: dns_spoof::DnsSpoofError) -> String {
    format!("{:?}: {}", err.code, err.message)
}

/// Parse the allowlist textarea: comma- and newline-separated entries,
/// deduplicated case-insensitively, order-preserving, ≤ 16 entries. Refusal,
/// never truncation.
fn parse_domain_list(text: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for token in text.split(|c: char| c == ',' || c == '\n' || c == '\r') {
        let value = token.trim().to_lowercase();
        if value.is_empty() {
            continue;
        }
        if !out.contains(&value) {
            out.push(value);
        }
        if out.len() > dns_spoof::MAX_DOMAINS {
            return Err(format!(
                "at most {} allowlist domains are allowed per session",
                dns_spoof::MAX_DOMAINS
            ));
        }
    }
    if out.is_empty() {
        return Err(
            "at least one allowlisted domain is required — the responder answers nothing \
             without an allowlist"
                .into(),
        );
    }
    Ok(out)
}

/// Backend confirmation is independent of the frontend checkbox: it names
/// EXACTLY what will be answered, and what will be forwarded, before the
/// socket even binds.
fn authorization_question(
    case_id: &str,
    port: u16,
    domains: &[String],
    answer_ip: &str,
    upstream: &str,
) -> String {
    format!(
        "Authorize DNS spoof answering in saved case '{case_id}'? The backend binds a UDP \
         DNS responder on port {port} and answers ONLY these {} allowlisted domain(s): {} — \
         A queries get the authorized answer {answer_ip}; other record types for those names \
         get an empty answer so the real address never leaks. Every other query is FORWARDED \
         to the system resolver at {upstream} — this responder is a resolver, not a \
         transparent interceptor, so only clients pointed at this machine are affected. \
         Requests are rate-limited to {} requests/s, every answer is logged, and the session \
         hard-caps at 30 minutes. Ports below 1024 require administrator privileges. \
         Requires permission to test this network.",
        domains.len(),
        domains.join(", "),
        dns_spoof::DEFAULT_RATE_PER_SEC,
    )
}

/// Current wall-clock in epoch milliseconds; 0 keeps the finding honest if
/// the clock is unavailable (0 is documented as unknown provenance).
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Byte-bound the rendered details on a char boundary with an honest marker
/// (same discipline as `network_wifi_monitor.rs`).
fn bound_details(details: String) -> (String, bool) {
    if details.len() <= MAX_DNS_EVIDENCE_BYTES {
        return (details, false);
    }
    let mut cap = MAX_DNS_EVIDENCE_BYTES.saturating_sub(DNS_EVIDENCE_TRUNCATION_MARKER.len());
    while cap > 0 && !details.is_char_boundary(cap) {
        cap -= 1;
    }
    let mut bounded = String::with_capacity(cap + DNS_EVIDENCE_TRUNCATION_MARKER.len());
    bounded.push_str(&details[..cap]);
    bounded.push_str(DNS_EVIDENCE_TRUNCATION_MARKER);
    (bounded, true)
}

/// The single persisted case finding: backend-constructed title, info
/// severity and the bounded artifact as details (session honesty header +
/// one query-log line per answered/refused request).
fn build_evidence_finding(
    config: Option<&DnsConfigSnapshot>,
    telemetry: &dns_spoof::ResponderTelemetry,
    generated_ms: u64,
) -> NewFinding {
    let mut details = match config {
        Some(config) => format!(
            "# DNS spoof responder session\n\nPort: {} · allowlist: {} · authorized answer: \
             {} · upstream: {}\nQueries seen: {} · spoofed answers: {} · forwarded upstream: \
             {} · refused: {} · rate-limited: {} · clients: {} · elapsed: {} ms\nGenerated \
             (unix ms): {generated_ms}\n\n## Query log (bounded ring, oldest dropped first)\n",
            config.port,
            config.domains.join(", "),
            config.answer_ip,
            config.upstream,
            telemetry.queries_seen(),
            telemetry.spoofed_count(),
            telemetry.forwarded_count(),
            telemetry.refused_count(),
            telemetry.rate_limited_count(),
            telemetry.clients_seen(),
            telemetry.log_snapshot().len(),
        ),
        None => format!(
            "# DNS spoof responder session\n\nConfiguration unavailable (idle session)\n\
             Generated (unix ms): {generated_ms}\n\n## Query log\n"
        ),
    };
    for entry in telemetry.log_snapshot() {
        details.push_str(&format!(
            "{} | {} | {} | {} | {}\n",
            entry.timestamp_ms,
            entry.client,
            entry.name,
            entry.answered_from,
            entry.answer_ip.as_deref().unwrap_or("-"),
        ));
    }
    let (bounded, _) = bound_details(details);
    NewFinding {
        title: DNS_EVIDENCE_TITLE.to_string(),
        severity: "info".into(),
        details: bounded,
    }
}

/// Start the gated DNS spoof responder: answers ONLY the authorized
/// allowlist with the authorized address (typically paired with the lab ARP
/// spoofer so LAN clients reach this machine first). Refuses without a saved
/// case, an explicit authorization, a free gate lease, an empty/malformed
/// allowlist, an unusable answer address, or a declined native confirmation.
/// A refused bind (privileged port without elevation) surfaces here as the
/// command's honest error.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn network_dns_spoof_start_v1(
    port: u16,
    domains: String,
    answer_ip: String,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    spoof: State<'_, Arc<DnsSpoofCtx>>,
) -> Result<DnsSpoofStartWire, String> {
    if !authorized {
        return Err("explicit DNS spoof responder authorization required".into());
    }
    let (scope, verified_case) = selected_saved_case(&session)?;
    if case_id != verified_case {
        return Err("request case id does not match the backend-selected case".into());
    }
    // The allowlist is the ONLY answering scope: validated on the backend
    // (exact + bounded leading wildcards, ≤ 16 entries, non-empty).
    let domain_list = parse_domain_list(&domains)?;
    let answer: Ipv4Addr = answer_ip.trim().parse().map_err(|_| {
        format!("the authorized answer must be an IPv4 address: {answer_ip}")
    })?;
    let upstream = dns_spoof::system_upstream().map_err(dns_err)?;
    let config = dns_spoof::ResponderConfig {
        bind_ip: IpAddr::from([0, 0, 0, 0]),
        port,
        domains: domain_list.clone(),
        answer_ip: answer,
        upstream,
        rate_per_sec: dns_spoof::DEFAULT_RATE_PER_SEC,
        runtime_cap_ms: dns_spoof::MAX_RUNTIME_MS,
    };
    // Full preflight (rate/cap/answer/allowlist bounds) before any state or
    // socket work; refusal, never correction.
    dns_spoof::validate_config(&config).map_err(dns_err)?;
    if spoof.running.load(Ordering::Acquire) {
        return Err("a DNS spoof responder is already active".into());
    }
    if gate.is_active() {
        return Err(
            "stop other active network scans before starting the DNS spoof responder".into(),
        );
    }
    {
        let store = evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?;
        if !store.case_exists(&verified_case)? {
            return Err("selected case does not exist".into());
        }
    }

    let question = authorization_question(
        &verified_case,
        config.port,
        &domain_list,
        &answer.to_string(),
        &upstream.to_string(),
    );
    let dialog_app = app.clone();
    let agreed = tokio::task::spawn_blocking(move || {
        dialog_app
            .dialog()
            .message(question)
            .title("Authorize DNS spoof responder")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "DNS spoof responder confirmation unavailable")?;
    if !agreed {
        return Err("DNS spoof responder cancelled by operator".into());
    }
    session.ensure(&scope)?;
    if spoof.running.load(Ordering::Acquire) || gate.is_active() {
        return Err(
            "another network operation became active while confirming the DNS spoof responder"
                .into(),
        );
    }
    // DNS answering is an ACTIVE UDP service: it takes the shared gate's
    // TcpUdp slot, so no other active network operation can run alongside it.
    let permit = gate.acquire(super::operation_gate::ActiveOperation::TcpUdp)?;
    // Bind BEFORE mutating run state: a refused privileged port surfaces as
    // the command's honest error with nothing left half-started.
    let bound = dns_spoof::bind_responder(&config).await.map_err(dns_err)?;
    if spoof.running.swap(true, Ordering::AcqRel) {
        return Err("a DNS spoof responder is already active".into());
    }
    spoof.stop.store(false, Ordering::Release);
    spoof.telemetry.reset();
    spoof.final_elapsed_ms.store(0, Ordering::Release);
    spoof.evidence_saved.store(false, Ordering::Release);
    if let Ok(mut slot) = spoof.last_error.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = spoof.config.lock() {
        *slot = Some(DnsConfigSnapshot {
            port: config.port,
            domains: domain_list.clone(),
            answer_ip: answer.to_string(),
            upstream: upstream.to_string(),
            rate_limit_per_sec: config.rate_per_sec,
            runtime_cap_minutes: (dns_spoof::MAX_RUNTIME_MS / 60_000) as u32,
        });
    } else {
        spoof.running.store(false, Ordering::Release);
        return Err("DNS spoof responder state registry unavailable".into());
    }
    if let Ok(mut slot) = spoof.started_at.lock() {
        *slot = Some(Instant::now());
    }
    if let Ok(mut slot) = spoof.owner.lock() {
        *slot = Some(scope.clone());
    }
    spoof.set_phase(DnsPhase::Starting);

    let worker_app = app.clone();
    let worker_scope = scope.clone();
    let worker_ctx = Arc::clone(&*spoof);
    let worker_stop = Arc::clone(&spoof.stop);
    let worker_telemetry = Arc::clone(&spoof.telemetry);
    let worker_config = config.clone();
    tauri::async_runtime::spawn(async move {
        let _active_operation = permit;
        let _guard = DnsRunGuard(Arc::clone(&worker_ctx));
        if worker_ctx.stop.load(Ordering::Acquire) {
            return;
        }
        worker_ctx.set_phase(DnsPhase::Answering);
        // The worker's scope closure stays authoritative: a revoked case
        // revision ends the responder honestly.
        let scope_active: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            worker_app
                .state::<CaseSessionCtx>()
                .ensure(&worker_scope)
                .is_ok()
        });
        let outcome = dns_spoof::run_responder(
            bound,
            worker_config,
            worker_stop,
            scope_active,
            worker_telemetry,
        )
        .await;
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
        if let Err(err) = outcome {
            if let Ok(mut slot) = worker_ctx.last_error.lock() {
                *slot = Some(format!("{:?}: {}", err.code, err.message));
            }
        }
    });
    Ok(DnsSpoofStartWire {
        port: config.port,
        domains: domain_list,
        answer_ip: answer.to_string(),
        upstream: upstream.to_string(),
        rate_limit_per_sec: config.rate_per_sec,
        runtime_cap_minutes: (dns_spoof::MAX_RUNTIME_MS / 60_000) as u32,
        status: spoof.status_wire(),
    })
}

/// Stop the running responder. Cancellation is NEVER refused: the flag is
/// set regardless of the selected case revision, the loop exits at its next
/// check boundary (≤ ~150 ms), the final log flush completes and the log
/// stays pollable. Returns true when a run existed.
#[tauri::command]
pub fn network_dns_spoof_stop_v1(
    spoof: State<'_, Arc<DnsSpoofCtx>>,
) -> Result<bool, String> {
    if !spoof.running.load(Ordering::Acquire) {
        return Ok(false);
    }
    spoof.stop.store(true, Ordering::Release);
    // The worker owns the real transition; "stopping" keeps the UI honest
    // while the final log flush is still pending.
    if spoof.phase() == DnsPhase::Answering || spoof.phase() == DnsPhase::Starting {
        spoof.set_phase(DnsPhase::Stopping);
    }
    Ok(true)
}

/// Poll the responder's live state: honest counters, the bounded log ring
/// and the flush flag — no invented progress.
#[tauri::command]
pub fn network_dns_spoof_status_v1(
    spoof: State<'_, Arc<DnsSpoofCtx>>,
) -> Result<DnsSpoofStatusWire, String> {
    Ok(spoof.status_wire())
}

/// Persist this responder session's request/answer log as ONE bounded
/// finding into the backend-selected saved case (source "network.dns_spoof").
/// Read-only over the session state; the only write is the one case finding.
/// Once per session: a second save refuses honestly instead of duplicating
/// case evidence.
#[tauri::command]
pub fn network_dns_spoof_evidence_save_v1(
    case_id: String,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    spoof: State<'_, Arc<DnsSpoofCtx>>,
) -> Result<DnsSpoofEvidenceReceiptWire, String> {
    let (scope, verified_case) = selected_saved_case(&session)?;
    if case_id != verified_case {
        return Err("request case id does not match the backend-selected case".into());
    }
    spoof.reserve_evidence_slot()?;
    let telemetry = &spoof.telemetry;
    if telemetry.queries_seen() == 0 && telemetry.log_snapshot().is_empty() {
        spoof.evidence_saved.store(false, Ordering::Release);
        return Err("no DNS queries were seen this session — nothing to save".into());
    }
    let config = spoof.config.lock().ok().and_then(|guard| guard.clone());
    let finding = build_evidence_finding(config.as_ref(), telemetry, unix_ms());
    let truncated = finding.details.contains(DNS_EVIDENCE_TRUNCATION_MARKER);
    let receipt = DnsSpoofEvidenceReceiptWire {
        case_id: verified_case.clone(),
        entry_count: telemetry.log_snapshot().len(),
        byte_len: finding.details.len() as u64,
        truncated,
    };
    let store = evidence
        .store
        .lock()
        .map_err(|_| "case evidence store unavailable")?;
    session.with_current_publication(&scope, || {
        store.add_findings(&verified_case, DNS_EVIDENCE_SOURCE, None, &[finding])?;
        Ok(())
    })?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicU64;

    // ---- phase machine / status honesty ------------------------------------

    #[test]
    fn phase_labels_cover_the_whole_lifecycle_in_snake_case() {
        assert_eq!(DnsPhase::Idle.as_str(), "idle");
        assert_eq!(DnsPhase::Starting.as_str(), "starting");
        assert_eq!(DnsPhase::Answering.as_str(), "answering");
        assert_eq!(DnsPhase::Stopping.as_str(), "stopping");
        assert_eq!(DnsPhase::Stopped.as_str(), "stopped");
    }

    #[test]
    fn status_wire_starts_honest_at_zero() {
        let ctx = DnsSpoofCtx::default();
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "idle");
        assert_eq!(wire.port, 0);
        assert!(wire.domains.is_empty());
        assert!(wire.answer_ip.is_empty());
        assert_eq!(wire.queries_seen, 0);
        assert_eq!(wire.spoofed_count, 0);
        assert_eq!(wire.forwarded_count, 0);
        assert_eq!(wire.refused_count, 0);
        assert_eq!(wire.rate_limited_count, 0);
        assert_eq!(wire.clients_seen, 0);
        assert_eq!(wire.elapsed_ms, 0);
        assert!(wire.log_entries.is_empty());
        assert!(!wire.log_flushed);
        assert!(wire.last_error.is_none());
    }

    #[test]
    fn status_wire_reports_the_authorized_run_verbatim() {
        let ctx = DnsSpoofCtx::default();
        if let Ok(mut slot) = ctx.config.lock() {
            *slot = Some(DnsConfigSnapshot {
                port: 5300,
                domains: vec!["lab.test".to_string(), "*.wild.test".to_string()],
                answer_ip: "10.0.0.42".to_string(),
                upstream: "10.0.0.1:53".to_string(),
                rate_limit_per_sec: dns_spoof::DEFAULT_RATE_PER_SEC,
                runtime_cap_minutes: 30,
            });
        }
        let client: SocketAddr = "127.0.0.1:53001".parse().unwrap();
        ctx.telemetry.spoof_answer(&client, "lab.test", Some("10.0.0.42".into()));
        ctx.telemetry.forward_answer(&client, "other.example", Some("203.0.113.9".into()));
        ctx.telemetry.refuse(&client, "(unparseable)");
        ctx.telemetry.rate_limit(&client, "flood.test");
        ctx.final_elapsed_ms.store(1500, Ordering::Release);
        ctx.set_phase(DnsPhase::Stopped);
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "stopped");
        assert_eq!(wire.port, 5300);
        assert_eq!(wire.domains, vec!["lab.test", "*.wild.test"]);
        assert_eq!(wire.answer_ip, "10.0.0.42");
        assert_eq!(wire.queries_seen, 0, "counters the engine owns stay engine-owned");
        assert_eq!(wire.spoofed_count, 1);
        assert_eq!(wire.forwarded_count, 1);
        assert_eq!(wire.refused_count, 1);
        assert_eq!(wire.rate_limited_count, 1);
        assert_eq!(wire.clients_seen, 1);
        assert_eq!(wire.elapsed_ms, 1500);
        assert_eq!(wire.log_entries.len(), 4);
        assert_eq!(wire.log_entries[0].answered_from, "spoof");
        assert_eq!(wire.log_entries[1].answered_from, "upstream");
        assert_eq!(wire.log_entries[1].answer_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(wire.log_entries[2].answered_from, "refused");
        assert_eq!(wire.log_entries[3].answered_from, "rate_limited");
    }

    // ---- run guard ----------------------------------------------------------

    #[test]
    fn the_run_guard_publishes_stopped_and_clears_ownership() {
        let ctx = Arc::new(DnsSpoofCtx::default());
        ctx.running.store(true, Ordering::Release);
        ctx.set_phase(DnsPhase::Answering);
        drop(DnsRunGuard(Arc::clone(&ctx)));
        assert!(!ctx.running.load(Ordering::Acquire));
        assert_eq!(ctx.phase(), DnsPhase::Stopped);
        assert!(ctx.owner.lock().unwrap().is_none());
        // The case-change hook arms the flag the worker polls.
        ctx.on_case_changed();
        assert!(ctx.stop.load(Ordering::Acquire));
    }

    // ---- evidence discipline ------------------------------------------------

    #[test]
    fn evidence_slot_allows_one_save_and_refuses_the_second() {
        let ctx = DnsSpoofCtx::default();
        ctx.reserve_evidence_slot().expect("first save reserved");
        let second = ctx.reserve_evidence_slot().unwrap_err();
        assert!(
            second.contains("already saved its one bounded evidence finding"),
            "{second}"
        );
    }

    #[test]
    fn evidence_finding_is_bounded_and_honest_about_the_session() {
        let client: SocketAddr = "127.0.0.1:53001".parse().unwrap();
        let telemetry = Arc::new(dns_spoof::ResponderTelemetry::default());
        telemetry.spoof_answer(&client, "lab.test", Some("10.0.0.42".into()));
        telemetry.forward_answer(&client, "other.example", None);
        let config = DnsConfigSnapshot {
            port: 5300,
            domains: vec!["lab.test".to_string()],
            answer_ip: "10.0.0.42".to_string(),
            upstream: "10.0.0.1:53".to_string(),
            rate_limit_per_sec: dns_spoof::DEFAULT_RATE_PER_SEC,
            runtime_cap_minutes: 30,
        };
        let finding = build_evidence_finding(Some(&config), &telemetry, 1700000000000);
        assert_eq!(finding.title, "DNS spoof responder session log");
        assert_eq!(finding.severity, "info");
        assert!(finding.details.contains("Port: 5300"), "{finding:?}");
        assert!(finding.details.contains("allowlist: lab.test"));
        assert!(finding.details.contains("authorized answer: 10.0.0.42"));
        assert!(finding.details.contains("spoofed answers: 1"));
        assert!(finding.details.contains("forwarded upstream: 1"));
        assert!(finding.details.contains("127.0.0.1 | lab.test"), "log line present");
        assert!(finding.details.contains("upstream"));
        assert!(!finding.details.contains("...[truncated"));
        // Overflow: the ring itself is capped at 512, so push beyond the 32 KiB
        // bound via very long names to prove the byte cap still holds.
        let big = Arc::new(dns_spoof::ResponderTelemetry::default());
        let long_name = format!("{}.lab.test", "x".repeat(240));
        for _ in 0..dns_spoof::MAX_LOG_ENTRIES {
            big.spoof_answer(&client, &long_name, Some("10.0.0.42".into()));
        }
        let finding = build_evidence_finding(Some(&config), &big, 1700000000000);
        assert!(finding.details.len() <= MAX_DNS_EVIDENCE_BYTES, "{}", finding.details.len());
        assert!(finding.details.contains(DNS_EVIDENCE_TRUNCATION_MARKER));
    }

    // ---- start preflight helpers --------------------------------------------

    #[test]
    fn domain_list_parsing_splits_dedupes_and_refuses_overruns() {
        let parsed =
            parse_domain_list("Lab.Test\n*.Wild.Test, lab.test,, other.test").expect("parses");
        assert_eq!(
            parsed,
            vec!["lab.test", "*.wild.test", "other.test"],
            "lowercased, deduplicated, order-preserving"
        );
        assert!(parse_domain_list("   ").is_err(), "empty list refused");
        let over: Vec<String> = (0..dns_spoof::MAX_DOMAINS + 1)
            .map(|i| format!("d{i}.test"))
            .collect();
        let err = parse_domain_list(&over.join(", ")).unwrap_err();
        assert!(err.contains("at most 16"), "{err}");
    }

    #[test]
    fn scratchpad_and_missing_cases_are_refused_by_the_saved_case_gate() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap(),
        ));
        let session = CaseSessionCtx::default();
        assert!(selected_saved_case(&session).is_err(), "nothing selected");
        session.select(&store.lock().unwrap(), "scratchpad").unwrap();
        let err = selected_saved_case(&session).unwrap_err();
        assert!(err.contains("requires a saved, backend-selected case"), "{err}");
        let saved = store.lock().unwrap().create_case("Saved", "").unwrap();
        session.select(&store.lock().unwrap(), &saved.id).unwrap();
        let (scope, case_id) = selected_saved_case(&session).expect("saved case ok");
        assert_eq!(scope.case_id.as_deref(), Some(case_id.as_str()));
    }

    #[test]
    fn authorization_question_names_exactly_what_will_be_answered_and_forwarded() {
        let question = authorization_question(
            "case-9",
            5300,
            &["lab.test".to_string(), "*.wild.test".to_string()],
            "10.0.0.42",
            "10.0.0.1:53",
        );
        assert!(question.contains("case-9"), "{question}");
        assert!(question.contains("port 5300"));
        assert!(question.contains("ONLY these 2 allowlisted domain(s)"));
        assert!(question.contains("lab.test, *.wild.test"));
        assert!(question.contains("authorized answer 10.0.0.42"));
        assert!(question.contains("FORWARDED to the system resolver at 10.0.0.1:53"));
        assert!(question.contains("not a transparent interceptor"));
        assert!(question.contains("rate-limited"));
        assert!(question.contains("30 minutes"));
        assert!(question.contains("administrator privileges"));
    }

    // ---- counter interop with the engine -------------------------------------

    #[test]
    fn telemetry_counters_reach_the_status_wire_with_engine_semantics() {
        // The IPC layer never invents counters: it reads the engine's
        // telemetry (final elapsed is computed, counts are polled).
        let ctx = DnsSpoofCtx::default();
        ctx.final_elapsed_ms.store(42, Ordering::Release);
        ctx.started_at.lock().unwrap().replace(Instant::now());
        // Not running -> elapsed comes from final_elapsed_ms, not a live timer.
        let wire = ctx.status_wire();
        assert_eq!(wire.elapsed_ms, 42);
    }
}

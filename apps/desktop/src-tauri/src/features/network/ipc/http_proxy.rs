//! Bettercap-parity gated plain-HTTP forward proxy IPC for the Network Lab
//! ("HTTP Proxy" mode). AUTHORIZED LAB USE ONLY, gated exactly like the lab
//! ARP spoof (`network_lab_spoof.rs`): saved backend case, explicit
//! `authorized` acknowledgment, shared `NetworkOperationGate` lease
//! (`ActiveOperation::TcpUdp` — proxying is an active TCP operation, so it
//! can never run next to another active network operation), a native Yes/No
//! dialog that names the listen port, the active rewrite rules, the logging
//! behavior, the honest CONNECT refusal and the allowlist disclosure, one
//! proxy per process, and a stop command that is never refused.
//!
//! The socket layer is NOT duplicated here: the bounded forward-proxy core
//! lives in `features/network/infrastructure/http_proxy.rs`
//! (`http_proxy::serve`), a pure `std::net` TCP engine (no TLS interception,
//! no new dependencies) with hard caps — ≤ 8 concurrent connections, 64 KiB
//! header caps, 1 MiB body cap, ≤ 4 KiB log excerpts, a 512-entry log ring
//! and a 30-minute runtime auto-stop — all refusals logged, never truncated.
//!
//! Evidence: ONE bounded finding per proxy session persisted under the
//! source key `network.http_proxy` through the standard case findings path
//! (same store-lock -> publication-gate order as every case finding); a
//! second save refuses honestly instead of duplicating case evidence.

#![allow(dead_code)] // commands are wired by the coordinator-insert main.rs registration

#[path = "../infrastructure/http_proxy.rs"]
pub mod http_proxy;

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::net::{IpAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use self::http_proxy::{ProxyConfig, ProxyShared, RequestLogEntry, RewriteRules};

/// Evidence source key for the proxy's persisted finding (scan findings use
/// "network.tcp"/"network.udp"; the wifi capture uses "network.wifi"; the
/// lab report uses "network.lab").
const HTTP_PROXY_EVIDENCE_SOURCE: &str = "network.http_proxy";
/// Fixed finding title so case review can recognize the artifact.
const HTTP_PROXY_EVIDENCE_TITLE: &str = "HTTP proxy session request log (plain HTTP)";
/// The persisted finding is ONE bounded artifact per proxy session.
const MAX_HTTP_PROXY_EVIDENCE_BYTES: usize = 32 * 1024;
const EVIDENCE_TRUNCATION_MARKER: &str = "\n...[truncated at the 32 KiB evidence bound]";

// ---------------------------------------------------------------------------
// Phase machine + managed state (mirrors NetworkLabSpoofCtx / NetworkWifiCtx).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ProxyPhase {
    #[default]
    Idle,
    Starting,
    Serving,
    Stopping,
    Stopped,
}
impl ProxyPhase {
    fn as_str(self) -> &'static str {
        match self {
            ProxyPhase::Idle => "idle",
            ProxyPhase::Starting => "starting",
            ProxyPhase::Serving => "serving",
            ProxyPhase::Stopping => "stopping",
            ProxyPhase::Stopped => "stopped",
        }
    }
}

/// Everything the status wire reads about the current (or last) run. Kept
/// after stop so the final counters/log stay readable — honest post-mortem.
#[derive(Clone)]
struct HttpProxyRun {
    config: ProxyConfig,
    shared: Arc<ProxyShared>,
}

/// Managed per-process proxy registry (one proxy per process).
#[derive(Default)]
pub struct NetworkHttpProxyCtx {
    running: AtomicBool,
    stop: AtomicBool,
    phase: Mutex<ProxyPhase>,
    started_at: Mutex<Option<Instant>>,
    final_elapsed_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// ONE bounded evidence finding per proxy session.
    evidence_saved: AtomicBool,
    run: Mutex<Option<HttpProxyRun>>,
    owner: Mutex<Option<CaseSessionWire>>,
}

impl NetworkHttpProxyCtx {
    /// Immediate case-change hook: a case switch revokes the run's ownership,
    /// so the accept loop stops at its next park (stop is never refused).
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
    }

    fn set_phase(&self, phase: ProxyPhase) {
        if let Ok(mut guard) = self.phase.lock() {
            *guard = phase;
        }
    }

    fn phase(&self) -> ProxyPhase {
        self.phase.lock().map(|g| *g).unwrap_or(ProxyPhase::Idle)
    }

    fn status_wire(&self) -> HttpProxyStatusWire {
        let run = self.run.lock().ok().and_then(|guard| guard.clone());
        let started = self.started_at.lock().ok().and_then(|guard| *guard);
        let elapsed = if started.is_some() && self.running.load(Ordering::Acquire) {
            started
                .map(|s| s.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0)
        } else {
            self.final_elapsed_ms.load(Ordering::Acquire)
        };
        let Some(run) = run else {
            return HttpProxyStatusWire {
                state: self.phase().as_str().to_string(),
                port: 0,
                rules: HttpProxyRulesWire::default(),
                allowlist_count: 0,
                connections: 0,
                requests: 0,
                refused_connections: 0,
                refused_busy: 0,
                refused_header_cap: 0,
                refused_body_cap: 0,
                connect_refusals: 0,
                https_target_refusals: 0,
                upstream_failures: 0,
                rewrites: HttpProxyRewriteCountsWire::default(),
                runtime_capped: false,
                elapsed_ms: elapsed,
                runtime_cap_minutes: (http_proxy::MAX_RUNTIME_MS / 60_000) as u32,
                log: Vec::new(),
                last_error: self.last_error.lock().ok().and_then(|g| g.clone()),
            };
        };
        let shared = &run.shared;
        let log = shared
            .log_snapshot()
            .into_iter()
            .map(|entry| log_entry_wire(entry))
            .collect();
        HttpProxyStatusWire {
            state: self.phase().as_str().to_string(),
            port: run.config.port,
            rules: HttpProxyRulesWire {
                rewrite_https_links: run.config.rules.rewrite_https_links,
                strip_hsts: run.config.rules.strip_hsts,
                strip_csp: run.config.rules.strip_csp,
            },
            allowlist_count: run.config.allowlist.len(),
            connections: shared.connections.load(Ordering::Acquire),
            requests: shared.requests.load(Ordering::Acquire),
            refused_connections: shared.refused_allowlist.load(Ordering::Acquire),
            refused_busy: shared.refused_busy.load(Ordering::Acquire),
            refused_header_cap: shared.refused_header_cap.load(Ordering::Acquire),
            refused_body_cap: shared.refused_body_cap.load(Ordering::Acquire),
            connect_refusals: shared.connect_refusals.load(Ordering::Acquire),
            https_target_refusals: shared.https_target_refusals.load(Ordering::Acquire),
            upstream_failures: shared.upstream_failures.load(Ordering::Acquire),
            rewrites: HttpProxyRewriteCountsWire {
                https_links: shared.rewrites_https_links.load(Ordering::Acquire),
                hsts_stripped: shared.rewrites_hsts_stripped.load(Ordering::Acquire),
                csp_stripped: shared.rewrites_csp_stripped.load(Ordering::Acquire),
            },
            runtime_capped: shared.runtime_capped.load(Ordering::Acquire),
            elapsed_ms: elapsed,
            runtime_cap_minutes: (http_proxy::MAX_RUNTIME_MS / 60_000) as u32,
            log,
            last_error: self.last_error.lock().ok().and_then(|g| g.clone()),
        }
    }
}

/// Runs for the whole worker lifetime; clears ownership and publishes the
/// final phase even when the worker panicked or the runtime dropped it.
struct ProxyRunGuard(Arc<NetworkHttpProxyCtx>);
impl Drop for ProxyRunGuard {
    fn drop(&mut self) {
        if let Ok(mut owner) = self.0.owner.lock() {
            *owner = None;
        }
        self.0.running.store(false, Ordering::Release);
        self.0.set_phase(ProxyPhase::Stopped);
    }
}

// ---------------------------------------------------------------------------
// Wire types (snake_case serde names, mirrored verbatim by lib/ipc.ts).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct HttpProxyRulesWire {
    pub rewrite_https_links: bool,
    pub strip_hsts: bool,
    pub strip_csp: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct HttpProxyRewriteCountsWire {
    pub https_links: u64,
    pub hsts_stripped: u64,
    pub csp_stripped: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpProxyLogEntryWire {
    pub ts_ms: u64,
    pub client: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub content_length: Option<u64>,
    pub excerpt: String,
    pub request_headers: String,
    pub response_headers: String,
    pub rewrites_https_links: usize,
    pub rewrites_hsts_stripped: usize,
    pub rewrites_csp_stripped: usize,
    pub note: Option<String>,
}

fn log_entry_wire(entry: RequestLogEntry) -> HttpProxyLogEntryWire {
    HttpProxyLogEntryWire {
        ts_ms: entry.ts_ms,
        client: entry.client,
        method: entry.method,
        host: entry.host,
        path: entry.path,
        status: entry.status,
        content_length: entry.content_length,
        excerpt: entry.excerpt,
        request_headers: entry.request_headers,
        response_headers: entry.response_headers,
        rewrites_https_links: entry.rewrites.https_links,
        rewrites_hsts_stripped: entry.rewrites.hsts_stripped,
        rewrites_csp_stripped: entry.rewrites.csp_stripped,
        note: entry.note,
    }
}

/// Live proxy state for `network_http_proxy_status_v1`: phase machine,
/// honest counters, per-rule rewrite counts, the bounded log ring and the
/// last error — no invented progress anywhere.
#[derive(Debug, Clone, Serialize)]
pub struct HttpProxyStatusWire {
    /// idle | starting | serving | stopping | stopped.
    pub state: String,
    /// Configured listen port (0 = no run yet).
    pub port: u16,
    pub rules: HttpProxyRulesWire,
    /// Allowlist size this run was started with (0 = any client).
    pub allowlist_count: usize,
    pub connections: u64,
    pub requests: u64,
    /// Peers refused by the allowlist.
    pub refused_connections: u64,
    /// Connections refused at the 8-connection cap.
    pub refused_busy: u64,
    /// Request heads refused at the 64 KiB cap.
    pub refused_header_cap: u64,
    /// Bodies refused at the 1 MiB cap (either side).
    pub refused_body_cap: u64,
    /// CONNECT attempts refused (plain-HTTP honesty).
    pub connect_refusals: u64,
    /// https:// absolute-URI targets refused.
    pub https_target_refusals: u64,
    pub upstream_failures: u64,
    pub rewrites: HttpProxyRewriteCountsWire,
    /// True when the run ended at the 30-minute runtime cap.
    pub runtime_capped: bool,
    pub elapsed_ms: u64,
    pub runtime_cap_minutes: u32,
    /// The bounded request log (≤ 512 entries, oldest first).
    pub log: Vec<HttpProxyLogEntryWire>,
    pub last_error: Option<String>,
}

/// Start response: the exact port/rules the backend authorized plus the
/// initial status (the UI never re-derives them).
#[derive(Debug, Clone, Serialize)]
pub struct HttpProxyStartWire {
    pub port: u16,
    pub active_rules: Vec<String>,
    pub allowlist_count: usize,
    pub runtime_cap_minutes: u32,
    pub status: HttpProxyStatusWire,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpProxyEvidenceReceiptWire {
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
        return Err("lab HTTP proxying requires a saved, backend-selected case".into());
    }
    Ok((scope, case_id))
}

// ---------------------------------------------------------------------------
// Backend-rendered honest copy (pure, so tests pin the exact wording).
// ---------------------------------------------------------------------------

/// The native dialog text: names EXACTLY what will run — port, logging
/// behavior, the active rewrite rules (or the all-off default), the honest
/// CONNECT refusal, the allowlist disclosure and the runtime cap — before
/// the listener is spawned.
fn build_dialog_question(config: &ProxyConfig, case_id: &str) -> String {
    let active = config.rules.active_names();
    let rules_text = if active.is_empty() {
        "none — every rewrite rule is OFF by default".to_string()
    } else {
        active.join("; ")
    };
    let allowlist_text = if config.allowlist.is_empty() {
        "the client allowlist is EMPTY, so ANY client that can reach this machine \
         (the whole LAN) may use the proxy"
            .to_string()
    } else {
        format!(
            "the client allowlist restricts use to {} client IP(s)",
            config.allowlist.len()
        )
    };
    format!(
        "Authorize a plain-HTTP forward proxy for saved case '{case_id}'? \
         It will listen on 0.0.0.0:{port} and forward HTTP/1.1 requests for testing purposes. \
         Logging: full request and response headers plus a 4 KiB response excerpt per request, \
         kept in a bounded 512-entry log. Rewrite rules active: {rules_text}. \
         CONNECT is refused: {connect}. {allowlist}. \
         Hard 30-minute runtime cap; Stop is always available. \
         Requires permission to test this network.",
        port = config.port,
        connect = http_proxy::CONNECT_REFUSAL,
        allowlist = allowlist_text,
    )
}

/// Parse the allowlist entries (each must be an IP literal; cap enforced by
/// `ProxyConfig::build`).
fn parse_allowlist(entries: &[String]) -> Result<Vec<IpAddr>, String> {
    entries
        .iter()
        .map(|entry| {
            entry.trim().parse::<IpAddr>().map_err(|_| {
                format!("allowlist entry is not an IP address: {entry}")
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

/// Start the gated plain-HTTP forward proxy. Refuses without a saved case,
/// explicit authorization, a free gate lease, a valid port (1024..=65535)
/// or a declined native confirmation; binds the listener before spawning the
/// worker so port conflicts fail honestly right here.
#[tauri::command]
pub async fn network_http_proxy_start_v1(
    port: u16,
    rewrite_https_links: bool,
    strip_hsts: bool,
    strip_csp: bool,
    allowlist: Vec<String>,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    proxy: State<'_, Arc<NetworkHttpProxyCtx>>,
) -> Result<HttpProxyStartWire, String> {
    if !authorized {
        return Err("explicit lab HTTP proxy authorization required".into());
    }
    let (scope, verified_case) = selected_saved_case(&session)?;
    if case_id != verified_case {
        return Err("request case id does not match the backend-selected case".into());
    }
    if gate.is_active() {
        return Err("stop other active network scans before starting the lab HTTP proxy".into());
    }
    let rules = RewriteRules {
        rewrite_https_links,
        strip_hsts,
        strip_csp,
    };
    let allow_ips = parse_allowlist(&allowlist)?;
    let config = ProxyConfig::build(port, rules, allow_ips)?;
    {
        let store = evidence
            .store
            .lock()
            .map_err(|_| "case store unavailable")?;
        if !store.case_exists(&verified_case)? {
            return Err("selected case does not exist".into());
        }
    }

    // Backend confirmation is independent of the frontend checkbox: it names
    // EXACTLY what will run before the listener is spawned.
    let question = build_dialog_question(&config, &verified_case);
    let dialog_app = app.clone();
    let agreed = tokio::task::spawn_blocking(move || {
        dialog_app
            .dialog()
            .message(question)
            .title("Authorize lab HTTP proxy")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "lab HTTP proxy confirmation unavailable")?;
    if !agreed {
        return Err("lab HTTP proxy cancelled by operator".into());
    }
    session.ensure(&scope)?;
    if gate.is_active() {
        return Err(
            "another network operation became active while confirming the HTTP proxy".into(),
        );
    }
    // Bind here so a port conflict fails as an honest command error instead
    // of a silent worker death; the listener is handed to the worker owned.
    let listener = TcpListener::bind(("0.0.0.0", config.port))
        .map_err(|err| format!("proxy listen on 0.0.0.0:{} failed: {err}", config.port))?;

    // Proxying is an active TCP operation: take the shared gate lease.
    let permit = gate.acquire(super::operation_gate::ActiveOperation::TcpUdp)?;
    if proxy.running.swap(true, Ordering::AcqRel) {
        return Err("a lab HTTP proxy operation is already active".into());
    }
    let shared = Arc::new(ProxyShared::default());
    proxy.stop.store(false, Ordering::Release);
    proxy.evidence_saved.store(false, Ordering::Release);
    proxy.final_elapsed_ms.store(0, Ordering::Release);
    if let Ok(mut err) = proxy.last_error.lock() {
        *err = None;
    }
    if let Ok(mut started) = proxy.started_at.lock() {
        *started = Some(Instant::now());
    } else {
        proxy.running.store(false, Ordering::Release);
        return Err("lab HTTP proxy state registry unavailable".into());
    }
    if let Ok(mut run) = proxy.run.lock() {
        *run = Some(HttpProxyRun {
            config: config.clone(),
            shared: Arc::clone(&shared),
        });
    }
    if let Ok(mut owner) = proxy.owner.lock() {
        *owner = Some(scope.clone());
    }
    proxy.set_phase(ProxyPhase::Starting);

    let worker_ctx = Arc::clone(&*proxy);
    let worker_config = config.clone();
    let worker_shared = Arc::clone(&shared);
    tokio::task::spawn_blocking(move || {
        let _active_operation = permit;
        let _guard = ProxyRunGuard(Arc::clone(&worker_ctx));
        if worker_ctx.stop.load(Ordering::Acquire) {
            return;
        }
        worker_ctx.set_phase(ProxyPhase::Serving);
        let started = worker_ctx
            .started_at
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .unwrap_or_else(Instant::now);
        http_proxy::serve(
            listener,
            &worker_config,
            started,
            &worker_ctx.stop,
            &worker_shared,
            http_proxy::MAX_RUNTIME_MS,
        );
        worker_ctx.final_elapsed_ms.store(
            worker_ctx
                .started_at
                .lock()
                .ok()
                .and_then(|guard| *guard)
                .map(|s| s.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0),
            Ordering::Release,
        );
    });
    Ok(HttpProxyStartWire {
        port: config.port,
        active_rules: config.rules.active_names().into_iter().map(String::from).collect(),
        allowlist_count: config.allowlist.len(),
        runtime_cap_minutes: (http_proxy::MAX_RUNTIME_MS / 60_000) as u32,
        status: proxy.status_wire(),
    })
}

/// Stop the running proxy. Cancellation is NEVER refused: the flag is set
/// regardless of the selected case revision, the accept loop exits at its
/// next park (≤ 20 ms later), in-flight bounded connections drain, and the
/// final counters/log stay readable. Returns true when a run existed.
#[tauri::command]
pub fn network_http_proxy_stop_v1(
    proxy: State<'_, Arc<NetworkHttpProxyCtx>>,
) -> Result<bool, String> {
    if !proxy.running.load(Ordering::Acquire) {
        return Ok(false);
    }
    proxy.stop.store(true, Ordering::Release);
    if matches!(proxy.phase(), ProxyPhase::Starting | ProxyPhase::Serving) {
        proxy.set_phase(ProxyPhase::Stopping);
    }
    Ok(true)
}

/// Poll the proxy's live state: honest counters only, no invented progress.
#[tauri::command]
pub fn network_http_proxy_status_v1(
    proxy: State<'_, Arc<NetworkHttpProxyCtx>>,
) -> Result<HttpProxyStatusWire, String> {
    Ok(proxy.status_wire())
}

// ---------------------------------------------------------------------------
// Evidence save: ONE bounded case finding per proxy session, persisted
// through the standard evidence path (same store-lock -> publication-gate
// order as every case finding).
// ---------------------------------------------------------------------------

/// Byte-bound the rendered details on a char boundary with an honest marker.
fn bound_details(details: String) -> (String, bool) {
    if details.len() <= MAX_HTTP_PROXY_EVIDENCE_BYTES {
        return (details, false);
    }
    let mut cap = MAX_HTTP_PROXY_EVIDENCE_BYTES.saturating_sub(EVIDENCE_TRUNCATION_MARKER.len());
    while cap > 0 && !details.is_char_boundary(cap) {
        cap -= 1;
    }
    let mut bounded = String::with_capacity(cap + EVIDENCE_TRUNCATION_MARKER.len());
    bounded.push_str(&details[..cap]);
    bounded.push_str(EVIDENCE_TRUNCATION_MARKER);
    (bounded, true)
}

/// The single persisted case finding: session honesty header (port, rules,
/// counters) plus one bounded summary line per logged request. Excerpts and
/// raw headers stay in the in-memory log; the case artifact is the bounded
/// request summary.
fn build_evidence_finding(
    config: &ProxyConfig,
    entries: &[RequestLogEntry],
    generated_ms: u64,
) -> NewFinding {
    let active = config.rules.active_names();
    let rules_text = if active.is_empty() {
        "none (all OFF by default)".to_string()
    } else {
        active.join("; ")
    };
    let mut details = format!(
        "# HTTP proxy session request log (plain HTTP)\n\nListen port: {} · rewrite rules: \
         {} · client allowlist: {} entr{} · logged requests: {}\nGenerated (unix ms): \
         {generated_ms}\n\n## Requests (time · client · method host path · status · \
         rewrites)\n",
        config.port,
        rules_text,
        config.allowlist.len(),
        if config.allowlist.len() == 1 { "y" } else { "ies" },
        entries.len(),
    );
    for entry in entries {
        let line = format!(
            "- {} · {} · {} {}{} · {} · rewrites https->http:{} hsts:{} csp:{}{}\n",
            entry.ts_ms,
            entry.client,
            entry.method,
            entry.host,
            entry.path,
            entry.status,
            entry.rewrites.https_links,
            entry.rewrites.hsts_stripped,
            entry.rewrites.csp_stripped,
            entry
                .note
                .as_ref()
                .map(|note| format!(" · note: {note}"))
                .unwrap_or_default(),
        );
        if details.len() + line.len() > MAX_HTTP_PROXY_EVIDENCE_BYTES {
            details.push_str(EVIDENCE_TRUNCATION_MARKER);
            details.push('\n');
            break;
        }
        details.push_str(&line);
    }
    let (bounded, _) = bound_details(details);
    NewFinding {
        title: HTTP_PROXY_EVIDENCE_TITLE.to_string(),
        severity: "info".into(),
        details: bounded,
    }
}

/// Current wall-clock in epoch milliseconds; 0 keeps the finding honest if
/// the clock is unavailable (0 is documented as unknown provenance).
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Persist this proxy session's request log as ONE bounded finding into the
/// backend-selected saved case. Read-only over the log; the only write is
/// the one case finding. Once per session: a second save refuses honestly
/// instead of duplicating case evidence.
#[tauri::command]
pub fn network_http_proxy_evidence_save_v1(
    case_id: String,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    proxy: State<'_, Arc<NetworkHttpProxyCtx>>,
) -> Result<HttpProxyEvidenceReceiptWire, String> {
    let (scope, verified_case) = selected_saved_case(&session)?;
    if case_id != verified_case {
        return Err("request case id does not match the backend-selected case".into());
    }
    if proxy.evidence_saved.swap(true, Ordering::AcqRel) {
        return Err(
            "this proxy session already saved its one bounded evidence finding".into(),
        );
    }
    let run = proxy
        .run
        .lock()
        .map_err(|_| "lab HTTP proxy state registry unavailable")?
        .clone();
    let Some(run) = run else {
        proxy.evidence_saved.store(false, Ordering::Release);
        return Err("no proxy session has run yet — nothing to save".into());
    };
    let entries = run.shared.log_snapshot();
    if entries.is_empty() {
        proxy.evidence_saved.store(false, Ordering::Release);
        return Err("no proxied requests logged this session — nothing to save".into());
    }
    let finding = build_evidence_finding(&run.config, &entries, unix_ms());
    let truncated = finding.details.contains(EVIDENCE_TRUNCATION_MARKER);
    let receipt = HttpProxyEvidenceReceiptWire {
        case_id: verified_case.clone(),
        entry_count: entries.len(),
        byte_len: finding.details.len() as u64,
        truncated,
    };
    let store = evidence
        .store
        .lock()
        .map_err(|_| "case evidence store unavailable")?;
    session.with_current_publication(&scope, || {
        store.add_findings(&verified_case, HTTP_PROXY_EVIDENCE_SOURCE, None, &[finding])?;
        Ok(())
    })?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use self::http_proxy::{RewriteCounts, MAX_LOG_ENTRIES};

    fn run_with(entries: usize) -> HttpProxyRun {
        let config = ProxyConfig::build(
            8080,
            RewriteRules {
                rewrite_https_links: true,
                strip_hsts: false,
                strip_csp: true,
            },
            vec!["10.0.0.5".parse().unwrap()],
        )
        .expect("config");
        let shared = Arc::new(ProxyShared::default());
        for i in 0..entries {
            let mut entry = RequestLogEntry {
                ts_ms: 1700000000000 + i as u64,
                client: "127.0.0.1".into(),
                method: "GET".into(),
                host: "target.test".into(),
                path: format!("/p{i}"),
                status: 200,
                content_length: Some(42),
                excerpt: "hello".into(),
                request_headers: "Host: target.test\r\n".into(),
                response_headers: "Content-Type: text/html\r\n".into(),
                rewrites: RewriteCounts {
                    https_links: 1,
                    hsts_stripped: 0,
                    csp_stripped: 1,
                },
                note: None,
            };
            entry.path = format!("/p{i}");
            shared.push_log(entry);
        }
        shared
            .requests
            .store(entries as u64, Ordering::Release);
        shared
            .rewrites_https_links
            .store(entries as u64, Ordering::Release);
        HttpProxyRun { config, shared }
    }

    #[test]
    fn phase_labels_cover_the_whole_lifecycle_in_snake_case() {
        assert_eq!(ProxyPhase::Idle.as_str(), "idle");
        assert_eq!(ProxyPhase::Starting.as_str(), "starting");
        assert_eq!(ProxyPhase::Serving.as_str(), "serving");
        assert_eq!(ProxyPhase::Stopping.as_str(), "stopping");
        assert_eq!(ProxyPhase::Stopped.as_str(), "stopped");
    }

    #[test]
    fn status_wire_starts_honest_at_zero_before_any_run() {
        let ctx = NetworkHttpProxyCtx::default();
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "idle");
        assert_eq!(wire.port, 0);
        assert_eq!(wire.connections, 0);
        assert_eq!(wire.requests, 0);
        assert_eq!(wire.connect_refusals, 0);
        assert_eq!(wire.rewrites.https_links, 0);
        assert_eq!(wire.runtime_cap_minutes, 30);
        assert!(wire.log.is_empty());
        assert!(wire.last_error.is_none());
        assert!(!wire.runtime_capped);
    }

    #[test]
    fn status_wire_reports_the_configured_run_and_its_log() {
        let ctx = NetworkHttpProxyCtx::default();
        let run = run_with(3);
        *ctx.run.lock().unwrap() = Some(run);
        ctx.set_phase(ProxyPhase::Serving);
        ctx.final_elapsed_ms.store(1500, Ordering::Release);
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "serving");
        assert_eq!(wire.port, 8080);
        assert!(wire.rules.rewrite_https_links);
        assert!(!wire.rules.strip_hsts);
        assert!(wire.rules.strip_csp);
        assert_eq!(wire.allowlist_count, 1);
        assert_eq!(wire.requests, 3);
        assert_eq!(wire.elapsed_ms, 1500);
        assert_eq!(wire.log.len(), 3);
        let entry = &wire.log[0];
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.host, "target.test");
        assert_eq!(entry.path, "/p0");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.content_length, Some(42));
        assert_eq!(entry.rewrites_https_links, 1);
        assert_eq!(entry.rewrites_csp_stripped, 1);
    }

    #[test]
    fn the_run_guard_publishes_stopped_and_clears_ownership() {
        let ctx = Arc::new(NetworkHttpProxyCtx::default());
        ctx.running.store(true, Ordering::Release);
        ctx.set_phase(ProxyPhase::Serving);
        drop(ProxyRunGuard(Arc::clone(&ctx)));
        assert!(!ctx.running.load(Ordering::Acquire));
        assert_eq!(ctx.phase(), ProxyPhase::Stopped);
        assert!(ctx.owner.lock().unwrap().is_none());
        // The case-change hook arms the flag the accept loop polls.
        ctx.on_case_changed();
        assert!(ctx.stop.load(Ordering::Acquire));
    }

    #[test]
    fn dialog_copy_names_port_logging_rewrites_connect_refusal_and_allowlist() {
        let off = ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("cfg");
        let text = build_dialog_question(&off, "case-42");
        assert!(text.contains("0.0.0.0:8080"), "{text}");
        assert!(text.contains("case-42"), "{text}");
        assert!(text.contains("full request and response headers"), "{text}");
        assert!(text.contains("4 KiB response excerpt"), "{text}");
        assert!(text.contains("512-entry log"), "{text}");
        assert!(text.contains("none — every rewrite rule is OFF by default"), "{text}");
        assert!(text.contains(http_proxy::CONNECT_REFUSAL), "{text}");
        assert!(text.contains("ANY client that can reach this machine"), "{text}");
        assert!(text.contains("Hard 30-minute runtime cap"), "{text}");
        assert!(text.contains("Stop is always available"), "{text}");
        // With rules ON, each one is named; a set allowlist is disclosed too.
        let on = ProxyConfig::build(
            9090,
            RewriteRules {
                rewrite_https_links: true,
                strip_hsts: true,
                strip_csp: true,
            },
            vec!["10.0.0.5".parse().unwrap()],
        )
        .expect("cfg");
        let text = build_dialog_question(&on, "case-7");
        assert!(text.contains("rewrite https:// links to http://"), "{text}");
        assert!(text.contains("strip Strict-Transport-Security"), "{text}");
        assert!(text.contains("strip Content-Security-Policy"), "{text}");
        assert!(text.contains("allowlist restricts use to 1 client IP(s)"), "{text}");
    }

    #[test]
    fn allowlist_parsing_refuses_non_ip_entries() {
        assert!(parse_allowlist(&["10.0.0.5".into(), "192.168.1.9".into()]).is_ok());
        assert!(parse_allowlist(&["router.local".into()]).is_err());
        assert!(parse_allowlist(&["10.0.0.0/24".into()]).is_err());
        assert_eq!(parse_allowlist(&[]).unwrap().len(), 0);
    }

    #[test]
    fn evidence_finding_is_one_bounded_artifact_with_honest_truncation() {
        let config = ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("cfg");
        let entries: Vec<RequestLogEntry> = (0..4)
            .map(|i| RequestLogEntry {
                ts_ms: 1700000000000 + i,
                client: "192.168.1.20".into(),
                method: "GET".into(),
                host: "target.test".into(),
                path: format!("/p{i}"),
                status: 200,
                content_length: Some(10),
                excerpt: String::new(),
                request_headers: String::new(),
                response_headers: String::new(),
                rewrites: RewriteCounts {
                    https_links: 2,
                    hsts_stripped: 1,
                    csp_stripped: 0,
                },
                note: None,
            })
            .collect();
        let finding = build_evidence_finding(&config, &entries, 1700000000999);
        assert_eq!(finding.title, HTTP_PROXY_EVIDENCE_TITLE);
        assert_eq!(finding.severity, "info");
        assert!(finding.details.contains("Listen port: 8080"), "{}", finding.details);
        assert!(finding.details.contains("none (all OFF by default)"));
        assert!(finding.details.contains("- 1700000000000 · 192.168.1.20 · GET target.test/p0 · 200 · rewrites https->http:2 hsts:1 csp:0"));
        assert!(finding.details.len() <= MAX_HTTP_PROXY_EVIDENCE_BYTES);
        assert!(!finding.details.contains(EVIDENCE_TRUNCATION_MARKER));
        // Over-long sessions truncate honestly at the char boundary.
        let long: Vec<RequestLogEntry> = (0..600)
            .map(|_i| RequestLogEntry {
                ts_ms: 1,
                client: "c".into(),
                method: "GET".into(),
                host: "h".into(),
                path: format!("/{}", "x".repeat(120)),
                status: 200,
                content_length: None,
                excerpt: String::new(),
                request_headers: String::new(),
                response_headers: String::new(),
                rewrites: RewriteCounts::default(),
                note: Some("n".repeat(160)),
            })
            .collect();
        let finding = build_evidence_finding(&config, &long, 1);
        assert!(finding.details.len() <= MAX_HTTP_PROXY_EVIDENCE_BYTES);
        assert!(finding.details.contains(EVIDENCE_TRUNCATION_MARKER));
    }

    #[test]
    fn evidence_save_is_once_per_session_by_atomic_flag() {
        // The one-save gate mirrors the wifi slice: swap wins exactly once;
        // refusals reset the flag so an honest failure is still retryable.
        let ctx = NetworkHttpProxyCtx::default();
        assert!(!ctx.evidence_saved.swap(true, Ordering::AcqRel));
        assert!(ctx.evidence_saved.swap(true, Ordering::AcqRel));
        ctx.evidence_saved.store(false, Ordering::Release);
        assert!(!ctx.evidence_saved.load(Ordering::Acquire));
    }

    #[test]
    fn log_ring_bound_is_carried_by_the_engine_not_the_wire() {
        // The wire maps at most the engine's ring: 512 entries, no more.
        assert_eq!(MAX_LOG_ENTRIES, 512);
        let run = run_with(MAX_LOG_ENTRIES + 10);
        let wire = {
            let ctx = NetworkHttpProxyCtx::default();
            *ctx.run.lock().unwrap() = Some(run);
            ctx.status_wire()
        };
        assert_eq!(wire.log.len(), MAX_LOG_ENTRIES);
    }
}

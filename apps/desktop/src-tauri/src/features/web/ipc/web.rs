//! Web studio backend (§5.2): HTTP sender, native review scanner, spider,
//! HTTP-only proxy, and sidecar slots for nikto/sqlmap/XSStrike.

use std::sync::{atomic::Ordering, Arc};
use tauri::State;

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{
    atomic::{AtomicBool, AtomicU16, AtomicU64},
    Mutex,
};
#[cfg(test)]
use std::time::Duration;

#[path = "../infrastructure/history.rs"]
mod webhistory;

#[path = "../domain/proxy_policy.rs"]
mod proxy_policy_domain;
#[path = "../domain/proxy_rules.rs"]
mod proxy_rules_domain;
#[path = "../domain/request.rs"]
mod request_domain;
#[path = "../domain/scan.rs"]
mod scan_domain;

use proxy_policy_domain::{is_hop_header_for_message, parse_connect_target, tls_host_matches};
use proxy_rules_domain::apply_rules;
#[cfg(test)]
use proxy_rules_domain::replace_bytes_limited;
pub use proxy_rules_domain::{MatchReplaceRule, MAX_PROXY_BODY};

pub use request_domain::parse_raw_request;
#[path = "../infrastructure/client.rs"]
mod client_infrastructure;
#[path = "../application/crawl.rs"]
mod crawl_application;
#[path = "../infrastructure/engine.rs"]
mod engine_infrastructure;
#[path = "../infrastructure/forward.rs"]
mod forward_infrastructure;
#[path = "../application/proxy.rs"]
mod proxy_application;
#[path = "../application/proxy_state.rs"]
mod proxy_state_application;
#[path = "../infrastructure/proxy_stream.rs"]
mod proxy_stream_infrastructure;
#[path = "../infrastructure/proxy_transport.rs"]
mod proxy_transport_infrastructure;
#[path = "../application/repeater.rs"]
mod repeater_application;
#[path = "../application/scan.rs"]
mod scan_application;
#[path = "../infrastructure/websocket.rs"]
mod websocket_infrastructure;
use forward_infrastructure::execute_request;
#[cfg(test)]
use forward_infrastructure::execute_request_with_client;
use proxy_application::{now_ms, proxy_status_inner, push_capture, reason_phrase};
pub use proxy_state_application::{PendingRequest, ProxyShared, WebCtx};
pub use proxy_stream_infrastructure::ProxyStream;
#[cfg(test)]
use proxy_transport_infrastructure::connect_tunnel_with_ws_connector;
use proxy_transport_infrastructure::handle_conn;
use websocket_infrastructure::{
    is_websocket_switching_protocols, read_http_response_head, relay_upgrade_rejection_body,
    relay_ws_counted, websocket_accept_matches,
};
#[path = "dto.rs"]
mod web_wire;
pub use web_wire::{
    CapturedRequest, EngineScanResult, HttpResponseWire, PendingWire, ProxyStatusWire,
    WebEngineStatus, WsConnectionWire,
};

use client_infrastructure::http_client;

#[cfg(test)]
use crawl_application::{extract_hrefs, resolve_scoped_link};
pub use scan_domain::Finding;
#[cfg(test)]
use scan_domain::{confirmed_exposure, require_authorization, session_cookie_findings};

const MAX_CAPTURED_REQUESTS: usize = 10_000;
const MAX_PENDING_REQUESTS: usize = 100;

/// Integration-only API: Agent6 supplies a grant minted from Agent5's
/// *server-owned*, case-existence-verified policy after explicit user consent.
/// This is never callable from an unregistered caller-owned IPC boolean.
pub(crate) fn bind_backend_case_capture(
    policy: Arc<std::sync::Mutex<cyberdeck_storage::ActiveCaseHistoryPolicy>>,
    grant: cyberdeck_storage::HistoryCaptureGrant,
) -> Result<u64, String> {
    webhistory::arm_backend_capture(policy, grant)
}

pub(crate) fn revoke_backend_case_capture() {
    webhistory::clear_session();
}

/// Backend-authorized history body reveal (requires a separately verified
/// user-confirmed reveal action in Agent6's state, not an IPC bool alone).
pub(crate) fn case_history_authorized_detail(
    grant: &cyberdeck_storage::HistoryCaptureGrant,
    permit: cyberdeck_storage::HistoryRevealPermit,
    id: u64,
) -> Result<Option<webhistory::Detail>, String> {
    webhistory::read_detail_authorized(grant, permit, id)
}

/// Replays a *logical* original or post-edit message with exact binary body.
/// Refuses truncated history and rechecks the active backend grant. Outbound
/// HTTP headers/framing will still be normalized by reqwest.
pub(crate) async fn replay_authorized_case_message(
    grant: &cyberdeck_storage::HistoryCaptureGrant,
    permit: cyberdeck_storage::HistoryRevealPermit,
    id: u64,
    forwarded: bool,
) -> Result<HttpResponseWire, String> {
    let request = webhistory::replay_draft_authorized(grant, permit, id, forwarded)?;
    repeater_application::send_binary(request).await
}

/// Send an editable raw request using the native Repeater service.
#[tauri::command]
pub async fn http_send(request_raw: String) -> Result<HttpResponseWire, String> {
    repeater_application::send(request_raw).await
}

// --- Native web review: thin IPC over feature-first application services ----

#[tauri::command]
pub async fn web_scan(target_url: String, authorized: bool) -> Result<Vec<Finding>, String> {
    scan_application::run_scan(&http_client(), target_url, authorized).await
}

#[tauri::command]
pub async fn spider_scan(
    target_url: String,
    max_depth: u8,
    authorized: bool,
) -> Result<Vec<String>, String> {
    crawl_application::run_spider(&http_client(), target_url, max_depth, authorized).await
}

#[cfg(test)]
#[path = "../tests/scope.rs"]
mod scope_tests;

// --- HTTP interception proxy ---------------------------------------------------

/// Start a localhost proxy session with a persistent per-install CA.
#[tauri::command]
pub async fn proxy_start(
    app: tauri::AppHandle,
    port: u16,
    ctx: State<'_, WebCtx>,
) -> Result<ProxyStatusWire, String> {
    if port == 0 {
        return Err("proxy port must be between 1 and 65535".to_string());
    }
    if ctx.shared.running.load(Ordering::Relaxed) {
        return Err("proxy already running; stop it first".to_string());
    }
    let ca_dir = crate::features::cases::infrastructure::storage_paths::data_dir(&app)?;
    proxy_application::start_proxy(port, &ctx, &ca_dir).await
}

#[tauri::command]
pub async fn proxy_stop(ctx: State<'_, WebCtx>) -> Result<ProxyStatusWire, String> {
    proxy_application::stop_proxy(&ctx).await
}

#[tauri::command]
pub fn proxy_status(ctx: State<'_, WebCtx>) -> ProxyStatusWire {
    proxy_status_inner(&ctx)
}

/// Capture is disabled by default. The integration owner must verify
/// the active case and collect consent before registering this IPC command.
#[tauri::command]
pub fn proxy_history_capture_configure(
    case_id: Option<String>,
    consent: bool,
) -> Result<bool, String> {
    if !consent {
        webhistory::clear_session();
        return Ok(false);
    }
    let case_id = case_id
        .as_deref()
        .ok_or("selected case required for capture")?;
    webhistory::configure_session(Some(case_id))?;
    Ok(true)
}

/// Full headers and bodies require a separate reveal confirmation. Integration
/// must verify active case selection before registering this IPC command.
#[tauri::command]
pub fn proxy_history_detail(
    case_id: String,
    id: u64,
    reveal_sensitive: bool,
    confirm_sensitive: bool,
) -> Result<Option<webhistory::Detail>, String> {
    if reveal_sensitive && !confirm_sensitive {
        return Err("sensitive history reveal requires explicit confirmation".to_string());
    }
    Ok(webhistory::read_detail(&case_id, id, reveal_sensitive))
}

#[tauri::command]
pub fn proxy_history(ctx: State<'_, WebCtx>) -> Vec<CapturedRequest> {
    ctx.shared
        .captured
        .lock()
        .expect("captured poisoned")
        .clone()
}

/// Toggle request interception. When on, requests are held in the pending
/// queue until forwarded or dropped; the browser waits for the decision.
#[tauri::command]
pub fn proxy_intercept(on: bool, ctx: State<'_, WebCtx>) -> bool {
    ctx.shared.intercept.store(on, Ordering::Relaxed);
    on
}

#[tauri::command]
pub fn proxy_pending(ctx: State<'_, WebCtx>) -> Vec<PendingWire> {
    proxy_application::list_pending(&ctx)
}

/// Forward a held request while preserving the original-history snapshot.
#[tauri::command]
pub async fn proxy_forward(id: u64, ctx: State<'_, WebCtx>) -> Result<u16, String> {
    proxy_application::forward(id, &ctx).await
}

/// Drop a held request; the browser receives a 502.
#[tauri::command]
pub async fn proxy_drop(id: u64, ctx: State<'_, WebCtx>) -> Result<(), String> {
    proxy_application::drop_pending(id, &ctx).await
}

#[tauri::command]
pub fn proxy_set_rules(rules: Vec<MatchReplaceRule>, ctx: State<'_, WebCtx>) -> usize {
    proxy_application::replace_rules(rules, &ctx)
}

/// Export the CA certificate PEM for browser trust-store installation.
#[tauri::command]
pub async fn proxy_ca_pem(app: tauri::AppHandle, ctx: State<'_, WebCtx>) -> Result<String, String> {
    if let Some(ca) = ctx.ca.lock().expect("ca poisoned").as_ref() {
        return Ok(ca.cert_pem.clone());
    }
    let ca_dir = crate::features::cases::infrastructure::storage_paths::data_dir(&app)?;
    let ca = crate::features::web::webtls::init_ca(&ca_dir)?;
    *ctx.ca.lock().expect("ca poisoned") = Some(Arc::clone(&ca));
    Ok(ca.cert_pem.clone())
}

#[tauri::command]
pub fn ws_list(ctx: State<'_, WebCtx>) -> Vec<WsConnectionWire> {
    proxy_application::list_ws(&ctx)
}

// --- external engine slots (GPLv2, user-approved) ------------------------------

#[tauri::command]
pub async fn web_engines_detect() -> Vec<WebEngineStatus> {
    engine_infrastructure::detect_engines().await
}

#[tauri::command]
pub async fn engine_scan(
    tool: String,
    target: String,
    authorized: bool,
) -> Result<EngineScanResult, String> {
    engine_infrastructure::run_engine(tool, target, authorized).await
}

#[cfg(test)]
#[path = "../tests/wire.rs"]
mod local_wire_tests;

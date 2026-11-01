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
#[path = "../application/assessment_jobs.rs"]
pub(crate) mod assessment_jobs;
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
#[path = "../infrastructure/target_scope.rs"]
mod target_scope;
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
    session: &crate::features::shared::session::CaseSessionCtx,
    selected: &crate::features::shared::session::CaseSessionWire,
    proxy: &WebCtx,
    grant: &cyberdeck_storage::HistoryCaptureGrant,
    permit: cyberdeck_storage::HistoryRevealPermit,
    id: u64,
    forwarded: bool,
    pinned: &target_scope::PinnedTarget,
) -> Result<HttpResponseWire, String> {
    // Only backend-held case revision and Agent5's live grant are authority.
    // All synchronous locks are released before HTTP network awaits.
    let authorize = || -> Result<(), String> {
        session.ensure(selected)?;
        if selected.case_id.as_deref() != Some(grant.case_id.as_str()) {
            return Err("replay case does not match selected case".into());
        }
        if !proxy.shared.running.load(Ordering::Acquire) {
            return Err("proxy stopped during replay".into());
        }
        session
            .history_policy
            .lock()
            .map_err(|_| "Web replay policy unavailable")?
            .authorize_grant(grant)?;
        session.ensure(selected)
    };
    authorize()?;
    let request = webhistory::replay_draft_authorized(grant, permit, id, forwarded)?;
    // Captured traffic is untrusted. Only the exact origin and concrete
    // addresses approved by the operator may be used. This also rules out
    // a changed original/forwarded request or a second DNS lookup.
    verify_pinned_replay_origin(&request.url, pinned)?;
    authorize()?;
    let reply = repeater_application::send_binary_authorized_with_client(
        &pinned.client,
        request,
        &authorize,
    )
    .await?;
    // Shared publication lock serializes final check/return against reselect.
    session.with_current_publication(selected, || {
        authorize()?;
        Ok(reply)
    })
}

/// Compare the full origin, including scheme and port. DNS destinations
/// are checked while preparing the pinned client, before native approval.
fn verify_pinned_replay_origin(
    request_url: &str,
    pinned: &target_scope::PinnedTarget,
) -> Result<(), String> {
    let request = target_scope::parse_target(request_url)?;
    if request.origin() != pinned.url.origin() || pinned.sockets.is_empty() {
        return Err("replay target differs from approved pinned destination".into());
    }
    target_scope::vetted_answers(pinned.sockets.iter().copied())?;
    Ok(())
}

/// A browser bool or a case_id parameter can never mint this grant.
fn selected_history_grant(
    session: &crate::features::shared::session::CaseSessionCtx,
    selected: &crate::features::shared::session::CaseSessionWire,
    proxy: &WebCtx,
) -> Result<cyberdeck_storage::HistoryCaptureGrant, String> {
    session.ensure(selected)?;
    if !proxy.shared.running.load(Ordering::Acquire) {
        return Err("Web proxy is stopped".into());
    }
    let case_id = selected
        .case_id
        .as_deref()
        .ok_or("a native-selected case is required")?;
    let policy = session
        .history_policy
        .lock()
        .map_err(|_| "Web history authority unavailable")?;
    let grant = policy.authorize_capture(case_id, policy.current_generation())?;
    // Respect publication -> selection -> policy lock order; never acquire
    // session.selection while still retaining the policy mutex.
    drop(policy);
    session.ensure(selected)?;
    Ok(grant)
}

/// Grant and one-time reveal permit minted only under the current case's
/// publication gate AFTER a trusted native approval event. Never hold policy
/// while entering Web history (history -> policy is the required mutex order).
fn mint_history_access(
    session: &crate::features::shared::session::CaseSessionCtx,
    selected: &crate::features::shared::session::CaseSessionWire,
    proxy: &WebCtx,
    id: u64,
) -> Result<
    (
        cyberdeck_storage::HistoryCaptureGrant,
        cyberdeck_storage::HistoryRevealPermit,
    ),
    String,
> {
    session.with_current_publication(selected, || {
        let grant = selected_history_grant(session, selected, proxy)?;
        if !webhistory::authorized_entry_ids().contains(&id) {
            return Err("HTTP history entry is no longer available".into());
        }
        let permit = session
            .history_policy
            .lock()
            .map_err(|_| "Web history authority unavailable")?
            .approve_reveal(&grant)?;
        Ok((grant, permit))
    })
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum WebHistoryAccessWire {
    Detail(webhistory::Detail),
    Replay(HttpResponseWire),
}

/// New narrow sensitive access path; unlike the legacy raw history functions,
/// it NEVER accepts a client-supplied case, consent boolean or reveal permit.
/// Keep unregistered until security fixtures and UI/authorization are accepted.
#[tauri::command]
pub async fn web_history_access_v1(
    id: u64,
    action: String,
    forwarded: bool,
    app: tauri::AppHandle,
    session: State<'_, crate::features::shared::session::CaseSessionCtx>,
    proxy: State<'_, WebCtx>,
) -> Result<WebHistoryAccessWire, String> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
    let selected = session.selected()?;
    let _grant = selected_history_grant(&session, &selected, &proxy)?;
    if !webhistory::authorized_entry_ids().contains(&id) {
        return Err("HTTP history entry is no longer available".into());
    }
    if action != "detail" && action != "replay" {
        return Err("invalid protected history action".into());
    }
    let is_replay = action == "replay";
    // Resolve and validate ALL DNS answers before asking the operator for
    // permission. The same isolated reqwest connector is used for dispatch.
    let pinned = if is_replay {
        let selected_grant = selected_history_grant(&session, &selected, &proxy)?;
        let origin = webhistory::replay_target_origin(&selected_grant, id, forwarded)?;
        let prepared = target_scope::prepare_private_target(&origin).await?;
        selected_history_grant(&session, &selected, &proxy)?;
        Some(prepared)
    } else {
        None
    };
    let description = if let Some(prepared) = pinned.as_ref() {
        let addresses = prepared
            .sockets
            .iter()
            .map(|socket| socket.ip().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("Replay the {} HTTP request #{} to {} through pinned address(es) {}? This sends a NEW network request that may contain credentials. Only authorize systems you own or may test.",
            if forwarded { "forwarded" } else { "original" }, id,
            prepared.url.origin().ascii_serialization(), addresses)
    } else {
        format!("Reveal captured request/response headers and binary bodies for history #{}? This may include passwords, cookies and tokens. Sensitive content will be shown temporarily.", id)
    };
    let approved = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .message(description)
            .title("Authorize sensitive Web history access")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "native history authorization unavailable")?;
    if !approved {
        return Err("history access declined by operator".into());
    }
    let (grant, permit) = mint_history_access(&session, &selected, &proxy, id)?;
    if is_replay {
        // Browser-captured URLs are untrusted: replay checks target restrictions
        // before any request is sent and rechecks consent/revision in-flight.
        let approved_target = pinned
            .as_ref()
            .ok_or("approved replay destination missing")?;
        let result = replay_authorized_case_message(
            &session,
            &selected,
            &proxy,
            &grant,
            permit,
            id,
            forwarded,
            approved_target,
        )
        .await?;
        Ok(WebHistoryAccessWire::Replay(result))
    } else {
        session.with_current_publication(&selected, || {
            let revealed = case_history_authorized_detail(&grant, permit, id)?
                .ok_or("HTTP history entry is no longer available")?;
            selected_history_grant(&session, &selected, &proxy)?;
            Ok(WebHistoryAccessWire::Detail(revealed))
        })
    }
}

#[cfg(test)]
mod protected_history_ipc_tests {
    use super::*;

    fn proxy(running: bool) -> WebCtx {
        WebCtx {
            proxy_running: AtomicBool::new(running),
            proxy_port: AtomicU16::new(8080),
            proxy_handle: Mutex::new(None),
            ca: Mutex::new(None),
            shared: Arc::new(ProxyShared {
                running: AtomicBool::new(running),
                intercept: AtomicBool::new(false),
                port: AtomicU16::new(8080),
                rules: Mutex::new(vec![]),
                captured: Mutex::new(vec![]),
                pending: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
                ca: Mutex::new(None),
                ws: Mutex::new(vec![]),
            }),
        }
    }

    #[test]
    fn replay_rejects_different_origin_and_unsafe_preapproved_socket() {
        let url = reqwest::Url::parse("http://fixture.cyberdeck.test:8080/").unwrap();
        let pinned = target_scope::PinnedTarget {
            url,
            client: reqwest::Client::new(),
            sockets: vec!["127.0.0.1:8080".parse().unwrap()],
        };
        assert!(verify_pinned_replay_origin(
            "http://fixture.cyberdeck.test:8080/original",
            &pinned
        )
        .is_ok());
        for changed in [
            "http://fixture.cyberdeck.test:9090/modified",
            "https://fixture.cyberdeck.test:8080/modified",
            "http://attacker.cyberdeck.test:8080/modified",
            "http://169.254.169.254:8080/",
            "file:///tmp/secret",
        ] {
            assert!(
                verify_pinned_replay_origin(changed, &pinned).is_err(),
                "{changed}"
            );
        }
        let untrusted = target_scope::PinnedTarget {
            url: pinned.url.clone(),
            client: reqwest::Client::new(),
            sockets: vec!["169.254.169.254:8080".parse().unwrap()],
        };
        assert!(
            verify_pinned_replay_origin("http://fixture.cyberdeck.test:8080/", &untrusted).is_err()
        );
    }

    #[test]
    fn history_access_requires_selected_case_live_consent_and_proxy() {
        let session = crate::features::shared::session::CaseSessionCtx::default();
        let none = session.snapshot().unwrap();
        assert!(selected_history_grant(&session, &none, &proxy(true)).is_err());

        let tmp = tempfile::tempdir().unwrap();
        let cases = cyberdeck_storage::ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let selected = session.select(&cases, "scratchpad").unwrap();
        assert!(selected_history_grant(&session, &selected, &proxy(true)).is_err());

        let grant = session
            .history_policy
            .lock()
            .unwrap()
            .enable_volatile_capture(
                "scratchpad",
                cyberdeck_storage::HistoryRetentionLimits::default(),
            )
            .unwrap();
        assert_eq!(
            selected_history_grant(&session, &selected, &proxy(true)).unwrap(),
            grant
        );
        assert!(selected_history_grant(&session, &selected, &proxy(false)).is_err());

        // Re-selecting the SAME case invalidates both revision and consent.
        session.select(&cases, "scratchpad").unwrap();
        assert!(selected_history_grant(&session, &selected, &proxy(true)).is_err());
        assert!(session
            .history_policy
            .lock()
            .unwrap()
            .authorize_grant(&grant)
            .is_err());
    }

    #[test]
    fn native_history_permit_cannot_be_issued_for_missing_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let cases = cyberdeck_storage::ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let session = crate::features::shared::session::CaseSessionCtx::default();
        let selected = session.select(&cases, "scratchpad").unwrap();
        let _grant = session
            .history_policy
            .lock()
            .unwrap()
            .enable_volatile_capture(
                "scratchpad",
                cyberdeck_storage::HistoryRetentionLimits::default(),
            )
            .unwrap();
        // No bound captured record exists; a client ID cannot fabricate one.
        assert!(mint_history_access(&session, &selected, &proxy(true), u64::MAX).is_err());
        session.clear().unwrap();
        assert!(mint_history_access(&session, &selected, &proxy(true), u64::MAX).is_err());
    }
}

/// One bounded HTTP operation prepared for trusted, native per-target approval.
/// Raw HTTP and credentials are never written to a case or backend job registry.
pub(crate) struct PreparedHttpRequest {
    pub origin: String,
    pub sockets: Vec<std::net::SocketAddr>,
    client: reqwest::Client,
    request: repeater_application::BinaryReplayRequest,
}

/// Cheap limits are also enforced in the registered shared controller. This
/// function is not an independent client authorization surface.
pub(crate) async fn prepare_scoped_http_request(raw: &str) -> Result<PreparedHttpRequest, String> {
    if raw.len() > 576 * 1024 {
        return Err("HTTP request exceeds 576 KiB limit".into());
    }
    let (method, url, headers, body) = parse_raw_request(raw, "http")?;
    if body.len() > 512 * 1024 {
        return Err("HTTP body exceeds 512 KiB limit".into());
    }
    let pinned = target_scope::prepare_private_target(&url).await?;
    Ok(PreparedHttpRequest {
        origin: pinned.url.origin().ascii_serialization(),
        sockets: pinned.sockets,
        client: pinned.client,
        request: repeater_application::BinaryReplayRequest {
            method,
            url,
            headers,
            body: body.into_bytes(),
        },
    })
}

/// Call only after the native case/target consent dialog has approved these
/// exact pinned addresses. No new DNS resolution or redirect can occur.
pub(crate) async fn send_scoped_http_request(
    prepared: PreparedHttpRequest,
) -> Result<HttpResponseWire, String> {
    repeater_application::send_binary_with_client(&prepared.client, prepared.request).await
}

/// Send an editable raw request using the native Repeater service.
#[tauri::command]
pub async fn http_send(request_raw: String) -> Result<HttpResponseWire, String> {
    repeater_application::send(request_raw).await
}

// --- Native web review: thin IPC over feature-first application services ----

/// Active scanner and crawler operations are independently authorized. The
/// legacy frontend checkbox is an acknowledgment, NOT a backend scope grant.
/// Until pinned-DNS support is verified, no hostname is resolved over the wire.
fn validate_assessment_target(target: &str) -> Result<reqwest::Url, String> {
    use std::net::IpAddr;
    if target.len() > 4096 {
        return Err("Web assessment target exceeds 4096-byte limit".into());
    }
    let url = reqwest::Url::parse(target.trim()).map_err(|_| "invalid Web assessment URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default().is_none()
    {
        return Err("assessment requires an HTTP(S) URL without credentials".into());
    }
    let host = url.host_str().ok_or("assessment URL host missing")?;
    let address: IpAddr = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| "DNS hostname assessments require verified pinned-address transport")?;
    let allowed = match address {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_private())
        }
    };
    if !allowed {
        return Err("assessment target is not an authorized private/loopback address".into());
    }
    Ok(url)
}

async fn authorize_assessment(
    app: tauri::AppHandle,
    session: &crate::features::shared::session::CaseSessionCtx,
    selected: &crate::features::shared::session::CaseSessionWire,
    target: &reqwest::Url,
) -> Result<(), String> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
    let origin = target.origin().ascii_serialization();
    let accepted = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .message(format!(
                "Authorize a bounded Web security assessment of {origin}?                  Only test systems you own or are explicitly permitted to assess."
            ))
            .title("Authorize active Web assessment")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "Web assessment confirmation unavailable")?;
    if !accepted {
        return Err("Web assessment rejected by operator".into());
    }
    session.ensure(selected)
}

/// The operator approves both the origin and the concrete pinned IPs.
/// No backend HTTP request is made until this separate native confirmation.
async fn authorize_pinned_assessment(
    app: tauri::AppHandle,
    session: &crate::features::shared::session::CaseSessionCtx,
    selected: &crate::features::shared::session::CaseSessionWire,
    pinned: &target_scope::PinnedTarget,
) -> Result<(), String> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
    let origin = pinned.url.origin().ascii_serialization();
    let destinations = pinned
        .sockets
        .iter()
        .map(|socket| socket.ip().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let accepted = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .message(format!(
                "Authorize this Web security assessment of {origin} through pinned address(es) {destinations}?                  Only approve hosts you own or are explicitly permitted to test."
            ))
            .title("Authorize pinned Web target")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    })
    .await
    .map_err(|_| "Web assessment confirmation unavailable")?;
    if !accepted {
        return Err("Web assessment rejected by operator".into());
    }
    session.ensure(selected)
}

async fn execute_case_scoped_assessment<T>(
    session: &crate::features::shared::session::CaseSessionCtx,
    selected: &crate::features::shared::session::CaseSessionWire,
    operation: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    // Bound concurrent active scans/crawls, independent of UI toggles.
    static WORK: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    let permit = WORK
        .get_or_init(|| tokio::sync::Semaphore::new(2))
        .try_acquire()
        .map_err(|_| "maximum concurrent Web assessments reached")?;
    session.ensure(selected)?;
    let expiry = tokio::time::sleep(std::time::Duration::from_secs(60));
    tokio::pin!(expiry);
    tokio::pin!(operation);
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
    let result = loop {
        tokio::select! {
            biased;
            _ = interval.tick() => session.ensure(selected)?,
            _ = &mut expiry => return Err("Web assessment exceeded 60-second limit".into()),
            reply = &mut operation => break reply?,
        }
    };
    session.with_current_publication(selected, || Ok(result))
}

#[tauri::command]
pub async fn web_scan(
    target_url: String,
    authorized: bool,
    app: tauri::AppHandle,
    session: State<'_, crate::features::shared::session::CaseSessionCtx>,
) -> Result<Vec<Finding>, String> {
    scan_domain::require_authorization(authorized)?;
    let selected = session.selected()?;
    let pinned = target_scope::prepare_private_target(&target_url).await?;
    session.ensure(&selected)?;
    authorize_pinned_assessment(app, &session, &selected, &pinned).await?;
    execute_case_scoped_assessment(
        &session,
        &selected,
        scan_application::run_scan(&pinned.client, pinned.url.to_string(), true),
    )
    .await
}

#[tauri::command]
pub async fn spider_scan(
    target_url: String,
    max_depth: u8,
    authorized: bool,
    app: tauri::AppHandle,
    session: State<'_, crate::features::shared::session::CaseSessionCtx>,
) -> Result<Vec<String>, String> {
    scan_domain::require_authorization(authorized)?;
    let selected = session.selected()?;
    let pinned = target_scope::prepare_private_target(&target_url).await?;
    session.ensure(&selected)?;
    authorize_pinned_assessment(app, &session, &selected, &pinned).await?;
    execute_case_scoped_assessment(
        &session,
        &selected,
        crawl_application::run_spider(&pinned.client, pinned.url.to_string(), max_depth, true),
    )
    .await
}

#[cfg(test)]
mod assessment_authorization_tests {
    use super::*;

    #[test]
    fn authorized_internal_literal_targets_only() {
        for target in [
            "http://127.0.0.1:8080/",
            "https://10.0.0.2/",
            "http://192.168.1.15:1234/",
            "http://[::1]:8080/",
            "https://[fd00::1]/",
            "http://[::ffff:127.0.0.1]/",
        ] {
            assert!(validate_assessment_target(target).is_ok(), "{target}");
        }
    }

    #[test]
    fn reject_dns_rebinding_and_metadata_address_surfaces() {
        for target in [
            "https://example.com/",
            "http://localhost/",
            "http://169.254.169.254/",
            "http://[fe80::1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://0.0.0.0/",
            "http://8.8.8.8/",
            "http://224.0.0.1/",
            "http://user:password@127.0.0.1/",
            "file:///etc/passwd",
        ] {
            assert!(validate_assessment_target(target).is_err(), "{target}");
        }
        assert!(
            validate_assessment_target(&format!("http://127.0.0.1/{}", "a".repeat(4100))).is_err()
        );
    }

    #[tokio::test]
    async fn case_revision_revoked_during_assessment_fails_before_publishing() {
        let temp = tempfile::tempdir().unwrap();
        let store = cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let session = crate::features::shared::session::CaseSessionCtx::default();
        let initial = session.select(&store, "scratchpad").unwrap();
        let (accepted, proceeding) = tokio::sync::oneshot::channel::<()>();
        let (resume, release) = tokio::sync::oneshot::channel::<()>();
        let job = execute_case_scoped_assessment(&session, &initial, async move {
            let _ = accepted.send(());
            let _ = release.await;
            Ok::<_, String>(42)
        });
        let decision = async {
            proceeding.await.unwrap();
            session.select(&store, "scratchpad").unwrap();
            let _ = resume.send(());
        };
        let (result, ()) = tokio::join!(job, decision);
        assert!(result.is_err());
    }
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
    // Revokes Agent5's still-current consent before awaiting listener shutdown.
    // In-flight authorized replays observe revocation within 100ms.
    revoke_backend_case_capture();
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
pub fn proxy_history(
    ctx: State<'_, WebCtx>,
    session: State<'_, crate::features::shared::session::CaseSessionCtx>,
) -> Vec<CapturedRequest> {
    // The legacy listener summary cache may contain events from earlier cases.
    // Never publish them unless their IDs are present in the current live
    // backend-consented volatile history generation. The publication mutex
    // serializes this read with backend case reselect/clear.
    let Ok(selected) = session.selected() else {
        return Vec::new();
    };
    session
        .with_current_publication(&selected, || {
            let permitted = webhistory::authorized_entry_ids();
            if permitted.is_empty() {
                return Ok(Vec::new());
            }
            let rows = ctx
                .shared
                .captured
                .lock()
                .map_err(|_| "proxy metadata unavailable")?;
            Ok(rows
                .iter()
                .filter(|row| permitted.contains(&row.id))
                .cloned()
                .collect())
        })
        .unwrap_or_default()
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

/// Only list engines whose entire outbound traffic is scoped by the native
/// transport. Third-party sidecars can initiate undisclosed secondary network
/// requests and must not be advertised as executable until sandboxed.
#[tauri::command]
pub async fn web_engines_detect() -> Vec<WebEngineStatus> {
    vec![WebEngineStatus {
        id: "cyberdeck-native".into(),
        label: "CyberDeck Native Web Scanner".into(),
        license: "MIT".into(),
        available: true,
        version: "0.1".into(),
    }]
}

fn require_scoped_engine(tool: &str) -> Result<(), String> {
    if tool == "cyberdeck-native" {
        Ok(())
    } else {
        Err("external Web engines are disabled until outbound scope can be enforced".into())
    }
}

/// Compatible legacy command, but every executable path uses an approved
/// pinned connector and the authoritative case/revision publication gate.
#[tauri::command]
pub async fn engine_scan(
    tool: String,
    target: String,
    authorized: bool,
    app: tauri::AppHandle,
    session: State<'_, crate::features::shared::session::CaseSessionCtx>,
) -> Result<EngineScanResult, String> {
    scan_domain::require_authorization(authorized)?;
    require_scoped_engine(&tool)?;
    let selected = session.selected()?;
    let pinned = target_scope::prepare_private_target(&target).await?;
    session.ensure(&selected)?;
    authorize_pinned_assessment(app, &session, &selected, &pinned).await?;
    let started = std::time::Instant::now();
    let findings = execute_case_scoped_assessment(
        &session,
        &selected,
        scan_application::run_scan(&pinned.client, pinned.url.to_string(), true),
    )
    .await?;
    let raw = serde_json::to_string_pretty(&findings)
        .map_err(|_| "cannot encode native Web assessment".to_string())?;
    Ok(EngineScanResult {
        tool,
        raw,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod native_engine_scope_tests {
    use super::*;

    #[test]
    fn only_pinned_native_web_engine_may_launch() {
        assert!(require_scoped_engine("cyberdeck-native").is_ok());
        for sidecar in ["sqlmap", "nikto", "xsstrike", "", "cyberdeck-native.exe"] {
            assert!(require_scoped_engine(sidecar).is_err(), "{sidecar}");
        }
    }
}

#[cfg(test)]
#[path = "../tests/wire.rs"]
mod local_wire_tests;

//! Backend-only voluntary Web traffic capture consent. This command never
//! reveals raw history. The sensitive detail/replay endpoints stay unregistered.
//! Lock order: CaseSession publication gate -> history-policy -> Web binding;
//! no network awaits while any guard is held.
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;

use cyberdeck_storage::{HistoryCaptureGrant, HistoryRetentionLimits};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use crate::features::web::ipc::web::{self, WebCtx};

#[derive(Debug, Clone, Serialize)]
pub struct WebCaptureConsentWire {
    pub enabled: bool,
    pub case_id: Option<String>,
    pub generation: Option<u64>,
    pub max_entries: usize,
    pub max_total_bytes: usize,
    pub max_body_bytes: usize,
    pub duration_seconds: u64,
}

fn response(scope: &CaseSessionWire, grant: Option<&HistoryCaptureGrant>) -> WebCaptureConsentWire {
    let limits = grant.map(|g| g.limits).unwrap_or_default();
    WebCaptureConsentWire {
        enabled: grant.is_some(),
        case_id: scope.case_id.clone(),
        generation: grant.map(|g| g.generation),
        max_entries: limits.max_entries,
        max_total_bytes: limits.max_total_bytes,
        max_body_bytes: limits.max_body_bytes,
        duration_seconds: limits.duration.as_secs(),
    }
}

/// This method must be called only after explicit native user consent.
/// Its callback is the local Web binding (never a network await). A failed
/// or panicking callback revokes newly minted authority before returning.
fn activate_with(
    session: &CaseSessionCtx,
    selected: &CaseSessionWire,
    limits: HistoryRetentionLimits,
    bind: impl FnOnce(&HistoryCaptureGrant) -> Result<(), String>,
) -> Result<WebCaptureConsentWire, String> {
    session.with_current_publication(selected, || {
        let case_id = selected
            .case_id
            .as_deref()
            .ok_or("select a case before enabling Web capture")?;
        let policy = &session.history_policy;
        let grant = policy
            .lock()
            .map_err(|_| "Web consent policy unavailable")?
            .enable_volatile_capture(case_id, limits)?;
        let outcome = catch_unwind(AssertUnwindSafe(|| bind(&grant)));
        match outcome {
            Ok(Ok(())) => {
                let still_valid = policy
                    .lock()
                    .map_err(|_| "Web consent policy unavailable")?
                    .authorize_grant(&grant)
                    .is_ok();
                if still_valid {
                    Ok(response(selected, Some(&grant)))
                } else {
                    policy
                        .lock()
                        .map_err(|_| "Web consent policy unavailable")?
                        .revoke();
                    Err("Web capture consent expired during activation".into())
                }
            }
            Ok(Err(error)) => {
                policy
                    .lock()
                    .map_err(|_| "Web consent policy unavailable")?
                    .revoke();
                Err(error)
            }
            Err(_) => {
                policy
                    .lock()
                    .map_err(|_| "Web consent policy unavailable")?
                    .revoke();
                Err("Web capture initialization failed".into())
            }
        }
    })
}

#[tauri::command]
pub async fn web_capture_consent_start_v1(
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    proxy: State<'_, WebCtx>,
) -> Result<WebCaptureConsentWire, String> {
    let selected = session.selected()?;
    if !proxy.shared.running.load(Ordering::Acquire) {
        return Err("start the local Web proxy before requesting capture consent".into());
    }
    let accepted = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .message("Capture a bounded, temporary HTTP request/response history for the current case? Traffic can contain personal data and credentials. Captures are volatile, expire within 15 minutes and are cleared when consent is revoked.")
            .title("Authorize Web traffic capture")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    }).await.map_err(|_| "native Web capture confirmation unavailable")?;
    if !accepted {
        return Err("Web capture not authorized by the operator".into());
    }
    if !proxy.shared.running.load(Ordering::Acquire) {
        return Err("Web proxy stopped before consent was granted".into());
    }
    let result = activate_with(
        &session,
        &selected,
        HistoryRetentionLimits::default(),
        |grant| {
            if !proxy.shared.running.load(Ordering::Acquire) {
                return Err("Web proxy stopped before capture handoff".into());
            }
            web::bind_backend_case_capture(session.history_policy.clone(), grant.clone())
                .map(|_| ())
        },
    );
    if result.is_err() {
        web::revoke_backend_case_capture();
    }
    result
}

#[tauri::command]
pub fn web_capture_consent_revoke_v1(
    session: State<'_, CaseSessionCtx>,
) -> Result<WebCaptureConsentWire, String> {
    let selected = session.snapshot()?;
    session.with_current_publication(&selected, || {
        session
            .history_policy
            .lock()
            .map_err(|_| "Web consent policy unavailable")?
            .revoke();
        web::revoke_backend_case_capture();
        Ok(response(&selected, None))
    })
}

#[tauri::command]
pub fn web_capture_consent_status_v1(
    session: State<'_, CaseSessionCtx>,
    proxy: State<'_, WebCtx>,
) -> Result<WebCaptureConsentWire, String> {
    let selected = session.snapshot()?;
    session.with_current_publication(&selected, || {
        let policy = session
            .history_policy
            .lock()
            .map_err(|_| "Web consent policy unavailable")?;
        let grant = selected.case_id.as_deref().and_then(|case| {
            policy
                .authorize_capture(case, policy.current_generation())
                .ok()
        });
        let active = proxy.shared.running.load(Ordering::Acquire);
        Ok(response(&selected, grant.as_ref().filter(|_| active)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_storage::ArtifactStore;
    use std::time::Duration;

    fn configured() -> (
        tempfile::TempDir,
        ArtifactStore,
        CaseSessionCtx,
        CaseSessionWire,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("case.db")).unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, "scratchpad").unwrap();
        (tmp, store, session, selected)
    }

    #[test]
    fn consent_off_by_default_and_backend_case_required() {
        let (_temp, store, session, scope) = configured();
        {
            let policy = session.history_policy.lock().unwrap();
            assert!(policy
                .authorize_capture("scratchpad", policy.current_generation())
                .is_err());
        }
        let none = CaseSessionWire {
            case_id: None,
            revision: scope.revision,
        };
        assert!(
            activate_with(&session, &none, HistoryRetentionLimits::default(), |_| Ok(
                ()
            ))
            .is_err()
        );
        assert!(session.select(&store, "missing").is_err());
    }

    #[test]
    fn consent_reselect_and_revocation_block_old_grants() {
        let (_temp, store, session, scope) = configured();
        let mut minted = None;
        let granted = activate_with(
            &session,
            &scope,
            HistoryRetentionLimits::default(),
            |grant| {
                minted = Some(grant.clone());
                Ok(())
            },
        )
        .unwrap();
        assert!(granted.enabled);
        let old = minted.unwrap();
        session.select(&store, "scratchpad").unwrap();
        assert!(session
            .history_policy
            .lock()
            .unwrap()
            .authorize_grant(&old)
            .is_err());
        assert!(
            activate_with(&session, &scope, HistoryRetentionLimits::default(), |_| Ok(
                ()
            ))
            .is_err()
        );
    }

    #[test]
    fn failed_or_panicking_binding_revokes_consent() {
        let (_temp, _store, session, scope) = configured();
        assert!(activate_with(
            &session,
            &scope,
            HistoryRetentionLimits::default(),
            |_| Err("simulated backend failure".into())
        )
        .is_err());
        assert!(activate_with(
            &session,
            &scope,
            HistoryRetentionLimits::default(),
            |_| panic!("simulated binding panic")
        )
        .is_err());
        let gate = session.history_policy.lock().unwrap();
        assert!(gate
            .authorize_capture("scratchpad", gate.current_generation())
            .is_err());
    }

    #[test]
    fn narrow_consent_limits_are_bounded() {
        let (_temp, _store, session, scope) = configured();
        let tiny = HistoryRetentionLimits {
            max_entries: 2,
            max_total_bytes: 2048,
            max_body_bytes: 512,
            duration: Duration::from_secs(2),
        };
        let issued = activate_with(&session, &scope, tiny, |_| Ok(())).unwrap();
        assert_eq!(issued.max_entries, 2);
        assert_eq!(issued.duration_seconds, 2);
        let too_big = HistoryRetentionLimits {
            max_entries: 65,
            ..tiny
        };
        assert!(activate_with(&session, &scope, too_big, |_| Ok(())).is_err());
    }
}

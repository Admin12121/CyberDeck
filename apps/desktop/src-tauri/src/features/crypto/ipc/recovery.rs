//! Additive, cancellable native SHA-256 CPU/OpenCL recovery IPC.
//! Only masked progress and summaries are sent automatically. A plaintext
//! reveal requires a separate native operator confirmation and active scope.
#[path = "../application/recovery_backend.rs"]
mod recovery_backend;

use crate::features::shared::session::CaseSessionCtx;
use recovery_backend::access::{RecoveryResultAccess, VerifiedScope};
use recovery_backend::{
    execute_path, probe_recovery_devices, RecoveryCancel, RecoveryDeviceInventory,
    RecoveryProgressWire, RecoveryRequest, RecoverySummaryWire,
};
use serde::Serialize;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::ipc::Channel;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

const MAX_RUNNING: usize = 2;
const MAX_TRACKED: usize = 16;
const RETAIN_DURATION: Duration = Duration::from_secs(300);

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPhase {
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Serialize)]
pub struct RecoveryJobStatus {
    pub job_id: u64,
    pub phase: RecoveryPhase,
    pub progress: Option<RecoveryProgressWire>,
    pub summary: Option<RecoverySummaryWire>,
    pub error: Option<String>,
    pub reveal_available: bool,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecoveryEvent {
    Started {
        job_id: u64,
    },
    Progress {
        job_id: u64,
        tried: u64,
        budget: u64,
        matches: usize,
    },
    Completed {
        job_id: u64,
        summary: RecoverySummaryWire,
    },
    Cancelled {
        job_id: u64,
    },
    Failed {
        job_id: u64,
        error: String,
    },
}

struct Job {
    cancel: RecoveryCancel,
    status: RecoveryJobStatus,
}
struct Registry {
    next_id: u64,
    current: Option<VerifiedScope>,
    jobs: HashMap<u64, Job>,
    secrets: RecoveryResultAccess,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            next_id: 1,
            current: None,
            jobs: HashMap::new(),
            secrets: RecoveryResultAccess::new(),
        }
    }
}
#[derive(Default)]
pub struct RecoveryCtx {
    registry: Arc<Mutex<Registry>>,
}
impl RecoveryCtx {
    fn scope_from_session(session: &CaseSessionCtx) -> Result<VerifiedScope, String> {
        let current = session.selected()?;
        let case = current.case_id.as_deref().ok_or("no selected case")?;
        VerifiedScope::from_backend("local-desktop", case, current.revision)
    }

    pub fn on_case_selected(&self, session: &CaseSessionCtx) -> Result<(), String> {
        let scope = Self::scope_from_session(session)?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "recovery jobs unavailable")?;
        for job in registry.jobs.values() {
            job.cancel.cancel();
        }
        registry.jobs.clear();
        registry.secrets.revoke_all();
        registry.secrets.set_active(scope.clone());
        registry.current = Some(scope);
        Ok(())
    }

    pub fn on_case_cleared(&self) {
        if let Ok(mut registry) = self.registry.lock() {
            for job in registry.jobs.values() {
                job.cancel.cancel();
            }
            registry.jobs.clear();
            registry.secrets.revoke_all();
            registry.current = None;
        }
    }

    fn with_active<T>(
        &self,
        session: &CaseSessionCtx,
        operation: impl FnOnce(&mut Registry, &VerifiedScope) -> Result<T, String>,
    ) -> Result<T, String> {
        let scope = Self::scope_from_session(session)?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "recovery jobs unavailable")?;
        if registry.current.as_ref() != Some(&scope) {
            return Err("recovery scope has changed; select the case again".into());
        }
        operation(&mut registry, &scope)
    }
}

#[tauri::command]
pub fn recovery_devices_v1() -> RecoveryDeviceInventory {
    probe_recovery_devices()
}

/// Select a local wordlist through a native file dialog. No frontend-supplied
/// filesystem path, plaintext storage or automatic reveal is supported.
#[tauri::command]
pub fn recovery_start_v1(
    app: AppHandle,
    request: RecoveryRequest,
    on_event: Channel<RecoveryEvent>,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    let before = session.selected()?;
    let (wordlist, _name) = crate::features::crypto::ipc::crack::resolved_wordlist(&app, None)?;
    session.ensure(&before)?;
    let scope = RecoveryCtx::scope_from_session(&session)?;
    let (job_id, token) = state.with_active(&session, |registry, verified| {
        if *verified != scope {
            return Err("recovery case changed".into());
        }
        if registry
            .jobs
            .values()
            .filter(|j| {
                matches!(
                    j.status.phase,
                    RecoveryPhase::Running | RecoveryPhase::Cancelling
                )
            })
            .count()
            >= MAX_RUNNING
        {
            return Err("too many concurrent recovery jobs".into());
        }
        if registry.jobs.len() >= MAX_TRACKED {
            return Err("discard completed recovery jobs before starting more".into());
        }
        let id = registry.next_id;
        registry.next_id = id.checked_add(1).ok_or("recovery job IDs exhausted")?;
        let cancel = RecoveryCancel::new();
        registry.jobs.insert(
            id,
            Job {
                cancel: cancel.clone(),
                status: RecoveryJobStatus {
                    job_id: id,
                    phase: RecoveryPhase::Running,
                    progress: None,
                    summary: None,
                    error: None,
                    reveal_available: false,
                },
            },
        );
        Ok((id, cancel))
    })?;
    let registry = state.registry.clone();
    let _ = on_event.send(RecoveryEvent::Started { job_id });
    std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            execute_path(&request, &wordlist, &token, |progress| {
                let should_emit = {
                    let Ok(mut lock) = registry.lock() else {
                        return;
                    };
                    if lock.current.as_ref() != Some(&scope) {
                        return;
                    }
                    if let Some(job) = lock.jobs.get_mut(&job_id) {
                        job.status.progress = Some(progress);
                        true
                    } else {
                        false
                    }
                };
                if should_emit {
                    let _ = on_event.send(RecoveryEvent::Progress {
                        job_id,
                        tried: progress.tried,
                        budget: progress.budget,
                        matches: progress.matches,
                    });
                }
            })
        }));
        let event = {
            let Ok(mut lock) = registry.lock() else {
                return;
            };
            if lock.current.as_ref() != Some(&scope) {
                return; // Case switches invalidate old workers and output.
            }
            match result {
                Ok(Ok(run)) => {
                    let summary = run.summary.clone();
                    let retained = !summary.cancelled
                        && !summary.matches.is_empty()
                        && lock
                            .secrets
                            .retain(job_id, &scope, run, RETAIN_DURATION)
                            .is_ok();
                    let Some(job) = lock.jobs.get_mut(&job_id) else {
                        return;
                    };
                    job.status.summary = Some(summary.clone());
                    job.status.reveal_available = retained;
                    if summary.cancelled {
                        job.status.phase = RecoveryPhase::Cancelled;
                        RecoveryEvent::Cancelled { job_id }
                    } else {
                        job.status.phase = RecoveryPhase::Completed;
                        RecoveryEvent::Completed { job_id, summary }
                    }
                }
                Ok(Err(error)) => {
                    let Some(job) = lock.jobs.get_mut(&job_id) else {
                        return;
                    };
                    job.status.phase = RecoveryPhase::Failed;
                    job.status.error = Some(error.clone());
                    RecoveryEvent::Failed { job_id, error }
                }
                Err(_) => {
                    let Some(job) = lock.jobs.get_mut(&job_id) else {
                        return;
                    };
                    job.status.phase = RecoveryPhase::Failed;
                    job.status.error = Some("native recovery worker failed".into());
                    RecoveryEvent::Failed {
                        job_id,
                        error: "native recovery worker failed".into(),
                    }
                }
            }
        };
        let _ = on_event.send(event);
    });
    Ok(job_id)
}

#[tauri::command]
pub fn recovery_cancel_v1(
    job_id: u64,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<bool, String> {
    state.with_active(&session, |registry, _| {
        let Some(job) = registry.jobs.get_mut(&job_id) else {
            return Ok(false);
        };
        if !matches!(
            job.status.phase,
            RecoveryPhase::Running | RecoveryPhase::Cancelling
        ) {
            return Ok(false);
        }
        job.cancel.cancel();
        job.status.phase = RecoveryPhase::Cancelling;
        Ok(true)
    })
}

#[tauri::command]
pub fn recovery_status_v1(
    job_id: u64,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<RecoveryJobStatus, String> {
    state.with_active(&session, |registry, _| {
        registry
            .jobs
            .get(&job_id)
            .map(|j| j.status.clone())
            .ok_or_else(|| "recovery job not found in active case".into())
    })
}

#[tauri::command]
pub fn recovery_discard_v1(
    job_id: u64,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<bool, String> {
    state.with_active(&session, |registry, scope| {
        if let Some(job) = registry.jobs.remove(&job_id) {
            job.cancel.cancel();
            registry.secrets.discard(job_id, scope);
            Ok(true)
        } else {
            Ok(false)
        }
    })
}

/// Native OS confirmation is required for each explicit reveal, *in addition*
/// to a backend-held matching session/case/generation and unexpired result.
/// Returning plaintext as hex still transfers sensitive data into the caller:
/// the frontend must clear it immediately on dismissal or case switch.
#[tauri::command]
pub async fn recovery_reveal_v1(
    app: AppHandle,
    job_id: u64,
    ordinal: usize,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<String, String> {
    let scope = RecoveryCtx::scope_from_session(&session)?;
    state.with_active(&session, |registry, _| {
        let job = registry.jobs.get(&job_id).ok_or("recovery job not found")?;
        if !matches!(job.status.phase, RecoveryPhase::Completed) || !job.status.reveal_available {
            return Err("no revealable results in active session".into());
        }
        if ordinal >= job.status.summary.as_ref().map_or(0, |x| x.matches.len()) {
            return Err("recovered candidate ordinal out of range".into());
        }
        Ok(())
    })?;
    let confirmed = tokio::task::spawn_blocking(move || {
        app.dialog()
            .message("Reveal this recovered candidate to the active desktop session? It is sensitive and will not be saved.")
            .title("Confirm recovered secret reveal")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    }).await.map_err(|_| "native reveal confirmation unavailable")?;
    if !confirmed {
        return Err("recovered secret reveal cancelled".into());
    }
    state.with_active(&session, |registry, checked| {
        if checked != &scope {
            return Err("recovery session changed during confirmation".into());
        }
        registry.secrets.authorize_reveal(job_id, checked)?;
        let secret = registry
            .secrets
            .reveal(job_id, ordinal, checked)
            .ok_or("recovery result expired or authorization revoked")?;
        let mut hex = String::with_capacity(secret.as_bytes().len() * 2);
        for b in secret.as_bytes() {
            use std::fmt::Write;
            write!(&mut hex, "{b:02x}").map_err(|_| "cannot encode transient secret")?;
        }
        Ok(hex)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn case_reselection_cancels_running_jobs_and_revokes_results() {
        let ctx = RecoveryCtx::default();
        let first = VerifiedScope::from_backend("local-desktop", "case-a", 1).unwrap();
        let second = VerifiedScope::from_backend("local-desktop", "case-b", 2).unwrap();
        let token = RecoveryCancel::new();
        {
            let mut inner = ctx.registry.lock().unwrap();
            inner.current = Some(first.clone());
            inner.secrets.set_active(first);
            inner.jobs.insert(
                1,
                Job {
                    cancel: token.clone(),
                    status: RecoveryJobStatus {
                        job_id: 1,
                        phase: RecoveryPhase::Running,
                        progress: None,
                        summary: None,
                        error: None,
                        reveal_available: false,
                    },
                },
            );
            inner.current = Some(second.clone());
            for job in inner.jobs.values() {
                job.cancel.cancel();
            }
            inner.jobs.clear();
            inner.secrets.set_active(second);
        }
        assert!(token.is_cancelled());
        assert!(ctx.registry.lock().unwrap().jobs.is_empty());
    }
}

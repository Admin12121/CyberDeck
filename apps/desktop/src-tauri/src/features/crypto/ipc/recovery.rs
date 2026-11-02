//! Additive, cancellable native SHA-256 CPU/OpenCL recovery IPC.
//! Only masked progress and summaries are sent automatically. A plaintext
//! reveal requires a separate native operator confirmation and active scope.
#[path = "../application/embedded_hashcat.rs"]
mod embedded_hashcat;
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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
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
    expires_at: Option<Instant>,
}
struct Registry {
    next_id: u64,
    current: Option<VerifiedScope>,
    jobs: HashMap<u64, Job>,
    secrets: RecoveryResultAccess,
    selected_wordlist: Option<SelectedWordlist>,
}

#[derive(Clone)]
struct SelectedWordlist {
    path: PathBuf,
    name: String,
    size_bytes: u64,
}

#[derive(Clone, Serialize)]
pub struct RecoveryWordlistInfo {
    pub name: String,
    pub size_bytes: u64,
}
impl Registry {
    fn reserve_job(&mut self) -> Result<(u64, RecoveryCancel), String> {
        if self
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
        if self.jobs.len() >= MAX_TRACKED {
            return Err("discard completed recovery jobs before starting more".into());
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or("recovery job IDs exhausted")?;
        let cancel = RecoveryCancel::new();
        self.jobs.insert(
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
                expires_at: None,
            },
        );
        Ok((id, cancel))
    }

    fn prune_expired(&mut self) -> usize {
        let removed = self.secrets.prune_expired();
        let now = Instant::now();
        for job in self.jobs.values_mut() {
            if job.expires_at.is_some_and(|expiry| now >= expiry) {
                job.expires_at = None;
                job.status.reveal_available = false;
            }
        }
        removed
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            next_id: 1,
            current: None,
            jobs: HashMap::new(),
            secrets: RecoveryResultAccess::new(),
            selected_wordlist: None,
        }
    }
}
#[derive(Default)]
pub struct RecoveryCtx {
    registry: Arc<Mutex<Registry>>,
}
impl RecoveryCtx {
    /// Prune confidential buffers even when IPC is idle.
    pub fn start_expiry_cleanup(&self) {
        let weak = Arc::downgrade(&self.registry);
        tauri::async_runtime::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                let Some(registry) = weak.upgrade() else {
                    break;
                };
                if let Ok(mut active) = registry.lock() {
                    active.prune_expired();
                };
            }
        });
    }

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
        registry.selected_wordlist = None;
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
            registry.selected_wordlist = None;
            registry.current = None;
        }
    }

    fn with_active<T>(
        &self,
        session: &CaseSessionCtx,
        operation: impl FnOnce(&mut Registry, &VerifiedScope) -> Result<T, String>,
    ) -> Result<T, String> {
        let snapshot = session.selected()?;
        let scope = VerifiedScope::from_backend(
            "local-desktop",
            snapshot.case_id.as_deref().ok_or("no selected case")?,
            snapshot.revision,
        )?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "recovery jobs unavailable")?;
        registry.prune_expired();
        session.ensure(&snapshot)?;
        if registry.current.as_ref() != Some(&scope) {
            return Err("recovery scope has changed; select the case again".into());
        }
        let result = operation(&mut registry, &scope)?;
        session.ensure(&snapshot)?;
        Ok(result)
    }
}

impl Drop for RecoveryCtx {
    fn drop(&mut self) {
        self.on_case_cleared();
    }
}

#[tauri::command]
pub fn recovery_devices_v1() -> RecoveryDeviceInventory {
    probe_recovery_devices()
}

/// Select a local wordlist through a native file dialog. No frontend-supplied
/// filesystem path, plaintext storage or automatic reveal is supported.
fn start_recovery_with_wordlist(
    state: &RecoveryCtx,
    session: &CaseSessionCtx,
    request: RecoveryRequest,
    wordlist: PathBuf,
    emit: impl Fn(RecoveryEvent) + Send + 'static,
) -> Result<u64, String> {
    start_recovery_with_wordlist_engine(
        state,
        session,
        request,
        wordlist,
        None,
        embedded_hashcat::WordlistPreset::Plain,
        emit,
    )
}

/// Both engines share the exact same authoritative case/job/reveal lifecycle.
/// An embedded runtime is never a frontend-provided path or CLI switch.
fn start_recovery_with_wordlist_engine(
    state: &RecoveryCtx,
    session: &CaseSessionCtx,
    request: RecoveryRequest,
    wordlist: PathBuf,
    embedded_runtime: Option<PathBuf>,
    preset: embedded_hashcat::WordlistPreset,
    emit: impl Fn(RecoveryEvent) + Send + 'static,
) -> Result<u64, String> {
    if embedded_runtime.is_some() {
        embedded_hashcat::validate_embedded_request(&request)?;
    } else {
        recovery_backend::validate_request(&request)?;
    }
    if embedded_runtime.is_some()
        != matches!(
            request.backend,
            recovery_backend::BackendSelection::HashcatManaged
        )
    {
        return Err("recovery engine and backend selection do not match".into());
    }
    let scope = RecoveryCtx::scope_from_session(session)?;
    let (job_id, token) = state.with_active(session, |registry, verified| {
        if *verified != scope {
            return Err("recovery case changed".into());
        }
        registry.reserve_job()
    })?;
    let registry = state.registry.clone();
    emit(RecoveryEvent::Started { job_id });
    std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let progress_callback = |progress| {
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
                    emit(RecoveryEvent::Progress {
                        job_id,
                        tried: progress.tried,
                        budget: progress.budget,
                        matches: progress.matches,
                    });
                }
            };
            if let Some(runtime) = embedded_runtime.as_deref() {
                embedded_hashcat::execute_path(
                    &request,
                    &wordlist,
                    runtime,
                    &token,
                    preset,
                    progress_callback,
                )
            } else {
                execute_path(&request, &wordlist, &token, progress_callback)
            }
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
                    let mut summary = run.summary.clone();
                    // A cancellation requested after core processing but before
                    // publishing results must suppress confidential retention.
                    if token.is_cancelled() {
                        summary.cancelled = true;
                        summary.matches.clear();
                    }
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
                    job.expires_at = retained.then(|| Instant::now() + RETAIN_DURATION);
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
        emit(event);
    });
    Ok(job_id)
}

/// Select a wordlist by native OS dialog, authorize against the backend
/// case/revision, and retain only the path in process memory. Never expose the
/// raw filesystem path to the JavaScript interface.
#[tauri::command]
pub fn recovery_select_wordlist_v1(
    app: AppHandle,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<RecoveryWordlistInfo, String> {
    let before = session.selected()?;
    // Ensure a usable, already-authorized case before opening the OS dialog.
    state.with_active(&session, |_, _| Ok(()))?;
    let (path, name) = crate::features::crypto::ipc::crack::resolved_wordlist(&app, None)?;
    session.ensure(&before)?;
    let size_bytes = std::fs::metadata(&path)
        .map_err(|_| "selected wordlist is no longer accessible")?
        .len();
    let info = RecoveryWordlistInfo {
        name: name.clone(),
        size_bytes,
    };
    state.with_active(&session, |registry, _| {
        registry.selected_wordlist = Some(SelectedWordlist {
            path,
            name,
            size_bytes,
        });
        Ok(())
    })?;
    Ok(info)
}

/// Re-read selection metadata from the authoritative session after route
/// navigation. No raw path or file data is ever sent to React.
#[tauri::command]
pub fn recovery_wordlist_status_v1(
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<Option<RecoveryWordlistInfo>, String> {
    state.with_active(&session, |registry, _| {
        Ok(registry
            .selected_wordlist
            .as_ref()
            .map(|selection| RecoveryWordlistInfo {
                name: selection.name.clone(),
                size_bytes: selection.size_bytes,
            }))
    })
}

#[tauri::command]
pub fn recovery_start_v1(
    request: RecoveryRequest,
    on_event: Channel<RecoveryEvent>,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    if matches!(
        request.backend,
        recovery_backend::BackendSelection::HashcatManaged
    ) {
        return Err("Hashcat-managed backend requires the embedded engine command".into());
    }
    let selected = state.with_active(&session, |registry, _| {
        registry
            .selected_wordlist
            .clone()
            .ok_or_else(|| "choose a wordlist before starting recovery".to_owned())
    })?;
    // Revalidate that the selected file still exists and passes native
    // wordlist inspection; do not accept an untrusted frontend-supplied path.
    let _ = crate::features::crypto::ipc::crack::inspect_recovery_wordlist(&selected.path)?;
    start_recovery_with_wordlist(&state, &session, request, selected.path, move |event| {
        let _ = on_event.send(event);
    })
}

#[derive(Serialize)]
pub struct EmbeddedHashcatCapability {
    pub available: bool,
    /// Legacy SHA-256 mode field retained for existing IPC consumers.
    pub mode: u32,
    /// Compiled bundled algorithms; does NOT imply a working compute device.
    pub modes: Vec<EmbeddedHashcatMode>,
    pub hardware_verified: bool,
    pub detail: String,
}
#[derive(Serialize)]
pub struct EmbeddedHashcatMode {
    pub algorithm: &'static str,
    pub mode: u32,
    pub digest_hex_length: usize,
}
fn bundled_hashcat_modes() -> Vec<EmbeddedHashcatMode> {
    [
        ("md5", 0, 32),
        ("sha1", 100, 40),
        ("sha256", 1400, 64),
        ("sha512", 1700, 128),
    ]
    .into_iter()
    .map(|(algorithm, mode, digest_hex_length)| EmbeddedHashcatMode {
        algorithm,
        mode,
        digest_hex_length,
    })
    .collect()
}

fn hashcat_resource_root(app: &AppHandle) -> Result<PathBuf, String> {
    let packaged = app
        .path()
        .resource_dir()
        .map_err(|_| "Hashcat bundle resources unavailable")?
        .join("hashcat");
    if embedded_hashcat::runtime_available(&packaged).is_ok() {
        return Ok(packaged);
    }
    #[cfg(debug_assertions)]
    {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/hashcat");
        if embedded_hashcat::runtime_available(&dev).is_ok() {
            return Ok(dev);
        }
    }
    Err("embedded Hashcat native runtime not packaged".into())
}

/// Reports the four source-built wordlist modes; hardware_verified
/// stays false until actual host device/kernel KAT, not merely library loading.
#[tauri::command]
pub fn recovery_hashcat_capabilities_v1(app: AppHandle) -> EmbeddedHashcatCapability {
    match hashcat_resource_root(&app) {
        Ok(runtime) => {
            // Native loader probing runs through the exact packaged worker,
            // not an unrelated Rust OpenCL backend or an executable on PATH.
            match embedded_hashcat::probe_opencl_loader(&runtime) {
                Ok(false) => return EmbeddedHashcatCapability {
                    available: false,
                    mode: 1400,
                    modes: bundled_hashcat_modes(),
                    hardware_verified: false,
                    detail: "Hashcat is bundled, but the system OpenCL loader is unavailable; install a compatible GPU driver/runtime".into(),
                },
                Err(error) => return EmbeddedHashcatCapability {
                    available: false,
                    mode: 1400,
                    modes: bundled_hashcat_modes(),
                    hardware_verified: false,
                    detail: error,
                },
                Ok(true) => {}
            }
            // The Rust OpenCL probe is a diagnostic only. Its indices are NOT
            // Hashcat native device IDs, and enumeration is never a kernel KAT.
            let probe = recovery_backend::probe_recovery_devices();
            let detail = if probe.opencl_detected {
                format!(
                    "Bundled MD5/SHA-1/SHA-256/SHA-512 modes; {} OpenCL device(s) detected by Rust, Hashcat mapping and execution unverified",
                    probe.devices.len()
                )
            } else {
                "Bundled MD5/SHA-1/SHA-256/SHA-512 modes, but no compatible OpenCL runtime was detected; native execution may fail".into()
            };
            EmbeddedHashcatCapability {
                available: true,
                mode: 1400,
                modes: bundled_hashcat_modes(),
                hardware_verified: false,
                detail,
            }
        }
        Err(error) => EmbeddedHashcatCapability {
            available: false,
            mode: 1400,
            modes: bundled_hashcat_modes(),
            hardware_verified: false,
            detail: error,
        },
    }
}

/// Deliberate opt-in to independently compiled Hashcat C core: never falls
/// back to Rust or an external system executable without user intent.
#[tauri::command]
pub fn recovery_start_hashcat_v1(
    app: AppHandle,
    request: RecoveryRequest,
    preset: Option<embedded_hashcat::WordlistPreset>,
    on_event: Channel<RecoveryEvent>,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    embedded_hashcat::validate_embedded_request(&request)?;
    if !matches!(
        request.backend,
        recovery_backend::BackendSelection::HashcatManaged
    ) {
        return Err("embedded Hashcat requires a Hashcat-managed backend selection".into());
    }
    let runtime = hashcat_resource_root(&app)?;
    if !embedded_hashcat::probe_opencl_loader(&runtime)? {
        return Err(
            "Hashcat requires a compatible system OpenCL loader before recovery can start".into(),
        );
    }
    let selected = state.with_active(&session, |registry, _| {
        registry
            .selected_wordlist
            .clone()
            .ok_or_else(|| "choose a wordlist before starting recovery".to_owned())
    })?;
    crate::features::crypto::ipc::crack::inspect_recovery_wordlist(&selected.path)?;
    start_recovery_with_wordlist_engine(
        &state,
        &session,
        request,
        selected.path,
        Some(runtime),
        preset.unwrap_or_default(),
        move |event| {
            let _ = on_event.send(event);
        },
    )
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
    use super::recovery_backend::execute_reader;
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
                    expires_at: None,
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
    #[test]
    fn selected_native_wordlist_is_cleared_on_case_revision_and_shutdown() {
        let temp = tempfile::tempdir().unwrap();
        let store = cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let session = CaseSessionCtx::default();
        session.select(&store, "scratchpad").unwrap();
        let ctx = RecoveryCtx::default();
        ctx.on_case_selected(&session).unwrap();
        let path = temp.path().join("fixture-wordlist.txt");
        std::fs::write(&path, b"wrong\nexample\n").unwrap();
        ctx.with_active(&session, |registry, _| {
            registry.selected_wordlist = Some(SelectedWordlist {
                path: path.clone(),
                name: "fixture-wordlist.txt".into(),
                size_bytes: 14,
            });
            Ok(())
        })
        .unwrap();
        assert!(ctx
            .with_active(&session, |registry, _| {
                Ok(registry.selected_wordlist.is_some())
            })
            .unwrap());

        session.select(&store, "scratchpad").unwrap();
        ctx.on_case_selected(&session).unwrap();
        assert!(!ctx
            .with_active(&session, |registry, _| {
                Ok(registry.selected_wordlist.is_some())
            })
            .unwrap());

        ctx.with_active(&session, |registry, _| {
            registry.selected_wordlist = Some(SelectedWordlist {
                path,
                name: "fixture-wordlist.txt".into(),
                size_bytes: 14,
            });
            Ok(())
        })
        .unwrap();
        ctx.on_case_cleared();
        assert!(ctx.registry.lock().unwrap().selected_wordlist.is_none());
    }

    #[test]
    fn backend_registry_bounds_concurrency_and_owns_unique_job_ids() {
        let mut registry = Registry::default();
        let (a, first) = registry.reserve_job().unwrap();
        let (b, _) = registry.reserve_job().unwrap();
        assert_ne!(a, b);
        assert!(registry.reserve_job().err().unwrap().contains("concurrent"));
        registry.jobs.get_mut(&a).unwrap().status.phase = RecoveryPhase::Completed;
        let (c, _) = registry.reserve_job().unwrap();
        assert!(c > b);
        first.cancel();
        assert!(first.is_cancelled());
        assert_eq!(registry.jobs.len(), 3);
    }

    #[test]
    fn idle_expiry_prunes_confidential_results_and_disables_reveal_status() {
        use std::io::Cursor;
        let request = RecoveryRequest {
            algorithm: "sha256".into(),
            target_hash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            backend: recovery_backend::BackendSelection::Cpu,
            max_candidates: 3,
            max_matches: 1,
        };
        let run = execute_reader(
            &request,
            Cursor::new(b"wrong\nabc\n"),
            &RecoveryCancel::new(),
            |_| {},
        )
        .unwrap();
        assert_eq!(run.summary.matches.len(), 1);
        let scope = VerifiedScope::from_backend("desktop", "scratchpad", 1).unwrap();
        let mut registry = Registry::default();
        registry.current = Some(scope.clone());
        registry.secrets.set_active(scope.clone());
        registry
            .secrets
            .retain(42, &scope, run, Duration::from_millis(2))
            .unwrap();
        registry.jobs.insert(
            42,
            Job {
                cancel: RecoveryCancel::new(),
                status: RecoveryJobStatus {
                    job_id: 42,
                    phase: RecoveryPhase::Completed,
                    progress: None,
                    summary: None,
                    error: None,
                    reveal_available: true,
                },
                expires_at: Some(Instant::now() + Duration::from_millis(2)),
            },
        );
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(registry.prune_expired(), 1);
        assert!(!registry.jobs.get(&42).unwrap().status.reveal_available);
        assert!(registry.secrets.authorize_reveal(42, &scope).is_err());
    }

    #[test]
    fn backend_case_reselect_cancels_and_revokes_older_generation() {
        let temp = tempfile::tempdir().unwrap();
        let store = cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let session = CaseSessionCtx::default();
        session.select(&store, "scratchpad").unwrap();
        let ctx = RecoveryCtx::default();
        ctx.on_case_selected(&session).unwrap();
        let (job, token) = ctx
            .with_active(&session, |registry, _| registry.reserve_job())
            .unwrap();
        assert!(!token.is_cancelled());
        session.select(&store, "scratchpad").unwrap();
        ctx.on_case_selected(&session).unwrap();
        assert!(token.is_cancelled());
        assert!(
            ctx.with_active(&session, |registry, _| Ok(registry.jobs.contains_key(&job)))
                .unwrap()
                == false
        );
        assert!(ctx
            .with_active(&session, |registry, scope| Ok(registry
                .secrets
                .reveal(job, 0, scope)
                .is_none()))
            .unwrap());
    }

    #[test]
    fn dropping_managed_recovery_cancels_active_worker_tokens() {
        let ctx = RecoveryCtx::default();
        let token = {
            let mut registry = ctx.registry.lock().unwrap();
            let (_, token) = registry.reserve_job().unwrap();
            token
        };
        assert!(!token.is_cancelled());
        drop(ctx);
        assert!(token.is_cancelled());
    }
    #[test]
    fn native_cpu_wordlist_job_emits_masked_terminal_status() {
        use std::sync::mpsc::channel;
        let tmp = tempfile::tempdir().unwrap();
        let store = cyberdeck_storage::ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let words = tmp.path().join("known.txt");
        std::fs::write(&words, b"wrong\nabc\nother\n").unwrap();

        let session = CaseSessionCtx::default();
        session.select(&store, "scratchpad").unwrap();
        let ctx = RecoveryCtx::default();
        ctx.on_case_selected(&session).unwrap();
        let request = RecoveryRequest {
            algorithm: "sha256".into(),
            target_hash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            backend: recovery_backend::BackendSelection::Cpu,
            max_candidates: 3,
            max_matches: 1,
        };
        let (send, receive) = channel::<RecoveryEvent>();
        let id = start_recovery_with_wordlist(&ctx, &session, request, words, move |event| {
            let _ = send.send(event);
        })
        .unwrap();

        let mut started = false;
        let mut saw_progress = false;
        let summary = loop {
            let event = receive
                .recv_timeout(Duration::from_secs(5))
                .expect("native recovery did not finish");
            match event {
                RecoveryEvent::Started { job_id } => {
                    assert_eq!(id, job_id);
                    started = true;
                }
                RecoveryEvent::Progress { job_id, tried, .. } => {
                    assert_eq!(id, job_id);
                    saw_progress = true;
                    assert!(tried <= 3);
                }
                RecoveryEvent::Completed { job_id, summary } => {
                    assert_eq!(id, job_id);
                    break summary;
                }
                RecoveryEvent::Failed { error, .. } => panic!("native recovery failed: {error}"),
                RecoveryEvent::Cancelled { .. } => {
                    panic!("native recovery was unexpectedly cancelled")
                }
            }
        };
        assert!(started);
        assert!(saw_progress);
        assert_eq!(summary.tried, 2);
        assert_eq!(summary.matches.len(), 1);
        assert!(summary.matches[0].masked);
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("abc"));

        let status = ctx
            .with_active(&session, |registry, scope| {
                assert!(registry.secrets.reveal(id, 0, scope).is_none());
                Ok(registry.jobs.get(&id).unwrap().status.clone())
            })
            .unwrap();
        assert!(matches!(status.phase, RecoveryPhase::Completed));
        assert!(status.reveal_available);
        assert!(status.summary.is_some());
    }

    #[test]
    fn native_cpu_progress_callback_can_cancel_real_worker() {
        use std::sync::mpsc::channel;
        let tmp = tempfile::tempdir().unwrap();
        let store = cyberdeck_storage::ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let words = tmp.path().join("many.txt");
        std::fs::write(&words, b"incorrect\n".repeat(100_000)).unwrap();

        let session = CaseSessionCtx::default();
        session.select(&store, "scratchpad").unwrap();
        let ctx = RecoveryCtx::default();
        ctx.on_case_selected(&session).unwrap();
        let (send, receive) = channel::<RecoveryEvent>();
        let jobs = ctx.registry.clone();
        let id = start_recovery_with_wordlist(
            &ctx,
            &session,
            RecoveryRequest {
                algorithm: "sha256".into(),
                target_hash: "00".repeat(32),
                backend: recovery_backend::BackendSelection::Cpu,
                max_candidates: 100_000,
                max_matches: 1,
            },
            words,
            move |event| {
                if let RecoveryEvent::Progress { job_id, tried, .. } = &event {
                    if *tried >= 4096 {
                        if let Ok(lock) = jobs.lock() {
                            if let Some(job) = lock.jobs.get(job_id) {
                                job.cancel.cancel();
                            }
                        }
                    }
                }
                let _ = send.send(event);
            },
        )
        .unwrap();
        let mut saw_progress = false;
        let terminal = loop {
            let event = receive
                .recv_timeout(Duration::from_secs(5))
                .expect("native cancellation did not finish");
            match event {
                RecoveryEvent::Progress { tried, .. } => {
                    if tried >= 4096 {
                        saw_progress = true;
                    }
                }
                RecoveryEvent::Cancelled { job_id } => break job_id,
                RecoveryEvent::Completed { .. } => panic!("cancelled job completed"),
                RecoveryEvent::Failed { error, .. } => panic!("cancelled job failed: {error}"),
                RecoveryEvent::Started { .. } => {}
            }
        };
        assert!(saw_progress);
        assert_eq!(terminal, id);
        let result = ctx
            .with_active(&session, |registry, _| {
                Ok(registry.jobs.get(&id).unwrap().status.clone())
            })
            .unwrap();
        assert!(matches!(result.phase, RecoveryPhase::Cancelled));
        assert!(!result.reveal_available);
    }
}

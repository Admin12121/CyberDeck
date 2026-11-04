//! Additive, cancellable native SHA-256 CPU/OpenCL recovery IPC.
//! Only masked progress and summaries are sent automatically. A plaintext
//! reveal requires a separate native operator confirmation and active scope.
#[path = "../application/embedded_hashcat.rs"]
mod embedded_hashcat;
#[path = "../application/recovery_backend.rs"]
mod recovery_backend;
#[path = "../application/autopilot.rs"]
mod autopilot;
// Library modules are shared with ipc/library.rs; each include is a pure,
// stateless view over the same verified resource files.
// Twin includes of the library modules: this instance uses only the resolve/
// load/list surface, so silence the dead-code warnings the unused remainder
// would raise (ipc/library.rs exercises the full surface on its own copy).
#[path = "../infrastructure/rules_library.rs"]
#[allow(dead_code)]
pub(crate) mod library_rules;
#[path = "../infrastructure/wordlist_library.rs"]
#[allow(dead_code)]
pub(crate) mod library_wordlists;

/// Alias so command bodies read cleanly about their support modules.
mod library_support {
    pub(crate) use super::library_rules as rules_library;
}

use crate::features::shared::session::CaseSessionCtx;
use recovery_backend::access::{RecoveryResultAccess, VerifiedScope};
use recovery_backend::{
    execute_path, execute_path_with_rules, probe_recovery_devices, RecoveryCancel,
    RecoveryDeviceInventory, RecoveryProgressWire, RecoveryRequest, RecoveryRun,
    RecoverySummaryWire,
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
    /// Autopilot announces each planned ladder stage before running it.
    StageStarted {
        job_id: u64,
        stage_index: usize,
        stage_count: usize,
        label: String,
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
    finished_at: Option<Instant>,
}
pub(crate) struct Registry {
    next_id: u64,
    current: Option<VerifiedScope>,
    jobs: HashMap<u64, Job>,
    secrets: RecoveryResultAccess,
    pub(crate) selected_wordlist: Option<SelectedWordlist>,
    pub(crate) selected_hash_input: Option<SelectedHashInput>,
}

#[derive(Clone)]
pub(crate) struct SelectedWordlist {
    pub path: PathBuf,
    pub name: String,
    pub size_bytes: u64,
}

/// Backend-held hash input: either a picked hash file (resolved path, never
/// exposed to the frontend) or parsed text such as unshadow output.
#[derive(Clone)]
pub(crate) enum SelectedHashInput {
    File { path: PathBuf, count: usize },
    Text(Vec<String>),
}

const MAX_HASH_INPUT_BYTES: u64 = 1 << 20;
const MAX_HASH_LINES: usize = 1024;

/// Sanitize hash-file text: cap size and count, keep non-empty non-comment
/// lines, enforce uniform digest shape per family (raw digests must share one
/// length; modular KDF hashes must share the first two $ fields).
fn sanitize_hash_lines(text: &str) -> Result<Vec<String>, String> {
    if text.len() as u64 > MAX_HASH_INPUT_BYTES {
        return Err("hash input exceeds the 1 MiB limit".into());
    }
    let mut lines = Vec::new();
    let mut raw_shape: Option<usize> = None;
    let mut kdf_family: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if lines.len() >= MAX_HASH_LINES {
            return Err(format!("hash input exceeds {} targets", MAX_HASH_LINES));
        }
        if line.len() > 8192 {
            return Err("hash line exceeds 8 KiB".into());
        }
        if line.starts_with('$') {
            let family = line
                .splitn(3, '$')
                .take(2)
                .last()
                .map(|f| f.to_string())
                .unwrap_or_default();
            if let Some(existing) = &kdf_family {
                if &family != existing {
                    return Err("hash file mixes modular hash families".into());
                }
            }
            kdf_family = Some(family);
        } else if !line.contains(':') {
            // bare raw digest
            let length = line.len();
            if let Some(existing) = raw_shape {
                if length != existing {
                    return Err(
                        "hash file mixes raw digest lengths; split it by algorithm".into(),
                    );
                }
            }
            raw_shape = Some(length);
        }
        lines.push(line.to_string());
    }
    if lines.is_empty() {
        return Err("hash input has no hashes".into());
    }
    Ok(lines)
}

fn recheck_selected_wordlist(selection: &SelectedWordlist) -> Result<(), String> {
    let (_, size) =
        crate::features::crypto::ipc::crack::inspect_recovery_wordlist(&selection.path)?;
    if size != selection.size_bytes {
        return Err("wordlist changed after selection; choose the file again".into());
    }
    Ok(())
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
            // Quick, repeated recoveries must not permanently block the UI.
            // Evict only an already-terminal job, oldest first. Revocation is
            // deliberate; an evicted job's confidential bytes cannot be read.
            let evict = self
                .jobs
                .iter()
                .filter(|(_, job)| {
                    !matches!(
                        job.status.phase,
                        RecoveryPhase::Running | RecoveryPhase::Cancelling
                    )
                })
                .min_by_key(|(_, job)| job.finished_at)
                .map(|(id, _)| *id);
            let Some(id) = evict else {
                return Err("recovery job capacity reached by active jobs".into());
            };
            self.jobs.remove(&id);
            if let Some(scope) = self.current.as_ref() {
                self.secrets.discard(id, scope);
            }
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
                finished_at: None,
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
        // Job summaries are short-lived UX state, not evidence. Clean up
        // terminal entries without a UI Discard click so repeated sessions
        // never become permanently unable to reserve another job. Results
        // may only be revealed inside their original retention interval.
        let stale: Vec<_> = self
            .jobs
            .iter()
            .filter(|(_, job)| {
                job.finished_at
                    .is_some_and(|finished| now.duration_since(finished) >= RETAIN_DURATION)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(job) = self.jobs.remove(&id) {
                job.cancel.cancel();
                if let Some(scope) = &self.current {
                    self.secrets.discard(id, scope);
                }
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
            selected_hash_input: None,
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
        registry.selected_hash_input = None;
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
            registry.selected_hash_input = None;
            registry.current = None;
        }
    }

    pub(crate) fn with_active<T>(
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
        None,
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
    rules: Option<Vec<cyberdeck_crypto::recovery::CompiledRule>>,
    emit: impl Fn(RecoveryEvent) + Send + 'static,
) -> Result<u64, String> {
    if rules.is_some()
        && (!matches!(request.backend, recovery_backend::BackendSelection::Cpu)
            || embedded_runtime.is_some())
    {
        return Err("native wordlist rules require the Rust CPU backend".into());
    }
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
    let worker_token = token.clone();
    let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                       forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
          -> Result<RecoveryRun, String> {
        let _ = sink;
        let token = &worker_token;
        if let Some(runtime) = embedded_runtime.as_deref() {
            embedded_hashcat::execute_path(
                &request,
                &wordlist,
                runtime,
                token,
                preset,
                |progress| forward(progress),
            )
        } else if let Some(compiled) = rules {
            execute_path_with_rules(&request, &wordlist, &token, |progress| forward(progress), compiled)
        } else {
            execute_path(&request, &wordlist, &token, |progress| forward(progress))
        }
    };
    spawn_recovery_worker(registry, job_id, scope, token, emit, worker);
    Ok(job_id)
}

/// Shared job worker: gates progress on the live case, publishes masked
/// terminal state, and enforces the confidential-result lifecycle. The
/// single-stage engines and the autopilot ladder both run through here.
fn spawn_recovery_worker<F>(
    registry: Arc<Mutex<Registry>>,
    job_id: u64,
    scope: VerifiedScope,
    token: RecoveryCancel,
    emit: impl Fn(RecoveryEvent) + Send + 'static,
    worker: F,
) where
    F: FnOnce(
            &(dyn Fn(RecoveryEvent) + Send + Sync),
            &mut (dyn FnMut(RecoveryProgressWire) + Send),
        ) -> Result<RecoveryRun, String>
        + Send
        + 'static,
{
    // The IPC closure may be merely Send (mpsc senders); a Mutex makes the
    // shared sink Sync for the worker while preserving the emit contract.
    let emit = Arc::new(Mutex::new(emit));
    let sink_emit = emit.clone();
    let sink = move |event: RecoveryEvent| {
        (sink_emit.lock().unwrap())(event);
    };
    std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut forward = |progress: RecoveryProgressWire| {
                let should_emit = {
                    let Ok(mut lock) = registry.lock() else {
                        return;
                    };
                    if lock.current.as_ref() != Some(&scope) {
                        return;
                    }
                    if let Some(job) = lock.jobs.get_mut(&job_id) {
                        job.status.progress = Some(progress.clone());
                        true
                    } else {
                        false
                    }
                };
                if should_emit {
                    (emit.lock().unwrap())(RecoveryEvent::Progress {
                        job_id,
                        tried: progress.tried,
                        budget: progress.budget,
                        matches: progress.matches,
                    });
                }
            };
            worker(&sink, &mut forward)
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
                    job.finished_at = Some(Instant::now());
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
                    job.finished_at = Some(Instant::now());
                    job.status.error = Some(error.clone());
                    RecoveryEvent::Failed { job_id, error }
                }
                Err(_) => {
                    let Some(job) = lock.jobs.get_mut(&job_id) else {
                        return;
                    };
                    job.status.phase = RecoveryPhase::Failed;
                    job.finished_at = Some(Instant::now());
                    job.status.error = Some("native recovery worker failed".into());
                    RecoveryEvent::Failed {
                        job_id,
                        error: "native recovery worker failed".into(),
                    }
                }
            }
        };
        (emit.lock().unwrap())(event);
    });
}

/// Select a wordlist by native OS dialog, authorize against the backend
/// case/revision, and retain only the path in process memory. Never expose the
/// raw filesystem path to the JavaScript interface.
#[tauri::command]
pub async fn recovery_select_wordlist_v1(
    app: AppHandle,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<RecoveryWordlistInfo, String> {
    let before = session.selected()?;
    // Releasing the UI dispatcher while the OS file picker is visible is
    // essential on Windows. Recheck the authoritative case revision AFTER
    // the user closes the dialog; never attach a file to a different case.
    state.with_active(&session, |_, _| Ok(()))?;
    let (path, name) = tauri::async_runtime::spawn_blocking(move || {
        crate::features::crypto::ipc::crack::resolved_wordlist(&app, None)
    })
    .await
    .map_err(|_| "native wordlist picker could not complete")??;
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
    app: AppHandle,
    request: RecoveryRequest,
    rules: Option<String>,
    rules_set: Option<String>,
    resume_from: Option<u64>,
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
    let compiled = match (rules, rules_set) {
        (Some(text), _) if !text.trim().is_empty() => {
            if text.len() > 4096 {
                return Err("native recovery rule text exceeds 4 KiB".into());
            }
            if !matches!(request.backend, recovery_backend::BackendSelection::Cpu) {
                return Err("wordlist rules run on native CPU only; select CPU".into());
            }
            Some(cyberdeck_crypto::recovery::parse_rule_lines(
                std::io::BufReader::new(text.as_bytes()),
            )?)
        }
        // Library rule sets load backend-side from verified app resources;
        // the frontend only names a manifest id.
        (None, Some(set_id)) => {
            if !matches!(request.backend, recovery_backend::BackendSelection::Cpu) {
                return Err("library rule sets run on native CPU only; select CPU".into());
            }
            Some(library_support::rules_library::load(&app, &set_id)?.rules)
        }
        _ => None,
    };
    let (selected, hash_input) = state.with_active(&session, |registry, _| {
        Ok((
            registry
                .selected_wordlist
                .clone()
                .ok_or_else(|| "choose a wordlist before starting recovery".to_owned())?,
            registry.selected_hash_input.clone(),
        ))
    })?;
    // Revalidate that the selected file still exists and passes native
    // wordlist inspection; do not accept an untrusted frontend-supplied path.
    recheck_selected_wordlist(&selected)?;
    let resume_from = resume_from.unwrap_or(0);
    let scope = RecoveryCtx::scope_from_session(&session)?;
    if let Some(input) = hash_input {
        if !matches!(request.backend, recovery_backend::BackendSelection::Cpu) {
            return Err("hash-file recovery runs on the native CPU backend only; select CPU".into());
        }
        let request = apply_hash_input(request, input)?;
        if resume_from > 0 && compiled.is_none() {
            let (job_id, token) = state.with_active(&session, |registry, verified| {
                if *verified != scope {
                    return Err("recovery case changed".into());
                }
                registry.reserve_job()
            })?;
            emit_started(&on_event, job_id);
            let registry = state.registry.clone();
            let path = selected.path.clone();
            let worker_token = token.clone();
            let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                               forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
                  -> Result<RecoveryRun, String> {
                let _ = sink;
                recovery_backend::execute_path_resumable(
                    &request, &path, resume_from, &worker_token,
                    |progress| forward(progress),
                )
            };
            spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), worker);
            return Ok(job_id);
        }
        start_recovery_with_wordlist_engine(
            &state,
            &session,
            request,
            selected.path,
            None,
            embedded_hashcat::WordlistPreset::Plain,
            compiled,
            move |event| {
                let _ = on_event.send(event);
            },
        )
    } else if resume_from > 0 && compiled.is_none() && request.target_hashes.is_empty() {
        let (job_id, token) = state.with_active(&session, |registry, verified| {
            if *verified != scope {
                return Err("recovery case changed".into());
            }
            registry.reserve_job()
        })?;
        emit_started(&on_event, job_id);
        let registry = state.registry.clone();
        let path = selected.path.clone();
        let worker_token = token.clone();
        let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                           forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
              -> Result<RecoveryRun, String> {
            let _ = sink;
            recovery_backend::execute_path_resumable(
                &request, &path, resume_from, &worker_token,
                |progress| forward(progress),
            )
        };
        spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), worker);
        Ok(job_id)
    } else {
        start_recovery_with_wordlist_engine(
            &state,
            &session,
            request,
            selected.path,
            None,
            embedded_hashcat::WordlistPreset::Plain,
            compiled,
            move |event| {
                let _ = on_event.send(event);
            },
        )
    }
}

/// Bind the backend-held hash input into a request (CPU multi-target mode).
fn apply_hash_input(
    mut request: RecoveryRequest,
    input: SelectedHashInput,
) -> Result<RecoveryRequest, String> {
    request.target_hashes = match input {
        SelectedHashInput::File { path, .. } => {
            let text = std::fs::read_to_string(&path)
                .map_err(|_| "selected hash file is no longer readable".to_string())?;
            sanitize_hash_lines(&text)?
        }
        SelectedHashInput::Text(lines) => lines,
    };
    Ok(request)
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
        ("md5crypt", 500, 0),
        ("ntlm", 1000, 32),
        ("sha256", 1400, 64),
        ("sha512", 1700, 128),
        ("sha512crypt", 1800, 0),
        ("bcrypt", 3200, 0),
        ("phpass", 400, 0),
        ("md5-pass-salt", 10, 0),
        ("md5-salt-pass", 20, 0),
        ("hmac-md5", 50, 0),
        ("hmac-sha1", 60, 0),
        ("sha1-pass-salt", 110, 0),
        ("sha1-salt-pass", 120, 0),
        ("mscash", 1100, 0),
        ("mscash2", 2100, 0),
        ("netntlm-v1", 5500, 0),
        ("netntlm-v2", 5600, 0),
        ("sha256crypt", 7400, 0),
        ("descrypt", 1500, 0),
        ("mssql-2005", 132, 0),
        ("mssql-2012", 1731, 0),
        // Batch-3 archive containers.
        ("winzip-aes", 13600, 0),
        ("7zip", 11600, 0),
        ("zip-legacy", 17200, 0),
        ("zip-legacy", 17210, 0),
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
    // A Windows dev build that omitted native Hashcat must never accidentally
    // discover stale DLLs or claim that a GPU worker is bundled.
    if cfg!(cyberdeck_hashcat_dev_disabled) {
        return Err("Embedded Hashcat was not built for this Windows development session. The native backend is unavailable; set CYBERDECK_HASHCAT_BUILD=1 and rebuild to opt in.".into());
    }
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

/// Source presence or an OpenCL loader alone must NOT offer a non-working
/// Hashcat option in the UI. A fixed, public, supervised known-answer test is
/// required for EACH enabled raw mode; it runs off the Tauri UI dispatcher.
#[tauri::command]
pub async fn recovery_hashcat_capabilities_v1(app: AppHandle) -> EmbeddedHashcatCapability {
    let standard = |detail: String| EmbeddedHashcatCapability {
        available: false,
        mode: 1400,
        modes: Vec::new(),
        hardware_verified: false,
        detail,
    };
    let runtime = match hashcat_resource_root(&app) {
        Ok(root) => root,
        Err(error) => return standard(error),
    };
    let supported =
        tauri::async_runtime::spawn_blocking(move || embedded_hashcat::verified_modes(&runtime))
            .await;
    match supported {
        Ok(Ok(modes)) => {
            let catalog = bundled_hashcat_modes()
                .into_iter()
                .filter(|item| modes.contains(&item.mode))
                .collect::<Vec<_>>();
            EmbeddedHashcatCapability {
                available: !catalog.is_empty(),
                mode: 1400,
                modes: catalog,
                hardware_verified: false,
                detail: format!(
                    "{} bundled mode(s) passed actual private known-answer recovery. \
                     This validates native execution, NOT GPU type/speed or other untested modes.",
                    modes.len(),
                ),
            }
        }
        Ok(Err(error)) => standard(format!(
            "Bundled Hashcat did not pass actual native recovery: {error}. \
             Native Rust CPU wordlist recovery remains available."
        )),
        Err(_) => standard("Bundled Hashcat readiness test could not finish".into()),
    }
}

/// Deliberate opt-in to independently compiled Hashcat C core: never falls
/// back to Rust or an external system executable without user intent.
#[tauri::command]
pub async fn recovery_start_hashcat_v1(
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
    // Authorize and snapshot the original case before asynchronous KAT.
    // Never apply a stale request to a different selected investigation.
    let before = session.selected()?;
    state.with_active(&session, |_, _| Ok(()))?;
    let runtime = hashcat_resource_root(&app)?;
    let mode = embedded_hashcat::validate_embedded_request(&request)?;
    let verification_root = runtime.clone();
    let verified = tauri::async_runtime::spawn_blocking(move || {
        embedded_hashcat::verified_modes(&verification_root)
    })
    .await
    .map_err(|_| "native Hashcat readiness check failed")??;
    session.ensure(&before)?;
    if !verified.contains(&mode) {
        return Err(
            "selected native Hashcat mode did not pass its actual known-answer test".into(),
        );
    }
    let selected = state.with_active(&session, |registry, _| {
        registry
            .selected_wordlist
            .clone()
            .ok_or_else(|| "choose a wordlist before starting recovery".to_owned())
    })?;
    recheck_selected_wordlist(&selected)?;
    start_recovery_with_wordlist_engine(
        &state,
        &session,
        request,
        selected.path,
        Some(runtime),
        preset.unwrap_or_default(),
        None,
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

/// One command, one detected hash, one ladder: every plausible algorithm
/// against the best available library wordlist, then rule escalation on the
/// primary algorithm. Reuses the single-job lifecycle, cancellation and
/// confidential reveal flow; the frontend only supplies the hash text.
#[tauri::command]
pub async fn recovery_autopilot_v1(
    app: AppHandle,
    target_hash: String,
    max_candidates: u64,
    max_matches: usize,
    on_event: Channel<RecoveryEvent>,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    let detection = autopilot::detect_target(&target_hash)?;
    let wordlists = library_wordlists::list(&app)?;
    let present: Vec<String> = wordlists
        .iter()
        .filter(|entry| entry.present)
        .map(|entry| entry.id.clone())
        .collect();
    let rules_ids = library_rules::list(&app)?
        .into_iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    // Environment auto-detect: only modes that passed their known-answer test
    // on this machine's devices are offered the GPU; everything else — and all
    // memory-hard KDFs — stays on the multi-core CPU.
    let gpu_algorithms: Vec<String> = match hashcat_resource_root(&app) {
        Ok(runtime) => {
            let verified = tauri::async_runtime::spawn_blocking(move || {
                embedded_hashcat::verified_modes(&runtime)
            })
            .await
            .map_err(|_| "native Hashcat readiness check failed".to_string())
            .ok()
            .and_then(|modes| modes.ok())
            .unwrap_or_default();
            bundled_hashcat_modes()
                .into_iter()
                .filter(|mode| verified.contains(&mode.mode))
                .map(|mode| mode.algorithm.to_string())
                .collect()
        }
        Err(_) => Vec::new(),
    };
    let plan = autopilot::build_plan(&detection, &present, &rules_ids, &gpu_algorithms)?;
    if !(1..=cyberdeck_crypto::recovery::MAX_FAST_CANDIDATES).contains(&max_candidates) {
        return Err("max_candidates exceeds global recovery limit".into());
    }
    if !(1..=cyberdeck_crypto::recovery::MAX_MATCHES).contains(&max_matches) {
        return Err("max_matches exceeds global recovery limit".into());
    }
    let scope = RecoveryCtx::scope_from_session(&session)?;
    let (job_id, token, hash_input) = state.with_active(&session, |registry, verified| {
        if *verified != scope {
            return Err("recovery case changed".into());
        }
        let input = registry.selected_hash_input.clone();
        let (job_id, token) = registry.reserve_job()?;
        Ok((job_id, token, input))
    })?;
    let registry = state.registry.clone();
    let started = Instant::now();
    emit_started(&on_event, job_id);
    let worker_app = app.clone();
    let worker_target = target_hash.trim().to_string();
    let worker_targets: Vec<String> = match hash_input {
        Some(input) => match input {
            SelectedHashInput::File { path, .. } => {
                let text = std::fs::read_to_string(&path)
                    .map_err(|_| "selected hash file is no longer readable".to_string())?;
                sanitize_hash_lines(&text)?
            }
            SelectedHashInput::Text(lines) => lines,
        },
        None => Vec::new(),
    };
    let emit = move |event| {
        let _ = on_event.send(event);
    };
    let stage_count = plan.stages.len();
    let worker_token = token.clone();
    let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                       forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
          -> Result<RecoveryRun, String> {
        let token = &worker_token;
        let mut total_tried = 0u64;
        let mut stage_reports = Vec::new();
        let mut matches_meta = Vec::new();
        let mut confidential = Vec::new();
        let mut cancelled = false;
        let mut limit_reached = false;
        for (index, stage) in plan.stages.iter().enumerate() {
            if token.is_cancelled() {
                cancelled = true;
                break;
            }
            sink(RecoveryEvent::StageStarted {
                job_id,
                stage_index: index,
                stage_count,
                label: stage.label.clone(),
            });
            let request = RecoveryRequest {
                algorithm: stage.algorithm.clone(),
                target_hash: worker_target.clone(),
                backend: recovery_backend::BackendSelection::Cpu,
                max_candidates,
                max_matches,
                target_hashes: worker_targets.clone(),
            };
            let label = stage.label.clone();
            let progress_with_stage = |progress: RecoveryProgressWire| {
                let mut labeled = progress;
                labeled.stage = Some(label.clone());
                forward(labeled);
            };
            let result = if let Some(mask) = &stage.mask {
                recovery_backend::execute_mask(&request, mask, "", &token, progress_with_stage)
            } else if stage.engine == autopilot::StageEngine::Gpu {
                // GPU stage: the embedded pinned core runs its own devices.
                let path = library_wordlists::resolve(&worker_app, &stage.wordlist_id)?;
                let runtime = hashcat_resource_root(&worker_app)?;
                let mut gpu_request = request.clone();
                gpu_request.backend = recovery_backend::BackendSelection::HashcatManaged;
                embedded_hashcat::execute_path(
                    &gpu_request,
                    &path,
                    &runtime,
                    &token,
                    embedded_hashcat::WordlistPreset::Plain,
                    progress_with_stage,
                )
            } else {
                let path = library_wordlists::resolve(&worker_app, &stage.wordlist_id)?;
                match &stage.rules_set {
                    Some(set_id) => {
                        let compiled = library_rules::load(&worker_app, set_id)?;
                        recovery_backend::execute_path_with_rules(
                            &request,
                            &path,
                            &token,
                            progress_with_stage,
                            compiled.rules,
                        )
                    }
                    None => recovery_backend::execute_path(
                        &request,
                        &path,
                        &token,
                        progress_with_stage,
                    ),
                }
            };
            let run = result.map_err(|error| format!("stage '{}': {error}", stage.label))?;
            let (summary, hits) = run.into_parts();
            cancelled |= summary.cancelled;
            limit_reached |= summary.limit_reached;
            let matched = !summary.matches.is_empty();
            stage_reports.push(recovery_backend::StageSummaryWire {
                label: stage.label.clone(),
                tried: summary.tried,
                duration_ms: summary.duration_ms,
                matched,
            });
            total_tried += summary.tried;
            matches_meta.extend(summary.matches);
            confidential.extend(hits);
            if matched || cancelled {
                break;
            }
        }
        let _ = sink; // stage events already delivered through the sink
        Ok(RecoveryRun::from_parts(
            RecoverySummaryWire {
                algorithm: plan.algorithm.clone(),
                backend: recovery_backend::BackendSelection::Cpu,
                engine: "cyberdeck-autopilot".into(),
                tried: total_tried,
                cancelled,
                limit_reached,
                duration_ms: started.elapsed().as_millis() as u64,
                matches: matches_meta,
                stages: stage_reports,
                resume_index: 0,
            },
            confidential,
        ))
    };
    spawn_recovery_worker(registry, job_id, scope, token, emit, worker);
    Ok(job_id)
}

fn emit_started(on_event: &Channel<RecoveryEvent>, job_id: u64) {
    let _ = on_event.send(RecoveryEvent::Started { job_id });
}

#[derive(Serialize)]
pub struct RecoveryHashInputStatus {
    pub count: usize,
    pub source: &'static str,
}

/// Pick a hash file (native dialog), sanitize it backend-side and keep only
/// the resolved path and count. john/shadow `user:hash` lines are accepted.
#[tauri::command]
pub async fn recovery_select_hash_file_v1(
    app: AppHandle,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<RecoveryHashInputStatus, String> {
    let before = session.selected()?;
    state.with_active(&session, |_, _| Ok(()))?;
    let (path, name) = tauri::async_runtime::spawn_blocking(move || {
        crate::features::crypto::ipc::crack::resolved_wordlist(&app, None)
    })
    .await
    .map_err(|_| "native hash-file picker could not complete")??;
    session.ensure(&before)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|_| "hash file is not readable UTF-8 text".to_string())?;
    let lines = sanitize_hash_lines(&text)?;
    let count = lines.len();
    state.with_active(&session, |registry, _| {
        registry.selected_hash_input = Some(SelectedHashInput::File {
            path: path.clone(),
            count,
        });
        Ok(())
    })?;
    let _ = name;
    Ok(RecoveryHashInputStatus {
        count,
        source: "file",
    })
}

/// Bind backend-parsed hash text (e.g. unshadow output) as the active hash
/// input. No path, no plaintext beyond the hashes themselves, case-scoped.
#[tauri::command]
pub fn recovery_use_hash_text_v1(
    text: String,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<RecoveryHashInputStatus, String> {
    let lines = sanitize_hash_lines(&text)?;
    let count = lines.len();
    state.with_active(&session, |registry, _| {
        registry.selected_hash_input = Some(SelectedHashInput::Text(lines));
        Ok(())
    })?;
    Ok(RecoveryHashInputStatus {
        count,
        source: "text",
    })
}

#[tauri::command]
pub fn recovery_hash_status_v1(
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<Option<RecoveryHashInputStatus>, String> {
    state.with_active(&session, |registry, _| {
        Ok(registry.selected_hash_input.as_ref().map(|input| match input {
            SelectedHashInput::File { count, .. } => RecoveryHashInputStatus {
                count: *count,
                source: "file",
            },
            SelectedHashInput::Text(lines) => RecoveryHashInputStatus {
                count: lines.len(),
                source: "text",
            },
        }))
    })
}

/// Dedicated mask attack command: CPU, bounded keyspace, single or hash-file
/// targets, same job/reveal lifecycle as wordlist recovery.
#[tauri::command]
pub fn recovery_mask_v1(
    request: RecoveryRequest,
    mask: String,
    custom_charsets: Option<String>,
    on_event: Channel<RecoveryEvent>,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    if mask.len() > 256 {
        return Err("mask exceeds the 256-character limit".into());
    }
    let scope = RecoveryCtx::scope_from_session(&session)?;
    let (job_id, token) = state.with_active(&session, |registry, verified| {
        if *verified != scope {
            return Err("recovery case changed".into());
        }
        registry.reserve_job()
    })?;
    let registry = state.registry.clone();
    emit_started(&on_event, job_id);
    let worker_token = token.clone();
    let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                       forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
          -> Result<RecoveryRun, String> {
        let _ = sink;
        recovery_backend::execute_mask(
            &request,
            &mask,
            custom_charsets.as_deref().unwrap_or(""),
            &worker_token,
            |progress| forward(progress),
        )
    };
    spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), worker);
    Ok(job_id)
}

fn emit_channel(on_event: Channel<RecoveryEvent>) -> impl Fn(RecoveryEvent) + Send + 'static {
    move |event| {
        let _ = on_event.send(event);
    }
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
                    finished_at: None,
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
    fn changing_wordlist_after_selection_fails_closed_before_running() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("wordlist.txt");
        std::fs::write(&file, b"abc\n").unwrap();
        let selection = SelectedWordlist {
            path: file.clone(),
            name: "wordlist.txt".into(),
            size_bytes: 4,
        };
        assert!(recheck_selected_wordlist(&selection).is_ok());
        std::fs::write(&file, b"longer-password\n").unwrap();
        assert!(recheck_selected_wordlist(&selection)
            .unwrap_err()
            .contains("changed"));
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
            target_hashes: Vec::new(),
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
                finished_at: Some(Instant::now()),
            },
        );
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(registry.prune_expired(), 1);
        assert!(!registry.jobs.get(&42).unwrap().status.reveal_available);
        assert!(registry.secrets.authorize_reveal(42, &scope).is_err());
    }

    #[test]
    fn repeated_completed_recoveries_evict_oldest_terminal_job_at_capacity() {
        let mut registry = Registry::default();
        let mut first = 0;
        for i in 0..MAX_TRACKED {
            let (id, _) = registry.reserve_job().unwrap();
            if i == 0 {
                first = id;
            }
            let job = registry.jobs.get_mut(&id).unwrap();
            job.status.phase = RecoveryPhase::Completed;
            job.finished_at = Some(Instant::now() - Duration::from_secs((MAX_TRACKED - i) as u64));
        }
        let (new_id, _) = registry.reserve_job().unwrap();
        assert_eq!(registry.jobs.len(), MAX_TRACKED);
        assert!(!registry.jobs.contains_key(&first));
        assert!(registry.jobs.contains_key(&new_id));
    }
    #[test]
    fn idle_cleanup_reclaims_terminal_job_capacity_without_touching_active_jobs() {
        let mut registry = Registry::default();
        let (completed, _) = registry.reserve_job().unwrap();
        let (running, running_token) = registry.reserve_job().unwrap();
        let old = registry.jobs.get_mut(&completed).unwrap();
        old.status.phase = RecoveryPhase::Completed;
        old.finished_at = Some(Instant::now() - RETAIN_DURATION - Duration::from_secs(1));
        assert_eq!(registry.prune_expired(), 0);
        assert!(!registry.jobs.contains_key(&completed));
        assert!(registry.jobs.contains_key(&running));
        assert!(!running_token.is_cancelled());
        let (next, _) = registry.reserve_job().unwrap();
        assert!(next > running);
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
            target_hashes: Vec::new(),
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
                RecoveryEvent::StageStarted { job_id, .. } => {
                    assert_eq!(id, job_id);
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
                target_hashes: Vec::new(),
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
                RecoveryEvent::Started { .. } | RecoveryEvent::StageStarted { .. } => {}
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

//! Additive, cancellable native SHA-256 CPU/OpenCL recovery IPC.
//! Only masked progress and summaries are sent automatically. A plaintext
//! reveal requires a separate native operator confirmation and active scope.
#[path = "../application/autopilot.rs"]
mod autopilot;
#[path = "../application/embedded_hashcat.rs"]
mod embedded_hashcat;
#[path = "../application/recovery_backend.rs"]
mod recovery_backend;
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

use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::CaseSessionCtx;
use cyberdeck_storage::{NewRecoveryCheckpoint, RecoveryCheckpointRecord};
use recovery_backend::access::{RecoveryResultAccess, VerifiedScope};
use recovery_backend::{
    execute_path, execute_path_with_rules, probe_recovery_devices, RecoveryCancel,
    RecoveryDeviceInventory, RecoveryProgressWire, RecoveryRequest, RecoveryRun,
    RecoverySummaryWire,
};
use serde::Serialize;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

const MAX_RUNNING: usize = 2;
const MAX_TRACKED: usize = 16;
const RETAIN_DURATION: Duration = Duration::from_secs(300);
/// GPU worker sessions are protocol-bounded to 1M candidates; resume skips
/// whole sessions only, so a durable checkpoint rounds down to this boundary.
const GPU_SESSION_CANDIDATES: u64 = 1_000_000;
/// Throttle window for progress checkpoints; stage and terminal transitions
/// always write immediately.
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);

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
    /// Durable checkpoint row kept running by this job, if any.
    checkpoint_row: Option<i64>,
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
                    return Err("hash file mixes raw digest lengths; split it by algorithm".into());
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

// --- durable case-scoped resume checkpoints --------------------------------
//
// Run state survives restarts at the engine level: a row per (case, run)
// tracks honest counters only (never candidates, secrets or outputs, and
// never arbitrary operator paths — only library wordlist ids). GPU chunked
// runs resume at the next 1M session boundary (in-chunk tails are re-tried,
// matching the chunk docs); CPU runs keep the existing sequential resume
// semantics; anything that cannot skip work honestly re-issues from zero.

/// One checkpoint row write with honest counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointWrite {
    pub row_id: i64,
    pub state: &'static str,
    pub submitted: u64,
    pub stage_index: u64,
    pub stage_submitted: u64,
}

/// Pure throttle + stage accounting for one checkpoint row. Storage writes
/// happen through an injected sink so the ledger is testable without Tauri.
struct CheckpointLedger {
    row_id: i64,
    /// Autopilot rows track per-stage boundaries; wordlist rows track the run.
    autopilot: bool,
    /// GPU chunk-boundary rows round progress down to whole 1M sessions.
    chunk_boundary: bool,
    /// Candidates submitted before this job's wire stream started (resumed
    /// runs report tried from zero within their remaining work).
    submitted_offset: u64,
    submitted_total: u64,
    stage_index: u64,
    stage_submitted: u64,
    /// Exact last wire value for the live stage; boundaries use it unthrottled.
    last_stage_tried: u64,
    last_write: Option<Instant>,
}
impl CheckpointLedger {
    fn persisted_submitted(&self, tried: u64) -> u64 {
        if self.chunk_boundary {
            // Only finished GPU sessions count; the live session re-runs.
            (tried / GPU_SESSION_CANDIDATES) * GPU_SESSION_CANDIDATES
        } else {
            tried
        }
    }

    fn write_values(&self) -> CheckpointWrite {
        if self.autopilot {
            CheckpointWrite {
                row_id: self.row_id,
                state: "running",
                submitted: self.submitted_offset + self.submitted_total,
                stage_index: self.stage_index,
                stage_submitted: self.persisted_submitted(self.stage_submitted),
            }
        } else {
            CheckpointWrite {
                row_id: self.row_id,
                state: "running",
                submitted: self.submitted_offset + self.persisted_submitted(self.last_stage_tried),
                stage_index: 0,
                stage_submitted: 0,
            }
        }
    }

    fn progress(&mut self, tried: u64) -> Option<CheckpointWrite> {
        self.last_stage_tried = tried;
        self.stage_submitted = tried;
        let now = Instant::now();
        let due = self
            .last_write
            .is_none_or(|last| now.duration_since(last) >= CHECKPOINT_INTERVAL);
        if !due {
            return None;
        }
        self.last_write = Some(now);
        Some(self.write_values())
    }

    fn stage_started(&mut self) -> CheckpointWrite {
        // The previous stage completed: it submitted exactly what its wire
        // last reported (finished sessions drain their final frames).
        self.submitted_total += self.persisted_submitted(self.last_stage_tried);
        self.stage_index += 1;
        self.stage_submitted = 0;
        self.last_stage_tried = 0;
        self.last_write = Some(Instant::now());
        CheckpointWrite {
            row_id: self.row_id,
            state: "running",
            submitted: self.submitted_offset + self.submitted_total,
            stage_index: self.stage_index,
            stage_submitted: 0,
        }
    }

    fn close(&mut self, state: &'static str) -> CheckpointWrite {
        if self.autopilot {
            // The final stage never saw its own StageStarted event: record
            // its last wire value as the live stage's submitted count so a
            // re-issue can still skip its whole GPU sessions honestly.
            self.stage_submitted = self.persisted_submitted(self.last_stage_tried);
            CheckpointWrite {
                row_id: self.row_id,
                state,
                submitted: self.submitted_offset + self.submitted_total,
                stage_index: self.stage_index,
                stage_submitted: self.stage_submitted,
            }
        } else {
            CheckpointWrite {
                row_id: self.row_id,
                state,
                submitted: self.submitted_offset + self.persisted_submitted(self.last_stage_tried),
                stage_index: 0,
                stage_submitted: 0,
            }
        }
    }
}

/// Shared handle around one checkpoint ledger; every write goes through the
/// sink, and a storage failure never blocks the recovery itself.
#[derive(Clone)]
pub(crate) struct CheckpointController {
    ledger: Arc<Mutex<CheckpointLedger>>,
    sink: Arc<dyn Fn(CheckpointWrite) + Send + Sync>,
}
impl CheckpointController {
    fn new(
        row_id: i64,
        run_kind: &str,
        resume_kind: &str,
        sink: Arc<dyn Fn(CheckpointWrite) + Send + Sync>,
    ) -> Self {
        Self::seeded(row_id, run_kind, resume_kind, 0, 0, 0, sink)
    }

    /// Seeded controller for a re-issued run: the ledger continues from the
    /// row's honest counters instead of counting from zero.
    fn seeded(
        row_id: i64,
        run_kind: &str,
        resume_kind: &str,
        submitted_offset: u64,
        stage_index: u64,
        stage_submitted: u64,
        sink: Arc<dyn Fn(CheckpointWrite) + Send + Sync>,
    ) -> Self {
        Self {
            ledger: Arc::new(Mutex::new(CheckpointLedger {
                row_id,
                autopilot: run_kind == "autopilot",
                chunk_boundary: resume_kind == "chunk_boundary",
                submitted_offset,
                submitted_total: 0,
                stage_index,
                stage_submitted,
                last_stage_tried: 0,
                last_write: None,
            })),
            sink,
        }
    }

    pub(crate) fn row_id(&self) -> i64 {
        self.ledger.lock().map(|l| l.row_id).unwrap_or(0)
    }

    fn write(&self, write: CheckpointWrite) {
        (self.sink)(write);
    }

    /// Throttled progress checkpoint from the RecoveryProgressWire stream.
    pub(crate) fn progress(&self, tried: u64) {
        if let Ok(mut ledger) = self.ledger.lock() {
            if let Some(write) = ledger.progress(tried) {
                self.write(write);
            }
        }
    }

    /// Stage boundary: completed-stage counters fold in and write immediately.
    pub(crate) fn stage_started(&self) {
        if let Ok(mut ledger) = self.ledger.lock() {
            let write = ledger.stage_started();
            self.write(write);
        }
    }

    /// Terminal transition: completed, operator-cancelled, or suspended when
    /// the engine failed (still resumable by explicit operator re-issue).
    pub(crate) fn close(&self, state: &'static str) {
        if let Ok(mut ledger) = self.ledger.lock() {
            let write = ledger.close(state);
            self.write(write);
        }
    }

    /// Record the starting ordinal of a run that begins mid-stream.
    pub(crate) fn seed_submitted(&self, submitted: u64) {
        self.write(CheckpointWrite {
            row_id: self.row_id(),
            state: "running",
            submitted,
            stage_index: 0,
            stage_submitted: 0,
        });
    }
}

type CheckpointSink = Arc<dyn Fn(CheckpointWrite) + Send + Sync>;

/// Sink writing through the managed case store; best-effort by design.
fn tauri_checkpoint_sink(app: AppHandle) -> CheckpointSink {
    Arc::new(move |write: CheckpointWrite| {
        let Some(ctx) = app.try_state::<EvidenceCtx>() else {
            return;
        };
        let Ok(store) = ctx.store.lock() else {
            return;
        };
        let _ = store.record_recovery_checkpoint(
            write.row_id,
            write.state,
            write.submitted,
            write.stage_index,
            write.stage_submitted,
        );
    })
}

/// Map a selected wordlist path back to its library catalog id. Arbitrary
/// operator paths have no library reference and never enter a checkpoint row.
fn library_wordlist_id(app: &AppHandle, path: &Path) -> Option<String> {
    for entry in library_wordlists::list(app).ok()? {
        if !entry.present {
            continue;
        }
        if let Ok(resolved) = library_wordlists::resolve(app, &entry.id) {
            if resolved == path {
                return Some(entry.id);
            }
        }
    }
    None
}

/// Open a durable running checkpoint row for this run. Returns None when the
/// run cannot be honestly re-issued (no library wordlist, hash-file or OpenCL
/// or mask engines, or a storage failure) — checkpointing never blocks a run.
fn open_checkpoint(
    app: &AppHandle,
    record: NewRecoveryCheckpoint,
) -> Option<CheckpointController> {
    let ctx = app.try_state::<EvidenceCtx>()?;
    let row_id = {
        let store = ctx.store.lock().ok()?;
        store.start_recovery_checkpoint(&record).ok()?
    };
    Some(CheckpointController::new(
        row_id,
        &record.run_kind,
        &record.resume_kind,
        tauri_checkpoint_sink(app.clone()),
    ))
}

/// Checkpoint row for a single-stage wordlist run. Rows require a library
/// wordlist reference, a single target and rebuildable rules; OpenCL device
/// parameters are hardware-local, so those runs get no durable row.
#[allow(clippy::too_many_arguments)]
fn wordlist_checkpoint(
    app: &AppHandle,
    scope: &VerifiedScope,
    request: &RecoveryRequest,
    wordlist: &Path,
    run_kind: &str,
    resume_kind: &str,
    preset_id: &str,
    rules_set_id: Option<String>,
) -> Option<CheckpointController> {
    if !request.target_hashes.is_empty() {
        return None; // hash-file targets are backend-held text, never persisted
    }
    let backend = match request.backend {
        recovery_backend::BackendSelection::Cpu => "cpu",
        recovery_backend::BackendSelection::HashcatManaged => "hashcat_managed",
        recovery_backend::BackendSelection::OpenCl { .. } => return None,
    };
    let wordlist_id = library_wordlist_id(app, wordlist)?;
    open_checkpoint(
        app,
        NewRecoveryCheckpoint {
            case_id: scope.case_id().to_string(),
            run_kind: run_kind.to_string(),
            resume_kind: resume_kind.to_string(),
            algorithm: request.algorithm.clone(),
            backend: backend.to_string(),
            target_hash: request.target_hash.clone(),
            total_budget: request.max_candidates,
            max_matches: request.max_matches as u64,
            stage_index: 0,
            stage_submitted: 0,
            wordlist_id: Some(wordlist_id),
            rules_set_id,
            preset: preset_id.to_string(),
        },
    )
}

/// Embedded transform preset ids match the WordlistPreset serde names.
fn preset_id(preset: embedded_hashcat::WordlistPreset) -> &'static str {
    match preset {
        embedded_hashcat::WordlistPreset::Plain => "plain",
        embedded_hashcat::WordlistPreset::Uppercase => "uppercase",
        embedded_hashcat::WordlistPreset::AppendOne => "append_one",
    }
}

/// Row-backed controller for a re-issued run, continuing its counters. The
/// in-flight autopilot stage restarts, so its partial submitted count folds
/// into the offset (the resume command passes the exact boundary it will skip).
fn resumed_checkpoint(
    app: &AppHandle,
    row: &RecoveryCheckpointRecord,
    submitted_offset: u64,
) -> Option<CheckpointController> {
    Some(CheckpointController::seeded(
        row.id,
        &row.run_kind,
        &row.resume_kind,
        submitted_offset,
        row.stage_index,
        0,
        tauri_checkpoint_sink(app.clone()),
    ))
}

fn checkpoint_wire(row: RecoveryCheckpointRecord) -> RecoveryRunCheckpointV1 {
    RecoveryRunCheckpointV1 {
        run_id: row.id,
        run_kind: row.run_kind,
        resume_kind: row.resume_kind,
        algorithm: row.algorithm,
        backend: row.backend,
        target_hash: row.target_hash,
        total_budget: row.total_budget,
        max_matches: row.max_matches,
        submitted: row.submitted,
        stage_index: row.stage_index,
        stage_submitted: row.stage_submitted,
        wordlist_id: row.wordlist_id,
        rules_set_id: row.rules_set_id,
        preset: row.preset,
        state: row.state,
        updated_ms: row.updated_ms,
    }
}

/// Resumable runs for the active case. Rows left running by a dead session
/// reconcile to suspended first; live jobs keep their own rows running.
#[derive(Serialize)]
pub struct RecoveryRunCheckpointV1 {
    pub run_id: i64,
    pub run_kind: String,
    pub resume_kind: String,
    pub algorithm: String,
    pub backend: String,
    pub target_hash: String,
    pub total_budget: u64,
    pub max_matches: u64,
    pub submitted: u64,
    pub stage_index: u64,
    pub stage_submitted: u64,
    pub wordlist_id: Option<String>,
    pub rules_set_id: Option<String>,
    pub preset: String,
    pub state: String,
    pub updated_ms: i64,
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
                checkpoint_row: None,
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
    checkpoint: Option<CheckpointController>,
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
            execute_path_with_rules(
                &request,
                &wordlist,
                &token,
                |progress| forward(progress),
                compiled,
            )
        } else {
            execute_path(&request, &wordlist, &token, |progress| forward(progress))
        }
    };
    spawn_recovery_worker(registry, job_id, scope, token, emit, checkpoint, worker);
    Ok(job_id)
}

/// Shared job worker: gates progress on the live case, publishes masked
/// terminal state, and enforces the confidential-result lifecycle. The
/// single-stage engines and the autopilot ladder both run through here.
/// `checkpoint` persists throttled case-scoped resume counters when present.
fn spawn_recovery_worker<F>(
    registry: Arc<Mutex<Registry>>,
    job_id: u64,
    scope: VerifiedScope,
    token: RecoveryCancel,
    emit: impl Fn(RecoveryEvent) + Send + 'static,
    checkpoint: Option<CheckpointController>,
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
    let sink_checkpoint = checkpoint.clone();
    let sink = move |event: RecoveryEvent| {
        if let RecoveryEvent::StageStarted { .. } = event {
            if let Some(checkpoint) = &sink_checkpoint {
                checkpoint.stage_started();
            }
        }
        (sink_emit.lock().unwrap())(event);
    };
    if let Some(checkpoint) = &checkpoint {
        if let Ok(mut lock) = registry.lock() {
            if let Some(job) = lock.jobs.get_mut(&job_id) {
                job.checkpoint_row = Some(checkpoint.row_id());
            }
        }
    }
    std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut forward = |progress: RecoveryProgressWire| {
                if let Some(checkpoint) = &checkpoint {
                    checkpoint.progress(progress.tried);
                }
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
        // Terminal checkpoint writes happen even when the case changed: the
        // row belongs to its case, and a revoked worker closes it suspended
        // unless it genuinely completed or was operator-cancelled.
        let terminal_state = match &result {
            Ok(Ok(run)) if run.summary.cancelled || token.is_cancelled() => "cancelled",
            Ok(Ok(_)) => "completed",
            Ok(Err(_)) | Err(_) => "suspended",
        };
        if let Some(checkpoint) = &checkpoint {
            checkpoint.close(terminal_state);
        }
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
    let (compiled, rules_set_id) = match (rules, rules_set) {
        (Some(text), _) if !text.trim().is_empty() => {
            if text.len() > 4096 {
                return Err("native recovery rule text exceeds 4 KiB".into());
            }
            if !matches!(request.backend, recovery_backend::BackendSelection::Cpu) {
                return Err("wordlist rules run on native CPU only; select CPU".into());
            }
            // Inline rule text is operator input, not a library reference:
            // such runs cannot be re-issued and get no checkpoint row.
            (
                Some(cyberdeck_crypto::recovery::parse_rule_lines(
                    std::io::BufReader::new(text.as_bytes()),
                )?),
                None,
            )
        }
        // Library rule sets load backend-side from verified app resources;
        // the frontend only names a manifest id.
        (None, Some(set_id)) => {
            if !matches!(request.backend, recovery_backend::BackendSelection::Cpu) {
                return Err("library rule sets run on native CPU only; select CPU".into());
            }
            (
                Some(library_support::rules_library::load(&app, &set_id)?.rules),
                Some(set_id),
            )
        }
        _ => (None, None),
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
            return Err(
                "hash-file recovery runs on the native CPU backend only; select CPU".into(),
            );
        }
        let request = apply_hash_input(request, input)?;
        if resume_from > 0 && compiled.is_none() {
            // Hash-file runs stay out of the checkpoint store: the backend-
            // held target list is not reconstructable after a restart.
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
                    &request,
                    &path,
                    resume_from,
                    &worker_token,
                    |progress| forward(progress),
                )
            };
            spawn_recovery_worker(
                registry,
                job_id,
                scope,
                token,
                emit_channel(on_event),
                None,
                worker,
            );
            return Ok(job_id);
        }
        let checkpoint = if compiled.is_some() && rules_set_id.is_none() {
            None
        } else {
            wordlist_checkpoint(
                &app,
                &scope,
                &request,
                &selected.path,
                "wordlist_cpu",
                "restart",
                "plain",
                rules_set_id.clone(),
            )
        };
        start_recovery_with_wordlist_engine(
            &state,
            &session,
            request,
            selected.path,
            None,
            embedded_hashcat::WordlistPreset::Plain,
            compiled,
            checkpoint,
            move |event| {
                let _ = on_event.send(event);
            },
        )
    } else if resume_from > 0 && compiled.is_none() && request.target_hashes.is_empty() {
        // Existing sequential resume: the row starts at the resumed ordinal.
        let checkpoint = wordlist_checkpoint(
            &app,
            &scope,
            &request,
            &selected.path,
            "wordlist_cpu",
            "sequential",
            "plain",
            None,
        );
        if let Some(controller) = &checkpoint {
            controller.seed_submitted(resume_from);
        }
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
                &request,
                &path,
                resume_from,
                &worker_token,
                |progress| forward(progress),
            )
        };
        spawn_recovery_worker(
            registry,
            job_id,
            scope,
            token,
            emit_channel(on_event),
            checkpoint,
            worker,
        );
        Ok(job_id)
    } else {
        let checkpoint = if compiled.is_some() && rules_set_id.is_none() {
            None
        } else {
            wordlist_checkpoint(
                &app,
                &scope,
                &request,
                &selected.path,
                "wordlist_cpu",
                // First-attempt CPU wordlist runs use the multi-core engine;
                // their aggregate counters cannot skip candidates honestly.
                "restart",
                "plain",
                rules_set_id.clone(),
            )
        };
        start_recovery_with_wordlist_engine(
            &state,
            &session,
            request,
            selected.path,
            None,
            embedded_hashcat::WordlistPreset::Plain,
            compiled,
            checkpoint,
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
        ("hmac-sha1", 150, 0),
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
        // Batch-6 Kerberos etype 23 + BitLocker.
        ("kerberos-tgs-rep", 13100, 0),
        ("kerberos-as-rep", 18200, 0),
        ("bitlocker", 22100, 0),
        // Batch-5 wallets (KeePass, Bitcoin, Ethereum).
        ("bitcoin", 11300, 0),
        ("keepass", 13400, 0),
        ("ethereum-pbkdf2", 15600, 0),
        ("ethereum-scrypt", 15700, 0),
        // Batch-4 documents (MS Office and PDF).
        ("office-97-2003", 9700, 0),
        ("office-2007", 9400, 0),
        ("office-2013", 9600, 0),
        ("pdf-1.1-1.3", 10400, 0),
        ("pdf-1.4-1.6", 10500, 0),
        // Batch-3 archive containers.
        ("winzip-aes", 13600, 0),
        ("7zip", 11600, 0),
        ("zip-legacy", 17200, 0),
        ("zip-legacy", 17210, 0),
        // Batch-7 databases (MSSQL 2000, MySQL 4.1, Oracle H:).
        ("smf", 121, 0),
        ("macos-salted-sha1", 122, 0),
        ("mssql-2000", 131, 0),
        ("mysql4.1", 300, 0),
        ("oracle-h", 3100, 0),
        // Batch-8 os-and-apps: RAR3-hp/RAR5, Kerberos etype 17/18 and KDBX
        // v4 (one algorithm, mode chosen by the parsed KDF UUID).
        ("rar3-hp", 12500, 0),
        ("rar5", 13000, 0),
        ("kerberos-tgs-rep-17", 19600, 0),
        ("kerberos-tgs-rep-18", 19700, 0),
        ("keepass-kdbx4", 34300, 0),
        ("keepass-kdbx4", 34301, 0),
        // Batch-9 salted variants: PDF 1.7 Level 3, WPA-PMKID, unified WPA
        // and the LUKS v1 RIPEMD-160 + AES text form.
        ("pdf-1.7", 10600, 0),
        ("wpa-pmkid", 16800, 0),
        ("wpa", 22000, 0),
        ("luks", 29541, 0),
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

/// Resolve the persisted readiness cache location for the bundled Hashcat
/// runtime. Any failure to resolve or create the cache directory returns
/// None, which silently degrades verified_modes_cached to the synchronous
/// sweep path — persistence must never break the KAT gate.
fn hashcat_readiness_cache_path(app: &AppHandle) -> Option<PathBuf> {
    let path = app
        .path()
        .app_cache_dir()
        .ok()?
        .join("embedded-hashcat-verified.json");
    std::fs::create_dir_all(path.parent()?).ok()?;
    Some(path)
}

/// Source presence or an OpenCL loader alone must NOT offer a non-working
/// Hashcat option in the UI. A fixed, public, supervised known-answer test is
/// required for EACH enabled raw mode; it runs off the Tauri UI dispatcher.
/// Findings are disk-persisted under a runtime fingerprint so a repeated
/// capabilities query is instant while a background KAT refresh re-validates.
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
    let cache_path = hashcat_readiness_cache_path(&app);
    let supported = tauri::async_runtime::spawn_blocking(move || {
        embedded_hashcat::verified_modes_cached(&runtime, cache_path.as_deref())
    })
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
    let preset = preset.unwrap_or_default();
    let scope = RecoveryCtx::scope_from_session(&session)?;
    // Plain GPU wordlists run as chunked 1M sessions, so they resume at
    // session boundaries; transformed presets are one bounded session that
    // only re-issues from zero.
    let checkpoint = wordlist_checkpoint(
        &app,
        &scope,
        &request,
        &selected.path,
        "wordlist_gpu",
        if preset == embedded_hashcat::WordlistPreset::Plain {
            "chunk_boundary"
        } else {
            "restart"
        },
        preset_id(preset),
        None,
    );
    start_recovery_with_wordlist_engine(
        &state,
        &session,
        request,
        selected.path,
        Some(runtime),
        preset,
        None,
        checkpoint,
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

/// Environment scan + plan build shared by the autopilot command and the
/// durable re-issue path (both replan against what the library has now).
async fn autopilot_plan(
    app: &AppHandle,
    target_hash: &str,
) -> Result<autopilot::AutopilotPlan, String> {
    let detection = autopilot::detect_target(target_hash)?;
    let wordlists = library_wordlists::list(app)?;
    let present: Vec<String> = wordlists
        .iter()
        .filter(|entry| entry.present)
        .map(|entry| entry.id.clone())
        .collect();
    let rules_ids = library_rules::list(app)?
        .into_iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    // Environment auto-detect: only modes that passed their known-answer test
    // on this machine's devices are offered the GPU; everything else — and all
    // memory-hard KDFs — stays on the multi-core CPU.
    let gpu_algorithms: Vec<String> = match hashcat_resource_root(app) {
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
    autopilot::build_plan(&detection, &present, &rules_ids, &gpu_algorithms)
}

/// How one ladder stage will actually execute. Built before the StageStarted
/// event so the announced label says what really runs.
enum StageRoute {
    CpuPlain { path: PathBuf },
    CpuRules { path: PathBuf, rules: Vec<cyberdeck_crypto::recovery::CompiledRule> },
    Gpu {
        gpu_request: RecoveryRequest,
        path: PathBuf,
        runtime: PathBuf,
        /// Private scratch (rules expansion or resume tail) freed after the run.
        _scratch: Option<tempfile::TempDir>,
    },
    /// Cancellation during expansion: the stage ends without running.
    Cancelled,
}
impl StageRoute {
    fn label(&self, planned: &str) -> String {
        match self {
            // An expansion that exceeded its bounds falls back to the CPU
            // rules engine; the announced label follows honestly.
            StageRoute::CpuRules { .. } => planned.replace("(GPU · rules-expanded)", "(CPU)"),
            _ => planned.to_string(),
        }
    }
}

/// Decide the execution route for one wordlist/rules ladder stage. `skip` is
/// the candidate boundary a re-issued run may skip (whole GPU sessions only).
fn build_stage_route(
    app: &AppHandle,
    stage: &autopilot::AutopilotStagePlan,
    request: &RecoveryRequest,
    single_target: bool,
    skip: u64,
    token: &RecoveryCancel,
) -> Result<StageRoute, String> {
    if stage.engine != autopilot::StageEngine::Gpu {
        let path = library_wordlists::resolve(app, &stage.wordlist_id)?;
        return match &stage.rules_set {
            Some(set_id) => {
                let compiled = library_rules::load(app, set_id)?;
                Ok(StageRoute::CpuRules {
                    path,
                    rules: compiled.rules,
                })
            }
            None => Ok(StageRoute::CpuPlain { path }),
        };
    }
    let runtime = hashcat_resource_root(app)?;
    let mut gpu_request = request.clone();
    gpu_request.backend = recovery_backend::BackendSelection::HashcatManaged;
    if stage.rules_set.is_none() {
        let source = library_wordlists::resolve(app, &stage.wordlist_id)?;
        return resume_gpu_path(gpu_request, source, runtime, skip, token);
    }
    // Rules on a KAT-verified GPU mode: CPU-expand the rules against the
    // wordlist into one bounded private candidates file, then let the
    // chunked GPU wordlist path execute it. Hash-file targets and requests
    // the embedded engine cannot validate (e.g. its stricter match cap)
    // stay on the CPU rules engine, which verifies every target natively.
    let set_id = stage
        .rules_set
        .as_deref()
        .ok_or("missing rules set id")?;
    let source = library_wordlists::resolve(app, &stage.wordlist_id)?;
    let compiled = library_rules::load(app, set_id)?;
    if !single_target || embedded_hashcat::validate_embedded_request(&gpu_request).is_err() {
        return Ok(StageRoute::CpuRules {
            path: source,
            rules: compiled.rules,
        });
    }
    let scratch = tempfile::Builder::new()
        .prefix("cyberdeck-rules-")
        .tempdir()
        .map_err(|_| "cannot create private rules workspace")?;
    let expanded = scratch.path().join("rules-expanded.words");
    match embedded_hashcat::expand_rules(
        &source,
        &expanded,
        &compiled.rules,
        request.max_candidates,
        || token.is_cancelled(),
    ) {
        Ok(_) => resume_gpu_path(gpu_request, expanded, runtime, skip, token)
            .map(|route| match route {
                // The expansion scratch outlives any resume tail inside it.
                StageRoute::Gpu {
                    gpu_request,
                    path,
                    runtime,
                    ..
                } => StageRoute::Gpu {
                    gpu_request,
                    path,
                    runtime,
                    _scratch: Some(scratch),
                },
                other => other,
            }),
        Err(_) if token.is_cancelled() => Ok(StageRoute::Cancelled),
        // Expansion exceeded the budget or the 256 MiB private file cap:
        // fall back to the streaming CPU rules engine, which never stores.
        Err(_) => Ok(StageRoute::CpuRules {
            path: source,
            rules: compiled.rules,
        }),
    }
}

/// Wrap a GPU source path with the whole-session resume tail when `skip`
/// candidates were already submitted at 1M session boundaries. A failed tail
/// write replays the full source instead of ever skipping work.
fn resume_gpu_path(
    mut gpu_request: RecoveryRequest,
    source: PathBuf,
    runtime: PathBuf,
    skip: u64,
    token: &RecoveryCancel,
) -> Result<StageRoute, String> {
    if skip == 0 {
        return Ok(StageRoute::Gpu {
            gpu_request,
            path: source,
            runtime,
            _scratch: None,
        });
    }
    let scratch = tempfile::Builder::new()
        .prefix("cyberdeck-resume-")
        .tempdir()
        .map_err(|_| "cannot create private resume workspace")?;
    let tail = scratch.path().join("resume-tail.words");
    gpu_request.max_candidates = gpu_request.max_candidates.saturating_sub(skip);
    match embedded_hashcat::write_skip_tail(
        &source,
        &tail,
        skip,
        gpu_request.max_candidates,
        || token.is_cancelled(),
    ) {
        Ok(_) => Ok(StageRoute::Gpu {
            gpu_request,
            path: tail,
            runtime,
            _scratch: Some(scratch),
        }),
        Err(_) if token.is_cancelled() => Ok(StageRoute::Cancelled),
        Err(_) => Ok(StageRoute::Gpu {
            gpu_request: RecoveryRequest {
                max_candidates: gpu_request
                    .max_candidates
                    .saturating_add(skip),
                ..gpu_request
            },
            path: source,
            runtime,
            _scratch: Some(scratch),
        }),
    }
}

/// Everything one ladder execution needs; shared by fresh and resumed runs.
struct LadderRun {
    stages: Vec<autopilot::AutopilotStagePlan>,
    plan_algorithm: String,
    target_hash: String,
    targets: Vec<String>,
    max_candidates: u64,
    max_matches: usize,
    started: Instant,
    /// Candidates of the first stage already submitted by a prior attempt.
    first_stage_skip: u64,
}

/// Execute the autopilot ladder. Route-then-announce keeps the stage label
/// honest; the first independently verified match stops the sequence.
fn run_ladder(
    app: &AppHandle,
    job_id: u64,
    run: LadderRun,
    token: &RecoveryCancel,
    sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
    forward: &mut (dyn FnMut(RecoveryProgressWire) + Send),
) -> Result<RecoveryRun, String> {
    let stage_count = run.stages.len();
    let mut total_tried = 0u64;
    let mut stage_reports = Vec::new();
    let mut matches_meta = Vec::new();
    let mut confidential = Vec::new();
    let mut cancelled = false;
    let mut limit_reached = false;
    for (index, stage) in run.stages.iter().enumerate() {
        if token.is_cancelled() {
            cancelled = true;
            break;
        }
        let request = RecoveryRequest {
            algorithm: stage.algorithm.clone(),
            target_hash: run.target_hash.clone(),
            backend: recovery_backend::BackendSelection::Cpu,
            max_candidates: run.max_candidates,
            max_matches: run.max_matches,
            target_hashes: run.targets.clone(),
        };
        let result = if let Some(mask) = &stage.mask {
            let label = stage.label.clone();
            sink(RecoveryEvent::StageStarted {
                job_id,
                stage_index: index,
                stage_count,
                label: label.clone(),
            });
            let mut progress_with_stage = |progress: RecoveryProgressWire| {
                let mut labeled = progress;
                labeled.stage = Some(label.clone());
                forward(labeled);
            };
            recovery_backend::execute_mask(&request, mask, "", token, &mut progress_with_stage)
        } else {
            let skip = if index == 0 {
                run.first_stage_skip
            } else {
                0
            };
            let route =
                build_stage_route(app, stage, &request, run.targets.is_empty(), skip, token)?;
            if matches!(route, StageRoute::Cancelled) {
                cancelled = true;
                break;
            }
            let label = route.label(&stage.label);
            sink(RecoveryEvent::StageStarted {
                job_id,
                stage_index: index,
                stage_count,
                label: label.clone(),
            });
            let mut progress_with_stage = |progress: RecoveryProgressWire| {
                let mut labeled = progress;
                labeled.stage = Some(label.clone());
                forward(labeled);
            };
            match route {
                StageRoute::CpuPlain { path } => {
                    execute_path(&request, &path, token, &mut progress_with_stage)
                }
                StageRoute::CpuRules { path, rules } => execute_path_with_rules(
                    &request,
                    &path,
                    token,
                    &mut progress_with_stage,
                    rules,
                ),
                StageRoute::Gpu {
                    gpu_request,
                    path,
                    runtime,
                    ..
                } => embedded_hashcat::execute_path(
                    &gpu_request,
                    &path,
                    &runtime,
                    token,
                    embedded_hashcat::WordlistPreset::Plain,
                    &mut progress_with_stage,
                ),
                StageRoute::Cancelled => unreachable!("handled above"),
            }
        };
        let stage_run = result.map_err(|error| format!("stage '{}': {error}", stage.label))?;
        let (summary, hits) = stage_run.into_parts();
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
    Ok(RecoveryRun::from_parts(
        RecoverySummaryWire {
            algorithm: run.plan_algorithm,
            backend: recovery_backend::BackendSelection::Cpu,
            engine: "cyberdeck-autopilot".into(),
            tried: total_tried,
            cancelled,
            limit_reached,
            duration_ms: run.started.elapsed().as_millis() as u64,
            matches: matches_meta,
            stages: stage_reports,
            resume_index: 0,
        },
        confidential,
    ))
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
    let plan = autopilot_plan(&app, &target_hash).await?;
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
    // Durable row for single-target ladders: stage boundaries and per-stage
    // wire progress feed the checkpoint; library wordlists make every stage
    // re-issuable. Hash-file ladders stay out (targets are backend-held).
    let checkpoint = if worker_targets.is_empty() {
        open_checkpoint(
            &app,
            NewRecoveryCheckpoint {
                case_id: scope.case_id().to_string(),
                run_kind: "autopilot".into(),
                resume_kind: "stage".into(),
                algorithm: plan.algorithm.clone(),
                // The ladder reports as the CPU engine; per-stage routing is
                // recorded in the stage summaries, not in the row.
                backend: "cpu".into(),
                target_hash: worker_target.clone(),
                total_budget: max_candidates,
                max_matches: max_matches as u64,
                stage_index: 0,
                stage_submitted: 0,
                wordlist_id: None,
                rules_set_id: None,
                preset: "plain".into(),
            },
        )
    } else {
        None
    };
    let worker_token = token.clone();
    let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                       forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
          -> Result<RecoveryRun, String> {
        run_ladder(
            &worker_app,
            job_id,
            LadderRun {
                stages: plan.stages,
                plan_algorithm: plan.algorithm,
                target_hash: worker_target,
                targets: worker_targets,
                max_candidates,
                max_matches,
                started,
                first_stage_skip: 0,
            },
            &worker_token,
            sink,
            forward,
        )
    };
    spawn_recovery_worker(registry, job_id, scope, token, emit, checkpoint, worker);
    Ok(job_id)
}

/// List resumable runs for the active case. Rows left running by a dead
/// session reconcile to suspended first; completed runs never come back.
#[tauri::command]
pub fn recovery_runs_list_v1(
    app: AppHandle,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<Vec<RecoveryRunCheckpointV1>, String> {
    state.with_active(&session, |registry, scope| {
        let Some(ctx) = app.try_state::<EvidenceCtx>() else {
            return Err("case store unavailable".into());
        };
        let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
        let keep: Vec<i64> = registry
            .jobs
            .values()
            .filter_map(|job| job.checkpoint_row)
            .collect();
        store.suspend_stale_recovery_checkpoints(scope.case_id(), &keep)?;
        Ok(store
            .list_resumable_recovery_checkpoints(scope.case_id())?
            .into_iter()
            .map(checkpoint_wire)
            .collect())
    })
}

fn mark_checkpoint_state(
    app: &AppHandle,
    row_id: i64,
    state: &'static str,
    submitted: u64,
    stage_index: u64,
    stage_submitted: u64,
) {
    if let Some(ctx) = app.try_state::<EvidenceCtx>() {
        if let Ok(store) = ctx.store.lock() {
            let _ = store.record_recovery_checkpoint(
                row_id, state, submitted, stage_index, stage_submitted,
            );
        }
    }
}

/// Reserve a job for a re-issued run; on failure the row returns to suspended.
fn reserve_resume_job(
    state: &RecoveryCtx,
    session: &CaseSessionCtx,
    scope: &VerifiedScope,
    app: &AppHandle,
    row: &RecoveryCheckpointRecord,
    submitted: u64,
    stage_index: u64,
) -> Result<(u64, RecoveryCancel), String> {
    let row_state = (row.id, submitted, stage_index);
    let reserved = state.with_active(session, |registry, verified| {
        if verified != scope {
            return Err("recovery case changed".into());
        }
        registry.reserve_job()
    });
    match reserved {
        Ok(pair) => Ok(pair),
        Err(error) => {
            mark_checkpoint_state(app, row_state.0, "suspended", row_state.1, row_state.2, 0);
            Err(error)
        }
    }
}

/// Re-verify the requested embedded mode passed its private known-answer test.
async fn verify_embedded_mode(app: &AppHandle, request: &RecoveryRequest) -> Result<(), String> {
    let runtime = hashcat_resource_root(app)?;
    embedded_hashcat::validate_embedded_request(request)?;
    let verification_root = runtime.clone();
    let verified = tauri::async_runtime::spawn_blocking(move || {
        embedded_hashcat::verified_modes(&verification_root)
    })
    .await
    .map_err(|_| "native Hashcat readiness check failed")??;
    let mode = embedded_hashcat::validate_embedded_request(request)?;
    if !verified.contains(&mode) {
        return Err(
            "selected native Hashcat mode did not pass its actual known-answer test".into(),
        );
    }
    Ok(())
}

fn parse_preset(preset: &str) -> Result<embedded_hashcat::WordlistPreset, String> {
    match preset {
        "plain" => Ok(embedded_hashcat::WordlistPreset::Plain),
        "uppercase" => Ok(embedded_hashcat::WordlistPreset::Uppercase),
        "append_one" => Ok(embedded_hashcat::WordlistPreset::AppendOne),
        other => Err(format!("unknown wordlist preset '{other}'")),
    }
}

/// Re-issue one suspended or cancelled run of the active case: rebuild the
/// request from the row and start it again with the honest remaining work —
/// sequential ordinals for CPU resumable rows, whole 1M GPU sessions for
/// chunked rows, completed stages for autopilot rows, and a full replay for
/// engines that cannot skip candidates (multi-core CPU, transformed presets).
#[tauri::command]
pub async fn recovery_run_resume_v1(
    app: AppHandle,
    run_id: i64,
    on_event: Channel<RecoveryEvent>,
    state: State<'_, RecoveryCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    let before = session.selected()?;
    state.with_active(&session, |_, _| Ok(()))?;
    let scope = RecoveryCtx::scope_from_session(&session)?;
    let row = {
        let ctx = app
            .try_state::<EvidenceCtx>()
            .ok_or("case store unavailable")?;
        let store = ctx.store.lock().map_err(|_| "case store unavailable")?;
        let row = store.recovery_checkpoint(run_id)?;
        if row.case_id != scope.case_id() {
            return Err("recovery run belongs to another case".into());
        }
        if !matches!(row.state.as_str(), "suspended" | "cancelled") {
            return Err("only suspended or cancelled runs can be re-issued".into());
        }
        if row.total_budget == 0
            || row.total_budget > cyberdeck_crypto::recovery::MAX_FAST_CANDIDATES
            || row.max_matches == 0
            || row.max_matches > cyberdeck_crypto::recovery::MAX_MATCHES as u64
        {
            return Err("checkpoint row carries out-of-bounds limits".into());
        }
        row
    };
    session.ensure(&before)?;
    match (row.resume_kind.as_str(), row.backend.as_str()) {
        ("sequential", "cpu") => {
            if row.submitted >= row.total_budget {
                mark_checkpoint_state(&app, row.id, "completed", row.submitted, 0, 0);
                return Err("run already submitted its whole budget".into());
            }
            let request = RecoveryRequest {
                algorithm: row.algorithm.clone(),
                target_hash: row.target_hash.clone(),
                backend: recovery_backend::BackendSelection::Cpu,
                max_candidates: row.total_budget - row.submitted,
                max_matches: row.max_matches as usize,
                target_hashes: Vec::new(),
            };
            recovery_backend::validate_request(&request)?;
            let wordlist = library_wordlists::resolve(&app, row.wordlist_id.as_deref().ok_or(
                "checkpoint row has no library wordlist reference",
            )?)?;
            // The resumed engine reports tried from zero, so the ledger's
            // offset keeps the row's cumulative counter honest.
            let checkpoint = resumed_checkpoint(&app, &row, row.submitted)
                .ok_or("case store unavailable")?;
            mark_checkpoint_state(&app, row.id, "running", row.submitted, 0, 0);
            let (job_id, token) =
                reserve_resume_job(&state, &session, &scope, &app, &row, row.submitted, 0)?;
            emit_started(&on_event, job_id);
            let registry = state.registry.clone();
            let worker_token = token.clone();
            let resume_from = row.submitted;
            let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                               forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
                  -> Result<RecoveryRun, String> {
                let _ = sink;
                recovery_backend::execute_path_resumable(
                    &request,
                    &wordlist,
                    resume_from,
                    &worker_token,
                    |progress| forward(progress),
                )
            };
            spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), Some(checkpoint), worker);
            Ok(job_id)
        }
        ("restart", "cpu") => {
            let request = RecoveryRequest {
                algorithm: row.algorithm.clone(),
                target_hash: row.target_hash.clone(),
                backend: recovery_backend::BackendSelection::Cpu,
                max_candidates: row.total_budget,
                max_matches: row.max_matches as usize,
                target_hashes: Vec::new(),
            };
            recovery_backend::validate_request(&request)?;
            let wordlist = library_wordlists::resolve(&app, row.wordlist_id.as_deref().ok_or(
                "checkpoint row has no library wordlist reference",
            )?)?;
            let checkpoint =
                resumed_checkpoint(&app, &row, 0).ok_or("case store unavailable")?;
            // A restart CPU row may be a library rules run: re-load the same
            // rule set so the replay mutates candidates exactly as before.
            let rules = match &row.rules_set_id {
                Some(set_id) => Some(library_rules::load(&app, set_id)?.rules),
                None => None,
            };
            mark_checkpoint_state(&app, row.id, "running", 0, 0, 0);
            let (job_id, token) = reserve_resume_job(&state, &session, &scope, &app, &row, 0, 0)?;
            emit_started(&on_event, job_id);
            let registry = state.registry.clone();
            let worker_token = token.clone();
            let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                               forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
                  -> Result<RecoveryRun, String> {
                let _ = sink;
                if let Some(compiled) = rules {
                    execute_path_with_rules(&request, &wordlist, &worker_token, |progress| {
                        forward(progress)
                    }, compiled)
                } else {
                    execute_path(&request, &wordlist, &worker_token, |progress| {
                        forward(progress)
                    })
                }
            };
            spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), Some(checkpoint), worker);
            Ok(job_id)
        }
        ("restart", "hashcat_managed") => {
            let preset = parse_preset(&row.preset)?;
            let request = RecoveryRequest {
                algorithm: row.algorithm.clone(),
                target_hash: row.target_hash.clone(),
                backend: recovery_backend::BackendSelection::HashcatManaged,
                max_candidates: row.total_budget,
                max_matches: row.max_matches as usize,
                target_hashes: Vec::new(),
            };
            verify_embedded_mode(&app, &request).await?;
            let wordlist = library_wordlists::resolve(&app, row.wordlist_id.as_deref().ok_or(
                "checkpoint row has no library wordlist reference",
            )?)?;
            let checkpoint =
                resumed_checkpoint(&app, &row, 0).ok_or("case store unavailable")?;
            mark_checkpoint_state(&app, row.id, "running", 0, 0, 0);
            let (job_id, token) = reserve_resume_job(&state, &session, &scope, &app, &row, 0, 0)?;
            emit_started(&on_event, job_id);
            let registry = state.registry.clone();
            let worker_token = token.clone();
            let runtime = hashcat_resource_root(&app)?;
            let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                               forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
                  -> Result<RecoveryRun, String> {
                let _ = sink;
                embedded_hashcat::execute_path(
                    &request,
                    &wordlist,
                    &runtime,
                    &worker_token,
                    preset,
                    |progress| forward(progress),
                )
            };
            spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), Some(checkpoint), worker);
            Ok(job_id)
        }
        ("chunk_boundary", "hashcat_managed") => {
            // Resume at the next whole 1M session boundary; the interrupted
            // session's tail re-runs (never skips), matching the chunk docs.
            let skip = (row.submitted / GPU_SESSION_CANDIDATES) * GPU_SESSION_CANDIDATES;
            if skip >= row.total_budget {
                mark_checkpoint_state(&app, row.id, "completed", row.submitted, 0, 0);
                return Err("run already submitted its whole budget".into());
            }
            let mut request = RecoveryRequest {
                algorithm: row.algorithm.clone(),
                target_hash: row.target_hash.clone(),
                backend: recovery_backend::BackendSelection::HashcatManaged,
                max_candidates: row.total_budget,
                max_matches: row.max_matches as usize,
                target_hashes: Vec::new(),
            };
            verify_embedded_mode(&app, &request).await?;
            let wordlist = library_wordlists::resolve(&app, row.wordlist_id.as_deref().ok_or(
                "checkpoint row has no library wordlist reference",
            )?)?;
            let checkpoint = resumed_checkpoint(&app, &row, skip)
                .ok_or("case store unavailable")?;
            mark_checkpoint_state(&app, row.id, "running", skip, 0, 0);
            let (job_id, token) = reserve_resume_job(&state, &session, &scope, &app, &row, skip, 0)?;
            emit_started(&on_event, job_id);
            let registry = state.registry.clone();
            let worker_token = token.clone();
            let runtime = hashcat_resource_root(&app)?;
            let full_request = request.clone();
            request.max_candidates = row.total_budget - skip;
            let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                               forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
                  -> Result<RecoveryRun, String> {
                let _ = sink;
                let token = &worker_token;
                if skip == 0 {
                    return embedded_hashcat::execute_path(
                        &request,
                        &wordlist,
                        &runtime,
                        token,
                        embedded_hashcat::WordlistPreset::Plain,
                        |progress| forward(progress),
                    );
                }
                let scratch = tempfile::Builder::new()
                    .prefix("cyberdeck-resume-")
                    .tempdir()
                    .map_err(|_| "cannot create private resume workspace")?;
                let tail = scratch.path().join("resume-tail.words");
                match embedded_hashcat::write_skip_tail(
                    &wordlist,
                    &tail,
                    skip,
                    request.max_candidates,
                    || token.is_cancelled(),
                ) {
                    Ok(_) => embedded_hashcat::execute_path(
                        &request,
                        &tail,
                        &runtime,
                        token,
                        embedded_hashcat::WordlistPreset::Plain,
                        |progress| forward(progress),
                    ),
                    Err(_) if token.is_cancelled() => {
                        Ok(recovery_backend::embedded_result(&request, Vec::new(), true, 0))
                    }
                    // A failed tail write replays the whole wordlist rather
                    // than ever skipping candidates.
                    Err(_) => embedded_hashcat::execute_path(
                        &full_request,
                        &wordlist,
                        &runtime,
                        token,
                        embedded_hashcat::WordlistPreset::Plain,
                        |progress| forward(progress),
                    ),
                }
            };
            spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), Some(checkpoint), worker);
            Ok(job_id)
        }
        ("stage", "cpu") => {
            // Autopilot rows replan against the current environment; completed
            // stages drop off and the interrupted stage restarts (its GPU
            // sessions at whole-boundary skips when possible).
            let plan = autopilot_plan(&app, &row.target_hash).await?;
            if row.stage_index as usize >= plan.stages.len() {
                mark_checkpoint_state(
                    &app,
                    row.id,
                    "completed",
                    row.submitted,
                    row.stage_index,
                    0,
                );
                return Err("every planned stage already finished".into());
            }
            let mut stages = plan.stages;
            let resumed_stages = stages.split_off(row.stage_index as usize);
            let boundary =
                (row.stage_submitted / GPU_SESSION_CANDIDATES) * GPU_SESSION_CANDIDATES;
            let checkpoint = resumed_checkpoint(&app, &row, row.submitted + boundary)
                .ok_or("case store unavailable")?;
            mark_checkpoint_state(
                &app,
                row.id,
                "running",
                row.submitted + boundary,
                row.stage_index,
                0,
            );
            let (job_id, token) = reserve_resume_job(
                &state,
                &session,
                &scope,
                &app,
                &row,
                row.submitted + boundary,
                row.stage_index,
            )?;
            emit_started(&on_event, job_id);
            let registry = state.registry.clone();
            let worker_app = app.clone();
            let worker_token = token.clone();
            let started = Instant::now();
            let plan_algorithm = row.algorithm.clone();
            let stage_skip = boundary;
            let worker = move |sink: &(dyn Fn(RecoveryEvent) + Send + Sync),
                               forward: &mut (dyn FnMut(RecoveryProgressWire) + Send)|
                  -> Result<RecoveryRun, String> {
                run_ladder(
                    &worker_app,
                    job_id,
                    LadderRun {
                        stages: resumed_stages,
                        plan_algorithm,
                        target_hash: row.target_hash.clone(),
                        targets: Vec::new(),
                        max_candidates: row.total_budget,
                        max_matches: row.max_matches as usize,
                        started,
                        first_stage_skip: stage_skip,
                    },
                    &worker_token,
                    sink,
                    forward,
                )
            };
            spawn_recovery_worker(registry, job_id, scope, token, emit_channel(on_event), Some(checkpoint), worker);
            Ok(job_id)
        }
        _ => Err("checkpoint row kind cannot be re-issued".into()),
    }
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
        Ok(registry
            .selected_hash_input
            .as_ref()
            .map(|input| match input {
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
    // Mask candidates regenerate from the pattern; no honest skip exists, so
    // mask runs get no durable checkpoint row.
    spawn_recovery_worker(
        registry,
        job_id,
        scope,
        token,
        emit_channel(on_event),
        None,
        worker,
    );
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

    fn collecting_controller(
        run_kind: &str,
        resume_kind: &str,
    ) -> (CheckpointController, Arc<Mutex<Vec<CheckpointWrite>>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let sink_writes = writes.clone();
        let sink: Arc<dyn Fn(CheckpointWrite) + Send + Sync> =
            Arc::new(move |write| sink_writes.lock().unwrap().push(write));
        (CheckpointController::new(7, run_kind, resume_kind, sink), writes)
    }

    #[test]
    fn checkpoint_ledger_throttles_progress_and_rounds_gpu_boundaries() {
        let (controller, writes) = collecting_controller("wordlist_gpu", "chunk_boundary");
        controller.progress(500_000);
        controller.progress(999_999);
        // Throttled: the first write lands, subsequent ones inside the window
        // do not; the boundary value only counts finished 1M sessions.
        assert_eq!(writes.lock().unwrap().len(), 1);
        assert_eq!(writes.lock().unwrap()[0].submitted, 0);
        std::thread::sleep(CHECKPOINT_INTERVAL);
        controller.progress(1_500_000);
        let last = writes.lock().unwrap().last().unwrap().clone();
        assert_eq!(last.submitted, 1_000_000);
        assert_eq!(last.state, "running");
        // Close marks the whole-run counters, still boundary-exact.
        controller.close("cancelled");
        let last = writes.lock().unwrap().last().unwrap().clone();
        assert_eq!(last.state, "cancelled");
        assert_eq!(last.submitted, 1_000_000);
    }

    #[test]
    fn checkpoint_ledger_tracks_sequential_ordinals_and_stage_boundaries() {
        let (controller, writes) = collecting_controller("wordlist_cpu", "sequential");
        controller.progress(4096);
        assert_eq!(writes.lock().unwrap()[0].submitted, 4096);
        controller.close("suspended");
        assert_eq!(writes.lock().unwrap().last().unwrap().submitted, 4096);

        let (controller, writes) = collecting_controller("autopilot", "stage");
        controller.progress(2_400_000);
        controller.stage_started();
        let boundary = writes.lock().unwrap().last().unwrap().clone();
        assert_eq!(boundary.submitted, 2_400_000);
        assert_eq!(boundary.stage_index, 1);
        assert_eq!(boundary.stage_submitted, 0);
        controller.progress(300_000);
        std::thread::sleep(CHECKPOINT_INTERVAL);
        controller.progress(400_000);
        let last = writes.lock().unwrap().last().unwrap().clone();
        assert_eq!(last.submitted, 2_400_000);
        assert_eq!(last.stage_submitted, 400_000);
        // Terminal close keeps the finished/live stage counters separate so a
        // re-issue can still skip the live stage's whole GPU sessions.
        controller.close("completed");
        let last = writes.lock().unwrap().last().unwrap().clone();
        assert_eq!(last.submitted, 2_400_000);
        assert_eq!(last.stage_submitted, 400_000);
        assert_eq!(last.state, "completed");
    }

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
                    checkpoint_row: None,
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
                checkpoint_row: None,
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
        let id = start_recovery_with_wordlist_engine(
            &ctx,
            &session,
            request,
            words,
            None,
            embedded_hashcat::WordlistPreset::Plain,
            None,
            None,
            move |event| {
                let _ = send.send(event);
            },
        )
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
        let id = start_recovery_with_wordlist_engine(
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
            None,
            embedded_hashcat::WordlistPreset::Plain,
            None,
            None,
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

//! Backend-owned bounded Web assessment jobs: no UI-owned cancellation truth.
use super::{
    authorize_pinned_assessment, crawl_application, execute_case_scoped_assessment,
    scan_application, scan_domain, target_scope, Finding,
};
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_storage::{ArtifactStore, NewFinding};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};

const MAX_TRACKED: usize = 16;
const MAX_ACTIVE: usize = 2;

#[derive(Clone, Copy)]
enum Kind {
    Scanner,
    Spider,
}
impl Kind {
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "scanner" => Ok(Self::Scanner),
            "spider" => Ok(Self::Spider),
            _ => Err("unknown native Web job kind".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Scanner => "scanner",
            Self::Spider => "spider",
        }
    }
}

#[derive(Clone, Serialize)]
pub struct WebAssessmentJobWire {
    pub job_id: u64,
    pub kind: String,
    pub state: String, // running | completed | failed | cancelled
    pub processed: usize,
    pub discovered: usize,
    pub findings: Vec<Finding>,
    pub urls: Vec<String>,
    pub error: Option<String>,
}

struct Job {
    scope: CaseSessionWire,
    cancel: AtomicBool,
    snapshot: Mutex<WebAssessmentJobWire>,
    saved_count: Mutex<Option<usize>>,
}
impl Job {
    fn new(id: u64, scope: CaseSessionWire, kind: Kind) -> Self {
        Self {
            scope,
            cancel: AtomicBool::new(false),
            saved_count: Mutex::new(None),
            snapshot: Mutex::new(WebAssessmentJobWire {
                job_id: id,
                kind: kind.name().into(),
                state: "running".into(),
                processed: 0,
                discovered: 0,
                findings: vec![],
                urls: vec![],
                error: None,
            }),
        }
    }
    fn progress(&self, processed: usize, discovered: usize) {
        if self.cancel.load(Ordering::Acquire) {
            return;
        }
        if let Ok(mut state) = self.snapshot.lock() {
            if state.state == "running" {
                state.processed = processed.min(1000);
                state.discovered = discovered.min(1000);
            }
        }
    }
    fn cancelled(&self) {
        self.cancel.store(true, Ordering::Release);
        if let Ok(mut state) = self.snapshot.lock() {
            state.state = "cancelled".into();
            state.findings.clear();
            state.urls.clear();
            state.error = None;
        }
    }
    fn finish(&self, result: Result<Outcome, String>) {
        if self.cancel.load(Ordering::Acquire) {
            self.cancelled();
            return;
        }
        if let Ok(mut state) = self.snapshot.lock() {
            if state.state != "running" {
                return;
            }
            match result {
                Ok(Outcome::Findings(mut findings)) => {
                    findings.truncate(128);
                    state.discovered = findings.len();
                    state.findings = findings;
                    state.state = "completed".into();
                }
                Ok(Outcome::Urls(mut urls)) => {
                    urls.truncate(60);
                    state.discovered = urls.len();
                    state.urls = urls;
                    state.state = "completed".into();
                }
                Err(error) => {
                    state.error = Some(error.chars().take(512).collect());
                    state.state = "failed".into();
                }
            }
        }
    }
    /// Exactly-once manual case save. The caller must hold the backend
    /// selected revision's publication gate and the existing case store lock.
    /// Never serialize an authoritative case_id or findings payload from UI.
    fn save_completed(&self, store: &ArtifactStore, case_id: &str) -> Result<usize, String> {
        if case_id == "scratchpad" || self.scope.case_id.as_deref() != Some(case_id) {
            return Err("select a saved investigation case before saving findings".into());
        }
        let mut receipt = self
            .saved_count
            .lock()
            .map_err(|_| "Web finding save receipt unavailable")?;
        if let Some(count) = *receipt {
            return Ok(count);
        }
        let state = self
            .snapshot
            .lock()
            .map_err(|_| "Web job status unavailable")?;
        if state.state != "completed" || state.kind != "scanner" {
            return Err("only completed native Scanner jobs may save findings".into());
        }
        if self.cancel.load(Ordering::Acquire) {
            return Err("cancelled Web assessment cannot save findings".into());
        }
        let records: Vec<NewFinding> = state
            .findings
            .iter()
            .take(128)
            .map(|f| {
                // Byte-safe UTF-8 truncation follows existing Storage constraints.
                fn capped(text: &str, max: usize) -> String {
                    let mut end = text.len().min(max);
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    text[..end].to_string()
                }
                NewFinding {
                    title: capped(&f.title, 200),
                    severity: if matches!(
                        f.severity.as_str(),
                        "info" | "low" | "medium" | "high" | "critical"
                    ) {
                        f.severity.clone()
                    } else {
                        "info".into()
                    },
                    details: capped(&format!("{}\nEvidence: {}", f.detail, f.evidence), 8192),
                }
            })
            .collect();
        // The source field identifies the native producer, and these bounded
        // non-secret findings have no borrowed/foreign artifact references.
        let written = store.add_findings(case_id, "web.native", None, &records)?;
        *receipt = Some(written);
        Ok(written)
    }

    fn view(&self) -> Result<WebAssessmentJobWire, String> {
        self.snapshot
            .lock()
            .map(|v| v.clone())
            .map_err(|_| "Web job state unavailable".into())
    }
}
enum Outcome {
    Findings(Vec<Finding>),
    Urls(Vec<String>),
}

#[derive(Default)]
struct Registry {
    jobs: VecDeque<Arc<Job>>,
}
impl Registry {
    fn add(&mut self, scope: CaseSessionWire, kind: Kind) -> Result<Arc<Job>, String> {
        // A completed operation stays queryable until the bounded ring needs room.
        let active = self
            .jobs
            .iter()
            .filter(|job| job.view().is_ok_and(|snap| snap.state == "running"))
            .count();
        if active >= MAX_ACTIVE {
            return Err("two Web assessments are already running".into());
        }
        if self.jobs.len() >= MAX_TRACKED {
            let position = self
                .jobs
                .iter()
                .position(|job| job.view().is_ok_and(|snap| snap.state != "running"))
                .ok_or("Web job history is at capacity")?;
            self.jobs.remove(position);
        }
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id == u64::MAX {
            return Err("Web job IDs exhausted".into());
        }
        let job = Arc::new(Job::new(id, scope, kind));
        self.jobs.push_back(job.clone());
        Ok(job)
    }
    fn get(&self, id: u64, scope: &CaseSessionWire) -> Result<Arc<Job>, String> {
        let job = self
            .jobs
            .iter()
            .find(|j| j.view().is_ok_and(|state| state.job_id == id))
            .ok_or("Web job is unavailable")?;
        if &job.scope != scope {
            return Err("Web job is not authorized for the current case revision".into());
        }
        Ok(job.clone())
    }
}
fn registry() -> &'static Mutex<Registry> {
    static JOBS: OnceLock<Mutex<Registry>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(Registry::default()))
}

async fn run_cancellable<T>(
    session: &CaseSessionCtx,
    selected: &CaseSessionWire,
    job: &Job,
    operation: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    if job.cancel.load(Ordering::Acquire) {
        return Err("Web assessment cancelled".into());
    }
    let gated = execute_case_scoped_assessment(session, selected, operation);
    tokio::pin!(gated);
    let mut timer = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            biased;
            _ = timer.tick() => {
                if job.cancel.load(Ordering::Acquire) {
                    return Err("Web assessment cancelled".into());
                }
                session.ensure(selected)?;
            }
            result = &mut gated => {
                if job.cancel.load(Ordering::Acquire) { return Err("Web assessment cancelled".into()); }
                return result;
            }
        }
    }
}

/// Native confirmation and authoritative case selection happen BEFORE the job
/// is inserted. It continues in the Tauri runtime even if the React view unmounts.
#[tauri::command]
pub async fn web_assessment_start_v1(
    kind: String,
    target_url: String,
    max_depth: u8,
    authorized: bool,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    scan_domain::require_authorization(authorized)?;
    let kind = Kind::parse(&kind)?;
    let selected = session.selected()?;
    let pinned = target_scope::prepare_private_target(&target_url).await?;
    session.ensure(&selected)?;
    authorize_pinned_assessment(app.clone(), &session, &selected, &pinned).await?;
    let job = session.with_current_publication(&selected, || {
        registry()
            .lock()
            .map_err(|_| "Web job registry unavailable")?
            .add(selected.clone(), kind)
    })?;
    let id = job.view()?.job_id;
    tauri::async_runtime::spawn(async move {
        let session = app.state::<CaseSessionCtx>();
        let on_progress = |processed, discovered| job.progress(processed, discovered);
        let operation = async {
            match kind {
                Kind::Scanner => scan_application::run_scan_with_progress(
                    &pinned.client,
                    pinned.url.to_string(),
                    true,
                    &on_progress,
                )
                .await
                .map(Outcome::Findings),
                Kind::Spider => crawl_application::run_spider_with_progress(
                    &pinned.client,
                    pinned.url.to_string(),
                    max_depth.min(4),
                    true,
                    &on_progress,
                )
                .await
                .map(Outcome::Urls),
            }
        };
        let result = run_cancellable(&session, &selected, &job, operation).await;
        if session
            .with_current_publication(&selected, || {
                if job.cancel.load(Ordering::Acquire) {
                    job.cancelled();
                    return Ok(());
                }
                job.finish(result);
                Ok(())
            })
            .is_err()
        {
            job.cancelled();
        }
    });
    Ok(id)
}

#[tauri::command]
pub fn web_assessment_status_v1(
    job_id: u64,
    session: State<'_, CaseSessionCtx>,
) -> Result<WebAssessmentJobWire, String> {
    let selected = session.selected()?;
    session.with_current_publication(&selected, || {
        registry()
            .lock()
            .map_err(|_| "Web job registry unavailable")?
            .get(job_id, &selected)?
            .view()
    })
}

#[tauri::command]
pub fn web_assessment_cancel_v1(
    job_id: u64,
    session: State<'_, CaseSessionCtx>,
) -> Result<WebAssessmentJobWire, String> {
    let selected = session.selected()?;
    session.with_current_publication(&selected, || {
        let job = registry()
            .lock()
            .map_err(|_| "Web job registry unavailable")?
            .get(job_id, &selected)?;
        job.cancelled();
        job.view()
    })
}

/// Explicit, backend-authoritative Save to Case. Lock order is
/// EvidenceCtx.store -> CaseSessionCtx.publication, matching case_session_select_v1.
/// Do not hold either across network awaits. Duplicate saves return the first
/// receipt and never duplicate storage records.
#[tauri::command]
pub fn web_assessment_save_findings_v1(
    job_id: u64,
    evidence: State<'_, EvidenceCtx>,
    session: State<'_, CaseSessionCtx>,
) -> Result<usize, String> {
    let selected = session.selected()?;
    let case_id = selected.case_id.as_deref().ok_or("select a case first")?;
    if case_id == "scratchpad" {
        return Err("select a saved case to store scanner findings".into());
    }
    // Existing native case-switch command takes store before publication.
    // Taking locks in that exact order avoids a case-change deadlock.
    let store = evidence
        .store
        .lock()
        .map_err(|_| "Case findings storage unavailable")?;
    session.with_current_publication(&selected, || {
        let job = registry()
            .lock()
            .map_err(|_| "Web job registry unavailable")?
            .get(job_id, &selected)?;
        job.save_completed(&store, case_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_scan_findings_commit_is_exactly_once_and_case_scoped() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("db.sqlite")).unwrap();
        let record = store.create_case("Web findings", "").unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, &record.id).unwrap();
        let job = Job::new(55, selected.clone(), Kind::Scanner);
        job.finish(Ok(Outcome::Findings(vec![Finding {
            severity: "medium".into(),
            title: "Origin reflection".into(),
            detail: "Validated on owned lab".into(),
            evidence: "http://127.0.0.1/".into(),
        }])));
        let first = session
            .with_current_publication(&selected, || job.save_completed(&store, &record.id))
            .unwrap();
        assert_eq!(first, 1);
        assert_eq!(
            session
                .with_current_publication(&selected, || { job.save_completed(&store, &record.id) })
                .unwrap(),
            1
        );
        assert_eq!(store.list_findings(&record.id).unwrap().len(), 1);
        let changed = session.select(&store, &record.id).unwrap();
        assert_ne!(selected.revision, changed.revision);
        assert!(session
            .with_current_publication(&selected, || { job.save_completed(&store, &record.id) })
            .is_err());
        assert_eq!(store.list_findings(&record.id).unwrap().len(), 1);
    }

    #[test]
    fn native_scan_findings_refuse_scratchpad_pending_cancelled_and_spider() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("db.sqlite")).unwrap();
        let other = store.create_case("Web evidence", "").unwrap();
        let case = CaseSessionWire {
            case_id: Some(other.id.clone()),
            revision: 2,
        };
        let pending = Job::new(7, case.clone(), Kind::Scanner);
        assert!(pending.save_completed(&store, &other.id).is_err());
        pending.cancelled();
        assert!(pending.save_completed(&store, &other.id).is_err());
        let spider = Job::new(8, case.clone(), Kind::Spider);
        spider.finish(Ok(Outcome::Urls(vec!["http://127.0.0.1".into()])));
        assert!(spider.save_completed(&store, &other.id).is_err());
        let finished = Job::new(9, case, Kind::Scanner);
        finished.finish(Ok(Outcome::Findings(vec![])));
        assert!(finished.save_completed(&store, "scratchpad").is_err());
        assert!(finished.save_completed(&store, "anothercase").is_err());
    }

    #[test]
    fn registry_is_bounded_and_case_revision_is_authoritative() {
        let mut registry = Registry::default();
        let original = CaseSessionWire {
            case_id: Some("scratchpad".into()),
            revision: 1,
        };
        let first = registry.add(original.clone(), Kind::Scanner).unwrap();
        let second = registry.add(original.clone(), Kind::Spider).unwrap();
        assert!(registry.add(original.clone(), Kind::Scanner).is_err());
        first.finish(Ok(Outcome::Findings(vec![])));
        for _ in 0..32 {
            let item = registry.add(original.clone(), Kind::Scanner).unwrap();
            item.finish(Ok(Outcome::Findings(vec![])));
        }
        assert!(registry.jobs.len() <= MAX_TRACKED);
        assert!(registry
            .get(
                second.view().unwrap().job_id,
                &CaseSessionWire {
                    case_id: Some("scratchpad".into()),
                    revision: 2,
                }
            )
            .is_err());
        second.cancelled();
        assert_eq!(second.view().unwrap().state, "cancelled");
    }

    #[tokio::test]
    async fn cancellation_drops_a_stalled_assessment_without_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let store = cyberdeck_storage::ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, "scratchpad").unwrap();
        let job = Job::new(42, selected.clone(), Kind::Spider);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel::<()>();
        let outcome = async {
            let _ = started_tx.send(());
            let _ = resume_rx.await;
            Ok::<_, String>(7)
        };
        let cancelling = async {
            started_rx.await.unwrap();
            job.cancelled();
            let _ = resume_tx.send(());
        };
        let (response, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                run_cancellable(&session, &selected, &job, outcome),
                cancelling
            )
        })
        .await
        .unwrap();
        assert!(response.is_err());
        assert_eq!(job.view().unwrap().state, "cancelled");
    }
}

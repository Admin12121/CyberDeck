//! Backend-owned bounded Web assessment jobs: no UI-owned cancellation truth.
use super::{
    authorize_pinned_assessment, crawl_application, execute_case_scoped_assessment,
    scan_application, scan_domain, target_scope, Finding,
};
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
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
}
impl Job {
    fn new(id: u64, scope: CaseSessionWire, kind: Kind) -> Self {
        Self {
            scope,
            cancel: AtomicBool::new(false),
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

#[cfg(test)]
mod tests {
    use super::*;

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

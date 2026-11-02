//! Backend-owned bounded Web assessment jobs: no UI-owned cancellation truth.
use super::auth_context_application::AuthContext;
use super::{
    active_body_application, active_injection_application, active_oast_application,
    active_query_application, authorize_pinned_assessment, crawl_application,
    execute_case_scoped_assessment, passive_rules_application, scan_application, scan_domain,
    selected_history_grant, target_scope, webhistory, Finding, WebCtx,
};
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_storage::{ArtifactStore, HistoryCaptureGrant, NewFinding};
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

/// Per-request native scan intensity. Never allows more than the existing
/// hard-coded GET/POST bounds. Standard avoids unnecessary network activity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanIntensity {
    Quick,
    Standard,
    Thorough,
}
impl ScanIntensity {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("thorough") {
            "quick" => Ok(Self::Quick),
            "standard" => Ok(Self::Standard),
            "thorough" => Ok(Self::Thorough),
            _ => Err("unknown Web scan intensity".into()),
        }
    }
    fn request_budget(self, kind: Kind) -> usize {
        match kind {
            Kind::ActiveQuery => match self {
                Self::Quick => 1,
                Self::Standard => 4,
                Self::Thorough => 8,
            },
            Kind::ActiveForm | Kind::ActiveJson => match self {
                Self::Quick => 1,
                Self::Standard => 2,
                Self::Thorough => 4,
            },
            Kind::ActiveSql | Kind::ActiveTraversal => match self {
                Self::Quick => 2,
                Self::Standard => 4,
                Self::Thorough => 8,
            },
            Kind::ActiveSqlBoolean => match self {
                Self::Quick => 1,
                Self::Standard => 2,
                Self::Thorough => 4,
            },
            Kind::ActiveOast => match self {
                Self::Quick => 1,
                Self::Standard => 2,
                Self::Thorough => 4,
            },
            _ => 0,
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Scanner,
    Spider,
    Passive,
    ActiveQuery,
    ActiveForm,
    ActiveJson,
    ActiveSql,
    ActiveSqlBoolean,
    ActiveTraversal,
    ActiveOast,
}
impl Kind {
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "scanner" => Ok(Self::Scanner),
            "spider" => Ok(Self::Spider),
            "passive" => Ok(Self::Passive),
            "active-query" => Ok(Self::ActiveQuery),
            "active-form" => Ok(Self::ActiveForm),
            "active-json" => Ok(Self::ActiveJson),
            "active-sql" => Ok(Self::ActiveSql),
            "active-sql-boolean" => Ok(Self::ActiveSqlBoolean),
            "active-traversal" => Ok(Self::ActiveTraversal),
            "active-oast" => Ok(Self::ActiveOast),
            _ => Err("unknown native Web job kind".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Scanner => "scanner",
            Self::Spider => "spider",
            Self::Passive => "passive",
            Self::ActiveQuery => "active-query",
            Self::ActiveForm => "active-form",
            Self::ActiveJson => "active-json",
            Self::ActiveSql => "active-sql",
            Self::ActiveSqlBoolean => "active-sql-boolean",
            Self::ActiveTraversal => "active-traversal",
            Self::ActiveOast => "active-oast",
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
    pub rule_findings: Vec<passive_rules_application::PassiveFinding>,
    pub urls: Vec<String>,
    pub error: Option<String>,
}

struct Job {
    scope: CaseSessionWire,
    cancel: AtomicBool,
    snapshot: Mutex<WebAssessmentJobWire>,
    saved_count: Mutex<Option<usize>>,
    passive_grant: OnceLock<HistoryCaptureGrant>,
}
impl Job {
    fn new(id: u64, scope: CaseSessionWire, kind: Kind) -> Self {
        Self {
            scope,
            cancel: AtomicBool::new(false),
            saved_count: Mutex::new(None),
            passive_grant: OnceLock::new(),
            snapshot: Mutex::new(WebAssessmentJobWire {
                job_id: id,
                kind: kind.name().into(),
                state: "running".into(),
                processed: 0,
                discovered: 0,
                findings: vec![],
                rule_findings: vec![],
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
            state.rule_findings.clear();
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
                Ok(Outcome::Passive(mut alerts)) => {
                    alerts.truncate(passive_rules_application::MAX_FINDINGS);
                    state.discovered = alerts.len();
                    state.rule_findings = alerts;
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
    /// Deny stale passive observations after consent expiry/revocation,
    /// even when the operator has not changed the selected case.
    fn with_passive_authority<T>(
        &self,
        session: &CaseSessionCtx,
        action: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        if self.view()?.kind != "passive" {
            return action();
        }
        let grant = self
            .passive_grant
            .get()
            .ok_or("passive job grant unavailable")?;
        // Hold consent authority through the complete result publication or
        // SQLite commit, so proxy_stop/revoke cannot interleave with it.
        // Lock order: case store (if saving) -> publication -> policy -> job.
        let policy = session
            .history_policy
            .lock()
            .map_err(|_| "History policy unavailable".to_string())?;
        policy.authorize_grant(grant)?;
        action()
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
        if state.state != "completed"
            || !matches!(
                state.kind.as_str(),
                "scanner"
                    | "spider"
                    | "passive"
                    | "active-query"
                    | "active-form"
                    | "active-json"
                    | "active-sql"
                    | "active-sql-boolean"
                    | "active-traversal"
                    | "active-oast"
            )
        {
            return Err("only completed native Web findings may be saved".into());
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
        let records = if state.kind == "spider" {
            // The crawler has already enforced same-origin, DNS pinning,
            // no query/fragment credentials and bounded discovery. Validate
            // the final immutable URLs again before any SQLite write. Saving
            // is explicit: no automatic persistence of browsing history.
            state
                .urls
                .iter()
                .take(60)
                .map(|url| {
                    if url.len() > 4096 {
                        return Err("discovered Web route exceeds case evidence limit".into());
                    }
                    let parsed = reqwest::Url::parse(url)
                        .map_err(|_| "discovered Web route is malformed")?;
                    if !matches!(parsed.scheme(), "http" | "https")
                        || parsed.host_str().is_none()
                        || !parsed.username().is_empty()
                        || parsed.password().is_some()
                        || parsed.query().is_some()
                        || parsed.fragment().is_some()
                    {
                        return Err("Web route contains unsupported or sensitive URL parts".into());
                    }
                    Ok(NewFinding {
                        title: "Discovered Web route".into(),
                        severity: "info".into(),
                        details: format!(
                            "URL: {}\\nSource: authorized bounded same-origin Spider",
                            url
                        ),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?
        } else if state.kind == "passive" {
            state
                .rule_findings
                .iter()
                .take(128)
                .map(|alert| {
                    let mut title = format!("[{}] {}", alert.rule_id, alert.title);
                    while title.len() > 200 {
                        title.pop();
                    }
                    let mut details = format!(
                        "Rule: {}\nConfidence: {}\n{}\nEvidence: {}",
                        alert.rule_id, alert.confidence, alert.detail, alert.evidence,
                    );
                    while details.len() > 8192 {
                        details.pop();
                    }
                    NewFinding {
                        title,
                        severity: alert.severity.clone(),
                        details,
                    }
                })
                .collect::<Vec<_>>()
        } else {
            records
        };
        let source = match state.kind.as_str() {
            "passive" => "web.passive",
            "spider" => "web.spider",
            "active-query" => "web.active.query",
            "active-form" => "web.active.form",
            "active-json" => "web.active.json",
            "active-sql" => "web.active.sql",
            "active-sql-boolean" => "web.active.sql.boolean",
            "active-traversal" => "web.active.traversal",
            "active-oast" => "web.active.oast",
            _ => "web.native",
        };
        let written = store.add_findings(case_id, source, None, &records)?;
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
    Passive(Vec<passive_rules_application::PassiveFinding>),
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

/// Volatile operator-supplied session context for one authenticated target.
/// No field is persisted, echoed in an error or written to a job view.
#[derive(serde::Deserialize)]
pub struct WebSessionHeaderWire {
    name: String,
    value: String,
}

#[derive(serde::Deserialize, Default)]
pub struct WebSessionWire {
    #[serde(default)]
    cookies: Option<String>,
    #[serde(default)]
    headers: Vec<WebSessionHeaderWire>,
}

impl WebSessionWire {
    fn into_context(self) -> Result<AuthContext, String> {
        let headers = self
            .headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect::<Vec<_>>();
        AuthContext::new(self.cookies.as_deref(), &headers)
    }
}

/// Volatile operator callback configuration for out-of-band checks.
/// The collector binds locally; the base URL is what the target must reach.
#[derive(serde::Deserialize)]
pub struct WebOastWire {
    bind: String,
    base_url: String,
}

impl WebOastWire {
    fn into_config(self) -> Result<active_oast_application::OastConfig, String> {
        active_oast_application::OastConfig::new(&self.bind, &self.base_url)
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
    probe_body: Option<String>,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    // Preserve the existing IPC and Rust call signature. Legacy clients
    // receive the previous full hard caps; v2 is explicitly opt-in.
    web_assessment_start_v2(
        kind, target_url, max_depth, authorized, probe_body, None, app, session,
    )
    .await
}

/// Optional native scan-intensity request budgets; additive IPC only.
#[tauri::command]
pub async fn web_assessment_start_v2(
    kind: String,
    target_url: String,
    max_depth: u8,
    authorized: bool,
    probe_body: Option<String>,
    scan_intensity: Option<String>,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    web_assessment_start_v3(
        kind,
        target_url,
        max_depth,
        authorized,
        probe_body,
        scan_intensity,
        None,
        app,
        session,
    )
    .await
}

/// Legacy authenticated entry point; out-of-band checks use v4.
#[tauri::command]
pub async fn web_assessment_start_v3(
    kind: String,
    target_url: String,
    max_depth: u8,
    authorized: bool,
    probe_body: Option<String>,
    scan_intensity: Option<String>,
    auth: Option<WebSessionWire>,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    web_assessment_start_v4(
        kind,
        target_url,
        max_depth,
        authorized,
        probe_body,
        scan_intensity,
        auth,
        None,
        app,
        session,
    )
    .await
}

/// Additive IPC: optional out-of-band callback configuration for confirmed
/// blind SSRF. The collector binds locally; the base URL is target-facing.
#[tauri::command]
pub async fn web_assessment_start_v4(
    kind: String,
    target_url: String,
    max_depth: u8,
    authorized: bool,
    probe_body: Option<String>,
    scan_intensity: Option<String>,
    auth: Option<WebSessionWire>,
    oast: Option<WebOastWire>,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
) -> Result<u64, String> {
    scan_domain::require_authorization(authorized)?;
    let auth = auth
        .map(WebSessionWire::into_context)
        .transpose()?
        .unwrap_or_default();
    let oast = oast.map(WebOastWire::into_config).transpose()?;
    if kind == "active-oast" && oast.is_none() {
        return Err("out-of-band checks require a callback bind address and base URL".into());
    }
    let kind = Kind::parse(&kind)?;
    if matches!(kind, Kind::Passive) {
        return Err("passive history scans require the protected offline entry point".into());
    }
    let intensity = ScanIntensity::parse(scan_intensity.as_deref())?;
    if scan_intensity.is_some()
        && !matches!(
            kind,
            Kind::ActiveQuery
                | Kind::ActiveForm
                | Kind::ActiveJson
                | Kind::ActiveSql
                | Kind::ActiveSqlBoolean
                | Kind::ActiveTraversal
                | Kind::ActiveOast
        )
    {
        return Err("scan intensity applies only to parameter probes".into());
    }
    // The template is supplied intentionally; Spider never auto-submits forms.
    // Parse before OS confirmation and reject all credential/CSRF-like fields.
    let body_plan = match kind {
        Kind::ActiveForm => Some(active_body_application::BodyPlan::new(
            active_body_application::BodyKind::Form,
            probe_body
                .as_deref()
                .ok_or("manual form POST template required")?,
        )?),
        Kind::ActiveJson => Some(active_body_application::BodyPlan::new(
            active_body_application::BodyKind::Json,
            probe_body
                .as_deref()
                .ok_or("manual JSON POST template required")?,
        )?),
        _ => {
            if probe_body.as_deref().is_some_and(|body| !body.is_empty()) {
                return Err("POST template is not valid for this Web job type".into());
            }
            None
        }
    };
    let selected = session.selected()?;
    let pinned = target_scope::prepare_private_target_with_auth(&target_url, &auth).await?;
    session.ensure(&selected)?;
    let purpose = match kind {
        Kind::ActiveQuery => "at most nine GET requests with inert HTML markup query probes",
        Kind::ActiveForm | Kind::ActiveJson => "an explicitly supplied POST template and up to four inert markup mutations; POST MAY CHANGE SERVER STATE even if probes are harmless HTML markers",
        Kind::ActiveSql => "at most nine read-only GET requests with bounded SQL syntax probes",
        Kind::ActiveSqlBoolean => "read-only paired GET comparisons for boolean SQL inference",
        Kind::ActiveTraversal => "bounded read-only GET requests with file-inclusion signatures",
        Kind::ActiveOast => "read-only GET requests to URL-like parameters with a local out-of-band callback collector",
        Kind::Scanner => "a bounded native HTTP security review",
        Kind::Spider => "bounded same-origin GET discovery",
        Kind::Passive => return Err("passive mode does not send network requests".into()),
    };
    let purpose = format!("{}{}", purpose, auth.summary());
    authorize_pinned_assessment(app.clone(), &session, &selected, &pinned, &purpose).await?;
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
                Kind::ActiveForm | Kind::ActiveJson => active_body_application::run_with_budget(
                    &pinned.client,
                    pinned.url.clone(),
                    id,
                    body_plan.ok_or("POST template missing")?,
                    intensity.request_budget(kind),
                    &on_progress,
                )
                .await
                .map(Outcome::Findings),
                Kind::ActiveQuery => active_query_application::run_active_query_with_budget(
                    &pinned.client,
                    pinned.url.clone(),
                    id,
                    active_query_application::Policy::InertHtmlElement,
                    intensity.request_budget(kind),
                    &on_progress,
                )
                .await
                .map(Outcome::Findings),
                Kind::ActiveSql => active_injection_application::run_active_injection_with_budget(
                    &pinned.client,
                    pinned.url.clone(),
                    active_injection_application::Policy::SqlError,
                    intensity.request_budget(kind),
                    &on_progress,
                )
                .await
                .map(Outcome::Findings),
                Kind::ActiveSqlBoolean => {
                    active_injection_application::run_active_injection_with_budget(
                        &pinned.client,
                        pinned.url.clone(),
                        active_injection_application::Policy::SqlBoolean,
                        intensity.request_budget(kind),
                        &on_progress,
                    )
                    .await
                    .map(Outcome::Findings)
                }
                Kind::ActiveTraversal => {
                    active_injection_application::run_active_injection_with_budget(
                        &pinned.client,
                        pinned.url.clone(),
                        active_injection_application::Policy::Traversal,
                        intensity.request_budget(kind),
                        &on_progress,
                    )
                    .await
                    .map(Outcome::Findings)
                }
                Kind::ActiveOast => {
                    let config = oast
                        .as_ref()
                        .ok_or("out-of-band callback configuration is not available")?;
                    let collector =
                        active_oast_application::OastCollector::bind(config.bind).await?;
                    active_oast_application::run_oast_with_budget(
                        &pinned.client,
                        pinned.url.clone(),
                        &config.base,
                        &collector,
                        id,
                        intensity.request_budget(kind),
                        std::time::Duration::from_secs(3),
                        &on_progress,
                    )
                    .await
                    .map(Outcome::Findings)
                }
                Kind::Scanner => scan_application::run_scan_with_progress(
                    &pinned.client,
                    pinned.url.to_string(),
                    true,
                    !auth.is_empty(),
                    &on_progress,
                )
                .await
                .map(Outcome::Findings),
                Kind::Passive => {
                    Err("passive history scans have a separate consent-bound entry point".into())
                }
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

/// Rule catalog is intentionally fixed and source-versioned. No dynamic
/// scripts, plugins, arbitrary regex or history-reveal controls in IPC.
#[tauri::command]
pub fn web_passive_rules_v1() -> Vec<passive_rules_application::RuleInfo> {
    passive_rules_application::RULES.to_vec()
}

/// Passively inspect only existing backend-consented volatile HTTP history.
/// No OS network authorization is needed because this issues NO HTTP requests.
/// Captured raw bytes never leave the History mutex or enter the job registry.
#[tauri::command]
pub fn web_passive_start_v1(
    enabled_rules: Vec<String>,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    proxy: State<'_, WebCtx>,
) -> Result<u64, String> {
    let selected_ids = passive_rules_application::selected_rules(&enabled_rules)?;
    let selected = session.selected()?;
    let grant = selected_history_grant(&session, &selected, &proxy)?;
    let observations = webhistory::passive_observations(&grant)?;
    if observations.is_empty() {
        return Err("no authorized volatile HTTP history to analyze".into());
    }
    let job = session.with_current_publication(&selected, || {
        session
            .history_policy
            .lock()
            .map_err(|_| "case history policy unavailable")?
            .authorize_grant(&grant)?;
        registry()
            .lock()
            .map_err(|_| "Web job registry unavailable")?
            .add(selected.clone(), Kind::Passive)
    })?;
    job.passive_grant
        .set(grant.clone())
        .map_err(|_| "passive job grant already bound")?;
    let id = job.view()?.job_id;
    tauri::async_runtime::spawn(async move {
        let session = app.state::<CaseSessionCtx>();
        let proxy = app.state::<WebCtx>();
        let mut findings = Vec::new();
        let mut failed = None;
        for (index, observation) in observations.iter().enumerate() {
            // Yield and bound work to make Stop, consent expiry and case switch
            // observable, even if all 64 responses are already in memory.
            tokio::time::sleep(Duration::from_millis(2)).await;
            if job.cancel.load(Ordering::Acquire) {
                job.cancelled();
                return;
            }
            let authority = session.ensure(&selected).and_then(|_| {
                if !proxy.shared.running.load(Ordering::Acquire) {
                    return Err("proxy stopped during passive analysis".into());
                }
                session
                    .history_policy
                    .lock()
                    .map_err(|_| "passive scan policy unavailable".to_string())?
                    .authorize_grant(&grant)
                    .map(|_| ())
            });
            if let Err(error) = authority {
                failed = Some(error);
                break;
            }
            for alert in passive_rules_application::analyze(observation, &selected_ids) {
                if findings.len() >= passive_rules_application::MAX_FINDINGS {
                    break;
                }
                findings.push(alert);
            }
            job.progress(index + 1, findings.len());
        }
        let result = match failed {
            Some(error) => Err(error),
            None => Ok(Outcome::Passive(findings)),
        };
        if session
            .with_current_publication(&selected, || {
                if !proxy.shared.running.load(Ordering::Acquire) {
                    return Err("proxy stopped before passive result publication".into());
                }
                session
                    .history_policy
                    .lock()
                    .map_err(|_| "passive scan policy unavailable".to_string())?
                    .authorize_grant(&grant)?;
                if job.cancel.load(Ordering::Acquire) {
                    job.cancelled();
                } else {
                    job.finish(result);
                }
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
        let job = registry()
            .lock()
            .map_err(|_| "Web job registry unavailable")?
            .get(job_id, &selected)?;
        job.with_passive_authority(&session, || job.view())
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
        job.with_passive_authority(&session, || job.save_completed(&store, case_id))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_intensity_is_strictly_allowlisted_and_never_exceeds_hard_caps() {
        assert_eq!(ScanIntensity::parse(None).unwrap(), ScanIntensity::Thorough);
        assert!(ScanIntensity::parse(Some("unlimited")).is_err());
        assert!(ScanIntensity::parse(Some("Thorough")).is_err());
        assert!(ScanIntensity::parse(Some("0")).is_err());
        for (text, query, post) in [("quick", 1, 1), ("standard", 4, 2), ("thorough", 8, 4)] {
            let intensity = ScanIntensity::parse(Some(text)).unwrap();
            assert_eq!(intensity.request_budget(Kind::ActiveQuery), query);
            assert_eq!(intensity.request_budget(Kind::ActiveForm), post);
            assert_eq!(intensity.request_budget(Kind::ActiveJson), post);
            assert_eq!(intensity.request_budget(Kind::Scanner), 0);
            assert_eq!(intensity.request_budget(Kind::Spider), 0);
        }
    }

    #[test]
    fn native_post_job_kinds_are_distinct_and_case_save_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("case.db")).unwrap();
        let case = store.create_case("Authorized POST lab", "").unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, &case.id).unwrap();
        for (number, text, source) in [
            (100, "active-form", "web.active.form"),
            (101, "active-json", "web.active.json"),
        ] {
            let kind = Kind::parse(text).unwrap();
            assert_eq!(kind.name(), text);
            let job = Job::new(number, selected.clone(), kind);
            job.finish(Ok(Outcome::Findings(vec![Finding {
                severity: "low".into(),
                title: "potential unescaped POST parameter reflection".into(),
                detail: "Inert HTML marker; check browser context".into(),
                evidence: "Rule cd.ascan.post-html-reflection.v1; field position 1".into(),
            }])));
            assert_eq!(job.save_completed(&store, &case.id).unwrap(), 1);
            assert_eq!(job.save_completed(&store, &case.id).unwrap(), 1);
            let found = store.list_findings(&case.id).unwrap();
            assert!(
                found.iter().any(|entry| entry.source == source),
                "case must retain findings from each native POST job"
            );
        }
        assert_eq!(store.list_findings(&case.id).unwrap().len(), 2);
        session.select(&store, &case.id).unwrap();
        assert!(session
            .with_current_publication(&selected, || Ok(()))
            .is_err());
    }

    #[test]
    fn active_query_findings_save_exactly_once_with_distinct_case_source() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("case.db")).unwrap();
        let case = store.create_case("Approved query probe", "").unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, &case.id).unwrap();
        assert_eq!(Kind::parse("active-query").unwrap().name(), "active-query");
        let job = Job::new(937, selected.clone(), Kind::ActiveQuery);
        job.finish(Ok(Outcome::Findings(vec![Finding {
            severity: "low".into(),
            title: "potential unescaped HTML parameter reflection".into(),
            detail: "Inert marker observed; browser-context confirmation required".into(),
            evidence: "Rule cd.ascan.query-html-reflection.v1; approved origin http://127.0.0.1:9000; position 1".into(),
        }])));
        let written = session
            .with_current_publication(&selected, || job.save_completed(&store, &case.id))
            .unwrap();
        assert_eq!(written, 1);
        assert_eq!(job.save_completed(&store, &case.id).unwrap(), 1);
        let findings = store.list_findings(&case.id).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "web.active.query");
        assert_eq!(findings[0].severity, "low");
        assert!(!findings[0].details.contains("token="));
        session.select(&store, &case.id).unwrap();
        assert!(session
            .with_current_publication(&selected, || { job.save_completed(&store, &case.id) })
            .is_err());
    }

    #[test]
    fn passive_job_consent_revocation_and_reconsent_prevent_stale_access() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("case.db")).unwrap();
        let case = store.create_case("Passive case", "").unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, &case.id).unwrap();
        let grant = session
            .history_policy
            .lock()
            .unwrap()
            .enable_volatile_capture(
                &case.id,
                cyberdeck_storage::HistoryRetentionLimits::default(),
            )
            .unwrap();
        let job = Job::new(912, selected.clone(), Kind::Passive);
        job.passive_grant.set(grant.clone()).unwrap();
        job.finish(Ok(Outcome::Passive(vec![
            passive_rules_application::PassiveFinding {
                rule_id: passive_rules_application::RULES[0].id.into(),
                title: "Missing CSP".into(),
                severity: "low".into(),
                confidence: "medium".into(),
                detail: "HTML response policy".into(),
                evidence: "Volatile HTTP history #42".into(),
                history_id: 42,
                status: 200,
            },
        ])));
        assert!(job.with_passive_authority(&session, || Ok(())).is_ok());
        session.history_policy.lock().unwrap().revoke();
        assert!(job.with_passive_authority(&session, || Ok(())).is_err());
        let renewed = session
            .history_policy
            .lock()
            .unwrap()
            .enable_volatile_capture(
                &case.id,
                cyberdeck_storage::HistoryRetentionLimits::default(),
            )
            .unwrap();
        assert_ne!(renewed.generation, grant.generation);
        assert!(job.with_passive_authority(&session, || Ok(())).is_err());
        // Revision need not change for a consent replacement: the grant is
        // distinct authority, so stale findings must not become saveable.
        assert_eq!(session.selected().unwrap(), selected);
    }

    #[test]
    fn passive_rule_job_saves_only_redacted_evidence_once() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("case.db")).unwrap();
        let record = store.create_case("Passive findings", "").unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, &record.id).unwrap();
        let job = Job::new(72, selected.clone(), Kind::Passive);
        job.finish(Ok(Outcome::Passive(vec![
            passive_rules_application::PassiveFinding {
                rule_id: passive_rules_application::RULES[0].id.into(),
                title: "Missing CSP".into(),
                severity: "low".into(),
                confidence: "medium".into(),
                detail: "HTML lacks enforcing CSP".into(),
                evidence: "Volatile HTTP history #456; response 200".into(),
                history_id: 456,
                status: 200,
            },
        ])));
        assert_eq!(job.view().unwrap().rule_findings.len(), 1);
        let saved = session
            .with_current_publication(&selected, || job.save_completed(&store, &record.id))
            .unwrap();
        assert_eq!(saved, 1);
        assert_eq!(job.save_completed(&store, &record.id).unwrap(), 1);
        let findings = store.list_findings(&record.id).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "web.passive");
        assert!(findings[0].title.contains("cd.pscan.csp-missing.v1"));
        assert!(findings[0].details.contains("Confidence: medium"));
        assert!(!findings[0].details.contains("token="));
        session.select(&store, &record.id).unwrap();
        assert!(session
            .with_current_publication(&selected, || { job.save_completed(&store, &record.id) })
            .is_err());
    }

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
    fn native_scan_findings_refuse_scratchpad_pending_and_cancelled() {
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
        let finished = Job::new(9, case, Kind::Scanner);
        finished.finish(Ok(Outcome::Findings(vec![])));
        assert!(finished.save_completed(&store, "scratchpad").is_err());
        assert!(finished.save_completed(&store, "anothercase").is_err());
    }

    #[test]
    fn spider_discovered_routes_require_explicit_case_save_and_preserve_scope() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("web-spider.db")).unwrap();
        let own = store.create_case("Authorized Spider case", "").unwrap();
        let other = store.create_case("Unrelated case", "").unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, &own.id).unwrap();
        let spider = Job::new(806, selected.clone(), Kind::Spider);
        spider.finish(Ok(Outcome::Urls(vec![
            "http://127.0.0.1:8080/".into(),
            "http://127.0.0.1:8080/about".into(),
        ])));
        assert!(spider.save_completed(&store, &other.id).is_err());
        let first = session
            .with_current_publication(&selected, || spider.save_completed(&store, &own.id))
            .unwrap();
        assert_eq!(first, 2);
        assert_eq!(spider.save_completed(&store, &own.id).unwrap(), first);
        let findings = store.list_findings(&own.id).unwrap();
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|entry| entry.source == "web.spider" && entry.severity == "info"));
        assert!(findings
            .iter()
            .any(|entry| entry.details.contains("/about")));
        assert!(store.list_findings(&other.id).unwrap().is_empty());
        session.select(&store, &own.id).unwrap();
        assert!(session
            .with_current_publication(&selected, || spider.save_completed(&store, &own.id))
            .is_err());
    }

    #[test]
    fn spider_rejects_sensitive_or_malformed_routes_before_any_case_write() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("web-spider-invalid.db")).unwrap();
        let own = store.create_case("Sensitive path case", "").unwrap();
        let session = CaseSessionCtx::default();
        let selected = session.select(&store, &own.id).unwrap();
        for (id, url) in [
            (90, "http://127.0.0.1/?token=secret"),
            (91, "http://user:secret@127.0.0.1/private"),
            (92, "file:///etc/passwd"),
            (93, "not a URL"),
        ] {
            let spider = Job::new(id, selected.clone(), Kind::Spider);
            spider.finish(Ok(Outcome::Urls(vec![url.to_string()])));
            assert!(spider.save_completed(&store, &own.id).is_err());
        }
        assert!(store.list_findings(&own.id).unwrap().is_empty());
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

"use client";
import { useEffect, useRef, useState } from "react";
import { Play, Square } from "lucide-react";
import { Chip, EmptyState, Pane, TextInput, ToolButton } from "@ds/panes";
import { WorkspaceShell } from "@ds/compact";
import { isDesktop } from "@lib/ipc";
import { useWebWorkflow } from "./WebWorkflow";
import { useCaseReady, useWorkbench } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import { CaseGate } from "@ds/case-gate";
import {
  cancelWebAssessment, startWebAssessment, webAssessmentStatus, waitForWebAssessment, saveWebAssessmentFindings,
  type WebAssessmentJob,
} from "./controller/assessment-jobs";

function parseSessionHeaders(text: string): { name: string; value: string }[] {
  return text.split("\n").map((line) => line.trim()).filter(Boolean).slice(0, 8).flatMap((line) => {
    const separator = line.indexOf(":");
    if (separator <= 0) return [];
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    return name && value ? [{ name, value }] : [];
  });
}

export function ScannerView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const { caseId, caseRevision, caseReady } = useCaseReady();
  const { target, setTarget, normalized } = useWebWorkflow();
  const [jobId, setJobId] = useWorkspaceDraft<number | null>(caseId, "web", "scanner-job", null);
  const [job, setJob] = useState<WebAssessmentJob | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [postFormat, setPostFormat] = useState<"form" | "json">("form");
  const [scanIntensity, setScanIntensity] = useState<"quick" | "standard" | "thorough">("standard");
  // Volatile input, never written to workspace drafts or SQLite.
  const [postTemplate, setPostTemplate] = useState("");
  const [postRiskApproved, setPostRiskApproved] = useState(false);
  // Volatile session context: never written to workspace drafts, cases or logs.
  const [sessionOpen, setSessionOpen] = useState(false);
  const [sessionCookie, setSessionCookie] = useState("");
  const [sessionHeaders, setSessionHeaders] = useState("");
  // Local SSRF confirmation collector; operator infrastructure, not a secret.
  const [oastOpen, setOastOpen] = useState(false);
  const [oastBind, setOastBind] = useState("");
  const [oastBase, setOastBase] = useState("");
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedCount, setSavedCount] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const context = useRef({ caseId, target: normalized, revision: 0 });
  const lastBinding = useRef({ caseId, caseRevision, target: normalized });
  context.current.caseId = caseId;
  context.current.target = normalized;
  const running = busy || job?.state === "running";
  const hasQuery = (() => {
    try { return new URL(normalized).searchParams.size > 0; }
    catch { return false; }
  })();
  const findings = job?.state === "completed" ? job.findings : [];

  useEffect(() => {
    const previous = lastBinding.current;
    const changed = previous.caseId !== caseId ||
      previous.caseRevision !== caseRevision || previous.target !== normalized;
    lastBinding.current = { caseId, caseRevision, target: normalized };
    context.current.revision++;
    if (changed) {
      // A target or native scope transition must not leave an old active
      // assessment consuming the two-job budget invisibly. The backend alone
      // decides whether this old ID is still authorized for cancellation.
      if (jobId !== null) void cancelWebAssessment(jobId).catch(() => {});
      setJobId(null);
    }
    setJob(null); setAuthorized(false); setSavedCount(0);
    setPostTemplate(""); setPostRiskApproved(false);
    setSessionCookie(""); setSessionHeaders("");
    setBusy(false); setError(null);
  }, [caseId, caseRevision, normalized]);

  useEffect(() => {
    if (!desktop || jobId === null) return;
    let disposed = false;
    let inFlight = false;
    const read = async () => {
      if (disposed || inFlight) return;
      inFlight = true;
      try {
        const status = await webAssessmentStatus(jobId);
        if (!disposed) setJob(status);
      } catch (cause) {
        if (!disposed) { setJob(null); setError(String(cause)); }
      } finally { inFlight = false; }
    };
    void read();
    const timer = setInterval(() => void read(), 650);
    return () => { disposed = true; clearInterval(timer); };
  }, [desktop, jobId, caseId, caseRevision]);

  const start = async (kind: "scanner" | "active-query" | "active-form" | "active-json" | "active-sql" | "active-sql-boolean" | "active-traversal" | "active-oast" = "scanner") => {
    if (!desktop || running || !normalized || !authorized || !caseReady) return;
    const post = kind === "active-form" || kind === "active-json";
    if (post && (!postRiskApproved || !postTemplate.trim())) return;
    const template = post ? postTemplate : undefined;
    const sessionHeaderPairs = parseSessionHeaders(sessionHeaders);
    const auth = sessionCookie.trim() || sessionHeaderPairs.length
      ? { cookies: sessionCookie.trim() || null, headers: sessionHeaderPairs }
      : undefined;
    const oast = kind === "active-oast" && oastBind.trim() && oastBase.trim()
      ? { bind: oastBind.trim(), base_url: oastBase.trim() }
      : undefined;
    if (kind === "active-oast" && !oast) return;
    const stamp = { ...context.current };
    setBusy(true); setSavedCount(0); setError(null); setJob(null);
    try {
      // The Jobs dock monitors the actual backend operation until it reaches
      // a terminal state. Navigation does not stop the native worker.
      const completed = await wb.trackOperation(
        kind === "active-query" ? "Web active query" :
        kind === "active-sql" ? "Web SQL injection probe" :
        kind === "active-sql-boolean" ? "Web boolean SQL probe" :
        kind === "active-traversal" ? "Web file inclusion probe" :
        kind === "active-oast" ? "Web SSRF callback probe" :
        post ? "Web approved POST probe" : "Web scanner", async () => {
        const id = await startWebAssessment(kind, stamp.target, true, 2, template,
          kind === "scanner" ? undefined : scanIntensity, auth, oast);
        if (context.current.revision === stamp.revision) setJobId(id);
        else void cancelWebAssessment(id).catch(() => {});
        return waitForWebAssessment(id, (current) => {
          if (context.current.revision === stamp.revision &&
              context.current.caseId === stamp.caseId) setJob(current);
        });
      });
      if (context.current.revision === stamp.revision &&
          context.current.caseId === stamp.caseId) {
        setJob(completed);
        if (completed.state === "failed") setError(completed.error ?? "Web scan failed");
        if (completed.state === "cancelled") setError("Scan cancelled");
      }
    } catch (cause) {
      if (context.current.revision === stamp.revision) setError(String(cause));
    } finally { if (context.current.revision === stamp.revision) setBusy(false); }
  };
  const stop = async () => {
    if (jobId === null) return;
    try { setJob(await cancelWebAssessment(jobId)); }
    catch (cause) { setError(String(cause)); }
  };
  const save = async () => {
    if (saving || !job || job.state !== "completed" || !findings.length ||
        !caseReady) return;
    const selectedCase = caseId;
    const selectedJob = job.job_id;
    setSaving(true);
    try {
      const current = await webAssessmentStatus(selectedJob);
      if (current.state !== "completed") throw new Error("Scan result is no longer available");
      if (context.current.caseId !== selectedCase) return;
      // Case identity, source and findings come only from the completed
      // backend job. Frontend must never choose the destination case.
      const saved = await saveWebAssessmentFindings(selectedJob);
      if (context.current.caseId === selectedCase) setSavedCount(saved);
    } catch (cause) { setError(String(cause)); }
    finally { setSaving(false); }
  };
  const tone = (s: string) => s === "critical" || s === "high" ? "err" :
    s === "medium" ? "orange" : "muted";
  return <WorkspaceShell
    contentClassName="flex flex-col"
    toolbar={
      <>
        <TextInput value={target} onChange={setTarget} placeholder="http://127.0.0.1:3000"
          ariaLabel="Scanner target" className="w-72" />
        {running && jobId !== null
          ? <ToolButton tone="danger" onClick={() => void stop()}><Square size={12} /> Stop</ToolButton>
          : <ToolButton tone="primary" disabled={!desktop || !caseReady || !normalized || !authorized || running}
              onClick={() => void start("scanner")}><Play size={12} /> Start review</ToolButton>}
        <ToolButton onClick={() => setAdvancedOpen((open) => !open)}
          title="Show additional bounded active Web testing tools">
          {advancedOpen ? "Hide advanced tests" : "Advanced tests"}
        </ToolButton>
        {(sessionCookie.trim() || sessionHeaders.trim()) && (
          <span className="flex items-center gap-1 text-[11px] text-fg-dim">
            Session context enabled (volatile)
            <ToolButton onClick={() => { setSessionCookie(""); setSessionHeaders(""); }}
              title="Discard all volatile authentication headers and cookies before another scan">
              Clear session
            </ToolButton>
          </span>
        )}
        <span className="ml-auto font-mono text-[10px] text-fg-muted">
          {job ? `${job.kind} · ${job.state} · ${job.processed} requests · ${job.discovered} findings` : "Native review"}
        </span>
      </>
    }
  >
    <CaseGate activity="Web security assessment" />
    {advancedOpen && (
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-panel p-2">
      <label className="flex items-center gap-1 text-[11px] text-fg-muted">
        Intensity
        <select value={scanIntensity} disabled={running}
          aria-label="Active scan intensity"
          onChange={(event) => setScanIntensity(event.target.value as "quick" | "standard" | "thorough")}
          className="rounded border border-line bg-panel px-1 py-0.5 text-fg">
          <option value="quick">Quick · 1 mutation</option>
          <option value="standard">Standard · 4 GET / 2 POST</option>
          <option value="thorough">Thorough · 8 GET / 4 POST</option>
        </select>
      </label>
      <ToolButton disabled={!desktop || !caseReady || !normalized || !authorized || running || !hasQuery}
        title="Send a baseline and bounded inert GET parameter probes, only to the approved private origin"
        onClick={() => void start("active-query")}>
        <Play size={12} /> Test query parameters
      </ToolButton>
      <ToolButton disabled={!desktop || !caseReady || !normalized || !authorized || running || !hasQuery}
        title="Append one quote to each eligible GET parameter and compare database error signatures; read-only, bounded"
        onClick={() => void start("active-sql")}>
        <Play size={12} /> Test SQL injection
      </ToolButton>
      <ToolButton disabled={!desktop || !caseReady || !normalized || !authorized || running || !hasQuery}
        title="Compare tautological and contradictory GET clauses against the baseline; heuristic, read-only, bounded"
        onClick={() => void start("active-sql-boolean")}>
        <Play size={12} /> Test SQL boolean
      </ToolButton>
      <ToolButton disabled={!desktop || !caseReady || !normalized || !authorized || running || !hasQuery}
        title="Substitute traversal sequences in file-like GET parameters and confirm known file signatures; read-only, bounded"
        onClick={() => void start("active-traversal")}>
        <Play size={12} /> Test file inclusion
      </ToolButton>
      <ToolButton disabled={!desktop || !caseReady || !normalized || !authorized || running || !hasQuery ||
        !oastBind.trim() || !oastBase.trim()}
        title="Send a URL-like parameter a local callback address and confirm only an actual out-of-band connection; read-only"
        onClick={() => void start("active-oast")}>
        <Play size={12} /> Test SSRF (OAST)
      </ToolButton>

        {!hasQuery && <span className="text-[11px] text-fg-muted">
          To run parameter tests, enter a URL with a query string, e.g. /search?q=sample.
        </span>}
      </div>
    )}
    <label className="flex items-center gap-2 border-b border-line px-2 py-1.5 text-[11px] text-fg-dim">
      <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
      Authorized target · native approval required
    </label>
    <div className="border-b border-line px-2 py-1 text-[10px] text-fg-muted">
      Start review checks an approved private or loopback target with the native engine. Expand Advanced tests for optional bounded query mutations; these are heuristics, not confirmed exploitation. A saved case, target ownership and native approval remain required.
    </div>
    {advancedOpen && (
      <>
    <div className="border-b border-line bg-panel px-2 py-1 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <ToolButton onClick={() => setOastOpen((value) => !value)}>
          {oastOpen ? "Hide out-of-band callback" : "Out-of-band callback"}
        </ToolButton>
        <span className="text-fg-muted">
          {oastBind.trim() && oastBase.trim() ? "Collector configured" : "Optional SSRF confirmation"}
        </span>
      </div>
      {oastOpen && <div className="mt-2 space-y-1">
        <input value={oastBind} disabled={running}
          onChange={(e) => setOastBind(e.target.value.slice(0, 64))}
          aria-label="Callback bind address"
          placeholder="Collector bind, for example 127.0.0.1:9099"
          className="w-full rounded border border-line bg-panel px-2 py-1 font-mono text-[11px] text-fg" />
        <input value={oastBase} disabled={running}
          onChange={(e) => setOastBase(e.target.value.slice(0, 2048))}
          aria-label="Callback base URL"
          placeholder="Base URL the target can reach, for example http://10.0.0.5:9099"
          className="w-full rounded border border-line bg-panel px-2 py-1 font-mono text-[11px] text-fg" />
        <div className="text-[10px] text-fg-muted">
          The collector binds only to a loopback or private address. The base URL must be
          reachable from the target. A finding is reported only if the target actually calls
          back; the collector keeps only the single-use path token.
        </div>
      </div>}
    </div>
    <div className="border-b border-line bg-panel px-2 py-1 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <ToolButton onClick={() => setSessionOpen((value) => !value)}>
          {sessionOpen ? "Hide session context" : "Session context"}
        </ToolButton>
        <span className="text-fg-muted">
          {sessionCookie.trim() || parseSessionHeaders(sessionHeaders).length
            ? "Authenticated requests enabled for this target"
            : "Optional authenticated requests"}
        </span>
      </div>
      {sessionOpen && <div className="mt-2 space-y-2">
        <textarea value={sessionCookie} disabled={running}
          onChange={(e) => setSessionCookie(e.target.value.slice(0, 4096))}
          aria-label="Session cookies"
          placeholder="Cookie value, for example: session=abc123; theme=dark"
          rows={2} spellCheck={false}
          className="w-full resize-y rounded border border-line bg-panel px-2 py-1 font-mono text-[11px] text-fg" />
        <textarea value={sessionHeaders} disabled={running}
          onChange={(e) => setSessionHeaders(e.target.value.slice(0, 8192))}
          aria-label="Session headers"
          placeholder={"One header per line, for example:\nX-Lab-Role: operator"}
          rows={2} spellCheck={false}
          className="w-full resize-y rounded border border-line bg-panel px-2 py-1 font-mono text-[11px] text-fg" />
        <div className="text-[10px] text-fg-muted">
          Sent only to the approved pinned target, including every scanner, crawler and
          parameter probe. Maximum 8 headers. Host, Content-Length, Transfer-Encoding,
          Connection and Cookie headers are rejected; use the cookie field instead.
          Values are never saved to the case, history or logs, and are cleared when the
          target changes. If the baseline is rejected or a probe is redirected to a login
          page, the review stops and reports it instead of continuing unauthenticated.
        </div>
      </div>}
    </div>
    <div className="border-b border-line bg-panel px-2 py-2 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold">Manual POST reflection probe</span>
        <select className="rounded border border-line bg-panel px-2 py-1"
          value={postFormat} disabled={running} aria-label="POST template type"
          onChange={(e) => { setPostFormat(e.target.value as "form" | "json");
            setPostRiskApproved(false); }}>
          <option value="form">Form URL-encoded</option>
          <option value="json">JSON object</option>
        </select>
        <ToolButton disabled={!desktop || !caseReady || !normalized || !authorized || running ||
          !postRiskApproved || !postTemplate.trim()}
          onClick={() => void start(postFormat === "form" ? "active-form" : "active-json")}>
          <Play size={12} /> Test POST fields
        </ToolButton>
        <span className="text-fg-muted">Baseline + intensity-limited mutations; pinned private target</span>
      </div>
      <textarea value={postTemplate} disabled={running}
        onChange={(e) => { setPostTemplate(e.target.value.slice(0, 2048)); setPostRiskApproved(false); }}
        aria-label="Manual POST body"
        placeholder={postFormat === "form" ? "q=example&label=sample" : '{"q":"example","label":"sample"}'}
        rows={2} spellCheck={false}
        className="mt-2 w-full resize-y rounded border border-line bg-panel px-2 py-1 font-mono text-[11px] text-fg" />
      <label className="mt-1 flex items-start gap-2 text-fg-dim">
        <input type="checkbox" checked={postRiskApproved} disabled={running}
          onChange={(e) => setPostRiskApproved(e.target.checked)} />
        I authorize POST submissions to this private target and understand that they may change server state.
        Do not enter passwords, session tokens or CSRF values. Native confirmation is also required.
      </label>
    </div>
      </>
    )}
    {error ? <div role="alert" className="border-b border-line px-2 py-1 text-xs text-err">{error}</div> : null}
    <Pane title="Findings" className="min-h-0 flex-1"
      actions={job?.state === "completed" && findings.length > 0 && caseReady
        ? <ToolButton disabled={saving || savedCount > 0} onClick={() => void save()}>
            {savedCount ? `${savedCount} saved` : saving ? "Saving…" : "Save to case"}
          </ToolButton> : undefined}>
      {findings.length ? <div className="h-full overflow-auto"><table className="data-table">
        <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Evidence</th></tr></thead>
        <tbody>{findings.map((f, i) => <tr key={i}>
          <td><Chip tone={tone(f.severity)}>{f.severity}</Chip></td>
          <td className="text-fg">{f.title}</td>
          <td className="text-fg-dim">{f.detail}</td>
          <td className="break-all text-fg-muted">{f.evidence}</td>
        </tr>)}</tbody>
      </table></div> : <EmptyState title={running ? "Scanning" : job?.state === "completed" ? "No findings" : "Ready"}
        detail={running ? `Checked ${job?.processed ?? 0} HTTP requests` :
          "Enter an authorized private target; choose Start review or Test query parameters."} />}
    </Pane>
  </WorkspaceShell>;
}

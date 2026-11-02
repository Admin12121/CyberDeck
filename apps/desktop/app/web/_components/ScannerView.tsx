"use client";
import { useEffect, useRef, useState } from "react";
import { Play, Square } from "lucide-react";
import { Chip, EmptyState, Pane, TextInput, ToolButton } from "@ds/panes";
import { isDesktop } from "@lib/ipc";
import { useWebWorkflow } from "./WebWorkflow";
import { useWorkbench, useWorkbenchCase } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import {
  cancelWebAssessment, startWebAssessment, webAssessmentStatus, waitForWebAssessment, saveWebAssessmentFindings,
  type WebAssessmentJob,
} from "./controller/assessment-jobs";

export function ScannerView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const { caseId, caseSession } = useWorkbenchCase();
  const { target, setTarget, normalized } = useWebWorkflow();
  const [jobId, setJobId] = useWorkspaceDraft<number | null>(caseId, "web", "scanner-job", null);
  const [job, setJob] = useState<WebAssessmentJob | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [postFormat, setPostFormat] = useState<"form" | "json">("form");
  const [scanIntensity, setScanIntensity] = useState<"quick" | "standard" | "thorough">("standard");
  // Volatile input, never written to workspace drafts or SQLite.
  const [postTemplate, setPostTemplate] = useState("");
  const [postRiskApproved, setPostRiskApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedCount, setSavedCount] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const context = useRef({ caseId, target: normalized, revision: 0 });
  context.current.caseId = caseId;
  context.current.target = normalized;
  const running = busy || job?.state === "running";
  const hasQuery = (() => {
    try { return new URL(normalized).searchParams.size > 0; }
    catch { return false; }
  })();
  const findings = job?.state === "completed" ? job.findings : [];

  useEffect(() => {
    context.current.revision++;
    setJob(null); setAuthorized(false); setSavedCount(0);
    setPostTemplate(""); setPostRiskApproved(false);
    setBusy(false); setError(null);
  }, [caseId, caseSession.revision, normalized]);

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
  }, [desktop, jobId, caseId, caseSession.revision]);

  const start = async (kind: "scanner" | "active-query" | "active-form" | "active-json" | "active-sql" | "active-sql-boolean" | "active-traversal" = "scanner") => {
    if (!desktop || running || !normalized || !authorized) return;
    const post = kind === "active-form" || kind === "active-json";
    if (post && (!postRiskApproved || !postTemplate.trim())) return;
    const template = post ? postTemplate : undefined;
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
        post ? "Web approved POST probe" : "Web scanner", async () => {
        const id = await startWebAssessment(kind, stamp.target, true, 2, template,
          kind === "scanner" ? undefined : scanIntensity);
        if (context.current.revision === stamp.revision) setJobId(id);
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
        caseId === "scratchpad") return;
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
  return <div className="flex h-full min-h-0 flex-col">
    <div className="cd-workspace-toolbar shrink-0 items-center gap-2 px-2">
      <TextInput value={target} onChange={setTarget} placeholder="http://127.0.0.1:3000"
        ariaLabel="Scanner target" className="w-72" />
      {running && jobId !== null
        ? <ToolButton tone="danger" onClick={() => void stop()}><Square size={12} /> Stop</ToolButton>
        : <ToolButton tone="primary" disabled={!desktop || !normalized || !authorized || running}
            onClick={() => void start("scanner")}><Play size={12} /> Start review</ToolButton>}
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
      <ToolButton disabled={!desktop || !normalized || !authorized || running || !hasQuery}
        title="Send a baseline and bounded inert GET parameter probes, only to the approved private origin"
        onClick={() => void start("active-query")}>
        <Play size={12} /> Test query parameters
      </ToolButton>
      <ToolButton disabled={!desktop || !normalized || !authorized || running || !hasQuery}
        title="Append one quote to each eligible GET parameter and compare database error signatures; read-only, bounded"
        onClick={() => void start("active-sql")}>
        <Play size={12} /> Test SQL injection
      </ToolButton>
      <ToolButton disabled={!desktop || !normalized || !authorized || running || !hasQuery}
        title="Compare tautological and contradictory GET clauses against the baseline; heuristic, read-only, bounded"
        onClick={() => void start("active-sql-boolean")}>
        <Play size={12} /> Test SQL boolean
      </ToolButton>
      <ToolButton disabled={!desktop || !normalized || !authorized || running || !hasQuery}
        title="Substitute traversal sequences in file-like GET parameters and confirm known file signatures; read-only, bounded"
        onClick={() => void start("active-traversal")}>
        <Play size={12} /> Test file inclusion
      </ToolButton>
      <span className="ml-auto font-mono text-[10px] text-fg-muted">
        {job ? `${job.kind} · ${job.state} · ${job.processed} requests · ${job.discovered} findings` : "Native review"}
      </span>
    </div>
    <label className="flex items-center gap-2 border-b border-line px-2 py-1.5 text-[11px] text-fg-dim">
      <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
      Authorized target · native approval required
    </label>
    <div className="border-b border-line px-2 py-1 text-[10px] text-fg-muted">
      Query probes send a baseline plus a bounded number of GET mutations according to intensity, skip credential/CSRF-like parameters, and report potential markup reflection—not confirmed executable XSS. The URL must contain query parameters; native approval and private-address scope are mandatory.
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
        <ToolButton disabled={!desktop || !normalized || !authorized || running ||
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
    {error ? <div role="alert" className="border-b border-line px-2 py-1 text-xs text-err">{error}</div> : null}
    <Pane title="Findings" className="min-h-0 flex-1"
      actions={job?.state === "completed" && findings.length > 0 && caseId !== "scratchpad"
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
  </div>;
}

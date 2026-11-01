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
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedCount, setSavedCount] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const context = useRef({ caseId, target: normalized, revision: 0 });
  context.current.caseId = caseId;
  context.current.target = normalized;
  const running = busy || job?.state === "running";
  const findings = job?.state === "completed" ? job.findings : [];

  useEffect(() => {
    context.current.revision++;
    setJob(null); setAuthorized(false); setSavedCount(0);
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

  const start = async () => {
    if (!desktop || running || !normalized || !authorized) return;
    const stamp = { ...context.current };
    setBusy(true); setSavedCount(0); setError(null); setJob(null);
    try {
      // The Jobs dock monitors the actual backend operation until it reaches
      // a terminal state. Navigation does not stop the native worker.
      const completed = await wb.trackOperation("Web scanner", async () => {
        const id = await startWebAssessment("scanner", stamp.target, true);
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
            onClick={() => void start()}><Play size={12} /> Start</ToolButton>}
      <span className="ml-auto font-mono text-[10px] text-fg-muted">
        {job ? `${job.state} · ${job.processed} requests · ${job.discovered} findings` : "Native review"}
      </span>
    </div>
    <label className="flex items-center gap-2 border-b border-line px-2 py-1.5 text-[11px] text-fg-dim">
      <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
      Authorized target · native approval required
    </label>
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
          "Enter an authorized IP target and start the native review."} />}
    </Pane>
  </div>;
}

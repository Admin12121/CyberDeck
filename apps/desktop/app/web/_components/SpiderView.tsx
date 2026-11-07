"use client";
import { useEffect, useRef, useState } from "react";
// Web-native crawler job UI pending integration.

import { Globe, Play, PlayCircle, Square } from "lucide-react";
import { CheckBox, Chip, EmptyState, Pane, Select, TextInput, ToolButton } from "@ds/panes";
import { ErrorStrip, WorkspaceShell } from "@ds/compact";
import {
  engineScan,
  httpSend,
  isDesktop,
  proxyHistory,
  proxyStart,
  proxyStatus,
  proxyStop,
  spiderScan,
  webEnginesDetect,
  webScan,
  type CapturedRequestWire,
  type EngineScanResultWire,
  type HttpResponseWire,
  type ProxyStatusWire,
  type WebEngineStatusWire,
  type WebFindingWire,
} from "@lib/ipc";
import { buildSitesTree, filterCaptured, useTarget } from "./controller";
import { makeGetDraft, useWebWorkflow } from "./WebWorkflow";
import { useCaseReady, useWorkbench } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import { cancelWebAssessment, startWebAssessment, webAssessmentStatus, waitForWebAssessment, saveWebAssessmentFindings, type WebAssessmentJob } from "./controller/assessment-jobs";

// ----------------------------------------------------------------- spider ---

export function SpiderView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const { caseId, caseRevision, caseReady } = useCaseReady();
  const caseRef = useRef(caseId);
  caseRef.current = caseId;
  const crawlRevision = useRef(0);
  const { target, setTarget, normalized, scanTarget, draftInRepeater } = useWebWorkflow();
  const [depth, setDepth] = useState("2");
  const [jobId, setJobId] = useWorkspaceDraft<number | null>(caseId, "web", "spider-job", null);
  const [job, setJob] = useState<WebAssessmentJob | null>(null);
  const [links, setLinks] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedCount, setSavedCount] = useState<number | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastBinding = useRef({ caseId, caseRevision, target: normalized });
  useEffect(() => {
    const before = lastBinding.current;
    const changed = before.caseId !== caseId ||
      before.caseRevision !== caseRevision || before.target !== normalized;
    lastBinding.current = { caseId, caseRevision, target: normalized };
    crawlRevision.current += 1;
    if (changed) {
      if (jobId !== null) void cancelWebAssessment(jobId).catch(() => {});
      setJobId(null);
    }
    setJob(null);
    setLinks([]);
    setSavedCount(null);
    setSaving(false);
    setAuthorized(false);
    setBusy(false);
    setError(null);
  }, [caseId, caseRevision, normalized]);

  useEffect(() => {
    if (!desktop || jobId === null) return;
    let disposed = false;
    let inFlight = false;
    const poll = async () => {
      if (disposed || inFlight) return;
      inFlight = true;
      try {
        const current = await webAssessmentStatus(jobId);
        if (!disposed) {
          setJob(current);
          if (current.state === "completed") setLinks(current.urls);
          if (current.state === "cancelled") setLinks([]);
        }
      } catch (cause) {
        if (!disposed) setError(String(cause));
      } finally { inFlight = false; }
    };
    void poll();
    const timer = setInterval(() => void poll(), 650);
    return () => { disposed = true; clearInterval(timer); };
  }, [desktop, jobId, caseId, caseRevision]);

  const crawl = async () => {
    if (busy || job?.state === "running" || !normalized || !authorized || !caseReady) return;
    const revision = ++crawlRevision.current;
    const selectedCase = caseId;
    const requestedTarget = normalized;
    const requestedDepth = Math.max(1, Math.min(4, Number.parseInt(depth, 10) || 2));
    setBusy(true); setError(null); setLinks([]); setJob(null); setSavedCount(null);
    try {
      const result = await wb.trackOperation("Web spider", async () => {
        const id = await startWebAssessment("spider", requestedTarget, true, requestedDepth);
        if (crawlRevision.current === revision) setJobId(id);
        else void cancelWebAssessment(id).catch(() => {});
        return waitForWebAssessment(id, (current) => {
          if (crawlRevision.current === revision && caseRef.current === selectedCase) {
            setJob(current);
            if (current.state === "completed") setLinks(current.urls);
          }
        });
      });
      if (crawlRevision.current === revision && caseRef.current === selectedCase) {
        setJob(result);
        if (result.state === "completed") setLinks(result.urls);
        if (result.state === "failed") setError(result.error ?? "Spider failed");
        if (result.state === "cancelled") setError("Spider cancelled");
      }
    } catch (cause) {
      if (crawlRevision.current === revision) setError(String(cause));
    } finally { if (crawlRevision.current === revision) setBusy(false); }
  };

  const stop = async () => {
    if (jobId === null) return;
    try { setJob(await cancelWebAssessment(jobId)); setLinks([]); }
    catch (cause) { setError(String(cause)); }
  };

  const save = async () => {
    if (!caseReady || saving || !job || job.state !== "completed" || !job.urls.length) return;
    const key = caseRef.current;
    const revision = crawlRevision.current;
    setSaving(true);
    setError(null);
    try {
      const count = await saveWebAssessmentFindings(job.job_id);
      if (caseRef.current === key && crawlRevision.current === revision) setSavedCount(count);
    } catch (cause) {
      if (caseRef.current === key && crawlRevision.current === revision) setError(String(cause));
    } finally {
      if (caseRef.current === key && crawlRevision.current === revision) setSaving(false);
    }
  };

  return (
    <WorkspaceShell
      contentClassName="flex flex-col"
      toolbar={
        <>
          <span className="font-mono text-3xs uppercase text-fg-muted">target</span>
          <TextInput value={target} onChange={setTarget} placeholder="http://127.0.0.1:3000" ariaLabel="Spider target" className="w-72" />
          <span className="font-mono text-3xs uppercase text-fg-muted">depth</span>
          <Select
            value={depth}
            onChange={setDepth}
            options={[
              { value: "1", label: "1" },
              { value: "2", label: "2" },
              { value: "3", label: "3" },
              { value: "4", label: "4" },
            ]}
            ariaLabel="Spider depth"
            className="w-20"
          />
          {job?.state === "running" && jobId !== null
            ? <ToolButton tone="danger" onClick={() => void stop()}><Square size={11} /> Stop</ToolButton>
            : <ToolButton tone="primary" disabled={busy || !desktop || !caseReady || !normalized || !authorized}
                onClick={() => void crawl()}><Play size={11} /> {busy ? "Authorizing…" : "Start"}</ToolButton>}
          <span className="ml-auto font-mono text-3xs text-fg-muted">
            {job ? `${job.state} · ${job.processed} pages · ${job.discovered} URLs` : `${links.length} URLs`}
          </span>
        </>
      }
    >
      {error ? <ErrorStrip>{error}</ErrorStrip> : null}
      <div className="border-b border-line bg-panel px-3 py-2">
        <CheckBox checked={authorized} onChange={setAuthorized}>
          Authorized target · native approval required
        </CheckBox>
      </div>
      <Pane title="Discovered URLs" className="min-h-0 flex-1"
        actions={caseReady && job?.state === "completed" && job.urls.length > 0
          ? <ToolButton disabled={saving || savedCount !== null}
              onClick={() => void save()}>
              {savedCount !== null ? savedCount + " saved to case" : saving ? "Saving…" : "Save discovered routes to case"}
            </ToolButton> : undefined}>
        {links.length === 0 ? (
          <EmptyState title={busy ? "Crawling…" : "No URLs yet"} detail="Depth-limited same-host crawl; discovered links can be sent to Scanner or drafted in Repeater." badge="spider" />
        ) : (
          <table className="data-table">
            <tbody>
              {links.map((url) => (
                <tr key={url}>
                  <td className="text-fg-dim">{url}</td>
                    <td className="w-44 whitespace-nowrap text-right">
                      <ToolButton onClick={() => draftInRepeater(makeGetDraft(url), true)} title="Create an editable GET request draft; original request headers are not available">Draft in Repeater</ToolButton>
                      <ToolButton onClick={() => scanTarget(url)} title="Set this URL as the scanner target; authorization must be confirmed there">Scan URL</ToolButton>
                    </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Pane>
    </WorkspaceShell>
  );
}

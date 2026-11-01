"use client";
import { useEffect, useRef, useState } from "react";
import { ToolButton } from "@ds/panes";
import {
  cancelWebAssessment, listWebPassiveRules, saveWebAssessmentFindings,
  startWebPassiveScan, webAssessmentStatus,
  type WebAssessmentJob, type WebPassiveRule,
} from "./controller/assessment-jobs";

interface Props {
  enabled: boolean;
  caseId: string;
  revision: number | null;
  generation: number | null;
}

/** The frontend receives only safe rule metadata and redacted findings. */
export function PassiveRulesPanel({ enabled, caseId, revision, generation }: Props) {
  const [open, setOpen] = useState(false);
  const [rules, setRules] = useState<WebPassiveRule[]>([]);
  const [chosen, setChosen] = useState<string[]>([]);
  const [jobId, setJobId] = useState<number | null>(null);
  const [job, setJob] = useState<WebAssessmentJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedCount, setSavedCount] = useState<number | null>(null);
  const stamp = useRef(0);
  useEffect(() => {
    stamp.current++;
    setJobId(null); setJob(null); setSavedCount(null); setSaving(false); setError(null);
  }, [caseId, revision, generation]);
  useEffect(() => {
    if (!open || !enabled) return;
    let disposed = false;
    void listWebPassiveRules().then((data) => {
      if (disposed) return;
      setRules(data);
      setChosen((previous) => previous.length ?
        previous.filter((id) => data.some((r) => r.id === id)) : data.map((r) => r.id));
    }).catch((err) => { if (!disposed) setError(String(err)); });
    return () => { disposed = true; };
  }, [open, enabled]);
  useEffect(() => {
    if (jobId === null || !enabled || !open) return;
    let disposed = false;
    let inflight = false;
    const poll = async () => {
      if (disposed || inflight) return;
      inflight = true;
      try {
        const next = await webAssessmentStatus(jobId);
        if (!disposed) setJob(next);
      } catch (err) {
        if (!disposed) { setJob(null); setError(String(err)); }
      } finally { inflight = false; }
    };
    void poll();
    const interval = setInterval(() => void poll(), 600);
    return () => { disposed = true; clearInterval(interval); };
  }, [jobId, open, enabled]);
  const start = async () => {
    if (!enabled || !chosen.length || job?.state === "running") return;
    const token = stamp.current;
    setError(null); setSavedCount(null); setJob(null);
    try {
      const id = await startWebPassiveScan(chosen);
      if (stamp.current === token) setJobId(id);
    } catch (err) { if (stamp.current === token) setError(String(err)); }
  };
  const stop = async () => {
    if (jobId === null) return;
    try { setJob(await cancelWebAssessment(jobId)); }
    catch (err) { setError(String(err)); }
  };
  const save = async () => {
    if (saving || jobId === null || !job || job.state !== "completed" ||
        !job.rule_findings.length || caseId === "scratchpad") return;
    const token = stamp.current;
    setSaving(true); setError(null);
    try {
      const count = await saveWebAssessmentFindings(jobId);
      if (stamp.current === token) setSavedCount(count);
    } catch (err) { if (stamp.current === token) setError(String(err)); }
    finally { if (stamp.current === token) setSaving(false); }
  };
  return <div className="shrink-0 border-b border-line bg-panel">
    <div className="flex items-center gap-2 px-2 py-1 text-[11px]">
      <ToolButton onClick={() => setOpen((value) => !value)}>{open ? "Hide" : "Passive rules"}</ToolButton>
      <span className="text-fg-muted">Check consented volatile History without sending requests</span>
      <span className="ml-auto text-fg-muted">
        {job ? job.state + " · " + job.processed + " responses · " + job.discovered + " findings" : "Offline only"}
      </span>
    </div>
    {open && <div className="max-h-72 space-y-2 overflow-auto border-t border-line px-3 py-2 text-[11px]">
      {!enabled && <div className="text-fg-muted">Start the proxy and enable case-bound History consent first.</div>}
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {rules.map((rule) => <label key={rule.id} className="flex items-center gap-1 text-fg-dim"
          title={rule.id + " · " + rule.severity}>
          <input type="checkbox" disabled={!enabled || job?.state === "running"}
            checked={chosen.includes(rule.id)} onChange={(e) => setChosen((selected) =>
              e.target.checked ? [...selected, rule.id] : selected.filter((id) => id !== rule.id))} />
          {rule.title}
        </label>)}
      </div>
      <div className="flex items-center gap-2">
        {job?.state === "running" && jobId !== null
          ? <ToolButton tone="danger" onClick={() => void stop()}>Stop</ToolButton>
          : <ToolButton disabled={!enabled || !chosen.length} tone="primary"
            onClick={() => void start()}>Analyze History</ToolButton>}
        {job?.state === "completed" && job.rule_findings.length > 0 && caseId !== "scratchpad" &&
          <ToolButton disabled={saving || savedCount !== null} onClick={() => void save()}>
            {savedCount === null ? "Save findings to case" : String(savedCount) + " saved"}
          </ToolButton>}
        <span className="text-fg-muted">No request bodies, tokens, cookie names or values in findings.</span>
      </div>
      {error && <div role="alert" className="text-err">{error}</div>}
      {job?.state === "completed" && <div className="max-h-44 overflow-auto">
        <table className="data-table">
          <thead><tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>History</th><th>Reason</th></tr></thead>
          <tbody>{job.rule_findings.map((finding, i) => <tr key={finding.rule_id + "-" + finding.history_id + "-" + i}>
            <td title={finding.rule_id}>{finding.title}</td>
            <td>{finding.severity}</td><td>{finding.confidence}</td>
            <td>#{finding.history_id}</td><td>{finding.detail}</td>
          </tr>)}
          {!job.rule_findings.length && <tr><td colSpan={5}>No enabled rule matched retained history.</td></tr>}
          </tbody>
        </table>
      </div>}
    </div>}
  </div>;
}

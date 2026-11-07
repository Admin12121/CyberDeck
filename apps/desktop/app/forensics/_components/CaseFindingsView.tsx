"use client";
/** Case-scoped findings from the shared Rust SQLite evidence store. */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Download, FileSearch, RefreshCcw } from "lucide-react";
import { Chip, EmptyState, Pane, TextInput, ToolButton } from "@ds/panes";
import { ErrorStrip, StatusStrip, WorkspaceShell } from "@ds/compact";
import { caseEventsList, caseFindingsList, caseReport, caseIntegrityVerify, isDesktop, type CaseEventWire, type FindingRecordWire, type CaseIntegritySummaryWire } from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import { downloadContent } from "@lib/download";

export function CaseFindingsView() {
  const wb = useWorkbench();
  const [findings, setFindings] = useState<FindingRecordWire[]>([]);
  const [query, setQuery] = useState("");
  const [events, setEvents] = useState<CaseEventWire[]>([]);
  const [exporting, setExporting] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [verification, setVerification] = useState<CaseIntegritySummaryWire | null>(null);
  const [verifying, setVerifying] = useState(false);
  const verificationSerial = useRef(0);
  const refreshSerial = useRef(0);
  const exportSerial = useRef(0);
  const activeCase = useRef(wb.caseId);
  activeCase.current = wb.caseId;

  useEffect(() => {
    verificationSerial.current += 1;
    refreshSerial.current += 1;
    exportSerial.current += 1;
    setVerification(null);
    setVerifying(false);
    setExporting(false);
    setLoading(false);
    setFindings([]);
    setEvents([]);
    setSelected(null);
    setError(null);
  }, [wb.caseId]);

  const verifyCase = async () => {
    const ticket = ++verificationSerial.current;
    setVerification(null);
    setVerifying(true);
    setError(null);
    try {
      const result = await caseIntegrityVerify(wb.caseId);
      if (ticket === verificationSerial.current) setVerification(result);
    } catch (cause) {
      if (ticket === verificationSerial.current) setError("Integrity verification failed: " + String(cause));
    } finally {
      if (ticket === verificationSerial.current) setVerifying(false);
    }
  };

  const refresh = useCallback(async () => {
    if (!isDesktop()) return;
    const caseId = wb.caseId;
    const ticket = ++refreshSerial.current;
    const isCurrent = () => ticket === refreshSerial.current && activeCase.current === caseId;
    setLoading(true);
    setError(null);
    try {
      const [data, activity] = await Promise.all([caseFindingsList(caseId), caseEventsList(caseId)]);
      if (!isCurrent()) return;
      setEvents(activity);
      setFindings(data);
      setSelected(data[0]?.id ?? null);
    } catch (cause) {
      if (!isCurrent()) return;
      setError(String(cause));
      setFindings([]);
      setEvents([]);
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [wb.caseId]);

  useEffect(() => { if (wb.tool === "forensics.findings") void refresh(); }, [refresh, wb.tool]);

  const exportReport = async () => {
    if (!isDesktop()) return;
    if (!window.confirm("Export this case report? Finding details may contain sensitive information. The JSON will include case metadata, artifact hashes, findings and activity (but not raw evidence or local file paths).")) return;
    const caseId = wb.caseId;
    const ticket = ++exportSerial.current;
    const isCurrent = () => activeCase.current === caseId && exportSerial.current === ticket;
    setExporting(true);
    setError(null);
    try {
      const report = await caseReport(caseId);
      if (!isCurrent()) return;
      downloadContent(JSON.stringify(report, null, 2), "cyberdeck-" + caseId + "-report.json", "application/json");
    } catch (cause) { if (isCurrent()) setError(String(cause)); }
    finally { if (isCurrent()) setExporting(false); }
  };

  const filtered = useMemo(() => {
    const search = query.toLowerCase().trim();
    return findings.filter((item) =>
      !search || [item.title, item.source, item.severity, item.details]
        .some((part) => part.toLowerCase().includes(search)));
  }, [findings, query]);
  const current = filtered.find((f) => f.id === selected) ?? filtered[0] ?? null;
  const severityTone = (value: string) =>
    value === "high" || value === "critical" ? "err" :
    value === "medium" ? "orange" : "muted";

  return (
    <WorkspaceShell
      contentClassName="flex flex-col"
      toolbar={
        <>
          <FileSearch size={13} className="text-orange" />
          <span className="font-mono text-3xs uppercase text-fg-muted">Case findings</span>
          <TextInput value={query} onChange={setQuery} placeholder="filter findings…" ariaLabel="Search case findings" className="w-64" />
          <ToolButton onClick={() => void refresh()} disabled={loading || !isDesktop()} title="Refresh findings">
            <RefreshCcw size={12} /> {loading ? "Loading…" : "Refresh"}
          </ToolButton>
          <ToolButton onClick={() => void verifyCase()} disabled={!isDesktop() || verifying}
            title="Verify case evidence bytes and local provenance; independent chain anchoring requires a retained trusted head">
            {verifying ? "Verifying…" : "Verify Case"}
          </ToolButton>
          <ToolButton onClick={() => void exportReport()} disabled={!isDesktop() || exporting} title="Export a portable, path-free JSON report (review before sharing)">
            <Download size={12} /> {exporting ? "Exporting…" : "Export JSON"}
          </ToolButton>
          <span className="ml-auto font-mono text-3xs text-fg-muted">{filtered.length} of {findings.length} · {events.length}</span>
        </>
      }
      status={<StatusStrip items={[{ label: "case: " + (wb.caseId === "scratchpad" ? "temporary" : wb.caseId) }]} />}
    >
      {error ? <ErrorStrip>{error}</ErrorStrip> : null}
      {verification ? <div className="border-b border-line bg-raised px-3 py-2 font-mono text-2xs text-fg-dim" role="status">
        Verified {verification.verified_artifacts} artifacts, {verification.verified_bytes} bytes, and {verification.provenance.verified_events} local provenance events in case {verification.case_id}.
        <span className="ml-2 text-fg-muted">Keep the chain head outside the case for independent tamper detection.</span>
      </div> : null}
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <Pane title="Findings" className="min-w-0 flex-[2]">
          {filtered.length === 0 ? (
            <EmptyState title="No findings saved" detail="Use the Web Scanner with an authorized target, then return here to inspect persisted results." badge="case" />
          ) : (
            <table className="data-table">
              <thead><tr><th className="w-20">Severity</th><th>Title</th><th className="w-28">Source</th><th className="w-32">Recorded</th></tr></thead>
              <tbody>{filtered.map((f) => (
                <tr key={f.id} onClick={() => setSelected(f.id)} tabIndex={0} aria-selected={current?.id === f.id}
                   onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelected(f.id); } }}
                  className={"cursor-pointer " + (current?.id === f.id ? "selected" : "")}>
                  <td><Chip tone={severityTone(f.severity)}>{f.severity}</Chip></td>
                  <td className="text-fg">{f.title}</td>
                  <td className="text-fg-dim">{f.source}</td>
                  <td className="text-fg-muted">{new Date(f.created_ms).toLocaleString()}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Pane>
        <Pane title={current ? "Finding #" + current.id : "Detail"} className="w-[38%] shrink-0">
          {current ? (
            <div className="space-y-3 overflow-auto p-3">
              <div className="text-sm font-medium text-fg">{current.title}</div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-fg-dim">
                <Chip tone={severityTone(current.severity)}>{current.severity}</Chip>
                <span>{current.source}</span>
                <span>{new Date(current.created_ms).toLocaleString()}</span>
              </div>
              {current.artifact_id ? <div className="break-all font-mono text-xs text-orange">artifact: {current.artifact_id}</div> : null}
              <pre className="whitespace-pre-wrap break-words border-t border-line pt-3 font-mono text-xs text-fg-dim">{current.details}</pre>
              {events.filter((e) => e.artifact_id && e.artifact_id === current.artifact_id).slice(0, 15).map((entry) => (
                <div key={entry.id} className="border-t border-line pt-2 font-mono text-3xs text-fg-dim">
                  {entry.source} · {entry.action} · {entry.source_description}
                </div>
              ))}
            </div>
          ) : <div className="p-3 text-xs text-fg-muted">Select a finding.</div>}
        </Pane>
      </div>
    </WorkspaceShell>
  );
}

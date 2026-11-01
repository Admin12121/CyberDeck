"use client";
/** Scan view: real multithreaded TCP connect scanning via the Rust core (§5.3). */
import { useCallback, useEffect, useRef, useState } from "react";
import { Play, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import {
  isDesktop,
  netscanExport,
  netscanResults,
  netscanStart,
  netscanStatus,
  netscanStop,
  type ScanEntryWire,
  type ScanProgressWire,
  type NetscanStatusWire,
} from "@lib/ipc";
import { useWorkbench, useWorkbenchCase } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";

const PORT_PRESETS = [
  { value: "top25", label: "Top 25 ports" },
  { value: "top100", label: "Top 100 ports" },
  { value: "1-1024", label: "Well known (1-1024)" },
];

export function ScanView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const { caseSession } = useWorkbenchCase();
  const revision = caseSession.phase === "ready" && caseSession.caseId === wb.caseId
    ? caseSession.revision : null;
  const identity = wb.caseId + ":" + String(revision);
  const [retainedRevision, setRetainedRevision] = useWorkspaceDraft<number | null>(
    wb.caseId, "network", "scan-session-revision", null,
  );
  const [target, setTarget] = useWorkspaceDraft(wb.caseId, "network", "scan-target", "127.0.0.1");
  const [notesWidth, setNotesWidth] = useState(320);
  const [ports, setPorts] = useWorkspaceDraft(wb.caseId, "network", "scan-ports", "top25");
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ScanProgressWire | null>(null);
  const [results, setResults] = useState<ScanEntryWire[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<NetscanStatusWire>({ running: false, results: 0, saved_findings: 0, save_error: null });
  // Native status/results now enforce the selected case generation on every read.
  const activeCase = useRef(identity);
  activeCase.current = identity;
  const scanCase = useRef<string | null>(
    revision !== null && retainedRevision === revision ? wb.caseId : null,
  );
  scanCase.current = revision !== null && retainedRevision === revision ? wb.caseId : null;
  const scanTicket = useRef(0);
  const pollTicket = useRef(0);

  useEffect(() => {
    scanTicket.current += 1;
    pollTicket.current += 1;
    setResults([]);
    setProgress(null);
    setError(null);
    setRunning(false);
  }, [identity]);

  const poll = useCallback(async () => {
    const caseId = wb.caseId;
    const key = identity;
    const ticket = ++pollTicket.current;
    const isCurrent = () => activeCase.current === key && ticket === pollTicket.current;
    try {
      const currentStatus = await netscanStatus();
      if (!isCurrent()) return;
      setStatus(currentStatus);
      // The backend independently gates these results by selected case revision.
      const currentResults = await netscanResults();
      if (isCurrent()) setResults(currentResults);
    } catch (cause) {
      if (isCurrent()) setError("Scanner status unavailable: " + String(cause));
    }
  }, [identity]);

  useEffect(() => {
    if (!desktop) return;
    void poll();
    const timer = setInterval(() => void poll(), 900);
    return () => clearInterval(timer);
  }, [poll, desktop]);

  const start = async () => {
    if (running || status.running || revision === null) return;
    const caseId = wb.caseId;
    const key = identity;
    const ticket = ++scanTicket.current;
    pollTicket.current += 1;
    scanCase.current = caseId;
    const isCurrent = () => activeCase.current === key && scanTicket.current === ticket;
    setRunning(true);
    setError(null);
    setResults([]);
    setProgress({ tried: 0, total: 0, percent: 0 });
    try {
      await netscanStart(target, ports, caseId, authorized, (p) => {
        if (isCurrent()) setProgress(p);
      });
      if (isCurrent()) setRetainedRevision(revision);
    } catch (err) {
      if (isCurrent()) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (isCurrent()) {
        setRunning(false);
        setProgress(null);
        void poll();
      }
    }
  };

  const stop = async () => {
    if (scanCase.current !== wb.caseId && !status.running) return;
    try {
      await netscanStop();
      void poll();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const openCount = results.filter((r) => r.state === "open").length;

  const exportResults = async (format: "json" | "csv") => {
    if (results.length === 0) return;
    const caseId = wb.caseId;
    setError(null);
    try {
      const path = await netscanExport(format);
      if (activeCase.current === identity) wb.logConsole(`scan exported for case ${caseId}: ${path}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled" && activeCase.current === identity) setError(message);
    }
  };
  const isPreset = PORT_PRESETS.some((p) => p.value === ports);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="cd-workspace-toolbar shrink-0 items-center gap-2  px-2">
        <span className="font-mono text-[10px] uppercase text-fg-muted">target</span>
        <TextInput value={target} onChange={setTarget} placeholder="host / CIDR / list" ariaLabel="Scan target" className="w-56" />
        <span className="font-mono text-[10px] uppercase text-fg-muted">ports</span>
        <Select
          value={isPreset ? ports : "custom"}
          onChange={setPorts}
          options={[
            ...PORT_PRESETS,
            ...(isPreset ? [] : [{ value: ports, label: ports || "custom" }]),
          ]}
          ariaLabel="Port selection"
          className="w-44"
        />
        {!isPreset ? (
          <TextInput value={ports} onChange={setPorts} placeholder="80,443,8000-8100" ariaLabel="Custom ports" className="w-40" />
        ) : null}
        {status.running || (running && scanCase.current === wb.caseId) ? (
          <ToolButton tone="danger" onClick={() => void stop()}>
            <Square size={11} /> Stop
          </ToolButton>
        ) : (
          <ToolButton
            tone="primary"
            onClick={() => void start()}
            disabled={!desktop || revision === null || !authorized || !target.trim() || status.running || running}
            title={revision === null ? "Select a saved native investigation case before scanning" : "Backend-selected case and native confirmation are required before TCP probes"}
          >
            <Play size={11} /> {running ? "scanning…" : "Run scan"}
          </ToolButton>
        )}
        <Chip tone={status.running || running ? "orange" : "muted"}>
          {running ? "running" : status.running ? "other session running" : "idle"}
        </Chip>
        {results.length > 0 ? (
          <>
            <ToolButton onClick={() => void exportResults("json")} title="Save results as JSON">JSON</ToolButton>
            <ToolButton onClick={() => void exportResults("csv")} title="Save results as CSV">CSV</ToolButton>
          </>
        ) : null}
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{openCount} open / {results.length} probed</span>
      </div>
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <div className="flex min-w-0 flex-1 flex-col gap-px bg-line">
          <Pane title="Authorization (§9.3)" className="shrink-0">
            <label className="flex cursor-pointer items-start gap-2 p-2 text-xs leading-relaxed text-fg-dim">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-0.5 accent-[var(--color-orange)]"
              />
              <span>
                I confirm the target is mine or I have explicit authorization to assess it. The backend verifies the selected saved case and asks for native confirmation before starting.
              </span>
            </label>
          </Pane>
          {progress ? (
            <div className="shrink-0 border-b border-line bg-panel px-2 py-1.5">
              <div className="mb-0.5 flex items-center justify-between font-mono text-[10px] text-fg-muted">
                <span>{progress.tried} / {progress.total} probes</span>
                <span>{progress.percent}%</span>
              </div>
              <div className="h-1.5 w-full border border-line bg-app">
                <div className="h-full bg-orange" style={{ width: `${progress.percent}%` }} />
              </div>
            </div>
          ) : null}
          <Pane title={`Results: ${openCount} open`} className="min-h-0 flex-1">
            {results.length === 0 ? (
              <EmptyState
                title={running ? "Scanning…" : "No results"}
                detail="TCP connect scan with observed banners. Select a saved case, acknowledge scope, confirm in the native dialog and run."
                badge="netscan"
              />
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="w-40">Host</th>
                    <th className="w-16">Port</th>
                    <th className="w-20">State</th>
                    <th className="w-28">Service</th>
                    <th>Banner</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={`${r.host}-${r.port}-${i}`}>
                      <td className="text-fg">{r.host}</td>
                      <td>{r.port}</td>
                      <td className={r.state === "open" ? "text-ok" : "text-fg-muted"}>{r.state}</td>
                      <td className="text-orange">{r.service}</td>
                      <td className="truncate text-fg-muted" title={r.banner}>{r.banner}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Pane>
        </div>
        <Resizer direction="horizontal" flip ariaLabel="Resize scan notes" value={notesWidth} onChange={setNotesWidth} min={220} max={500} />
        <Pane title="Notes" className="shrink-0" style={{ width: notesWidth }}>
          <div className="p-2 font-mono text-[10px] leading-relaxed text-fg-muted">
            native TCP connect scanner: CIDR/host targets, port presets or ranges, banner grab on
            open ports, all cores, live progress. nmap (NPSL) stays license-gated; this engine is
            our own code.
          </div>
          <div className="border-t border-line px-2 py-1.5 font-mono text-[10px] text-fg-muted">
            {scanCase.current === wb.caseId
              ? `status: ${status.running ? "scan running" : "idle"} · ${status.results} stored results · ${status.saved_findings} case findings`
              : "Native scan status is global; results and findings withheld until a scan is started in this case"}
          </div>
          {status.save_error ? <div className="border-t border-line p-2 text-xs text-err">Case save failed: {status.save_error}</div> : null}
          <div className="border-t border-line p-2">
            <span className="text-fg-muted">Live scan status appears above; completed scans are listed below.</span>
          </div>
          <div className="border-t border-line p-2 text-[10px] text-fg-muted">
            Scan results, findings and Stop are bound to the backend-selected case generation; switching cases revokes stale read access.
          </div>
        </Pane>
      </div>
    </div>
  );
}

"use client";
/** Scan view: real multithreaded TCP connect scanning via the Rust core (§5.3). */
import { useCallback, useEffect, useState } from "react";
import { Play, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Select, TextInput, ToolButton } from "@ds/panes";
import {
  isDesktop,
  netscanExport,
  netscanHistory,
  netscanResults,
  netscanStart,
  netscanStatus,
  netscanStop,
  type ScanEntryWire,
  type ScanHistoryItemWire,
  type ScanProgressWire,
} from "@lib/ipc";
import { useWorkbench } from "@state/workbench";

const PORT_PRESETS = [
  { value: "top25", label: "Top 25 ports" },
  { value: "top100", label: "Top 100 ports" },
  { value: "1-1024", label: "Well known (1-1024)" },
];

export function ScanView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const [target, setTarget] = useState("127.0.0.1");
  const [ports, setPorts] = useState("top25");
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ScanProgressWire | null>(null);
  const [results, setResults] = useState<ScanEntryWire[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<{ running: boolean; results: number }>({ running: false, results: 0 });
  const [history, setHistory] = useState<ScanHistoryItemWire[]>([]);

  const poll = useCallback(() => {
    netscanStatus().then(setStatus).catch(() => undefined);
    netscanResults().then(setResults).catch(() => undefined);
    netscanHistory().then(setHistory).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!desktop) return;
    const timer = setInterval(poll, 900);
    return () => clearInterval(timer);
  }, [poll, desktop]);

  const start = async () => {
    setRunning(true);
    setError(null);
    setResults([]);
    setProgress({ tried: 0, total: 0, percent: 0 });
    try {
      await netscanStart(target, ports, authorized, (p) => setProgress(p));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
      setProgress(null);
      poll();
    }
  };

  const stop = async () => {
    try {
      await netscanStop();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const openCount = results.filter((r) => r.state === "open").length;

  const exportResults = async (format: "json" | "csv") => {
    setError(null);
    try {
      const path = await netscanExport(format);
      wb.logConsole(`scan exported: ${path}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setError(message);
    }
  };
  const isPreset = PORT_PRESETS.some((p) => p.value === ports);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
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
        {running ? (
          <ToolButton tone="danger" onClick={() => void stop()}>
            <Square size={11} /> Stop
          </ToolButton>
        ) : (
          <ToolButton
            tone="primary"
            onClick={() => void start()}
            disabled={!desktop || !authorized || !target.trim()}
            title={desktop ? "TCP connect scan across all cores" : "Scanning requires the desktop runtime"}
          >
            <Play size={11} /> {running ? "scanning…" : "Run scan"}
          </ToolButton>
        )}
        <Chip tone={running ? "orange" : "muted"}>{running ? "running" : "idle"}</Chip>
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
                I confirm the target is mine or I have written authorization to scan it. Active
                scanning without authorization is illegal in most jurisdictions.
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
                detail="TCP connect scan with service banners. Acknowledge the authorization, set target and ports, run."
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
        <Pane title="Notes" className="w-80 shrink-0">
          <div className="p-2 font-mono text-[10px] leading-relaxed text-fg-muted">
            native TCP connect scanner: CIDR/host targets, port presets or ranges, banner grab on
            open ports, all cores, live progress. nmap (NPSL) stays license-gated; this engine is
            our own code.
          </div>
          <div className="border-t border-line px-2 py-1.5 font-mono text-[10px] text-fg-muted">
            status: {status.running ? "scan running" : "idle"} · {status.results} stored results
          </div>
          <div className="border-t border-line p-2">
            <ToolButton onClick={() => wb.runDemoJob()} title="Queue the shared pipeline demo job">Demo job</ToolButton>
          </div>
          <div className="border-t border-line p-2">
            <div className="mb-1 text-[10px] uppercase tracking-wider text-fg-muted">Scan history ({history.length})</div>
            {history.length === 0 ? (
              <div className="font-mono text-[10px] text-fg-muted">completed scans appear here</div>
            ) : (
              <div className="max-h-40 space-y-0.5 overflow-auto">
                {[...history].reverse().map((h) => (
                  <div key={h.id} className="font-mono text-[10px] text-fg-dim">
                    {h.targets} · {h.open_ports} open · {(h.duration_ms / 1000).toFixed(1)}s
                  </div>
                ))}
              </div>
            )}
          </div>
        </Pane>
      </div>
    </div>
  );
}

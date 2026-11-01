"use client";
import { useCallback, useEffect, useState } from "react";
import { Globe, Play, PlayCircle, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import {
  caseFindingsAdd,
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
import { buildSitesTree, filterCaptured, useTarget } from "../controller";
import { useWorkbench } from "@state/workbench";
import { useWebWorkflow } from "./WebWorkflow";

// ---------------------------------------------------------------- scanner ---

export function ScannerView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const { target, setTarget, normalized } = useWebWorkflow();
  const [findings, setFindings] = useState<WebFindingWire[]>([]);
  const [busy, setBusy] = useState(false);
  const [savedCount, setSavedCount] = useState(0);
  const [authorized, setAuthorized] = useState(false);
  useEffect(() => { setAuthorized(false); }, [normalized]);
  const [error, setError] = useState<string | null>(null);
  const [engines, setEngines] = useState<WebEngineStatusWire[]>([]);
  const [engineOut, setEngineOut] = useState<EngineScanResultWire | null>(null);
  const [engineBusy, setEngineBusy] = useState<string | null>(null);
  const [engineWidth, setEngineWidth] = useState(384);

  useEffect(() => {
    if (!desktop) return;
    webEnginesDetect().then(setEngines).catch(() => setEngines([]));
  }, [desktop]);

  const scan = async () => {
    setBusy(true);
    setError(null);
    setFindings([]);
    setSavedCount(0);
    const caseId = wb.caseId;
    try {
      const found = await wb.trackOperation("Web scan", () => webScan(normalized, authorized));
      setFindings(found);
      if (found.length > 0) {
        try {
          const saved = await caseFindingsAdd(caseId, "web.native", found.slice(0, 128).map((f) => ({
            title: f.title.slice(0, 200),
            severity: ["info", "low", "medium", "high", "critical"].includes(f.severity)
              ? f.severity as "info" | "low" | "medium" | "high" | "critical" : "info",
            details: `Target: ${normalized}\n${f.detail}\nEvidence: ${f.evidence}`.slice(0, 8192),
          })));
          setSavedCount(saved);
        } catch (error) { setError(`Scan completed, but findings were not saved: ${String(error)}`); }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const runEngine = async (tool: string) => {
    setEngineBusy(tool);
    setEngineOut(null);
    try {
      setEngineOut(await wb.trackOperation(`Engine: ${tool}`, () => engineScan(tool, normalized, authorized)));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setEngineBusy(null);
    }
  };

  const severityTone = (s: string) => (s === "high" ? "err" : s === "medium" ? "orange" : "muted");

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="cd-workspace-toolbar shrink-0 items-center gap-2  px-2">
        <span className="font-mono text-[10px] uppercase text-fg-muted">target</span>
        <TextInput value={target} onChange={setTarget} placeholder="http://host" ariaLabel="Scan target" className="w-72" />
        <ToolButton tone="primary" onClick={() => void scan()} disabled={busy || !desktop || !normalized || !authorized} title={desktop ? "Native review: paths, headers, banners" : "Scanning requires the desktop runtime"}>
          <Play size={11} /> {busy ? "scanning…" : "Native scan"}
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{findings.length} findings · {savedCount} saved to case</span>
      </div>
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
      <label className="flex items-center gap-2 border-b border-line bg-panel px-3 py-2 text-xs text-fg-dim">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="accent-[var(--color-orange)]" />
        I confirm that I own this target or have written authorization for active assessment.
      </label>
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <Pane title="Findings" className="min-w-0 flex-1">
          {findings.length === 0 ? (
            <EmptyState title={busy ? "Scanning…" : "No findings yet"} detail="Set a target and run the native scan: reachable paths, security headers, banner disclosure." badge="scanner" />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-20">Severity</th>
                  <th>Finding</th>
                  <th>Detail</th>
                  <th className="w-40">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => (
                  <tr key={i}>
                    <td><Chip tone={severityTone(f.severity)}>{f.severity}</Chip></td>
                    <td className="text-fg">{f.title}</td>
                    <td className="text-fg-dim">{f.detail}</td>
                    <td className="truncate text-fg-muted">{f.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Pane>
        <Resizer direction="horizontal" flip ariaLabel="Resize engine bay" value={engineWidth} onChange={setEngineWidth} min={280} max={560} />
        <div className="flex shrink-0 flex-col gap-px bg-line" style={{ width: engineWidth }}>
          <Pane title="Engine bay (GPL sidecars, user-approved)">
            <div className="space-y-1 p-2">
              {engines.map((engine) => (
                <div key={engine.id} className="flex items-center gap-2 border border-line bg-app px-2 py-1">
                  <span className="flex-1 truncate font-mono text-[11px]">
                    {engine.label} <span className="text-fg-muted">{engine.available ? engine.version : "not detected"}</span>
                  </span>
                  <Chip tone={engine.available ? "ok" : "muted"}>{engine.license.split("-")[0]}</Chip>
                  <ToolButton onClick={() => void runEngine(engine.id)} disabled={!engine.available || !normalized || !authorized || engineBusy !== null} title={engine.available ? `Run ${engine.label} against the target` : "Not on PATH; bundled sidecars arrive with the installer"}>
                    {engineBusy === engine.id ? "…" : <Play size={11} />}
                  </ToolButton>
                </div>
              ))}
              {!desktop ? <div className="font-mono text-[10px] text-fg-muted">engine detection runs in the desktop runtime</div> : null}
              {engineOut ? (
                <div className="border border-line bg-app p-2">
                  <div className="font-mono text-[10px] text-fg-muted">{engineOut.tool} · {engineOut.duration_ms} ms</div>
                  <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px] text-fg-dim">{engineOut.raw}</pre>
                </div>
              ) : null}
            </div>
          </Pane>
        </div>
      </div>
    </div>
  );
}


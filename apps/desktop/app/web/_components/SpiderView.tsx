"use client";
import { useEffect, useRef, useState } from "react";
import { Globe, Play, PlayCircle, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Select, TextInput, ToolButton } from "@ds/panes";
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
import { useWorkbench, useWorkbenchCase } from "@state/workbench";

// ----------------------------------------------------------------- spider ---

export function SpiderView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const { caseId } = useWorkbenchCase();
  const caseRef = useRef(caseId);
  caseRef.current = caseId;
  const crawlRevision = useRef(0);
  useEffect(() => {
    crawlRevision.current += 1;
    setLinks([]);
    setBusy(false);
    setError(null);
  }, [caseId]);
  const { target, setTarget, normalized, scanTarget, draftInRepeater } = useWebWorkflow();
  const [depth, setDepth] = useState("2");
  const [links, setLinks] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  useEffect(() => { setAuthorized(false); }, [normalized]);
  const [error, setError] = useState<string | null>(null);

  const crawl = async () => {
    if (busy || !normalized || !authorized) return;
    const revision = ++crawlRevision.current;
    const startingCase = caseId;
    const target = normalized;
    setBusy(true);
    setError(null);
    setLinks([]);
    try {
      const found = await wb.trackOperation("Web spider", () => spiderScan(target, Math.max(1, Math.min(4, Number.parseInt(depth, 10) || 2)), authorized));
      if (revision === crawlRevision.current && caseRef.current === startingCase) setLinks(found);
    } catch (err) {
      if (revision === crawlRevision.current && caseRef.current === startingCase) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (revision === crawlRevision.current) setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="cd-workspace-toolbar shrink-0 items-center gap-2  px-2">
        <span className="font-mono text-[10px] uppercase text-fg-muted">target</span>
        <TextInput value={target} onChange={setTarget} placeholder="http://127.0.0.1:3000" ariaLabel="Spider target" className="w-72" />
        <span className="font-mono text-[10px] uppercase text-fg-muted">depth</span>
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
        />
        <ToolButton tone="primary" onClick={() => void crawl()} disabled={busy || !desktop || !normalized || !authorized} title={desktop ? "Native scope-checked same-host crawl, private/loopback literal IP only" : "Spidering requires the desktop runtime"}>
          <Play size={11} /> {busy ? "crawling…" : "Start spider"}
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{links.length} urls</span>
      </div>
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
      <label className="flex items-center gap-2 border-b border-line bg-panel px-3 py-2 text-xs text-fg-dim">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="accent-[var(--color-orange)]" />
        I confirm I own this target or have written permission. The native backend also requires a selected case, literal private/loopback IP target, and one-request OS confirmation. DNS hostnames are not enabled until address pinning is verified.
      </label>
      <Pane title="Discovered URLs" className="min-h-0 flex-1">
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
    </div>
  );
}

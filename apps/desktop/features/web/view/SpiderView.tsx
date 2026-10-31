"use client";
import { useCallback, useEffect, useState } from "react";
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
import { buildSitesTree, filterCaptured, useTarget } from "../controller";

// ----------------------------------------------------------------- spider ---

export function SpiderView() {
  const desktop = isDesktop();
  const { target, setTarget, normalized } = useTarget();
  const [depth, setDepth] = useState("2");
  const [links, setLinks] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const crawl = async () => {
    setBusy(true);
    setError(null);
    setLinks([]);
    try {
      setLinks(await spiderScan(normalized, Math.max(1, Math.min(4, Number.parseInt(depth, 10) || 2)), authorized));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <span className="font-mono text-[10px] uppercase text-fg-muted">target</span>
        <TextInput value={target} onChange={setTarget} placeholder="http://host" ariaLabel="Spider target" className="w-72" />
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
        <ToolButton tone="primary" onClick={() => void crawl()} disabled={busy || !desktop || !normalized || !authorized} title={desktop ? "Same-host crawl, GET only" : "Spidering requires the desktop runtime"}>
          <Play size={11} /> {busy ? "crawling…" : "Start spider"}
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{links.length} urls</span>
      </div>
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
      <label className="flex items-center gap-2 border-b border-line bg-panel px-3 py-2 text-xs text-fg-dim">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} className="accent-[var(--color-orange)]" />
        I confirm that I own this target or have written authorization for active assessment.
      </label>
      <Pane title="Discovered URLs" className="min-h-0 flex-1">
        {links.length === 0 ? (
          <EmptyState title={busy ? "Crawling…" : "No URLs yet"} detail="Depth-limited same-host crawl; discovered links feed the scanner and repeater." badge="spider" />
        ) : (
          <table className="data-table">
            <tbody>
              {links.map((url) => (
                <tr key={url}>
                  <td className="text-fg-dim">{url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Pane>
    </div>
  );
}

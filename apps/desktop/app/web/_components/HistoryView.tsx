"use client";
import { useCallback, useEffect, useState } from "react";
import { Globe, Play, PlayCircle, Square } from "lucide-react";
import { Chip, EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import {
  engineScan,
  httpSend,
  isDesktop,
  proxyHistory,
  webCaptureConsentStatusV1,
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
import { useWorkbenchCase } from "@state/workbench";

// ---------------------------------------------------------------- history ---

export function HistoryView() {
  const desktop = isDesktop();
  const { caseId } = useWorkbenchCase();
  const [rows, setRows] = useState<CapturedRequestWire[]>([]);
  const [captureEnabled, setCaptureEnabled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [sitesWidth, setSitesWidth] = useState(256);
  const { draftInRepeater, scanTarget } = useWebWorkflow();

  useEffect(() => {
    let disposed = false;
    let inFlight = false;
    setRows([]);
    setCaptureEnabled(false);
    const refresh = async () => {
      if (!desktop || inFlight) return;
      inFlight = true;
      try {
        // The backend is authoritative. Do not display or retain old summary
        // rows after a case switch, consent expiry or explicit revocation.
        const consent = await webCaptureConsentStatusV1();
        if (disposed) return;
        setCaptureEnabled(consent.enabled);
        if (!consent.enabled) {
          setRows([]);
        } else {
          const summary = await proxyHistory();
          if (!disposed) setRows(summary);
        }
        if (!disposed) setError(null);
      } catch (cause) {
        if (!disposed) {
          setRows([]);
          setCaptureEnabled(false);
          setError(cause instanceof Error ? cause.message : String(cause));
        }
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 3000);
    return () => { disposed = true; clearInterval(timer); };
  }, [desktop, caseId]);

  const filtered = captureEnabled ? rows.filter((r) => {
    const q = query.trim().toLowerCase();
    return !q || r.method.toLowerCase().includes(q) || r.host.toLowerCase().includes(q) || r.path.toLowerCase().includes(q) || String(r.status) === q;
  }) : [];

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <Pane title={`Redacted proxy history: ${captureEnabled ? rows.length : 0} requests`} className="min-w-0 flex-1" bodyClassName="p-0"
        actions={<TextInput value={query} onChange={setQuery} placeholder="filter" ariaLabel="History filter" className="w-48" />}
      >
        <>
        {error ? <div role="alert" className="border-b border-err/50 p-2 text-xs text-err">{error}</div> : null}
        {!captureEnabled ? <div className="border-b border-line p-2 font-mono text-[10px] text-fg-muted">Case-bound capture consent is off. Start the proxy and authorize volatile capture in Proxy to inspect redacted summaries. Confidential bodies and headers remain restricted.</div> : null}
        <table className="data-table">
          <thead>
            <tr>
              <th className="w-8">#</th>
              <th className="w-14">Method</th>
              <th className="w-40">Host</th>
              <th>Path</th>
              <th className="w-14">Status</th>
              <th className="w-20">Size</th>
              <th className="w-44">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.id}>
                <td className="text-fg-muted">{r.id}</td>
                <td className="text-fg-dim">{r.method}</td>
                <td>{r.host}</td>
                <td className="text-fg-dim">{r.path}</td>
                <td className={r.status >= 400 ? "text-err" : "text-ok"}>{r.status}</td>
                <td>{r.size}</td>
                <td className="whitespace-nowrap">
                  <ToolButton disabled={r.method.toUpperCase() !== "GET"} title={r.method.toUpperCase() === "GET" ? "Draft only: reconstructed from summary. Verify scheme and headers before sending" : "Original request bytes are not stored, so non-GET replay is unsafe"} onClick={() => draftInRepeater(makeGetDraft(`http://${r.host}${r.path}`), true)}>Draft</ToolButton>
                  <ToolButton onClick={() => scanTarget(`http://${r.host}${r.path}`)} title="Select HTTP URL for scanner; verify protocol and scope">Scan</ToolButton>
                </td>
              </tr>
            ))}
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="text-center text-fg-muted">no traffic captured yet; start the proxy and browse through it</td></tr>
            ) : null}
          </tbody>
        </table>
        </>
      </Pane>
      <Resizer direction="horizontal" flip ariaLabel="Resize sites tree" value={sitesWidth} onChange={setSitesWidth} min={192} max={440} />
      <Pane title="Sites" className="shrink-0" style={{ width: sitesWidth }}>
        <SitesTree rows={captureEnabled ? rows : []} />
      </Pane>
    </div>
  );
}

function SitesTree({ rows }: { rows: CapturedRequestWire[] }) {
  const hosts = new Map<string, Set<string>>();
  for (const r of rows) {
    if (!hosts.has(r.host)) hosts.set(r.host, new Set());
    hosts.get(r.host)!.add(r.path.split("?")[0]);
  }
  if (hosts.size === 0) {
    return <EmptyState title="No sites yet" detail="the sites tree builds from captured traffic" />;
  }
  return (
    <div className="p-1">
      {[...hosts.entries()].map(([host, paths]) => (
        <div key={host} className="mb-1">
          <div className="flex items-center gap-1 px-1 py-0.5 font-mono text-[11px] text-fg">
            <Globe size={11} className="text-fg-dim" /> {host}
          </div>
          {[...paths].sort().map((path) => (
            <div key={path} className="truncate pl-5 font-mono text-[10px] text-fg-dim">{path}</div>
          ))}
        </div>
      ))}
    </div>
  );
}


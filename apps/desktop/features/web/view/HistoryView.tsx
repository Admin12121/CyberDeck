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

// ---------------------------------------------------------------- history ---

export function HistoryView() {
  const desktop = isDesktop();
  const [rows, setRows] = useState<CapturedRequestWire[]>([]);
  const [query, setQuery] = useState("");

  const refresh = useCallback(() => {
    if (!desktop) return;
    proxyHistory().then(setRows).catch(() => undefined);
  }, [desktop]);
  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, [refresh]);

  const filtered = rows.filter((r) => {
    const q = query.trim().toLowerCase();
    return !q || r.method.toLowerCase().includes(q) || r.host.toLowerCase().includes(q) || r.path.toLowerCase().includes(q) || String(r.status) === q;
  });

  return (
    <div className="flex h-full min-h-0">
      <Pane title={`HTTP history: ${rows.length} captured`} className="min-w-0 flex-1" bodyClassName="p-0"
        actions={<TextInput value={query} onChange={setQuery} placeholder="filter" ariaLabel="History filter" className="w-48" />}
      >
        <table className="data-table">
          <thead>
            <tr>
              <th className="w-8">#</th>
              <th className="w-14">Method</th>
              <th className="w-40">Host</th>
              <th>Path</th>
              <th className="w-14">Status</th>
              <th className="w-20">Size</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.id}>
                <td className="text-fg-muted">{r.id}</td>
                <td className="text-blue">{r.method}</td>
                <td>{r.host}</td>
                <td className="text-fg-dim">{r.path}</td>
                <td className={r.status >= 400 ? "text-err" : "text-ok"}>{r.status}</td>
                <td>{r.size}</td>
              </tr>
            ))}
            {filtered.length === 0 ? (
              <tr><td colSpan={6} className="text-center text-fg-muted">no traffic captured yet; start the proxy and browse through it</td></tr>
            ) : null}
          </tbody>
        </table>
      </Pane>
      <Pane title="Sites" className="w-64 shrink-0">
        <SitesTree rows={rows} />
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
            <Globe size={11} className="text-blue" /> {host}
          </div>
          {[...paths].sort().map((path) => (
            <div key={path} className="truncate pl-5 font-mono text-[10px] text-fg-dim">{path}</div>
          ))}
        </div>
      ))}
    </div>
  );
}


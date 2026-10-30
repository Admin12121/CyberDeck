"use client";
/**
 * Web feature view layer.
 * Burp/ZAP-style workflow: Proxy, History, Repeater, Scanner tabs with site
 * tree and request/response editors (Master Plan §5.2). Live interception and
 * the bundled scan engine arrive arc 4; the layout and editors land now so the
 * workflow is proven early against the shell.
 */
import { useState } from "react";
import { Chip, EmptyState, Pane, TextInput, ToolButton } from "@ds/panes";
import type { ToolId } from "@features/registry";
import { filterHistory } from "../controller";
import { methodTone, statusTone, SAMPLE_HISTORY, SAMPLE_REQUEST, SAMPLE_RESPONSE, SAMPLE_SITES } from "../model";

export function WebWorkspace({ tool }: { tool: ToolId }) {
  if (tool === "web.repeater") return <RepeaterView />;
  if (tool === "web.scanner") return <ScannerView />;
  // proxy and history share the history-centric layout until the listener lands
  return <ProxyHistoryView mode={tool === "web.proxy" ? "proxy" : "history"} />;
}

type WebTab = "proxy" | "history" | "repeater" | "scanner";

function SiteTree() {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const toggle = (path: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });

  const renderNode = (
    node: { name: string; children?: { name: string; children?: unknown[] }[] },
    depth: number,
    pathKey: string,
  ): React.ReactNode[] => {
    const lines: React.ReactNode[] = [];
    const isCollapsed = collapsed.has(pathKey);
    const key = pathKey;
    lines.push(
      <button
        key={key}
        type="button"
        onClick={() => node.children && toggle(pathKey)}
        className="block w-full truncate text-left font-mono text-[11px] text-fg-dim hover:text-fg"
        style={{ paddingLeft: depth * 12 }}
      >
        {node.children && node.name.includes("/") ? (isCollapsed ? "▸ " : "▾ ") : ""}
        {node.name}
      </button>,
    );
    if (node.children && !isCollapsed) {
      for (const child of node.children) {
        lines.push(...renderNode(child as never, depth + 1, `${key}/${child.name}`));
      }
    }
    return lines;
  };

  return <div className="p-1">{renderNode(SAMPLE_SITES as never, 0, SAMPLE_SITES.name)}</div>;
}

function ProxyHistoryView({ mode }: { mode: "proxy" | "history" }) {
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState(SAMPLE_HISTORY[2].id);
  const rows = filterHistory(SAMPLE_HISTORY, query);
  const selected = rows.find((r) => r.id === selectedId) ?? rows[0];

  return (
    <div className="flex h-full min-h-0">
      <Pane title="Sites / scope" className="w-56 shrink-0">
        <SiteTree />
      </Pane>
      <div className="flex min-w-0 flex-1 flex-col gap-px bg-line">
        <Pane
          title={mode === "proxy" ? "Intercept: listener offline (arc 4)" : "HTTP history"}
          className="min-h-0 flex-1"
          actions={
            mode === "proxy" ? (
              <>
                <Chip tone="muted">proxy off</Chip>
                <ToolButton disabled title="Local loopback listener, arc 4">Start proxy</ToolButton>
              </>
            ) : (
              <TextInput value={query} onChange={setQuery} placeholder="filter: method, host, path, status" ariaLabel="History filter" className="w-56" />
            )
          }
        >
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-8">#</th>
                <th className="w-14">Method</th>
                <th className="w-36">Host</th>
                <th>Path</th>
                <th className="w-14">Status</th>
                <th className="w-16">Length</th>
                <th className="w-16">Time</th>
                <th className="w-40">Notes</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} onClick={() => setSelectedId(row.id)} className={`cursor-pointer ${row.id === selected?.id ? "selected" : ""}`}>
                  <td className="text-fg-muted">{row.id}</td>
                  <td className={methodTone(row.method)}>{row.method}</td>
                  <td>{row.host}</td>
                  <td className="text-fg">{row.path}</td>
                  <td className={statusTone(row.status)}>{row.status}</td>
                  <td>{row.length}</td>
                  <td>{row.timeMs} ms</td>
                  <td className="text-fg-muted">{row.note ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Pane>
        <div className="flex min-h-0 flex-1 gap-px">
          <Pane title={selected ? `Request: #${selected.id} ${selected.method} ${selected.path}` : "Request"} className="min-w-0 flex-1">
            <pre className="whitespace-pre-wrap break-all p-2 font-mono text-[11px] leading-relaxed text-fg-dim">{SAMPLE_REQUEST}</pre>
          </Pane>
          <Pane title="Response" className="min-w-0 flex-1">
            <pre className="whitespace-pre-wrap break-all p-2 font-mono text-[11px] leading-relaxed text-fg-dim">{SAMPLE_RESPONSE}</pre>
          </Pane>
        </div>
      </div>
    </div>
  );
}

function RepeaterView() {
  const [request, setRequest] = useState(SAMPLE_REQUEST);
  const [response, setResponse] = useState<string | null>(null);
  const [tabName, setTabName] = useState("R1");

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <Chip tone="blue">{tabName}</Chip>
        <ToolButton onClick={() => setTabName(tabName === "R1" ? "R2" : "R1")} title="Multiple replay tabs, state per tab (§3.5)">+ Tab</ToolButton>
        <ToolButton
          tone="primary"
          onClick={() => setResponse(SAMPLE_RESPONSE.replace("200 OK", "200 OK (replayed)"))}
          title="Replay through the local engine; arc 4 sends this through the proxy session"
        >
          Send
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">redirects: follow · engine: arc 4</span>
      </div>
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <Pane title="Request editor" className="min-w-0 flex-1" bodyClassName="p-0">
          <textarea
            value={request}
            onChange={(e) => setRequest(e.target.value)}
            spellCheck={false}
            aria-label="Request editor"
            className="h-full w-full resize-none bg-app p-2 font-mono text-[11px] leading-relaxed text-fg focus:outline-none"
          />
        </Pane>
        <Pane
          title="Response"
          className="min-w-0 flex-1"
          actions={response ? <ToolButton onClick={() => void navigator.clipboard?.writeText(response)}>Copy</ToolButton> : undefined}
        >
          {response ? (
            <pre className="whitespace-pre-wrap break-all p-2 font-mono text-[11px] leading-relaxed text-fg-dim">{response}</pre>
          ) : (
            <EmptyState title="No response" detail="Edit the request and press Send. Live replay through the proxy session arrives arc 4." badge="repeater" />
          )}
        </Pane>
      </div>
    </div>
  );
}

function ScannerView() {
  return (
    <div className="flex h-full min-h-0">
      <Pane title="Scan queue" className="w-64 shrink-0">
        <EmptyState title="No active scan" detail="Crawl and active scan run on the bundled engine (arc 4). Queue, cancellation and findings provenance ship with it." badge="scanner" />
      </Pane>
      <Pane title="Findings (evidence-backed)" className="min-w-0 flex-1">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding</th>
              <th>Endpoint</th>
              <th>Confidence</th>
              <th>Evidence</th>
              <th>Engine</th>
            </tr>
          </thead>
          <tbody>
            <tr className="opacity-60">
              <td colSpan={6} className="text-center text-fg-muted">
                findings appear here with request IDs, validator and engine version (§5.2)
              </td>
            </tr>
          </tbody>
        </table>
      </Pane>
      <Pane title="Alerts" className="w-64 shrink-0">
        <EmptyState title="No alerts" badge="scanner" />
      </Pane>
    </div>
  );
}

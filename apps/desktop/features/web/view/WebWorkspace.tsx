"use client";
/**
 * Web feature view layer, modeled on the ZAP/Burp workflow the Master Plan
 * names (§5.2): Proxy, History, Repeater, Scanner, Spider, plus a Sites tree
 * and an engine bay for the approved GPLv2 tools (nikto, sqlmap, XSStrike).
 * Tabs sit in a top bar like the reference tools. All views stay mounted so
 * work survives switching. Real network operations run in the Rust core.
 */
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

export function WebWorkspace() {
  const [tab, setTab] = useState<"proxy" | "history" | "repeater" | "scanner" | "spider">("proxy");
  const show = (id: string) => (tab === id ? "h-full" : "hidden h-full");
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-1 border-b border-line bg-sidebar px-2">
        {(["proxy", "history", "repeater", "scanner", "spider"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`h-6 border px-3 font-mono text-[10px] uppercase tracking-wide ${
              tab === t ? "border-orange/50 text-orange" : "border-transparent text-fg-muted hover:text-fg"
            }`}
          >
            {t}
          </button>
        ))}
        <span className="ml-auto font-mono text-[10px] text-fg-muted">web studio · zap-model workflow</span>
      </div>
      <div className="min-h-0 flex-1">
        <div className={show("proxy")}><ProxyView /></div>
        <div className={show("history")}><HistoryView /></div>
        <div className={show("repeater")}><RepeaterView /></div>
        <div className={show("scanner")}><ScannerView /></div>
        <div className={show("spider")}><SpiderView /></div>
      </div>
    </div>
  );
}

function useTarget() {
  const [target, setTarget] = useState("");
  const normalized = target.trim().length > 0 && !target.trim().startsWith("http") ? `http://${target.trim()}` : target.trim();
  return { target, setTarget, normalized };
}

// ------------------------------------------------------------------ proxy ---

function ProxyView() {
  const desktop = isDesktop();
  const [status, setStatus] = useState<ProxyStatusWire>({ running: false, port: 8080, captured: 0 });
  const [port, setPort] = useState("8080");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    proxyStatus().then(setStatus).catch(() => undefined);
  }, []);
  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, [refresh]);

  const start = async () => {
    setError(null);
    try {
      setStatus(await proxyStart(Number.parseInt(port, 10) || 8080));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  const stop = async () => {
    setError(null);
    try {
      setStatus(await proxyStop());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col p-3">
      <div className="mx-auto max-w-2xl space-y-3">
        <div className="border border-line bg-panel">
          <div className="flex h-8 items-center justify-between border-b border-line bg-sidebar px-2">
            <span className="text-[10px] font-medium uppercase tracking-wider text-fg-muted">Local interception proxy</span>
            <Chip tone={status.running ? "ok" : "muted"}>{status.running ? `running on 127.0.0.1:${status.port}` : "stopped"}</Chip>
          </div>
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              Point your browser at 127.0.0.1:{status.port} and every plain-HTTP request is captured into
              History for replay and scanning. CONNECT (HTTPS) tunnels pass through unintercepted until the
              CA arc lands, and the status line says so.
            </p>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase text-fg-muted">port</span>
              <TextInput value={port} onChange={setPort} ariaLabel="Proxy port" className="w-24" />
              {status.running ? (
                <ToolButton tone="danger" onClick={() => void stop()}>
                  <Square size={11} /> Stop
                </ToolButton>
              ) : (
                <ToolButton tone="primary" onClick={() => void start()} disabled={!desktop} title={desktop ? "Bind 127.0.0.1 and start capturing" : "The proxy requires the desktop runtime"}>
                  <PlayCircle size={11} /> Start
                </ToolButton>
              )}
              <Chip>{status.captured} captured</Chip>
            </div>
            {error ? <div className="font-mono text-[10px] text-err">{error}</div> : null}
            {!desktop ? <div className="font-mono text-[10px] text-fg-muted">proxy control requires the desktop runtime</div> : null}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- history ---

function HistoryView() {
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

// ---------------------------------------------------------------- repeater ---

const SAMPLE_REQUEST = `GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: HackTool-Workbench/0.1\r\nAccept: */*\r\n\r\n`;

function RepeaterView() {
  const desktop = isDesktop();
  const [request, setRequest] = useState(SAMPLE_REQUEST);
  const [response, setResponse] = useState<HttpResponseWire | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showBodyOnly, setShowBodyOnly] = useState(false);

  const send = async () => {
    setBusy(true);
    setError(null);
    try {
      setResponse(await httpSend(request));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <ToolButton tone="primary" onClick={() => void send()} disabled={busy || !desktop} title={desktop ? "Send the raw request through the native HTTP engine" : "Sending requires the desktop runtime"}>
          <Play size={11} /> {busy ? "sending…" : "Send"}
        </ToolButton>
        <Chip tone={desktop ? "ok" : "muted"}>{desktop ? "live" : "desktop"}</Chip>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">
          {response ? `${response.status} · ${response.size} bytes · ${response.duration_ms} ms` : "edit the raw request and send"}
        </span>
      </div>
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <Pane title="Request" className="min-w-0 flex-1" bodyClassName="p-0">
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
          bodyClassName="p-0"
          actions={
            response ? (
              <div className="flex h-6 items-center gap-1">
                <button
                  type="button"
                  onClick={() => setShowBodyOnly((v) => !v)}
                  className={`flex h-6 items-center border px-1.5 font-mono text-[10px] uppercase ${showBodyOnly ? "border-orange/50 text-orange" : "border-line text-fg-muted"}`}
                >
                  body
                </button>
                <ToolButton onClick={() => void navigator.clipboard?.writeText(response.body)}>Copy</ToolButton>
              </div>
            ) : undefined
          }
        >
          {error ? (
            <div className="m-2 border border-err/50 p-2 font-mono text-[11px] text-err">{error}</div>
          ) : response ? (
            <div className="h-full overflow-auto p-2 font-mono text-[11px] leading-relaxed">
              {!showBodyOnly ? (
                <>
                  <div className="text-ok">HTTP {response.status} · {response.url}</div>
                  {response.headers.map(([name, value]) => (
                    <div key={name} className="text-fg-dim">{name}: {value}</div>
                  ))}
                  <div className="my-2 border-t border-line" />
                </>
              ) : null}
              <pre className="whitespace-pre-wrap break-all text-fg">{response.body}</pre>
              {response.body_truncated ? <div className="mt-2 text-fg-muted">body truncated for display; {response.size} bytes received</div> : null}
            </div>
          ) : (
            <EmptyState title="No response" detail="Send a request to see status, headers and body." badge="repeater" />
          )}
        </Pane>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- scanner ---

function ScannerView() {
  const desktop = isDesktop();
  const { target, setTarget, normalized } = useTarget();
  const [findings, setFindings] = useState<WebFindingWire[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [engines, setEngines] = useState<WebEngineStatusWire[]>([]);
  const [engineOut, setEngineOut] = useState<EngineScanResultWire | null>(null);
  const [engineBusy, setEngineBusy] = useState<string | null>(null);

  useEffect(() => {
    if (!desktop) return;
    webEnginesDetect().then(setEngines).catch(() => setEngines([]));
  }, [desktop]);

  const scan = async () => {
    setBusy(true);
    setError(null);
    setFindings([]);
    try {
      setFindings(await webScan(normalized));
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
      setEngineOut(await engineScan(tool, normalized));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setEngineBusy(null);
    }
  };

  const severityTone = (s: string) => (s === "high" ? "err" : s === "medium" ? "orange" : s === "low" ? "blue" : "muted");

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <span className="font-mono text-[10px] uppercase text-fg-muted">target</span>
        <TextInput value={target} onChange={setTarget} placeholder="http://host" ariaLabel="Scan target" className="w-72" />
        <ToolButton tone="primary" onClick={() => void scan()} disabled={busy || !desktop || !normalized} title={desktop ? "Native review: paths, headers, banners" : "Scanning requires the desktop runtime"}>
          <Play size={11} /> {busy ? "scanning…" : "Native scan"}
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{findings.length} findings</span>
      </div>
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
      <div className="flex min-h-0 flex-1">
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
        <div className="flex w-96 shrink-0 flex-col gap-px bg-line">
          <Pane title="Engine bay (GPL sidecars, user-approved)">
            <div className="space-y-1 p-2">
              {engines.map((engine) => (
                <div key={engine.id} className="flex items-center gap-2 border border-line bg-app px-2 py-1">
                  <span className="flex-1 truncate font-mono text-[11px]">
                    {engine.label} <span className="text-fg-muted">{engine.available ? engine.version : "not detected"}</span>
                  </span>
                  <Chip tone={engine.available ? "ok" : "muted"}>{engine.license.split("-")[0]}</Chip>
                  <ToolButton onClick={() => void runEngine(engine.id)} disabled={!engine.available || !normalized || engineBusy !== null} title={engine.available ? `Run ${engine.label} against the target` : "Not on PATH; bundled sidecars arrive with the installer"}>
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

// ----------------------------------------------------------------- spider ---

function SpiderView() {
  const desktop = isDesktop();
  const { target, setTarget, normalized } = useTarget();
  const [depth, setDepth] = useState("2");
  const [links, setLinks] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const crawl = async () => {
    setBusy(true);
    setError(null);
    setLinks([]);
    try {
      setLinks(await spiderScan(normalized, Math.max(1, Math.min(4, Number.parseInt(depth, 10) || 2))));
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
        <ToolButton tone="primary" onClick={() => void crawl()} disabled={busy || !desktop || !normalized} title={desktop ? "Same-host crawl, GET only" : "Spidering requires the desktop runtime"}>
          <Play size={11} /> {busy ? "crawling…" : "Start spider"}
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{links.length} urls</span>
      </div>
      {error ? <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{error}</div> : null}
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

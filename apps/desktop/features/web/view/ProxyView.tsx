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

// ------------------------------------------------------------------ proxy ---

export function ProxyView() {
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


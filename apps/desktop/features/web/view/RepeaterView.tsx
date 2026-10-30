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
const SAMPLE_REQUEST = `GET / HTTP/1.1
Host: example.com
User-Agent: HackTool-Workbench/0.1
Accept: */*

`;


// ---------------------------------------------------------------- repeater ---


export function RepeaterView() {
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


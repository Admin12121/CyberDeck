/** Repeater: multiple request tabs with response inspector, raw and hex views. */
import { useEffect, useRef, useState } from "react";
import { Copy, Play, X } from "lucide-react";
import { Chip, EmptyState, Pane, ToolButton } from "@ds/panes";
import { ErrorStrip, HexRows, WorkspaceShell } from "@ds/compact";
import { httpSend, isDesktop, type HttpResponseWire } from "@lib/ipc";
import { hexDump } from "@lib/hex";
import { useWebWorkflow } from "./WebWorkflow";
import { useCaseReady } from "@state/workbench";
import { CaseGate } from "@ds/case-gate";

interface RepeaterTab {
  name: string;
  request: string;
  response: HttpResponseWire | null;
  error: string | null;
}

const SAMPLE_REQUEST = `GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: CyberDeck-Workbench/0.1\r\nAccept: */*\r\n\r\n`;

// Decode the authoritative binary wire field, never re-encode displayed UTF-8.
function binaryResponseBytes(reply: HttpResponseWire): Uint8Array {
  try {
    // The Rust wire contains body_base64; older frontend IPC typings omit it.
    // Do not fabricate binary bytes from the lossy display-text field.
    const encoded = (reply as HttpResponseWire & { body_base64?: string }).body_base64;
    if (!encoded) return new Uint8Array();
    const decoded = atob(encoded);
    return Uint8Array.from(decoded, (symbol) => symbol.charCodeAt(0));
  } catch {
    return new Uint8Array();
  }
}

export function RepeaterView() {
  const desktop = isDesktop();
  const { repeaterHandoff } = useWebWorkflow();
  const { caseId, caseRevision, caseReady } = useCaseReady();
  const caseRef = useRef(caseId);
  caseRef.current = caseId;
  const inFlightRevision = useRef(0);
  const nextTabId = useRef(2);
  const lastHandoff = useRef(0);
  const lastCaseIdentity = useRef({ caseId, revision: caseRevision });
  const [tabs, setTabs] = useState<RepeaterTab[]>([{ name: "R1", request: SAMPLE_REQUEST, response: null, error: null }]);
  const [active, setActive] = useState(0);
  const [busy, setBusy] = useState(false);
  const [bodyMode, setBodyMode] = useState<"inspector" | "raw" | "hex">("inspector");

  // Repeater drafts may contain Authorization and Cookie headers. Never carry
  // requests, responses or in-flight jobs from one case revision to another.
  useEffect(() => {
    const changed = lastCaseIdentity.current.caseId !== caseId ||
      lastCaseIdentity.current.revision !== caseRevision;
    lastCaseIdentity.current = { caseId, revision: caseRevision };
    if (changed) {
      inFlightRevision.current += 1;
      lastHandoff.current = repeaterHandoff?.id ?? 0;
      setTabs([{ name: "R1", request: SAMPLE_REQUEST, response: null, error: null }]);
      setActive(0);
      nextTabId.current = 2;
      setBusy(false);
    }
  }, [caseId, caseRevision, repeaterHandoff?.id]);

  useEffect(() => {
    if (!repeaterHandoff || repeaterHandoff.id === lastHandoff.current) return;
    lastHandoff.current = repeaterHandoff.id;
    const name = `R${nextTabId.current++}`;
    setTabs((previous) => [...previous, { name, request: repeaterHandoff.request, response: null, error: repeaterHandoff.reconstructed ? "Draft reconstructed from metadata. Verify scheme, method, headers and body before sending." : null }]);
    setActive(tabs.length);
  }, [repeaterHandoff, tabs.length]);

  const current = tabs[active];
  const update = (patch: Partial<RepeaterTab>) =>
    setTabs((prev) => prev.map((t, i) => (i === active ? { ...t, ...patch } : t)));

  const send = async () => {
    if (busy || !current || !caseReady) return;
    const revision = ++inFlightRevision.current;
    const selectedCase = caseId;
    const name = current.name;
    const request = current.request;
    setBusy(true);
    setTabs((previous) => previous.map((tab) =>
      tab.name === name ? { ...tab, response: null, error: null } : tab));
    try {
      // The registered native wrapper enforces backend case authority, literal
      // private/loopback scope, and an explicit one-request OS approval dialog.
      const response = await httpSend(request);
      if (revision !== inFlightRevision.current || caseRef.current !== selectedCase) return;
      setTabs((previous) => previous.map((tab) =>
        tab.name === name && tab.request === request
          ? { ...tab, response, error: null } : tab));
    } catch (cause) {
      if (revision !== inFlightRevision.current || caseRef.current !== selectedCase) return;
      setTabs((previous) => previous.map((tab) =>
        tab.name === name && tab.request === request
          ? { ...tab, error: cause instanceof Error ? cause.message : String(cause) } : tab));
    } finally {
      if (revision === inFlightRevision.current) setBusy(false);
    }
  };

  const hexRows = current?.response
    ? hexDump(binaryResponseBytes(current.response).slice(0, 2048))
    : [];

  return (
    <WorkspaceShell
      contentClassName="flex flex-col"
      toolbar={
        <>
          {tabs.map((t, i) => (
            <div key={t.name} className={`flex h-6 items-center gap-1 border px-1 font-mono text-2xs uppercase ${i === active ? "border-line bg-selected text-fg" : "border-line text-fg-muted"}`}>
              <button type="button" aria-selected={i === active} onClick={() => setActive(i)}
                className="h-full px-1 hover:text-fg" title={`Open ${t.name}`}>{t.name}</button>
              {tabs.length > 1 ? (
                <button type="button" aria-label={`Close ${t.name}`} onClick={() => {
                  setTabs((prev) => prev.filter((_, j) => j !== i));
                  setActive((a) => (i < a ? a - 1 : Math.min(a, tabs.length - 2)));
                }} className="px-0.5 text-fg-muted hover:text-err">×</button>
              ) : null}
            </div>
          ))}
          <ToolButton
            onClick={() => {
              const name = `R${nextTabId.current++}`;
              setTabs((prev) => [...prev, { name, request: SAMPLE_REQUEST, response: null, error: null }]);
              setActive(tabs.length);
            }}
            title="New repeater tab"
          >
            +
          </ToolButton>
          <span className="mx-1 h-4 w-px bg-line" />
          <ToolButton tone="primary" onClick={() => void send()} disabled={busy || !desktop || !caseReady} title={desktop ? "Send the raw request through the native HTTP engine" : "Sending requires the desktop runtime"}>
            <Play size={11} /> {busy ? "sending…" : "Send"}
          </ToolButton>
          <span className="ml-auto font-mono text-3xs text-fg-muted" title="A native selected case, a private/loopback literal-IP target and per-request OS confirmation are required">
            {current.response ? `${current.response.status} · ${current.response.size} B · ${current.response.duration_ms} ms` : "Native approval · scoped private/loopback IP only"}
          </span>
        </>
      }
    >
      <CaseGate activity="Web request replay" />
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <Pane title={`Request: ${current.name}`} className="min-w-0 flex-1" bodyClassName="p-0">
          <textarea
            value={current.request}
            onChange={(e) => update({ request: e.target.value })}
            spellCheck={false}
            aria-label="Request editor"
            className="h-full w-full resize-none bg-app p-2 font-mono text-2xs leading-relaxed text-fg focus:outline-none"
          />
        </Pane>
        <Pane
          title="Response"
          className="min-w-0 flex-1"
          bodyClassName="p-0"
          actions={
            current.response ? (
              <div className="flex h-6 items-center gap-1">
                {(["inspector", "raw", "hex"] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setBodyMode(mode)}
                    className={`flex h-6 items-center border px-1.5 font-mono text-3xs uppercase ${bodyMode === mode ? "border-line bg-selected text-fg" : "border-line text-fg-muted"}`}
                  >
                    {mode === "hex" ? "Binary hex" : mode}
                  </button>
                ))}
                <ToolButton onClick={() => void navigator.clipboard?.writeText(current.response?.body ?? "")}>
                  <Copy size={11} />
                </ToolButton>
              </div>
            ) : undefined
          }
        >
          {current.error ? (
            <ErrorStrip>{current.error}</ErrorStrip>
          ) : current.response ? (
            bodyMode === "inspector" ? (
              <div className="h-full overflow-auto p-2 font-mono text-2xs leading-relaxed">
                <div className="text-ok">HTTP {current.response.status} · {current.response.url}</div>
                <div className="mt-1 border-t border-line" />
                {current.response.headers.map(([name, value]) => (
                  <div key={name} className="text-fg-dim">{name}: {value}</div>
                ))}
                <div className="my-2 border-t border-line" />
                <pre className="whitespace-pre-wrap break-all text-fg">{current.response.body}</pre>
                {current.response.body_truncated ? <div className="mt-2 text-fg-muted">body truncated for display</div> : null}
              </div>
            ) : bodyMode === "raw" ? (
              <div className="h-full overflow-auto p-2 font-mono text-2xs leading-relaxed">
                <div className="text-ok">HTTP {current.response.status}</div>
                {current.response.headers.map(([name, value]) => (
                  <div key={name} className="text-fg-dim">{name}: {value}</div>
                ))}
                <div className="my-2 border-t border-line" />
                <pre className="whitespace-pre-wrap break-all text-fg">{current.response.body}</pre>
              </div>
            ) : (
              <pre className="h-full overflow-auto p-2 font-mono text-2xs leading-relaxed text-fg-dim">
                <div className="mb-2 text-warn">Exact decoded response bytes from the bounded Base64 payload (first 2048 bytes).</div>
                <HexRows rows={hexRows} />
              </pre>
            )
          ) : (
            <EmptyState title="No response" detail="Send a request to see status, headers and body." badge="repeater" />
          )}
        </Pane>
      </div>
    </WorkspaceShell>
  );
}

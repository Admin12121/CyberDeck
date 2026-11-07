"use client";
import { useEffect, useRef, useState } from "react";
import { Globe } from "lucide-react";
import { EmptyState, Pane, Resizer, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import {
  isDesktop, proxyHistory, webCaptureConsentStatusV1,
  type CapturedRequestWire, type HttpResponseWire,
} from "@lib/ipc";
import { useCaseReady } from "@state/workbench";
import { useWebWorkflow } from "./WebWorkflow";
import { PassiveRulesPanel } from "./PassiveRulesPanel";
import { CaseGate } from "@ds/case-gate";
import {
  decodedBody, editableHistoryDraft, protectedHistoryAccess,
  type ProtectedHistoryDetail,
} from "./controller/history-access";

type InspectionMode = "original" | "forwarded" | "response";
function BinaryPreview({ data, truncated }: { data: string | null; truncated: boolean }) {
  const bytes = decodedBody(data);
  if (bytes === null) return <span className="text-fg-muted">Not retained</span>;
  let text: string | null = null;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { /* Binary, not text. */ }
  return (
    <div className="min-h-0 space-y-2">
      <div className="text-fg-muted">{bytes.length} bytes {truncated ? "· truncated" : ""}</div>
      {text !== null
        ? <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all text-fg">{text.slice(0, 16384)}</pre>
        : <pre className="max-h-48 overflow-auto text-fg-dim">{hexDump(bytes.slice(0, 1024)).map((line) =>
          <div key={line.offset}>{line.offset.toString(16).padStart(8, "0")}  {line.hex}  {line.ascii}</div>
        )}</pre>}
    </div>
  );
}

export function HistoryView() {
  const desktop = isDesktop();
  const { caseId, caseRevision: nativeRevision, caseReady } = useCaseReady();
  const { draftInRepeater } = useWebWorkflow();
  const [rows, setRows] = useState<CapturedRequestWire[]>([]);
  const [query, setQuery] = useState("");
  const [sideWidth, setSideWidth] = useState(424);
  const [captureGeneration, setCaptureGeneration] = useState<number | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<ProtectedHistoryDetail | null>(null);
  const [reply, setReply] = useState<(HttpResponseWire & { body_base64: string }) | null>(null);
  const [mode, setMode] = useState<InspectionMode>("original");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const identity = useRef({ caseId, nativeRevision, generation: captureGeneration, revision: 0 });
  identity.current.caseId = caseId;
  identity.current.nativeRevision = nativeRevision;
  identity.current.generation = captureGeneration;

  useEffect(() => {
    identity.current.revision++;
    setRows([]);
    setCaptureGeneration(null);
    setSelected(null);
    setDetail(null);
    setReply(null);
    setBusy(false);
    let disposed = false;
    let fetching = false;
    const refresh = async () => {
      if (disposed || !desktop || fetching) return;
      fetching = true;
      try {
        const authorization = await webCaptureConsentStatusV1();
        if (disposed) return;
        const generation = authorization.enabled ? authorization.generation : null;
        if (identity.current.generation !== generation || !generation) {
          identity.current.revision++;
          setDetail(null);
          setReply(null);
          setSelected(null);
          setBusy(false);
        }
        identity.current.generation = generation;
        setCaptureGeneration(generation);
        const next = generation ? await proxyHistory() : [];
        if (!disposed) {
          setRows(next);
          if (identity.current.generation !== generation) return;
          setError(null);
        }
      } catch (cause) {
        if (!disposed) {
          identity.current.revision++;
          identity.current.generation = null;
          setRows([]);
          setCaptureGeneration(null);
          setDetail(null);
          setReply(null);
          setError(String(cause));
        }
      } finally { fetching = false; }
    };
    void refresh();
    const poll = setInterval(() => void refresh(), 1000);
    return () => { disposed = true; clearInterval(poll); identity.current.revision++; };
  }, [caseId, nativeRevision, desktop]);

  // Revealed confidential bytes remain volatile and are dismissed automatically.
  useEffect(() => {
    if (!detail && !reply) return;
    const timeout = setTimeout(() => { setDetail(null); setReply(null); }, 30000);
    return () => clearTimeout(timeout);
  }, [detail, reply]);

  const act = async (id: number, action: "detail" | "replay", forwarded = false) => {
    if (!desktop || !captureGeneration || busy) return;
    const stamp = { ...identity.current };
    setSelected(id);
    setBusy(true);
    setError(null);
    if (action === "detail") { setDetail(null); setReply(null); setMode("original"); }
    try {
      const result = await protectedHistoryAccess(id, action, forwarded);
      const status = await webCaptureConsentStatusV1();
      if (identity.current.revision !== stamp.revision ||
          identity.current.caseId !== stamp.caseId ||
          identity.current.generation !== stamp.generation ||
          !status.enabled || status.generation !== stamp.generation) return;
      if (result.kind === "detail" && action === "detail") setDetail(result.data);
      else if (result.kind === "replay" && action === "replay") {
        setReply(result.data); setMode("response");
      } else setError("Unexpected protected-history response");
    } catch (cause) {
      if (identity.current.revision === stamp.revision) setError(String(cause));
    } finally {
      if (identity.current.revision === stamp.revision) setBusy(false);
    }
  };

  const filtered = rows.filter((r) => {
    const q = query.trim().toLowerCase();
    return !q || [r.method, r.host, r.path, String(r.status)].some((s) => s.toLowerCase().includes(q));
  });
  const draft = detail ? editableHistoryDraft(detail, mode === "forwarded") : null;
  const showDetail = detail !== null && captureGeneration !== null;
  const responseHeaders = reply?.headers ?? detail?.response_headers ?? [];
  const responseBase64 = reply?.body_base64 ?? detail?.response_body_base64 ?? null;

  return (
    <div className="flex h-full min-h-0 flex-col bg-line">
      <CaseGate activity="Private Web history" />
      <PassiveRulesPanel enabled={Boolean(desktop && captureGeneration)} caseId={caseId}
        revision={nativeRevision} generation={captureGeneration} />
      <div className="flex min-h-0 flex-1 gap-px">
      <Pane title={`HTTP history · ${rows.length}`} className="min-w-0 flex-1" bodyClassName="p-0"
        actions={<TextInput value={query} onChange={setQuery} placeholder="Filter requests" ariaLabel="History filter" className="w-40" />}>
        {error ? <div role="alert" className="border-b border-line px-2 py-1 text-xs text-err">{error}</div> : null}
        {!captureGeneration
          ? <EmptyState title="No active history" detail={caseReady
              ? "In Proxy, start the listener, open Advanced and authorize private History for this case. Configure an isolated browser to use the local proxy."
              : "First select or create a saved case, then authorize private History capture in Proxy."} />
          : <div className="h-full overflow-auto">
            <table className="data-table">
              <thead><tr><th>#</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Size</th><th /></tr></thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={r.id} className={selected === r.id ? "bg-selected" : ""}>
                    <td className="text-fg-muted">{r.id}</td><td>{r.method}</td>
                    <td>{r.host}</td><td className="text-fg-dim">{r.path}</td>
                    <td className={r.status >= 400 ? "text-err" : "text-ok"}>{r.status}</td>
                    <td>{r.size}</td>
                    <td><ToolButton disabled={busy} onClick={() => void act(r.id, "detail")}>
                      {busy && selected === r.id ? "Opening…" : "Inspect"}
                    </ToolButton></td>
                  </tr>
                ))}
                {filtered.length === 0 ? <tr><td colSpan={7} className="text-center text-fg-muted">No captured requests</td></tr> : null}
              </tbody>
            </table>
          </div>}
      </Pane>
      <Resizer direction="horizontal" flip ariaLabel="Resize history inspector" value={sideWidth}
        onChange={setSideWidth} min={290} max={680} />
      <Pane title={showDetail ? `Request #${detail.id}` : "Inspector"} className="shrink-0"
        style={{ width: sideWidth }} bodyClassName="p-0"
        actions={showDetail ? <ToolButton onClick={() => { setDetail(null); setReply(null); }}>Clear</ToolButton> : undefined}>
        {showDetail ? (
          <div className="flex h-full min-h-0 flex-col">
            <div className="flex flex-wrap gap-1 border-b border-line p-1">
              {(["original", "forwarded", "response"] as const).map((tab) =>
                <ToolButton key={tab} tone={mode === tab ? "primary" : "default"}
                  disabled={tab === "forwarded" && !detail.forwarded_decoded_message}
                  onClick={() => setMode(tab)}>{tab}</ToolButton>)}
            </div>
            <div className="flex flex-wrap gap-1 border-b border-line p-1">
              {mode !== "response" && <ToolButton disabled={busy || !draft}
                title={draft ? "Send this editable text request to Repeater; not original wire framing" : "Binary or truncated request: use protected replay"}
                onClick={() => { if (draft) draftInRepeater(draft, true); }}>To Repeater</ToolButton>}
              <ToolButton disabled={busy} onClick={() => void act(detail.id, "replay", mode === "forwarded")}>
                {busy ? "Authorizing…" : `Replay ${mode === "forwarded" ? "forwarded" : "original"}`}
              </ToolButton>
            </div>
            <div className="min-h-0 flex-1 overflow-auto p-2 font-mono text-[11px]">
              {mode === "original" ? <>
                <div className="break-all text-fg">{detail.url}</div>
                <pre className="my-2 whitespace-pre-wrap break-all text-fg-dim">{detail.request_head}</pre>
                <BinaryPreview data={detail.request_body_base64} truncated={detail.request_truncated} />
              </> : mode === "forwarded" ? <>
                <div className="break-all text-fg">{detail.forwarded_method} {detail.forwarded_url}</div>
                <pre className="my-2 whitespace-pre-wrap break-all text-fg-dim">{detail.forwarded_headers?.map(([k,v]) => `${k}: ${v}`).join("\n")}</pre>
                <BinaryPreview data={detail.forwarded_body_base64} truncated={detail.forwarded_truncated} />
              </> : <>
                <div className="text-fg">HTTP {reply?.status ?? detail.status}</div>
                <pre className="my-2 whitespace-pre-wrap break-all text-fg-dim">{responseHeaders.map(([k,v]) => `${k}: ${v}`).join("\n")}</pre>
                <BinaryPreview data={responseBase64} truncated={reply?.body_truncated ?? detail.response_truncated} />
              </>}
            </div>
          </div>
        ) : <div className="h-full overflow-auto">
          <EmptyState title="Select a request" detail="Inspecting or replaying captured bytes requires native authorization." />
          <div className="border-t border-line px-2 py-2 text-[10px] text-fg-muted">Sites</div>
          {[...new Set(rows.map((r) => r.host))].map((host) =>
            <div key={host} className="flex items-center gap-2 truncate px-2 py-1 font-mono text-[11px]">
              <Globe size={12} className="shrink-0" />{host}
            </div>)}
        </div>}
      </Pane>
      </div>
    </div>
  );
}

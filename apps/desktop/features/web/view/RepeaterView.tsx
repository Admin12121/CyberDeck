/** Repeater: multiple request tabs with response inspector, raw and hex views. */
import { useState } from "react";
import { Copy, Play, X } from "lucide-react";
import { Chip, EmptyState, Pane, ToolButton } from "@ds/panes";
import { httpSend, isDesktop, type HttpResponseWire } from "@lib/ipc";
import { hexDump } from "@lib/hex";

interface RepeaterTab {
  name: string;
  request: string;
  response: HttpResponseWire | null;
  error: string | null;
}

const SAMPLE_REQUEST = `GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: CyberDeck-Workbench/0.1\r\nAccept: */*\r\n\r\n`;

export function RepeaterView() {
  const desktop = isDesktop();
  const [tabs, setTabs] = useState<RepeaterTab[]>([{ name: "R1", request: SAMPLE_REQUEST, response: null, error: null }]);
  const [active, setActive] = useState(0);
  const [busy, setBusy] = useState(false);
  const [bodyMode, setBodyMode] = useState<"inspector" | "raw" | "hex">("inspector");

  const current = tabs[active];
  const update = (patch: Partial<RepeaterTab>) =>
    setTabs((prev) => prev.map((t, i) => (i === active ? { ...t, ...patch } : t)));

  const send = async () => {
    setBusy(true);
    update({ error: null });
    try {
      const response = await httpSend(current.request);
      update({ response });
    } catch (err) {
      update({ error: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  const hexRows = current.response
    ? hexDump(new TextEncoder().encode(current.response.body).slice(0, 2048))
    : [];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-1 border-b border-line bg-sidebar px-2">
        {tabs.map((t, i) => (
          <button
            key={t.name}
            type="button"
            onClick={() => setActive(i)}
            className={`flex h-6 items-center gap-1 border px-2 font-mono text-[10px] uppercase ${
              i === active ? "border-orange/50 text-orange" : "border-transparent text-fg-muted hover:text-fg"
            }`}
          >
            {t.name}
            {tabs.length > 1 ? (
              <span
                role="button"
                aria-label={`Close ${t.name}`}
                onClick={(e) => {
                  e.stopPropagation();
                  setTabs((prev) => prev.filter((_, j) => j !== i));
                  setActive((a) => (i < a ? a - 1 : Math.min(a, tabs.length - 2)));
                }}
                className="text-fg-muted hover:text-err"
              >
                ×
              </span>
            ) : null}
          </button>
        ))}
        <ToolButton
          onClick={() => {
            const name = `R${tabs.length + 1}`;
            setTabs((prev) => [...prev, { name, request: SAMPLE_REQUEST, response: null, error: null }]);
            setActive(tabs.length);
          }}
          title="New repeater tab"
        >
          +
        </ToolButton>
        <span className="mx-1 h-4 w-px bg-line" />
        <ToolButton tone="primary" onClick={() => void send()} disabled={busy || !desktop} title={desktop ? "Send the raw request through the native HTTP engine" : "Sending requires the desktop runtime"}>
          <Play size={11} /> {busy ? "sending…" : "Send"}
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">
          {current.response ? `${current.response.status} · ${current.response.size} B · ${current.response.duration_ms} ms` : ""}
        </span>
      </div>
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <Pane title={`Request: ${current.name}`} className="min-w-0 flex-1" bodyClassName="p-0">
          <textarea
            value={current.request}
            onChange={(e) => update({ request: e.target.value })}
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
            current.response ? (
              <div className="flex h-6 items-center gap-1">
                {(["inspector", "raw", "hex"] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setBodyMode(mode)}
                    className={`flex h-6 items-center border px-1.5 font-mono text-[10px] uppercase ${bodyMode === mode ? "border-orange/50 text-orange" : "border-line text-fg-muted"}`}
                  >
                    {mode}
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
            <div className="m-2 border border-err/50 p-2 font-mono text-[11px] text-err">{current.error}</div>
          ) : current.response ? (
            bodyMode === "inspector" ? (
              <div className="h-full overflow-auto p-2 font-mono text-[11px] leading-relaxed">
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
              <div className="h-full overflow-auto p-2 font-mono text-[11px] leading-relaxed">
                <div className="text-ok">HTTP {current.response.status}</div>
                {current.response.headers.map(([name, value]) => (
                  <div key={name} className="text-fg-dim">{name}: {value}</div>
                ))}
                <div className="my-2 border-t border-line" />
                <pre className="whitespace-pre-wrap break-all text-fg">{current.response.body}</pre>
              </div>
            ) : (
              <pre className="h-full overflow-auto p-2 font-mono text-[11px] leading-relaxed text-fg-dim">
                {hexRows.map((row) => (
                  <div key={row.offset}>
                    <span className="text-fg-muted">{row.offset.toString(16).padStart(8, "0")}</span>
                    {"  "}
                    {row.hex}
                    {"  "}
                    <span className="text-orange">{row.ascii}</span>
                  </div>
                ))}
              </pre>
            )
          ) : (
            <EmptyState title="No response" detail="Send a request to see status, headers and body." badge="repeater" />
          )}
        </Pane>
      </div>
    </div>
  );
}

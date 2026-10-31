/** Proxy view: listener control, intercept queue, match & replace. */
import { useCallback, useEffect, useState } from "react";
import { Copy, Download, PlayCircle, Square, X } from "lucide-react";
import { Chip, Pane, TextInput, ToolButton } from "@ds/panes";
import {
  isDesktop,
  proxyCaPem,
  proxyDrop,
  proxyForward,
  proxyHistory,
  proxyIntercept,
  proxyPending,
  proxySetRules,
  proxyStart,
  proxyStatus,
  proxyStop,
  type PendingRequestWire,
  type ProxyStatusWire,
} from "@lib/ipc";

export function ProxyView() {
  const desktop = isDesktop();
  const [status, setStatus] = useState<ProxyStatusWire>({ running: false, port: 8080, captured: 0 });
  const [port, setPort] = useState("8080");
  const [interceptOn, setInterceptOn] = useState(false);
  const [pending, setPending] = useState<PendingRequestWire[]>([]);
  const [rules, setRules] = useState<{ find: string; replace: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [caSaved, setCaSaved] = useState(false);
  const [caPem, setCaPem] = useState<string | null>(null);

  const refresh = useCallback(() => {
    proxyStatus().then(setStatus).catch(() => undefined);
    if (interceptOn) proxyPending().then(setPending).catch(() => undefined);
  }, [interceptOn]);

  useEffect(() => {
    const timer = setInterval(refresh, interceptOn ? 1200 : 3000);
    return () => clearInterval(timer);
  }, [refresh, interceptOn]);

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
  const toggleIntercept = async () => {
    setError(null);
    try {
      const on = await proxyIntercept(!interceptOn);
      setInterceptOn(on);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  const forward = async (id: number) => {
    try {
      await proxyForward(id);
      setPending(await proxyPending());
      proxyHistory().then(() => undefined).catch(() => undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  const drop = async (id: number) => {
    try {
      await proxyDrop(id);
      setPending(await proxyPending());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };
  const saveRules = (next: { find: string; replace: string }[]) => {
    setRules(next);
    void proxySetRules(next);
  };

  const fetchCa = async (): Promise<string | null> => {
    setError(null);
    try {
      const pem = await proxyCaPem();
      setCaPem(pem);
      return pem;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return null;
    }
  };

  const saveCa = async () => {
    const pem = caPem ?? (await fetchCa());
    if (!pem) return;
    try {
      const blob = new Blob([pem], { type: "application/x-x509-ca-cert" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "cyberdeck-root-ca.crt";
      a.click();
      URL.revokeObjectURL(url);
      setCaSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const copyCa = async () => {
    const pem = caPem ?? (await fetchCa());
    if (pem) void navigator.clipboard?.writeText(pem);
  };

  return (
    <div className="flex h-full min-h-0 flex-col items-center justify-center overflow-auto p-4">
      <div className="w-full max-w-3xl space-y-3">
        {/* CA + trust */}
        <div className="border border-line bg-panel">
          <div className="flex h-8 items-center justify-between border-b border-line bg-sidebar px-2">
            <span className="text-[10px] font-medium uppercase tracking-wider text-fg-muted">CA certificate & browser trust</span>
            <Chip tone={caSaved ? "ok" : "muted"}>{caSaved ? "downloaded" : "per install"}</Chip>
          </div>
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              One time per machine: download the CA, then install it into your browser or OS trust
              store (Windows: double-click → Install Certificate → Trusted Root Certification
              Authorities. Firefox: Settings → Certificates → Import). After that, HTTPS interception
              works without warnings.
            </p>
            <div className="flex items-center gap-2">
              <ToolButton tone="primary" onClick={() => void saveCa()} disabled={!desktop} title="Download cyberdeck-root-ca.crt">
                <Download size={11} /> {caSaved ? "Download again" : "Download CA cert"}
              </ToolButton>
              <ToolButton onClick={() => void copyCa()} disabled={!desktop} title="Copy the PEM to the clipboard">
                <Copy size={11} /> Copy PEM
              </ToolButton>
            </div>
          </div>
        </div>

        {/* listener */}
        <div className="border border-line bg-panel">
          <div className="flex h-8 items-center justify-between border-b border-line bg-sidebar px-2">
            <span className="text-[10px] font-medium uppercase tracking-wider text-fg-muted">Local interception proxy</span>
            <Chip tone={status.running ? "ok" : "muted"}>{status.running ? `running on 127.0.0.1:${status.port}` : "stopped"}</Chip>
          </div>
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              Point your browser at 127.0.0.1:{status.port}. Plain-HTTP requests land in History;
              with Intercept on they are held here for Forward or Drop. HTTPS tunnels pass through
              unintercepted until the CA arc.
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
              <ToolButton
                tone={interceptOn ? "danger" : "default"}
                onClick={() => void toggleIntercept()}
                disabled={!desktop || !status.running}
                title={desktop ? "Hold requests here until you forward or drop them" : "The proxy requires the desktop runtime"}
              >
                {interceptOn ? "Intercept: ON" : "Intercept: OFF"}
              </ToolButton>
            </div>
            <ToolButton onClick={() => void saveCa()} disabled={!desktop} title="Save the CA certificate to install in your browser/OS trust store">
              <Download size={11} /> {caSaved ? "CA saved" : "Save CA cert"}
            </ToolButton>
            {error ? <div className="font-mono text-[10px] text-err">{error}</div> : null}
            {!desktop ? <div className="font-mono text-[10px] text-fg-muted">proxy control requires the desktop runtime</div> : null}
          </div>
        </div>

        {/* intercept queue */}
        {interceptOn ? (
          <Pane title={`Intercept queue (${pending.length})`}>
            <div className="space-y-px p-1">
              {pending.length === 0 ? (
                <div className="p-2 font-mono text-[10px] text-fg-muted">waiting for requests through the proxy…</div>
              ) : (
                pending.map((p) => (
                  <div key={p.id} className="flex items-center gap-2 border border-line bg-app px-2 py-1">
                    <span className={`w-12 shrink-0 font-mono text-[10px] ${p.method === "GET" ? "text-blue" : "text-orange"}`}>{p.method}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-fg-dim" title={p.url}>
                      {p.host}{p.path}
                    </span>
                    <ToolButton tone="primary" onClick={() => void forward(p.id)}>Forward</ToolButton>
                    <ToolButton tone="danger" onClick={() => void drop(p.id)}>Drop</ToolButton>
                  </div>
                ))
              )}
            </div>
          </Pane>
        ) : null}

        {/* match and replace */}
        <Pane
          title={`Match & replace (${rules.length})`}
          actions={
            <ToolButton onClick={() => saveRules([...rules, { find: "", replace: "" }])} disabled={!desktop} title="Add a rule applied to proxied requests">
              + rule
            </ToolButton>
          }
        >
          <div className="space-y-1 p-2">
            {rules.length === 0 ? (
              <div className="font-mono text-[10px] text-fg-muted">
                rules rewrite path, headers and body of proxied requests before they are forwarded
              </div>
            ) : (
              rules.map((rule, i) => (
                <div key={i} className="flex items-center gap-1">
                  <TextInput
                    value={rule.find}
                    onChange={(v) => saveRules(rules.map((r, j) => (j === i ? { ...r, find: v } : r)))}
                    placeholder="find"
                    ariaLabel={`Match rule ${i + 1}`}
                    className="min-w-0 flex-1"
                  />
                  <span className="font-mono text-[10px] text-fg-muted">→</span>
                  <TextInput
                    value={rule.replace}
                    onChange={(v) => saveRules(rules.map((r, j) => (j === i ? { ...r, replace: v } : r)))}
                    placeholder="replace"
                    ariaLabel={`Replace rule ${i + 1}`}
                    className="min-w-0 flex-1"
                  />
                  <button type="button" aria-label="Remove rule" onClick={() => saveRules(rules.filter((_, j) => j !== i))} className="text-fg-muted hover:text-err">
                    <X size={12} />
                  </button>
                </div>
              ))
            )}
          </div>
        </Pane>

        <div className="pb-2 text-center font-mono text-[10px] text-fg-muted">
          websocket history and HTTPS interception arrive with the CA + WS relay arcs
        </div>
      </div>
    </div>
  );
}

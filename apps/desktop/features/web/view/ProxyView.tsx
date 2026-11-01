/** Proxy view: listener control, intercept queue, match & replace. */
import { downloadContent } from "@lib/download";
import { useEffect, useRef, useState } from "react";
import { Copy, Download, PlayCircle, Square, X } from "lucide-react";
import { Chip, Pane, TextInput, ToolButton } from "@ds/panes";
import {
  isDesktop,
  proxyCaPem,
  proxyDrop,
  proxyForward,
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
  const [busy, setBusy] = useState(false);
  const [pendingBusy, setPendingBusy] = useState<number | null>(null);
  const [rulesSaving, setRulesSaving] = useState(false);
  const [rulesApplied, setRulesApplied] = useState(false);
  const ruleQueue = useRef<Promise<void>>(Promise.resolve());
  const ruleRevision = useRef(0);

  useEffect(() => {
    if (!desktop) return;
    let disposed = false;
    let inFlight = false;
    const refresh = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const current = await proxyStatus();
        if (disposed) return;
        setStatus(current);
        if (interceptOn && current.running) {
          const waiting = await proxyPending();
          if (!disposed) setPending(waiting);
        } else {
          setPending([]);
        }
      } catch (cause) {
        if (!disposed) setError("Proxy status unavailable: " + String(cause));
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), interceptOn ? 1200 : 3000);
    return () => { disposed = true; clearInterval(timer); };
  }, [desktop, interceptOn]);

  // Apply only the latest draft, in order. Individual keystrokes must not race
  // independent native proxy_set_rules commands and overwrite newer rules.
  useEffect(() => {
    if (!desktop) return;
    const revision = ++ruleRevision.current;
    setRulesApplied(false);
    const timer = setTimeout(() => {
      const next = rules.map((rule) => ({ ...rule }));
      setRulesSaving(true);
      const operation = ruleQueue.current.then(() => proxySetRules(next));
      ruleQueue.current = operation.then(() => undefined, () => undefined);
      void operation.then(() => {
        if (ruleRevision.current === revision) {
          setRulesApplied(true);
          setError(null);
        }
      }).catch((cause) => {
        if (ruleRevision.current === revision) setError("Cannot apply proxy rules: " + String(cause));
      }).finally(() => {
        if (ruleRevision.current === revision) setRulesSaving(false);
      });
    }, 300);
    return () => clearTimeout(timer);
  }, [desktop, rules]);

  const start = async () => {
    if (!desktop || busy) return;
    const requestedPort = Number(port.trim());
    if (!/^\d+$/.test(port.trim()) || !Number.isInteger(requestedPort) || requestedPort < 1 || requestedPort > 65535) {
      setError("Choose a valid TCP port (1–65535)");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setStatus(await proxyStart(requestedPort));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setBusy(false); }
  };
  const stop = async () => {
    if (!desktop || busy) return;
    setBusy(true);
    setError(null);
    try {
      setStatus(await proxyStop());
      setInterceptOn(false);
      setPending([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setBusy(false); }
  };
  const toggleIntercept = async () => {
    if (!desktop || busy || !status.running) return;
    setBusy(true);
    setError(null);
    try {
      const on = await proxyIntercept(!interceptOn);
      setInterceptOn(on);
      if (!on) setPending([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setBusy(false); }
  };
  const forward = async (id: number) => {
    if (pendingBusy !== null) return;
    setPendingBusy(id);
    setError(null);
    try {
      await proxyForward(id);
      setPending(await proxyPending());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setPendingBusy(null); }
  };
  const drop = async (id: number) => {
    if (pendingBusy !== null) return;
    setPendingBusy(id);
    setError(null);
    try {
      await proxyDrop(id);
      setPending(await proxyPending());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setPendingBusy(null); }
  };
  const saveRules = (next: { find: string; replace: string }[]) => setRules(next);

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
      downloadContent(pem, "cyberdeck-root-ca.crt", "application/x-x509-ca-cert");
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
          <div className="cd-workspace-toolbar items-center justify-between  px-2">
            <span className="text-[10px] font-medium uppercase tracking-wider text-fg-muted">CA certificate & browser trust</span>
            <Chip tone={caSaved ? "ok" : "muted"}>{caSaved ? "downloaded" : "per install"}</Chip>
          </div>
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              Trust the CyberDeck CA only in an isolated testing browser/profile on targets you are authorized to inspect. Installing a root CA permits interception of sensitive HTTPS traffic. Remove it when the assessment ends. Trust configuration, TLS compatibility, and end-to-end HTTPS interception must be checked on your platform.
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
          <div className="cd-workspace-toolbar items-center justify-between  px-2">
            <span className="text-[10px] font-medium uppercase tracking-wider text-fg-muted">Local interception proxy</span>
            <Chip tone={status.running ? "ok" : "muted"}>{status.running ? `running on 127.0.0.1:${status.port}` : "stopped"}</Chip>
          </div>
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              Configure your browser HTTP and HTTPS proxy to 127.0.0.1:{status.port}. History records requests observed by the listener. Intercept can hold supported requests for Forward/Drop; HTTPS interception depends on trust, TLS compatibility and runtime support. Confirm HTTPS behavior with a controlled test before relying on it.
            </p>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase text-fg-muted">port</span>
              <TextInput value={port} onChange={setPort} ariaLabel="Proxy port" className="w-24" />
              {status.running ? (
                <ToolButton tone="danger" onClick={() => void stop()} disabled={busy}>
                  <Square size={11} /> Stop
                </ToolButton>
              ) : (
                <ToolButton tone="primary" onClick={() => void start()} disabled={!desktop || busy} title={desktop ? "Bind 127.0.0.1 and start capturing" : "The proxy requires the desktop runtime"}>
                  <PlayCircle size={11} /> Start
                </ToolButton>
              )}
              <Chip>{status.captured} captured</Chip>
              <ToolButton
                tone={interceptOn ? "danger" : "default"}
                onClick={() => void toggleIntercept()}
                disabled={!desktop || !status.running || busy}
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
                    <span className={`w-12 shrink-0 font-mono text-[10px] ${p.method === "GET" ? "text-fg-dim" : "text-orange"}`}>{p.method}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-fg-dim" title={p.url}>
                      {p.host}{p.path}
                    </span>
                    <ToolButton tone="primary" onClick={() => void forward(p.id)} disabled={pendingBusy !== null}>Forward</ToolButton>
                    <ToolButton tone="danger" onClick={() => void drop(p.id)} disabled={pendingBusy !== null}>Drop</ToolButton>
                  </div>
                ))
              )}
            </div>
          </Pane>
        ) : null}

        {/* match and replace */}
        <Pane
          title={`Match & replace (${rules.length}) · ${rulesSaving ? "applying…" : rulesApplied ? "applied" : "draft"}`}
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
          HTTP(S) and WebSocket behavior varies by route and runtime; verify traffic in History before relying on interception.
        </div>
      </div>
    </div>
  );
}

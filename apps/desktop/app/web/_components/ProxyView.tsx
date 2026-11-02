/** Proxy view: listener control, intercept queue, match & replace. */
import { useEffect, useRef, useState } from "react";
import { Copy, PlayCircle, Settings2, Square, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbenchCase } from "@state/workbench";
import { AuthorizedCaseAction } from "@/app/_components/AuthorizedCaseAction";
import { Frame, FrameHeader, FramePanel, FrameTitle } from "@/components/ui/frame";
import { Chip, TextInput, ToolButton } from "@ds/panes";
import {
  isDesktop,
  webCaptureConsentStartV1,
  webCaptureConsentRevokeV1,
  webCaptureConsentStatusV1,
  type WebCaptureConsentV1,
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
  const { caseId, caseSession } = useWorkbenchCase();
  const caseReady = caseId !== "scratchpad" && caseSession.phase === "ready" && caseSession.caseId === caseId;
  const [status, setStatus] = useState<ProxyStatusWire>({ running: false, port: 8080, captured: 0 });
  const [port, setPort] = useState("8080");
  const [interceptOn, setInterceptOn] = useState(false);
  const [pending, setPending] = useState<PendingRequestWire[]>([]);
  const [consent, setConsent] = useState<WebCaptureConsentV1 | null>(null);
  const [consentBusy, setConsentBusy] = useState(false);
  const [consentError, setConsentError] = useState<string | null>(null);
  const [rules, setRules] = useState<{ find: string; replace: string }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [caPem, setCaPem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pendingBusy, setPendingBusy] = useState<number | null>(null);
  const [rulesSaving, setRulesSaving] = useState(false);
  const [rulesApplied, setRulesApplied] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
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
        try {
          const authorization = await webCaptureConsentStatusV1();
          if (!disposed) setConsent(authorization);
        } catch (cause) {
          if (!disposed) setConsentError("Capture consent unavailable: " + String(cause));
        }
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
      setConsent((previous) => previous ? { ...previous, enabled: false, generation: null } : null);
      setInterceptOn(false);
      setPending([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setBusy(false); }
  };
  const requestCaptureConsent = async () => {
    if (!desktop || consentBusy || !status.running || !caseReady) return;
    setConsentBusy(true);
    setConsentError(null);
    try {
      setConsent(await webCaptureConsentStartV1());
    } catch (cause) {
      setConsentError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setConsentBusy(false);
    }
  };
  const revokeCaptureConsent = async () => {
    if (!desktop || consentBusy) return;
    setConsentBusy(true);
    setConsentError(null);
    try {
      setConsent(await webCaptureConsentRevokeV1());
    } catch (cause) {
      setConsentError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setConsentBusy(false);
    }
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

  const copyCa = async () => {
    const pem = caPem ?? (await fetchCa());
    if (pem) void navigator.clipboard?.writeText(pem);
  };

  return (
    <div className="h-full min-h-0 overflow-y-auto bg-app p-4 sm:p-6">
      <div className="flex min-h-full w-full items-center justify-center">
        <Frame className="mx-auto w-full max-w-2xl rounded-xl bg-muted/72 p-1">
          <FrameHeader className="flex-row items-center justify-between gap-3 px-4 py-3">
            <FrameTitle>Local interception proxy</FrameTitle>
            <Chip tone={status.running ? "ok" : "muted"}>
              {status.running ? "Running" : "Stopped"}
            </Chip>
          </FrameHeader>
          <FramePanel className="space-y-4 rounded-lg bg-background px-4 pb-5 pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <label htmlFor="cyberdeck-proxy-port" className="text-xs text-fg-muted">Port</label>
            <div id="cyberdeck-proxy-port">
              <TextInput value={port} onChange={setPort} ariaLabel="Proxy port" className="w-24" />
            </div>
            {status.running ? (
              <ToolButton tone="danger" onClick={() => void stop()} disabled={busy}>
                <Square size={13} /> Stop
              </ToolButton>
            ) : (
              <ToolButton tone="primary" onClick={() => void start()} disabled={!desktop || busy}
                title={desktop ? "Start local proxy on 127.0.0.1" : "Requires the native desktop runtime"}>
                <PlayCircle size={13} /> Start
              </ToolButton>
            )}
            <ToolButton tone={interceptOn ? "danger" : "default"} onClick={() => void toggleIntercept()}
              disabled={!desktop || !status.running || busy}
              title="Hold supported requests for Forward or Drop">
              Intercept {interceptOn ? "on" : "off"}
            </ToolButton>
            <span className="ml-auto font-mono text-[11px] text-fg-muted">
              127.0.0.1:{status.running ? status.port : port} · {status.captured} requests
            </span>
          </div>

          {error && <p role="alert" className="text-xs text-err">{error}</p>}
          <p className="text-xs leading-relaxed text-fg-muted">
            To inspect traffic: start the proxy, select a saved case, authorize private History
            in Advanced, and point an isolated test browser to 127.0.0.1:{status.running ? status.port : port}.
            HTTPS interception also requires explicit CA trust in that browser; CyberDeck does not install trust automatically.
          </p>
          {!desktop && <p className="text-xs text-fg-muted">Proxy control requires the desktop application.</p>}

          <div className="flex items-center">
            <Button type="button" variant="ghost" size="sm"
              aria-expanded={advancedOpen} aria-controls="cyberdeck-proxy-advanced"
              onClick={() => setAdvancedOpen((open) => !open)}>
              <Settings2 size={14} /> Advanced
            </Button>
          </div>

          {advancedOpen && (
            <section id="cyberdeck-proxy-advanced" aria-label="Proxy advanced controls"
              className="space-y-4 border-t border-line pt-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-xs font-semibold">Private history</span>
                <Chip tone={consent?.enabled && status.running ? "ok" : "muted"}>
                  {consent?.enabled && status.running ? "Authorized" : "Off"}
                </Chip>
                <ToolButton disabled={!desktop || !caseReady || !status.running || consentBusy || !!consent?.enabled}
                  onClick={() => void requestCaptureConsent()}
                  title="Requires a saved case and explicit native operator confirmation">
                  {consentBusy ? "Checking…" : "Authorize"}
                </ToolButton>
                <ToolButton tone="danger" disabled={!desktop || consentBusy || !consent?.enabled}
                  onClick={() => void revokeCaptureConsent()}
                  title="Revoke authorization and clear volatile confidential capture">
                  Revoke & clear
                </ToolButton>
              </div>
              {!caseReady && <AuthorizedCaseAction activity="Private HTTP history capture" />}
              {consentError && <p role="alert" className="text-xs text-err">{consentError}</p>}
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-xs font-semibold">CA trust</span>
                <ToolButton onClick={() => void copyCa()} disabled={!desktop} title="Copy CA certificate PEM">
                  <Copy size={13} /> Copy PEM
                </ToolButton>
                <span className="text-[11px] text-fg-muted">Trust only in an isolated authorized test profile.</span>
              </div>
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs font-semibold">Request rules</span>
                  <span className="text-[11px] text-fg-muted">
                    {rules.length} {rules.length === 1 ? "rule" : "rules"}
                    {rulesSaving ? " · applying…" : rulesApplied ? " · applied" : ""}
                  </span>
                  <ToolButton disabled={!desktop}
                    onClick={() => saveRules([...rules, { find: "", replace: "" }])}>
                    + Add rule
                  </ToolButton>
                </div>
                {rules.map((rule, index) => (
                  <div key={index} className="flex flex-wrap items-center gap-2">
                    <TextInput value={rule.find}
                      onChange={(value) => saveRules(rules.map((item, i) => index === i ? { ...item, find: value } : item))}
                      ariaLabel={`Match rule ${index + 1}`} placeholder="Find" className="min-w-36 flex-1" />
                    <span aria-hidden="true" className="text-fg-muted">→</span>
                    <TextInput value={rule.replace}
                      onChange={(value) => saveRules(rules.map((item, i) => index === i ? { ...item, replace: value } : item))}
                      ariaLabel={`Replace rule ${index + 1}`} placeholder="Replace" className="min-w-36 flex-1" />
                    <Button type="button" size="icon-sm" variant="ghost"
                      aria-label={`Remove rule ${index + 1}`}
                      onClick={() => saveRules(rules.filter((_, i) => i !== index))}>
                      <X size={14} />
                    </Button>
                  </div>
                ))}
              </div>
            </section>
          )}

          {interceptOn && (
            <section aria-label="Intercept queue" className="space-y-2 border-t border-line pt-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold">Intercept queue</span>
                <Chip>{pending.length} pending</Chip>
              </div>
              {pending.length === 0 ? (
                <p className="text-xs text-fg-muted">Waiting for requests…</p>
              ) : (
                <div className="space-y-1">
                  {pending.map((request) => (
                    <div key={request.id} className="flex items-center gap-2 rounded-sm bg-raised px-2 py-1.5">
                      <span className="w-12 shrink-0 font-mono text-[11px] text-fg-dim">{request.method}</span>
                      <span className="min-w-0 flex-1 truncate font-mono text-[11px]" title={request.url}>
                        {request.host}{request.path}
                      </span>
                      <ToolButton tone="primary" disabled={pendingBusy !== null}
                        onClick={() => void forward(request.id)}>Forward</ToolButton>
                      <ToolButton tone="danger" disabled={pendingBusy !== null}
                        onClick={() => void drop(request.id)}>Drop</ToolButton>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
          </FramePanel>
        </Frame>
      </div>
    </div>
  );
}

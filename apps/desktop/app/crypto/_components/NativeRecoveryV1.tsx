"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Select } from "@ds/panes";
import { useWorkbenchCase } from "@state/workbench";
import {
  isDesktop, recoveryCancelV1, recoveryDevicesV1, recoveryDiscardV1,
  recoveryRevealV1, recoveryStartV1, recoveryStatusV1,
  type RecoveryBackendV1, type RecoveryDeviceInventoryV1,
  type RecoveryJobStatusV1, type RecoveryRequestV1,
} from "@lib/ipc";

// Store only a backend-owned opaque job reference across route remounts.
let currentJob: { scope: string; id: number } | null = null;

export function NativeRecoveryV1({ targetHash }: { targetHash: string }) {
  const { caseId, caseSession } = useWorkbenchCase();
  const [desktop, setDesktop] = useState(false);
  useEffect(() => setDesktop(isDesktop()), []);
  const scope = caseSession.phase === "ready" && caseSession.caseId === caseId
    ? caseId + ":" + String(caseSession.revision) : null;
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const [backend, setBackend] = useState("cpu");
  const [inventory, setInventory] = useState<RecoveryDeviceInventoryV1 | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [batchSize, setBatchSize] = useState(4096);
  const [maxCandidates, setMaxCandidates] = useState(100000);
  const [maxMatches, setMaxMatches] = useState(1);
  const [jobId, setJobId] = useState<number | null>(null);
  const [status, setStatus] = useState<RecoveryJobStatusV1 | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secretHex, setSecretHex] = useState<string | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [pendingCancel, setPendingCancel] = useState(false);
  const clearReveal = useCallback(() => setSecretHex(null), []);
  const hash = targetHash.trim();
  const validHash = /^[0-9a-fA-F]{64}$/.test(hash);
  const running = status?.phase === "running" || status?.phase === "cancelling";
  const selectedDevice = backend.startsWith("open_cl:") ? Number(backend.slice(8)) : null;
  const deviceAvailable = selectedDevice === null ||
    !!inventory?.devices.some((item) => item.device_index === selectedDevice);

  useEffect(() => {
    clearReveal();
    setStatus(null);
    setError(null);
    setBusy(false);
    setPendingCancel(false);
    if (scope && currentJob?.scope === scope) {
      setJobId(currentJob.id);
    } else {
      // A route remount may briefly have no selected native case while the
      // backend session is being restored. Do not forget a still-running job.
      if (scope || caseId === "scratchpad") currentJob = null;
      setJobId(null);
    }
  }, [scope, caseId, clearReveal]);

  useEffect(() => {
    if (!desktop || !scope) { setInventory(null); return; }
    let active = true;
    void recoveryDevicesV1().then((data) => {
      if (active) { setInventory(data); setDeviceError(null); }
    }).catch((reason: unknown) => {
      if (active) setDeviceError(String(reason));
    });
    return () => { active = false; };
  }, [desktop, scope]);

  useEffect(() => {
    if (!scope || jobId === null) return;
    let active = true;
    const refresh = async () => {
      try {
        const next = await recoveryStatusV1(jobId);
        if (!active || scopeRef.current !== scope || currentJob?.id !== jobId) return;
        setStatus(next);
        if (next.error) setError(next.error);
      } catch (reason) {
        if (!active || scopeRef.current !== scope) return;
        setError(String(reason));
        setStatus(null);
        setJobId(null);
        if (currentJob?.id === jobId) currentJob = null;
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 900);
    return () => { active = false; window.clearInterval(timer); };
  }, [scope, jobId]);

  useEffect(() => {
    if (secretHex === null) return;
    const timer = window.setTimeout(clearReveal, 30000);
    return () => window.clearTimeout(timer);
  }, [secretHex, clearReveal]);

  const start = async () => {
    if (!scope || !validHash || busy || !deviceAvailable || jobId !== null) return;
    clearReveal(); setError(null); setBusy(true); setStatus(null); setJobId(null);
    const requestScope = scope;
    const selected: RecoveryBackendV1 = selectedDevice === null
      ? { backend: "cpu" }
      : { backend: "open_cl", device_index: selectedDevice, batch_size: batchSize };
    const request: RecoveryRequestV1 = {
      algorithm: "sha256", target_hash: hash.toLowerCase(), backend: selected,
      max_candidates: maxCandidates, max_matches: maxMatches,
    };
    try {
      // The native OS wordlist picker runs within the Tauri backend.
      const id = await recoveryStartV1(request, () => {
        // Poll authoritative Rust state; events never contain recovered plaintext.
      });
      if (scopeRef.current !== requestScope) return;
      currentJob = { scope: requestScope, id };
      setJobId(id);
    } catch (reason) {
      if (scopeRef.current === requestScope && !/cancelled/i.test(String(reason)))
        setError(String(reason));
    } finally { if (scopeRef.current === requestScope) setBusy(false); }
  };

  const cancel = async () => {
    if (jobId === null || !scope || !running) return;
    setPendingCancel(true);
    try {
      if (!await recoveryCancelV1(jobId) && scopeRef.current === scope)
        setError("Native recovery already finished or revoked.");
    } catch (reason) {
      if (scopeRef.current === scope) setError(String(reason));
    } finally { if (scopeRef.current === scope) setPendingCancel(false); }
  };

  const discard = async () => {
    if (jobId === null || !scope || running) return;
    clearReveal();
    try { await recoveryDiscardV1(jobId); } catch (reason) { setError(String(reason)); }
    if (scopeRef.current === scope) {
      if (currentJob?.id === jobId) currentJob = null;
      setJobId(null); setStatus(null);
    }
  };

  const reveal = async (ordinal: number) => {
    if (jobId === null || !scope || !status?.reveal_available) return;
    setRevealing(true); clearReveal(); setError(null);
    try {
      // A separate native OS confirmation is required for EACH reveal.
      const hex = await recoveryRevealV1(jobId, ordinal);
      if (scopeRef.current === scope && currentJob?.id === jobId) setSecretHex(hex);
    } catch (reason) {
      if (scopeRef.current === scope) setError(String(reason));
    } finally { if (scopeRef.current === scope) setRevealing(false); }
  };

  const disabledReason = !desktop ? "Requires the native desktop runtime"
    : !scope ? (caseId === "scratchpad" ? "Select a saved case to authorize recovery"
      : caseSession.error ?? "Waiting for native case selection")
    : !validHash ? "Enter a SHA-256 digest (64 hexadecimal characters)"
    : !deviceAvailable ? "Selected OpenCL device unavailable" : null;
  const progress = status?.progress;
  const percent = progress && progress.budget > 0
    ? Math.min(100, Math.round(progress.tried / progress.budget * 100)) : 0;

  return (
    <section aria-label="Native SHA-256 Recovery V1" className="border-b border-line p-2 text-xs">
      <div className="mb-2 flex items-center justify-between gap-2">
        <strong>Native SHA-256 recovery</strong>
        <span className="font-mono text-[10px] text-fg-muted">
          {scope ? "case authorized" : "case required"} · wordlist
        </span>
      </div>
      <p className="mb-2 text-[11px] text-fg-muted">
        Native wordlist picker, CPU or OpenCL, cancellable jobs and masked results.
        Plaintext requires explicit OS confirmation. Nothing is saved automatically.
      </p>
      <div className="grid grid-cols-2 gap-2">
        <label className="space-y-1">
          <span className="text-[10px] text-fg-muted">Backend</span>
          <Select ariaLabel="Recovery V1 backend" value={backend}
            onChange={(value) => { setBackend(value); clearReveal(); }}
            options={[
              { value: "cpu", label: "CPU — Rust" },
              ...(inventory?.devices ?? []).map((d) => ({
                value: "open_cl:" + d.device_index,
                label: "OpenCL " + d.device_index + ": " + d.name + " (unverified)",
              })),
            ]} className="w-full" />
        </label>
        <label className="space-y-1">
          <span className="text-[10px] text-fg-muted">Candidate budget (1–1,000,000)</span>
          <input type="number" aria-label="Recovery candidate budget" min={1} max={1000000}
            value={maxCandidates} onChange={(e) => {
              const n = Number(e.target.value);
              if (Number.isSafeInteger(n)) setMaxCandidates(Math.max(1, Math.min(1000000, n)));
            }} className="w-full rounded border border-line bg-app px-2 py-1 font-mono text-xs" />
        </label>
        <label className="space-y-1">
          <span className="text-[10px] text-fg-muted">Maximum matches (1–4)</span>
          <input type="number" aria-label="Maximum matches" min={1} max={4}
            value={maxMatches} onChange={(e) => {
              const n = Number(e.target.value);
              if (Number.isSafeInteger(n)) setMaxMatches(Math.max(1, Math.min(4, n)));
            }} className="w-full rounded border border-line bg-app px-2 py-1 font-mono text-xs" />
        </label>
        {selectedDevice !== null ? (
          <label className="space-y-1">
            <span className="text-[10px] text-fg-muted">OpenCL batch (1–65,536)</span>
            <input type="number" aria-label="OpenCL batch size" min={1} max={65536}
              value={batchSize} onChange={(e) => {
                const n = Number(e.target.value);
                if (Number.isSafeInteger(n)) setBatchSize(Math.max(1, Math.min(65536, n)));
              }} className="w-full rounded border border-line bg-app px-2 py-1 font-mono text-xs" />
          </label>
        ) : null}
      </div>
      {inventory ? <p className="mt-1 text-[10px] text-fg-muted">{inventory.detail}</p> : null}
      {deviceError ? <p role="alert" className="mt-1 text-err">{deviceError}</p> : null}
      {disabledReason ? <p className="mt-2 text-warn">{disabledReason}</p> : null}
      <div className="mt-2 flex flex-wrap gap-1">
        <Button size="sm" disabled={!!disabledReason || busy || jobId !== null}
          onClick={() => void start()}>{busy ? "Choosing wordlist…" : "Start native recovery"}</Button>
        <Button size="sm" variant="outline" disabled={!running || pendingCancel}
          onClick={() => void cancel()}>{status?.phase === "cancelling" ? "Cancelling…" : "Cancel"}</Button>
        <Button size="sm" variant="outline" disabled={jobId === null || running}
          onClick={() => void discard()}>Discard</Button>
      </div>
      {jobId !== null ? (
        <div className="mt-2 space-y-1 font-mono text-[11px]" aria-live="polite">
          <p>Native job #{jobId} · {status?.phase ?? "loading"}</p>
          {progress ? <>
            <p>{progress.tried.toLocaleString()} / {progress.budget.toLocaleString()} tried · {progress.matches} masked matches</p>
            <progress aria-label="Native recovery progress" value={percent} max={100} className="w-full" />
          </> : null}
          {status?.summary ? <>
            <p>{status.summary.tried.toLocaleString()} tried · {status.summary.matches.length} matches
              {status.summary.limit_reached ? " · candidate limit reached" : ""}</p>
            {status.summary.matches.map((match, ordinal) => (
              <div key={ordinal} className="flex items-center justify-between gap-1">
                <span>Candidate #{match.candidate_index} · masked</span>
                <Button size="sm" variant="outline" disabled={!status.reveal_available || revealing}
                  onClick={() => void reveal(ordinal)}>Reveal (OS consent)</Button>
              </div>
            ))}
            {!!status.summary.matches.length && !status.reveal_available
              ? <p>Confidential results expired, revoked or unavailable.</p> : null}
          </> : null}
        </div>
      ) : null}
      {secretHex !== null ? (
        <div role="region" aria-label="Transient recovered candidate" className="mt-2 border border-line p-2">
          <div className="mb-1 flex items-center justify-between gap-1">
            <span className="text-warn">Sensitive hex · hides after 30 seconds</span>
            <Button size="sm" variant="outline" onClick={clearReveal}>Hide</Button>
          </div>
          <code className="break-all">{secretHex}</code>
        </div>
      ) : null}
      {error ? <p role="alert" className="mt-2 break-words text-err">{error}</p> : null}
    </section>
  );
}

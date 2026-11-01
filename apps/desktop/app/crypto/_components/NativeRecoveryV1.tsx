"use client";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Play, Square, Trash2, Eye, EyeOff, Info, FileUp } from "lucide-react";
import { Chip } from "@ds/panes";
import { hasCurrentRecoveryScope, isSha256WordlistTarget, recoveryDisplay } from "./recovery-presentation";
import { chooseRecoveryBackend, DEFAULT_CANDIDATES, DEFAULT_MATCHES, DEFAULT_OPENCL_BATCH } from "./recovery-auto";
import { Button } from "@/components/ui/button";
import { Select } from "@ds/panes";
import { useWorkbenchCase } from "@state/workbench";
import {
  isDesktop, recoveryCancelV1, recoveryDevicesV1, recoveryDiscardV1,
  recoverySelectWordlistV1, recoveryWordlistStatusV1, type RecoveryWordlistV1,
  recoveryRevealV1, recoveryStartV1, recoveryStatusV1,
  type RecoveryBackendV1, type RecoveryDeviceInventoryV1,
  type RecoveryJobStatusV1, type RecoveryRequestV1,
} from "@lib/ipc";

// Store only a backend-owned opaque job reference across route remounts.
let currentJob: { scope: string; id: number } | null = null;

function useRecoveryController(targetHash: string) {
  const { caseId, caseSession } = useWorkbenchCase();
  const [desktop, setDesktop] = useState(false);
  useEffect(() => setDesktop(isDesktop()), []);
  const scope = caseSession.phase === "ready" && caseSession.caseId === caseId
    ? caseId + ":" + String(caseSession.revision) : null;
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const [backend, setBackend] = useState("auto");
  const [inventory, setInventory] = useState<RecoveryDeviceInventoryV1 | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [batchSize, setBatchSize] = useState(DEFAULT_OPENCL_BATCH);
  const [maxCandidates, setMaxCandidates] = useState(DEFAULT_CANDIDATES);
  const [maxMatches, setMaxMatches] = useState(DEFAULT_MATCHES);
  const [jobId, setJobId] = useState<number | null>(null);
  const [status, setStatus] = useState<RecoveryJobStatusV1 | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secretHex, setSecretHex] = useState<string | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [pendingCancel, setPendingCancel] = useState(false);
  const [wordlist, setWordlist] = useState<{ scope: string; info: RecoveryWordlistV1 } | null>(null);
  const [choosingWordlist, setChoosingWordlist] = useState(false);
  const [wordlistError, setWordlistError] = useState<string | null>(null);
  const [discarded, setDiscarded] = useState(false);
  const clearReveal = useCallback(() => setSecretHex(null), []);
  const hash = targetHash.trim();
  const validHash = isSha256WordlistTarget(hash);
  const running = status?.phase === "running" || status?.phase === "cancelling";
  const selection = chooseRecoveryBackend(backend, inventory, batchSize);
  const selectedDevice = selection.backend === "open_cl" ? selection.device_index : null;
  const deviceAvailable = selectedDevice === null ||
    !!inventory?.devices.some((item) => item.device_index === selectedDevice);

  useEffect(() => {
    clearReveal();
    setStatus(null);
    setError(null);
    setBusy(false);
    setPendingCancel(false);
    setDiscarded(false);
    setWordlistError(null);
    setChoosingWordlist(false);
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
    if (!scope || !desktop) { setWordlist(null); return; }
    let active = true;
    setWordlist(null);
    void recoveryWordlistStatusV1().then((info) => {
      if (active && scopeRef.current === scope)
        setWordlist(info ? { scope, info } : null);
    }).catch((reason: unknown) => {
      if (active && scopeRef.current === scope) setWordlistError(String(reason));
    });
    return () => { active = false; };
  }, [scope, desktop]);

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

  const selectedWordlist = wordlist?.scope === scope ? wordlist.info : null;

  const chooseWordlist = async () => {
    if (!desktop || !scope || choosingWordlist || busy || jobId !== null) return;
    const requestedScope = scope;
    setChoosingWordlist(true);
    setWordlistError(null);
    try {
      const info = await recoverySelectWordlistV1();
      if (scopeRef.current === requestedScope) setWordlist({ scope: requestedScope, info });
    } catch (reason) {
      if (scopeRef.current === requestedScope && !/cancelled/i.test(String(reason)))
        setWordlistError(String(reason));
    } finally {
      if (scopeRef.current === requestedScope) setChoosingWordlist(false);
    }
  };

  const start = async () => {
    if (!scope || !validHash || !selectedWordlist || busy || !deviceAvailable || jobId !== null) return;
    clearReveal(); setError(null); setBusy(true); setStatus(null); setJobId(null);
    setDiscarded(false);
    const requestScope = scope;
    const selected: RecoveryBackendV1 = selection;
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
    try {
      const discarded = await recoveryDiscardV1(jobId);
      if (!discarded) { setError("Result already revoked; check active case."); return; }
    } catch (reason) { setError(String(reason)); return; }
    if (scopeRef.current === scope) {
      if (currentJob?.id === jobId) currentJob = null;
      setJobId(null); setStatus(null); setError(null); setDiscarded(true);
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
    : !selectedWordlist ? "Choose a local wordlist before starting"
    : !deviceAvailable ? "Selected OpenCL device unavailable" : null;
  const progress = status?.progress;
  const percent = progress && progress.budget > 0
    ? Math.min(100, Math.round(progress.tried / progress.budget * 100)) : 0;
  // Mask even the next paint after a case switch; effects run after rendering.
  const scopedJob = hasCurrentRecoveryScope(currentJob, scope, jobId);

  return {
    desktop, scope, backend, setBackend, inventory, deviceError, batchSize, setBatchSize,
    maxCandidates, setMaxCandidates, maxMatches, setMaxMatches,
    jobId: scopedJob ? jobId : null,
    status: scopedJob ? status : null,
    busy, error: scopedJob || jobId === null ? error : null,
    secretHex: scopedJob ? secretHex : null,
    discarded, revealing, pendingCancel, clearReveal, validHash,
    selectedWordlist, choosingWordlist, wordlistError, chooseWordlist,
    running: scopedJob && running, selectedDevice, deviceAvailable, start, cancel, discard, reveal,
    disabledReason, progress: scopedJob ? progress : null, percent, hash, caseId, selection,
  };
}

type RecoveryController = ReturnType<typeof useRecoveryController>;
const RecoveryContext = createContext<RecoveryController | null>(null);
function useRecovery() {
  const state = useContext(RecoveryContext);
  if (!state) throw new Error("Recovery V1 requires its provider");
  return state;
}

export function NativeRecoveryV1({
  targetHash, children,
}: { targetHash: string; children: ReactNode }) {
  const state = useRecoveryController(targetHash);
  return <RecoveryContext.Provider value={state}>{children}</RecoveryContext.Provider>;
}

export function NativeRecoveryControls() {
  const r = useRecovery();
  return (
    <section aria-label="Recovery controls" className="space-y-3 border-b border-line px-3 py-3">
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs font-semibold text-fg">Recovery</div>
        <Chip tone={r.scope ? "ok" : "muted"}>{r.scope ? "Case ready" : "Case required"}</Chip>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] text-fg-dim">SHA-256 wordlist recovery · CPU/OpenCL</span>
        <details className="relative text-[11px] text-fg-muted">
          <summary className="inline-flex cursor-pointer items-center gap-1 rounded px-1 focus-visible:outline focus-visible:outline-2" aria-label="Recovery security and limits information">
            <Info size={13} aria-hidden="true" /> Info
          </summary>
          <div className="mt-2 max-w-sm rounded border border-line bg-app p-2 leading-relaxed">
            Choose a local wordlist before starting. Running jobs can be stopped.
            Results are masked; each Reveal requires native OS confirmation.
            Results expire and are never saved automatically. Auto never assumes
            that GPU enumeration proves correct kernel execution.
          </div>
        </details>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-fg-dim">
        <span>Auto · {r.selection.backend === "cpu" ? "CPU" : "verified OpenCL device " + r.selection.device_index}</span>
        <span>Wordlist · SHA-256</span>
      </div>
      <details className="rounded-sm border border-line/70 px-2.5 py-2 text-xs">
        <summary className="cursor-pointer font-medium text-fg" aria-label="Advanced recovery settings">Advanced</summary>
        <div className="mt-3 grid grid-cols-2 gap-3">
          <label className="col-span-2 space-y-1">
            <span className="text-[11px] text-fg-muted">Compute device</span>
            <Select ariaLabel="Recovery V1 backend" value={r.backend}
              onChange={(value) => { r.setBackend(value); r.clearReveal(); }}
              options={[
                { value: "auto", label: "Auto · verified GPU or CPU" },
                { value: "cpu", label: "CPU · Native Rust" },
                ...(r.inventory?.devices ?? []).map((device) => ({
                  value: "open_cl:" + device.device_index,
                  label: "OpenCL " + device.device_index + " · " + device.name
                    + (device.hardware_verified ? "" : " (unverified)"),
                })),
              ]} className="w-full" />
          </label>
          <label className="space-y-1">
            <span className="text-[11px] text-fg-muted">Candidate limit</span>
            <input type="number" aria-label="Recovery candidate budget" min={1} max={1000000}
              value={r.maxCandidates} onChange={(event) => {
                const value = Number(event.target.value);
                if (Number.isSafeInteger(value)) r.setMaxCandidates(Math.max(1, Math.min(1000000, value)));
              }} className="h-8 w-full rounded-sm border border-line bg-app px-2 font-mono text-xs text-fg" />
          </label>
          <label className="space-y-1">
            <span className="text-[11px] text-fg-muted">Max matches</span>
            <input type="number" aria-label="Maximum matches" min={1} max={4}
              value={r.maxMatches} onChange={(event) => {
                const value = Number(event.target.value);
                if (Number.isSafeInteger(value)) r.setMaxMatches(Math.max(1, Math.min(4, value)));
              }} className="h-8 w-full rounded-sm border border-line bg-app px-2 font-mono text-xs text-fg" />
          </label>
          {r.selectedDevice !== null ? (
            <label className="col-span-2 space-y-1">
              <span className="text-[11px] text-fg-muted">OpenCL batch size</span>
              <input type="number" aria-label="OpenCL batch size" min={1} max={65536}
                value={r.batchSize} onChange={(event) => {
                  const value = Number(event.target.value);
                  if (Number.isSafeInteger(value)) r.setBatchSize(Math.max(1, Math.min(65536, value)));
                }} className="h-8 w-full rounded-sm border border-line bg-app px-2 font-mono text-xs text-fg" />
            </label>
          ) : null}
          <p className="col-span-2 text-[11px] leading-relaxed text-fg-muted">
            Strategy: wordlist only. Rules, masks and hybrid combinations are not
            available in this authorized Recovery V1 workflow.
            Auto uses CPU until a device has passed real OpenCL verification.
          </p>
        </div>
      </details>
      {!r.validHash && r.hash.length > 0 ? (
        <p role="status" className="text-[11px] text-warn">
          This input is not a 64-character SHA-256 digest. Recovery V1 cannot process it.
        </p>
      ) : null}
      {r.disabledReason && !(r.hash.length > 0 && !r.validHash) ? (
        <p role="status" className="text-[11px] text-warn">{r.disabledReason}</p>
      ) : null}
      <div className="space-y-1.5">
        <span className="text-[11px] text-fg-muted">Wordlist</span>
        <div className="flex min-w-0 items-center gap-2">
          <Button size="sm" variant="outline" className="h-8 w-8 shrink-0 p-0"
            aria-label={r.choosingWordlist ? "Selecting wordlist" : "Choose wordlist"}
            title="Choose or replace local wordlist (native OS picker)"
            disabled={!r.desktop || !r.scope || r.choosingWordlist || r.busy || r.jobId !== null}
            onClick={() => void r.chooseWordlist()}>
            <FileUp size={15} aria-hidden="true" />
          </Button>
          <span className="min-w-0 truncate font-mono text-[11px] text-fg-dim"
            title={r.selectedWordlist?.name ?? "No wordlist selected"}>
            {r.selectedWordlist?.name ?? "No file selected"}
          </span>
        </div>
        {r.wordlistError ? <p role="alert" className="text-[11px] text-err">{r.wordlistError}</p> : null}
      </div>
      <div role="group" aria-label="Recovery action">
        {r.busy || r.jobId === null ? (
          <Button size="sm" className="h-8 w-8 p-0"
            aria-label={r.busy ? "Starting recovery" : "Start recovery"}
            title={r.disabledReason ?? "Start SHA-256 recovery"}
            disabled={!!r.disabledReason || r.busy || r.choosingWordlist}
            onClick={() => void r.start()}>
            <Play size={15} aria-hidden="true" />
          </Button>
        ) : r.status === null ? (
          <Button size="sm" className="h-8 w-8 p-0" aria-label="Loading recovery job" title="Loading job" disabled><Play size={15} /></Button>
        ) : r.running ? (
          <Button size="sm" variant="outline" className="h-8 w-8 p-0"
            aria-label={r.pendingCancel || r.status.phase === "cancelling" ? "Stopping recovery" : "Stop recovery"}
            title="Stop recovery (cooperative cancellation)"
            disabled={r.pendingCancel || r.status.phase === "cancelling"}
            onClick={() => void r.cancel()}>
            <Square size={14} aria-hidden="true" />
          </Button>
        ) : (
          <Button size="sm" variant="outline" className="h-8 w-8 p-0"
            aria-label="Discard recovery result"
            title="Discard finished or failed results"
            disabled={r.revealing}
            onClick={() => void r.discard()}>
            <Trash2 size={14} aria-hidden="true" />
          </Button>
        )}
      </div>
    </section>
  );
}

export function NativeRecoveryDevices() {
  const { inventory, deviceError, desktop } = useRecovery();
  return (
    <section aria-label="Recovery devices" className="space-y-2 px-3 py-3 text-[11px]">
      <div className="text-xs font-semibold text-fg">Devices</div>
      <div className="flex items-center justify-between gap-2">
        <span>CPU · Native Rust</span><Chip tone={desktop ? "ok" : "muted"}>{desktop ? "Available" : "Desktop only"}</Chip>
      </div>
      {(inventory?.devices ?? []).map((device) => (
        <div key={device.device_index} className="flex flex-wrap items-start justify-between gap-2 border-t border-line pt-2">
          <span className="min-w-0 flex-1 break-words">
            {device.name}<span className="block text-fg-muted">{device.vendor} · {device.driver}</span>
          </span>
          <Chip tone="muted">Unverified</Chip>
        </div>
      ))}
      {desktop && inventory?.devices.length === 0 ? (
        <p className="text-fg-muted">No OpenCL devices detected. CPU remains available.</p>
      ) : null}
      {deviceError ? <p role="alert" className="text-err">{deviceError}</p> : null}
      {inventory && !inventory.opencl_detected ? (
        <details className="text-fg-muted">
          <summary className="cursor-pointer">OpenCL details</summary>
          <p className="mt-1 break-words">{inventory.detail}</p>
        </details>
      ) : null}
    </section>
  );
}

export function NativeRecoveryResults() {
  const r = useRecovery();
  const view = recoveryDisplay(r.scope, r.jobId, r.status, r.error, r.discarded);
  const matches = r.status?.summary?.matches ?? [];
  const [visibleMatches, setVisibleMatches] = useState(16);
  useEffect(() => { setVisibleMatches(16); }, [r.scope, r.jobId]);
  const isActive = view.kind === "running";
  return (
    <div className="h-full min-h-0 space-y-3 overflow-y-auto p-3"
      aria-live="polite" aria-relevant="text" aria-label="Scroll recovery results"
      onScroll={(event) => {
        const node = event.currentTarget;
        if (node.scrollTop + node.clientHeight >= node.scrollHeight - 72) {
          setVisibleMatches((count) => Math.min(count + 16, matches.length));
        }
      }}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-fg">{view.title}</span>
          {isActive ? <Chip tone="orange">Active</Chip> : null}
          {view.kind === "completed" ? <Chip tone="ok">Masked</Chip> : null}
          {view.kind === "failed" ? <Chip tone="err">Failed</Chip> : null}
        </div>
        {r.jobId !== null ? <span className="font-mono text-[11px] text-fg-muted">Job #{r.jobId}</span> : null}
      </div>
      <p className="text-[11px] leading-relaxed text-fg-muted">{view.detail}</p>
      {r.status?.progress && (
        <div className="space-y-1.5">
          <div className="flex justify-between gap-2 font-mono text-[11px] text-fg-dim">
            <span>{r.status.progress.tried.toLocaleString()} / {r.status.progress.budget.toLocaleString()} candidates</span>
            <span>{r.percent}%</span>
          </div>
          <progress className="h-2 w-full" aria-label="Native recovery progress" value={r.percent} max={100} />
        </div>
      )}
      {r.status?.summary && (
        <div className="flex flex-wrap gap-3 text-[11px] text-fg-muted">
          <span>{r.status.summary.tried.toLocaleString()} checked</span>
          <span>{r.status.summary.duration_ms.toLocaleString()} ms</span>
          {r.status.summary.limit_reached ? <span>Candidate limit reached</span> : null}
        </div>
      )}
      {matches.length > 0 && (
        <div className="space-y-2" aria-label="Masked recovered candidates">
          {matches.slice(0, visibleMatches).map((match, ordinal) => (
            <div key={ordinal} className="flex items-center justify-between gap-2 rounded-sm border border-line bg-app px-3 py-2">
              <div className="min-w-0">
                <p className="font-mono text-xs text-fg">••••••••</p>
                <p className="mt-1 text-[11px] text-fg-muted">Candidate #{match.candidate_index}</p>
              </div>
              <Button size="sm" variant="outline" className="h-8 gap-1.5"
                title="Native OS confirmation required before revealing sensitive candidate bytes"
                disabled={r.status?.phase !== "completed" || !r.status.reveal_available || r.revealing}
                onClick={() => void r.reveal(ordinal)}>
                <Eye size={13} aria-hidden="true" /> Reveal
              </Button>
            </div>
          ))}
        </div>
      )}
      {visibleMatches < matches.length ? <p className="text-[11px] text-fg-muted">Scroll to view more masked matches</p> : null}
      {r.secretHex !== null && (
        <div role="region" aria-label="Transient recovered candidate" className="rounded-sm border border-line bg-app p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <span className="text-[11px] text-warn">Sensitive hex · auto-hide in 30 seconds</span>
            <Button size="sm" variant="outline" className="h-8 gap-1"
              onClick={r.clearReveal}><EyeOff size={13} aria-hidden="true" /> Hide</Button>
          </div>
          <code className="break-all font-mono text-xs text-fg">{r.secretHex}</code>
        </div>
      )}
      {r.error && r.jobId !== null && <p role="alert" className="text-[11px] text-err">{r.error}</p>}
    </div>
  );
}

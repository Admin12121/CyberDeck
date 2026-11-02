"use client";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Play, Square, Trash2, Eye, EyeOff, Info, FileUp, SlidersHorizontal, FileText } from "lucide-react";
import { Phosphor } from "@lucasmarkes/hairline/react";
import { Accordion, AccordionItem, AccordionTrigger, AccordionPanel } from "@/components/ui/accordion";
import { Chip } from "@ds/panes";
import { hasCurrentRecoveryScope, recoveryDisplay } from "./recovery-presentation";
import { chooseRecoveryBackend, DEFAULT_CANDIDATES, DEFAULT_MATCHES, DEFAULT_OPENCL_BATCH } from "./recovery-auto";
import { Button } from "@/components/ui/button";
import { Select } from "@ds/panes";
import { useWorkbenchCase } from "@state/workbench";
import { AuthorizedCaseAction } from "@/app/_components/AuthorizedCaseAction";
import {
  isDesktop, recoveryCancelV1, recoveryDevicesV1, recoveryDiscardV1,
  recoverySelectWordlistV1, recoveryWordlistStatusV1, type RecoveryWordlistV1,
  recoveryRevealV1, recoveryStartV1, recoveryStatusV1,
  recoveryHashcatCapabilitiesV1, recoveryStartHashcatV1,
  type EmbeddedHashcatCapabilityV1,
  type RecoveryBackendV1, type RecoveryDeviceInventoryV1,
  type RecoveryJobStatusV1, type RecoveryRequestV1, type HashcatRawAlgorithmV1, type RecoveryRawAlgorithmV1, type HashcatWordlistPresetV1,
} from "@lib/ipc";

const EMBEDDED_MODES: readonly { value: HashcatRawAlgorithmV1; label: string; digits: number }[] = [
  { value: "md5", label: "MD5 · mode 0", digits: 32 },
  { value: "sha1", label: "SHA-1 · mode 100", digits: 40 },
  { value: "ntlm", label: "NTLM · mode 1000", digits: 32 },
  { value: "sha256", label: "SHA-256 · mode 1400", digits: 64 },
  { value: "sha512", label: "SHA-512 · mode 1700", digits: 128 },
];
const RUST_MODES: readonly { value: RecoveryRawAlgorithmV1; label: string; digits: number }[] = [
  ...EMBEDDED_MODES,
  { value: "sha3_256", label: "SHA3-256 · CPU", digits: 64 },
];
// A digest algorithm is an explicit operator choice: length alone is insufficient.
let lastHashcatMode: RecoveryRawAlgorithmV1 = "sha256";
let lastHashcatPreset: HashcatWordlistPresetV1 = "plain";

// Store only a backend-owned opaque job reference across route remounts.
let currentJob: { scope: string; id: number } | null = null;

function useRecoveryController(targetHash: string, onCaseCreated?: (caseId: string) => void) {
  const { caseId, caseSession } = useWorkbenchCase();
  const [desktop, setDesktop] = useState(false);
  useEffect(() => setDesktop(isDesktop()), []);
  const scope = caseSession.phase === "ready" && caseSession.caseId === caseId
    ? caseId + ":" + String(caseSession.revision) : null;
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const [backend, setBackend] = useState("auto");
  const [engineChoice, setEngineChoice] = useState<"rust" | "hashcat">("rust");
  const [hashcatAlgorithm, setHashcatAlgorithm] = useState<RecoveryRawAlgorithmV1>(lastHashcatMode);
  const [hashcatPreset, setHashcatPreset] = useState<HashcatWordlistPresetV1>(lastHashcatPreset);
  const [hashcatCapability, setHashcatCapability] = useState<EmbeddedHashcatCapabilityV1 | null>(null);
  const [inventory, setInventory] = useState<RecoveryDeviceInventoryV1 | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [batchSize, setBatchSize] = useState(DEFAULT_OPENCL_BATCH);
  const [ruleText, setRuleText] = useState("");
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
  const hashcatMode = RUST_MODES.find((item) => item.value === hashcatAlgorithm)!;
  const validHash = hash.length === hashcatMode.digits && /^[a-fA-F0-9]+$/.test(hash);
  useEffect(() => {
    // Length is a suggestion, never an identity claim: preserve an operator's
    // explicit MD5/NTLM choice when both share 32-digit digest shapes.
    if (!/^[a-fA-F0-9]+$/.test(hash) || hash.length === hashcatMode.digits) return;
    const suggestions: Partial<Record<number, RecoveryRawAlgorithmV1>> = {
      32: "md5", 40: "sha1", 64: "sha256", 128: "sha512",
    };
    const suggestion = suggestions[hash.length];
    if (suggestion) setHashcatAlgorithm(suggestion);
  }, [hash, hashcatMode.digits]);
  const running = status?.phase === "running" || status?.phase === "cancelling";
  // GPU route is currently SHA-256-only. In Auto, other raw modes must run
  // on the available Rust CPU, even if a GPU later passes independent KAT.
  const selection: RecoveryBackendV1 = chooseRecoveryBackend(backend, inventory, batchSize, hashcatAlgorithm);
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
    if (!desktop) { setInventory(null); return; }
    let active = true;
    void recoveryDevicesV1().then((data) => {
      if (active) { setInventory(data); setDeviceError(null); }
    }).catch((reason: unknown) => {
      if (active) setDeviceError(String(reason));
    });
    return () => { active = false; };
  }, [desktop]);

  useEffect(() => {
    if (!desktop) { setHashcatCapability(null); return; }
    let active = true;
    void recoveryHashcatCapabilitiesV1().then((capability) => {
      if (active) setHashcatCapability(capability);
    }).catch(() => {
      if (active) setHashcatCapability({
        available: false, mode: 1400, modes: [], hardware_verified: false,
        detail: "Bundled native Hashcat is unavailable",
      });
    });
    return () => { active = false; };
  }, [desktop]);

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
    if (!scope || !validHash || !selectedWordlist || busy ||
      (engineChoice === "hashcat" ? !hashcatCapability?.available : !deviceAvailable) ||
      jobId !== null) return;
    if (ruleText.trim() && (engineChoice !== "rust" || selection.backend !== "cpu")) {
      setError("Wordlist rules require the native Rust CPU backend. Select CPU first.");
      return;
    }
    clearReveal(); setError(null); setBusy(true); setStatus(null); setJobId(null);
    setDiscarded(false);
    const requestScope = scope;
    const selected: RecoveryBackendV1 = engineChoice === "hashcat"
      ? { backend: "hashcat_managed" }
      : selection;
    const request: RecoveryRequestV1 = {
      algorithm: hashcatAlgorithm,
      target_hash: hash.toLowerCase(), backend: selected,
      max_candidates: maxCandidates, max_matches: maxMatches,
    };
    try {
      // Both paths share the same backend-authorized job, cancellation and
      // confidential Reveal lifecycle; never silently substitute engines.
      const onEvent = () => {
        // Poll authoritative Rust state; events never contain recovered plaintext.
      };
      const id = engineChoice === "hashcat"
        ? await recoveryStartHashcatV1(request, onEvent, hashcatPreset)
        : await recoveryStartV1(request, onEvent, ruleText);
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
    : !validHash ? "Enter a " + hashcatMode.label + " digest (" + hashcatMode.digits + " hexadecimal characters)"
    : !selectedWordlist ? "Choose a local wordlist before starting"
    : ruleText.trim().length > 4096 ? "Rule text exceeds the 4 KiB limit"
    : ruleText.trim() && (engineChoice !== "rust" || selection.backend !== "cpu")
      ? "Wordlist rules require native Rust CPU mode"
    : engineChoice === "hashcat" && !hashcatCapability?.available
      ? hashcatCapability?.detail ?? "Embedded Hashcat capability unavailable"
    : engineChoice === "hashcat" && !hashcatCapability?.modes.some((mode) => mode.algorithm === hashcatAlgorithm)
      ? "Selected Hashcat mode has not passed its native known-answer recovery test"
    : engineChoice === "rust" && !deviceAvailable ? "Selected OpenCL device unavailable" : null;
  const progress = status?.progress;
  const percent = progress && progress.budget > 0
    ? Math.min(100, Math.round(progress.tried / progress.budget * 100)) : 0;
  // Mask even the next paint after a case switch; effects run after rendering.
  const scopedJob = hasCurrentRecoveryScope(currentJob, scope, jobId);

  return {
    desktop, scope, onCaseCreated, backend, setBackend, inventory, deviceError, batchSize, setBatchSize,
    ruleText, setRuleText,
    engineChoice, setEngineChoice, hashcatCapability,
    hashcatAlgorithm, setHashcatAlgorithm, hashcatMode,
    hashcatPreset, setHashcatPreset,
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
  targetHash, children, onCaseCreated,
}: { targetHash: string; children: ReactNode; onCaseCreated?: (caseId: string) => void }) {
  const state = useRecoveryController(targetHash, onCaseCreated);
  return <RecoveryContext.Provider value={state}>{children}</RecoveryContext.Provider>;
}

export function NativeRecoveryControls() {
  const r = useRecovery();
  const jobInProgress = r.busy || r.running || (r.jobId !== null && r.status === null);
  const fileLabel = r.selectedWordlist?.name ?? "No wordlist selected";
  const statusText = !r.desktop
    ? "Open the desktop app to run recovery."
    : !r.scope
      ? "Select a saved case to authorize recovery."
      : r.disabledReason && r.hash.length > 0 && !r.validHash
        ? r.disabledReason
        : r.wordlistError
          ? r.wordlistError
          : null;

  return (
    <section aria-label="Recovery controls" className="border-b border-line px-3 pb-3 pt-3">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold text-fg">Recovery</h3>
        <Chip tone={r.scope ? "ok" : "muted"}>{r.scope ? "Case ready" : "Case required"}</Chip>
      </div>
      <div className="mt-2 flex items-center justify-between gap-2 text-[11px]">
        <span className="min-w-0 truncate text-fg-dim">{r.hashcatMode.label} · Wordlist · {r.engineChoice === "hashcat" ? "Hashcat embedded (GPU unverified)" : r.selection.backend === "cpu" ? "CPU" : "OpenCL"}</span>
        <details className="shrink-0 text-fg-muted">
          <summary className="inline-flex cursor-pointer items-center gap-1 rounded px-1 outline-none focus-visible:ring-2 focus-visible:ring-orange"
            aria-label="Recovery security and limits information">
            <Info size={13} aria-hidden="true" /> Info
          </summary>
          <p className="mt-2 max-w-sm rounded-md border border-line bg-app px-3 py-2 text-[11px] leading-relaxed">
            Native recovery needs an authorized case. Results remain masked until
            explicit OS confirmation, expire, and are not saved automatically.
            Auto uses CPU until OpenCL hardware is independently verified.
          </p>
        </details>
      </div>

      {!r.scope && <AuthorizedCaseAction activity="Password recovery" onCaseCreated={r.onCaseCreated} />}
      <div className="mt-4 space-y-1.5">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-medium text-fg-dim">Wordlist</span>
          <span className="text-[10px] text-fg-muted">{r.selectedWordlist
            ? r.selectedWordlist.size_bytes.toLocaleString() + " bytes"
            : "Required"}</span>
        </div>
        <div className="flex min-w-0 items-stretch gap-2" role="group" aria-label="Wordlist and recovery actions">
          <Button size="sm" variant="outline"
            className="h-10 min-w-0 flex-1 justify-start gap-2 rounded-md px-2.5 text-left shadow-none"
            aria-label={r.choosingWordlist ? "Selecting wordlist" : "Choose wordlist"}
            title={r.selectedWordlist ? "Replace wordlist: " + fileLabel : "Choose a local wordlist in the native file picker"}
            disabled={!r.desktop || !r.scope || r.choosingWordlist || jobInProgress || r.jobId !== null}
            onClick={() => void r.chooseWordlist()}>
            {r.selectedWordlist ? <FileText size={15} className="shrink-0" aria-hidden="true" />
              : <FileUp size={15} className="shrink-0" aria-hidden="true" />}
            <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-fg-dim"
              title={fileLabel}>{r.choosingWordlist ? "Selecting…" : fileLabel}</span>
          </Button>
          {r.busy || r.jobId === null ? (
            <Button size="icon" className="h-10 w-10 shrink-0 rounded-md"
              aria-label={r.busy ? "Starting recovery" : "Start recovery"}
              title={r.disabledReason ?? "Start selected wordlist recovery"}
              disabled={!!r.disabledReason || r.busy || r.choosingWordlist}
              onClick={() => void r.start()}>
              <Play size={16} aria-hidden="true" />
            </Button>
          ) : r.status === null ? (
            <Button size="icon" className="h-10 w-10 shrink-0 rounded-md"
              aria-label="Loading recovery job" title="Loading job" disabled>
              <Play size={16} aria-hidden="true" />
            </Button>
          ) : r.running ? (
            <Button size="icon" variant="outline" className="h-10 w-10 shrink-0 rounded-md"
              aria-label={r.pendingCancel || r.status.phase === "cancelling" ? "Stopping recovery" : "Stop recovery"}
              title="Stop recovery (cooperative cancellation)"
              disabled={r.pendingCancel || r.status.phase === "cancelling"}
              onClick={() => void r.cancel()}>
              <Square size={15} aria-hidden="true" />
            </Button>
          ) : (
            <Button size="icon" variant="outline" className="h-10 w-10 shrink-0 rounded-md"
              aria-label="Discard recovery result"
              title="Discard finished or failed results"
              disabled={r.revealing}
              onClick={() => void r.discard()}>
              <Trash2 size={15} aria-hidden="true" />
            </Button>
          )}
        </div>
        {r.wordlistError ? <p role="alert" className="text-[11px] text-err">{r.wordlistError}</p> : null}
        {statusText && !r.wordlistError
          ? <p role="status" className="pt-1 text-[11px] text-fg-muted">{statusText}</p>
          : null}
        {r.desktop && r.scope && !r.selectedWordlist && !r.wordlistError
          ? <p className="pt-1 text-[11px] text-fg-muted">Choose a wordlist to enable Start.</p>
          : null}
      </div>

      <Accordion defaultValue={[]} className="mt-3 border-t border-line/70">
        <AccordionItem value="advanced" className="border-0">
          <AccordionTrigger className="group w-full rounded-none px-0 py-2.5 text-[11px] font-medium text-fg-dim hover:text-fg focus-visible:ring-2 focus-visible:ring-orange">
            <span className="flex min-w-0 items-center gap-2">
              <SlidersHorizontal size={14} aria-hidden="true" className="text-fg-muted" />
              Advanced settings
            </span>
          </AccordionTrigger>
          <AccordionPanel className="space-y-3 border-t border-line/50 pt-3 pb-1">
            <div className="space-y-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-fg-muted">Engine</span>
              <Select ariaLabel="Recovery execution engine" value={r.engineChoice}
                onChange={(value) => {
                  if (r.jobId === null && !r.busy && (value === "rust" || value === "hashcat")) {
                    if (value === "hashcat") {
                      // Only modes with a successful fixed native KAT are
                      // advertised; never leave a stale, unverified selection.
                      const validated = r.hashcatCapability?.modes ?? [];
                      if (!validated.some((mode) => mode.algorithm === r.hashcatAlgorithm) && validated.length > 0) {
                        r.setHashcatAlgorithm(validated[0].algorithm);
                        lastHashcatMode = validated[0].algorithm;
                      }
                    }
                    r.setEngineChoice(value);
                    r.clearReveal();
                  }
                }}
                options={[
                  { value: "rust", label: "CyberDeck native Rust" },
                  ...(r.hashcatCapability?.available && !r.ruleText.trim() ? [
                    { value: "hashcat", label: "Hashcat embedded · 5 raw modes (experimental)" },
                  ] : []),
                ]} className="w-full" />
              {(
                <label className="block space-y-1">
                  <span className="text-[11px] text-fg-dim">Hash algorithm</span>
                  <Select ariaLabel="Recovery wordlist hash algorithm"
                    value={r.hashcatAlgorithm}
                    onChange={(value) => {
                      if (r.jobId !== null || r.busy) return;
                      const match = (r.engineChoice === "hashcat" ? EMBEDDED_MODES : RUST_MODES).find((mode) => mode.value === value);
                      if (!match) return;
                      r.setHashcatAlgorithm(match.value);
                      if (match.value !== "sha256" && r.backend.startsWith("open_cl:")) r.setBackend("cpu");
                      lastHashcatMode = match.value;
                      r.clearReveal();
                    }}
                    options={(r.engineChoice === "hashcat" ? EMBEDDED_MODES : RUST_MODES).filter((entry) =>
                      r.engineChoice !== "hashcat" || !r.hashcatCapability?.modes.length ||
                      r.hashcatCapability.modes.some((mode) => mode.algorithm === entry.value)
                    ).map(({value, label}) => ({value, label}))}
                    className="w-full" />
                  <span className="text-[10px] leading-relaxed text-fg-muted">
                    MD5, NTLM and MD4 all use 32 hex digits. Select the actual algorithm; digest length alone cannot identify it.
                  </span>
                </label>
              )}
              {r.engineChoice === "hashcat" && (
                <label className="block space-y-1">
                  <span className="text-[11px] text-fg-dim">Wordlist transformation</span>
                  <Select ariaLabel="Embedded Hashcat candidate preset"
                    value={r.hashcatPreset}
                    onChange={(value) => {
                      if (r.jobId !== null || r.busy) return;
                      if (value !== "plain" && value !== "uppercase" && value !== "append_one") return;
                      r.setHashcatPreset(value);
                      lastHashcatPreset = value;
                      r.clearReveal();
                    }}
                    options={[
                      { value: "plain", label: "Original wordlist" },
                      { value: "uppercase", label: "Uppercase candidates" },
                      { value: "append_one", label: "Append 1 to candidates" },
                    ]} className="w-full" />
                  <span className="text-[10px] text-fg-muted">
                    Prepared privately and bounded before native Hashcat; not arbitrary Hashcat rule scripts.
                  </span>
                </label>
              )}
              <p className="text-[10px] leading-relaxed text-fg-muted">
                {r.hashcatCapability?.detail ?? "Checking bundled Hashcat capability…"}
                {r.engineChoice === "hashcat"
                  ? " Hashcat uses its own device enumeration; no CPU/GPU speed or hardware guarantee."
                  : ""}
              </p>
            </div>
            <div className="space-y-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-fg-muted">Compute</span>
              {r.engineChoice === "hashcat" ? (
                <p className="text-[11px] leading-relaxed text-fg-muted">
                  Embedded Hashcat uses its own device selection. GPU detection,
                  kernel execution and performance remain unverified; no silent fallback.
                </p>
              ) : <Select ariaLabel="Recovery V1 backend" value={r.backend}
                onChange={(value) => {
                  if (r.jobId === null && !r.busy) { r.setBackend(value); r.clearReveal(); }
                }}
                options={[
                  { value: "auto", label: "Auto · verified GPU or CPU" },
                  { value: "cpu", label: "CPU · Native Rust" },
                  ...(r.hashcatAlgorithm === "sha256" ? r.inventory?.devices ?? [] : []).map((device) => ({
                    value: "open_cl:" + device.device_index,
                    label: "OpenCL " + device.device_index + " · " + device.name
                      + (device.hardware_verified ? "" : " (unverified)"),
                  })),
                ]} className="w-full" />}
            </div>
            {r.engineChoice === "rust" && (
              <div className="space-y-1.5">
                <label className="block text-[10px] font-semibold uppercase tracking-wider text-fg-muted"
                  htmlFor="recovery-native-rules">CPU wordlist rules · optional</label>
                <textarea id="recovery-native-rules"
                  aria-label="Native CPU wordlist transformation rules"
                  value={r.ruleText} maxLength={4096}
                  disabled={r.jobId !== null || r.busy}
                  onChange={(event) => {
                    const text = event.target.value.slice(0, 4096);
                    r.setRuleText(text);
                    if (text.trim()) r.setBackend("cpu");
                    r.clearReveal();
                  }}
                  rows={3} spellCheck={false}
                  placeholder={":\n$1\nu"}
                  className="w-full resize-y rounded-md border border-line bg-app p-2 font-mono text-xs text-fg outline-none focus-visible:ring-1 focus-visible:ring-orange disabled:opacity-50" />
                <p className="text-[10px] leading-relaxed text-fg-muted">
                  One rule per line. Example: : (unchanged), $1 (append 1), u (uppercase).
                  Supports a bounded native subset of Hashcat/John-style syntax.
                  Each rule expands every word; global attempt limits and cancellation still apply.
                  Leave blank for the original wordlist. Rules run only on CPU.
                </p>
              </div>
            )}
            <div className="space-y-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-fg-muted">Processing limits</span>
              <div className="grid grid-cols-2 gap-2">
                <label className="min-w-0 space-y-1">
                  <span className="text-[11px] text-fg-muted">Passwords to try</span>
                  <input type="number" aria-label="Recovery candidate budget" min={1} max={1000000}
                    disabled={r.jobId !== null || r.busy}
                    value={r.maxCandidates} onChange={(event) => {
                      const value = Number(event.target.value);
                      if (Number.isSafeInteger(value)) r.setMaxCandidates(Math.max(1, Math.min(1000000, value)));
                    }} className="h-8 w-full min-w-0 rounded-md border border-line bg-app px-2 font-mono text-xs text-fg outline-none focus-visible:ring-1 focus-visible:ring-orange disabled:opacity-50" />
                </label>
                <label className="min-w-0 space-y-1">
                  <span className="text-[11px] text-fg-muted">Masked results</span>
                  <input type="number" aria-label="Maximum matches" min={1} max={4}
                    disabled={r.jobId !== null || r.busy}
                    value={r.maxMatches} onChange={(event) => {
                      const value = Number(event.target.value);
                      if (Number.isSafeInteger(value)) r.setMaxMatches(Math.max(1, Math.min(4, value)));
                    }} className="h-8 w-full min-w-0 rounded-md border border-line bg-app px-2 font-mono text-xs text-fg outline-none focus-visible:ring-1 focus-visible:ring-orange disabled:opacity-50" />
                </label>
              </div>
              <p className="text-[10px] text-fg-muted">These numbers are safety limits: maximum wordlist entries checked and matching results retained. They are not password inputs.</p>
            </div>
            {r.selectedDevice !== null ? (
              <label className="block space-y-1">
                <span className="text-[11px] text-fg-muted">OpenCL batch size</span>
                <input type="number" aria-label="OpenCL batch size" min={1} max={65536}
                  disabled={r.jobId !== null || r.busy}
                  value={r.batchSize} onChange={(event) => {
                    const value = Number(event.target.value);
                    if (Number.isSafeInteger(value)) r.setBatchSize(Math.max(1, Math.min(65536, value)));
                  }} className="h-8 w-full rounded-md border border-line bg-app px-2 font-mono text-xs text-fg outline-none focus-visible:ring-1 focus-visible:ring-orange disabled:opacity-50" />
              </label>
            ) : null}
            <p className="border-t border-line/50 pt-2 text-[11px] leading-relaxed text-fg-muted">
              {r.engineChoice === "hashcat"
                ? "Wordlist with optional bounded uppercase/append-one transformation. Native Hashcat rule scripts, masks and hybrid attacks remain unavailable."
                : "Native Rust CPU recovery supports all six fast hashes and bounded streamed wordlist rules. Mask and hybrid attacks remain unavailable in this Recovery V1 screen; OpenCL is SHA-256-only and must be hardware verified."}
            </p>
          </AccordionPanel>
        </AccordionItem>
      </Accordion>
    </section>
  );
}

export function NativeRecoveryDevices() {
  const { inventory, deviceError, desktop } = useRecovery();
  return (
    <section aria-label="Recovery devices" className="space-y-2 px-3 py-3 text-[11px]">
      <div className="text-xs font-semibold text-fg">Devices</div>
      <div className="flex items-center justify-between gap-2">
        <div><span>CPU · Native Rust</span>
          <p className="text-fg-muted">{inventory?.cpu
            ? inventory.cpu.model + " · " + inventory.cpu.logical_processors + " logical processors (" + inventory.cpu.architecture + ")"
            : desktop ? "Detecting CPU resources…" : "Desktop only"}</p>
        </div><Chip tone={desktop ? "ok" : "muted"}>{desktop ? "Available" : "Desktop only"}</Chip>
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

/** Only called for a backend-authorized, native-OS-confirmed transient reveal.
 * Binary/non-UTF8 candidates retain unambiguous hex rather than mojibake.
 * Never log or persist the result; clear underlying candidate byte array.
 */
function printableRevealedCandidate(hex: string): string | null {
  if (hex.length === 0 || hex.length > 8192 ||
    hex.length % 2 !== 0 || !/^[a-fA-F0-9]+$/.test(hex)) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return /[\x00-\x1f\x7f-\x9f]/u.test(text) ? null : text;
  } catch {
    return null;
  } finally {
    bytes.fill(0);
  }
}

export function NativeRecoveryResults() {
  const r = useRecovery();
  const view = recoveryDisplay(r.scope, r.jobId, r.status, r.error, r.discarded);
  const matches = r.status?.summary?.matches ?? [];
  const revealedText = r.secretHex === null ? null : printableRevealedCandidate(r.secretHex);
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
      {isActive ? (
        <div className="flex items-center gap-3 rounded-md border border-line/70 bg-app/50 px-2.5 py-2">
          <Phosphor intensity={1} play theme="dark" label="Recovery activity"
            className="h-20 w-20 shrink-0" />
          <div className="min-w-0 space-y-1">
            <div className="text-[11px] font-semibold text-fg">Processing wordlist</div>
            <p className="text-[11px] leading-relaxed text-fg-muted">{view.detail}</p>
          </div>
        </div>
      ) : <p className="text-[11px] leading-relaxed text-fg-muted">{view.detail}</p>}
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
          {r.status.summary.engine.startsWith("embedded_hashcat")
              ? <span>Hashcat processed · count unavailable in ABI v1</span>
              : <span>{r.status.summary.tried.toLocaleString()} checked</span>}
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
            <span className="text-[11px] text-warn">{revealedText === null ? "Sensitive binary candidate · hex" : "Recovered candidate · UTF-8"} · auto-hide in 30 seconds</span>
            <Button size="sm" variant="outline" className="h-8 gap-1"
              onClick={r.clearReveal}><EyeOff size={13} aria-hidden="true" /> Hide</Button>
          </div>
          <code className="block whitespace-pre-wrap break-all font-mono text-xs text-fg">
            {revealedText ?? r.secretHex}
          </code>
          {revealedText !== null ? (
            <details className="mt-2 text-[10px] text-fg-muted">
              <summary className="cursor-pointer">Show exact candidate bytes (hex)</summary>
              <code className="mt-1 block break-all font-mono text-[11px]">{r.secretHex}</code>
            </details>
          ) : null}
        </div>
      )}
      {r.error && <p role="alert" className="text-[11px] text-err">{r.error}</p>}
    </div>
  );
}

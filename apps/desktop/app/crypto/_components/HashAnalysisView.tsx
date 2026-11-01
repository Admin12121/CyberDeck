"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Copy, Play, Wand2, X } from "lucide-react";
import { Chip, EmptyState, Field, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import { useWorkbench } from "@state/workbench";
import {
  OPERATIONS,
  detectImageMime,
  magicRecipe,
  operationById,
  runRecipe,
  type OperationCategory,
  type RecipeState,
} from "./model";
import {
  addStep,
  clearRecipe,
  initialRecipeState,
  moveStep,
  moveStepTo,
  removeStep,
  setAutoBake,
  setInput,
  setStepParam,
  toggleStep,
} from "./controller";
import { detectHashFormats } from "./model/hash";
import {
  b64,
  benchmarkDigest,
  crackCombinatorDialog,
  crackHistoryClear,
  crackHistoryDelete,
  crackHistoryList,
  crackHybridDialog,
  crackHybridReverseDialog,
  crackMask,
  crackRulesDialog,
  crackWordlistDialog,
  cryptoOp,
  deviceInfo,
  enginesDetect,
  engineAttack,
  digestFileDialog,
  isDesktop,
  kdfVerify,
  pickWordlist,
  type AttackResultWire,
  type BenchmarkWire,
  type CrackEntryWire,
  type CrackProgressWire,
  type CrackResultWire,
  type DeviceInfoWire,
  type EngineAttackResultWire,
  type EngineStatusWire,
  type FileDigestsWire,
  type OpResult,
  type WordlistInfoWire,
} from "@lib/ipc";
import type { ToolId } from "@state/tool-registry";

// ---------------------------------------------------------- hash analysis ---

function formatRate(hps: number): string {
  if (hps >= 1e9) return `${(hps / 1e9).toFixed(2)} GH/s`;
  if (hps >= 1e6) return `${(hps / 1e6).toFixed(2)} MH/s`;
  if (hps >= 1e3) return `${(hps / 1e3).toFixed(2)} kH/s`;
  return `${Math.round(hps)} H/s`;
}

interface HashFamily {
  algo: string;
  label: string;
  kind: "digest" | "kdf" | "engine-format";
}

/** Detect the hash family from the pasted string; the UI asks only when this fails. */
function detectHashFamily(input: string): HashFamily | null {
  const t = input.trim();
  if (!t) return null;
  if (/^\$2[abxy]\$/.test(t)) return { algo: "bcrypt", label: "bcrypt", kind: "kdf" };
  if (/^\$argon2id\$/.test(t)) return { algo: "argon2", label: "argon2id", kind: "kdf" };
  if (/^\$argon2(i|d)\$/.test(t)) return { algo: "argon2", label: "argon2i/d", kind: "kdf" };
  if (/^\$y\$|^@?7\$/.test(t) || /^\$y\$j9T\$/.test(t)) return { algo: "yescrypt", label: "yescrypt", kind: "kdf" };
  if (/^\$6\$/.test(t)) return { algo: "sha512crypt", label: "sha512crypt", kind: "engine-format" };
  if (/^\$5\$/.test(t)) return { algo: "sha256crypt", label: "sha256crypt", kind: "engine-format" };
  if (/^\$1\$/.test(t)) return { algo: "md5crypt", label: "md5crypt", kind: "engine-format" };
  if (/^\$apr1\$/.test(t)) return { algo: "apr1", label: "APR1 (Apache)", kind: "engine-format" };
  if (/^\$[PH]\$/.test(t)) return { algo: "phpass", label: "phpass", kind: "engine-format" };
  if (/^\$S\$/.test(t)) return { algo: "sunmd5", label: "Sun MD5 crypt", kind: "engine-format" };
  if (/^\$DCC2\$/.test(t)) return { algo: "mscash2", label: "MSCASH2 (DCC2)", kind: "engine-format" };
  if (/^\$krb5(pa|tgs|5)\$/.test(t)) return { algo: "krb5asrep", label: "Kerberos 5", kind: "engine-format" };
  if (/^\$NT\$/.test(t)) return { algo: "ntlm", label: "NTLM", kind: "digest" };
  if (/^[a-f0-9]{56}$/i.test(t)) return { algo: "sha224", label: "SHA-224 length", kind: "digest" };
  if (/^[a-f0-9]{96}$/i.test(t)) return { algo: "sha384", label: "SHA-384 length", kind: "digest" };
  if (/^[a-f0-9]{32}$/i.test(t)) return { algo: "md5", label: "MD5 / NTLM length", kind: "digest" };
  if (/^[a-f0-9]{40}$/i.test(t)) return { algo: "sha1", label: "SHA-1 length", kind: "digest" };
  if (/^[a-f0-9]{64}$/i.test(t)) return { algo: "sha256", label: "SHA-256 length", kind: "digest" };
  if (/^[a-f0-9]{128}$/i.test(t)) return { algo: "sha512", label: "SHA-512 length", kind: "digest" };
  return null;
}

export function HashAnalysisView() {
  const wb = useWorkbench();
  const [operationsWidth, setOperationsWidth] = useState(384);
  const [input, setInput] = useState("5d41402abc4b2a76b9719d911017c592");
  const [plaintext, setPlaintext] = useState("hello");
  const [algo, setAlgo] = useState("md5");
  const [verdict, setVerdict] = useState<"match" | "mismatch" | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [crackAlgo, setCrackAlgo] = useState("md5");
  const [crackMode, setCrackMode] = useState<
    "wordlist" | "rules" | "mask" | "hybrid" | "hybrid-reverse" | "combinator"
  >("wordlist");
  const [mask, setMask] = useState("?d?d?d?d");
  const [attackResult, setAttackResult] = useState<AttackResultWire | CrackResultWire | EngineAttackResultWire | null>(null);
  const [crackBusy, setCrackBusy] = useState(false);
  const [crackError, setCrackError] = useState<string | null>(null);
  const [devices, setDevices] = useState<DeviceInfoWire | null>(null);
  const [engines, setEngines] = useState<EngineStatusWire[]>([]);
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkWire | null>(null);
  const [benchmarking, setBenchmarking] = useState(false);
  const [benchmarkError, setBenchmarkError] = useState<string | null>(null);
  const [engineChoice, setEngineChoice] = useState("native");
  const [wordlist, setWordlist] = useState<WordlistInfoWire | null>(null);
  const [wordlistB, setWordlistB] = useState<WordlistInfoWire | null>(null);
  const [wordlistBusy, setWordlistBusy] = useState(false);
  const [crackProgress, setCrackProgress] = useState<CrackProgressWire | null>(null);
  const desktop = isDesktop();
  const candidates = useMemo(() => detectHashFormats(input), [input]);
  // Auto-detection decides the hash family from the pasted string itself; the
  // dropdown only exists as an override when detection fails.
  const detected = useMemo(() => detectHashFamily(input), [input]);
  const effectiveAlgo = crackAlgo === "auto" ? detected?.algo ?? null : crackAlgo;

  const [history, setHistory] = useState<CrackEntryWire[]>([]);
  const loadHistory = () => {
    if (!desktop) return;
    crackHistoryList()
      .then(setHistory)
      .catch(() => setHistory([]));
  };
  useEffect(() => {
    if (!desktop) return;
    deviceInfo()
      .then(setDevices)
      .catch(() => setDevices(null));
    enginesDetect()
      .then(setEngines)
      .catch(() => setEngines([]));
    crackHistoryList()
      .then(setHistory)
      .catch(() => setHistory([]));
  }, [desktop]);

  const chooseWordlist = async (which: "first" | "second" = "first") => {
    setWordlistBusy(true);
    try {
      const picked = await pickWordlist();
      if (which === "second") setWordlistB(picked);
      else setWordlist(picked);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setCrackError(message);
    } finally {
      setWordlistBusy(false);
    }
  };

  // engine-only formats: the crypt-family formats native code does not digest
  const ENGINE_ONLY = new Set(["sha512crypt", "sha256crypt", "md5crypt", "apr1", "phpass", "mscash2", "sunmd5", "krb5asrep"]);
  const engineOnly = effectiveAlgo !== null && ENGINE_ONLY.has(effectiveAlgo);
  const isKdfAlgo = effectiveAlgo === "bcrypt" || effectiveAlgo === "argon2" || effectiveAlgo === "scrypt" || effectiveAlgo === "pbkdf2";
  const needsWordlist =
    crackMode === "wordlist" || crackMode === "hybrid" || crackMode === "hybrid-reverse" || crackMode === "combinator";
  const needsSecondWordlist = crackMode === "combinator";
  const nativeOnlyMode =
    crackMode === "rules" || crackMode === "hybrid" || crackMode === "hybrid-reverse" || crackMode === "combinator";
  const benchAlgo = effectiveAlgo ?? (crackAlgo === "auto" ? null : crackAlgo);
  const benchUnsupported =
    benchAlgo !== null &&
    (ENGINE_ONLY.has(benchAlgo) || ["bcrypt", "argon2", "scrypt", "pbkdf2", "yescrypt"].includes(benchAlgo));
  const engineMissing = engineChoice !== "native" && !engines.find((e) => e.id === engineChoice)?.available;
  const runDisabled =
    crackBusy || !desktop || input.trim().length === 0 ||
    effectiveAlgo === null ||
    (engineChoice !== "native" && nativeOnlyMode) ||
    (engineChoice === "native" && engineOnly) ||
    (engineChoice === "native" && isKdfAlgo && crackMode !== "wordlist") ||
    (needsWordlist && !wordlist) ||
    (needsSecondWordlist && !wordlistB);

  const verify = async () => {
    setVerifying(true);
    setVerifyError(null);
    setVerdict(null);
    try {
      const trimmed = input.trim();
      // KDF hashes (bcrypt/argon2/yescrypt PHC strings) verify natively without an engine
      if (/^\$(2[abxy]|argon2|y\$|7\$)/.test(trimmed)) {
        const matched = await kdfVerify(trimmed, plaintext);
        setVerdict(matched ? "match" : "mismatch");
      } else {
        const verifyAlgo = detected && detected.kind === "digest" ? detected.algo : algo;
        const result = await cryptoOp(verifyAlgo, new TextEncoder().encode(plaintext));
        setVerdict(result.output_hex === trimmed.toLowerCase() ? "match" : "mismatch");
      }
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifying(false);
    }
  };

  const runAttack = async () => {
    setCrackBusy(true);
    setCrackError(null);
    setAttackResult(null);
    setCrackProgress(null);
    try {
      const algoForEngine = effectiveAlgo ?? crackAlgo;
      const result = await wb.trackOperation(`Recovery: ${algoForEngine}`, async () =>
        engineChoice !== "native"
          ? await engineAttack(engineChoice, algoForEngine, input, crackMode, crackMode === "mask" ? mask : undefined)
          : crackMode === "mask"
            ? await crackMask(algoForEngine, input, mask)
            : crackMode === "hybrid"
              ? await crackHybridDialog(algoForEngine, input, mask, wordlist?.path)
              : crackMode === "hybrid-reverse"
                ? await crackHybridReverseDialog(algoForEngine, input, mask, wordlist?.path)
                : crackMode === "combinator"
                  ? await crackCombinatorDialog(algoForEngine, input, wordlist?.path, wordlistB?.path)
                  : crackMode === "rules"
                    ? await crackRulesDialog(algoForEngine, input)
                    : await crackWordlistDialog(algoForEngine, input, wordlist?.path, (p) => setCrackProgress(p))
      );
      setAttackResult(result);
      if ("matches" in result && result.matches.length > 0) loadHistory();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setCrackError(message);
    } finally {
      setCrackBusy(false);
      setCrackProgress(null);
    }
  };

  const runBenchmark = async () => {
    if (!benchAlgo) return;
    setBenchmarking(true);
    setBenchmarkError(null);
    setBenchmarkResult(null);
    try {
      setBenchmarkResult(await benchmarkDigest(benchAlgo, 1000));
    } catch (err) {
      setBenchmarkError(err instanceof Error ? err.message : String(err));
    } finally {
      setBenchmarking(false);
    }
  };

  const resultView = (r: AttackResultWire | CrackResultWire | EngineAttackResultWire) => {
    const matches = "matches" in r ? r.matches : [];
    const tried = "tried" in r ? r.tried : 0;
    const source = "source" in r ? r.source : (r as CrackResultWire).wordlist;
    const threads = "threads" in r ? r.threads : null;
    return (
      <div className="mt-2 border border-line bg-app p-2 font-mono text-[10px] leading-relaxed">
        <div className="text-fg-dim">
          {source}: {tried} tried in {r.duration_ms} ms · engine {r.engine} {r.engine_version}
          {threads ? ` · ${threads} threads` : ""}
          {"cap_reached" in r && r.cap_reached ? " · candidate cap reached" : ""}
        </div>
        {"raw_tail" in r && r.raw_tail ? (
          <div className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all text-fg-muted">{r.raw_tail}</div>
        ) : null}
        {matches.length === 0 ? (
          <div className="mt-1 text-warn">no match in this run</div>
        ) : (
          <div className="mt-1 space-y-0.5">
            <div className="text-ok">{matches.length} match(es):</div>
            {matches.map((m) => (
              <div key={`${m.line_no}-${m.password}`} className="text-fg">
                line {m.line_no}: <span className="text-ok">{m.password}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <div className="flex min-w-0 flex-1 flex-col gap-px">
        <Pane title="Hash input" bodyClassName="p-2">
          <textarea
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setVerdict(null);
            }}
            spellCheck={false}
            aria-label="Hash input"
            className="h-24 w-full resize-none border border-line bg-app p-2 font-mono text-xs text-fg"
          />
          <div className="mt-2 flex items-center gap-1">
            <ToolButton disabled title="Import from file, planned arc 4">Import file</ToolButton>
            <ToolButton disabled title="Handoff from forensic scan, planned arc 4">Handoff</ToolButton>
            <span className="ml-auto font-mono text-[10px] text-fg-muted">{input.trim().length} chars</span>
          </div>
        </Pane>
        <Pane title="Identified formats (candidates, never asserted as fact)" className="max-h-44 shrink-0">
          <table className="data-table">
            <thead>
              <tr>
                <th>Format</th>
                <th>Confidence</th>
                <th>Compute</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {candidates.map((candidate) => (
                <tr key={candidate.format}>
                  <td className="text-fg">{candidate.format}</td>
                  <td>
                    <Chip tone={candidate.confidence === "high" ? "ok" : "muted"}>
                      {candidate.confidence}
                    </Chip>
                  </td>
                  <td><span className="text-orange">GPU/CPU</span></td>
                  <td className="text-fg-muted">{candidate.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Pane>
        <CrackedHistory
          history={history}
          desktop={desktop}
          onReload={loadHistory}
        />
      </div>
      <Resizer direction="horizontal" flip ariaLabel="Resize recovery operations" value={operationsWidth} onChange={setOperationsWidth} min={280} max={560} />
      <Pane title="Operations" className="shrink-0" style={{ width: operationsWidth }} bodyClassName="overflow-auto">
        <div className="border-b border-line p-2">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-fg-muted">Verify candidate</div>
          <div className="flex items-center gap-1">
            <Select
              value={algo}
              onChange={(v) => {
                setAlgo(v);
                setVerdict(null);
              }}
              options={[
                { value: "md5", label: "MD5" },
                { value: "sha1", label: "SHA-1" },
                { value: "sha256", label: "SHA-256" },
                { value: "sha512", label: "SHA-512" },
              ]}
              ariaLabel="Verification algorithm"
            />
            <TextInput value={plaintext} onChange={(value) => {
              setPlaintext(value);
              setVerdict(null);
            }} placeholder="candidate password" ariaLabel="Candidate password" className="min-w-0 flex-1" />
            <ToolButton tone="primary" onClick={() => void verify()} disabled={verifying || plaintext.length === 0}>
              <Play size={11} /> {verifying ? "…" : "Verify"}
            </ToolButton>
          </div>
          <div className="mt-2">
            {verdict === "match" ? <Chip tone="ok">verified: digest matches</Chip> : null}
            {verdict === "mismatch" ? <Chip tone="err">mismatch: not this plaintext</Chip> : null}
            {verifyError ? <span className="font-mono text-[10px] text-err">{verifyError}</span> : null}
          </div>
        </div>
        <div className="border-b border-line p-2">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-wider text-fg-muted">Recovery</span>
            <Chip tone={desktop ? "ok" : "muted"}>{desktop ? "live" : "desktop"}</Chip>
          </div>
          <div className="mb-1 flex items-center gap-1">
            <span className="text-[10px] uppercase tracking-wider text-fg-muted">detected</span>
            {detected ? (
              <Chip tone="ok">{detected.label} ({detected.kind})</Chip>
            ) : (
              <Chip tone="muted">unrecognized: choose below</Chip>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Select
              value={crackAlgo}
              onChange={(v) => {
                setCrackAlgo(v);
                setAttackResult(null);
              }}
              options={[
                { value: "auto", label: detected ? `auto (${detected.algo})` : "auto (detect)" },
                { value: "md5", label: "MD5" },
                { value: "sha1", label: "SHA-1" },
                { value: "sha224", label: "SHA-224" },
                { value: "sha256", label: "SHA-256" },
                { value: "sha384", label: "SHA-384" },
                { value: "sha512", label: "SHA-512" },
                { value: "ntlm", label: "NTLM (native)" },
                { value: "md4", label: "MD4" },
                { value: "bcrypt", label: "bcrypt (native KDF)" },
                { value: "argon2", label: "argon2 (native KDF)" },
                { value: "scrypt", label: "scrypt (native KDF)" },
                { value: "pbkdf2", label: "pbkdf2 (native KDF)" },
                { value: "yescrypt", label: "yescrypt (engine)" },
                { value: "sha512crypt", label: "sha512crypt (engine)" },
                { value: "sha256crypt", label: "sha256crypt (engine)" },
                { value: "md5crypt", label: "md5crypt (engine)" },
                { value: "apr1", label: "APR1 (engine)" },
                { value: "phpass", label: "phpass (engine)" },
                { value: "mscash2", label: "MSCASH2 (engine)" },
                { value: "sunmd5", label: "Sun MD5 (engine)" },
                { value: "krb5asrep", label: "Kerberos 5 (engine)" },
              ]}
              ariaLabel="Recovery algorithm"
              className="min-w-0 flex-1"
            />
          </div>
          <div className="flex items-center gap-2">
            <Select
              value={engineChoice}
              onChange={(v) => {
                setEngineChoice(v);
                setAttackResult(null);
              }}
              options={[
                { value: "native", label: "native (rust)" },
                ...engines.map((e) => ({
                  value: e.id,
                  label: `${e.label} ${e.available ? e.version : "(not detected)"}`,
                })),
              ]}
              ariaLabel="Recovery engine"
              className="min-w-0 flex-1"
            />
            <Select
              value={crackMode}
              onChange={(v) => {
                setCrackMode(v as typeof crackMode);
                setAttackResult(null);
              }}
              options={[
                { value: "wordlist", label: "Wordlist" },
                { value: "rules", label: "Wordlist + rules" },
                { value: "mask", label: "Mask" },
                { value: "hybrid", label: "Wordlist + mask" },
                { value: "hybrid-reverse", label: "Mask + wordlist" },
                { value: "combinator", label: "Wordlist + wordlist" },
              ]}
              ariaLabel="Attack mode"
              className="shrink-0"
            />
          </div>
          {crackMode === "mask" || crackMode === "hybrid" || crackMode === "hybrid-reverse" ? (
            <div className="mt-1 flex items-center gap-1">
              <TextInput value={mask} onChange={setMask} placeholder="?d?d?d?d" ariaLabel="Mask pattern" className="min-w-0 flex-1" />
              <span className="font-mono text-[10px] text-fg-muted">?l ?u ?d ?s ?a</span>
            </div>
          ) : null}
          {crackMode !== "mask" ? (
            <div className="mt-1 space-y-1">
              <div className="flex items-center gap-1">
                <ToolButton
                  onClick={() => void chooseWordlist("first")}
                  disabled={wordlistBusy || !desktop}
                  title={desktop ? "Pick the wordlist file once; it is reused for every run" : "Wordlist picking requires the desktop runtime"}
                >
                  {wordlistBusy ? "reading…" : crackMode === "combinator" ? "Choose first wordlist…" : "Choose wordlist…"}
                </ToolButton>
                {wordlist ? (
                  <>
                    <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-fg-dim" title={wordlist.path}>
                      {wordlist.name} ({Math.round(wordlist.size / 1024)} KB)
                    </span>
                    <button type="button" onClick={() => setWordlist(null)} aria-label="Clear wordlist" className="text-fg-muted hover:text-fg">×</button>
                  </>
                ) : (
                  <span className="font-mono text-[10px] text-fg-muted">none selected</span>
                )}
              </div>
              {crackMode === "combinator" ? (
                <div className="flex items-center gap-1">
                  <ToolButton
                    onClick={() => void chooseWordlist("second")}
                    disabled={wordlistBusy || !desktop}
                    title={desktop ? "Second wordlist; each word is appended after the first" : "Wordlist picking requires the desktop runtime"}
                  >
                    {wordlistBusy ? "reading…" : "Choose second wordlist…"}
                  </ToolButton>
                  {wordlistB ? (
                    <>
                      <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-fg-dim" title={wordlistB.path}>
                        {wordlistB.name} ({Math.round(wordlistB.size / 1024)} KB)
                      </span>
                      <button type="button" onClick={() => setWordlistB(null)} aria-label="Clear second wordlist" className="text-fg-muted hover:text-fg">×</button>
                    </>
                  ) : (
                    <span className="font-mono text-[10px] text-fg-muted">none selected</span>
                  )}
                </div>
              ) : null}
            </div>
          ) : null}
          {crackBusy && crackProgress ? (
            <div className="mt-1">
              <div className="mb-0.5 flex items-center justify-between font-mono text-[10px] text-fg-muted">
                <span>{crackProgress.tried} / {crackProgress.total} candidates</span>
                <span>{crackProgress.percent}%</span>
              </div>
              <div className="h-1.5 w-full border border-line bg-app">
                <div className="h-full bg-orange" style={{ width: `${crackProgress.percent}%` }} />
              </div>
            </div>
          ) : null}
          <div className="mt-1 flex items-center gap-1">
            <ToolButton
              tone="primary"
              onClick={() => void runAttack()}
              disabled={runDisabled}
              title={
                !desktop
                  ? "Recovery sessions require the desktop runtime"
                  : effectiveAlgo === null
                    ? "Hash not recognized: pick the algorithm manually"
                    : engineChoice === "native" && engineOnly
                      ? "NTLM runs through hashcat or john; pick an external engine"
                      : engineChoice === "native" && isKdfAlgo && crackMode !== "wordlist"
                        ? "KDF hashes: wordlist mode only (they verify at password-hashing speed)"
                        : engineChoice !== "native" && nativeOnlyMode
                          ? "External engines: use wordlist or mask this arc"
                          : engineChoice !== "native" && engineMissing
                            ? "Engine not detected; bundled binaries arrive with the installer"
                            : needsWordlist && !wordlist
                              ? "Choose a wordlist first"
                              : needsSecondWordlist && !wordlistB
                                ? "Choose the second wordlist first"
                                : "Runs in the selected engine"
              }
            >
              {crackBusy ? "cracking…" : "Run attack"}
            </ToolButton>
            {engineOnly ? <Chip tone="muted">engine format</Chip> : null}
            {isKdfAlgo && engineChoice === "native" ? <Chip tone="orange">KDF slow by design</Chip> : null}
          </div>
          {crackError ? <div className="mt-1 font-mono text-[10px] text-err">{crackError}</div> : null}
          {attackResult ? resultView(attackResult) : null}
        </div>
                <div className="border-b border-line p-2">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-wider text-fg-muted">Devices & engines</span>
            <Chip tone={desktop ? "ok" : "muted"}>{desktop ? "probed" : "desktop"}</Chip>
          </div>
          {desktop ? (
            <div className="space-y-0.5 font-mono text-[10px] text-fg-dim">
              <div>
                cpu: {devices ? `${devices.cpu_cores}× ${devices.cpu_arch}` : "…"} · cyberdeck-crypto <span className="text-ok">active</span>
              </div>
              <div className="flex flex-wrap items-center gap-1">
                <ToolButton
                  onClick={() => void runBenchmark()}
                  disabled={benchmarking || benchAlgo === null || benchUnsupported}
                  title={
                    benchAlgo === null
                      ? "Hash not recognized: pick the algorithm manually"
                      : benchUnsupported
                        ? "KDF and engine-only formats benchmark in their own engine"
                        : "Measure the native digest rate for the selected algorithm"
                  }
                >
                  {benchmarking ? "measuring…" : benchAlgo ? `Benchmark ${benchAlgo}` : "Benchmark"}
                </ToolButton>
                {benchmarkResult ? (
                  <span className="text-ok">
                    {benchmarkResult.algo}: {formatRate(benchmarkResult.hashes_per_second)} · {benchmarkResult.duration_ms} ms
                  </span>
                ) : null}
                {benchmarkError ? <span className="text-err">{benchmarkError}</span> : null}
              </div>
              {devices?.gpu_devices.map((gpu) => (
                <div key={gpu.name} className="border border-line bg-app px-2 py-1">
                  <div className="text-fg">{gpu.name} <span className="text-warn">native GPU engine pending</span></div>
                  <div className="text-fg-muted">driver {gpu.driver_version} · vram {gpu.memory_total} · compute cap {gpu.compute_cap}</div>
                  <div className="text-fg-muted">{gpu.backend}</div>
                </div>
              ))}
              {devices && devices.gpu_devices.length === 0 ? <div>gpu: not detected via NVIDIA tooling <span className="text-warn">native GPU engine pending</span></div> : null}
              {engines.map((engine) => (
                <div key={engine.id}>
                  engine: {engine.label} {engine.version || "—"} · {engine.license} · {engine.available ? `available (${engine.source})` : "not detected"}{" "}
                  {engine.available ? <span className="text-warn">optional external adapter</span> : <span className="text-fg-muted">not installed</span>}
                </div>
              ))}
              {devices ? <div className="text-fg-muted">{devices.planner_note}</div> : null}
            </div>
          ) : (
            <div className="font-mono text-[10px] text-fg-muted">device and engine probing run in the desktop runtime</div>
          )}
        </div>
        </Pane>
    </div>
  );
}



// --------------------------------------------------------- cracked history ---

const HISTORY_PAGE = 20;

export function CrackedHistory({
  history,
  desktop,
  onReload,
}: {
  history: CrackEntryWire[];
  desktop: boolean;
  onReload: () => void;
}) {
  const [visible, setVisible] = useState(HISTORY_PAGE);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const onScroll = () => {
    const el = listRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 24) {
      setVisible((v) => Math.min(v + HISTORY_PAGE, history.length));
    }
  };

  return (
    <Pane
      title={`Cracked history (${history.length})`}
      className="min-h-0 flex-1"
      actions={
        history.length > 0 ? (
          <ToolButton
            onClick={() => {
              void crackHistoryClear().then(onReload);
            }}
            title="Delete every recovered pair"
          >
            Clear all
          </ToolButton>
        ) : undefined
      }
    >
      {!desktop ? (
        <div className="p-3 font-mono text-[10px] leading-relaxed text-fg-muted">
          recovered pairs persist here until you delete them; cracking runs in the desktop runtime
        </div>
      ) : history.length === 0 ? (
        <div className="p-3 font-mono text-[10px] leading-relaxed text-fg-muted">
          recovered pairs persist here until you delete them
        </div>
      ) : (
        <div ref={listRef} onScroll={onScroll} className="h-full overflow-auto p-1">
          {history.slice(0, visible).map((entry) => {
            const expanded = expandedId === entry.id;
            return (
              <div key={entry.id} className="mb-px border border-line bg-app">
                <button
                  type="button"
                  onClick={() => setExpandedId(expanded ? null : entry.id)}
                  className="flex w-full items-center gap-2 px-2 py-1 text-left hover:bg-raised"
                >
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px]">
                    <span className="text-ok">{entry.password}</span>
                    <span className="text-fg-muted"> · {entry.algo} · {entry.hash.slice(0, 16)}…</span>
                  </span>
                  <button
                    type="button"
                    aria-label="Delete entry"
                    onClick={(e) => {
                      e.stopPropagation();
                      void crackHistoryDelete(entry.id).then(() => {
                        onReload();
                        setVisible((v) => Math.max(HISTORY_PAGE, v - 1));
                      });
                    }}
                    className="shrink-0 text-fg-muted opacity-0 hover:text-err group-hover:opacity-100"
                  >
                    ×
                  </button>
                </button>
                {expanded ? (
                  <div className="border-t border-line px-2 py-1.5 font-mono text-[10px] leading-relaxed">
                    <div className="text-[11px] text-ok">cracked value: {entry.password}</div>
                    <div className="mt-1 break-all text-fg-dim">hash: {entry.hash}</div>
                    <div className="mt-1 text-fg-muted">
                      algo: {entry.algo} · engine: {entry.engine}
                      {entry.wordlist ? ` · wordlist: ${entry.wordlist}` : ""}
                    </div>
                    <div className="text-fg-muted">recovered: {new Date(Number(entry.recovered_at)).toLocaleString()}</div>
                  </div>
                ) : null}
              </div>
            );
          })}
          {visible < history.length ? (
            <button
              type="button"
              onClick={() => setVisible((v) => Math.min(v + HISTORY_PAGE, history.length))}
              className="block w-full px-2 py-1 text-left font-mono text-[10px] text-fg-muted hover:text-fg"
            >
              load more ({history.length - visible} remaining)
            </button>
          ) : null}
        </div>
      )}
    </Pane>
  );
}


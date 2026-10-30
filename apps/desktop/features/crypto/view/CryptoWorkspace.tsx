"use client";
/**
 * Crypto feature view layer.
 * Recipes: the transformation workflow (Operations | Recipe | Input over
 * Output) with live auto-bake (Master Plan §5.4). Operations drag into the
 * recipe, steps drag to reorder and take inline parameters, columns resize
 * between clamped bounds, and image outputs render a preview. Hash Analysis:
 * real format identification and candidate verification. Crypto Ops: native
 * digests with provenance.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Copy, Play, Wand2, X } from "lucide-react";
import { Chip, EmptyState, Field, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import {
  OPERATIONS,
  detectImageMime,
  magicRecipe,
  operationById,
  runRecipe,
  type OperationCategory,
  type RecipeState,
} from "../model";
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
} from "../controller";
import { detectHashFormats } from "../model/hash";
import { b64, crackMask, crackRulesDialog, crackWordlistDialog, cryptoOp, deviceInfo, enginesDetect, engineAttack, digestFileDialog, isDesktop, kdfVerify, type AttackResultWire, type CrackResultWire, type DeviceInfoWire, type EngineAttackResultWire, type EngineStatusWire, type FileDigestsWire, type OpResult } from "@lib/ipc";
import type { ToolId } from "@features/registry";

const CATEGORY_ORDER: OperationCategory[] = ["encoding", "transforms", "parsing", "formatting"];

/** MIME type used by drag-and-drop between the catalog and the recipe. */
const OP_MIME = "application/x-hacktool-op";
const STEP_MIME = "application/x-hacktool-step";

export function CryptoWorkspace({ tool }: { tool: ToolId }) {
  if (tool === "crypto.hash") return <HashAnalysisView />;
  if (tool === "crypto.ops") return <CryptoOpsView />;
  return <RecipesView />;
}

// ---------------------------------------------------------------- recipes ---

function RecipesView() {
  const [state, setState] = useState<RecipeState>(initialRecipeState);
  const [search, setSearch] = useState("");
  const [committed, setCommitted] = useState<ReturnType<typeof runRecipe> | null>(null);
  const [showHex, setShowHex] = useState(false);
  const [opsWidth, setOpsWidth] = useState(224);
  const [recipeWidth, setRecipeWidth] = useState(256);
  // null keeps input and output at an even 50/50 split; dragging pins px.
  const [inputHeight, setInputHeight] = useState<number | null>(null);
  const [magicPath, setMagicPath] = useState<string[] | null>(null);
  const inputPaneRef = useRef<HTMLDivElement>(null);
  const [dropIndex, setDropIndex] = useState<number | null>(null);
  // elapsedMs is real timing, which differs between prerender and hydration,
  // so display it only after mount to keep the first paint stable.
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const live = useMemo(() => runRecipe(state.input, state.steps), [state.input, state.steps]);
  const result = state.autoBake ? live : committed;
  const inputBytes = useMemo(() => new TextEncoder().encode(state.input).length, [state.input]);
  const imageMime = useMemo(
    () => (result && !result.error ? detectImageMime(result.outputBytes) : null),
    [result],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return OPERATIONS.filter((op) => !q || op.label.toLowerCase().includes(q) || op.id.includes(q));
  }, [search]);

  const dropOp = (e: React.DragEvent, index: number | null) => {
    e.preventDefault();
    setDropIndex(null);
    const opId = e.dataTransfer.getData(OP_MIME);
    const fromRaw = e.dataTransfer.getData(STEP_MIME);
    if (opId) {
      setState((s) => {
        const withStep = addStep(s, opId);
        return index === null ? withStep : moveStepTo(withStep, withStep.steps.length - 1, index);
      });
    } else if (fromRaw !== "") {
      const from = Number.parseInt(fromRaw, 10);
      if (!Number.isNaN(from)) {
        setState((s) => moveStepTo(s, from, index === null ? s.steps.length : index));
      }
    }
  };

  const dropAllowed = (e: React.DragEvent) =>
    e.dataTransfer.types.includes(OP_MIME) || e.dataTransfer.types.includes(STEP_MIME);

  const applyMagic = () => {
    const { steps, path } = magicRecipe(state.input);
    setMagicPath(path.length > 0 ? path : null);
    setState((s) => ({ ...s, steps }));
  };

  return (
    <div className="flex h-full min-h-0 bg-line">
      <Pane title="Operations" className="shrink-0" bodyClassName="p-1" style={{ width: opsWidth }}>
        <div className="p-1">
          <TextInput value={search} onChange={setSearch} placeholder="search operations…" ariaLabel="Search operations" className="w-full" />
        </div>
        {CATEGORY_ORDER.map((category) => {
          const ops = filtered.filter((op) => op.category === category);
          if (ops.length === 0) return null;
          return (
            <div key={category} className="mb-1">
              <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-fg-muted">{category}</div>
              {ops.map((op) => (
                <button
                  key={op.id}
                  type="button"
                  draggable
                  onDragStart={(e) => {
                    e.dataTransfer.setData(OP_MIME, op.id);
                    e.dataTransfer.effectAllowed = "copy";
                  }}
                  title={`${op.description} (drag into the recipe, or click to append)`}
                  onClick={() => setState((s) => addStep(s, op.id))}
                  className="block w-full cursor-grab truncate px-2 py-1 text-left font-mono text-[11px] text-fg-dim hover:bg-raised hover:text-fg active:cursor-grabbing"
                >
                  {op.label}
                </button>
              ))}
            </div>
          );
        })}
      </Pane>

      <Resizer
        direction="horizontal"
        ariaLabel="Resize operations column"
        value={opsWidth}
        onChange={setOpsWidth}
        min={170}
        max={340}
      />

      <Pane
        title={`Recipe: ${state.steps.length} step${state.steps.length === 1 ? "" : "s"}`}
        className="shrink-0"
        style={{ width: recipeWidth }}
        bodyClassName="flex flex-col"
        actions={
          <label className="flex cursor-pointer items-center gap-1 font-mono text-[10px] text-fg-dim">
            <input
              type="checkbox"
              checked={state.autoBake}
              onChange={(e) => setState((s) => setAutoBake(s, e.target.checked))}
              className="accent-[var(--color-orange)]"
            />
            auto-bake
          </label>
        }
      >
        <div
          className={`min-h-0 flex-1 overflow-auto p-1 ${dropIndex !== null ? "ring-1 ring-inset ring-orange/60" : ""}`}
          onDragOver={(e) => {
            if (dropAllowed(e)) {
              e.preventDefault();
              e.dataTransfer.dropEffect = e.dataTransfer.types.includes(OP_MIME) ? "copy" : "move";
            }
          }}
          onDragLeave={(e) => {
            if (e.currentTarget === e.target) setDropIndex(null);
          }}
          onDrop={(e) => dropOp(e, null)}
        >
          {state.steps.length === 0 ? (
            <div className="p-3 font-mono text-[11px] leading-relaxed text-fg-muted">
              Drop operations here, or add them from the catalog.
              <br />
              Steps apply top to bottom.
            </div>
          ) : (
            state.steps.map((step, index) => (
              <StepRow
                key={`${step.opId}-${index}`}
                step={step}
                index={index}
                isDropTarget={dropIndex === index}
                onToggle={() => setState((s) => toggleStep(s, index))}
                onMoveUp={() => setState((s) => moveStep(s, index, -1))}
                onMoveDown={() => setState((s) => moveStep(s, index, 1))}
                onRemove={() => setState((s) => removeStep(s, index))}
                onParam={(value) => setState((s) => setStepParam(s, index, value))}
                onDragOverRow={(e) => {
                  if (dropAllowed(e)) {
                    e.preventDefault();
                    e.stopPropagation();
                    e.dataTransfer.dropEffect = "move";
                    setDropIndex(index);
                  }
                }}
                onDropRow={(e) => {
                  e.stopPropagation();
                  dropOp(e, index);
                }}
              />
            ))
          )}
        </div>
        <div className="flex items-center gap-1 border-t border-line p-1">
          <ToolButton onClick={applyMagic} title="Detect stacked encodings and build the decode recipe">
            <Wand2 size={11} /> Magic
          </ToolButton>
          <ToolButton onClick={() => setCommitted(runRecipe(state.input, state.steps))} disabled={state.autoBake} title="Run recipe manually">
            <Play size={11} /> Bake
          </ToolButton>
          <ToolButton onClick={() => {
            setState((s) => clearRecipe(s));
            setMagicPath(null);
          }}>
            Clear
          </ToolButton>
        </div>
        {magicPath ? (
          <div className="border-t border-line px-2 py-1 font-mono text-[10px] leading-relaxed text-fg-muted">
            magic: {magicPath.join(" → ") || "no recognizable encoding"}
          </div>
        ) : null}
      </Pane>

      <Resizer
        direction="horizontal"
        ariaLabel="Resize recipe column"
        value={recipeWidth}
        onChange={setRecipeWidth}
        min={190}
        max={380}
      />

      <div className="flex min-w-0 flex-1 flex-col bg-line">
        <div
          ref={inputPaneRef}
          className={inputHeight === null ? "flex min-h-0 flex-1" : "flex shrink-0"}
          style={inputHeight === null ? undefined : { height: inputHeight }}
        >
          <Pane
            title="Input"
            className="min-h-0 flex-1"
            bodyClassName="p-0"
            actions={<Chip>{inputBytes} bytes</Chip>}
          >
            <textarea
              value={state.input}
              onChange={(e) => setState((s) => setInput(s, e.target.value))}
              spellCheck={false}
              aria-label="Recipe input"
              className="h-full w-full resize-none bg-app p-2 font-mono text-xs text-fg focus:outline-none"
            />
          </Pane>
        </div>

        <Resizer
          direction="vertical"
          ariaLabel="Resize input pane"
          value={inputHeight ?? 0}
          onChange={setInputHeight}
          min={120}
          max={600}
          onDragStart={() => {
            // 50/50 mode has no pixel size yet; measure so the first move
            // applies a delta from the real height instead of collapsing.
            if (inputHeight === null) {
              const measured = Math.round(inputPaneRef.current?.getBoundingClientRect().height ?? 0);
              setInputHeight(measured);
              return measured;
            }
          }}
        />

        <Pane
          title="Output"
          className="min-h-0 flex-1"
          bodyClassName="flex min-h-0 flex-col p-0"
          actions={
            <>
              <button
                type="button"
                onClick={() => setShowHex((v) => !v)}
                className={`border px-1.5 font-mono text-[10px] uppercase ${showHex ? "border-orange/50 text-orange" : "border-line text-fg-muted"}`}
              >
                hex
              </button>
              <ToolButton onClick={() => void navigator.clipboard?.writeText(result?.output ?? "")} title="Copy output">
                <Copy size={11} />
              </ToolButton>
            </>
          }
        >
          {result?.error ? (
            <div className="min-h-0 flex-1 overflow-auto p-2">
              <div className="border border-err/50 bg-err/10 p-2 font-mono text-[11px] leading-relaxed text-err">
                <div className="uppercase tracking-wide">step {result.error.stepIndex + 1} failed: {result.error.opId}</div>
                <div className="mt-1 text-fg-dim">{result.error.message}</div>
              </div>
            </div>
          ) : result ? (
            showHex ? (
              <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-xs text-fg">
                {Array.from(result.outputBytes, (b) => b.toString(16).padStart(2, "0")).join(" ")}
              </pre>
            ) : imageMime ? (
              <div className="flex min-h-0 flex-1 flex-col">
                <div className="flex min-h-0 flex-1 items-center justify-center overflow-auto bg-app p-3">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={`data:${imageMime};base64,${b64.encode(result.outputBytes)}`}
                    alt="recipe output preview"
                    className="max-h-full max-w-full object-contain"
                  />
                </div>
                <div className="shrink-0 border-t border-line px-2 py-0.5 font-mono text-[10px] text-fg-muted">
                  {imageMime} preview · {result.byteLength} bytes
                </div>
              </div>
            ) : (
              <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-xs text-fg">
                {result.output || "(empty output)"}
              </pre>
            )
          ) : (
            <div className="min-h-0 flex-1 overflow-hidden">
              <EmptyState title="No result yet" detail="Enable auto-bake or press Bake to evaluate the recipe." badge="recipes" />
            </div>
          )}
          <div className="shrink-0 border-t border-line px-2 py-0.5 font-mono text-[10px] text-fg-muted">
            {result ? `${result.byteLength} bytes out${mounted ? ` · ${result.elapsedMs.toFixed(1)} ms` : ""}` : "n/a"}
          </div>
        </Pane>
      </div>
    </div>
  );
}

interface StepRowProps {
  step: RecipeState["steps"][number];
  index: number;
  isDropTarget: boolean;
  onToggle: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onRemove: () => void;
  onParam: (value: string) => void;
  onDragOverRow: (e: React.DragEvent) => void;
  onDropRow: (e: React.DragEvent) => void;
}

function StepRow({ step, index, isDropTarget, onToggle, onMoveUp, onMoveDown, onRemove, onParam, onDragOverRow, onDropRow }: StepRowProps) {
  const op = operationById(step.opId);
  return (
    <div
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData(STEP_MIME, String(index));
        e.dataTransfer.effectAllowed = "move";
      }}
      onDragOver={onDragOverRow}
      onDrop={onDropRow}
      className={`group mb-px flex items-center gap-2 border border-line bg-app px-2 py-1.5 ${step.enabled ? "" : "opacity-50"} ${
        isDropTarget ? "border-t-orange" : ""
      }`}
    >
      <span aria-hidden title="Drag to reorder" className="cursor-grab select-none font-mono text-[13px] leading-none text-fg-muted group-hover:text-fg-dim">⠿</span>
      <input
        type="checkbox"
        checked={step.enabled}
        onChange={onToggle}
        aria-label={`Toggle step ${index + 1}`}
        className="accent-[var(--color-orange)]"
      />
      <span className="flex-1 truncate font-mono text-[11px]" title={op?.description}>
        {op?.label ?? step.opId}
      </span>
      {op?.takesParam ? (
        <input
          value={step.param ?? ""}
          onChange={(e) => onParam(e.target.value)}
          title={`${op.paramLabel ?? "parameter"} for ${op.label}`}
          aria-label={`${op.label} parameter`}
          draggable={false}
          className="h-5 w-16 shrink-0 border border-line bg-app px-1 font-mono text-[10px] text-fg focus:border-orange focus:outline-none"
        />
      ) : null}
      <button type="button" title="Move up" onClick={onMoveUp} className="text-fg-muted opacity-0 transition-opacity group-hover:opacity-100 hover:text-fg">
        <ArrowUp size={14} />
      </button>
      <button type="button" title="Move down" onClick={onMoveDown} className="text-fg-muted opacity-0 transition-opacity group-hover:opacity-100 hover:text-fg">
        <ArrowDown size={14} />
      </button>
      <button type="button" title="Remove" onClick={onRemove} className="text-fg-muted opacity-0 transition-opacity group-hover:opacity-100 hover:text-err">
        <X size={14} />
      </button>
    </div>
  );
}

// ---------------------------------------------------------- hash analysis ---

function HashAnalysisView() {
  const [input, setInput] = useState("5d41402abc4b2a76b9719d911017c592");
  const [plaintext, setPlaintext] = useState("hello");
  const [algo, setAlgo] = useState("md5");
  const [verdict, setVerdict] = useState<"match" | "mismatch" | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [crackAlgo, setCrackAlgo] = useState("md5");
  const [crackMode, setCrackMode] = useState<"wordlist" | "rules" | "mask">("wordlist");
  const [mask, setMask] = useState("?d?d?d?d");
  const [attackResult, setAttackResult] = useState<AttackResultWire | CrackResultWire | EngineAttackResultWire | null>(null);
  const [crackBusy, setCrackBusy] = useState(false);
  const [crackError, setCrackError] = useState<string | null>(null);
  const [devices, setDevices] = useState<DeviceInfoWire | null>(null);
  const [engines, setEngines] = useState<EngineStatusWire[]>([]);
  const [engineChoice, setEngineChoice] = useState("native");
  const desktop = isDesktop();
  const candidates = useMemo(() => detectHashFormats(input), [input]);

  useEffect(() => {
    if (!desktop) return;
    deviceInfo()
      .then(setDevices)
      .catch(() => setDevices(null));
    enginesDetect()
      .then(setEngines)
      .catch(() => setEngines([]));
  }, [desktop]);

  // engine-only digest families and KDF-native rules
  const engineOnly = algo === "ntlm";
  const isKdfAlgo = crackAlgo === "bcrypt" || crackAlgo === "argon2";
  const runDisabled =
    crackBusy || !desktop || input.trim().length === 0 ||
    (engineChoice !== "native" && crackMode === "rules") ||
    (engineChoice === "native" && engineOnly) ||
    (engineChoice === "native" && isKdfAlgo && crackMode !== "wordlist");

  const verify = async () => {
    setVerifying(true);
    setVerifyError(null);
    setVerdict(null);
    try {
      const trimmed = input.trim();
      // KDF hashes (bcrypt/argon2 PHC strings) verify natively without an engine
      if (/^\$(2[abxy]|argon2)/.test(trimmed)) {
        const matched = await kdfVerify(trimmed, plaintext);
        setVerdict(matched ? "match" : "mismatch");
      } else {
        const result = await cryptoOp(algo, new TextEncoder().encode(plaintext));
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
    try {
      const result =
        engineChoice !== "native"
          ? await engineAttack(engineChoice, crackAlgo, input, crackMode, crackMode === "mask" ? mask : undefined)
          : crackMode === "mask"
            ? await crackMask(crackAlgo, input, mask)
            : crackMode === "rules"
              ? await crackRulesDialog(crackAlgo, input)
              : await crackWordlistDialog(crackAlgo, input);
      setAttackResult(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setCrackError(message);
    } finally {
      setCrackBusy(false);
    }
  };

  const resultView = (r: AttackResultWire | CrackResultWire | EngineAttackResultWire) => {
    const matches = "matches" in r ? r.matches : [];
    const tried = "tried" in r ? r.tried : 0;
    const source = "source" in r ? r.source : (r as CrackResultWire).wordlist;
    const engineLine = "engine_version" in r && r.engine !== "hacktool-crypto"
      ? `engine ${r.engine} ${r.engine_version}`
      : `engine ${r.engine} ${r.engine_version}`;
    return (
      <div className="mt-2 border border-line bg-app p-2 font-mono text-[10px] leading-relaxed">
        <div className="text-fg-dim">
          {source}: {tried} tried in {r.duration_ms} ms · {engineLine}
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
            className="h-24 w-full resize-none border border-line bg-app p-2 font-mono text-xs text-fg focus:border-orange focus:outline-none"
          />
          <div className="mt-2 flex items-center gap-1">
            <ToolButton disabled title="Import from file, planned arc 4">Import file</ToolButton>
            <ToolButton disabled title="Handoff from forensic scan, planned arc 4">Handoff</ToolButton>
            <span className="ml-auto font-mono text-[10px] text-fg-muted">{input.trim().length} chars</span>
          </div>
        </Pane>
        <Pane title="Identified formats (candidates, never asserted as fact)" className="flex-1">
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
                    <Chip tone={candidate.confidence === "high" ? "ok" : candidate.confidence === "medium" ? "blue" : "muted"}>
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
      </div>
      <Pane title="Operations" className="w-96 shrink-0" bodyClassName="overflow-auto">
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
          <div className="flex items-center gap-1">
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
              ]}
              ariaLabel="Attack mode"
            />
            <Select
              value={crackAlgo}
              onChange={(v) => {
                setCrackAlgo(v);
                setAttackResult(null);
              }}
              options={[
                { value: "md5", label: "MD5" },
                { value: "sha1", label: "SHA-1" },
                { value: "sha256", label: "SHA-256" },
                { value: "sha512", label: "SHA-512" },
                { value: "ntlm", label: "NTLM (engine)" },
                { value: "bcrypt", label: "bcrypt (native KDF)" },
                { value: "argon2", label: "argon2 (native KDF)" },
              ]}
              ariaLabel="Recovery algorithm"
            />
          </div>
          {crackMode === "mask" ? (
            <div className="mt-1 flex items-center gap-1">
              <TextInput value={mask} onChange={setMask} placeholder="?d?d?d?d" ariaLabel="Mask pattern" className="min-w-0 flex-1" />
              <span className="font-mono text-[10px] text-fg-muted">?l ?u ?d ?s ?a</span>
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
                  : engineChoice === "native" && engineOnly
                    ? "NTLM runs through hashcat or john; pick an external engine"
                    : engineChoice === "native" && isKdfAlgo && crackMode !== "wordlist"
                      ? "KDF hashes: wordlist mode only (they verify at password-hashing speed)"
                      : engineChoice !== "native" && crackMode === "rules"
                        ? "External engines: use wordlist or mask this arc"
                        : engineChoice !== "native" && !engines.find((e) => e.id === engineChoice)?.available
                          ? "Engine not detected; bundled binaries arrive with the installer"
                          : "Runs in the selected engine"
              }
            >
              {crackBusy ? "cracking…" : crackMode === "wordlist" ? "Pick wordlist…" : "Run attack"}
            </ToolButton>
            {engineOnly ? <Chip tone="blue">engine format</Chip> : null}
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
                cpu: {devices ? `${devices.cpu_cores}× ${devices.cpu_arch}` : "…"} · hacktool-crypto <span className="text-ok">active</span>
              </div>
              {devices?.gpu_devices.map((gpu) => (
                <div key={gpu.name}>gpu: {gpu.name} · {gpu.backend} <span className="text-warn">gated</span></div>
              ))}
              {devices && devices.gpu_devices.length === 0 ? <div>gpu: none detected <span className="text-warn">reported honestly</span></div> : null}
              {engines.map((engine) => (
                <div key={engine.id}>
                  engine: {engine.label} {engine.version || "—"} · {engine.license} · {engine.available ? `available (${engine.source})` : "not detected"}{" "}
                  {engine.available ? <span className="text-ok">ready</span> : <span className="text-warn">bundles with installer</span>}
                </div>
              ))}
              {devices ? <div className="text-fg-muted">{devices.planner_note}</div> : null}
            </div>
          ) : (
            <div className="font-mono text-[10px] text-fg-muted">device and engine probing run in the desktop runtime</div>
          )}
        </div>
        <div className="p-2">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-fg-muted">Engine planner</div>
          <ol className="space-y-1 font-mono text-[11px] text-fg-dim">
            <li>1. normalize format + parameters <Chip tone="ok">live</Chip></li>
            <li>2. digest verification <Chip tone="ok">live</Chip></li>
            <li>3. wordlist / rules / mask attacks (cpu) <Chip tone="ok">live</Chip></li>
            <li>4. device probe + planner report <Chip tone="ok">live</Chip></li>
            <li className="opacity-60">5. GPU compute engines <Chip>license gate</Chip></li>
          </ol>
          <p className="mt-2 font-mono text-[10px] leading-relaxed text-fg-muted">
            Sessions persist engine version, work units and recovery evidence; audit logs never expose password material.
          </p>
        </div>
      </Pane>
    </div>
  );
}

// -------------------------------------------------------------- crypto ops ---

interface AlgoDescriptor {
  id: string;
  label: string;
  nativeOnly?: boolean;
  needsKey?: boolean;
}

const DIGEST_ALGOS: AlgoDescriptor[] = [
  { id: "md5", label: "MD5", nativeOnly: true },
  { id: "sha1", label: "SHA-1" },
  { id: "sha224", label: "SHA-224", nativeOnly: true },
  { id: "sha256", label: "SHA-256" },
  { id: "sha384", label: "SHA-384" },
  { id: "sha512", label: "SHA-512" },
  { id: "crc32", label: "CRC32", nativeOnly: true },
  { id: "hmac_sha256", label: "HMAC-SHA256", nativeOnly: true, needsKey: true },
  { id: "hmac_sha512", label: "HMAC-SHA512", nativeOnly: true, needsKey: true },
];

function CryptoOpsView() {
  const desktop = isDesktop();
  const [algo, setAlgo] = useState("sha256");
  const [input, setInput] = useState("workbench");
  const [key, setKey] = useState("");
  const [result, setResult] = useState<OpResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [fileDigest, setFileDigest] = useState<FileDigestsWire | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [fileBusy, setFileBusy] = useState(false);
  const [compareA, setCompareA] = useState("");
  const [compareB, setCompareB] = useState("");
  const current = DIGEST_ALGOS.find((a) => a.id === algo)!;
  const disabled = current.nativeOnly && !desktop;
  const compareVerdict = useMemo(() => {
    const a = compareA.trim().toLowerCase();
    const b = compareB.trim().toLowerCase();
    if (!a || !b) return null;
    return a === b ? "match" : "mismatch";
  }, [compareA, compareB]);

  const compute = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(
        await cryptoOp(algo, new TextEncoder().encode(input), current.needsKey ? new TextEncoder().encode(key) : undefined),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const hashFile = async () => {
    setFileBusy(true);
    setFileError(null);
    setFileDigest(null);
    try {
      setFileDigest(await digestFileDialog());
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setFileError(message);
    } finally {
      setFileBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <Pane title="Parameters" className="w-72 shrink-0">
        <div className="p-2">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-fg-muted">Algorithm</div>
          <Select
            value={algo}
            onChange={(v) => {
              setAlgo(v);
              setResult(null);
              setError(null);
            }}
            options={DIGEST_ALGOS.map((a) => ({ value: a.id, label: a.label + (a.nativeOnly && !desktop ? " (desktop)" : "") }))}
            ariaLabel="Digest algorithm"
            className="w-full"
          />
          <div className="mb-1 mt-3 text-[10px] uppercase tracking-wider text-fg-muted">Input</div>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            aria-label="Digest input"
            className="h-24 w-full resize-none border border-line bg-app p-2 font-mono text-xs text-fg focus:border-orange focus:outline-none"
          />
          {current.needsKey ? (
            <>
              <div className="mb-1 mt-2 text-[10px] uppercase tracking-wider text-fg-muted">Key</div>
              <TextInput value={key} onChange={setKey} placeholder="HMAC key" ariaLabel="HMAC key" className="w-full" />
            </>
          ) : null}
          <div className="mt-2 flex gap-1">
            <ToolButton tone="primary" onClick={() => void compute()} disabled={busy || disabled} title={disabled ? "Requires the desktop runtime" : "Compute with the native engine"}>
              <Play size={11} /> Compute
            </ToolButton>
            <ToolButton onClick={() => void hashFile()} disabled={fileBusy || !desktop} title={desktop ? "Pick a file to digest without importing it" : "File hashing requires the desktop runtime"}>
              {fileBusy ? "hashing…" : "Hash a file…"}
            </ToolButton>
          </div>
          {fileError ? <div className="mt-1 font-mono text-[10px] text-err">{fileError}</div> : null}
          {!desktop ? (
            <p className="mt-2 font-mono text-[10px] leading-relaxed text-fg-muted">
              SHA algorithms run via WebCrypto here; MD5, CRC32, HMAC and file hashing use the native engine in the desktop app.
            </p>
          ) : null}
        </div>
      </Pane>
      <Pane title="Result" className="min-w-0 flex-1" bodyClassName="flex flex-col">
        <div className="min-h-0 flex-1 overflow-auto">
          {fileDigest ? (
            <div className="p-3">
              <div className="text-[10px] uppercase tracking-wider text-fg-muted">File digests: {fileDigest.name} ({fileDigest.size} bytes)</div>
              <div className="mt-2 space-y-1 font-mono text-[11px]">
                <div><span className="text-fg-muted">sha256 </span><span className="break-all text-ok">{fileDigest.sha256}</span></div>
                <div><span className="text-fg-muted">sha1   </span><span className="break-all text-fg">{fileDigest.sha1}</span></div>
                <div><span className="text-fg-muted">md5    </span><span className="break-all text-fg">{fileDigest.md5}</span></div>
                <div><span className="text-fg-muted">crc32  </span><span className="text-fg">{fileDigest.crc32}</span></div>
              </div>
            </div>
          ) : error ? (
            <div className="m-2 border border-err/50 p-2 font-mono text-[11px] text-err">{error}</div>
          ) : result ? (
            <div className="p-3">
              <div className="text-[10px] uppercase tracking-wider text-fg-muted">{current.label} (hex)</div>
              <div className="mt-1 break-all border border-line bg-app p-2 font-mono text-xs text-ok">{result.output_hex}</div>
              <div className="mt-2">
                <ToolButton onClick={() => void navigator.clipboard?.writeText(result.output_hex)}>
                  <Copy size={11} /> Copy
                </ToolButton>
              </div>
            </div>
          ) : (
            <EmptyState title="No digest computed" detail="Pick an algorithm and compute, or hash a picked file. Digests run in the native Rust engine and never touch the network." badge="crypto ops" />
          )}
        </div>
        <div className="shrink-0 border-t border-line p-2">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-fg-muted">Compare digests</div>
          <div className="space-y-1">
            <TextInput value={compareA} onChange={setCompareA} placeholder="digest A" ariaLabel="Digest A" className="w-full" />
            <TextInput value={compareB} onChange={setCompareB} placeholder="digest B" ariaLabel="Digest B" className="w-full" />
            <div className="h-4">
              {compareVerdict === "match" ? <Chip tone="ok">identical</Chip> : null}
              {compareVerdict === "mismatch" ? <Chip tone="err">different</Chip> : null}
            </div>
          </div>
        </div>
      </Pane>
      <Pane title="Provenance" className="w-72 shrink-0">
        <Field label="Engine" value={result?.engine ?? (desktop ? "hacktool-crypto (rust)" : "webcrypto fallback for SHA")} />
        <Field label="Engine version" value={result?.engine_version ?? (desktop ? "native" : "n/a")} />
        <Field label="Hashing vs encryption" value="digests are one-way; passwords verify against KDF formats" />
        <Field label="Next arc" value="streaming digests, KDF formats, benchmark planner" />
      </Pane>
    </div>
  );
}

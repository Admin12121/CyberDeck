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
import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Copy, Play, X } from "lucide-react";
import { Chip, EmptyState, Field, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import {
  OPERATIONS,
  detectImageMime,
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
import { b64, cryptoOp, isDesktop, type OpResult } from "@lib/ipc";
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
  const [inputHeight, setInputHeight] = useState(300);
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
          <ToolButton onClick={() => setCommitted(runRecipe(state.input, state.steps))} disabled={state.autoBake} title="Run recipe manually">
            <Play size={11} /> Bake
          </ToolButton>
          <ToolButton onClick={() => setState((s) => clearRecipe(s))}>Clear</ToolButton>
        </div>
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
        <Pane
          title="Input"
          className="shrink-0"
          style={{ height: inputHeight }}
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

        <Resizer
          direction="vertical"
          flip
          ariaLabel="Resize input pane"
          value={inputHeight}
          onChange={setInputHeight}
          min={120}
          max={600}
        />

        <Pane
          title="Output"
          className="min-h-0 flex-1"
          bodyClassName="p-0"
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
            <div className="m-2 border border-err/50 bg-err/10 p-2 font-mono text-[11px] leading-relaxed text-err">
              <div className="uppercase tracking-wide">step {result.error.stepIndex + 1} failed: {result.error.opId}</div>
              <div className="mt-1 text-fg-dim">{result.error.message}</div>
            </div>
          ) : result ? (
            showHex ? (
              <pre className="h-full overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-xs text-fg">
                {Array.from(result.outputBytes, (b) => b.toString(16).padStart(2, "0")).join(" ")}
              </pre>
            ) : imageMime ? (
              <div className="flex h-full flex-col">
                <div className="flex min-h-0 flex-1 items-center justify-center overflow-auto bg-app p-3">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={`data:${imageMime};base64,${b64.encode(result.outputBytes)}`}
                    alt="recipe output preview"
                    className="max-h-full max-w-full object-contain"
                  />
                </div>
                <div className="border-t border-line px-2 py-0.5 font-mono text-[10px] text-fg-muted">
                  {imageMime} preview · {result.byteLength} bytes
                </div>
              </div>
            ) : (
              <pre className="h-full overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-xs text-fg">
                {result.output || "(empty output)"}
              </pre>
            )
          ) : (
            <EmptyState title="No result yet" detail="Enable auto-bake or press Bake to evaluate the recipe." badge="recipes" />
          )}
          <div className="border-t border-line px-2 py-0.5 font-mono text-[10px] text-fg-muted">
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
      className={`group mb-px flex items-center gap-1 border border-line bg-app px-1.5 py-1 ${step.enabled ? "" : "opacity-50"} ${
        isDropTarget ? "border-t-orange" : ""
      }`}
    >
      <span className="w-4 shrink-0 text-right font-mono text-[10px] text-fg-muted">{index + 1}</span>
      <span aria-hidden className="cursor-grab select-none font-mono text-[10px] leading-none text-fg-muted">⠿</span>
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
          className="h-4 w-16 shrink-0 border border-line bg-app px-1 font-mono text-[10px] text-fg focus:border-orange focus:outline-none"
        />
      ) : null}
      <button type="button" title="Move up" onClick={onMoveUp} className="text-fg-muted opacity-0 group-hover:opacity-100 hover:text-fg">
        <ArrowUp size={12} />
      </button>
      <button type="button" title="Move down" onClick={onMoveDown} className="text-fg-muted opacity-0 group-hover:opacity-100 hover:text-fg">
        <ArrowDown size={12} />
      </button>
      <button type="button" title="Remove" onClick={onRemove} className="text-fg-muted opacity-0 group-hover:opacity-100 hover:text-err">
        <X size={12} />
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
  const candidates = useMemo(() => detectHashFormats(input), [input]);

  const verify = async () => {
    setVerifying(true);
    setVerifyError(null);
    setVerdict(null);
    try {
      const result = await cryptoOp(algo, new TextEncoder().encode(plaintext));
      setVerdict(result.output_hex === input.trim().toLowerCase() ? "match" : "mismatch");
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifying(false);
    }
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
            <ToolButton disabled title="Import from file, planned arc 3">Import file</ToolButton>
            <ToolButton disabled title="Handoff from forensic scan, planned arc 3">Handoff</ToolButton>
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
                  <td>{candidate.gpuCapable ? <span className="text-orange">GPU/CPU</span> : <span className="text-orange">CPU</span>}</td>
                  <td className="text-fg-muted">{candidate.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Pane>
      </div>
      <Pane title="Operations" className="w-80 shrink-0">
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
        <div className="px-3 pb-2 pt-2 text-[10px] uppercase tracking-wider text-fg-muted">Engine planner</div>
        <ol className="space-y-1 px-3 font-mono text-[11px] text-fg-dim">
          <li>1. normalize format + parameters <Chip tone="ok">live</Chip></li>
          <li>2. digest verification <Chip tone="ok">live</Chip></li>
          <li className="opacity-60">3. engine support matrix (john / hashcat) <Chip>arc 3</Chip></li>
          <li className="opacity-60">4. hardware probe (GPU, drivers, memory) <Chip>arc 3</Chip></li>
          <li className="opacity-60">5. choose implementation or explain fallback <Chip>arc 3</Chip></li>
        </ol>
        <div className="mt-3 border-t border-line p-2">
          <ToolButton disabled title="Authorized offline recovery, engine integration arc 3">Recovery session</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="Benchmark devices, planned arc 3">Benchmark devices</ToolButton>
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
  { id: "sha224", label: "SHA-224" },
  { id: "sha256", label: "SHA-256" },
  { id: "sha384", label: "SHA-384" },
  { id: "sha512", label: "SHA-512" },
  { id: "crc32", label: "CRC32", nativeOnly: true },
  { id: "hmac_sha256", label: "HMAC-SHA256", nativeOnly: true, needsKey: true },
];

function CryptoOpsView() {
  const desktop = isDesktop();
  const [algo, setAlgo] = useState("sha256");
  const [input, setInput] = useState("workbench");
  const [key, setKey] = useState("");
  const [result, setResult] = useState<OpResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const current = DIGEST_ALGOS.find((a) => a.id === algo)!;
  const disabled = current.nativeOnly && !desktop;

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
          </div>
          {!desktop ? (
            <p className="mt-2 font-mono text-[10px] leading-relaxed text-fg-muted">
              SHA algorithms run via WebCrypto here; MD5, CRC32 and HMAC use the native engine in the desktop app.
            </p>
          ) : null}
        </div>
      </Pane>
      <Pane title="Result" className="min-w-0 flex-1">
        {error ? (
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
          <EmptyState title="No digest computed" detail="Pick an algorithm and compute. Digests run in the native Rust engine and never touch the network." badge="crypto ops" />
        )}
      </Pane>
      <Pane title="Provenance" className="w-72 shrink-0">
        <Field label="Engine" value={result?.engine ?? (desktop ? "hacktool-crypto (rust)" : "webcrypto fallback for SHA")} />
        <Field label="Engine version" value={result?.engine_version ?? "n/a"} />
        <Field label="Hashing vs encryption" value="digests are one-way; passwords verify against KDF formats" />
        <Field label="Next arc" value="streaming digests, KDF formats, benchmark planner" />
      </Pane>
    </div>
  );
}

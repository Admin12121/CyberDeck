"use client";
/**
 * Crypto feature — view layer.
 * Recipes: the four-column transformation workflow (Operations | Recipe |
 * Input | Output) with live auto-bake (Master Plan §5.4). Hash Analysis:
 * real format identification; recovery sessions gate on the engine planner
 * (arc 2). Crypto Ops: real digests via WebCrypto.
 */
import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Copy, Play, X } from "lucide-react";
import { Chip, EmptyState, Field, Pane, Select, TextInput, ToolButton } from "@ds/panes";
import {
  OPERATIONS,
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
  removeStep,
  setAutoBake,
  setInput,
  toggleStep,
} from "../controller";
import { detectHashFormats } from "../model/hash";
import { digestText, type DigestAlgorithm } from "../controller/digest";
import type { ToolId } from "@features/registry";

const CATEGORY_ORDER: OperationCategory[] = ["encoding", "transforms", "parsing"];

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

  const live = useMemo(() => runRecipe(state.input, state.steps), [state.input, state.steps]);
  const result = state.autoBake ? live : committed;
  const inputBytes = useMemo(() => new TextEncoder().encode(state.input).length, [state.input]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return OPERATIONS.filter((op) => !q || op.label.toLowerCase().includes(q) || op.id.includes(q));
  }, [search]);

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <Pane title="Operations" className="w-56 shrink-0" bodyClassName="p-1">
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
                  title={op.description}
                  onClick={() => setState((s) => addStep(s, op.id))}
                  className="block w-full truncate px-2 py-1 text-left font-mono text-[11px] text-fg-dim hover:bg-raised hover:text-fg"
                >
                  {op.label}
                </button>
              ))}
            </div>
          );
        })}
      </Pane>

      <Pane
        title={`Recipe — ${state.steps.length} step${state.steps.length === 1 ? "" : "s"}`}
        className="w-64 shrink-0"
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
        bodyClassName="flex flex-col"
      >
        <div className="flex-1 overflow-auto p-1">
          {state.steps.length === 0 ? (
            <div className="p-3 font-mono text-[11px] leading-relaxed text-fg-muted">
              Add operations from the catalog.
              <br />
              Steps apply top to bottom.
            </div>
          ) : (
            state.steps.map((step, index) => {
              const op = operationById(step.opId);
              return (
                <div
                  key={`${step.opId}-${index}`}
                  className={`group mb-px flex items-center gap-1 border border-line bg-app px-1.5 py-1 ${step.enabled ? "" : "opacity-50"}`}
                >
                  <span className="w-4 shrink-0 text-right font-mono text-[10px] text-fg-muted">{index + 1}</span>
                  <input
                    type="checkbox"
                    checked={step.enabled}
                    onChange={() => setState((s) => toggleStep(s, index))}
                    aria-label={`Toggle step ${index + 1}`}
                    className="accent-[var(--color-blue)]"
                  />
                  <span className="flex-1 truncate font-mono text-[11px]" title={op?.description}>
                    {op?.label ?? step.opId}
                  </span>
                  <button type="button" title="Move up" onClick={() => setState((s) => moveStep(s, index, -1))} className="text-fg-muted opacity-0 group-hover:opacity-100 hover:text-fg">
                    <ArrowUp size={12} />
                  </button>
                  <button type="button" title="Move down" onClick={() => setState((s) => moveStep(s, index, 1))} className="text-fg-muted opacity-0 group-hover:opacity-100 hover:text-fg">
                    <ArrowDown size={12} />
                  </button>
                  <button type="button" title="Remove" onClick={() => setState((s) => removeStep(s, index))} className="text-fg-muted opacity-0 group-hover:opacity-100 hover:text-err">
                    <X size={12} />
                  </button>
                </div>
              );
            })
          )}
        </div>
        <div className="flex items-center gap-1 border-t border-line p-1">
          <ToolButton onClick={() => setCommitted(runRecipe(state.input, state.steps))} disabled={state.autoBake} title="Run recipe manually">
            <Play size={11} /> Bake
          </ToolButton>
          <ToolButton onClick={() => setState((s) => clearRecipe(s))}>Clear</ToolButton>
        </div>
      </Pane>

      <Pane
        title="Input"
        className="min-w-0 flex-1"
        actions={<Chip>{inputBytes} bytes</Chip>}
        bodyClassName="p-0"
      >
        <textarea
          value={state.input}
          onChange={(e) => setState((s) => setInput(s, e.target.value))}
          spellCheck={false}
          aria-label="Recipe input"
          className="h-full w-full resize-none bg-app p-2 font-mono text-xs text-fg focus:outline-none"
        />
      </Pane>

      <Pane
        title="Output"
        className="min-w-0 flex-1"
        actions={
          <>
            <button
              type="button"
              onClick={() => setShowHex((v) => !v)}
              className={`border px-1.5 font-mono text-[10px] uppercase ${showHex ? "border-blue/50 text-blue" : "border-line text-fg-muted"}`}
            >
              hex
            </button>
            <ToolButton onClick={() => void navigator.clipboard?.writeText(result?.output ?? "")} title="Copy output">
              <Copy size={11} />
            </ToolButton>
          </>
        }
        bodyClassName="p-0"
      >
        {result?.error ? (
          <div className="m-2 border border-err/50 bg-err/10 p-2 font-mono text-[11px] leading-relaxed text-err">
            <div className="uppercase tracking-wide">step {result.error.stepIndex + 1} failed — {result.error.opId}</div>
            <div className="mt-1 text-fg-dim">{result.error.message}</div>
          </div>
        ) : result ? (
          <pre className="h-full overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-xs text-fg">
            {showHex
              ? Array.from(new TextEncoder().encode(result.output), (b) => b.toString(16).padStart(2, "0")).join(" ")
              : result.output || "(empty output)"}
          </pre>
        ) : (
          <EmptyState title="No result yet" detail="Enable auto-bake or press Bake to evaluate the recipe." badge="recipes" />
        )}
        <div className="border-t border-line px-2 py-0.5 font-mono text-[10px] text-fg-muted">
          {result ? `${result.byteLength} bytes out · ${result.elapsedMs.toFixed(1)} ms` : "—"}
        </div>
      </Pane>
    </div>
  );
}

// ---------------------------------------------------------- hash analysis ---

function HashAnalysisView() {
  const [input, setInput] = useState("5d41402abc4b2a76b9719d911017c592");
  const candidates = useMemo(() => detectHashFormats(input), [input]);

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <div className="flex min-w-0 flex-1 flex-col gap-px">
        <Pane title="Hash input" bodyClassName="p-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            aria-label="Hash input"
            className="h-24 w-full resize-none border border-line bg-app p-2 font-mono text-xs text-fg focus:border-blue focus:outline-none"
          />
          <div className="mt-2 flex items-center gap-1">
            <ToolButton disabled title="Import from file — arc 2">Import file</ToolButton>
            <ToolButton disabled title="Handoff from forensic scan — arc 2">Handoff</ToolButton>
            <span className="ml-auto font-mono text-[10px] text-fg-muted">{input.trim().length} chars</span>
          </div>
        </Pane>
        <Pane title="Identified formats — candidates, never asserted as fact" className="flex-1">
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
                  <td>{candidate.gpuCapable ? <span className="text-blue">GPU/CPU</span> : <span className="text-orange">CPU</span>}</td>
                  <td className="text-fg-muted">{candidate.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Pane>
      </div>
      <Pane title="Operations" className="w-72 shrink-0">
        <div className="p-2">
          <ToolButton tone="primary" title="Format identification is live — see candidate table">
            Identify <Chip tone="ok">live</Chip>
          </ToolButton>
        </div>
        <div className="px-3 pb-2 text-[10px] uppercase tracking-wider text-fg-muted">Engine planner</div>
        <ol className="space-y-1 px-3 font-mono text-[11px] text-fg-dim">
          <li>1. normalize format + parameters <Chip tone="ok">live</Chip></li>
          <li className="opacity-60">2. engine support matrix — john / hashcat <Chip>arc 2</Chip></li>
          <li className="opacity-60">3. hardware probe — GPU, drivers, memory <Chip>arc 2</Chip></li>
          <li className="opacity-60">4. cached benchmark comparison <Chip>arc 2</Chip></li>
          <li className="opacity-60">5. choose implementation or explain fallback <Chip>arc 2</Chip></li>
        </ol>
        <div className="mt-3 border-t border-line p-2">
          <ToolButton disabled title="Authorized offline recovery — engine integration arc 2">Verify candidate</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="Recovery session — engine integration arc 2">Recovery session</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="Benchmark — device probing arc 2">Benchmark devices</ToolButton>
          <p className="mt-2 font-mono text-[10px] leading-relaxed text-fg-muted">
            Sessions persist engine version, work units and recovery evidence; audit logs never expose password material.
          </p>
        </div>
      </Pane>
    </div>
  );
}

// -------------------------------------------------------------- crypto ops ---

function CryptoOpsView() {
  const [algorithm, setAlgorithm] = useState<DigestAlgorithm>("SHA-256");
  const [input, setInput] = useState("workbench");
  const [digest, setDigest] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const compute = async () => {
    setBusy(true);
    setError(null);
    try {
      setDigest(await digestText(algorithm, input));
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
            value={algorithm}
            onChange={(v) => setAlgorithm(v as DigestAlgorithm)}
            options={[
              { value: "SHA-1", label: "SHA-1" },
              { value: "SHA-256", label: "SHA-256" },
              { value: "SHA-384", label: "SHA-384" },
              { value: "SHA-512", label: "SHA-512" },
            ]}
            ariaLabel="Digest algorithm"
            className="w-full"
          />
          <div className="mb-1 mt-3 text-[10px] uppercase tracking-wider text-fg-muted">Input</div>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            aria-label="Digest input"
            className="h-28 w-full resize-none border border-line bg-app p-2 font-mono text-xs text-fg focus:border-blue focus:outline-none"
          />
          <div className="mt-2 flex gap-1">
            <ToolButton tone="primary" onClick={() => void compute()} disabled={busy}>
              <Play size={11} /> Compute digest
            </ToolButton>
            <ToolButton disabled title="HMAC with key management — arc 2">HMAC</ToolButton>
          </div>
        </div>
      </Pane>
      <Pane title="Result" className="min-w-0 flex-1">
        {error ? (
          <div className="m-2 border border-err/50 p-2 font-mono text-[11px] text-err">{error}</div>
        ) : digest ? (
          <div className="p-3">
            <div className="text-[10px] uppercase tracking-wider text-fg-muted">{algorithm} — hex</div>
            <div className="mt-1 break-all border border-line bg-app p-2 font-mono text-xs text-ok">{digest}</div>
            <div className="mt-2">
              <ToolButton onClick={() => void navigator.clipboard?.writeText(digest)}>
                <Copy size={11} /> Copy
              </ToolButton>
            </div>
          </div>
        ) : (
          <EmptyState title="No digest computed" detail="Pick an algorithm and compute. Runs locally via the platform crypto provider — no network." badge="crypto ops" />
        )}
      </Pane>
      <Pane title="Notes" className="w-72 shrink-0">
        <Field label="Engine" value="webcrypto (platform)" />
        <Field label="Hashing vs encryption" value="digests are one-way; passwords verify against KDF formats" />
        <Field label="Next arc" value="Rust core: streaming digests, HMAC, KDF formats, large inputs" />
      </Pane>
    </div>
  );
}

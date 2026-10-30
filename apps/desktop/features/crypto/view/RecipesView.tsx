"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Copy, Play, Wand2, X } from "lucide-react";
import { Chip, EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
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
import { b64 } from "@lib/ipc";

/** Recipes: four-column pipeline with drag-and-drop, params, image preview. */

const CATEGORY_ORDER: OperationCategory[] = ["encoding", "transforms", "parsing", "formatting"];

/** MIME types used by drag-and-drop between the catalog and the recipe. */
const OP_MIME = "application/x-hacktool-op";
const STEP_MIME = "application/x-hacktool-step";

export function RecipesView() {
  const [state, setState] = useState<RecipeState>(initialRecipeState);
  const [search, setSearch] = useState("");
  const [committed, setCommitted] = useState<ReturnType<typeof runRecipe> | null>(null);
  const [showHex, setShowHex] = useState(false);
  const [opsWidth, setOpsWidth] = useState(224);
  const [recipeWidth, setRecipeWidth] = useState(256);
  // null keeps input and output at an even 50/50 split; dragging pins px.
  const [inputHeight, setInputHeight] = useState<number | null>(null);
  const [dropIndex, setDropIndex] = useState<number | null>(null);
  const inputPaneRef = useRef<HTMLDivElement>(null);
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
    const { steps } = magicRecipe(state.input);
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
            <div className="flex h-6 items-center gap-1">
              <button
                type="button"
                onClick={() => setShowHex((v) => !v)}
                className={`flex h-6 items-center border px-1.5 font-mono text-[10px] uppercase ${showHex ? "border-orange/50 text-orange" : "border-line text-fg-muted"}`}
              >
                hex
              </button>
              <ToolButton onClick={() => void navigator.clipboard?.writeText(result?.output ?? "")} title="Copy output">
                <Copy size={11} />
              </ToolButton>
            </div>
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

export function StepRow({ step, index, isDropTarget, onToggle, onMoveUp, onMoveDown, onRemove, onParam, onDragOverRow, onDropRow }: StepRowProps) {
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

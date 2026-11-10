"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Copy, FileDown, Play, Save, Wand2, X } from "lucide-react";
import { ErrorStrip } from "@ds/compact";
import { CheckBox, Chip, EmptyState, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import {
  OPERATIONS,
  detectImageMime,
  magicRecipe,
  operationById,
  runRecipe,
  type OperationCategory,
  type RecipeState,
  type RecipeResult,
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
import { b64, fileImportDerived, isDesktop, recipeRun, type RecipeRunWire } from "@lib/ipc";
import { useCaseReady, useWorkbench } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import { outputCapabilities, recipeResultIdentity } from "./recipe-output-policy";
import { canUseNativeRecipe } from "./native-recipe-policy";
import { downloadContent } from "@lib/download";

/** Recipes: four-column pipeline with drag-and-drop, params, image preview. */

const CATEGORY_ORDER: OperationCategory[] = ["encoding", "transforms", "parsing", "formatting"];

/** MIME types used by drag-and-drop between the catalog and the recipe. */
const OP_MIME = "application/x-cyberdeck-op";
const STEP_MIME = "application/x-cyberdeck-step";

const NATIVE_RECIPE_OPS = new Set([
  "to_base64", "from_base64", "to_base64url", "from_base64url",
  "to_base32", "from_base32", "url_encode", "url_decode", "to_hex", "from_hex", "to_binary", "from_binary",
  "to_decimal", "from_decimal", "rot_n", "rot13", "rot47", "atbash",
  "xor", "reverse", "swap_endianness", "rotate_bytes", "bit_shift_left",
  "bit_shift_right", "to_uppercase", "to_lowercase", "trim_lines", "add_line_numbers", "defang", "refang",
  "unique_lines", "reverse_lines", "filter_lines", "head_lines",
  "tail_lines", "text_split", "find_replace", "json_beautify",
  "json_minify", "slice_bytes", "to_utf8",
  "hex_dump", "from_hexdump", "html_encode", "html_decode", "strip_html_tags",
  "to_charcode", "from_charcode", "vigenere", "nato_encode", "morse_encode", "morse_decode",
  "escape_string", "unescape_string",
  "extract_urls", "extract_ips", "extract_emails", "extract_domains", "jwt_decode",
  "normalize_unicode", "unix_to_datetime", "datetime_to_unix",
  "to_base45", "from_base45", "to_base58", "from_base58", "to_base58check", "from_base58check",
  "to_base62", "from_base62", "to_base85", "from_base85", "to_base92", "from_base92",
  "to_bech32", "from_bech32", "to_base", "from_base", "to_octal", "from_octal",
  "to_bcd", "from_bcd", "to_float", "from_float", "escape_unicode", "unescape_unicode",
  "escape_smart_chars", "to_hex_content", "from_hex_content", "caret_m_decode",
  "to_modhex", "from_modhex", "to_quoted_printable", "from_quoted_printable",
  "to_punycode", "from_punycode", "mime_decode", "pem_to_hex", "hex_to_pem",
  "parse_asn1_hex_string", "parse_tlv", "change_ip_format", "text_integer_conversion",
  "to_braille", "from_braille", "to_cobs", "from_cobs", "encode_text", "decode_text",
  "unicode_text_format",
]);

function nativeUiResult(wire: RecipeRunWire): RecipeResult {
  const bytes = wire.error ? new Uint8Array() : b64.decode(wire.outputB64);
  return {
    output: new TextDecoder().decode(bytes),
    outputBytes: bytes,
    byteLength: wire.byteLength,
    elapsedMs: wire.elapsedMs,
    error: wire.error
      ? { stepIndex: wire.error.stepIndex, opId: wire.error.opId, message: wire.error.message }
      : undefined,
  };
}

export function RecipesView() {
  const wb = useWorkbench();
  const activeCase = useRef(wb.caseId);
  activeCase.current = wb.caseId;
  const [savingCase, setSavingCase] = useState(false);
  const [caseSaveError, setCaseSaveError] = useState<string | null>(null);
  const [outputActionError, setOutputActionError] = useState<string | null>(null);
  const [sourceDescription, setSourceDescription] = useState<string | null>(null);
  const initialDraft = useMemo(initialRecipeState, []);
  const [state, setState] = useWorkspaceDraft<RecipeState>(wb.caseId, "crypto", "recipes", initialDraft);
  const [search, setSearch] = useWorkspaceDraft(wb.caseId, "crypto", "operation-search", "");
  const [committed, setCommitted] = useState<{ key: string; value: RecipeResult; native: boolean } | null>(null);
  // Consume an explicit cross-workspace transfer once, without saving it
  // in localStorage (captured traffic may contain sensitive data).
  useEffect(() => {
    if (!wb.recipeHandoff) return;
    const transfer = wb.recipeHandoff;
    setSourceDescription(transfer.source);
    setState((previous) => ({ ...previous, input: transfer.input, steps: transfer.steps }));
    wb.consumeRecipeHandoff();
  }, [wb.recipeHandoff, wb.consumeRecipeHandoff]);
  const [nativeAuto, setNativeAuto] = useState<{ key: string; value: RecipeResult } | null>(null);
  const [opsWidth, setOpsWidth] = useWorkspaceDraft(wb.caseId, "crypto", "operations-width", 224);
  const [recipeWidth, setRecipeWidth] = useWorkspaceDraft(wb.caseId, "crypto", "recipe-width", 256);
  // null keeps input and output at an even 50/50 split; dragging pins px.
  const [inputHeight, setInputHeight] = useWorkspaceDraft<number | null>(wb.caseId, "crypto", "input-height", null);
  const [dropIndex, setDropIndex] = useState<number | null>(null);
  const inputPaneRef = useRef<HTMLDivElement>(null);
  // elapsedMs is real timing, which differs between prerender and hydration,
  // so display it only after mount to keep the first paint stable.
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const eligibleForNative = isDesktop() && canUseNativeRecipe(state.input, state.steps, NATIVE_RECIPE_OPS);
  const live = useMemo(() => eligibleForNative ? null : runRecipe(state.input, state.steps), [state.input, state.steps, eligibleForNative]);
  const recipeKey = useMemo(() => recipeResultIdentity(wb.caseId, state.input, state.steps), [wb.caseId, state.input, state.steps]);
  useEffect(() => {
    if (!state.autoBake || !eligibleForNative) return;
    let active = true;
    const timer = setTimeout(() => {
      recipeRun(state.input, state.steps).then((wire) => {
        if (active) setNativeAuto({ key: recipeKey, value: nativeUiResult(wire) });
      }).catch((err: unknown) => {
        if (active) setNativeAuto({
          key: recipeKey,
          value: {
            output: "", outputBytes: new Uint8Array(), byteLength: 0, elapsedMs: 0,
            error: { stepIndex: 0, opId: "native", message: String(err) },
          },
        });
      });
    }, 120);
    return () => { active = false; clearTimeout(timer); };
  }, [state.input, state.steps, state.autoBake, eligibleForNative, recipeKey]);

  const nativeReady = eligibleForNative && nativeAuto?.key === recipeKey;
  const result = state.autoBake ? (nativeReady && nativeAuto ? nativeAuto.value : live) : (committed?.key === recipeKey ? committed.value : null);
  const nativeResult = state.autoBake ? nativeReady : committed?.key === recipeKey && committed.native;
  const bake = async () => {
    if (!eligibleForNative) {
      setCommitted({ key: recipeKey, value: runRecipe(state.input, state.steps), native: false });
      return;
    }
    try {
      const wire = await recipeRun(state.input, state.steps);
      setCommitted({ key: recipeKey, value: nativeUiResult(wire), native: true });
    } catch (error) {
      setCommitted({ key: recipeKey, native: false, value: { output: "", outputBytes: new Uint8Array(), byteLength: 0, elapsedMs: 0,
        error: { stepIndex: 0, opId: "native", message: String(error) } } });
    }
  };
  const inputBytes = useMemo(() => new TextEncoder().encode(state.input).length, [state.input]);
  const imageMime = useMemo(
    () => (result && !result.error ? detectImageMime(result.outputBytes) : null),
    [result],
  );
  // Output renders as an image when the bytes are one directly, or when the
  // output text itself is Base64 that decodes to one (the common paste flow).
  const decodedImage = useMemo(() => {
    if (!result || result.error) return null;
    if (imageMime) return { mime: imageMime, bytes: result.outputBytes };
    const b64 = result.output.replace(/\s+/g, "");
    if (b64.length < 16 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
    try {
      const bin = atob(b64);
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      const mime = detectImageMime(bytes);
      return mime ? { mime, bytes } : null;
    } catch {
      return null;
    }
  }, [result, imageMime]);
  const [outMode, setOutMode] = useState<"text" | "hex" | "image">("text");
  const textOutput = useMemo(
    () => outputCapabilities(result, "text", decodedImage?.mime ?? null),
    [result, decodedImage],
  );
  useEffect(() => {
    setOutMode(decodedImage ? "image" : textOutput.canText || !textOutput.hasBytes ? "text" : "hex");
  }, [decodedImage, textOutput]);
  useEffect(() => setOutputActionError(null), [result, outMode]);
  const supportsTextClipboard = mounted && typeof navigator !== "undefined" && typeof navigator.clipboard?.writeText === "function";
  const supportsImageClipboard = mounted && typeof navigator !== "undefined"
    && typeof navigator.clipboard?.write === "function" && typeof ClipboardItem !== "undefined";
  const output = outputCapabilities(result, outMode, decodedImage?.mime ?? null, supportsImageClipboard);
  const copyEnabled = output.canCopy && (outMode === "image" ? supportsImageClipboard : supportsTextClipboard);
  const { caseReady: caseLinked } = useCaseReady();
  const imageSrc = decodedImage
    ? `data:${decodedImage.mime};base64,${b64.encode(decodedImage.bytes)}`
    : null;
  const saveToCase = async () => {
    if (!output.hasBytes || !caseLinked || !result) return;
    const caseId = wb.caseId;
    const bytes = outMode === "image" && decodedImage ? decodedImage.bytes : result.outputBytes;
    const format = outMode === "image" && decodedImage ? decodedImage.mime : "application/octet-stream";
    const filename = format === "image/jpeg" ? "recipe-output.jpg"
      : format === "image/png" ? "recipe-output.png"
      : format === "image/gif" ? "recipe-output.gif"
      : format === "image/webp" ? "recipe-output.webp"
      : format === "image/bmp" ? "recipe-output.bmp"
      : outMode === "text" && output.canText ? "recipe-output.txt" : "recipe-output.bin";
    setSavingCase(true);
    setCaseSaveError(null);
    try {
      const steps = state.steps.filter((step) => step.enabled).map((step) => step.opId).join(" > ");
      const source = (sourceDescription ?? "Manual input") + (steps ? " | steps: " + steps : "") + (format !== "application/octet-stream" ? " | output: " + format : "");
      const record = await fileImportDerived(caseId, filename, bytes, source.slice(0, 500));
      if (activeCase.current !== caseId) return;
      wb.logConsole("saved derived evidence to case " + caseId + ": " + record.sha256);
      wb.selectTool("forensics.files");
    } catch (error) {
      setCaseSaveError(String(error));
    } finally {
      setSavingCase(false);
    }
  };

  const downloadOutput = () => {
    if (!output.canDownload || !result) return;
    const image = outMode === "image" ? decodedImage : null;
    const bytes = image?.bytes ?? result.outputBytes;
    const ext = image?.mime === "image/jpeg" ? "jpg"
      : image?.mime?.split("/")[1] ?? (outMode === "text" && output.canText ? "txt" : "bin");
    downloadContent(bytes, `output.${ext}`, image?.mime ?? (outMode === "text" && output.canText ? "text/plain;charset=utf-8" : "application/octet-stream"));
  };

  const copyOutput = async () => {
    if (!copyEnabled || !result) return;
    try {
      if (outMode === "image" && decodedImage) {
        const png = new Blob([Uint8Array.from(decodedImage.bytes)], { type: "image/png" });
        await navigator.clipboard.write([new ClipboardItem({ "image/png": png })]);
      } else {
        const text = outMode === "hex"
          ? Array.from(result.outputBytes, (byte) => byte.toString(16).padStart(2, "0")).join(" ")
          : new TextDecoder("utf-8", { fatal: true }).decode(result.outputBytes);
        await navigator.clipboard.writeText(text);
      }
    } catch {
      setOutputActionError("Could not copy output. Check clipboard permissions.");
    }
  };

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
    <div className="flex h-full min-h-0 bg-panel">
      <Pane title="Operations" className="shrink-0" bodyClassName="p-1" style={{ width: opsWidth }}>
        <div className="p-1">
          <TextInput value={search} onChange={setSearch} placeholder="search operations…" ariaLabel="Search operations" className="w-full" />
        </div>
        {CATEGORY_ORDER.map((category) => {
          const ops = filtered.filter((op) => op.category === category);
          if (ops.length === 0) return null;
          return (
            <div key={category} className="mb-1">
              <div className="px-2 py-1 text-3xs uppercase tracking-wider text-fg-muted">{category}</div>
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
                  className="block w-full cursor-grab truncate px-2 py-1 text-left font-mono text-2xs text-fg-dim hover:bg-raised hover:text-fg active:cursor-grabbing"
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
          <CheckBox checked={state.autoBake} onChange={(checked) => setState((s) => setAutoBake(s, checked))}>
            auto-bake
          </CheckBox>
        }
      >
        <div
          className="min-h-0 flex-1 overflow-auto p-1"
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
          {state.steps.length === 0 ? null : (
            state.steps.map((step, index) => (
              <StepRow
                key={`${step.opId}-${index}`}
                step={step}
                index={index}
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
          <ToolButton onClick={() => void bake()} disabled={state.autoBake} title="Run recipe manually">
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
              onChange={(e) => { setSourceDescription(null); setState((s) => setInput(s, e.target.value)); }}
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
              {(["text", "hex", "image"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  disabled={mode === "text" ? !output.canText : mode === "hex" ? !output.canHex : !output.canImage}
                  onClick={() => setOutMode(mode)}
                  className={`flex h-6 items-center border px-1.5 font-mono text-3xs uppercase disabled:opacity-30 ${outMode === mode ? "border-line bg-selected text-fg" : "border-line text-fg-muted"}`}
                >
                  {mode}
                </button>
              ))}
              <ToolButton onClick={() => void saveToCase()} disabled={!isDesktop() || !output.hasBytes || !caseLinked || savingCase}
                title={!caseLinked ? "Select and link a native case to save evidence" : !output.hasBytes ? "No output bytes to save" : "Save derived bytes with provenance to the selected case"}>
                <Save size={11} /> {savingCase ? "Saving" : "To Case"}
              </ToolButton>
              <ToolButton onClick={downloadOutput} disabled={!output.canDownload} title={output.canDownload ? "Download output bytes" : "No output bytes to download"}>
                <FileDown size={11} />
              </ToolButton>
              <ToolButton onClick={() => void copyOutput()} disabled={!copyEnabled} title={copyEnabled ? "Copy the selected output format" : "No copyable output in this format or clipboard unavailable"}>
                <Copy size={11} />
              </ToolButton>
            </div>
          }
        >
          {result?.error ? (
            <div className="min-h-0 flex-1 overflow-auto">
              <ErrorStrip>
                <div className="uppercase tracking-wide">step {result.error.stepIndex + 1} failed: {result.error.opId}</div>
                <div className="mt-1 text-fg-dim">{result.error.message}</div>
              </ErrorStrip>
            </div>
          ) : result ? (
            outMode === "hex" ? (
              <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-xs text-fg">
                {Array.from(result.outputBytes, (b) => b.toString(16).padStart(2, "0")).join(" ")}
              </pre>
            ) : outMode === "image" ? (
              decodedImage ? (
                <div className="flex min-h-0 flex-1 flex-col">
                  <div className="flex min-h-0 flex-1 items-center justify-center overflow-auto bg-app p-3">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={imageSrc ?? ""} alt="recipe output preview" className="max-h-full max-w-full object-contain" />
                  </div>
                  <div className="shrink-0 border-t border-line px-2 py-0.5 font-mono text-3xs text-fg-muted">
                    {decodedImage.mime} · {result.byteLength} bytes
                  </div>
                </div>
              ) : (
                <div className="min-h-0 flex-1 overflow-auto p-2 font-mono text-2xs text-fg-muted">
                  output is not a recognizable image (PNG, JPEG, GIF, WebP, BMP)
                </div>
              )
            ) : (
              <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-xs text-fg">
                {result.output || "(empty output)"}
              </pre>
            )
          ) : (
            <div className="min-h-0 flex-1 overflow-hidden">
              <EmptyState title={state.autoBake && eligibleForNative ? "Processing in Rust…" : "No result yet"} detail={state.autoBake && eligibleForNative ? "Evaluating the recipe in the native engine." : "Enable auto-bake or press Bake to evaluate the recipe."} badge="recipes" />
            </div>
          )}
          {caseSaveError ? <ErrorStrip>{caseSaveError}</ErrorStrip> : null}
          {outputActionError ? <ErrorStrip>{outputActionError}</ErrorStrip> : null}
          <div className="shrink-0 border-t border-line px-2 py-0.5 font-mono text-3xs text-fg-muted">
            {result ? `${result.byteLength} bytes out${mounted ? ` · ${result.elapsedMs.toFixed(1)} ms` : ""} · ${nativeResult ? "Rust engine" : "TypeScript engine"}` : "n/a"}
          </div>
        </Pane>
      </div>
    </div>
  );
}

interface StepRowProps {
  step: RecipeState["steps"][number];
  index: number;
  onToggle: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onRemove: () => void;
  onParam: (value: string) => void;
  onDragOverRow: (e: React.DragEvent) => void;
  onDropRow: (e: React.DragEvent) => void;
}

export function StepRow({ step, index, onToggle, onMoveUp, onMoveDown, onRemove, onParam, onDragOverRow, onDropRow }: StepRowProps) {
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
      className={`group mb-px flex items-center gap-2 border border-line bg-app px-2 py-1.5 ${step.enabled ? "" : "opacity-50"}`}
    >
      <span aria-hidden title="Drag to reorder" className="cursor-grab select-none font-mono text-xs leading-none text-fg-muted group-hover:text-fg-dim">⠿</span>
      <CheckBox checked={step.enabled} onChange={onToggle}>
        <span className="flex-1 truncate font-mono text-2xs" title={op?.description}>
          {op?.label ?? step.opId}
        </span>
      </CheckBox>
      {op?.takesParam ? (
        <input
          value={step.param ?? ""}
          onChange={(e) => onParam(e.target.value)}
          title={`${op.paramLabel ?? "parameter"} for ${op.label}`}
          aria-label={`${op.label} parameter`}
          draggable={false}
          className="h-5 w-16 shrink-0 border border-line bg-app px-1 font-mono text-3xs text-fg"
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

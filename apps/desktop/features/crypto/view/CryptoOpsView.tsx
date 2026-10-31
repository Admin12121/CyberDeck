"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import {
  b64,
  crackHistoryClear,
  crackHistoryDelete,
  crackHistoryList,
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
import type { ToolId } from "@features/registry";

// -------------------------------------------------------------- crypto ops ---

interface AlgoDescriptor {
  id: string;
  label: string;
  nativeOnly?: boolean;
  needsKey?: boolean;
}

const DIGEST_ALGOS: AlgoDescriptor[] = [
  { id: "md4", label: "MD4", nativeOnly: true },
  { id: "ntlm", label: "NTLM", nativeOnly: true },
  { id: "md5", label: "MD5", nativeOnly: true },
  { id: "sha1", label: "SHA-1" },
  { id: "sha3_256", label: "SHA3-256", nativeOnly: true },
  { id: "sha3_512", label: "SHA3-512", nativeOnly: true },
  { id: "sha224", label: "SHA-224", nativeOnly: true },
  { id: "sha256", label: "SHA-256" },
  { id: "sha384", label: "SHA-384" },
  { id: "sha512", label: "SHA-512" },
  { id: "crc32", label: "CRC32", nativeOnly: true },
  { id: "hmac_sha256", label: "HMAC-SHA256", nativeOnly: true, needsKey: true },
  { id: "hmac_sha512", label: "HMAC-SHA512", nativeOnly: true, needsKey: true },
];

export function CryptoOpsView() {
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
        <Field label="Engine" value={result?.engine ?? (desktop ? "cyberdeck-crypto (rust)" : "webcrypto fallback for SHA")} />
        <Field label="Engine version" value={result?.engine_version ?? (desktop ? "native" : "n/a")} />
        <Field label="Hashing vs encryption" value="digests are one-way; passwords verify against KDF formats" />
        <Field label="Next arc" value="streaming digests, KDF formats, benchmark planner" />
      </Pane>
    </div>
  );
}

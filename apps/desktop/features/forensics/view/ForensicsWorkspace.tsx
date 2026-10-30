"use client";
/**
 * Forensics feature view layer.
 * Arc 2 runs on the real evidence pipeline: import through the native file
 * dialog, immutable copies in the case store, real digests (SHA-256, MD5,
 * SHA-1, CRC32), signatures, entropy, hex and strings served from the Rust
 * core (Master Plan §5.6). The browser fallback keeps deterministic sample
 * evidence so the layout stays developable without the desktop shell.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Chip, Field, Pane, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import {
  fileHex,
  fileImportDialog,
  fileList,
  fileStrings,
  isDesktop,
  type ArtifactRecord,
  type HexResponseWire,
  type StringHitWire,
} from "@lib/ipc";
import type { ToolId } from "@features/registry";
import { extractStrings, formatEntropy, shannonEntropy } from "../controller";
import { SAMPLE_EVIDENCE, sampleContent, sampleMetadata } from "../model";

export function ForensicsWorkspace({ tool }: { tool: ToolId }) {
  if (tool === "forensics.metadata") return <MetadataView />;
  if (tool === "forensics.strings") return <StringsView />;
  return <FileAnalysisView />;
}

interface Selected {
  /** Real artifact id, or a sample evidence id when in browser fallback. */
  id: string;
  real: boolean;
}

function useEvidence() {
  const desktop = isDesktop();
  const [artifacts, setArtifacts] = useState<ArtifactRecord[]>([]);
  const [selected, setSelected] = useState<Selected | null>(null);
  const [query, setQuery] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (!desktop) return;
    try {
      const list = await fileList();
      setArtifacts(list);
      setSelected((prev) => {
        if (prev?.real && list.some((a) => a.id === prev.id)) return prev;
        return list[0] ? { id: list[0].id, real: true } : null;
      });
    } catch (err) {
      setImportError(err instanceof Error ? err.message : String(err));
    }
  }, [desktop]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const importEvidence = useCallback(async () => {
    setBusy(true);
    setImportError(null);
    try {
      await fileImportDialog();
      await refresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setImportError(message);
    } finally {
      setBusy(false);
    }
  }, [refresh]);

  const selectedArtifact = useMemo(
    () => artifacts.find((a) => a.id === selected?.id) ?? null,
    [artifacts, selected],
  );
  const selectedSample = useMemo(
    () => (!selected || selected.real ? null : SAMPLE_EVIDENCE.find((f) => f.id === selected.id) ?? null),
    [selected],
  );

  return {
    desktop,
    artifacts,
    selected,
    setSelected,
    selectedArtifact,
    selectedSample,
    query,
    setQuery,
    importError,
    busy,
    importEvidence,
  };
}

type EvidenceContext = ReturnType<typeof useEvidence>;

function EvidenceTree({ ctx }: { ctx: EvidenceContext }) {
  const q = ctx.query.trim().toLowerCase();
  const realFiles = ctx.artifacts.filter((a) => !q || a.name.toLowerCase().includes(q));
  const sampleFiles = SAMPLE_EVIDENCE.filter((f) => !q || f.name.toLowerCase().includes(q));

  return (
    <Pane
      title={`Evidence${ctx.desktop ? "" : " (samples, browser fallback)"}`}
      className="w-72 shrink-0"
      bodyClassName="p-1"
      actions={
        <ToolButton
          onClick={() => void ctx.importEvidence()}
          disabled={ctx.busy || !ctx.desktop}
          title={ctx.desktop ? "Pick a file; it is copied immutably into the case store" : "Import requires the desktop runtime"}
        >
          {ctx.busy ? "importing…" : "Import…"}
        </ToolButton>
      }
    >
      {ctx.importError ? (
        <div className="m-1 border border-err/50 p-2 font-mono text-[10px] text-err">{ctx.importError}</div>
      ) : null}
      {ctx.desktop ? (
        <>
          <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-fg-muted">▾ imported ({realFiles.length})</div>
          {realFiles.map((artifact) => (
            <button
              key={artifact.id}
              type="button"
              onClick={() => ctx.setSelected({ id: artifact.id, real: true })}
              title={artifact.original_path ?? artifact.name}
              className={`block w-full truncate px-2 py-1 text-left font-mono text-[11px] ${
                ctx.selected?.id === artifact.id ? "bg-orange-dim text-orange" : "text-fg-dim hover:bg-raised hover:text-fg"
              }`}
            >
              {artifact.name}
            </button>
          ))}
          {realFiles.length === 0 ? (
            <div className="p-2 font-mono text-[10px] leading-relaxed text-fg-muted">
              no evidence in this case yet. Import a file; originals are copied into the case store and hashed.
            </div>
          ) : null}
        </>
      ) : (
        ["samples", "archives", "logs"].map((group) => {
          const items = sampleFiles.filter((f) => f.group === group);
          if (items.length === 0) return null;
          return (
            <div key={group}>
              <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-fg-muted">▾ {group}</div>
              {items.map((file) => (
                <button
                  key={file.id}
                  type="button"
                  onClick={() => ctx.setSelected({ id: file.id, real: false })}
                  className={`block w-full truncate px-2 py-1 text-left font-mono text-[11px] ${
                    ctx.selected?.id === file.id ? "bg-orange-dim text-orange" : "text-fg-dim hover:bg-raised hover:text-fg"
                  }`}
                >
                  {file.name}
                </button>
              ))}
            </div>
          );
        })
      )}
    </Pane>
  );
}

function useArtifactBytes(ctx: EvidenceContext) {
  const id = ctx.selected?.id ?? null;
  const real = ctx.selected?.real ?? false;
  const [hexData, setHexData] = useState<HexResponseWire | null>(null);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setHexData(null);
    setBytes(null);
    setError(null);
    if (!id) return;
    let cancelled = false;
    if (real) {
      fileHex(id, 0, 512)
        .then((data) => {
          if (!cancelled) setHexData(data);
        })
        .catch((err) => {
          if (!cancelled) setError(err instanceof Error ? err.message : String(err));
        });
    } else {
      setBytes(sampleContent(id));
    }
    return () => {
      cancelled = true;
    };
  }, [id, real]);

  return { hexData, bytes, error };
}

function HexBody({ ctx }: { ctx: EvidenceContext }) {
  const { hexData, bytes, error } = useArtifactBytes(ctx);
  if (error) {
    return <div className="m-2 border border-err/50 p-2 font-mono text-[11px] text-err">{error}</div>;
  }
  if (hexData) {
    return (
      <>
        <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
          {hexData.rows.map((row) => (
            <div key={row.offset}>
              <span className="text-fg-muted">{row.offset.toString(16).padStart(8, "0")}</span>
              {"  "}
              {row.hex}
              {"  "}
              <span className="text-orange">{row.ascii}</span>
            </div>
          ))}
        </pre>
        <div className="sticky bottom-0 border-t border-line bg-panel px-2 py-0.5 font-mono text-[10px] text-fg-muted">
          {hexData.rows.length} rows from offset 0x0 · {hexData.total_size} bytes total · first 512 bytes this arc
        </div>
      </>
    );
  }
  if (bytes) {
    const rows = hexDump(bytes);
    return (
      <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
        {rows.map((row) => (
          <div key={row.offset}>
            <span className="text-fg-muted">{row.offset.toString(16).padStart(8, "0")}</span>
            {"  "}
            {row.hex}
            {"  "}
            <span className="text-orange">{row.ascii}</span>
          </div>
        ))}
      </pre>
    );
  }
  return <div className="p-3 font-mono text-[11px] text-fg-muted">select evidence to inspect</div>;
}

function FileAnalysisView() {
  const ctx = useEvidence();
  const highEntropy =
    ctx.selectedArtifact
      ? ctx.selectedArtifact.entropy > 7.5
      : ctx.selectedSample
        ? shannonEntropy(sampleContent(ctx.selectedSample.id)) > 7.5
        : false;

  return (
    <div className="flex h-full min-h-0">
      <EvidenceTree ctx={ctx} />
      <Pane title={`Hex: ${ctx.selectedArtifact?.name ?? ctx.selectedSample?.name ?? "no selection"}`} className="min-w-0 flex-1" bodyClassName="relative">
        <HexBody ctx={ctx} />
      </Pane>
      <Pane title="Inspector" className="w-80 shrink-0">
        {ctx.selectedArtifact ? (
          <>
            <Field label="sha256" value={<span className="break-all">{ctx.selectedArtifact.sha256}</span>} />
            <Field label="md5" value={ctx.selectedArtifact.md5} />
            <Field label="sha1" value={ctx.selectedArtifact.sha1} />
            <Field label="crc32" value={ctx.selectedArtifact.crc32} />
            <Field label="signature" value={ctx.selectedArtifact.signature ?? "unrecognized"} />
            <Field label="size" value={`${ctx.selectedArtifact.size} bytes`} />
            <Field label="entropy" value={formatEntropy(ctx.selectedArtifact.entropy)} />
            <Field label="imported" value={new Date(Number(ctx.selectedArtifact.imported_at)).toLocaleString()} />
            <Field label="original path" value={ctx.selectedArtifact.original_path ?? "n/a"} />
            <Field label="case" value={ctx.selectedArtifact.case_id} />
          </>
        ) : ctx.selectedSample ? (
          sampleMetadata(ctx.selectedSample).map((row) => <Field key={row.key} label={row.key} value={row.value} />)
        ) : (
          <div className="p-3 font-mono text-[11px] text-fg-muted">select evidence to inspect</div>
        )}
        {highEntropy ? (
          <div className="px-3 py-1.5">
            <Chip tone="orange">high entropy; compressed or encrypted?</Chip>
          </div>
        ) : null}
        <div className="border-t border-line p-2">
          <ToolButton disabled title="Extraction with path safety and decompression-bomb guards, arc 3">Extract…</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="YARA-X rules, arc 3">YARA scan</ToolButton>
        </div>
      </Pane>
    </div>
  );
}

function MetadataView() {
  const ctx = useEvidence();
  return (
    <div className="flex h-full min-h-0">
      <EvidenceTree ctx={ctx} />
      <Pane title={`Metadata: ${ctx.selectedArtifact?.name ?? ctx.selectedSample?.name ?? "no selection"}`} className="min-w-0 flex-1">
        {ctx.selectedArtifact ? (
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-32">Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr><td className="text-fg">sha256</td><td className="text-fg-dim">{ctx.selectedArtifact.sha256}</td></tr>
              <tr><td className="text-fg">md5</td><td className="text-fg-dim">{ctx.selectedArtifact.md5}</td></tr>
              <tr><td className="text-fg">sha1</td><td className="text-fg-dim">{ctx.selectedArtifact.sha1}</td></tr>
              <tr><td className="text-fg">crc32</td><td className="text-fg-dim">{ctx.selectedArtifact.crc32}</td></tr>
              <tr><td className="text-fg">signature</td><td className="text-fg-dim">{ctx.selectedArtifact.signature ?? "unrecognized"}</td></tr>
              <tr><td className="text-fg">size</td><td className="text-fg-dim">{ctx.selectedArtifact.size} bytes</td></tr>
              <tr><td className="text-fg">entropy</td><td className="text-fg-dim">{formatEntropy(ctx.selectedArtifact.entropy)}</td></tr>
              <tr><td className="text-fg">imported</td><td className="text-fg-dim">{new Date(Number(ctx.selectedArtifact.imported_at)).toLocaleString()}</td></tr>
            </tbody>
          </table>
        ) : ctx.selectedSample ? (
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-32">Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {sampleMetadata(ctx.selectedSample).map((row) => (
                <tr key={row.key}>
                  <td className="text-fg">{row.key}</td>
                  <td className="text-fg-dim">{row.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="p-3 font-mono text-[11px] text-fg-muted">select evidence to inspect</div>
        )}
      </Pane>
    </div>
  );
}

function StringsView() {
  const ctx = useEvidence();
  const [minLength, setMinLength] = useState("4");
  const min = Math.max(2, Number.parseInt(minLength, 10) || 4);
  const id = ctx.selected?.id ?? null;
  const real = ctx.selected?.real ?? false;
  const [hits, setHits] = useState<StringHitWire[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setHits(null);
    setError(null);
    if (!id || !real) return;
    let cancelled = false;
    fileStrings(id, min, 500)
      .then((data) => {
        if (!cancelled) setHits(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [id, real, min]);

  const localHits = useMemo(() => {
    if (real || !ctx.selectedSample) return null;
    return extractFromSample(ctx.selectedSample.id, min);
  }, [real, ctx.selectedSample, min]);

  const rows = hits ?? localHits;

  return (
    <div className="flex h-full min-h-0">
      <EvidenceTree ctx={ctx} />
      <Pane
        title={`Strings: ${ctx.selectedArtifact?.name ?? ctx.selectedSample?.name ?? "no selection"}`}
        className="min-w-0 flex-1"
        actions={
          <>
            <span className="font-mono text-[10px] text-fg-muted">min length</span>
            <TextInput value={minLength} onChange={setMinLength} ariaLabel="Minimum string length" className="w-12" />
            {rows ? <Chip tone="ok">{rows.length} hits</Chip> : null}
          </>
        }
      >
        {error ? (
          <div className="m-2 border border-err/50 p-2 font-mono text-[11px] text-err">{error}</div>
        ) : rows ? (
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-24">Offset</th>
                <th>String</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((hit) => (
                <tr key={hit.offset}>
                  <td className="text-fg-muted">0x{hit.offset.toString(16)}</td>
                  <td className="text-fg">{hit.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="p-3 font-mono text-[11px] text-fg-muted">select evidence to scan</div>
        )}
      </Pane>
      <Pane title="Entropy profile" className="w-72 shrink-0">
        {ctx.selectedArtifact ? (
          <>
            <Field label="whole file" value={formatEntropy(ctx.selectedArtifact.entropy)} />
            <Field label="bytes" value={`${ctx.selectedArtifact.size}`} />
            <Field label="computed" value="native engine at import time" />
          </>
        ) : ctx.selectedSample ? (
          <>
            <Field label="whole file" value={formatEntropy(shannonEntropy(sampleContent(ctx.selectedSample.id)))} />
            <Field label="bytes" value={`${sampleContent(ctx.selectedSample.id).length}`} />
            <Field label="computed" value="webview (sample fallback)" />
          </>
        ) : (
          <div className="p-3 font-mono text-[11px] text-fg-muted">select evidence to profile</div>
        )}
        <div className="p-3 font-mono text-[10px] leading-relaxed text-fg-muted">
          per-region entropy blocks and the binwalk-compatible signature sweep arrive arc 3.
        </div>
      </Pane>
    </div>
  );
}

function extractFromSample(id: string, minLength: number): StringHitWire[] {
  return extractStrings(sampleContent(id), minLength);
}

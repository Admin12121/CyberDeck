"use client";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { Chip, Field, Pane, Resizer, TextInput, ToolButton } from "@ds/panes";
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
import { useWorkbench } from "@state/workbench";
import { extractStrings, formatEntropy, shannonEntropy } from "../controller";
import { SAMPLE_EVIDENCE, sampleContent, sampleMetadata } from "../model";

interface Selected {
  /** Real artifact id, or a sample evidence id when in browser fallback. */
  id: string;
  real: boolean;
}

function useEvidenceState() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const [artifacts, setArtifacts] = useState<ArtifactRecord[]>([]);
  const [selected, setSelected] = useState<Selected | null>(null);
  const [query, setQuery] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [treeWidth, setTreeWidth] = useState(288);

  const refresh = useCallback(async () => {
    if (!desktop) return;
    try {
      const list = await fileList(wb.caseId);
      setArtifacts(list);
      setSelected((prev) => {
        if (prev?.real && list.some((a) => a.id === prev.id)) return prev;
        return list[0] ? { id: list[0].id, real: true } : null;
      });
    } catch (err) {
      setImportError(err instanceof Error ? err.message : String(err));
    }
  }, [desktop, wb.caseId]);

  useEffect(() => {
    if (wb.tool.startsWith("forensics.")) void refresh();
  }, [refresh, wb.tool]);

  const importEvidence = useCallback(async () => {
    setBusy(true);
    setImportError(null);
    try {
      await fileImportDialog(wb.caseId);
      await refresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setImportError(message);
    } finally {
      setBusy(false);
    }
  }, [refresh, wb.caseId]);

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
    treeWidth,
    setTreeWidth,
    importEvidence,
    refresh,
  };
}

type EvidenceContext = ReturnType<typeof useEvidenceState>;
const EvidenceContextStore = createContext<EvidenceContext | null>(null);

export function EvidenceProvider({ children }: { children: ReactNode }) {
  const state = useEvidenceState();
  return <EvidenceContextStore.Provider value={state}>{children}</EvidenceContextStore.Provider>;
}

export function useEvidence(): EvidenceContext {
  const state = useContext(EvidenceContextStore);
  if (!state) throw new Error("EvidenceProvider is required for forensic views");
  return state;
}

export function EvidenceTree({ ctx }: { ctx: EvidenceContext }) {
  const q = ctx.query.trim().toLowerCase();
  const realFiles = ctx.artifacts.filter((a) => !q || a.name.toLowerCase().includes(q));
  const sampleFiles = SAMPLE_EVIDENCE.filter((f) => !q || f.name.toLowerCase().includes(q));

  return (
    <>
    <Pane
      title={`Evidence${ctx.desktop ? "" : " (samples, browser fallback)"}`}
      className="shrink-0"
      style={{ width: ctx.treeWidth }}
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
    <Resizer direction="horizontal" ariaLabel="Resize evidence tree" value={ctx.treeWidth} onChange={ctx.setTreeWidth} min={192} max={420} />
    </>
  );
}

export function useArtifactBytes(ctx: EvidenceContext) {
  const wb = useWorkbench();
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
      fileHex(wb.caseId, id, 0, 512)
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
  }, [id, real, wb.caseId]);

  return { hexData, bytes, error };
}

export function HexBody({ ctx }: { ctx: EvidenceContext }) {
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


"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
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
import { extractStrings, formatEntropy, shannonEntropy } from "../controller";
import { SAMPLE_EVIDENCE, sampleContent, sampleMetadata } from "../model";

import { EvidenceTree, useEvidence } from "./shared";
import { useWorkbench } from "@state/workbench";

export function StringsView() {
  const wb = useWorkbench();
  const ctx = useEvidence();
  const [minLength, setMinLength] = useState("4");
  const [entropyWidth, setEntropyWidth] = useState(288);
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
    fileStrings(wb.caseId, id, min, 500)
      .then((data) => {
        if (!cancelled) setHits(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [id, real, min, wb.caseId]);

  const localHits = useMemo(() => {
    if (real || !ctx.selectedSample) return null;
    return extractFromSample(ctx.selectedSample.id, min);
  }, [real, ctx.selectedSample, min]);

  const rows = hits ?? localHits;

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
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
      <Resizer direction="horizontal" flip ariaLabel="Resize entropy profile" value={entropyWidth} onChange={setEntropyWidth} min={220} max={440} />
      <Pane title="Entropy profile" className="shrink-0" style={{ width: entropyWidth }}>
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

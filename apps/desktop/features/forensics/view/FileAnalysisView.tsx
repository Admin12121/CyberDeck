"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Chip, Field, Pane, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import {
  fileHex,
  fileSignatureScan,
  fileExtractGzip,
  fileExtractArchive,
  type SignatureScanWire,
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

import { EvidenceTree, HexBody, useArtifactBytes, useEvidence } from "./shared";
import { useWorkbench } from "@state/workbench";

export function FileAnalysisView() {
  const ctx = useEvidence();
  const wb = useWorkbench();
  const [scan, setScan] = useState<SignatureScanWire | null>(null);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [extracting, setExtracting] = useState<number | null>(null);
  const [extractNote, setExtractNote] = useState<string | null>(null);
  useEffect(() => { setScan(null); setScanError(null); setExtractNote(null); }, [ctx.selectedArtifact?.id, wb.caseId]);
  const extract = async (offset: number) => {
    const artifact = ctx.selectedArtifact;
    if (!artifact || extracting !== null) return;
    setExtracting(offset);
    setScanError(null);
    setExtractNote(null);
    try {
      const output = await fileExtractGzip(wb.caseId, artifact.id, offset);
      setExtractNote("Extracted into this case: " + output.name);
      await ctx.refresh();
    } catch (cause) { setScanError(String(cause)); }
    finally { setExtracting(null); }
  };
  const extractArchive = async (format: "zip" | "tar", offset: number) => {
    const artifact = ctx.selectedArtifact;
    if (!artifact || extracting !== null) return;
    setExtracting(offset);
    setScanError(null);
    setExtractNote(null);
    try {
      const outputs = await fileExtractArchive(wb.caseId, artifact.id, format, offset);
      setExtractNote(`Extracted ${outputs.length} ${format.toUpperCase()} files into this case`);
      await ctx.refresh();
    } catch (cause) { setScanError(String(cause)); }
    finally { setExtracting(null); }
  };
  const runScan = async () => {
    const artifact = ctx.selectedArtifact;
    if (!artifact) return;
    setScanBusy(true);
    setScanError(null);
    try { setScan(await fileSignatureScan(wb.caseId, artifact.id)); }
    catch (cause) { setScanError(String(cause)); }
    finally { setScanBusy(false); }
  };
  const highEntropy =
    ctx.selectedArtifact
      ? ctx.selectedArtifact.entropy > 7.5
      : ctx.selectedSample
        ? shannonEntropy(sampleContent(ctx.selectedSample.id)) > 7.5
        : false;

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
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
        <div className="border-t border-line p-2 space-y-2">
          <ToolButton onClick={() => void runScan()} disabled={!ctx.selectedArtifact || !ctx.desktop || scanBusy}
            title="Native Rust scan of the first 16 MiB; includes SHA-256 verification for smaller evidence">
            {scanBusy ? "Scanning…" : "Scan Embedded Formats"}
          </ToolButton>
          {scanError ? <div className="text-xs text-err">{scanError}</div> : null}
          {extractNote ? <div className="text-xs text-fg">{extractNote}</div> : null}
          {scan ? (
            <div className="space-y-1 font-mono text-[10px] text-fg-dim">
              <div>{scan.hits.length} signatures · {scan.scanned_bytes} bytes scanned
                {scan.truncated ? " (first 16 MiB only)" : ""}
                {scan.integrity_checked ? " · SHA-256 verified" : ""}
              </div>
              {scan.hits.map((hit, index) => (
                <div key={index} className="flex gap-2 border-t border-line py-1">
                  <span className="shrink-0 text-orange">0x{hit.offset.toString(16)}</span>
                  <span className="flex-1">{hit.format}: {hit.description}</span>
                  {(hit.format === "zip" || hit.format === "tar") && (
                    <ToolButton
                      onClick={() => void extractArchive(hit.format as "zip" | "tar", hit.offset)}
                      disabled={extracting !== null || !ctx.desktop}
                      title="Native Rust extraction: validates paths, CRC/checksums, 128-entry and 16 MiB limits"
                    >
                      {extracting === hit.offset ? "Extracting…" : `Extract ${hit.format.toUpperCase()}`}
                    </ToolButton>
                  )}
                  {hit.format === "gzip" && (
                    <ToolButton
                      onClick={() => void extract(hit.offset)}
                      disabled={extracting !== null || !ctx.desktop}
                      title="Safely decompress one Gzip member (16 MiB input/output limits) into this case"
                    >
                      {extracting === hit.offset ? "Extracting…" : "Extract Gzip"}
                    </ToolButton>
                  )}
                </div>
              ))}
              {scan.hits.length === 0 ? <div>No known signatures detected.</div> : null}
            </div>
          ) : null}
          <ToolButton disabled title="Additional archive parsers under development">Other archive formats pending</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="YARA-X rules, arc 3">YARA scan</ToolButton>
        </div>
      </Pane>
    </div>
  );
}


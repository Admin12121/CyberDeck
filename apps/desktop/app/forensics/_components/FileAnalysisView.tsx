"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Chip, Field, Pane, Resizer, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import {
  fileHex,
  fileSignatureScan,
  fileCarvePreview,
  fileExtractGzip,
  fileExtractArchive,
  fileExtractNestedArchive,
  fileBinaryInspect,
  type BinaryInfoWire,
  type SignatureScanWire,
  type FileCarveResponseWire,
  fileImportDialog,
  fileList,
  fileStrings,
  isDesktop,
  type ArtifactRecord,
  type HexResponseWire,
  type StringHitWire,
} from "@lib/ipc";
import type { ToolId } from "@state/tool-registry";
import { extractStrings, formatEntropy, shannonEntropy } from "./controller";
import { SAMPLE_EVIDENCE, sampleContent, sampleMetadata } from "./model";

import { EvidenceTree, HexBody, useArtifactBytes, useEvidence } from "./shared";
import { YaraSubsetPanel } from "./YaraSubsetPanel";
import { useWorkbench } from "@state/workbench";

export function FileAnalysisView({ active }: { active: boolean }) {
  const ctx = useEvidence();
  const wb = useWorkbench();
  const [scan, setScan] = useState<SignatureScanWire | null>(null);
  const [carve, setCarve] = useState<FileCarveResponseWire | null>(null);
  const [carveBusy, setCarveBusy] = useState(false);
  const [carveError, setCarveError] = useState<string | null>(null);
  const carveSerial = useRef(0);
  const [binary, setBinary] = useState<BinaryInfoWire | null>(null);
  const [binaryBusy, setBinaryBusy] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [inspectorWidth, setInspectorWidth] = useState(320);
  const [extracting, setExtracting] = useState<number | null>(null);
  const [extractNote, setExtractNote] = useState<string | null>(null);
  const [extractedRecords, setExtractedRecords] = useState<ArtifactRecord[]>([]);
  const activeScope = useRef("");
  activeScope.current = wb.caseId + ":" + (ctx.selectedArtifact?.id ?? "");
  const stillActive = (scope: string) => activeScope.current === scope;

  useEffect(() => {
    carveSerial.current += 1;
    setScan(null);
    setCarve(null);
    setCarveError(null);
    setCarveBusy(false);
    setBinary(null);
    setScanError(null);
    setExtracting(null);
    setScanBusy(false);
    setBinaryBusy(false);
  }, [ctx.selectedArtifact?.id, wb.caseId]);
  useEffect(() => {
    setExtractNote(null);
    setExtractedRecords([]);
  }, [wb.caseId]);
  const extract = async (offset: number) => {
    const artifact = ctx.selectedArtifact;
    if (!artifact || extracting !== null) return;
    const scope = activeScope.current;
    setExtracting(offset);
    setScanError(null);
    setExtractNote(null);
    setExtractedRecords([]);
    try {
      const output = await fileExtractGzip(wb.caseId, artifact.id, offset);
      if (!stillActive(scope)) return;
      setExtractNote("Extracted into this case: " + output.name);
      setExtractedRecords([output]);
      await ctx.refresh();
      ctx.setSelected({ id: output.id, real: true });
      ctx.setHexOffset(0);
    } catch (cause) { if (stillActive(scope)) setScanError(String(cause)); }
    finally { if (stillActive(scope)) setExtracting(null); }
  };
  const extractArchive = async (format: "zip" | "tar", offset: number) => {
    const artifact = ctx.selectedArtifact;
    if (!artifact || extracting !== null) return;
    const scope = activeScope.current;
    setExtracting(offset);
    setScanError(null);
    setExtractNote(null);
    setExtractedRecords([]);
    try {
      const outputs = await fileExtractArchive(wb.caseId, artifact.id, format, offset);
      if (!stillActive(scope)) return;
      setExtractNote(`Extracted ${outputs.length} ${format.toUpperCase()} files into this case`);
      setExtractedRecords(outputs);
      await ctx.refresh();
      if (outputs[0]) {
        ctx.setSelected({ id: outputs[0].id, real: true });
        ctx.setHexOffset(0);
      }
    } catch (cause) { if (stillActive(scope)) setScanError(String(cause)); }
    finally { if (stillActive(scope)) setExtracting(null); }
  };
  const extractNested = async (format: "zip" | "tar" | "gzip", offset: number) => {
    const artifact = ctx.selectedArtifact;
    if (!artifact || extracting !== null) return;
    if (!window.confirm("Extract up to two nested archive levels as derived case evidence?")) return;
    const scope = activeScope.current;
    setExtracting(offset);
    setScanError(null);
    setExtractNote(null);
    setExtractedRecords([]);
    try {
      const children = await fileExtractNestedArchive(wb.caseId, artifact.id, format, offset, 2);
      if (!stillActive(scope)) return;
      setExtractNote("Extracted " + children.length + " nested members into this case");
      setExtractedRecords(children);
      await ctx.refresh();
      if (children[0]) {
        ctx.setSelected({ id: children[0].id, real: true });
        ctx.setHexOffset(0);
      }
    } catch (cause) { if (stillActive(scope)) setScanError(String(cause)); }
    finally { if (stillActive(scope)) setExtracting(null); }
  };
  const inspectBinary = async () => {
    const selected = ctx.selectedArtifact;
    if (!selected) return;
    const scope = activeScope.current;
    setBinaryBusy(true);
    setScanError(null);
    setBinary(null);
    try {
      const inspected = await fileBinaryInspect(wb.caseId, selected.id);
      if (stillActive(scope)) setBinary(inspected);
    } catch (cause) {
      if (stillActive(scope)) setScanError(String(cause));
    } finally { if (stillActive(scope)) setBinaryBusy(false); }
  };
  const runScan = async () => {
    const artifact = ctx.selectedArtifact;
    if (!artifact) return;
    const scope = activeScope.current;
    setScanBusy(true);
    setScanError(null);
    try {
      const result = await fileSignatureScan(wb.caseId, artifact.id);
      if (stillActive(scope)) setScan(result);
    } catch (cause) {
      if (stillActive(scope)) setScanError(String(cause));
    } finally { if (stillActive(scope)) setScanBusy(false); }
  };
  const runCarvePreview = async () => {
    const artifact = ctx.selectedArtifact;
    if (!active || !ctx.desktop || !artifact || carveBusy) return;
    const scope = activeScope.current;
    const ticket = ++carveSerial.current;
    const isCurrent = () => stillActive(scope) && ticket === carveSerial.current;
    const offset = ctx.hexOffset;
    const size = artifact.size;
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || offset >= size) {
      setCarveError("Select a valid source offset within this evidence file.");
      return;
    }
    const len = Math.min(4 * 1024 * 1024, size - offset);
    setCarve(null);
    setCarveError(null);
    setCarveBusy(true);
    try {
      const result = await fileCarvePreview(wb.caseId, artifact.id, offset, len);
      if (isCurrent()) setCarve(result);
    } catch (cause) {
      if (isCurrent()) setCarveError(String(cause));
    } finally {
      if (isCurrent()) setCarveBusy(false);
    }
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
        <HexBody ctx={ctx} enabled={active} />
      </Pane>
      <Resizer direction="horizontal" flip ariaLabel="Resize file inspector" value={inspectorWidth} onChange={setInspectorWidth} min={240} max={520} />
      <Pane title="Inspector" className="shrink-0" style={{ width: inspectorWidth }}>
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
            title="Native signature scan of up to 16 MiB; verifies SHA-256 of the entire stored evidence file">
            {scanBusy ? "Scanning…" : "Scan Embedded Formats"}
          </ToolButton>
          <ToolButton onClick={() => void inspectBinary()} disabled={!ctx.selectedArtifact || !ctx.desktop || binaryBusy}
            title="Native PE, ELF and Mach-O structural inspection with SHA-256 verification and strict size limits">
            {binaryBusy ? "Inspecting…" : "Inspect Executable"}
          </ToolButton>
          <ToolButton onClick={() => void runCarvePreview()}
            disabled={!ctx.selectedArtifact || !ctx.desktop || !active || carveBusy}
            title="Read-only structural PNG / RIFF-WAVE / JPEG boundary preview from selected evidence offset, max 4 MiB; full source SHA-256 verified">
            {carveBusy ? "Validating boundaries…" : "Preview Structural Carving"}
          </ToolButton>
          {binary ? (
            <div className="space-y-1 border-t border-line py-2 font-mono text-[10px] text-fg-dim">
              <div className="text-fg">{binary.format.toUpperCase()} · {binary.architecture} · {binary.bits}-bit</div>
              <div>{binary.little_endian ? "Little-endian" : "Big-endian"} · {binary.sections.length} sections</div>
              <div>Entry ({binary.entry_kind}): {binary.entry_point === null ? "n/a" : `0x${binary.entry_point.toString(16)}`}</div>
              <div className="max-h-60 overflow-y-auto border-t border-line">
                {binary.sections.slice(0, 64).map((section, index) => (
                  <div key={index} className="border-b border-line/50 py-1">
                    <div className="text-fg break-all">{section.name || `section ${index}`}</div>
                    <div>file 0x{section.offset.toString(16)} · {section.size} bytes</div>
                    <div>address 0x{section.address.toString(16)}</div>
                  </div>
                ))}
                {binary.sections.length > 64 ? <div>Showing first 64 of {binary.sections.length} sections</div> : null}
              </div>
            </div>
          ) : null}
          {scanError ? <div className="text-xs text-err">{scanError}</div> : null}
          {carveError ? <div className="text-xs text-err">{carveError}</div> : null}
          {carve ? (
            <div className="space-y-1 border-t border-line py-2 font-mono text-[10px] text-fg-dim">
              <div className="text-fg">Read-only PNG / RIFF-WAVE / JPEG structural candidates: {carve.candidates.length} (max 32)</div>
              <div>
                Verified source: {carve.integrity_checked ? "yes" : "no"} ·
                {" "}{carve.analyzed_bytes} bytes starting at 0x{carve.analyzed_offset.toString(16)}
                {" "}of {carve.file_bytes} total
                {carve.coverage_truncated ? " · partial window" : ""}
                {carve.candidate_limit_reached ? " · candidate limit reached" : ""}
                {carve.rejected_or_incomplete ? ` · ${carve.rejected_or_incomplete} rejected/incomplete` : ""}
              </div>
              <div>Structural bounds only: PNG chunks/CRC, RIFF-WAVE framing and JPEG markers/restarts. No image pixels decoded, compressed payload decompression, fragment recovery, automatic extraction or evidence changes.</div>
              {carve.candidates.map((candidate, index) => (
                <div key={index} className="flex gap-2 border-t border-line py-1">
                  <ToolButton title="Navigate to verified source offset" onClick={() => ctx.setHexOffset(candidate.offset)}>
                    0x{candidate.offset.toString(16)}
                  </ToolButton>
                  <span>{candidate.format.toUpperCase()} · {candidate.length} bytes</span>
                </div>
              ))}
              {carve.candidates.length === 0 ? <div>No structurally validated PNG / RIFF-WAVE / JPEG members in this window.</div> : null}
            </div>
          ) : null}
          {extractNote ? <div role="status" className="text-xs text-fg">{extractNote}</div> : null}
          {extractedRecords.length > 0 ? (
            <section aria-label="Derived case artifacts" className="space-y-1 border-t border-line py-2">
              <h4 className="font-mono text-xs font-semibold text-fg">Derived evidence · {extractedRecords.length} case record(s)</h4>
              <p className="text-[10px] text-fg-muted">Read-only list of backend-created case artifacts. Choose any record to inspect its verified source bytes; provenance remains in the case store.</p>
              {extractedRecords.slice(0, 128).map((record) => (
                <div key={record.id} className="flex flex-wrap items-center gap-2 border-b border-line/50 py-1 font-mono text-[10px]">
                  <ToolButton onClick={() => { if (ctx.artifacts.some((a) => a.id === record.id && a.case_id === wb.caseId)) { ctx.setSelected({ id: record.id, real: true }); ctx.setHexOffset(0); } }}
                    disabled={!ctx.artifacts.some((a) => a.id === record.id && a.case_id === wb.caseId)}
                    title="Inspect this derived artifact in the current case">{record.name}</ToolButton>
                  <span className="break-all text-fg-muted">{record.size.toLocaleString()} bytes · SHA-256 {record.sha256.slice(0, 16)}…</span>
                </div>
              ))}
              {extractedRecords.length > 128 ? <p className="text-[10px] text-fg-muted">Showing 128 of {extractedRecords.length} case records.</p> : null}
            </section>
          ) : null}
          {scan ? (
            <div className="space-y-1 font-mono text-[10px] text-fg-dim">
              <div>{scan.hits.length} candidate signatures · {scan.scanned_bytes} of {scan.file_bytes} bytes scanned
                {scan.truncated ? " · partial coverage" : ""}
                {scan.integrity_checked ? " · full-source SHA-256 verified" : ""}
                {scan.hit_cap_reached ? " · hit limit reached" : ""}
              </div>
              {scan.hits.map((hit, index) => (
                <div key={index} className="flex gap-2 border-t border-line py-1">
                  <ToolButton title="Open signature candidate in verified source hex"
                    onClick={() => ctx.setHexOffset(hit.offset)}>0x{hit.offset.toString(16)}</ToolButton>
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
                  {(hit.format === "zip" || hit.format === "tar" || hit.format === "gzip") && (
                    <ToolButton onClick={() => void extractNested(hit.format as "zip" | "tar" | "gzip", hit.offset)}
                      disabled={extracting !== null || !ctx.desktop}
                      title="Explicitly extract up to two nested archive levels into immutable case evidence">
                      {extracting === hit.offset ? "Extracting…" : "Extract Nested"}
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

          <YaraSubsetPanel caseId={wb.caseId} artifactId={ctx.selectedArtifact?.id ?? null}
            size={ctx.selectedArtifact?.size ?? 0} offset={ctx.hexOffset} desktop={ctx.desktop} active={active}
            onOpenOffset={(offset) => ctx.setHexOffset(offset)} />
        </div>
      </Pane>
    </div>
  );
}


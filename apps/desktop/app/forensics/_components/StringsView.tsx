"use client";
import { useEffect, useRef, useState } from "react";
import { EmptyState, Pane, Resizer, TextInput, ToolButton } from "@ds/panes";
import { ErrorStrip } from "@ds/compact";
import {
  fileEntropyRegions,
  fileStringsScan,
  type ForensicEntropyResponseWire,
  type ForensicStringsResponseWire,
} from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import { EvidenceTree, useEvidence } from "./shared";

const MAX_WINDOW = 8 * 1024 * 1024;
const MAX_HITS = 500;
const ENTROPY_BLOCK = 4096;

export function StringsView() {
  const wb = useWorkbench();
  const ctx = useEvidence();
  const artifact = ctx.selectedArtifact;
  const [minLength, setMinLength] = useState("4");
  const [entropyWidth, setEntropyWidth] = useState(320);
  const [strings, setStrings] = useState<ForensicStringsResponseWire | null>(null);
  const [entropy, setEntropy] = useState<ForensicEntropyResponseWire | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const serial = useRef(0);

  useEffect(() => {
    serial.current++;
    setStrings(null);
    setEntropy(null);
    setError(null);
    setBusy(false);
  }, [wb.caseId, artifact?.id]);

  const analyze = async () => {
    if (!ctx.desktop || !artifact || busy || artifact.size === 0) return;
    const ticket = ++serial.current;
    const min = Math.min(128, Math.max(2, Number.parseInt(minLength, 10) || 4));
    const len = Math.min(MAX_WINDOW, artifact.size);
    setBusy(true);
    setStrings(null);
    setEntropy(null);
    setError(null);
    try {
      const [extracted, regions] = await Promise.all([
        fileStringsScan(wb.caseId, artifact.id, 0, len, min, MAX_HITS),
        fileEntropyRegions(wb.caseId, artifact.id, 0, len, ENTROPY_BLOCK),
      ]);
      if (ticket !== serial.current) return;
      setStrings(extracted);
      setEntropy(regions);
    } catch (cause) {
      if (ticket === serial.current) setError(String(cause));
    } finally {
      if (ticket === serial.current) setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <EvidenceTree ctx={ctx} />
      <Pane title={`Strings: ${artifact?.name ?? "no selection"}`} className="min-w-0 flex-1"
        actions={<div className="flex items-center gap-2">
          <span className="font-mono text-2xs text-fg-muted">Minimum length</span>
          <TextInput value={minLength} onChange={setMinLength} ariaLabel="Minimum string length"
            className="w-12" />
          <ToolButton onClick={() => void analyze()} disabled={!ctx.desktop || !artifact || artifact.size === 0 || busy}
            title="Native ASCII and UTF-16LE/BE scan of up to 8 MiB with full source SHA-256 verification">
            {busy ? "Analyzing…" : "Analyze"}
          </ToolButton>
        </div>}>
        {!ctx.desktop ? (
          <EmptyState title="Native desktop required" detail="No simulated strings are displayed." />
        ) : !artifact ? (
          <EmptyState title="No evidence selected" detail="Select an imported case artifact, then analyze strings and regional entropy." />
        ) : artifact.size === 0 ? (
          <EmptyState title="Empty evidence" detail="This evidence file is empty." />
        ) : (
          <>
            {error ? <ErrorStrip>{error}</ErrorStrip> : null}
            {strings ? (
              <div className="border-b border-line px-3 py-2 font-mono text-2xs text-fg-dim">
                {strings.hits.length} matches (ASCII / UTF-16LE / UTF-16BE) · analyzed {strings.analyzed_bytes.toLocaleString()} of {strings.file_bytes.toLocaleString()} bytes
                {strings.coverage_truncated ? " · partial file coverage" : ""}
                {strings.hit_limit_reached ? " · hit limit reached" : ""}
                {strings.integrity_checked ? " · source SHA-256 verified" : ""}
              </div>
            ) : null}
            {strings ? (
              <table className="data-table">
                <thead><tr><th className="w-28">Offset</th><th className="w-24">Encoding</th><th>String</th></tr></thead>
                <tbody>{strings.hits.map((hit, index) => (
                  <tr key={`${hit.offset}:${hit.encoding}:${index}`}>
                    <td className="font-mono">
                      <ToolButton title="Open this byte offset in Hex"
                        onClick={() => { ctx.setHexOffset(hit.offset); wb.selectTool("forensics.files"); }}>
                        0x{hit.offset.toString(16)}
                      </ToolButton>
                    </td>
                    <td className="text-fg-muted">{hit.encoding.toUpperCase()}</td>
                    <td className="break-all text-fg">{hit.text}</td>
                  </tr>
                ))}</tbody>
              </table>
            ) : <EmptyState title={busy ? "Analyzing" : "No results yet"}
              detail={busy ? "Verifying and analyzing selected evidence…" : "Select Analyze to scan the first 8 MiB. No background scan runs without your action."} />}
          </>
        )}
      </Pane>
      <Resizer direction="horizontal" flip ariaLabel="Resize regional entropy results" value={entropyWidth} onChange={setEntropyWidth} min={220} max={440} />
      <Pane title="Regional entropy" className="shrink-0" style={{ width: entropyWidth }}>
        {entropy ? (
          <div className="p-3">
            <div className="mb-3 text-2xs text-fg-dim">
              {entropy.regions.length} actual blocks · {entropy.block_size} bytes each · {entropy.analyzed_bytes.toLocaleString()} bytes analyzed
              {entropy.coverage_truncated ? " (partial)" : ""}
            </div>
            <div className="space-y-1">
              {entropy.regions.slice(0, 128).map((region) => (
                <div key={region.offset} className="flex items-center gap-2 font-mono text-3xs">
                  <span className="w-20 shrink-0">
                    <ToolButton title="Inspect entropy region in Hex"
                      onClick={() => { ctx.setHexOffset(region.offset); wb.selectTool("forensics.files"); }}>
                      0x{region.offset.toString(16)}
                    </ToolButton>
                  </span>
                  <div className="h-2 flex-1 overflow-hidden bg-raised">
                    <div className="h-full bg-orange" style={{ width: `${Math.max(0, Math.min(100, region.entropy / 8 * 100))}%` }} />
                  </div>
                  <span className="w-9 text-right text-fg">{region.entropy.toFixed(2)}</span>
                </div>
              ))}
            </div>
            {entropy.regions.length > 128 ? (
              <div className="mt-3 font-mono text-3xs text-fg-muted">Displaying first 128 of {entropy.regions.length} measured blocks.</div>
            ) : null}
          </div>
        ) : <EmptyState title={busy ? "Measuring entropy" : "No results yet"}
          detail={busy ? "Calculating native regional entropy…" : "Regional entropy is calculated on demand from the selected evidence."} />}
      </Pane>
    </div>
  );
}

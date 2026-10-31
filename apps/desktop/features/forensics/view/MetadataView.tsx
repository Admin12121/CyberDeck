"use client";
import { useEffect, useState } from "react";
import { Pane, ToolButton } from "@ds/panes";
import { fileMetadataScan, type ForensicMetadataResponseWire } from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import { formatEntropy } from "../controller";
import { EvidenceTree, useEvidence } from "./shared";

export function MetadataView({ active }: { active: boolean }) {
  const ctx = useEvidence();
  const wb = useWorkbench();
  const artifact = ctx.selectedArtifact;
  const [data, setData] = useState<ForensicMetadataResponseWire | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    if (!active || !ctx.desktop || !artifact) {
      setLoading(false);
      return;
    }
    setLoading(true);
    fileMetadataScan(wb.caseId, artifact.id).then(
      (result) => { if (!cancelled) setData(result); },
      (cause) => { if (!cancelled) setError(String(cause)); },
    ).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [active, ctx.desktop, artifact?.id, wb.caseId, revision]);

  const properties = artifact ? [
    ["SHA-256", artifact.sha256],
    ["SHA-1", artifact.sha1],
    ["MD5", artifact.md5],
    ["CRC32", artifact.crc32],
    ["Stored format hint", artifact.signature ?? "unrecognized"],
    ["Size", artifact.size.toLocaleString() + " bytes"],
    ["Whole-file entropy", formatEntropy(artifact.entropy)],
    ["Imported", new Date(Number(artifact.imported_at)).toLocaleString()],
  ] : [];

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <EvidenceTree ctx={ctx} />
      <Pane
        title={`Metadata: ${artifact?.name ?? "no selection"}`}
        className="min-w-0 flex-1"
        actions={<ToolButton onClick={() => setRevision((n) => n + 1)} disabled={!ctx.desktop || !artifact || loading}
          title="Run the native bounded metadata parser again">{loading ? "Inspecting…" : "Refresh metadata"}</ToolButton>}
      >
        {!ctx.desktop ? (
          <div className="p-4 text-xs text-fg-muted">Metadata extraction requires the native desktop runtime. No demonstration results are shown.</div>
        ) : !artifact ? (
          <div className="p-4 text-xs text-fg-muted">Import or select evidence to inspect recorded file properties and native format metadata.</div>
        ) : (
          <div className="space-y-4 p-3">
            <section aria-label="Stored evidence properties">
              <div className="mb-2 font-mono text-xs font-semibold text-fg">Evidence properties</div>
              <table className="data-table">
                <thead><tr><th className="w-44">Property</th><th>Value</th></tr></thead>
                <tbody>{properties.map(([key, value]) => (
                  <tr key={key}><td className="text-fg-dim">{key}</td><td className="break-all font-mono text-fg">{value}</td></tr>
                ))}</tbody>
              </table>
            </section>
            <section aria-label="Parsed native metadata">
              <div className="mb-2 font-mono text-xs font-semibold text-fg">Parsed format metadata</div>
              {error ? <div role="alert" className="border border-err/50 p-2 text-xs text-err">{error}</div> : null}
              {loading ? <div className="text-xs text-fg-muted">Verifying artifact and parsing supported metadata…</div> : null}
              {data ? (
                <>
                  <div className="mb-2 font-mono text-[11px] text-fg-dim">
                    {data.report.format.toUpperCase()} · {data.report.fields.length} fields · {data.analyzed_bytes.toLocaleString()} of {data.file_bytes.toLocaleString()} bytes inspected
                    {data.coverage_truncated ? " · prefix only" : ""} · {data.integrity_checked ? "source SHA-256 verified" : "integrity unverified"}
                  </div>
                  {data.report.fields.length ? (
                    <table className="data-table">
                      <thead><tr><th className="w-28">Namespace</th><th className="w-44">Field</th><th>Value</th><th className="w-24">Offset</th></tr></thead>
                      <tbody>{data.report.fields.map((field, i) => (
                        <tr key={`${field.namespace}:${field.key}:${field.offset}:${i}`}>
                          <td>{field.namespace}</td><td>{field.key}</td>
                          <td className="break-all text-fg">{field.value}</td>
                          <td className="font-mono">0x{field.offset.toString(16)}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  ) : <div className="text-xs text-fg-muted">No supported metadata fields found.</div>}
                  {!data.report.complete || data.coverage_truncated ? (
                    <p className="mt-2 text-xs text-fg-muted">This is a bounded PNG/JPEG parser, not a complete ExifTool or PDF/XMP metadata audit.</p>
                  ) : null}
                </>
              ) : !loading && !error ? (
                <div className="text-xs text-fg-muted">No metadata report available.</div>
              ) : null}
            </section>
          </div>
        )}
      </Pane>
    </div>
  );
}

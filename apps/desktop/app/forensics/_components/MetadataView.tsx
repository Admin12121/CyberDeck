"use client";
import { useEffect, useMemo, useState } from "react";
import { Pane, ToolButton } from "@ds/panes";
import { fileMetadataScan, type ForensicMetadataResponseWire } from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import { formatEntropy } from "./controller";
import { availableMetadataGroups, sourceOffsetHex } from "./metadata-presentation";
import { EvidenceTree, useEvidence } from "./shared";

export function MetadataView({ active }: { active: boolean }) {
  const ctx = useEvidence();
  const wb = useWorkbench();
  const artifact = ctx.selectedArtifact;
  const [data, setData] = useState<ForensicMetadataResponseWire | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);
  const groups = useMemo(() => availableMetadataGroups(data?.report.fields ?? []), [data]);

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
    ["Original source", artifact.original_path ?? "not recorded"],
    ["Case", artifact.case_id],
  ] : [];
  const inspectAt = (offset: number) => {
    if (!artifact || !Number.isSafeInteger(offset) || offset < 0 || offset >= artifact.size) return;
    ctx.setHexOffset(offset);
    wb.selectTool("forensics.files");
  };

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <EvidenceTree ctx={ctx} />
      <Pane title={`Metadata: ${artifact?.name ?? "no selection"}`} className="min-w-0 flex-1"
        actions={<ToolButton onClick={() => setRevision((n) => n + 1)}
          disabled={!ctx.desktop || !artifact || loading}
          title="Re-verify source SHA-256 and rerun the bounded native metadata parser">
          {loading ? "Inspecting…" : "Refresh metadata"}
        </ToolButton>}>
        {!ctx.desktop ? (
          <div className="p-4 text-xs text-fg-muted">Native desktop required. No sample or fabricated EXIF values are displayed.</div>
        ) : !artifact ? (
          <div className="p-4 text-xs text-fg-muted">Select imported case evidence to inspect format metadata and provenance.</div>
        ) : (
          <div className="space-y-4 p-3">
            <section aria-label="Stored evidence properties">
              <h3 className="mb-2 font-mono text-xs font-semibold text-fg">Verified case evidence</h3>
              <table className="data-table">
                <thead><tr><th className="w-44">Property</th><th>Value</th></tr></thead>
                <tbody>{properties.map(([key, value]) => (
                  <tr key={key}><td className="text-fg-dim">{key}</td><td className="break-all font-mono text-fg">{value}</td></tr>
                ))}</tbody>
              </table>
            </section>
            <section aria-label="Parsed native metadata" className="space-y-3">
              <h3 className="font-mono text-xs font-semibold text-fg">Native metadata inspector</h3>
              <p className="text-xs text-fg-muted">Read-only, bounded TIFF/EXIF and PNG/JPEG metadata subset. Values are parsed from the selected case artifact. Original/digitized times are local camera clock values; separate optional UTC offsets and fractional-second digits appear exactly as recorded. A missing offset is unknown, not UTC; no timestamp conversion is performed.</p>
              {error ? <div role="alert" className="border border-err/50 p-2 text-xs text-err">{error}</div> : null}
              {loading ? <div role="status" className="text-xs text-fg-muted">Verifying complete source SHA-256 and parsing available metadata…</div> : null}
              {data ? (
                <>
                  <div className="border border-line p-2 font-mono text-[11px] text-fg-dim">
                    <div>{data.report.format.toUpperCase()} · {data.report.fields.length} fields · {data.analyzed_bytes.toLocaleString()} / {data.file_bytes.toLocaleString()} evidence bytes in inspected window</div>
                    <div>{data.integrity_checked ? "Full source SHA-256 verified" : "Source integrity not verified"}
                      {data.coverage_truncated ? " · prefix coverage only" : ""}
                      {!data.report.complete ? " · metadata parsing ended at a structural boundary" : ""}</div>
                  </div>
                  {groups.length ? groups.map((group) => (
                    <section key={group.name} aria-label={group.name}>
                      <h4 className="mb-1 font-mono text-xs font-semibold text-fg">{group.name}</h4>
                      <table className="data-table">
                        <thead><tr><th className="w-52">Field</th><th>Native value</th><th className="w-36">Evidence offset</th></tr></thead>
                        <tbody>{group.fields.map((field, i) => (
                          <tr key={`${field.namespace}:${field.key}:${field.offset}:${i}`}>
                            <td title={`${field.namespace}.${field.key}`} className="text-fg-dim">{field.label}</td>
                            <td className="break-all font-mono text-fg">{field.value}{field.suffix}</td>
                            <td className="font-mono">
                              <ToolButton
                                title={`${field.offsetBasis}; open verified source hex at ${sourceOffsetHex(field.offset)}`}
                                disabled={!Number.isSafeInteger(field.offset) || field.offset < 0 || field.offset >= artifact.size}
                                onClick={() => inspectAt(field.offset)}>
                                {sourceOffsetHex(field.offset)}
                              </ToolButton>
                            </td>
                          </tr>
                        ))}</tbody>
                      </table>
                    </section>
                  )) : <div className="text-xs text-fg-muted">No supported metadata fields were found. Missing optional camera/GPS tags are not inferred.</div>}
                  <p className="text-xs text-fg-muted">
                    Offset buttons open bytes within the original verified case evidence. EXIF IFD0 offsets identify directory entries; newer SubIFD/GPS offsets identify stored values. Structural metadata does not prove image decodability or complete ExifTool parity.
                  </p>
                </>
              ) : !loading && !error ? (
                <div className="text-xs text-fg-muted">No native metadata report available.</div>
              ) : null}
            </section>
          </div>
        )}
      </Pane>
    </div>
  );
}

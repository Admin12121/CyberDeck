"use client";
/**
 * Forensics feature — view layer.
 * Evidence tree → hex/preview/strings/metadata with inspector (Master Plan
 * §5.6). Arc 1 runs on deterministic sample evidence; import, real hashing,
 * signature scan, YARA-X and extraction move to the Rust core in arc 2.
 */
import { useMemo, useState } from "react";
import { Chip, Field, Pane, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import type { ToolId } from "@features/registry";
import { extractStrings, formatEntropy, shannonEntropy } from "../controller";
import { SAMPLE_EVIDENCE, sampleContent, sampleMetadata, type EvidenceFile } from "../model";

export function ForensicsWorkspace({ tool }: { tool: ToolId }) {
  if (tool === "forensics.metadata") return <MetadataView />;
  if (tool === "forensics.strings") return <StringsView />;
  return <FileAnalysisView />;
}

function useEvidence() {
  const [selected, setSelected] = useState<EvidenceFile>(SAMPLE_EVIDENCE[0]);
  const [query, setQuery] = useState("");
  const files = useMemo(() => {
    const q = query.trim().toLowerCase();
    return SAMPLE_EVIDENCE.filter((f) => !q || f.name.toLowerCase().includes(q));
  }, [query]);
  const content = useMemo(() => sampleContent(selected.id), [selected.id]);
  return { files, query, setQuery, selected, setSelected, content };
}

function EvidenceTree({
  files,
  query,
  setQuery,
  selected,
  onSelect,
}: {
  files: EvidenceFile[];
  query: string;
  setQuery: (v: string) => void;
  selected: EvidenceFile;
  onSelect: (f: EvidenceFile) => void;
}) {
  const groups = ["samples", "archives", "logs"] as const;
  return (
    <Pane title="Evidence" className="w-64 shrink-0" bodyClassName="p-1">
      <div className="p-1">
        <TextInput value={query} onChange={setQuery} placeholder="search evidence…" ariaLabel="Search evidence" className="w-full" />
      </div>
      {groups.map((group) => {
        const items = files.filter((f) => f.group === group);
        if (items.length === 0) return null;
        return (
          <div key={group}>
            <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-fg-muted">▾ {group}</div>
            {items.map((file) => (
              <button
                key={file.id}
                type="button"
                onClick={() => onSelect(file)}
                className={`block w-full truncate px-2 py-1 text-left font-mono text-[11px] ${
                  file.id === selected.id ? "bg-blue-dim text-blue" : "text-fg-dim hover:bg-raised hover:text-fg"
                }`}
              >
                {file.name}
              </button>
            ))}
          </div>
        );
      })}
      <div className="mt-2 border-t border-line p-2">
        <ToolButton disabled title="Import preserves originals + records SHA-256 (§5.6) — arc 2">Import evidence…</ToolButton>
      </div>
    </Pane>
  );
}

function FileAnalysisView() {
  const evidence = useEvidence();
  const { selected, content } = evidence;
  const rows = useMemo(() => hexDump(content), [content]);
  const entropy = useMemo(() => shannonEntropy(content), [content]);

  return (
    <div className="flex h-full min-h-0">
      <EvidenceTree {...evidence} onSelect={evidence.setSelected} />
      <Pane title={`Hex — ${selected.name}`} className="min-w-0 flex-1">
        <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
          {rows.map((row) => (
            <div key={row.offset}>
              <span className="text-fg-muted">{row.offset.toString(16).padStart(8, "0")}</span>
              {"  "}
              {row.hex}
              {"  "}
              <span className="text-blue">{row.ascii}</span>
            </div>
          ))}
        </pre>
      </Pane>
      <Pane title="Inspector" className="w-72 shrink-0">
        {sampleMetadata(selected).map((row) => (
          <Field key={row.key} label={row.key} value={row.value} />
        ))}
        <div className="px-3 py-1.5">
          <div className="text-[10px] uppercase tracking-wider text-fg-muted">computed live</div>
          <div className="font-mono text-xs text-fg-dim">{formatEntropy(entropy)}</div>
          {entropy > 7.5 ? <Chip tone="orange">high entropy — compressed/encrypted?</Chip> : null}
        </div>
        <div className="border-t border-line p-2">
          <ToolButton disabled title="Signature scan — arc 2">Scan signatures</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="Extraction with path safety + decompression-bomb guards — arc 2">Extract…</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="YARA-X rules — arc 2">YARA scan</ToolButton>
        </div>
      </Pane>
    </div>
  );
}

function MetadataView() {
  const evidence = useEvidence();
  return (
    <div className="flex h-full min-h-0">
      <EvidenceTree {...evidence} onSelect={evidence.setSelected} />
      <Pane title={`Metadata — ${evidence.selected.name}`} className="min-w-0 flex-1">
        <table className="data-table">
          <thead>
            <tr>
              <th className="w-40">Key</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {sampleMetadata(evidence.selected).map((row) => (
              <tr key={row.key}>
                <td className="text-fg">{row.key}</td>
                <td className="text-fg-dim">{row.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Pane>
    </div>
  );
}

function StringsView() {
  const evidence = useEvidence();
  const [minLength, setMinLength] = useState("4");
  const min = Math.max(2, Number.parseInt(minLength, 10) || 4);
  const hits = useMemo(() => extractStrings(evidence.content, min), [evidence.content, min]);

  return (
    <div className="flex h-full min-h-0">
      <EvidenceTree {...evidence} onSelect={evidence.setSelected} />
      <Pane
        title={`Strings — ${evidence.selected.name}`}
        className="min-w-0 flex-1"
        actions={
          <>
            <span className="font-mono text-[10px] text-fg-muted">min length</span>
            <TextInput value={minLength} onChange={setMinLength} ariaLabel="Minimum string length" className="w-12" />
            <Chip tone="ok">{hits.length} hits</Chip>
          </>
        }
      >
        <table className="data-table">
          <thead>
            <tr>
              <th className="w-24">Offset</th>
              <th>String</th>
            </tr>
          </thead>
          <tbody>
            {hits.map((hit) => (
              <tr key={hit.offset}>
                <td className="text-fg-muted">0x{hit.offset.toString(16)}</td>
                <td className="text-fg">{hit.text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Pane>
      <Pane title="Entropy profile" className="w-72 shrink-0">
        <Field label="whole file" value={formatEntropy(shannonEntropy(evidence.content))} />
        <Field label="bytes" value={`${evidence.content.length}`} />
        <div className="p-3 font-mono text-[10px] leading-relaxed text-fg-muted">
          per-region entropy blocks and the binwalk-compatible signature sweep arrive arc 2.
        </div>
      </Pane>
    </div>
  );
}

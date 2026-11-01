"use client";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { fileYaraSubsetScan, MAX_YARA_SOURCE_BYTES, type YaraSubsetResponse } from "./yara-subset";
import { yaraScanWindow } from "./yara-window";

const STARTER_RULE = `rule file_marker {
  strings:
    $marker = "MZ" ascii
  condition:
    any of them
}`;

export function YaraSubsetPanel({
  caseId, artifactId, size, offset, desktop, active, onOpenOffset,
}: {
  caseId: string;
  artifactId: string | null;
  size: number;
  offset: number;
  desktop: boolean;
  active: boolean;
  onOpenOffset: (offset: number) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [rule, setRule] = useState(STARTER_RULE);
  const [result, setResult] = useState<YaraSubsetResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const window = yaraScanWindow(size, offset);

  useEffect(() => {
    generation.current += 1;
    setResult(null);
    setError(null);
    setBusy(false);
  }, [caseId, artifactId]);

  const run = async () => {
    if (!desktop || !active || !artifactId || !window || busy) return;
    const ticket = ++generation.current;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const data = await fileYaraSubsetScan(caseId, artifactId, window.offset, window.len, rule);
      if (ticket === generation.current) setResult(data);
    } catch (cause) {
      if (ticket === generation.current) setError(String(cause));
    } finally {
      if (ticket === generation.current) setBusy(false);
    }
  };

  return (
    <section className="border-t border-line py-2 text-xs">
      <Button variant="outline" size="sm" className="w-full justify-start" onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded} aria-controls="forensics-yara-subset">
        {expanded ? "Hide" : "Open"} YARA-style literal/hex subset
      </Button>
      {expanded ? (
        <div id="forensics-yara-subset" className="mt-2 space-y-2">
          <p className="text-[11px] leading-relaxed text-fg-muted">
            Read-only native rule subset: ASCII / nocase or hex bytes (?? wildcard), 1–16 patterns,
            any/all/N-of-them condition (N up to 16); no regex, modules, full YARA compatibility or executable evaluation.
            Rules stay in this view only and are not saved to evidence.
          </p>
          <label className="block text-[11px] text-fg-dim" htmlFor="forensics-yara-source">Rule source (ASCII, up to 4096 bytes)</label>
          <Textarea id="forensics-yara-source" size="sm" rows={6} spellCheck={false}
            className="font-mono text-xs"
            value={rule} onChange={(event) => { generation.current++; setBusy(false); setResult(null); setError(null); setRule(event.target.value); }} />
          <div className="font-mono text-[10px] text-fg-muted">
            {rule.length} / {MAX_YARA_SOURCE_BYTES} source characters · source window {window
              ? `0x${window.offset.toString(16)}–0x${(window.offset + window.len - 1).toString(16)} (max 1 MiB)`
              : "unavailable"}
          </div>
          <Button size="sm" variant="secondary" onClick={() => void run()}
            disabled={!desktop || !active || !artifactId || !window || busy || !rule.trim() || rule.length > MAX_YARA_SOURCE_BYTES || !/^[\x00-\x7F]*$/.test(rule)}>
            {busy ? "Scanning verified evidence…" : "Scan selected source window"}
          </Button>
          {error ? <div role="alert" className="break-words text-[11px] text-err">{error}</div> : null}
          {result ? (
            <div className="space-y-1 border border-line p-2 font-mono text-[11px]">
              <div className={result.matched ? "text-fg" : "text-fg-muted"}>
                Rule {result.rule}: {result.matched ? "matched" : "no match in examined window"}
              </div>
              <div className="text-fg-muted">
                {result.language_subset} · {result.analyzed_bytes.toLocaleString()} / {result.file_bytes.toLocaleString()} bytes examined
                {result.coverage_truncated ? " · partial file coverage" : ""}
                {result.integrity_checked ? " · complete source SHA-256 verified" : " · integrity not verified"}
              </div>
              {result.hits.map((hit, index) => (
                <div key={`${hit.identifier}:${hit.offset}:${index}`} className="flex gap-2 border-t border-line/50 py-1">
                  <Button variant="ghost" size="xs" onClick={() => onOpenOffset(hit.offset)}
                    title="Open verified source byte offset">
                    0x{hit.offset.toString(16)}
                  </Button>
                  <span className="break-all">{hit.identifier}</span>
                </div>
              ))}
              {result.hits.length === 0 ? <div className="text-fg-muted">No literal/hex hits in this window.</div> : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

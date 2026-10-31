"use client";
/** Case-scoped findings from the shared Rust SQLite evidence store. */
import { useCallback, useEffect, useMemo, useState } from "react";
import { FileSearch, RefreshCcw } from "lucide-react";
import { Chip, EmptyState, Pane, TextInput, ToolButton } from "@ds/panes";
import { caseFindingsList, isDesktop, type FindingRecordWire } from "@lib/ipc";
import { useWorkbench } from "@state/workbench";

export function CaseFindingsView() {
  const wb = useWorkbench();
  const [findings, setFindings] = useState<FindingRecordWire[]>([]);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!isDesktop()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await caseFindingsList(wb.caseId);
      setFindings(data);
      setSelected(data[0]?.id ?? null);
    } catch (cause) {
      setError(String(cause));
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }, [wb.caseId]);

  useEffect(() => { if (wb.tool === "forensics.findings") void refresh(); }, [refresh, wb.tool]);

  const filtered = useMemo(() => {
    const search = query.toLowerCase().trim();
    return findings.filter((item) =>
      !search || [item.title, item.source, item.severity, item.details]
        .some((part) => part.toLowerCase().includes(search)));
  }, [findings, query]);
  const current = filtered.find((f) => f.id === selected) ?? filtered[0] ?? null;
  const severityTone = (value: string) =>
    value === "high" || value === "critical" ? "err" :
    value === "medium" ? "orange" : value === "low" ? "blue" : "muted";

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <FileSearch size={13} className="text-orange" />
        <span className="font-mono text-[10px] uppercase text-fg-muted">Case findings</span>
        <TextInput value={query} onChange={setQuery} placeholder="filter findings…" ariaLabel="Search case findings" className="w-64" />
        <ToolButton onClick={() => void refresh()} disabled={loading || !isDesktop()} title="Refresh findings">
          <RefreshCcw size={12} /> {loading ? "Loading…" : "Refresh"}
        </ToolButton>
        <span className="ml-auto font-mono text-[10px] text-fg-muted">{filtered.length} of {findings.length} · {wb.caseId}</span>
      </div>
      {error ? <div className="border-b border-err/50 px-2 py-1 text-xs text-err">{error}</div> : null}
      <div className="flex min-h-0 flex-1 gap-px bg-line">
        <Pane title="Findings" className="min-w-0 flex-[2]">
          {filtered.length === 0 ? (
            <EmptyState title="No findings saved" detail="Use the Web Scanner with an authorized target, then return here to inspect persisted results." badge="case" />
          ) : (
            <table className="data-table">
              <thead><tr><th className="w-20">Severity</th><th>Title</th><th className="w-28">Source</th><th className="w-32">Recorded</th></tr></thead>
              <tbody>{filtered.map((f) => (
                <tr key={f.id} onClick={() => setSelected(f.id)}
                  className={"cursor-pointer " + (current?.id === f.id ? "selected" : "")}>
                  <td><Chip tone={severityTone(f.severity)}>{f.severity}</Chip></td>
                  <td className="text-fg">{f.title}</td>
                  <td className="text-fg-dim">{f.source}</td>
                  <td className="text-fg-muted">{new Date(f.created_ms).toLocaleString()}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Pane>
        <Pane title={current ? "Finding #" + current.id : "Detail"} className="w-[38%] shrink-0">
          {current ? (
            <div className="space-y-3 overflow-auto p-3">
              <div className="text-sm font-medium text-fg">{current.title}</div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-fg-dim">
                <Chip tone={severityTone(current.severity)}>{current.severity}</Chip>
                <span>{current.source}</span>
                <span>{new Date(current.created_ms).toLocaleString()}</span>
              </div>
              {current.artifact_id ? <div className="break-all font-mono text-xs text-orange">artifact: {current.artifact_id}</div> : null}
              <pre className="whitespace-pre-wrap break-words border-t border-line pt-3 font-mono text-xs text-fg-dim">{current.details}</pre>
            </div>
          ) : <div className="p-3 text-xs text-fg-muted">Select a finding.</div>}
        </Pane>
      </div>
    </div>
  );
}

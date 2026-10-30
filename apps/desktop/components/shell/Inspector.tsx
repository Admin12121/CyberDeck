"use client";
/** Contextual inspector — selected tool metadata + live job summary (§3.4). */
import { toolById } from "@features/registry";
import { useWorkbench } from "@state/workbench";
import { Chip, Field } from "@ds/panes";

export function Inspector() {
  const wb = useWorkbench();
  const tool = toolById(wb.tool);
  const runningJobs = Object.values(wb.jobs).filter((j) => j.status === "running");
  const recentJobs = Object.values(wb.jobs).sort((a, b) => b.startedAt - a.startedAt).slice(0, 5);

  return (
    <aside className="flex w-72 shrink-0 flex-col border-l border-line bg-sidebar" aria-label="Inspector">
      <div className="flex h-8 shrink-0 items-center justify-between border-b border-line px-3">
        <span className="text-[10px] font-medium uppercase tracking-wider text-fg-muted">Inspector</span>
        <button type="button" onClick={wb.toggleInspector} aria-label="Close inspector" className="text-fg-muted hover:text-fg">
          ×
        </button>
      </div>
      <div className="flex-1 overflow-auto">
        <Field label="Workspace" value={tool ? `${tool.category} / ${tool.label}` : wb.tool} />
        <Field label="Purpose" value={<span className="whitespace-normal">{tool?.hint ?? "—"}</span>} />
        <div className="border-b border-line/50 px-3 py-1.5">
          <div className="text-[10px] uppercase tracking-wider text-fg-muted">Engine provenance</div>
          <div className="font-mono text-[11px] leading-relaxed text-fg-dim">
            engines are named in results and diagnostics, never in navigation — capability-first UI (§6)
          </div>
        </div>
        <div className="px-3 py-2">
          <div className="mb-1 flex items-center gap-2 text-[10px] uppercase tracking-wider text-fg-muted">
            Active jobs
            {runningJobs.length > 0 ? <Chip tone="orange">{runningJobs.length} running</Chip> : <Chip>idle</Chip>}
          </div>
          {recentJobs.length === 0 ? (
            <div className="font-mono text-[11px] text-fg-muted">no jobs this session</div>
          ) : (
            <ul className="space-y-1">
              {recentJobs.map((job) => (
                <li key={job.id} className="flex items-center justify-between font-mono text-[11px]">
                  <span className="truncate text-fg-dim">#{job.id} {job.kind}</span>
                  <span className={job.status === "running" ? "text-orange" : job.status === "completed" ? "text-ok" : "text-fg-muted"}>
                    {job.status === "running" ? `${job.percent}%` : job.status}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </aside>
  );
}

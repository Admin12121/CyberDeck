"use client";
/** Bottom dock: live job execution, progress and cancel (§8.3 via §3.4). */
import { useWorkbench } from "@state/workbench";
import { Chip, EmptyState, ToolButton } from "@ds/panes";

export function JobsDock() {
  const wb = useWorkbench();
  if (!wb.dockOpen) return null;
  const jobs = Object.values(wb.jobs).sort((a, b) => b.startedAt - a.startedAt);

  return (
    <div
      className="flex h-full min-h-0 flex-col border-t border-line bg-panel"
      role="region"
      aria-label="Jobs dock"
    >
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-line bg-sidebar px-2">
        <div className="flex items-center gap-1">
          {(["jobs", "console"] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => wb.setDockTab(t)}
              className={`border px-2 font-mono text-[10px] uppercase ${wb.dockTab === t ? "border-orange/50 text-orange" : "border-transparent text-fg-muted hover:text-fg"}`}
            >
              {t}
            </button>
          ))}
        </div>
        <Chip>{jobs.length}</Chip>
        <div className="ml-auto flex items-center gap-2">
          <span className="font-mono text-[10px] text-fg-muted">Ctrl+J toggles this dock</span>
          <button type="button" onClick={wb.toggleDock} aria-label="Close jobs dock" className="text-fg-muted hover:text-fg">
            ×
          </button>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {jobs.length === 0 ? (
          <EmptyState title="No jobs" detail="Start a scan or analysis from its workspace. Operations tracked by the UI appear here; cancellation is available only for backend jobs that support it." />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-16">Job</th>
                <th className="w-20">Kind</th>
                <th className="w-24">Status</th>
                <th className="w-40">Progress</th>
                <th>Message</th>
                <th className="w-24">Action</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id}>
                  <td className="text-fg-muted">{job.id > 0 ? `#${job.id}` : "local"}</td>
                  <td>{job.kind}</td>
                  <td>
                    <span className={job.status === "running" ? "text-orange" : job.status === "completed" ? "text-ok" : job.status === "failed" ? "text-err" : "text-fg-muted"}>
                      {job.status}
                    </span>
                  </td>
                  <td>
                    <div className="h-1.5 w-full min-w-24 border border-line bg-app">
                      <div
                        className={`h-full ${job.status === "running" ? "bg-orange" : job.status === "completed" ? "bg-ok" : "bg-line-strong"}`}
                        style={{ width: `${job.percent}%` }}
                      />
                    </div>
                  </td>
                  <td className="text-fg-dim">{job.message}</td>
                  <td>
                    {job.status === "running" && job.id > 0 ? (
                      <ToolButton tone="danger" onClick={() => wb.cancelJob(job.id)}>cancel</ToolButton>
                    ) : (
                      <span className="font-mono text-[10px] text-fg-muted">{job.status === "running" ? "running" : "—"}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

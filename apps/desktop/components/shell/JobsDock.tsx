"use client";

import { useWorkbenchJobs } from "@state/workbench";
import { EmptyState, ToolButton } from "@ds/panes";

export function JobsDock() {
  const wb = useWorkbenchJobs();
  const jobs = Object.values(wb.jobs).sort((a, b) => b.startedAt - a.startedAt);
  return (
    <div className="h-full min-h-0 overflow-auto bg-panel" role="region" aria-label="All jobs">
      {jobs.length === 0 ? <EmptyState title="No jobs yet" /> : (
        <table className="data-table">
          <thead><tr><th>Job</th><th>Kind</th><th>Status</th><th>Progress</th><th>Action</th></tr></thead>
          <tbody>
            {jobs.map((job) => (
              <tr key={job.id}>
                <td className="text-fg-dim">{job.id > 0 ? `#${job.id}` : "Local"}</td>
                <td>{job.kind}</td>
                <td className={job.status === "failed" ? "text-err" : "text-fg"}>{job.status}</td>
                <td>
                  <div role="progressbar" aria-valuenow={job.percent} aria-valuemin={0} aria-valuemax={100}
                    aria-label={`Job ${job.id} progress`} className="h-1.5 min-w-16 bg-raised">
                    <div className="h-full bg-fg-dim" style={{ width: `${Math.min(100, Math.max(0, job.percent))}%` }} />
                  </div>
                </td>
                <td>{job.status === "running" && job.id > 0 ?
                  <ToolButton onClick={() => wb.cancelJob(job.id)}>Cancel</ToolButton> : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function JobDetail({ jobId }: { jobId: number }) {
  const wb = useWorkbenchJobs();
  const job = wb.jobs[jobId];
  if (!job) return <EmptyState title="Job no longer available" />;
  return (
    <div className="h-full overflow-auto bg-panel p-3 text-sm text-fg" role="region" aria-label={`Job ${jobId} detail`}>
      <div className="mb-3 text-sm font-semibold">{job.kind} · {job.id > 0 ? `#${job.id}` : "Local operation"}</div>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-5 gap-y-2 text-xs">
        <dt className="text-fg-muted">State</dt><dd>{job.status}</dd>
        <dt className="text-fg-muted">Progress</dt><dd>{Math.min(100, Math.max(0, job.percent))}%</dd>
        <dt className="text-fg-muted">Message</dt><dd className="break-words">{job.message}</dd>
      </dl>
      {job.status === "running" && job.id > 0 && (
        <div className="mt-4"><ToolButton onClick={() => wb.cancelJob(job.id)}>Cancel job</ToolButton></div>
      )}
    </div>
  );
}

/**
 * Job model: the frontend mirror of the Rust `JobEvent` wire type
 * (apps/desktop/src-tauri/src/jobs.rs). Keep both sides in sync; these
 * contracts belong to the shared job model in Master Plan §8.3.
 */

export type JobEvent =
  | { type: "started"; job_id: number; total_steps: number }
  | { type: "progress"; job_id: number; step: number; percent: number; message: string }
  | { type: "completed"; job_id: number; message: string }
  | { type: "cancelled"; job_id: number }
  | { type: "failed"; job_id: number; error: string };

export type JobStatus = "running" | "completed" | "cancelled" | "failed";

export interface JobView {
  id: number;
  kind: string;
  status: JobStatus;
  percent: number;
  message: string;
  startedAt: number;
  finishedAt?: number;
}

/** Pure reducer applying a wire event to the job table. */
export function applyJobEvent(
  jobs: Record<number, JobView>,
  event: JobEvent,
  kind: string,
  now: number = Date.now(),
): Record<number, JobView> {
  const job = jobs[event.job_id];
  switch (event.type) {
    case "started":
      return {
        ...jobs,
        [event.job_id]: {
          id: event.job_id,
          kind,
          status: "running",
          percent: 0,
          message: `started (${event.total_steps} units)`,
          startedAt: now,
        },
      };
    case "progress":
      if (!job) return jobs;
      return {
        ...jobs,
        [event.job_id]: { ...job, percent: event.percent, message: event.message },
      };
    case "completed":
      if (!job) return jobs;
      return {
        ...jobs,
        [event.job_id]: {
          ...job,
          status: "completed",
          percent: 100,
          message: event.message,
          finishedAt: now,
        },
      };
    case "cancelled":
      if (!job) return jobs;
      return {
        ...jobs,
        [event.job_id]: { ...job, status: "cancelled", message: "cancelled", finishedAt: now },
      };
    case "failed":
      if (!job) return jobs;
      return {
        ...jobs,
        [event.job_id]: { ...job, status: "failed", message: event.error, finishedAt: now },
      };
  }
}

/** Complete local job only while its original case-bound record is still active. */
export function completeLocalJob(
  jobs: Record<number, JobView>,
  id: number,
  status: "completed" | "failed",
  message: string,
  now: number,
): Record<number, JobView> {
  const job = jobs[id];
  if (!job || job.status !== "running") return jobs;
  return {
    ...jobs,
    [id]: {
      ...job, status,
      percent: status === "completed" ? 100 : job.percent,
      message, finishedAt: now,
    },
  };
}

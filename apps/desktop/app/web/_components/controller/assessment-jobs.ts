import { invoke } from "@tauri-apps/api/core";
import { isDesktop, type WebFindingWire } from "@lib/ipc";

export interface WebAssessmentJob {
  job_id: number;
  kind: "scanner" | "spider";
  state: "running" | "completed" | "failed" | "cancelled";
  processed: number;
  discovered: number;
  findings: WebFindingWire[];
  urls: string[];
  error: string | null;
}

export async function startWebAssessment(
  kind: "scanner" | "spider", targetUrl: string, authorized: boolean, maxDepth = 2,
): Promise<number> {
  if (!isDesktop()) throw new Error("Web assessments require the native desktop runtime");
  return invoke<number>("web_assessment_start_v1", { kind, targetUrl, maxDepth, authorized });
}

export async function webAssessmentStatus(jobId: number): Promise<WebAssessmentJob> {
  if (!Number.isSafeInteger(jobId) || jobId < 1) throw new Error("Invalid Web job ID");
  return invoke<WebAssessmentJob>("web_assessment_status_v1", { jobId });
}

export async function cancelWebAssessment(jobId: number): Promise<WebAssessmentJob> {
  if (!Number.isSafeInteger(jobId) || jobId < 1) throw new Error("Invalid Web job ID");
  return invoke<WebAssessmentJob>("web_assessment_cancel_v1", { jobId });
}

export async function waitForWebAssessment(
  jobId: number, onProgress: (job: WebAssessmentJob) => void,
): Promise<WebAssessmentJob> {
  // This monitor can outlive an individual tool view. Backend owns execution.
  for (;;) {
    const job = await webAssessmentStatus(jobId);
    onProgress(job);
    if (job.state !== "running") return job;
    await new Promise<void>((resolve) => setTimeout(resolve, 500));
  }
}

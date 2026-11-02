import { invoke } from "@tauri-apps/api/core";
import { isDesktop, type WebFindingWire } from "@lib/ipc";

export interface WebPassiveRule {
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high";
}
export interface WebPassiveFinding {
  rule_id: string;
  title: string;
  severity: string;
  confidence: string;
  detail: string;
  evidence: string;
  history_id: number;
  status: number;
}

export interface WebAssessmentJob {
  job_id: number;
  kind: "scanner" | "spider" | "passive" | "active-query" | "active-form" | "active-json";
  state: "running" | "completed" | "failed" | "cancelled";
  processed: number;
  discovered: number;
  findings: WebFindingWire[];
  rule_findings: WebPassiveFinding[];
  urls: string[];
  error: string | null;
}

/** Only response-policy facts are analyzed; no active requests or secret reveal. */
export async function listWebPassiveRules(): Promise<WebPassiveRule[]> {
  if (!isDesktop()) throw new Error("Passive analysis requires CyberDeck desktop");
  return invoke<WebPassiveRule[]>("web_passive_rules_v1");
}
export async function startWebPassiveScan(enabledRules: string[]): Promise<number> {
  if (!isDesktop()) throw new Error("Passive analysis requires CyberDeck desktop");
  if (!enabledRules.length || enabledRules.length > 6 ||
      enabledRules.some((x) => typeof x !== "string")) {
    throw new Error("Select at least one known passive rule");
  }
  return invoke<number>("web_passive_start_v1", { enabledRules });
}

export async function startWebAssessment(
  kind: "scanner" | "spider" | "active-query" | "active-form" | "active-json",
  targetUrl: string, authorized: boolean, maxDepth = 2, probeBody?: string,
): Promise<number> {
  if (!isDesktop()) throw new Error("Web assessments require the native desktop runtime");
  if ((kind === "active-form" || kind === "active-json") &&
      (!probeBody || new TextEncoder().encode(probeBody).length > 2048)) {
    throw new Error("Provide a bounded manual POST template");
  }
  return invoke<number>("web_assessment_start_v1", {
    kind, targetUrl, maxDepth, authorized, probeBody: probeBody ?? null,
  });
}

export async function webAssessmentStatus(jobId: number): Promise<WebAssessmentJob> {
  if (!Number.isSafeInteger(jobId) || jobId < 1) throw new Error("Invalid Web job ID");
  return invoke<WebAssessmentJob>("web_assessment_status_v1", { jobId });
}

/** Save only completed backend-owned Scanner/Active/Passive findings to the selected
 * non-Scratchpad case. No client supplied case ID or findings are accepted. */
export async function saveWebAssessmentFindings(jobId: number): Promise<number> {
  if (!isDesktop()) throw new Error("Web findings need the native desktop runtime");
  if (!Number.isSafeInteger(jobId) || jobId < 1) throw new Error("Invalid Web job ID");
  return invoke<number>("web_assessment_save_findings_v1", { jobId });
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

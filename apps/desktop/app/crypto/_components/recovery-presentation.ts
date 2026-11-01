import type { RecoveryJobStatusV1 } from "@lib/ipc";

export type RecoveryDisplay = {
  kind: "empty" | "discarded" | "case" | "loading" | "running" | "completed" | "no-match" | "cancelled" | "failed" | "expired";
  title: string;
  detail: string;
};

export function recoveryDisplay(
  scope: string | null,
  jobId: number | null,
  status: RecoveryJobStatusV1 | null,
  error: string | null,
  discarded = false,
): RecoveryDisplay {
  if (!scope) {
    return { kind: "case", title: "Case required", detail: "Select a saved case to start authorized recovery." };
  }
  if (error && jobId === null) {
    return { kind: "expired", title: "Result unavailable", detail: error };
  }
  if (jobId === null && discarded) {
    return { kind: "discarded", title: "Result discarded", detail: "Confidential results were cleared. Start a new job when ready." };
  }
  if (jobId === null) {
    return { kind: "empty", title: "No recovery started", detail: "Start a SHA-256 wordlist job to see masked results here." };
  }
  if (!status) {
    return { kind: "loading", title: "Loading job", detail: "Checking the native recovery status…" };
  }
  if (status.phase === "running" || status.phase === "cancelling") {
    return {
      kind: "running",
      title: status.phase === "cancelling" ? "Cancelling recovery" : "Recovery running",
      detail: status.phase === "cancelling" ? "Waiting for the native worker to stop." : "Native wordlist scan is active.",
    };
  }
  if (status.phase === "cancelled") {
    return { kind: "cancelled", title: "Recovery cancelled", detail: "No confidential result was retained." };
  }
  if (status.phase === "failed") {
    return { kind: "failed", title: "Recovery failed", detail: status.error ?? "The native worker reported a failure." };
  }
  const matches = status.summary?.matches.length ?? 0;
  if (matches === 0) {
    return { kind: "no-match", title: "No match found", detail: "No candidate matched within the selected limits." };
  }
  if (!status.reveal_available) {
    return { kind: "expired", title: "Result expired or revoked", detail: "Candidate metadata remains masked. Clear to start again." };
  }
  return {
    kind: "completed",
    title: "Recovery completed",
    detail: matches === 1 ? "One masked candidate found." : String(matches) + " masked candidates found.",
  };
}

export function isSha256WordlistTarget(input: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(input.trim());
}

export function hasCurrentRecoveryScope(
  current: { scope: string; id: number } | null,
  scope: string | null,
  jobId: number | null,
): boolean {
  return scope !== null && jobId !== null && current?.scope === scope && current.id === jobId;
}

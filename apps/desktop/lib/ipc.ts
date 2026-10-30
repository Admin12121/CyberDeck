/**
 * Typed IPC client. The frontend never invokes raw paths or shell commands —
 * every native action goes through a named wrapper here (Master Plan §9.2).
 *
 * When running in a plain browser (next dev without Tauri) the wrappers fall
 * back to a local simulation so UI development does not require the desktop
 * shell. The status bar always shows which transport is live.
 */
import { invoke, Channel } from "@tauri-apps/api/core";
import type { JobEvent } from "@state/jobs-model";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export type JobKindWire = "demo";

export function isDesktop(): boolean {
  return inTauri;
}

export async function jobStart(
  kind: JobKindWire,
  onEvent: (event: JobEvent) => void,
): Promise<number> {
  if (!inTauri) return simulateJob(kind, onEvent);
  const channel = new Channel<JobEvent>();
  channel.onmessage = onEvent;
  return invoke<number>("job_start", { kind, onEvent: channel });
}

export async function jobCancel(id: number): Promise<boolean> {
  if (!inTauri) return cancelSimulated(id);
  return invoke<boolean>("job_cancel", { id });
}

// --- browser fallback -------------------------------------------------------

const simTimers = new Map<number, ReturnType<typeof setInterval>>();

function simulateJob(kind: JobKindWire, onEvent: (event: JobEvent) => void): Promise<number> {
  const id = Math.floor(Math.random() * 1_000_000) + 1;
  const total = 50;
  let step = 0;
  onEvent({ type: "started", job_id: id, total_steps: total });
  const timer = setInterval(() => {
    if (!simTimers.has(id)) return;
    step += 1;
    onEvent({
      type: "progress",
      job_id: id,
      step,
      percent: Math.round((step / total) * 100),
      message: `processing unit ${step}/${total}`,
    });
    if (step >= total) {
      clearInterval(timer);
      simTimers.delete(id);
      onEvent({ type: "completed", job_id: id, message: `demo job finished (${total} units)` });
    }
  }, 100);
  simTimers.set(id, timer);
  return Promise.resolve(id);
}

function cancelSimulated(id: number): Promise<boolean> {
  const timer = simTimers.get(id);
  if (!timer) return Promise.resolve(false);
  clearInterval(timer);
  simTimers.delete(id);
  return Promise.resolve(true);
}

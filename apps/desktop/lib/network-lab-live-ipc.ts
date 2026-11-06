/**
 * Local IPC client for the Bettercap-mode live Network Lab slice.
 *
 * The Lab subscribes to a RUNNING Packet Studio capture session (one
 * capture, many modules) and never starts its own. This module is
 * deliberately separate from lib/ipc.ts so the canonical client block can be
 * merged there later without a cross-feature edit; the wire type mirrors
 * features/network/ipc/network_lab_live.rs LabLiveStatusWire exactly
 * (snake_case serialized names, never renamed). Event rows reuse the
 * canonical LabEventWire/LabEventKindWire types from lib/ipc.ts, which
 * mirror crates/packet/src/lab_events.rs.
 */
import { invoke } from "@tauri-apps/api/core";
import type { LabEventWire } from "./ipc.ts";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** snake_case Debug form of the manager Phase, lowercased by the backend. */
export type LabLivePhaseWire = "running" | "stopping" | "completed" | "failed";

export interface LabLiveStatusWire {
  /** True while the subscribed capture session is running or stopping. */
  active: boolean;
  phase: LabLivePhaseWire;
  interface: string;
  /** Packets the timeline was actually derived from (0 while still running). */
  sampled_packets: number;
  /** Live capture progress counter (packets captured so far). */
  captured_packets: number;
  /** Passive event timeline, oldest first, capped at 512 events. */
  events: LabEventWire[];
  new_hosts: number;
  new_services: number;
  conflicts: number;
  gateway_changes: number;
  truncated: boolean;
  arp_observations: number;
  arp_findings: number;
  gratuitous_bursts: number;
}

/**
 * Read-only live lab status for one subscribed capture session. The backend
 * revalidates case-revision ownership on every poll (same gate as the
 * capture commands) and never mutates the session; the frontend polls this
 * every ~2s while live mode is enabled.
 */
export async function networkLabLiveStatusV1(
  sessionId: number,
  routerIp: string | null,
): Promise<LabLiveStatusWire> {
  if (!inTauri) throw new Error("Live lab subscription requires the desktop runtime");
  return invoke<LabLiveStatusWire>("network_lab_live_status_v1", { sessionId, routerIp });
}

/**
 * Session id gate for the live source input: the id is assigned by the
 * backend capture manager (small monotonic u64), so only plain digits in a
 * safe-integer range are ever sent. Empty/garbage stays local to the input.
 */
export function isValidLiveSessionId(text: string): boolean {
  if (!/^[0-9]{1,15}$/.test(text)) return false;
  const value = Number(text);
  return Number.isSafeInteger(value) && value > 0;
}

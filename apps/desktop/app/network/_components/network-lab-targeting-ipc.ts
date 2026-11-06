/**
 * Local IPC client for the lab-scope-targeted ARP sweep slice (Ettercap-style
 * host targeting).
 *
 * Deliberately separate from lib/ipc.ts (same pattern as the live-lab
 * client): the sweep is the Network Lab arc's only ACTIVE command, and its
 * wire types mirror features/network/ipc/network_lab_targeting.rs exactly —
 * snake_case serialized names, never renamed. Targets are resolved
 * EXCLUSIVELY on the backend from the saved memory-only lab scope
 * (Target 1 ∪ Target 2); the frontend never sends target addresses, so it
 * cannot widen the scope.
 */
import { invoke, Channel } from "@tauri-apps/api/core";
import { isDesktop, type NetworkLabScopeWire } from "../../../lib/ipc.ts";

/** Progress event: honest totals + elapsed time only (see the backend wire). */
export interface LabSweepProgressWire {
  phase: "running" | "done";
  total_targets: number;
  elapsed_ms: number;
  /** Hosts that answered; populated only on "done". */
  answered: number | null;
}

/** One host that answered the sweep (same shape as the netscan ARP rows). */
export interface LabArpNeighborWire {
  host: string;
  mac: string;
  elapsed_ms: number;
}

/**
 * Start the authorized lab ARP sweep. The backend re-validates everything:
 * explicit authorization checkbox, a saved backend-selected case matching
 * `caseId`, a set lab scope, the ≤32-target cap, exclusivity against every
 * other active network operation, and a native Yes/No confirmation dialog
 * naming the saved lab scope before the first frame is sent.
 */
export async function networkLabArpSweepV1(
  interfaceName: string,
  authorized: boolean,
  caseId: string,
  onProgress?: (progress: LabSweepProgressWire) => void,
): Promise<LabArpNeighborWire[]> {
  if (!isDesktop()) throw new Error("Lab ARP sweeps require the desktop runtime");
  const channel = new Channel<LabSweepProgressWire>();
  if (onProgress) channel.onmessage = onProgress;
  return invoke<LabArpNeighborWire[]>("network_lab_arp_sweep_v1", {
    interfaceName,
    authorized,
    caseId,
    onProgress: channel,
  });
}

/** Stop the sweep owned by the currently selected case revision. */
export async function networkLabArpSweepStopV1(): Promise<boolean> {
  if (!isDesktop()) throw new Error("Lab ARP sweep cancellation requires the desktop runtime");
  return invoke<boolean>("network_lab_arp_sweep_stop_v1", {});
}

/** True while a sweep owned by the currently selected case revision runs. */
export async function networkLabArpSweepStatusV1(): Promise<boolean> {
  if (!isDesktop()) return false;
  return invoke<boolean>("network_lab_arp_sweep_status_v1", {});
}

/**
 * Pure UI gate mirroring the backend's scope requirements, so the button is
 * disabled with an honest reason instead of letting the backend error tell
 * the operator later. Returns null when a sweep may be requested; desktop
 * and interface selection are checked separately in the view.
 */
export function labSweepBlockReason(scope: NetworkLabScopeWire | null): string | null {
  if (!scope || !scope.authorized) {
    return "No lab scope is set — set Target 1 / Target 2 first";
  }
  if (scope.targets_t1.length === 0 && scope.targets_t2.length === 0) {
    return "The lab scope is empty — add Target 1 / Target 2 entries first";
  }
  return null;
}

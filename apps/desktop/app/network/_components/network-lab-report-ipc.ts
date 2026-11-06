/**
 * Local IPC client for the lab session report slice (Bettercap
 * session-report parity).
 *
 * Deliberately separate from lib/ipc.ts (same pattern as the sweep client):
 * the wire types mirror features/network/ipc/network_lab_report.rs exactly —
 * snake_case serialized names, never renamed. The command is read-only over
 * the opened capture; the backend reduces ARP findings, the event timeline,
 * the host inventory and the DNS findings exactly like the individual lab
 * panes, renders ONE bounded markdown artifact (<= 32 KiB, truncation always
 * marked) and persists it as ONE case finding in the backend-selected saved
 * case. The frontend never sees the markdown — only the receipt.
 */
import { invoke } from "@tauri-apps/api/core";
import { isDesktop } from "../../../lib/ipc.ts";

/** Receipt for network_lab_report_export_v1: size, destination, honesty. */
export interface LabReportReceiptWire {
  byte_len: number;
  case_id: string;
  truncated: boolean;
}

/**
 * Export the lab session report for the opened capture into the selected
 * saved case. Read-only over the capture; the backend validates the optional
 * router IP, refuses the scratchpad case and persists the finding through the
 * standard evidence gate. Transmits nothing.
 */
export async function networkLabReportExportV1(
  routerIp: string | null,
  includeDns: boolean,
): Promise<LabReportReceiptWire> {
  if (!isDesktop()) {
    throw new Error("Lab session report export requires the desktop runtime");
  }
  return invoke<LabReportReceiptWire>("network_lab_report_export_v1", {
    routerIp,
    includeDns,
  });
}

/**
 * Pure receipt chip text: honest about the artifact size, the destination
 * case and truncation. Mirrors the backend's contract — a truncated report
 * is always labeled as such, never silently shrunk.
 */
export function reportReceiptText(receipt: LabReportReceiptWire): string {
  const size =
    receipt.byte_len >= 1024
      ? `${(receipt.byte_len / 1024).toFixed(1)} KiB`
      : `${receipt.byte_len} B`;
  return `report saved · ${size} · case ${receipt.case_id}${receipt.truncated ? " · truncated" : ""}`;
}

/**
 * Pure gate mirroring the backend's requirements so the button is disabled
 * with an honest reason instead of a backend error: a capture must be open
 * (the report reduces the opened capture) and the desktop runtime must host
 * the command. Case selection is backend-resolved, so it is not gated here.
 */
export function reportExportBlockReason(
  desktop: boolean,
  hasCapture: boolean,
): string | null {
  if (!desktop) return "requires the desktop runtime";
  if (!hasCapture) return "open a capture first";
  return null;
}

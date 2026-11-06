/**
 * Packet Studio pending IPC client + pure helpers for "export view -> case".
 *
 * The canonical client and wire types will be folded into lib/ipc.ts by the
 * coordinator (same pattern as scan-insights-ipc.ts); until then this module
 * follows the network-lab-model.ts convention: a typed wrapper calling
 * `invoke` directly (never raw paths, never process spawning — exports become
 * case artifacts only through the backend command), wire field names exactly
 * mirroring the Rust serde structs in
 * src-tauri/src/features/network/ipc/pcap_export.rs and
 * src-tauri/src/features/network/ipc/pcap_wire.rs, and pure helpers at the
 * bottom.
 */
import { invoke } from "@tauri-apps/api/core";
import type { PcapOpenWire } from "@lib/ipc";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// --- wire types (mirror pcap_export.rs / pcap_wire.rs serde structs) ---------

/** Receipt for pcap_export_view_v1: identity and size only, never bytes. */
export interface PcapExportReceiptWire {
  artifact_id: string;
  sha256: string;
  byte_len: number;
  packet_count: number;
  file_name: string;
}

/** Additive reassembly summary on the pcap open wire (serde default: null). */
export interface ReassemblySummaryWire {
  datagram_count: number;
  flagged_overlap_count: number;
  first_datagram_ids: string[];
}

/** Mirrors the backend selection cap (MAX_CAPTURE_PACKETS in the packet crate). */
export const PCAP_EXPORT_MAX_PACKETS = 200_000;

// --- pending canonical client ------------------------------------------------

/**
 * Export the given packet indices of the currently opened capture as an
 * immutable classic-PCAP case artifact. The backend re-validates everything:
 * indices against the opened capture cache, the saved selected case, and the
 * Ethernet/frame-size/total-size bounds of the evidence importer.
 */
export async function pcapExportViewV1(indices: number[]): Promise<PcapExportReceiptWire> {
  if (!inTauri) throw new Error("case artifact export requires the desktop runtime");
  if (indices.length === 0 || indices.length > PCAP_EXPORT_MAX_PACKETS) {
    throw new Error("export selection must contain 1..200000 packet indices");
  }
  return invoke<PcapExportReceiptWire>("pcap_export_view_v1", { indices });
}

// --- pure helpers ------------------------------------------------------------

/** Short artifact id for the result chip ("case:capture-a1b2c3d4…" tail). */
export function shortArtifactId(artifactId: string): string {
  const tail = artifactId.includes(":") ? artifactId.slice(artifactId.lastIndexOf(":") + 1) : artifactId;
  return tail.slice(0, 12);
}

/**
 * Read the additive `reassembly` field from the open-capture wire. The Rust
 * wire struct carries it since the pcap-export slice (serde default: null);
 * the canonical lib/ipc.ts interface gains it when the coordinator folds
 * these types in, so it is read defensively and both shapes typecheck.
 */
export function reassemblyOf(capture: PcapOpenWire): ReassemblySummaryWire | null {
  const extended = capture as PcapOpenWire & { reassembly?: ReassemblySummaryWire | null };
  return extended.reassembly ?? null;
}

/** One-line banner text for the reassembly summary; empty ids are omitted. */
export function reassemblyBannerText(summary: ReassemblySummaryWire): string {
  const parts = [
    `fragment reassembly: ${summary.datagram_count} datagram(s) reconstructed`,
    summary.flagged_overlap_count > 0
      ? `${summary.flagged_overlap_count} overlap conflict(s) flagged`
      : null,
    summary.first_datagram_ids.length > 0
      ? `first: ${summary.first_datagram_ids.join(", ")}`
      : null,
    "derived datagrams stay out of the evidence packet list",
  ].filter((part): part is string => part !== null);
  return parts.join(" · ");
}

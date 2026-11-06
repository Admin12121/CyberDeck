/**
 * Packet Studio "export view -> case" wire re-exports + pure helpers.
 *
 * The canonical client and wire types live in lib/ipc.ts and mirror the Rust
 * serde structs in src-tauri/src/features/network/ipc/pcap_export.rs and
 * pcap_wire.rs exactly. Pure helpers at the bottom are what node --test
 * exercises directly; the relative .ts import keeps node's TS-strip loader
 * able to resolve them without a bundler.
 */
import type { PcapOpenWire, ReassemblySummaryWire } from "../../../lib/ipc.ts";

export {
  pcapExportViewNgV1,
  pcapExportViewV1,
  type PcapExportReceiptWire,
  type ReassemblySummaryWire,
} from "../../../lib/ipc.ts";

// --- pure helpers ------------------------------------------------------------

/** Short artifact id for the result chip ("case:capture-a1b2c3d4…" tail). */
export function shortArtifactId(artifactId: string): string {
  const tail = artifactId.includes(":") ? artifactId.slice(artifactId.lastIndexOf(":") + 1) : artifactId;
  return tail.slice(0, 12);
}

/**
 * Read the additive `reassembly` field from the open-capture wire. Present
 * on the canonical interface since the pcap-export slice; read defensively
 * so older cached wires without the field stay usable.
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

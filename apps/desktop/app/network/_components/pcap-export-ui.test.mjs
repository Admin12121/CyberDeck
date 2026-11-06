// Source-contract tests for the Packet Studio "export view -> case" slice and
// the fragment-reassembly surfacing. PacketStudioView.tsx is a React client
// component, so under plain `node --test` it is asserted as SOURCE TEXT: the
// toolbar control, the filtered-indices handoff, the result chip and the
// dismissible reassembly banner must exist verbatim. The pending IPC client,
// the Rust command and the pure PCAP writer are cross-checked for the wire
// names and bounded-caps guarantees the UI depends on.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const studioSource = readFileSync(join(here, "PacketStudioView.tsx"), "utf8");
const pendingClientSource = readFileSync(join(here, "pcap-export-ipc.ts"), "utf8");
const exportCommandSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/ipc/pcap_export.rs"),
  "utf8",
);
const pcapWireSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/ipc/pcap_wire.rs"),
  "utf8",
);
const captureServiceSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/application/capture_service.rs"),
  "utf8",
);
const pcapWriteSource = readFileSync(
  join(here, "../../../../../crates/packet/src/pcap_write.rs"),
  "utf8",
);

// ------------------------------------------------- export view -> case -------

test("offline toolbar carries the Export view -> case control, gated and busy-labeled", () => {
  assert.match(studioSource, /Export view → case/);
  // Disabled without an opened capture, while a request is in flight, and
  // without a saved selected case (artifact destination).
  assert.match(
    studioSource,
    /disabled=\{!capture \|\| exporting \|\| !savedCaseReady\}/,
  );
  assert.match(studioSource, /exporting \? "exporting…" : "Export view → case"/);
  // The honest reason is visible via the tooltip for each disabled state.
  assert.match(studioSource, /Select a saved case to export the view into/);
  assert.match(studioSource, /Open a capture to export its filtered view/);
});

test("export sends the currently FILTERED packet indices and renders a result chip", () => {
  const handler = /const exportView = async \(\) => \{([\s\S]*?)\n  \};/.exec(studioSource);
  assert.ok(handler, "exportView handler missing from PacketStudioView.tsx");
  assert.match(handler[1], /if \(!capture\) return;/);
  assert.match(handler[1], /pcapExportViewV1\(filtered\.map\(\(packet\) => packet\.index\)\)/);
  // The chip reports the exported count plus a short artifact id only —
  // never a stored path, file bytes or a case secret.
  const chip = /\{exportResult \? \(\s*<Chip tone="ok">([\s\S]*?)<\/Chip>\s*\) : null\}/.exec(studioSource);
  assert.ok(chip, "export result chip missing");
  assert.match(chip[1], /exportResult\.packet_count/);
  assert.match(chip[1], /shortArtifactId\(exportResult\.artifact_id\)/);
  // Failures surface through the existing error banner, not a silent drop.
  assert.match(handler[1], /setOpenError\(/);
});

test("pending client invokes the backend command with guarded indices", () => {
  const client = /export async function pcapExportViewV1\([\s\S]*?\n\}/.exec(pendingClientSource);
  assert.ok(client, "pcapExportViewV1 client missing");
  assert.match(client[0], /if \(!inTauri\) throw new Error/);
  assert.match(client[0], /indices\.length === 0 \|\| indices\.length > PCAP_EXPORT_MAX_PACKETS/);
  assert.match(client[0], /invoke<PcapExportReceiptWire>\("pcap_export_view_v1", \{ indices \}\)/);
  // The bound mirrors the packet crate's capture record cap, not an invented one.
  assert.match(pendingClientSource, /export const PCAP_EXPORT_MAX_PACKETS = 200_000;/);
});

test("receipt wire names mirror the Rust serde struct exactly", () => {
  const rust = /pub struct ExportReceiptWire \{([\s\S]*?)\n\}/.exec(exportCommandSource);
  assert.ok(rust, "ExportReceiptWire missing from pcap_export.rs");
  const fields = [...rust[1].matchAll(/pub (\w+):/g)].map((m) => m[1]);
  assert.deepEqual(fields, ["artifact_id", "sha256", "byte_len", "packet_count", "file_name"]);
  for (const field of fields) {
    assert.match(pendingClientSource, new RegExp(`\\b${field}:`), `wire field ${field} missing`);
  }
});

test("backend command keeps the case, capture and format gates", () => {
  // Saved-case gate: scratchpad and empty ids never become artifact sinks.
  assert.match(exportCommandSource, /fn selected_saved_case/);
  assert.match(exportCommandSource, /id == "scratchpad"/);
  assert.match(exportCommandSource, /pcap export requires a saved selected case/);
  // Selection is deduplicated, ordered and reader-capped before any bytes.
  assert.match(exportCommandSource, /indices\.sort_unstable\(\);/);
  assert.match(exportCommandSource, /indices\.dedup\(\);/);
  assert.match(exportCommandSource, /MAX_CAPTURE_PACKETS/);
  // Only classic Ethernet captures fit the evidence importer this arc.
  assert.match(exportCommandSource, /ETHERNET_LINKTYPE/);
  // Persistence reuses the capture_save_v1 path: store lock first, then the
  // publication gate, then the original-network-capture importer.
  const gate = /let store = evidence\s*\.store\s*\.lock\(\)[\s\S]*?session\.with_current_publication\(&scope, \|\| \{[\s\S]*?import_original_network_capture/.exec(exportCommandSource);
  assert.ok(gate, "store lock must precede the publication-gated artifact import");
  // Receipt never leaks the stored path.
  assert.ok(!/stored_path/.test(exportCommandSource), "receipt must not expose stored_path");
});

test("packet crate writer enforces reader-mirroring caps and round-trips", () => {
  assert.match(
    pcapWriteSource,
    /pub fn write_pcap\(linktype: u32, records: &\[\(u32, u32, &\[u8\]\)\]\) -> Result<Vec<u8>, PcapWriteError>/,
  );
  assert.match(pcapWriteSource, /PCAP_MAGIC_LE_USEC\.to_le_bytes\(\)/);
  assert.match(pcapWriteSource, /records\.len\(\) > MAX_CAPTURE_PACKETS/);
  assert.match(pcapWriteSource, /frame\.len\(\) > MAX_PACKET_BYTES/);
  // Round-trip contract: writer output re-reads through the same parser.
  assert.match(pcapWriteSource, /fn write_then_parse_round_trips_linktype_timestamps_and_bytes/);
  assert.match(pcapWriteSource, /parse_pcap\(&bytes\)/);
  // Cap-refusal tests exist for both caps.
  assert.match(pcapWriteSource, /selections_above_the_reader_record_cap_are_refused/);
  assert.match(pcapWriteSource, /frames_above_the_reader_record_cap_are_refused/);
});

// ------------------------------------------------ reassembly surfacing -------

test("opened captures surface a dismissible fragment-reassembly banner", () => {
  const banner = /aria-label="Fragment reassembly summary"[\s\S]*?<\/div>/.exec(studioSource);
  assert.ok(banner, "reassembly banner missing from PacketStudioView.tsx");
  // Banner text is a single bounded helper call over the wire summary.
  assert.match(studioSource, /\{reassemblyBannerText\(reassembly\)\}/);
  // Dismissal mirrors the malformed-tail banner style and is per-capture.
  assert.match(studioSource, /aria-label="Dismiss reassembly summary"/);
  assert.match(studioSource, /onClick=\{\(\) => setShowReassembly\(false\)\}/);
  assert.match(studioSource, /setShowReassembly\(true\)/);
  // The summary comes from the open wire only; it is read defensively so the
  // canonical wire type and older captures without the field both work.
  assert.match(studioSource, /reassemblyOf\(capture\)/);
});

test("banner text summarizes count, overlap conflicts and first datagram ids", () => {
  const helper = /export function reassemblyBannerText\([\s\S]*?\n\}/.exec(pendingClientSource);
  assert.ok(helper, "reassemblyBannerText helper missing");
  assert.match(helper[0], /summary\.datagram_count/);
  assert.match(helper[0], /summary\.flagged_overlap_count/);
  assert.match(helper[0], /summary\.first_datagram_ids\.join/);
  const rust = /pub struct ReassemblySummaryWire \{([\s\S]*?)\n\}/.exec(pcapWireSource);
  assert.ok(rust, "ReassemblySummaryWire missing from pcap_wire.rs");
  const fields = [...rust[1].matchAll(/pub (\w+):/g)].map((m) => m[1]);
  assert.deepEqual(fields, ["datagram_count", "flagged_overlap_count", "first_datagram_ids"]);
});

test("reassembly stays additive on the open wire and out of the evidence path", () => {
  // serde default keeps old callers compiling; Option keeps no-evidence
  // captures silent.
  assert.match(pcapWireSource, /#\[serde\(default\)\]\s*\n\s*pub reassembly: Option<ReassemblySummaryWire>/);
  // Identifier list is bounded (<= 8) on the backend, not just in the UI.
  assert.match(pcapWireSource, /\.take\(8\)/);
  // The report rides the import result; the packet cache keeps original
  // evidence only and never promotes derived datagrams into the packet list.
  assert.match(captureServiceSource, /pub\(super\) reassembly: cyberdeck_packet::fragments::ReassemblyReport/);
  assert.match(pcapWriteSource, /never substitutes|Frame bytes are written verbatim/s);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = import.meta.dirname;
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const ipcSource = (file) =>
  fs.readFileSync(path.join(root, "../../../src-tauri/src/features/network/ipc", file), "utf8");

test("capture-wide statistics ship exactly two commands per data path", () => {
  const pcap = ipcSource("pcap.rs");
  for (const command of [
    "network_capture_io_graph_v1",
    "network_capture_endpoints_v1",
    "pcap_case_io_graph_v1",
    "pcap_case_endpoints_v1",
  ]) {
    assert.match(pcap, new RegExp(`#\\[tauri::command\\]\\s*pub fn ${command}\\(`));
  }
  const client = read("packet-stats-ipc.ts");
  for (const name of [
    "network_capture_io_graph_v1",
    "network_capture_endpoints_v1",
    "pcap_case_io_graph_v1",
    "pcap_case_endpoints_v1",
  ]) {
    assert.match(client, new RegExp(`invoke<\\w+>\\("${name}"`));
  }
});

test("case-scoped statistics follow the verified-reader pattern, not a cached authority", () => {
  const saved = ipcSource("saved_capture.rs");
  // Strictly additive case paths reuse with_verified_artifact + strict parse.
  assert.match(saved, /pub\(super\) fn io_graph\(/);
  assert.match(saved, /pub\(super\) fn endpoints\(/);
  const ioBlock = saved.slice(saved.indexOf("pub(super) fn io_graph("));
  assert.match(ioBlock, /with_verified_artifact\(/);
  assert.match(ioBlock, /EvidenceConsumer::PacketAnalysis/);
  assert.match(ioBlock, /saved original capture is malformed/);
});

test("statistics wire types are snake_case and structurally bounded", () => {
  const wire = ipcSource("pcap_wire.rs");
  assert.match(wire, /const IO_GRAPH_MAX_BUCKETS: usize = 120/);
  assert.match(wire, /const ENDPOINTS_MAX_ROWS: usize = 64/);
  assert.match(wire, /pub struct IoBucketWire/);
  for (const field of ["pub from_ms", "pub tcp_packets", "pub udp_packets", "pub other_packets"]) {
    assert.match(wire, new RegExp(field));
  }
  assert.match(wire, /pub buckets: Vec<IoBucketWire>/);
  assert.match(wire, /pub rows: Vec<EndpointRowWire>/);
  assert.match(wire, /rows\.truncate\(ENDPOINTS_MAX_ROWS\)/);
  // Top talkers are the byte-heaviest rows, ties broken by address.
  assert.match(wire, /rows\.sort_by\(\|a, b\| b\.bytes\.cmp\(&a\.bytes\)\.then_with\(\|\| a\.address\.cmp\(&b\.address\)\)/);
  // Talker convention is stated in the code, not guessed.
  assert.match(wire, /pub bytes_out: u64/);
  assert.match(wire, /pub bytes_in: u64/);
});

test("graph and endpoint math are pure functions over the capture cache", () => {
  const wire = ipcSource("pcap_wire.rs");
  assert.match(wire, /pub\(super\) fn io_graph_of\(packets: &\[PacketMeta\], nanosecond: bool\)/);
  assert.match(wire, /pub\(super\) fn endpoints_of\(packets: &\[PacketMeta\]\)/);
  // Bucket math honours the source file's timestamp scale (ns vs µs).
  assert.match(wire, /if nanosecond \{ 1 \} else \{ 1_000 \}/);
  // UDP classification rides the dissector's own layer, not port guesses.
  assert.match(wire, /"User Datagram Protocol"/);
});

test("Rust tests pin bucket math, byte sums, family aggregation and bounds", () => {
  const wire = ipcSource("pcap_wire.rs");
  for (const name of [
    "io_graph_empty_capture_yields_no_buckets_and_zero_totals",
    "io_graph_single_packet_lands_in_one_exact_bucket",
    "io_graph_span_wider_than_the_cap_is_capped_at_120_buckets",
    "io_graph_short_span_uses_the_one_ms_bucket_floor",
    "io_graph_timestamp_scale_follows_the_source_file",
    "io_graph_byte_and_packet_sums_are_exact_per_bucket",
    "endpoints_aggregate_real_dissected_frames_by_family_with_talker_directions",
    "endpoints_cap_at_64_rows_sorted_by_bytes_desc_and_disclose_truncation",
    "endpoints_empty_capture_is_an_empty_bounded_table",
  ]) {
    assert.match(wire, new RegExp(`fn ${name}\\(`));
  }
  const saved = ipcSource("saved_capture.rs");
  assert.match(saved, /fn case_statistics_reopen_the_verified_capture_and_deny_case_switch\(/);
});

test("PacketStudioView adds capture-wide sections while existing stats stay untouched", () => {
  const studio = read("PacketStudioView.tsx");
  // Existing client-side (filtered view) statistics remain in place.
  assert.match(studio, /<IoGraphView buckets=\{ioBuckets\} \/>/);
  assert.match(studio, /ioSeriesOf\(filtered\)/);
  assert.match(studio, /endpointsOf\(filtered\)/);
  assert.match(studio, /protocolStats\(filtered\)/);
  assert.match(studio, /no endpoints in the current view/);
  // The two new backend-depth affordances sit inside the existing tabs.
  assert.match(studio, /tab === "io" \? \(\s*<>[\s\S]*?<IoGraphView buckets=\{ioBuckets\} \/>[\s\S]*?<CaptureIoGraph wire=\{captureIo\} hasCapture=\{Boolean\(capture\)\} \/>/);
  assert.match(studio, /<CaptureEndpointsTable wire=\{captureEndpoints\} hasCapture=\{Boolean\(capture\)\} \/>/);
  assert.match(studio, /IO graph — whole capture/);
  assert.match(studio, /Endpoints — whole capture/);
  assert.match(studio, /Tx bytes/);
  assert.match(studio, /Rx bytes/);
  // One-line descriptions + InfoTip, no chart library.
  assert.match(studio, /InfoTip text="Whole-capture IO graph over the full native cache/);
  assert.match(studio, /InfoTip text="Top talkers over the full capture cache/);
  assert.doesNotMatch(studio, /recharts|chart\.js|Chart.js|<canvas|d3-/i);
});

test("capture-wide statistics refetch with the opened capture and case scope", () => {
  const studio = read("PacketStudioView.tsx");
  assert.match(studio, /savedArtifactId \? pcapCaseIoGraphV1\(savedArtifactId\) : networkCaptureIoGraphV1\(\)/);
  assert.match(studio, /savedArtifactId \? pcapCaseEndpointsV1\(savedArtifactId\) : networkCaptureEndpointsV1\(\)/);
  assert.match(studio, /\}, \[capture, savedArtifactId, wb\.caseId\]\);/);
  // Results are dropped when a different case session wins the race.
  assert.match(studio, /currentCase\.current === caseId\) setCaptureIo\(wire\)/);
  assert.match(studio, /currentCase\.current === caseId\) setCaptureEndpoints\(wire\)/);
});

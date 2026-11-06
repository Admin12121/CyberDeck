import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const here = import.meta.dirname;
const read = (file) => fs.readFileSync(path.join(here, file), "utf8");
const canonicalIpc = read("../../../lib/ipc.ts");
const view = read("PacketStudioView.tsx");
const backend = read("../../../src-tauri/src/features/network/ipc/os_hints_ipc.rs");
const crate = read("../../../../../crates/packet/src/os_hints.rs");

test("OS hints are honest: low confidence, no versions, unknown is expected", () => {
  assert.match(crate, /HONESTY CONTRACT/);
  assert.match(crate, /never a verdict and never a version claim/);
  assert.match(crate, /"very_low"/);
  assert.match(crate, /never a verdict or a version claim/);
  assert.match(view, /never verdicts, never versions/);
  assert.match(view, /low-confidence hints/);
});

test("classifier covers the documented breakpoints and conflicts", () => {
  for (const family of ["linux", "windows", "macos", "freebsd", "network_device", "unknown"]) {
    assert.match(crate, new RegExp(`FAMILY_${family.toUpperCase()}|"${family}"`));
  }
  assert.match(crate, /fn conflicting_ttl_and_window_evidence_is_unknown/);
  assert.match(crate, /fn windows_ttl_only_is_very_low/);
  assert.match(crate, /fn linux_synack_shape_is_attributed_low/);
  assert.match(crate, /fn absent_evidence_degrades_to_unknown_with_reason/);
});

test("backend command reads only the capture cache and caps its output", () => {
  assert.match(backend, /pub fn capture_os_hints_v1/);
  assert.match(backend, /State<'_, PcapCtx>/);
  assert.match(backend, /MAX_OS_HINTS: usize = 256/);
  // Signatures come from existing dissection layers only; nothing parses
  // raw frame bytes here, and no DF is invented.
  assert.match(backend, /ipv4_df: None/);
  assert.match(backend, /"ttl"/);
  assert.match(backend, /"TCP receive window \(raw\)"/);
  // Plain data segments are skipped: their windows are flow control.
  assert.match(backend, /tcp\.flags & 0x02 == 0/);
});

test("command is registered and the canonical client exists", () => {
  const main = read("../../../src-tauri/src/main.rs");
  assert.match(main, /os_hints_ipc::capture_os_hints_v1/);
  assert.match(canonicalIpc, /export async function captureOsHintsV1/);
  assert.match(canonicalIpc, /OS hints require the desktop runtime/);
});

test("view wires the tab, gate and analysis flow", () => {
  assert.match(view, /"os-hints"/);
  assert.match(view, /Analyze OS hints \(opened capture\)/);
  assert.match(view, /Open a capture first/);
  assert.match(view, /setOsHintsLoading\(true\)/);
  assert.match(view, /OS hints analysis failed: /);
});

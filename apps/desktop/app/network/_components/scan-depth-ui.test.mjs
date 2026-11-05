// Source-contract tests for the scan-depth slice (raw FIN/NULL/Xmas/ACK/Window
// scan types + service probes). ScanView.tsx is a React client component, so
// under plain `node --test` it is asserted as SOURCE TEXT: the controls, the
// authorization gates, and the honesty labels must exist verbatim. The Rust
// backend files are cross-checked for the wire labels the UI renders, and the
// declared scan-type registry is extracted and evaluated for real assertions.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const scanViewSource = readFileSync(join(here, "ScanView.tsx"), "utf8");
const scanDepthSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/ipc/scan_depth.rs"),
  "utf8",
);
const activeScanTypesSource = readFileSync(
  join(here, "../../../../../crates/packet/src/active_scan_types.rs"),
  "utf8",
);

test("raw scan-type selector declares exactly the five documented flag scans", () => {
  const match = /const STEALTH_SCAN_TYPES[^=]*= (\[[^\]]*\]);/.exec(scanViewSource);
  assert.ok(match, "STEALTH_SCAN_TYPES registry missing from ScanView.tsx");
  // Evaluate the extracted literal: it contains only string/object literals,
  // so a Function evaluation of our own source is deterministic and safe here.
  const registry = new Function("return " + match[1])();
  assert.deepEqual(
    registry.map((entry) => entry.value),
    ["fin", "null", "xmas", "ack", "window"],
  );
  for (const entry of registry) {
    assert.equal(typeof entry.label, "string");
    assert.ok(entry.label.length > 0);
  }
});

test("stealth scan controls exist with progress and stop mirroring the SYN flow", () => {
  assert.match(scanViewSource, /Raw depth/);
  assert.match(scanViewSource, /Stop raw/);
  assert.match(scanViewSource, /ariaLabel="Raw scan type"/);
  // Progress line bound to the stealth channel state.
  assert.match(scanViewSource, /stealthProgress\.tried.*stealthProgress\.total/s);
  // Notes-pane findings panel with the documented silence semantics.
  assert.match(scanViewSource, /open\|filtered/);
  assert.match(scanViewSource, /stealthFindings\.map/);
});

test("raw scan types carry the explicit Linux platform note", () => {
  assert.match(scanViewSource, /Raw scan types require Linux/);
  // Non-Linux fallback also names the restriction.
  assert.match(
    scanViewSource,
    /Raw FIN\/NULL\/Xmas\/ACK\/Window scan types require Linux/,
  );
  // Linux-only raw ops are also listed in the Windows note.
  assert.match(scanViewSource, /raw SYN and raw FIN\/NULL\/Xmas\/ACK\/Window scan types are Linux-only/);
});

test("stealth and service-probe flows are gated behind authorization and a saved case", () => {
  const stealthBody = /const runStealth = async \(\) => \{([\s\S]*?)\n  \};/.exec(scanViewSource);
  assert.ok(stealthBody, "runStealth handler missing");
  assert.match(stealthBody[1], /!authorized/);
  assert.match(stealthBody[1], /revision === null/);
  assert.match(stealthBody[1], /netscanStealthStartV1\(/);
  assert.match(stealthBody[1], /wb\.caseId/);
  const probeBody = /const probeService = async \(host: string, port: number\) => \{([\s\S]*?)\n  \};/.exec(scanViewSource);
  assert.ok(probeBody, "probeService handler missing");
  assert.match(probeBody[1], /!authorized/);
  assert.match(probeBody[1], /revision === null/);
  assert.match(probeBody[1], /netscanServiceProbeV1\(/);
  // Both clients pass the saved-case id so the backend can reject stale UI state.
  assert.match(scanViewSource, /caseId/);
});

test("service-probe panel renders per-open-row buttons and basis badges", () => {
  assert.match(scanViewSource, /probe service/);
  assert.match(scanViewSource, /probeCell\(/);
  // Basis badge text: service claim + basis label, with a distinct no-claim state.
  assert.match(scanViewSource, /result\.basis === "none" \? "no claim" : result\.service_claim \+ " · " \+ result\.basis/);
  // Confidence tones distinguish high/medium/low evidence.
  assert.match(scanViewSource, /result\.confidence === "high" \? "text-ok"/);
  assert.match(scanViewSource, /result\.confidence === "medium" \? "text-orange"/);
  // Claims stay labeled as unverified remote assertions.
  assert.match(scanViewSource, /Unverified software identity claimed by the remote server/);
  assert.match(scanViewSource, /claims \{result\.remote_software_claim\}/);
  // The probe column exists in the observations table header.
  assert.match(scanViewSource, /<th className="w-32">Probe<\/th>/);
  // Excerpt + probe used surface in the badge tooltip for evidence honesty.
  assert.match(scanViewSource, /raw_excerpt_trimmed/);
  assert.match(scanViewSource, /result\.probe_used/);
});

test("frontend clients target the registered scan-depth command names", () => {
  for (const command of [
    "netscan_stealth_start_v1",
    "netscan_stealth_stop_v1",
    "netscan_service_probe_v1",
  ]) {
    assert.match(scanViewSource, new RegExp("[\"']" + command + "[\"']"));
    assert.match(
      scanDepthSource,
      new RegExp("pub (async )?fn " + command),
      command + " not defined in scan_depth.rs",
    );
  }
  // Status command exists backend-side (polled less often, optional client).
  assert.match(scanDepthSource, /pub fn netscan_stealth_status_v1/);
});

test("backend wire states match the documented nmap reply semantics", () => {
  // The five per-port states the UI can render, exactly as the Rust classifier
  // emits them (PortState::as_str).
  for (const state of ["open", "closed", "unfiltered", "filtered", "open_filtered"]) {
    assert.match(activeScanTypesSource, new RegExp('"' + state + '"'));
  }
  // Honest per-outcome reasons emitted with each finding.
  for (const reason of [
    "tcp_rst_matching_tuple",
    "icmp_ipv4_unreachable",
    "no_response_default_openfiltered",
    "no_response_default_filtered",
  ]) {
    assert.match(activeScanTypesSource, new RegExp('"' + reason + '"'));
  }
  // ScanKind wire labels align with the frontend registry values.
  for (const label of ["fin", "null", "xmas", "ack", "window"]) {
    assert.match(activeScanTypesSource, new RegExp('"' + label + '"'));
  }
});

test("backend service-probe honesty contract: basis, confidence and bounded excerpt", () => {
  for (const basis of ["banner", "probe_response", "none"]) {
    assert.match(scanDepthSource, new RegExp('"' + basis + '"'));
  }
  for (const confidence of ["high", "medium", "low"]) {
    assert.match(scanDepthSource, new RegExp('"' + confidence + '"'));
  }
  // Bounded response read and sanitized excerpt caps exist backend-side.
  assert.match(scanDepthSource, /MAX_SERVICE_RESPONSE_BYTES/);
  assert.match(scanDepthSource, /sanitize_excerpt/);
  // Unverified claim is preserved as its own field, never merged into service.
  assert.match(scanDepthSource, /remote_software_claim/);
  // Hosts must be IP literals: no hidden DNS resolution from the UI.
  assert.match(scanDepthSource, /host must be an IP literal/);
});

test("stealth commands enforce authorization and saved-case agreement", () => {
  assert.match(
    scanDepthSource,
    /explicit raw scan-type authorization acknowledgment required/,
  );
  assert.match(
    scanDepthSource,
    /request case id does not match the backend-selected case/,
  );
  assert.match(scanDepthSource, /saved case selection required/);
  // Service probe is equally gated.
  assert.match(
    scanDepthSource,
    /explicit service-probe authorization acknowledgment required/,
  );
});

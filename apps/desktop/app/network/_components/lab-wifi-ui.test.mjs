// Source-contract tests for the Wifi monitor slice (Network Lab "Wifi"
// mode). NetworkLabView.tsx is a React client component, so under plain
// `node --test` the UI is asserted as SOURCE TEXT: the mode must exist on the
// rail, start must go through the backend's native authorization dialog (no
// on-screen checkbox), monitor-mode platform honesty must be visible in the
// UI copy ("monitor mode requires Linux"), stop must be available the whole
// time a capture exists, the hashcat 22000 lines must be visible with a
// save-to-case wiring, and the Windows Npcap status must be surfaced without
// pretending it is support. The Rust command file is cross-checked for the
// contracts the UI relies on: the crate-layer reuse (no duplicated sockets in
// the command layer beyond the AF_PACKET pump), the 16-channel bound, the
// honest Unsupported refusal off Linux, the phase machine and the
// one-bounded-finding-per-session evidence save.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = read("NetworkLabView.tsx");
const backendSource = read(
  "../../../src-tauri/src/features/network/ipc/wifi_monitor.rs",
);
const crateSource = read("../../../../../crates/packet/src/wifi/mod.rs");

// --------------------------------------------------------------- UI contract ---

test("Wifi mode exists on the rail and renders as its own centered control card", () => {
  assert.match(
    viewSource,
    /type LabMode = "scope" \| "arp" \| "live" \| "dns" \| "wifi" \| "spoof" \| "dns_spoof" \| "http_proxy" \| "report";/,
  );
  assert.match(viewSource, /\{ id: "wifi", label: "Wifi", icon: Wifi, badge: wifiHandshakeBadge \}/);
  assert.match(viewSource, /<ModeCard\s+title="Wifi monitor"\s+icon=\{Wifi\}/);
  // ONE-line card description + InfoTip: the ModeCard info prop is the tip.
  const card = /<ModeCard\s+title="Wifi monitor"[\s\S]*?info="([^"]+)"/.exec(viewSource);
  assert.ok(card, "Wifi monitor ModeCard missing its InfoTip description");
  assert.ok(!card[1].includes("\n"), "card description must stay one line");
  assert.match(card[1], /monitor-mode 802\.11 capture on Linux/);
  assert.match(card[1], /passive receive-only/);
  assert.match(card[1], /native dialog on start/);
  assert.match(card[1], /hashcat 22000/);
});

test("start routes through the backend native dialog: no on-screen authorization checkbox", () => {
  const start = /<ToolButton\s+tone="primary"\s+onClick=\{\(\) => void runWifiStart\(\)\}[\s\S]*?Start capture/.exec(
    viewSource,
  );
  assert.ok(start, "Start capture button missing");
  // The acknowledgment is the backend's native Yes/No dialog, never chrome.
  assert.doesNotMatch(start[0], /authorized|checkbox/i);
  assert.match(viewSource, /networkWifiMonitorStartV1\(wifiInterface, wifiChannels, true, wb\.caseId\)/);
  assert.match(backendSource, /MessageDialogButtons::YesNo/);
  assert.match(backendSource, /blocking_show/);
  assert.match(backendSource, /Authorize wifi monitor capture/);
  assert.match(backendSource, /cancelled by operator/);
});

test("monitor-mode platform honesty is visible in the UI copy", () => {
  const start =
    /<ToolButton\s+tone="primary"\s+onClick=\{\(\) => void runWifiStart\(\)\}\s+disabled=\{([\s\S]*?)\}\s+title="([^"]+)"/.exec(
      viewSource,
    );
  assert.ok(start, "Start capture button missing or misgated");
  const gates = start[1];
  assert.match(gates, /!desktop/);
  assert.match(gates, /!wifiInterface/);
  assert.match(gates, /parseWifiChannels\(wifiChannels\) === null/);
  assert.match(gates, /wifiBlock !== null/);
  // Linux-only honesty is surfaced in the visible tooltip copy.
  assert.match(start[2], /^Linux only:/);
  assert.match(start[2], /passively reads 802\.11 frames/);
  assert.match(start[2], /nothing is transmitted/);
  assert.match(start[2], /no channel hopping is automated/);
  // The platform block and the backend note render verbatim.
  const block = /export function wifiPlatformBlock\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(block, "wifiPlatformBlock helper missing");
  assert.match(block[0], /Monitor mode requires Linux/);
  assert.match(block[0], /Npcap detected, but no Windows monitor-mode control is wired/);
  const note = /export function wifiPlatformNote\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(note, "wifiPlatformNote helper missing");
  assert.match(viewSource, /\{wifiPlatformNote\(wifiInterfaces\)\}/);
});

test("stop is always available while a capture exists and never requires re-authorization", () => {
  const stop =
    /\{wifiActive \? \(\s*<ToolButton\s+tone="danger"\s+onClick=\{\(\) => void stopWifi\(\)\}/.exec(
      viewSource,
    );
  assert.ok(stop, "conditional Stop capture button missing");
  // The stop branch carries no capability gate beyond the capture being alive.
  assert.doesNotMatch(stop[0], /disabled/);
  assert.match(viewSource, /await networkWifiMonitorStopV1\(\)/);
  // The backend never refuses cancellation (safety over ownership).
  const stopCommand =
    /pub fn network_wifi_monitor_stop_v1\([\s\S]*?\n\}/.exec(backendSource);
  assert.ok(stopCommand, "stop command missing");
  assert.match(backendSource, /Cancellation is NEVER refused/);
});

test("hashcat 22000 lines are visible with save-to-case wiring and an honest one-save rule", () => {
  assert.match(viewSource, /Hashcat 22000 evidence \(\{wifiStatus\.hashcat_22000_lines\.length\}/);
  assert.match(viewSource, /wifiStatus\.hashcat_22000_lines\.map/);
  assert.match(viewSource, /wifiStatus\.handshakes_captured > 0 \? "orange" : "muted"/);
  assert.match(viewSource, /wifiStatus\.frames_seen/);
  assert.match(viewSource, /wifiStatus\.beacons/);
  assert.match(viewSource, /wifiStatus\.clients_seen/);
  assert.match(viewSource, /wifiStatus\.access_points\.map/);
  // Save-to-case: one bounded finding per session, receipt honest about truncation.
  assert.match(viewSource, /await networkWifiEvidenceSaveV1\(caseId\)/);
  assert.match(viewSource, /wifiSaved/);
  assert.match(viewSource, /wifiReceipt\.truncated/);
  assert.match(viewSource, /truncated at the 32 KiB bound/);
  const saveTip = /<InfoTip text="([^"]*one bounded artifact[^"]*)"/i.exec(viewSource);
  assert.ok(saveTip, "save-to-case InfoTip missing");
});

test("wifi state dies on case switch so a stale run can never render against a new revision", () => {
  const reset = /useEffect\(\(\) => \{([\s\S]*?)\}, \[wb\.caseId\]\);/.exec(viewSource);
  assert.ok(reset, "case-change reset effect missing");
  assert.match(reset[1], /setWifiStatus\(null\)/);
  assert.match(reset[1], /setWifiReceipt\(null\)/);
  assert.match(reset[1], /setWifiError\(null\)/);
});

test("channel input is bounded client-side at 16 and the interface select is honest", () => {
  const channels = /export function parseWifiChannels\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(channels, "parseWifiChannels helper missing");
  assert.match(channels[0], /tokens\.length > 16/);
  assert.match(channels[0], /tokens\.length === 0/);
  assert.match(viewSource, /ariaLabel="Wifi monitor wireless interface"/);
  assert.match(
    viewSource,
    /ariaLabel="Capture channels: 2\.4\/5 GHz channel numbers or explicit MHz frequencies, at most 16, comma separated"/,
  );
});

test("windows Npcap status is surfaced without pretending it is support", () => {
  // The interfaces wire carries the honest booleans; the UI renders the
  // backend note verbatim and gates start on monitor_supported only.
  assert.match(viewSource, /wifiInterfaces && !wifiInterfaces\.monitor_supported/);
  assert.match(viewSource, /"unsupported here"/);
  assert.match(backendSource, /pub npcap_detected: bool/);
  assert.match(backendSource, /pub monitor_supported: bool/);
  assert.match(backendSource, /presence is NOT support/);
});

test("gates render only errors and the shared gate cluster is not repeated", () => {
  const wifiSection =
    /\{mode === "wifi" && \(([\s\S]*?)\n      \)\}\n\n      \{mode === "/.exec(viewSource);
  assert.ok(wifiSection, "wifi mode section missing");
  assert.match(wifiSection[1], /<ErrorStrip>\{wifiError\}<\/ErrorStrip>/);
  assert.doesNotMatch(wifiSection[1], /pointer|case management/i);
  assert.equal(viewSource.match(/\{gateCluster\}/g)?.length, 1);
});

// ------------------------------------------------------- backend contracts ---

test("backend commands exist with the v1 names and keep the radio control in the crate layer", () => {
  for (const command of [
    "network_wifi_interfaces_v1",
    "network_wifi_monitor_start_v1",
    "network_wifi_monitor_stop_v1",
    "network_wifi_monitor_status_v1",
    "network_wifi_evidence_save_v1",
  ]) {
    assert.match(backendSource, new RegExp(`pub (async )?fn ${command}`));
  }
  // The command layer reuses the crate's nl80211 client and pure engine
  // instead of duplicating them.
  assert.match(backendSource, /MonitorCapture::new\(\)/);
  assert.match(crateSource, /pub fn process_frame/);
  assert.match(crateSource, /pub fn hashcat_22000_lines/);
});

test("monitor control is Linux-only with honest Unsupported elsewhere", () => {
  assert.match(crateSource, /pub fn monitor_mode_supported/);
  assert.match(backendSource, /currently requires Linux/);
  // The pump core is portable; only the AF_PACKET source is cfg-gated.
  assert.match(backendSource, /pub\(crate\) fn run_frame_pump/);
  assert.match(backendSource, /#\[cfg\(target_os = "linux"\)\]\s*\nmod monitor_socket/);
});

test("bounds are hard: 16 channels, 64 APs, 256 clients, one bounded evidence artifact", () => {
  assert.match(backendSource, /MAX_WIFI_CHANNELS: usize = 16/);
  assert.match(backendSource, /MAX_WIFI_ACCESS_POINTS: usize = 64/);
  assert.match(backendSource, /MAX_WIFI_CLIENTS: usize = 256/);
  assert.match(backendSource, /MAX_WIFI_EVIDENCE_BYTES: usize = 32 \* 1024/);
  assert.match(backendSource, /at most \{MAX_WIFI_CHANNELS\} capture frequencies/);
  assert.match(backendSource, /already saved its one bounded evidence finding/);
});

test("the pump is passive and stop-checked per read with honest counters", () => {
  assert.match(backendSource, /The pump never transmits/);
  assert.match(backendSource, /stop flag is checked BEFORE every read/);
  assert.match(backendSource, /if stop\.load\(Ordering::Acquire\) \{/);
  assert.match(backendSource, /the case session was revoked — monitor capture stopped/);
  // Every exit publishes the final snapshot; status stays honest after stop.
  assert.match(backendSource, /Every exit publishes the final bounded snapshot first/);
});

test("evidence persists through the standard case findings path", () => {
  assert.match(backendSource, /WIFI_EVIDENCE_SOURCE: &str = "network\.wifi"/);
  assert.match(backendSource, /with_current_publication/);
  assert.match(backendSource, /add_findings\(&verified_case, WIFI_EVIDENCE_SOURCE, None, &\[finding\]\)/);
  assert.match(backendSource, /no hashcat 22000 lines captured this session — nothing to save/);
});

test("status wire stays snake_case and the view reads exactly those fields", () => {
  for (const field of [
    "pub state: String",
    "pub frames_seen: u64",
    "pub beacons: u64",
    "pub clients_seen: usize",
    "pub handshakes_captured: usize",
    "pub hashcat_22000_lines: Vec<String>",
    "pub access_points: Vec<WifiApWire>",
    "pub clients: Vec<String>",
    "pub elapsed_ms: u64",
    "pub last_error: Option<String>",
  ]) {
    assert.match(backendSource, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(backendSource, /idle \| starting \| monitoring \| stopping \| stopped/);
});

test("Rust unit tests cover the promised contracts in the command file", () => {
  for (const test_name of [
    "fn phase_labels_cover_the_whole_lifecycle_in_snake_case",
    "fn status_wire_starts_honest_at_zero_and_reports_after_a_session",
    "fn the_run_guard_publishes_stopped_and_case_change_arms_the_stop_flag",
    "fn channel_parsing_maps_bands_and_explicit_frequencies",
    "fn channel_parsing_refuses_garbage_out_of_range_and_oversized_lists",
    "fn run_frame_pump_counts_frames_beacons_clients_and_publishes_evidence",
    "fn the_stop_flag_is_checked_before_every_read",
    "fn scope_revocation_stops_the_capture_with_an_honest_error",
    "fn snapshot_tables_stay_bounded",
    "fn monitor_control_is_unsupported_off_linux_honestly",
    "fn npcap_probe_is_false_off_windows",
    "fn evidence_finding_is_fixed_titled_and_carries_the_22000_lines",
    "fn oversize_evidence_is_bounded_at_the_cap_with_an_honest_marker",
    "fn one_save_per_session_is_enforced_by_the_session_flag",
  ]) {
    assert.match(backendSource, new RegExp(test_name.replace(/_/g, "_")));
  }
});

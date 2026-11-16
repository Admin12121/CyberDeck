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
//
// Injection slice (additive pins): deauth is ACTIVE interference gated
// end-to-end like the spoof mode — targets bounded to the CURRENT session's
// observed APs, native dialog naming every BSSID and the exact counts, gate
// lease, hard bounds (≤ 32 frames/burst, ≤ 4 bursts, ≤ 10 s), stop never
// refused, Linux-only honesty; channel hopping is passive radio control over
// the live capture (250-2000 ms, ≤ 16 in-band channels, pause/resume keeps
// the capture, full ≤ 256-entry hop log visible in the UI).
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

// ------------------------------------------------- injection slice pins ---

const crateInjectSource = read("../../../../../crates/packet/src/wifi/inject.rs");

test("deauth injection is an explicitly gated active-interference cluster in the wifi block", () => {
  const injectButton =
    /<ToolButton\s+tone="primary"\s+onClick=\{\(\) => void runWifiDeauth\(\)\}[\s\S]*?Inject deauth/.exec(
      viewSource,
    );
  assert.ok(injectButton, "Inject deauth button missing");
  // The gated Start mirrors the spoof discipline: platform, live-session and
  // bounded-input gates, never an on-screen authorization checkbox.
  assert.match(injectButton[0], /!desktop/);
  assert.match(injectButton[0], /wifiDeauthBlock !== null/);
  assert.match(injectButton[0], /wifiHopRunning/);
  assert.match(injectButton[0], /parseWifiDeauthTargets\(wifiDeauthTargets, wifiObservedBssids\) === null/);
  assert.match(injectButton[0], /parseWifiDeauthFrames\(wifiDeauthFrames\) === null/);
  assert.match(injectButton[0], /parseWifiDeauthBursts\(wifiDeauthBursts\) === null/);
  assert.doesNotMatch(injectButton[0], /checkbox/i);
  // Honest copy: interference, platform, target provenance, hard bounds.
  assert.match(injectButton[0], /ACTIVE interference/);
  assert.match(injectButton[0], /Linux only/);
  assert.match(injectButton[0], /observed by this monitor session/);
  assert.match(injectButton[0], /no blind targets/);
  assert.match(injectButton[0], /native Yes\/No dialog/);
  assert.match(injectButton[0], /at most 32 frames per burst, 4 bursts, 10 seconds total/);
  // The cluster labels the interference before any control.
  assert.match(viewSource, /<Chip tone="orange">active interference<\/Chip>/);
  assert.match(viewSource, /<Chip tone="muted">Linux only<\/Chip>/);
});

test("deauth start is dialog-named backend-side and leases the shared active-operation gate", () => {
  assert.match(backendSource, /pub async fn network_wifi_inject_deauth_v1/);
  assert.match(backendSource, /Authorize wifi deauth injection/);
  assert.match(backendSource, /MessageDialogButtons::YesNo/);
  assert.match(backendSource, /wifi deauth injection cancelled by operator/);
  assert.match(backendSource, /This is ACTIVE interference/);
  assert.match(backendSource, /gate\.acquire\(super::operation_gate::ActiveOperation::WifiInject\)/);
  assert.match(backendSource, /let _permit = permit/);
});

test("deauth targets are bounded to BSSIDs the CURRENT monitor session observed", () => {
  // UI: the picker only offers observed APs and the parser refuses blind ones.
  assert.match(
    viewSource,
    /ariaLabel="Deauth target picker: access points observed by this monitor session"/,
  );
  const targets = /export function parseWifiDeauthTargets\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(targets, "parseWifiDeauthTargets helper missing");
  assert.match(targets[0], /tokens\.length === 0 \|\| tokens\.length > 4/);
  assert.match(targets[0], /!observed\.includes\(mac\)/);
  const add = /export function addWifiDeauthTarget\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(add, "addWifiDeauthTarget helper missing");
  assert.match(add[0], /tokens\.length >= 4/);
  // Backend: the observed AP table is the only target source.
  const resolve =
    /fn resolve_observed_targets\([\s\S]*?\n\}/.exec(backendSource);
  assert.ok(resolve, "resolve_observed_targets missing");
  assert.match(resolve[0], /not observed by the current monitor session/);
  assert.match(backendSource, /no blind targets/);
  assert.match(backendSource, /MAX_INJECT_TARGETS: usize = inject::MAX_DEAUTH_TARGETS/);
  assert.match(backendSource, /require_live_monitor\(&wifi\)\?/);
});

test("deauth stop is never refused and the run is hard-bounded in the crate core", () => {
  const stopCommand =
    /pub fn network_wifi_inject_deauth_stop_v1\([\s\S]*?\n\}/.exec(backendSource);
  assert.ok(stopCommand, "deauth stop command missing");
  assert.match(stopCommand[0], /deauth_stop\.store\(true, Ordering::Release\)/);
  assert.match(viewSource, /await networkWifiInjectDeauthStopV1\(\)/);
  // The crate core carries the hard bounds and the paced loop.
  assert.match(crateInjectSource, /pub const MAX_DEAUTH_TARGETS: usize = 4/);
  assert.match(crateInjectSource, /pub const MAX_DEAUTH_BURSTS: usize = 4/);
  assert.match(crateInjectSource, /pub const MAX_FRAMES_PER_BURST: usize = 32/);
  assert.match(crateInjectSource, /pub const MAX_DEAUTH_RUN_MS: u64 = 10_000/);
  assert.match(crateInjectSource, /pub const MIN_FRAME_INTERVAL_MS: u64 = 20/);
  assert.match(crateInjectSource, /pub fn run_wifi_deauth/);
});

test("the deauth frame is byte-pinned and round-trips through the landed parser", () => {
  assert.match(crateInjectSource, /fn deauth_frame_matches_the_hand_built_fixture_byte_for_byte/);
  assert.match(crateInjectSource, /f\[0\] = 0xC0/);
  assert.match(
    crateInjectSource,
    /fn the_built_deauth_round_trips_through_the_landed_frame_parser/,
  );
  assert.match(crateInjectSource, /DEAUTH_REASON_CLASS_3_FROM_NONASSOCIATED: u16 = 7/);
  assert.match(crateInjectSource, /pub const INJECT_FRAME_LEN: usize = TX_RADIOTAP_LEN \+ DEAUTH_FRAME_LEN/);
});

test("channel hop is bounded, keeps the capture running and logs every hop in the UI", () => {
  const hopButton =
    /<ToolButton\s+tone="primary"\s+onClick=\{\(\) => void controlWifiHop\("start"\)\}[\s\S]*?Start hop/.exec(
      viewSource,
    );
  assert.ok(hopButton, "Start hop button missing");
  assert.match(hopButton[0], /parseWifiHopIntervalMs\(wifiHopInterval\) === null/);
  assert.match(hopButton[0], /parseWifiChannels\(wifiChannels\) === null/);
  assert.match(hopButton[0], /wifiDeauthActive/);
  assert.match(hopButton[0], /at most 16, in-band/);
  assert.match(hopButton[0], /every 250-2000 ms/);
  assert.match(hopButton[0], /every hop is logged \(at most 256 entries\)/);
  // Pause/resume keeps the capture; stop never re-authorizes.
  assert.match(viewSource, /void controlWifiHop\(wifiHopPaused \? "resume" : "pause"\)/);
  assert.match(viewSource, /<Chip tone="muted">capture keeps running<\/Chip>/);
  assert.match(viewSource, /await networkWifiChannelHopV1\(/);
  // The full hop log is visible with its bound named.
  assert.match(viewSource, /wifiStatus\.hop_log\.map/);
  assert.match(viewSource, /bounded at 256/);
  // Backend + crate bounds.
  assert.match(backendSource, /pub async fn network_wifi_channel_hop_v1/);
  assert.match(backendSource, /HOP_UNSUPPORTED_MESSAGE\.contains\("requires Linux"\)|"wifi channel hopping uses the Linux nl80211 control door and currently requires Linux"/);
  assert.match(crateInjectSource, /pub const MAX_HOP_CHANNELS: usize = 16/);
  assert.match(crateInjectSource, /pub const MIN_HOP_INTERVAL_MS: u64 = 250/);
  assert.match(crateInjectSource, /pub const MAX_HOP_INTERVAL_MS: u64 = 2_000/);
  assert.match(crateInjectSource, /pub const MAX_HOP_LOG: usize = 256/);
  assert.match(crateInjectSource, /fn hop_pause_freezes_and_resume_rearms_without_a_catchup_burst/);
});

test("injection and hop status stay additive snake_case fields the view reads verbatim", () => {
  for (const field of [
    "pub deauth_state: String",
    "pub deauth_frames_sent: u64",
    "pub deauth_bursts_done: usize",
    "pub deauth_targets: usize",
    "pub deauth_note: Option<String>",
    "pub injection_last_error: Option<String>",
    "pub hop_running: bool",
    "pub hop_paused: bool",
    "pub hop_channel_mhz: u32",
    "pub hop_channels: Vec<u32>",
    "pub hop_interval_ms: u32",
    "pub hop_count: u64",
    "pub hop_log: Vec<WifiHopEntryWire>",
    "pub hop_last_error: Option<String>",
  ]) {
    assert.match(backendSource, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  // The command file's own tests cover the additive slice.
  for (const test_name of [
    "fn bssid_parsing_accepts_colon_hex_and_refuses_garbage",
    "fn injection_targets_are_limited_to_the_current_sessions_observed_aps",
    "fn deauth_bounds_mirror_the_crate_plan_validation",
    "fn injection_requires_a_live_monitor_session",
    "fn status_wire_carries_additive_injection_and_hop_fields_honestly",
    "fn case_change_arms_the_injection_and_hop_stop_flags",
    "fn hop_scheduler_wiring_pauses_resumes_and_logs_through_the_ctx_slot",
    "fn injection_and_hop_report_unsupported_off_linux_honestly",
  ]) {
    assert.match(backendSource, new RegExp(test_name.replace(/_/g, "_")));
  }
  // Injection honestly reports Unsupported off Linux; the status word set
  // extends the monitor phase machine rather than replacing it.
  assert.match(backendSource, /INJECTION_UNSUPPORTED_MESSAGE: &str =[\s\S]*?requires Linux/);
  assert.match(backendSource, /idle \| injecting \| stopping \| stopped/);
  assert.match(backendSource, /idle \| starting \| monitoring \| stopping \| stopped/);
});

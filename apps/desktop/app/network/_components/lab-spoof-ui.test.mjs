// Source-contract tests for the Bettercap-parity ARP spoofing slice
// (Network Lab "Spoof" mode). NetworkLabView.tsx is a React client component,
// so under plain `node --test` the UI is asserted as SOURCE TEXT: the mode
// must exist on the rail, start must go through the backend's native
// authorization dialog (no on-screen checkbox), Linux-only honesty must be
// visible in the UI copy, stop must be available the whole time a run exists,
// and the restoration summary must render on stop. The Rust command file and
// the pure spoofer core are cross-checked for the contracts the UI relies on:
// saved-scope-only addressing, the shared gate lease, the 32-pair cap, the
// 1-10 rounds/s bound, the 30-minute runtime cap, and a restoration pass that
// always runs and reports exactly what was restored and what stayed unknown.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = read("NetworkLabView.tsx");
const backendSource = read(
  "../../../src-tauri/src/features/network/ipc/network_lab_spoof.rs",
);
const coreSource = read(
  "../../../src-tauri/src/features/network/infrastructure/arp_spoof.rs",
);

// --------------------------------------------------------------- UI contract ---

test("Spoof mode exists on the rail and renders as its own centered control card", () => {
  assert.match(viewSource, /type LabMode = "scope" \| "arp" \| "live" \| "dns" \| "spoof" \| "report";/);
  assert.match(viewSource, /\{ id: "spoof", label: "Spoof", icon: Syringe \}/);
  assert.match(viewSource, /<ModeCard\s+title="ARP spoof"\s+icon=\{Syringe\}/);
  // ONE-line card description + InfoTip: the ModeCard info prop is the tip.
  const card = /<ModeCard\s+title="ARP spoof"[\s\S]*?info="([^"]+)"/.exec(viewSource);
  assert.ok(card, "ARP spoof ModeCard missing its InfoTip description");
  assert.ok(!card[1].includes("\n"), "card description must stay one line");
  assert.match(card[1], /saved lab scope only/);
  assert.match(card[1], /native dialog/);
  assert.match(card[1], /restores real MACs on stop/);
});

test("start routes through the backend native dialog: no on-screen authorization checkbox", () => {
  const start = /<ToolButton\s+tone="primary"\s+onClick=\{\(\) => void runSpoofStart\(\)\}[\s\S]*?Start spoof/.exec(
    viewSource,
  );
  assert.ok(start, "Start spoof button missing");
  // The acknowledgment is the backend's native Yes/No dialog, never chrome.
  assert.doesNotMatch(start[0], /authorized|checkbox/i);
  assert.match(viewSource, /networkLabSpoofStartV1\(\s*sweepInterface,\s*spoofGateway,\s*count,\s*rate,\s*true,\s*wb\.caseId,/);
  assert.match(backendSource, /MessageDialogButtons::YesNo/);
  assert.match(backendSource, /blocking_show/);
  assert.match(backendSource, /Authorize lab ARP spoofing/);
  assert.match(backendSource, /cancelled by operator/);
  assert.match(backendSource, /Backend confirmation is independent of the frontend checkbox/);
});

test("start button is desktop-, interface-, scope- and bound-gated with honest copy", () => {
  const start =
    /<ToolButton\s+tone="primary"\s+onClick=\{\(\) => void runSpoofStart\(\)\}\s+disabled=\{([\s\S]*?)\}\s+title="([^"]+)"/.exec(
      viewSource,
    );
  assert.ok(start, "Start spoof button missing or misgated");
  const gates = start[1];
  assert.match(gates, /!desktop/);
  assert.match(gates, /!sweepInterface/);
  assert.match(gates, /spoofBlock !== null/);
  assert.match(gates, /!spoofGateway/);
  assert.match(gates, /parseSpoofRate\(spoofRate\) === null/);
  assert.match(gates, /parseSpoofTargetCount\(spoofTargetCount\) === null/);
  // Linux-only honesty is surfaced in the visible tooltip copy.
  assert.match(start[2], /^Linux only:/);
  assert.match(start[2], /native Yes\/No dialog names exactly what will be sent/);
  assert.match(start[2], /refuses anything outside the saved lab scope/);
  assert.match(start[2], /30-minute hard runtime cap/);
  assert.match(start[2], /restoration pass on stop/);
});

test("stop is always available while a run exists and never requires re-authorization", () => {
  const stop =
    /\{spoofActive \? \(\s*<ToolButton\s+tone="danger"\s+onClick=\{\(\) => void stopSpoof\(\)\}/.exec(
      viewSource,
    );
  assert.ok(stop, "conditional Stop spoof button missing");
  // The stop branch carries no capability gate beyond the run being alive.
  assert.doesNotMatch(stop[0], /disabled/);
  assert.match(viewSource, /await networkLabSpoofStopV1\(\)/);
  // The backend never refuses cancellation (safety over ownership).
  const stopCommand =
    /pub fn network_lab_spoof_stop_v1\([\s\S]*?\n\}/.exec(backendSource);
  assert.ok(stopCommand, "stop command missing");
  assert.match(backendSource, /Cancellation is NEVER refused/);
});

test("live status panel shows honest counts and the restored summary on stop", () => {
  assert.match(viewSource, /spoofStatus\?\.packets_sent \?\? 0/);
  assert.match(viewSource, /spoofStatus\?\.pairs \?\? 0/);
  assert.match(viewSource, /spoofStatus\.elapsed_ms/);
  assert.match(viewSource, /spoofStatus\?\.restored_targets \?\? 0/);
  // Per-target line comes from the backend's authorized start wire.
  assert.match(viewSource, /targets: \{spoofStart\.targets\.join\(", "\)/);
  const stopped =
    /\{spoofPhase === "stopped" \? \(\s*<p[\s\S]*?\)\s*:\s*null\}/.exec(viewSource);
  assert.ok(stopped, "stopped-state restoration summary missing");
  assert.match(stopped[0], /restoration_note/);
  // The lab timeline honesty: the spoof's own traffic is visible to arp_watch.
  assert.match(
    viewSource,
    /spoof's own replies also appear as ARP conflicts in the lab timeline/,
  );
});

test("spoof state dies on case switch so a stale run can never render against a new revision", () => {
  const reset = /useEffect\(\(\) => \{([\s\S]*?)\}, \[wb\.caseId\]\);/.exec(viewSource);
  assert.ok(reset, "case-change reset effect missing");
  assert.match(reset[1], /setSpoofStatus\(null\)/);
  assert.match(reset[1], /setSpoofStart\(null\)/);
  assert.match(reset[1], /setSpoofError\(null\)/);
});

test("pure UI gate mirrors the backend scope requirements", () => {
  const gate = /export function spoofBlockReason\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(gate, "spoofBlockReason helper missing");
  assert.match(gate[0], /No lab scope is set — set Target 1 \/ Target 2 first/);
  assert.match(gate[0], /no pinned IPv4 entry to use as the gateway/);
  const candidates = /export function spoofGatewayCandidates\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(candidates, "gateway candidates helper missing");
  // Pinned IPv4 literals only; CIDR and IPv6 entries are excluded client-side.
  assert.ok(
    candidates[0].includes("/^\\d{1,3}(\\.\\d{1,3}){3}$/"),
    "IPv4-literal filter missing from gateway candidates",
  );
  const rate = /export function parseSpoofRate\([\s\S]*?\n\}/.exec(viewSource);
  const count = /export function parseSpoofTargetCount\([\s\S]*?\n\}/.exec(viewSource);
  assert.match(rate[0], /value < 1 \|\| value > 10/);
  assert.match(count[0], /value < 1 \|\| value > 32/);
});

test("gates render only errors and the shared gate cluster is not repeated", () => {
  const spoofSection =
    /\{mode === "spoof" && \(([\s\S]*?)\n      \)\}\n    <\/WorkspaceShell>/.exec(viewSource);
  assert.ok(spoofSection, "spoof mode section missing");
  assert.match(spoofSection[1], /<ErrorStrip>\{spoofError\}<\/ErrorStrip>/);
  assert.doesNotMatch(spoofSection[1], /pointer|case management/i);
  assert.equal(viewSource.match(/\{gateCluster\}/g)?.length, 1);
});

// ------------------------------------------------------- backend contracts ---

test("backend commands exist with the v1 names and keep socket code out of the IPC layer", () => {
  for (const command of [
    "network_lab_spoof_start_v1",
    "network_lab_spoof_stop_v1",
    "network_lab_spoof_status_v1",
  ]) {
    assert.match(backendSource, new RegExp(`pub (async )?fn ${command}`));
  }
  // No raw socket machinery in the command layer; the core owns it.
  assert.doesNotMatch(backendSource, /AF_PACKET|SOCK_RAW|libc|socket\(/);
  assert.match(coreSource, /AF_PACKET/);
  // The command layer reuses the pure worker instead of duplicating it.
  assert.match(backendSource, /arp_spoof::run_arp_spoof\(/);
  assert.match(coreSource, /pub fn run_arp_spoof\(/);
});

test("spoofing is Linux-only with honest Unsupported elsewhere", () => {
  assert.match(coreSource, /SpoofErrorCode::Unsupported/);
  assert.match(coreSource, /ARP spoofing currently requires Linux AF_PACKET and CAP_NET_RAW/);
  assert.match(coreSource, /#\[cfg\(target_os = "linux"\)\]\s*\n\s*mod linux/);
  assert.match(coreSource, /#\[cfg\(not\(target_os = "linux"\)\)\]/);
  assert.match(
    backendSource,
    /lab ARP spoofing uses the native ARP worker and currently requires Linux/,
  );
});

test("core docs state the authorization discipline and scope exclusivity", () => {
  assert.match(coreSource, /AUTHORIZED LAB USE ONLY/);
  assert.match(coreSource, /NetworkOperationGate/);
  assert.match(coreSource, /native confirmation dialog/);
  assert.match(coreSource, /saved lab scope/);
  assert.match(coreSource, /never widens or re-derives a scope/);
});

test("backend resolves targets only from the saved lab scope and refuses outsiders", () => {
  assert.match(backendSource, /no lab scope is set/);
  assert.match(backendSource, /arp_spoof::build_scope_set\(/);
  assert.match(backendSource, /arp_spoof::build_spoof_pairs\(&set, gateway_ip, target_count/);
  assert.match(backendSource, /gateway must be an IPv4 address from the saved lab scope/);
  assert.match(coreSource, /outside the saved lab scope \(Target 1 ∪ Target 2\)/);
  // The worker closure revalidates the case revision like the sweep does.
  assert.match(backendSource, /\.ensure\(&worker_scope\)/);
});

test("bounds are hard: 32 pairs, 1-10 rounds/s, 30-minute auto-stop", () => {
  assert.match(coreSource, /MAX_SPOOF_PAIRS: usize = 32/);
  assert.match(coreSource, /MIN_SPOOF_RATE_PER_SEC: u32 = 1/);
  assert.match(coreSource, /MAX_SPOOF_RATE_PER_SEC: u32 = 10/);
  assert.match(coreSource, /MAX_SPOOF_RUNTIME_MS: u64 = 30 \* 60 \* 1000/);
  assert.match(coreSource, /spoof rate must be/);
  assert.match(coreSource, /spoof target count must be 1\.\.=/);
  // The loop auto-stops at the cap and then still restores.
  assert.match(coreSource, /SpoofEndReason::RuntimeCapReached/);
  assert.match(backendSource, /hard 30-minute/);
});

test("full-duplex poisoning sends both directions with OUR MAC, rate-limited per round", () => {
  assert.match(coreSource, /pub fn poison_frame_to_target\(/);
  assert.match(coreSource, /pub fn poison_frame_to_gateway\(/);
  assert.match(
    coreSource,
    /poison_frame_to_target\(\*pair, our_mac, ledger\.target_mac\(pair\.target\)\)/,
  );
  assert.match(coreSource, /poison_frame_to_gateway\(\*pair, our_mac, ledger\.gateway_mac\(\)\)/);
  // One pacer drives one round per interval; the stop flag is polled before
  // every round and during every park.
  assert.match(coreSource, /let mut pacer = SpoofPacer::new\(rate_per_sec\)\?;/);
  assert.match(coreSource, /if stop\.load\(Ordering::Acquire\) \{/);
});

test("stop semantics always restore: real MACs both ways, unknowns reported honestly", () => {
  assert.match(coreSource, /pub enum SpoofEndReason/);
  assert.match(coreSource, /OperatorStop|ScopeRevoked|RuntimeCapReached|SendFailure/);
  // Restoration runs after every loop end (the loop always falls through to it).
  assert.match(coreSource, /let restoration = restoration_pass\(/);
  assert.match(coreSource, /pub fn restore_frame_to_target\(/);
  assert.match(coreSource, /pub fn restore_frame_to_gateway\(/);
  assert.match(coreSource, /pub fn arp_request_frame\(/);
  assert.match(coreSource, /pub struct RestorationReport/);
  assert.match(coreSource, /unknown_target_macs: Vec<Ipv4Addr>/);
  assert.match(coreSource, /pub fn run_spoof_loop\(/);
  assert.match(coreSource, /pub struct MacLedger/);
  // Every transmitted frame is counted, live, on the shared counter.
  assert.match(coreSource, /sent_counter\.store\(packets_sent, Ordering::Release\)/);
});

test("status wire stays snake_case and the view reads exactly those fields", () => {
  for (const field of [
    "pub state: String",
    "pub packets_sent: u64",
    "pub pairs: usize",
    "pub elapsed_ms: u64",
    "pub restored_targets: usize",
    "pub restoration_note: Option<String>",
    "pub last_error: Option<String>",
  ]) {
    assert.match(backendSource, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(backendSource, /restoration_note_text\(/);
  // The start wire hands the authorized target list to the UI verbatim.
  assert.match(backendSource, /pub struct SpoofStartWire/);
  assert.match(backendSource, /pub targets: Vec<String>/);
  assert.match(backendSource, /pub rate_per_sec: u32/);
  assert.match(backendSource, /pub runtime_cap_minutes: u32/);
});

test("Rust unit tests cover the promised contracts in the spoofer core", () => {
  for (const test of [
    "fn poison_frames_match_hand_built_fixtures_in_both_directions",
    "fn restore_frames_carry_real_macs_not_our_own",
    "fn rate_limiter_paces_rounds_without_burst_catchup",
    "fn out_of_scope_gateways_and_targets_are_refused_with_explicit_errors",
    "fn ledger_learns_real_macs_and_ignores_our_own_claims",
    "fn stop_semantics_end_poisoning_and_still_restore",
    "fn runtime_cap_auto_stops_the_run",
    "fn scope_revocation_mid_run_ends_the_run_and_restores",
    "fn spoofing_reports_unsupported_off_linux_regardless_of_scope",
  ]) {
    assert.match(coreSource, new RegExp(test.replace(/_/g, "_")));
  }
});

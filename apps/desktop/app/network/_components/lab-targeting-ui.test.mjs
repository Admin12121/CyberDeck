// Source-contract tests for the lab-scope-targeted ARP sweep slice
// (Ettercap-style host targeting). NetworkLabView.tsx is a React client
// component, so under plain `node --test` the UI is asserted as SOURCE TEXT:
// the sweep button must be labeled for Target 1 ∪ Target 2, gated on
// authorization + a set scope + an interface, and the results must render in
// the findings-table area with the reused alert surface. The Rust command
// file is cross-checked for the contracts the UI relies on: refusal errors,
// the native confirmation dialog, exclusivity, the 32-target cap and reuse
// of the existing native ARP worker. The client module's pure gate helper is
// exercised for real logic assertions.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = read("NetworkLabView.tsx");
const clientSource = read("network-lab-targeting-ipc.ts");
const backendSource = read(
  "../../../src-tauri/src/features/network/ipc/network_lab_targeting.rs",
);

// --------------------------------------------------------------- UI contract ---

test("sweep button is scope-constrained: labeled Target 1 ∪ Target 2 in its tooltip and gated on authorization + set scope + desktop + interface", () => {
  assert.match(viewSource, /ARP sweep \(Target 1 ∪ Target 2\)/);
  // Anchor the whole contiguous button block (attributes and label), so the
  // earlier Set-scope primary button cannot satisfy this match. The visible
  // label stays short ("Sweep"); the full scope constraint lives in the
  // tooltip.
  const button =
    /<ToolButton\s+tone="primary"\s+(?:onClick=\{[^}]*\}\s+)?disabled=\{[^}]*\}\s+title="[^"]*refuses anything outside the declared scope[^"]*"\s*>\s+Sweep/.exec(
      viewSource,
    );
  assert.ok(button, "ARP sweep button missing");
  assert.match(button[0], /!desktop/, "sweep must be desktop-gated");
  assert.match(button[0], /!authorized/, "sweep must require the authorization checkbox");
  assert.match(button[0], /sweepBlock !== null/, "sweep must be blocked without a set scope");
  assert.match(button[0], /!sweepInterface/, "sweep must require a selected interface");
  // The tooltip states the scope constraint honestly.
  assert.match(button[0], /ONLY the IPv4 targets resolved from the saved lab scope/);
});

test("sweep UI reports why it is blocked and reuses the alert surface for refusals", () => {
  assert.match(viewSource, /labSweepBlockReason\(scope\)/);
  // The reused role="alert" error surface renders sweep refusals too.
  const alertBlocks = viewSource.match(/<div role="alert"[^>]*>[\s\S]*?<\/div>/g) ?? [];
  assert.ok(
    alertBlocks.some((block) => block.includes("{sweepError}")),
    "sweep errors must render through the reused alert surface",
  );
});

test("sweep progress and stop run through the channel and results render in the findings-table area", () => {
  assert.match(viewSource, /networkLabArpSweepV1\(sweepInterface, authorized, caseId/);
  assert.match(viewSource, /setSweepProgress\(progress\)/);
  assert.match(viewSource, /networkLabArpSweepStopV1\(\)/);
  assert.match(viewSource, /Stop sweep/);
  // Results render with the same data-table styling as the ARP findings.
  assert.match(viewSource, /sweepResults\.map/);
  assert.match(viewSource, /data-table/);
  assert.match(viewSource, /Responder MAC/);
  // Honest zero state: silence is never spun as evidence.
  assert.match(viewSource, /silence is not evidence of/);
});

test("sweep state dies on case switch so stale results never survive a revision change", () => {
  const reset = /useEffect\(\(\) => \{([\s\S]*?)\}, \[wb\.caseId\]\);/.exec(viewSource);
  assert.ok(reset, "case-change reset effect missing");
  assert.match(reset[1], /setSweepResults\(null\)/);
  assert.match(reset[1], /setSweepProgress\(null\)/);
  assert.match(reset[1], /setSweepBusy\(false\)/);
});

// ------------------------------------------------------------ backend contract ---

test("backend refuses a sweep when no scope is set or the scope resolves to no probeable IPv4 target", () => {
  assert.match(backendSource, /no lab scope is set/);
  assert.match(backendSource, /no probeable IPv4 targets/);
  assert.match(backendSource, /IPv6 entries need Neighbor Discovery, not ARP/);
  // Out-of-scope refusal, stated in operator terms.
  assert.match(backendSource, /outside the saved lab scope \(Target 1 ∪ Target 2\)/);
});

test("backend enforces the 32-target cap with narrowing guidance, never truncation", () => {
  assert.match(backendSource, /MAX_ARP_TARGETS/);
  assert.match(backendSource, /narrow the scope/);
  assert.match(backendSource, /resolve_sweep_targets\(/);
  // Honest cap: refusal instead of silently scanning a fraction.
  assert.match(backendSource, /never trunc|refuses instead of|is refused, never truncated/);
});

test("backend confirms with a native Yes/No dialog that names the saved lab scope", () => {
  assert.match(backendSource, /MessageDialogButtons::YesNo/);
  assert.match(backendSource, /blocking_show/);
  assert.match(backendSource, /Authorize lab-scope ARP sweep/);
  assert.match(backendSource, /saved Network Lab scope \(Target 1 ∪ Target 2\)/);
  assert.match(backendSource, /cancelled by operator/);
  // The confirmation is independent of the frontend checkbox and is
  // followed by case revalidation.
  assert.match(backendSource, /Backend confirmation is independent of the frontend checkbox/);
  assert.match(backendSource, /session\.ensure\(&scope\)\?/);
});

test("backend enforces exclusivity: shared gate lease, ARP discovery ctx, one sweep per process", () => {
  assert.match(backendSource, /ActiveOperation::LinkNeighbor/);
  assert.match(backendSource, /arp\.is_running\(\)/);
  assert.match(backendSource, /gate\.is_active\(\)/);
  assert.match(backendSource, /running\.swap\(true, Ordering::AcqRel\)/);
  assert.match(backendSource, /a lab ARP sweep operation is already active/);
  // Re-check after the modal dialog closes.
  assert.match(backendSource, /became active while confirming the lab ARP sweep/);
  // The worker closure revalidates the case revision, mirroring arp_discovery.
  assert.match(backendSource, /\.ensure\(&worker_scope\)/);
});

test("backend reuses the existing native ARP worker instead of duplicating socket code", () => {
  assert.match(backendSource, /discover_on_link_arp\(/);
  // No raw socket machinery may appear in this command layer.
  assert.doesNotMatch(backendSource, /AF_PACKET|SOCK_RAW|libc|socket\(/);
});

test("stop and status commands exist and are owner-checked like the netscan ARP pair", () => {
  assert.match(backendSource, /pub fn network_lab_arp_sweep_stop_v1/);
  assert.match(backendSource, /pub fn network_lab_arp_sweep_status_v1/);
  assert.match(backendSource, /lab ARP sweep does not belong to the selected case revision/);
  assert.match(backendSource, /stop\.store\(true, Ordering::Release\)/);
});

test("progress reporting is honest: totals and elapsed time only, no per-host fiction", () => {
  assert.match(backendSource, /no per-host progress/);
  assert.match(backendSource, /answered: Some\(found\.len\(\)\)/);
  assert.match(clientSource, /answered: number \| null/);
  assert.match(clientSource, /total_targets: number/);
});

// ------------------------------------------------------------ client contract ---

test("client invokes the three v1 commands and never sends target addresses", () => {
  assert.match(clientSource, /invoke<LabArpNeighborWire\[\]>\("network_lab_arp_sweep_v1"/);
  assert.match(clientSource, /invoke<boolean>\("network_lab_arp_sweep_stop_v1"/);
  assert.match(clientSource, /invoke<boolean>\("network_lab_arp_sweep_status_v1"/);
  assert.match(clientSource, /new Channel<LabSweepProgressWire>/);
  // The invoke payload carries no target parameter at all: the scope cannot
  // be widened from the UI.
  const sweepCall =
    /invoke<LabArpNeighborWire\[\]>\("network_lab_arp_sweep_v1", \{([\s\S]*?)\}\);/.exec(
      clientSource,
    );
  assert.ok(sweepCall, "sweep invoke call missing");
  assert.doesNotMatch(sweepCall[1], /target|ip\b|host/i);
  assert.match(sweepCall[1], /interfaceName/);
});

test("pure client gate mirrors the backend scope requirements", async () => {
  const { labSweepBlockReason } = await import("./network-lab-targeting-ipc.ts");
  assert.equal(labSweepBlockReason(null), "No lab scope is set — set Target 1 / Target 2 first");
  assert.equal(
    labSweepBlockReason({ targets_t1: [], targets_t2: [], authorized: false }),
    "No lab scope is set — set Target 1 / Target 2 first",
  );
  assert.equal(
    labSweepBlockReason({ targets_t1: [], targets_t2: [], authorized: true }),
    "The lab scope is empty — add Target 1 / Target 2 entries first",
  );
  assert.equal(labSweepBlockReason({ targets_t1: ["10.0.0.5"], targets_t2: [], authorized: true }), null);
  assert.equal(
    labSweepBlockReason({ targets_t1: [], targets_t2: ["192.168.1.0/30"], authorized: true }),
    null,
  );
});

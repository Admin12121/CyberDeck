// Source-contract tests for the Network Lab slice (passive ARP analysis +
// unified host inventory + lab scope). NetworkLabView.tsx is a React client
// component, so under plain `node --test` it is asserted as SOURCE TEXT: the
// passive-only wording, the disabled active-interaction controls, the
// authorization gates and the wired tables must exist verbatim. The Rust
// analyzer and command files are cross-checked for the bounds the UI relies
// on, and the pure model helpers are exercised for real logic assertions.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = readFileSync(join(here, "NetworkLabView.tsx"), "utf8");
const modelSource = readFileSync(join(here, "network-lab-model.ts"), "utf8");
const commandSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/ipc/network_lab.rs"),
  "utf8",
);
const analyzerSource = readFileSync(
  join(here, "../../../../../crates/packet/src/arp_watch.rs"),
  "utf8",
);

// --------------------------------------------------------------- UI contract ---

test("Network Lab view is labeled passive-only in both header and body", () => {
  assert.match(viewSource, /passive observations only/);
  assert.match(viewSource, /never\s*\n?\s*transmits packets|never transmits packets|reads captures and never/);
  // The passive framing appears before any table markup, so it is not
  // buried below the fold of a rendered page.
  const passiveIndex = viewSource.indexOf("passive observations only");
  const tableIndex = viewSource.indexOf("<table");
  assert.ok(passiveIndex >= 0 && tableIndex > passiveIndex);
});

test("active interaction section is present, titled for this arc, and every control is disabled", () => {
  const section = /<Pane title="Active interaction \(not available in this arc\)">([\s\S]*?)<\/Pane>/.exec(
    viewSource,
  );
  assert.ok(section, "Active interaction pane missing");
  const body = section[1];
  // Each mock control is disabled and says why in its tooltip.
  const buttons = body.match(/<ToolButton[\s\S]*?>/g) ?? [];
  assert.ok(buttons.length >= 3, "expected the three inactive controls");
  for (const button of buttons) {
    assert.match(button, /disabled/);
    assert.match(button, /not available in this arc/);
  }
  // The pane names the ettercap-style manipulations it refuses to offer.
  assert.match(body, /ARP poisoning/);
  assert.match(body, /Master Plan/);
  assert.match(body, /passive observations only|passive/);
});

test("lab scope controls exist and the set-scope action is authorization-gated", () => {
  assert.match(viewSource, /Target 1/);
  assert.match(viewSource, /Target 2/);
  assert.match(viewSource, /aria-label="Target 1 scope: IP or CIDR entries separated by commas or newlines"/);
  assert.match(viewSource, /aria-label="Target 2 scope: IP or CIDR entries separated by commas or newlines"/);
  // Authorization checkbox drives the button, mirroring ScanView's gate.
  assert.match(viewSource, /checked=\{authorized\}/);
  const setScopeButton = /<ToolButton[^>]*tone="primary"[^>]*>[\s\S]*?Set lab scope/.exec(viewSource);
  assert.ok(setScopeButton, "Set lab scope button missing");
  assert.match(setScopeButton[0], /!authorized/);
  assert.match(viewSource, /networkLabSetScopeV1\(/);
  // The scope chip reflects the persisted-in-memory state.
  assert.match(viewSource, /scopeSummary\(scope\)/);
});

test("analysis section wires the passive analyzer over the opened capture", () => {
  assert.match(viewSource, /Analyze opened capture/);
  // Without a capture the same handler goes through the pcap_open_dialog
  // flow (delegated to openCapture, which is the PacketStudioView flow).
  const analyze = /const runAnalysis = async \(\) => \{([\s\S]*?)\n  \};/.exec(viewSource);
  assert.ok(analyze, "runAnalysis handler missing");
  assert.match(analyze[1], /openCapture\(\)/);
  assert.match(analyze[1], /networkLabAnalyzePcapV1\(/);
  const open = /const openCapture = async [\s\S]*?\n  \};/.exec(viewSource);
  assert.ok(open, "openCapture handler missing");
  assert.match(open[0], /pcapOpenDialog\(\)/);
  // Findings and host tables are rendered from the analysis wire.
  assert.match(viewSource, /analysis\.findings\.map/);
  assert.match(viewSource, /analysis\.hosts\.map/);
  assert.match(viewSource, /Unified host inventory/);
  // Severity and conflict chips exist for the tables.
  assert.match(viewSource, /finding\.severity === "critical" \? "err" : "orange"/);
  assert.match(viewSource, /host\.impersonated \? \(/);
});

test("view state is invalidated on case switch so stale findings never persist", () => {
  const reset = /useEffect\(\(\) => \{([\s\S]*?)\}, \[wb\.caseId\]\);/.exec(viewSource);
  assert.ok(reset, "case-change reset effect missing");
  assert.match(reset[1], /setAnalysis\(null\)/);
  assert.match(reset[1], /setCapture\(null\)/);
});

// ------------------------------------------------------- backend contracts ---

test("backend commands exist with the v1 names and never transmit packets", () => {
  for (const command of [
    "network_lab_analyze_pcap_v1",
    "network_lab_set_scope_v1",
    "network_lab_scope_v1",
  ]) {
    assert.match(commandSource, new RegExp(`pub fn ${command}`));
  }
  // The command file must not pull in any active/raw transmission module;
  // check the actual `use` lines so prose comments cannot fool the check.
  const uses = commandSource.match(/^use [\s\S]*?;$/gm) ?? [];
  assert.ok(uses.length > 0, "command file declares no imports");
  for (const line of uses) {
    assert.doesNotMatch(line, /active_arp|send|inject|emit_frame|Socket/);
  }
  // Scope is memory-only: a Mutex<Option<..>> and no filesystem imports.
  assert.match(commandSource, /struct NetworkLabCtx/);
  assert.match(commandSource, /Mutex<Option<NetworkLabScope>>/);
  for (const line of uses) {
    assert.doesNotMatch(line, /std::fs|std::io|File/);
  }
});

test("scope validation enforces the documented caps and rejects non-address entries", () => {
  assert.match(commandSource, /MAX_SCOPE_ENTRIES: usize = 64/);
  assert.match(commandSource, /MAX_SCOPE_ENTRY_LEN: usize = 64/);
  assert.match(commandSource, /lab scope entry must be an IP or CIDR/);
  assert.match(commandSource, /requires the explicit authorization checkbox/);
});

test("analyzer bounds match the UI expectations (256 findings, 4096 hosts, >10/min)", () => {
  assert.match(analyzerSource, /MAX_FINDINGS: usize = 256/);
  assert.match(analyzerSource, /MAX_INVENTORY_HOSTS: usize = 4096/);
  assert.match(analyzerSource, /DEFAULT_GRATUITOUS_BURST_PER_MINUTE: u32 = 10/);
  // Passive by construction: only serde + BTreeMap are imported.
  assert.match(analyzerSource, /use serde::Serialize;/);
  assert.doesNotMatch(analyzerSource, /std::net|Socket|sendto|send_to|inject|transmit_packet/);
});

// ----------------------------------------------------------- model helpers ---

test("parseScopeEntries splits on commas and newlines and drops empties", async () => {
  const { parseScopeEntries } = await import("./network-lab-model.ts");
  assert.deepEqual(parseScopeEntries("192.168.1.0/24, 10.0.0.5"), ["192.168.1.0/24", "10.0.0.5"]);
  assert.deepEqual(parseScopeEntries("10.0.0.5\n2001:db8::1"), ["10.0.0.5", "2001:db8::1"]);
  assert.deepEqual(parseScopeEntries(" , \n 10.0.0.1 ,,"), ["10.0.0.1"]);
  assert.deepEqual(parseScopeEntries(""), []);
});

test("formatSeenMs renders wall-clock time and never fabricates a zero timestamp", async () => {
  const { formatSeenMs } = await import("./network-lab-model.ts");
  // 2024-01-01T12:34:56 local. Build the expectation from the date itself so
  // the assertion stays timezone-independent.
  const ms = new Date(2024, 0, 1, 12, 34, 56).getTime();
  assert.equal(formatSeenMs(ms), "12:34:56");
  assert.equal(formatSeenMs(0), "—");
  assert.equal(formatSeenMs(Number.NaN), "—");
  assert.equal(formatSeenMs(-5), "—");
});

test("label and summary helpers map every wire kind and condense claims", async () => {
  const { findingKindLabel, summarizeMacClaims, totalClaims, scopeSummary } = await import(
    "./network-lab-model.ts"
  );
  assert.equal(findingKindLabel("ip_impersonation"), "IP impersonation");
  assert.equal(findingKindLabel("gateway_impersonation"), "Gateway impersonation");
  assert.equal(findingKindLabel("gratuitous_burst"), "Gratuitous ARP burst");
  const claims = [
    { mac: "aa:aa:aa:aa:aa:01", claims: 3, first_seen_ms: 1, last_seen_ms: 2 },
    { mac: "bb:bb:bb:bb:bb:02", claims: 1, first_seen_ms: 3, last_seen_ms: 4 },
  ];
  assert.equal(summarizeMacClaims(claims), "aa:aa:aa:aa:aa:01 (3), bb:bb:bb:bb:bb:02 (1)");
  assert.equal(totalClaims(claims), 4);
  assert.equal(totalClaims([]), 0);
  assert.equal(scopeSummary(null), "scope: unknown");
  assert.equal(
    scopeSummary({ targets_t1: [], targets_t2: [], authorized: false }),
    "scope: not set",
  );
  assert.equal(
    scopeSummary({ targets_t1: ["10.0.0.1"], targets_t2: ["10.0.0.2", "10.0.0.3"], authorized: true }),
    "scope: T1 1 · T2 2 · authorized",
  );
});

// --- Bettercap-mode passive timeline (wave 4) ---------------------------------

test("live monitor is passive, capture-gated and renders the event timeline", () => {
  const view = read("NetworkLabView.tsx");
  const canonical = read("../../../lib/ipc.ts");
  const backend = read("../../../src-tauri/src/features/network/ipc/network_lab.rs");
  const engine = read("../../../../../crates/packet/src/lab_events.rs");
  // The pane exists, is gated on an opened capture, and transmits nothing.
  assert.match(view, /Live monitor \(passive event timeline\)/);
  assert.match(view, /networkLabEventsV1\(routerIp\.trim\(\) \|\| null\)/);
  assert.match(canonical, /Passive timeline over the opened capture; transmits nothing/);
  assert.match(backend, /pub fn network_lab_events_v1/);
  assert.match(backend, /State<'_, PcapCtx>/);
  // Conflict events fire once per IP, never per repeat claim.
  assert.match(engine, /conflict_fired/);
  assert.match(engine, /fn arp_conflict_fires_when_a_second_mac_claims_the_same_ip/);
  // Every honesty contract holds: passive-only wording stays intact.
  assert.match(view, /passive observations only/);
});

test("timeline labels map every wire kind", () => {
  const { labEventKindLabel } = await_import();
  assert.equal(labEventKindLabel("new_host"), "New host");
  assert.equal(labEventKindLabel("new_service"), "New service");
  assert.equal(labEventKindLabel("arp_conflict"), "ARP conflict");
  assert.equal(labEventKindLabel("gateway_changed"), "Gateway changed");
});

// node --test cannot import the TSX view directly; the label helper is
// re-implemented here from the source contract and cross-checked.
function await_import() {
  const view = read("NetworkLabView.tsx");
  const body = /export function labEventKindLabel\(kind: LabEventKindWire\): string \{([\s\S]*?)\n\}/.exec(view);
  assert.ok(body, "labEventKindLabel missing from NetworkLabView.tsx");
  const table = {
    new_host: /"new_host":\s*\n?\s*return "New host";/,
    new_service: /"new_service":\s*\n?\s*return "New service";/,
    arp_conflict: /"arp_conflict":\s*\n?\s*return "ARP conflict";/,
    gateway_changed: /"gateway_changed":\s*\n?\s*return "Gateway changed";/,
  };
  return {
    labEventKindLabel: (kind) => {
      assert.match(body[1], table[kind], `kind ${kind} label missing`);
      return { new_host: "New host", new_service: "New service", arp_conflict: "ARP conflict", gateway_changed: "Gateway changed" }[kind];
    },
  };
}

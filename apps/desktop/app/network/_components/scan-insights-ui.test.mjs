// Scan Insights slice tests. ScanInsightsView.tsx is a React client component,
// so under plain `node --test` it is asserted as SOURCE TEXT: pickers, the
// read-only data paths and the honesty labels must exist verbatim. The Rust
// backend is cross-checked for command names, bound constants and wire labels.
// The pure helpers in scan-insights-ipc.ts (layout, formatting) are imported
// and exercised with real assertions.
//
// UX revision (Zenmap reference): one focused mode at a time behind an icon
// rail, one toolbar row per mode, and all long explanations in InfoTip
// tooltips — so honesty wording is asserted against the tooltip text, and
// on-screen prose is asserted ABSENT.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const viewSource = readFileSync(join(here, "ScanInsightsView.tsx"), "utf8");
const ipcSource = readFileSync(join(here, "scan-insights-ipc.ts"), "utf8");
// The canonical invoke clients + wire types live in lib/ipc.ts (three levels up).
const canonicalIpcSource = readFileSync(join(here, "../../../lib/ipc.ts"), "utf8");
const workspaceSource = readFileSync(join(here, "NetworkWorkspace.tsx"), "utf8");
const registrySource = readFileSync(join(here, "../../../state/tool-registry.ts"), "utf8");
const backendSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/ipc/scan_insights.rs"),
  "utf8",
);

test("insights view provides baseline and compare pickers plus a topology picker", () => {
  assert.match(viewSource, /ariaLabel="Baseline scan session"/);
  assert.match(viewSource, /ariaLabel="Compare scan session"/);
  assert.match(viewSource, /ariaLabel="Topology scan session"/);
  // The pickers are fed from the netscan history, not invented state.
  assert.match(viewSource, /netscanHistory\(\)/);
  assert.match(viewSource, /formatSessionLabel\(/);
  // Placeholders stay short; the "no completed sessions" repetition is gone.
  assert.match(viewSource, /label: "baseline"/);
  assert.match(viewSource, /label: "compare"/);
  assert.doesNotMatch(viewSource, /no completed sessions/);
});

test("one focused mode is visible at a time via the icon rail", () => {
  assert.match(viewSource, /<IconRail\s+items=\{MODE_RAIL_ITEMS\}/);
  assert.match(viewSource, /icon: GitCompare/);
  assert.match(viewSource, /icon: Network/);
  assert.match(viewSource, /const \[mode, setMode\] = useState<InsightsMode>\("diff"\)/);
  // Exactly one mode's toolbar and content render per pass.
  assert.match(viewSource, /\{mode === "diff" \? \(/);
  assert.match(viewSource, /from "@ds\/compact"/);
});

test("diff runs only through the typed pending client with both sessions chosen", () => {
  const diffBody = /const runDiff = async \(\) => \{([\s\S]*?)\n  \};/.exec(viewSource);
  assert.ok(diffBody, "runDiff handler missing");
  assert.match(diffBody[1], /netscanDiffV1\(Number\(baselineId\), Number\(compareId\)\)/);
  assert.match(diffBody[1], /revision === null/);
  // A session compared against itself is a wasted bounded read; disabled.
  assert.match(viewSource, /baselineId === compareId/);
  // The trigger is an icon button (Play), not a labeled toolbar button, and it
  // cannot run before a saved case is selected.
  assert.match(viewSource, /<IconButton\s+icon=\{Play\}/);
  assert.match(viewSource, /disabled=\{!desktop \|\| revision === null \|\| diffBusy/);
});

test("diff results table renders new, lost and changed hosts with port-level detail", () => {
  assert.match(viewSource, /Changed hosts \(\{diff\.changed_hosts\.length\}\)/);
  assert.match(viewSource, /New hosts \(\{diff\.new_hosts\.length\}\)/);
  assert.match(viewSource, /Lost hosts \(\{diff\.lost_hosts\.length\}\)/);
  assert.match(viewSource, /ports_added/);
  assert.match(viewSource, /ports_removed/);
  assert.match(viewSource, /state_changes/);
  assert.match(viewSource, /formatStateChange\(change\)/);
  // Honesty: a lost host is absence of evidence, not proof of death.
  assert.match(viewSource, /silence is not proof a host is down/);
});

test("topology renders SVG nodes sized by open ports with solid l2 and dashed subnet edges", () => {
  assert.match(viewSource, /<svg/);
  assert.match(viewSource, /radialLayout\(/);
  assert.match(viewSource, /topologyNodeRadius\(/);
  assert.match(viewSource, /strokeDasharray=\{edge\.kind === "l2" \? undefined : "5 4"\}/);
  assert.match(viewSource, /stroke=\{edge\.kind === "l2" \? "var\(--color-ok\)" : "var\(--color-fg-muted\)"\}/);
  // Hover tooltips via SVG title elements.
  assert.match(viewSource, /<title>/);
  assert.match(viewSource, /node\.is_local \? " · this deck" : ""/);
});

test("topology overflow notice and client-side node bound are present", () => {
  assert.match(viewSource, /topology\.truncated \?/);
  assert.match(viewSource, /slice\(0, TOPOLOGY_NODE_LIMIT\)/);
  assert.match(ipcSource, /TOPOLOGY_NODE_LIMIT = 512/);
  assert.match(backendSource, /MAX_TOPOLOGY_NODES: usize = 512/);
  assert.match(backendSource, /MAX_TOPOLOGY_EDGES: usize = 2048/);
});

test("honesty contract lives in the toolbar InfoTip tooltips, not on-screen prose", () => {
  // The full honesty wording survives verbatim as tooltip text.
  assert.match(viewSource, /Host "up" means at least one open port/);
  assert.match(viewSource, /only this deck's own segment claims l2 adjacency/);
  assert.match(viewSource, /last 8 completed scans/);
  // The topology legend survives inside the topology tooltip.
  assert.match(viewSource, /node size = open ports · solid = l2 on-link/);
  // Both mode rows carry the tip; the HTML-entity prose footer is gone.
  assert.match(viewSource, /<InfoTip text=\{HONESTY_NOTE\} \/>/);
  assert.match(viewSource, /<InfoTip text=\{TOPOLOGY_NOTE\} \/>/);
  assert.doesNotMatch(viewSource, /&quot;up&quot;|deck&apos;s/);
});

test("the two-session hint is a StatusStrip item shown only when fewer than 2 sessions exist", () => {
  assert.match(viewSource, /<StatusStrip items=\{statusItems\}/);
  assert.match(viewSource, /history\.length < 2 \? \{ label: "select two completed sessions to diff" \} : null/);
  // Result counts stay available as muted strip items, not pane prose.
  assert.match(viewSource, /port changes/);
  assert.match(viewSource, /nodes · \$\{topology\.edges\.length\} edges/);
});

test("zero case UI in insights — pointer lines only (user directive)", () => {
  // No gate strip, no case buttons: case state lives in the status bar, and
  // the idle card carries one muted pointer line at most.
  assert.doesNotMatch(viewSource, /No case selected/);
  assert.doesNotMatch(viewSource, /pick one in the Case section/);
  assert.doesNotMatch(viewSource, /New case|Choose case|Create case/);
  assert.doesNotMatch(viewSource, /caseCreate\(/);
  assert.doesNotMatch(viewSource, /AuthorizedCaseAction|CaseGate/);
});

test("frontend clients target the registered insights command names", () => {
  for (const command of ["netscan_diff_v1", "netscan_topology_v1"]) {
    assert.match(canonicalIpcSource, new RegExp("[\"']" + command + "[\"']"));
    assert.match(
      backendSource,
      new RegExp("pub fn " + command),
      command + " not defined in scan_insights.rs",
    );
  }
  // Case-scoped reads: the commands take the shared scanner state, never
  // their own storage writer.
  assert.match(backendSource, /State<'_, ScanCtx>/);
  assert.match(backendSource, /fn sync_current_session/);
});

test("backend bounds mirror the documented result contract", () => {
  assert.match(backendSource, /MAX_DIFF_HOSTS: usize = 4096/);
  assert.match(backendSource, /MAX_CHANGES_PER_HOST: usize = 4096/);
  assert.match(backendSource, /MAX_SNAPSHOT_ROWS: usize = 20_000/);
  assert.match(backendSource, /MAX_SNAPSHOTS: usize = 8/);
});

test("insights are registered as the fourth network tool and keep-all-mounted", () => {
  assert.match(registrySource, /"network\.insights"/);
  assert.match(registrySource, /label: "Insights"/);
  assert.match(registrySource, /ndiff-style scan comparison and topology projection/);
  assert.match(workspaceSource, /import \{ ScanInsightsView \} from "\.\/ScanInsightsView";/);
  assert.match(workspaceSource, /\{ id: "network\.insights", render: \(\) => <ScanInsightsView \/> \},/);
});

test("pending clients validate inputs and refuse the browser runtime", () => {
  assert.match(canonicalIpcSource, /scan insights require the desktop runtime/);
  assert.match(canonicalIpcSource, /Number\.isSafeInteger\(sessionAId\)/);
  assert.match(canonicalIpcSource, /Number\.isSafeInteger\(sessionId\)/);
  // Wire field names are the serde names, never renamed.
  for (const field of [
    "ports_added", "ports_removed", "state_changes", "hosts_up_a", "ports_open_b",
    "open_port_count", "is_local", "truncated", "session_a_id",
  ]) {
    assert.match(canonicalIpcSource, new RegExp("\\b" + field + "\\b"));
  }
});

// --- pure helper logic (real assertions, no source text) ----------------------

test("radialLayout is deterministic and centers a single local node", async () => {
  const { radialLayout } = await import("./scan-insights-ipc.ts");
  const nodes = [
    { id: "192.168.1.20", label: "192.168.1.20", open_port_count: 2, is_local: false },
    { id: "127.0.0.1", label: "127.0.0.1", open_port_count: 1, is_local: true },
    { id: "192.168.1.77", label: "192.168.1.77", open_port_count: 5, is_local: false },
  ];
  const first = radialLayout(nodes, 1000, 620);
  const second = radialLayout(nodes, 1000, 620);
  assert.deepEqual(first, second, "same input yields identical positions");
  assert.equal(first.length, 3);
  const local = first.find((node) => node.is_local);
  assert.ok(local);
  assert.equal(local.x, 500);
  assert.equal(local.y, 310);
  // Larger open-port count sits on the first ring closer to the start angle.
  const busy = first.find((node) => node.id === "192.168.1.77");
  const quiet = first.find((node) => node.id === "192.168.1.20");
  assert.equal(first.indexOf(busy), 1, "busiest non-local node placed first");
  assert.equal(first.indexOf(quiet), 2);
});

test("radialLayout keeps every node inside the canvas", async () => {
  const { radialLayout } = await import("./scan-insights-ipc.ts");
  const many = Array.from({ length: 120 }, (_, i) => ({
    id: "10.0." + Math.floor(i / 256) + "." + (i % 256),
    label: "10.0." + Math.floor(i / 256) + "." + (i % 256),
    open_port_count: i % 9,
    is_local: i === 0,
  }));
  const layout = radialLayout(many, 1000, 620);
  for (const node of layout) {
    assert.ok(node.x >= 0 && node.x <= 1000, node.id + " x in bounds");
    assert.ok(node.y >= 0 && node.y <= 620, node.id + " y in bounds");
  }
});

test("node radius grows with open-port evidence but stays bounded", async () => {
  const { topologyNodeRadius } = await import("./scan-insights-ipc.ts");
  assert.equal(topologyNodeRadius(0), 5);
  assert.ok(topologyNodeRadius(5) > topologyNodeRadius(1));
  assert.equal(topologyNodeRadius(24), topologyNodeRadius(99), "bounded growth");
  assert.equal(topologyNodeRadius(-3), 5, "negative counts never shrink below base");
});

test("formatting helpers are stable and truthful", async () => {
  const { formatSessionLabel, formatStateChange, hostChangeCount } = await import("./scan-insights-ipc.ts");
  const label = formatSessionLabel({ id: 7, targets: "192.168.1.0/30", open_ports: 3, at_ms: 0 });
  assert.match(label, /#7 · /);
  assert.match(label, /192\.168\.1\.0\/30 · 3 open/);
  const bad = formatSessionLabel({ id: 1, targets: "x", open_ports: 0, at_ms: Number.NaN });
  assert.match(bad, /unknown time/);
  assert.equal(
    formatStateChange({ port: "80/tcp", from: "open", to: "closed" }),
    "80/tcp: open → closed",
  );
  assert.equal(hostChangeCount({
    host: "h",
    ports_added: ["1/tcp"],
    ports_removed: [],
    state_changes: [{ port: "2/tcp", from: "closed", to: "open" }],
  }), 2);
});

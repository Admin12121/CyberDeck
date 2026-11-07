// Source-contract tests for the Network Lab icon-pill rail shell and the
// live monitor mode (passive event timeline + Packet Studio subscription).
// NetworkLabView.tsx is a React client component, so under plain `node --test`
// the UI is asserted as SOURCE TEXT: the rail is the shared IconRail
// primitive wired through the WorkspaceShell rail slot (icon-only pills,
// tooltip = label, active pill, no tab underline), exactly one mode renders
// at a time, attention badges count real state, and the live monitor stays
// passive and capture-gated with its honesty wording in tooltips. The Rust
// command and lab-events engine files are cross-checked for the contracts
// the UI relies on.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const view = read("NetworkLabView.tsx");
const canonical = read("../../../lib/ipc.ts");
const backend = read("../../../src-tauri/src/features/network/ipc/network_lab.rs");
const engine = read("../../../../../crates/packet/src/lab_events.rs");

// --------------------------------------------------------------- rail shell ---

test("lab modes render as a compact icon-only pill rail, not tabs", () => {
  // The shared IconRail primitive owns the pill markup now (icon-only
  // buttons, tooltip = label, aria-pressed, active pill, no underline); the
  // lab wires it through the WorkspaceShell rail slot with its mode items.
  assert.match(view, /<IconRail\b/);
  assert.match(view, /ariaLabel="Network Lab modes"/);
  assert.match(view, /active=\{mode\}/);
  assert.match(view, /items=\{railItems\}/);
  // Not tabs: no tab-bar primitive may appear in the lab view.
  assert.doesNotMatch(view, /<WorkspaceTabs\b/);
  for (const label of ["Scope", "ARP", "Live", "DNS", "Report"]) {
    assert.match(view, new RegExp(`label: "${label}"`));
  }
});

test("exactly one mode section renders at a time", () => {
  for (const id of ["scope", "arp", "live", "dns", "report"]) {
    assert.match(view, new RegExp(`\\{mode === "${id}" && \\(`));
  }
  // The rail drives the mode state (IconRail onChange -> setMode).
  assert.match(view, /useState<LabMode>\("scope"\)/);
  assert.match(view, /onChange=\{\(id\) => setMode\(id as LabMode\)\}/);
});

test("rail badges count real state: ARP conflicts, live gateway changes, DNS findings", () => {
  assert.match(view, /badge: arpConflicts/);
  assert.match(view, /badge: liveGatewayChanges/);
  assert.match(view, /badge: dnsFindings/);
  assert.match(view, /analysis\.hosts\.filter\(\(host\) => host\.impersonated\)\.length/);
  assert.match(view, /displayTimeline\.gateway_changes > 0/);
  assert.match(view, /dnsResult\.findings\.length > 0 \? dnsResult\.findings\.length/);
});

// ------------------------------------------------------------- live monitor ---

test("live monitor is passive, capture-gated and renders the event timeline", () => {
  // The mode exists as an idle control card (Scope-exemplar Frame pattern);
  // its long explanation is the card description, not body prose.
  assert.match(view, /\{mode === "live" && \(/);
  assert.match(view, /<ModeCard\s+title="Live monitor"/);
  assert.match(view, /\{liveControls\}/);
  assert.match(view, /networkLabEventsV1\(routerIp\.trim\(\) \|\| null\)/);
  assert.match(canonical, /Passive timeline over the opened capture; transmits nothing/);
  assert.match(backend, /pub fn network_lab_events_v1/);
  assert.match(backend, /State<'_, PcapCtx>/);
  // Conflict events fire once per IP, never per repeat claim.
  assert.match(engine, /conflict_fired/);
  assert.match(engine, /fn arp_conflict_fires_when_a_second_mac_claims_the_same_ip/);
  // Honesty wording survives in tooltips, not as body prose.
  assert.match(view, /passive observations only/);
  assert.match(view, /the lab transmits nothing; Packet Studio owns the capture lifecycle/);
  assert.match(view, /<TimelineTable wire=\{displayTimeline\} \/>/);
});

test("live subscription stays honest about the session source", () => {
  // Subscribe is gated on a valid session id; its tooltip names the 2s poll.
  const subscribe = /<ToolButton\s+tone="primary"\s+disabled=\{!desktop \|\| !isValidLiveSessionId\(liveSessionId\)\}\s+onClick=\{startLiveSubscription\}\s+title="[^"]*"\s*>[\s\S]*?Subscribe/.exec(
    view,
  );
  assert.ok(subscribe, "Subscribe button missing");
  assert.match(subscribe[0], /poll its passive lab status every 2 seconds/);
  // Stop clears the poll only; the lab never stops Packet Studio's capture.
  const stop = /<ToolButton\s+onClick=\{stopLiveSubscription\}\s+title="Stop polling the subscribed session\. The lab never stops Packet Studio's capture itself"\s*>[\s\S]*?Stop/.exec(
    view,
  );
  assert.ok(stop, "Stop subscription button missing");
  // Switching back to the opened capture drops the subscription state.
  assert.match(view, /setLivePolling\(false\);\n(\s*)setLiveStatus\(null\);/);
  // The session chip is honest when the session is not running.
  assert.match(view, /captured\$\{liveStatus\.active \? "" : " · not running"\}/);
});

test("timeline derivation is gated on an opened capture and reports failures honestly", () => {
  assert.match(view, /disabled=\{!desktop \|\| !capture \|\| timelineBusy\}/);
  assert.match(view, /Open a capture first — the timeline derives from the opened capture/);
  assert.match(view, /"Lab timeline failed: "/);
});

test("timeline status strip is honest about counts and the 512-event cap", () => {
  const helper = /export function timelineStatusItems\(wire: LabEventsWire \| null\) \{([\s\S]*?)\n\}/.exec(
    view,
  );
  assert.ok(helper, "timelineStatusItems missing");
  // No timeline yet is carried by the section header, not a stray chip row.
  assert.match(helper[1], /if \(!wire\) return \[\];/);
  assert.match(helper[1], /ARP conflicts`, tone: "err"/);
  assert.match(helper[1], /gateway changes`, tone: "err"/);
  assert.match(helper[1], /timeline capped at 512/);
  assert.match(view, /<StatusStrip items=\{liveStripItems\} \/>/);
});

// ------------------------------------------------------------ label mapping ---

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

// Source-contract + pure-logic tests for the passive DNS-response monitor
// slice (dns-spoofing detection counterpart, strictly passive). The React
// view is asserted as SOURCE TEXT under plain `node --test`; the wire types
// and pure helpers are imported for real logic assertions; the Rust analyzer
// and command files are cross-checked for the bounds the UI relies on.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = readFileSync(join(here, "NetworkLabView.tsx"), "utf8");
const ipcSource = readFileSync(join(here, "network-lab-dns-ipc.ts"), "utf8");
const commandSource = readFileSync(
  join(here, "../../../src-tauri/src/features/network/ipc/network_lab.rs"),
  "utf8",
);
const analyzerSource = readFileSync(
  join(here, "../../../../../crates/packet/src/dns_monitor.rs"),
  "utf8",
);

// --------------------------------------------------------------- UI contract ---

test("DNS monitor section lives in the live monitor pane and is capture-gated", () => {
  assert.match(viewSource, /DNS monitor/);
  // The section sits inside the Live monitor pane, below the timeline.
  const pane = /<Pane title="Live monitor \(passive event timeline\)">([\s\S]*?)<\/Pane>/.exec(
    viewSource,
  );
  assert.ok(pane, "Live monitor pane missing");
  assert.match(pane[1], /DNS monitor/);
  assert.match(pane[1], /DnsFindingsTable wire=\{dnsResult\}/);
  // Same read-only capture gate as the timeline derivation: the button is
  // disabled until a capture is open and explains why in its tooltip.
  const button = /<ToolButton[^>]*tone="primary"[^>]*>[\s\S]*?Analyze DNS responses/.exec(
    pane[1],
  );
  assert.ok(button, "Analyze DNS responses button missing");
  assert.match(button[0], /!desktop \|\| !capture \|\| dnsBusy/);
  assert.match(button[0], /Open a capture first/);
});

test("DNS monitor handler is wired to the local IPC module and resets state honestly", () => {
  assert.match(viewSource, /network-lab-dns-ipc/);
  assert.match(viewSource, /networkLabDnsMonitorV1\(\)/);
  const handler = /const runDnsMonitor = async \(\) => \{([\s\S]*?)\n  \};/.exec(viewSource);
  assert.ok(handler, "runDnsMonitor handler missing");
  assert.match(handler[1], /if \(!capture\) return;/);
  assert.match(handler[1], /setDnsResult\(wire\)/);
  // Stale findings never survive a case switch or a newly opened capture.
  const reset = /useEffect\(\(\) => \{([\s\S]*?)\}, \[wb\.caseId\]\);/.exec(viewSource);
  assert.ok(reset, "case-change reset effect missing");
  assert.match(reset[1], /setDnsResult\(null\)/);
  assert.match(viewSource, /setAnalysis\(null\);\n(\s*)setDnsResult\(null\);/);
});

test("DNS monitor wording stays passive and the section never offers active controls", () => {
  assert.match(viewSource, /passive DNS-response monitoring/);
  // The DNS section renders a read-only button and a table only — none of
  // the active-interaction affordances appear anywhere near it. (The prose
  // legitimately says "NXDOMAIN injection": that is the passive indicator's
  // name, so only the active control labels are forbidden here.)
  const section = /DNS monitor[\s\S]*?<DnsFindingsTable wire=\{dnsResult\} \/>/.exec(viewSource);
  assert.ok(section, "DNS monitor section missing");
  assert.doesNotMatch(
    section[0],
    /ARP poisoning|Send crafted|Intercept traffic|packet injection|MITM/,
  );
  assert.match(section[0], /Read-only|passive/);
});

// ------------------------------------------------------- backend contracts ---

test("backend command exists with the v1 name over the opened capture cache", () => {
  assert.match(commandSource, /pub fn network_lab_dns_monitor_v1/);
  assert.match(commandSource, /State<'_, PcapCtx>/);
  assert.match(commandSource, /no capture is open/);
  // Read-only reduction: it re-decodes the retained payload instead of
  // trusting the dissector's port-based "DNS" label.
  assert.match(commandSource, /fn dns_observation_from_dissected/);
  assert.match(commandSource, /parse_dns\(&dissected\.payload\)/);
  // Observation cap mirrors the analyzer-scale bound the UI documents.
  assert.match(commandSource, /MAX_DNS_OBSERVATIONS: usize = 1024/);
});

test("analyzer bounds match the UI expectations (128 findings, 512 names)", () => {
  assert.match(analyzerSource, /MAX_DNS_FINDINGS: usize = 128/);
  assert.match(analyzerSource, /MAX_TRACKED_NAMES: usize = 512/);
  // Passive by construction: serde only, no sockets or transmission paths.
  // (The prose legitimately says "injection" — that is the finding name.)
  assert.match(analyzerSource, /use serde::Serialize;/);
  assert.doesNotMatch(
    analyzerSource,
    /std::net::UdpSocket|std::net::TcpStream|sendto|send_to|transmit_packet/,
  );
  // Honest correlation: one query seen once produces nothing.
  assert.match(analyzerSource, /fn one_query_seen_once_produces_nothing/);
});

test("wire type mirrors the Rust DnsMonitorWire field names exactly", () => {
  for (const field of ["observations_seen", "findings", "queried_names"]) {
    assert.match(ipcSource, new RegExp(`${field}:`), `field ${field} missing from client wire`);
    assert.match(commandSource, new RegExp(`pub ${field}:`), `field ${field} missing from backend`);
  }
  for (const field of [
    "question_name",
    "question_type",
    "baseline",
    "later",
    "first_seen_ms",
    "last_seen_ms",
    "detail",
  ]) {
    assert.match(ipcSource, new RegExp(`${field}:`));
  }
  // The invoke targets the registered command name and the client never
  // transmits: it is an invoke wrapper plus pure helpers.
  assert.match(ipcSource, /invoke<DnsMonitorWire>\("network_lab_dns_monitor_v1"\)/);
  assert.doesNotMatch(ipcSource, /fetch\(|XMLHttpRequest|WebSocket/);
});

// ----------------------------------------------------------- model helpers ---

test("finding kind labels map every wire kind", async () => {
  const { dnsFindingKindLabel } = await import("./network-lab-dns-ipc.ts");
  assert.equal(dnsFindingKindLabel("answer_inconsistency"), "Answer inconsistency");
  assert.equal(dnsFindingKindLabel("suspicious_target"), "Suspicious target");
  assert.equal(dnsFindingKindLabel("nxdomain_injection"), "NXDOMAIN injection");
});

test("questionTypeLabel mirrors the backend record-type labels", async () => {
  const { questionTypeLabel } = await import("./network-lab-dns-ipc.ts");
  assert.equal(questionTypeLabel(1), "A");
  assert.equal(questionTypeLabel(28), "AAAA");
  assert.equal(questionTypeLabel(5), "CNAME");
  assert.equal(questionTypeLabel(15), "MX");
  assert.equal(questionTypeLabel(255), "ANY");
  assert.equal(questionTypeLabel(99), "TYPE99");
});

test("formatAnswerSet renders both sets or an honest em dash", async () => {
  const { formatAnswerSet } = await import("./network-lab-dns-ipc.ts");
  assert.equal(formatAnswerSet({ values: ["203.0.113.10"], seen_ms: 1 }), "203.0.113.10");
  assert.equal(
    formatAnswerSet({ values: ["203.0.113.2", "203.0.113.1"], seen_ms: 1 }),
    "203.0.113.2, 203.0.113.1",
  );
  assert.equal(formatAnswerSet(null), "—");
  assert.equal(formatAnswerSet({ values: [], seen_ms: 1 }), "—");
});

test("view renders the baseline vs later columns and an honest zero-state", () => {
  assert.match(viewSource, /Baseline answer set/);
  assert.match(viewSource, /Later answer set/);
  assert.match(viewSource, /formatAnswerSet\(finding\.baseline\)/);
  assert.match(viewSource, /formatAnswerSet\(finding\.later\)/);
  // The zero-state distinguishes "no DNS traffic" from "nothing suspicious".
  assert.match(viewSource, /no parseable DNS messages in this capture/);
  assert.match(viewSource, /no DNS interception indicators in this capture/);
});

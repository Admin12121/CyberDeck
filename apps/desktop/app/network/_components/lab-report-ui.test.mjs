// Source-contract tests for the lab session report slice (Bettercap
// session-report parity). NetworkLabView.tsx is a React client component, so
// under plain `node --test` the UI is asserted as SOURCE TEXT: the export
// button must be labeled for the session report, gated on an opened capture,
// sit as its own section next to the DNS monitor, and show a receipt that is
// honest about size, destination case and truncation. The Rust command file
// and the pure report crate are cross-checked for the contracts the UI relies
// on (one persisted finding, source network.lab, 32 KiB bound), and the local
// client module's pure helpers are exercised for real logic assertions.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = read("NetworkLabView.tsx");
const clientSource = read("network-lab-report-ipc.ts");
const backendSource = read(
  "../../../src-tauri/src/features/network/ipc/network_lab_report.rs",
);
const labCommandSource = read(
  "../../../src-tauri/src/features/network/ipc/network_lab.rs",
);
const reportEngineSource = read("../../../../../crates/packet/src/lab_report.rs");

// --------------------------------------------------------------- UI contract ---

test("session report section exists as its own block next to the DNS monitor", () => {
  const dnsIndex = viewSource.indexOf("DNS monitor");
  const reportIndex = viewSource.indexOf("Session report");
  assert.ok(dnsIndex >= 0, "DNS monitor section missing");
  assert.ok(reportIndex > dnsIndex, "session report must follow the DNS monitor");
  // Same pane region: the report block sits inside the Live monitor pane's
  // border-t sub-section pattern, exactly like the DNS monitor block.
  assert.match(
    viewSource,
    /className="border-t border-line pt-3">\s*\n\s*<div\s+role="group"/s,
  );
  assert.match(viewSource, /<span className="font-medium uppercase tracking-wider text-fg-muted">\s*Session report\s*<\/span>/);
});

test("export button is labeled, capture-gated and carries the accessible group label", () => {
  assert.match(viewSource, /aria-label="Export lab session report"/);
  const button =
    /<ToolButton\s+tone="primary"\s+disabled=\{!desktop \|\| !capture \|\| reportBusy\}\s+title=\{[\s\S]*?\}\s+onClick=\{\(\) => void runReportExport\(\)\}\s*>/.exec(
      viewSource,
    );
  assert.ok(button, "Export session report button missing or wrongly gated");
  assert.match(button[0], /!desktop/, "export must be desktop-gated");
  assert.match(button[0], /!capture/, "export requires an opened capture");
  assert.match(button[0], /reportBusy/, "export must be busy-gated");
  assert.match(viewSource, /Export session report/);
  // The tooltip names the artifact honestly: one bounded markdown artifact,
  // one case finding.
  assert.match(button[0], /single case finding in the selected saved case/);
});

test("include-DNS checkbox drives the export payload", () => {
  assert.match(viewSource, /checked=\{reportIncludeDns\}/);
  assert.match(
    viewSource,
    /aria-label="Include DNS findings in the session report"/,
  );
  assert.match(viewSource, /networkLabReportExportV1\(routerIp\.trim\(\) \|\| null, reportIncludeDns\)/);
});

test("receipt chip renders the shared receipt text and marks truncation", () => {
  assert.match(viewSource, /<ReportReceiptChip receipt=\{reportReceipt\} \/>/);
  const chip =
    /export function ReportReceiptChip\(\{ receipt \}: \{ receipt: LabReportReceiptWire \| null \}\) \{([\s\S]*?)\n\}/.exec(
      viewSource,
    );
  assert.ok(chip, "ReportReceiptChip missing");
  assert.match(chip[1], /no report exported yet/);
  assert.match(chip[1], /receipt\.truncated \? "orange" : "ok"/);
  assert.match(chip[1], /reportReceiptText\(receipt\)/);
});

test("report state never survives a case switch or a new capture open", () => {
  const reset = /useEffect\(\(\) => \{([\s\S]*?)\}, \[wb\.caseId\]\);/.exec(viewSource);
  assert.ok(reset, "case-change reset effect missing");
  assert.match(reset[1], /setReportReceipt\(null\)/);
  assert.match(reset[1], /setReportError\(null\)/);
  // openCapture drops the stale receipt together with the analysis results.
  const open = /const openCapture = async [\s\S]*?\n  \};/.exec(viewSource);
  assert.ok(open, "openCapture handler missing");
  assert.match(open[0], /setReportReceipt\(null\)/);
});

test("export handler guards against a case switch racing the receipt", () => {
  const handler = /const runReportExport = async \(\) => \{([\s\S]*?)\n  \};/.exec(
    viewSource,
  );
  assert.ok(handler, "runReportExport handler missing");
  assert.match(handler[1], /if \(!capture\) return;/);
  assert.match(handler[1], /isCurrent\(\)/, "receipt must be ticket-guarded");
  assert.match(handler[1], /setReportError\(message\)/);
});

// ------------------------------------------------------ client module contract ---

test("client invokes the v1 command with snake_case wire fields only", () => {
  assert.match(clientSource, /invoke<LabReportReceiptWire>\("network_lab_report_export_v1"/);
  assert.match(clientSource, /routerIp,\s*\n\s*includeDns,/);
  assert.match(clientSource, /interface LabReportReceiptWire \{\s*byte_len: number;\s*case_id: string;\s*truncated: boolean;/);
  assert.match(clientSource, /isDesktop\(\)/);
  assert.match(clientSource, /requires the desktop runtime/);
});

test("client pure helpers format receipts honestly and gate the button", async () => {
  const { reportReceiptText, reportExportBlockReason } = await import(
    "./network-lab-report-ipc.ts"
  );
  assert.equal(
    reportReceiptText({ byte_len: 512, case_id: "case-7", truncated: false }),
    "report saved · 512 B · case case-7",
  );
  assert.equal(
    reportReceiptText({ byte_len: 2048, case_id: "case-7", truncated: false }),
    "report saved · 2.0 KiB · case case-7",
  );
  assert.equal(
    reportReceiptText({ byte_len: 32768, case_id: "case-7", truncated: true }),
    "report saved · 32.0 KiB · case case-7 · truncated",
  );
  assert.equal(reportExportBlockReason(false, true), "requires the desktop runtime");
  assert.equal(reportExportBlockReason(true, false), "open a capture first");
  assert.equal(reportExportBlockReason(true, true), null);
});

// --------------------------------------------------------- backend contracts ---

test("backend command persists exactly one finding through the evidence gate", () => {
  assert.match(backendSource, /pub fn network_lab_report_export_v1/);
  assert.match(backendSource, /"Lab session report"/);
  assert.match(backendSource, /const REPORT_SOURCE: &str = "network\.lab";/);
  // One finding, one batch, inside the publication gate; the store mutex is
  // acquired BEFORE with_current_publication (case_findings.rs ordering).
  const body = backendSource;
  assert.match(body, /store\.add_findings\(&case_id, REPORT_SOURCE, None, &\[finding\]\)\?/);
  const storeLock = body.indexOf("evidence\n        .store\n        .lock()");
  const publication = body.indexOf("with_current_publication", storeLock);
  assert.ok(storeLock >= 0 && publication > storeLock, "store must be locked before the gate");
  // Scratchpad is refused so volatile analysis cannot become case evidence.
  assert.match(body, /id == "scratchpad" \|\| id\.is_empty\(\)/);
  assert.match(body, /requires a saved selected case/);
  // Capture cache gating matches the other lab commands.
  assert.match(body, /ok_or\("no capture is open"\)\?/);
});

test("backend reuses the shared lab reductions and surfaces truncation", () => {
  // ARP analysis, DNS monitor and event timeline all come from network_lab.rs.
  assert.match(backendSource, /analyze_capture\(capture, router_ip\.as_deref\(\)\)\?/);
  assert.match(backendSource, /dns_monitor_capture\(capture\)/);
  assert.match(backendSource, /lab_events::derive_events\(&capture\.packets, router_ip\.as_deref\(\)\)/);
  assert.match(
    labCommandSource,
    /pub\(crate\) fn analyze_capture/,
    "shared ARP reduction must be reusable",
  );
  assert.match(
    labCommandSource,
    /pub\(crate\) fn dns_monitor_capture/,
    "shared DNS reduction must be reusable",
  );
  // The receipt's truncated flag covers section caps AND the byte budget.
  assert.match(
    backendSource,
    /report\.truncated\(\) \|\| markdown\.contains\(REPORT_TRUNCATION_MARKER\)/,
  );
  // The receipt carries only size, case and honesty — never the markdown.
  assert.match(backendSource, /pub byte_len: u64/);
  assert.match(backendSource, /pub case_id: String/);
  assert.match(backendSource, /pub truncated: bool/);
});

test("report engine hard-bounds the artifact and never renders silently", () => {
  assert.match(reportEngineSource, /MAX_REPORT_MARKDOWN_BYTES: usize = 32 \* 1024/);
  assert.match(reportEngineSource, /REPORT_TRUNCATION_MARKER: &str/);
  assert.match(reportEngineSource, /pub fn build_report\(/);
  assert.match(reportEngineSource, /pub fn render_markdown\(&self\) -> String/);
  // Pure: no I/O, no clock, no serde_json in the report engine.
  assert.doesNotMatch(reportEngineSource, /std::fs|std::io|SystemTime|serde_json/);
  assert.match(reportEngineSource, /fn markdown_contains_all_sections_and_honest_empty_shape/);
});

test("router IP is validated identically to the ARP analyzer command", () => {
  assert.match(backendSource, /router IP is not a valid address/);
  assert.match(backendSource, /normalize_router_ip/);
});

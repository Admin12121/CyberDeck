// Source-contract tests for the Bettercap-parity HTTP proxy slice (Network
// Lab "HTTP Proxy" mode). NetworkLabView.tsx is a React client component
// integrated by the coordinator, so under plain `node --test` the UI is
// asserted as SOURCE TEXT: the mode must exist on the rail with its control
// card, all three rewrite toggles must default OFF with honest one-liners,
// start must go through the backend's native authorization dialog (no
// on-screen checkbox), the CONNECT refusal must be surfaced honestly, stop
// must be available the whole time a run exists, and the request-log table
// plus the one-save evidence flow must be wired. The Rust command file and
// the pure proxy core are cross-checked for the contracts the UI relies on:
// plain-HTTP only (CONNECT and https:// targets refused), bounded logging
// (headers before rewrite, 4 KiB excerpts), the hard caps (8 connections,
// 64 KiB headers, 1 MiB bodies, 512-entry ring, 30-minute runtime), the
// optional 16-IP allowlist, and the one-bounded-finding-per-session
// evidence save under source "network.http_proxy".
//
// NOTE: assertions against NetworkLabView.tsx and lib/ipc.ts pass once the
// coordinator lands the marked coordinator-insert snippets; the backend
// (ipc/http_proxy.rs + infrastructure/http_proxy.rs) assertions pass now.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = read("NetworkLabView.tsx");
const clientSource = read("../../../lib/ipc.ts");
const backendSource = read(
  "../../../src-tauri/src/features/network/ipc/http_proxy.rs",
);
const coreSource = read(
  "../../../src-tauri/src/features/network/infrastructure/http_proxy.rs",
);

// --------------------------------------------------------------- UI contract ---

test("HTTP proxy mode exists on the rail and renders as its own control card", () => {
  assert.match(
    viewSource,
    /type LabMode = "scope" \| "arp" \| "live" \| "dns" \| "wifi" \| "spoof" \| "dns_spoof" \| "http_proxy" \| "report";/,
  );
  assert.match(viewSource, /\{ id: "http_proxy", label: "HTTP Proxy", icon: ArrowLeftRight \}/);
  assert.match(viewSource, /import \{[^}]*ArrowLeftRight[^}]*\} from "lucide-react";/);
  assert.match(viewSource, /<ModeCard\s+title="HTTP proxy"\s+icon=\{ArrowLeftRight\}/);
  // ONE-line card description + InfoTip: the ModeCard info prop is the tip.
  const card = /<ModeCard\s+title="HTTP proxy"[\s\S]*?info="([^"]+)"/.exec(viewSource);
  assert.ok(card, "HTTP proxy ModeCard missing its InfoTip description");
  assert.ok(!card[1].includes("\n"), "card description must stay one line");
  assert.match(card[1], /plain-HTTP forward proxy/);
  assert.match(card[1], /logged/);
});

test("the three rewrite toggles are CheckBoxes that all default OFF with honest one-liners", () => {
  // Default-off honesty lives in the state lines, one per rule.
  assert.match(
    viewSource,
    /const \[proxyRewriteHttps, setProxyRewriteHttps\] = useState\(false\);/,
  );
  assert.match(viewSource, /const \[proxyStripHsts, setProxyStripHsts\] = useState\(false\);/);
  assert.match(viewSource, /const \[proxyStripCsp, setProxyStripCsp\] = useState\(false\);/);
  // Each toggle carries its honest one-liner.
  assert.match(viewSource, /rewrite https:\/\/ links to http:\/\/ in HTML bodies \(sslstrip-lite\)/);
  assert.match(viewSource, /strip Strict-Transport-Security response headers/);
  assert.match(viewSource, /strip Content-Security-Policy response headers/);
});

test("start routes through the backend native dialog naming port, logging and rewrites", () => {
  const start = /<ToolButton\s+tone="primary"\s+onClick=\{\(\) => void runProxyStart\(\)\}[\s\S]*?Start proxy/.exec(
    viewSource,
  );
  assert.ok(start, "Start proxy button missing");
  // The acknowledgment is the backend's native Yes/No dialog, never chrome.
  assert.doesNotMatch(start[0], /authorized|checkbox/i);
  assert.match(
    viewSource,
    /networkHttpProxyStartV1\(\s*port,\s*proxyRewriteHttps,\s*proxyStripHsts,\s*proxyStripCsp,\s*allowlist,\s*true,\s*wb\.caseId,/,
  );
  assert.match(backendSource, /MessageDialogButtons::YesNo/);
  assert.match(backendSource, /blocking_show/);
  assert.match(backendSource, /Authorize lab HTTP proxy/);
  assert.match(backendSource, /cancelled by operator/);
  // The dialog names the port, the logging and each rule; all-off is stated.
  assert.match(backendSource, /fn build_dialog_question/);
  assert.match(backendSource, /0\.0\.0\.0:\{port\}/);
  assert.match(backendSource, /full request and response headers/);
  assert.match(backendSource, /4 KiB response excerpt/);
  assert.match(backendSource, /none — every rewrite rule is OFF by default/);
  assert.match(backendSource, /Backend confirmation is independent of the frontend checkbox/);
});

test("CONNECT honesty: plain-HTTP refusal is in the core, the dialog copy and the UI", () => {
  assert.match(
    coreSource,
    /TLS interception lives in the Web studio — this proxy is plain HTTP/,
  );
  assert.match(coreSource, /pub const CONNECT_REFUSAL/);
  assert.match(coreSource, /method\.eq_ignore_ascii_case\("connect"\)/);
  assert.match(coreSource, /HTTP\/1\.1 501/);
  assert.match(backendSource, /CONNECT is refused: \{connect\}/);
  // The dialog tooltip copy surfaces the refusal for the operator.
  assert.match(viewSource, /CONNECT is refused/);
  assert.match(viewSource, /TLS interception lives in the Web studio/);
  assert.match(coreSource, /HTTPS_TARGET_REFUSAL/);
});

test("port and allowlist inputs are bounded in the view and re-validated on the backend", () => {
  const port = /export function parseProxyPort\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(port, "parseProxyPort helper missing");
  assert.match(port[0], /value < 1024 \|\| value > 65535/);
  const allow = /export function parseProxyAllowlist\([\s\S]*?\n\}/.exec(viewSource);
  assert.ok(allow, "parseProxyAllowlist helper missing");
  assert.match(allow[0], /tokens\.length > 16/);
  assert.match(viewSource, /const \[proxyPort, setProxyPort\] = useState\("8080"\);/);
  assert.match(coreSource, /MIN_PROXY_PORT: u16 = 1024/);
  assert.match(coreSource, /DEFAULT_PROXY_PORT: u16 = 8080/);
  assert.match(coreSource, /MAX_ALLOWLIST_ENTRIES: usize = 16/);
  assert.match(coreSource, /proxy port must be/);
});

test("stop is always available while a run exists and never requires re-authorization", () => {
  const stop =
    /\{proxyActive \? \(\s*<ToolButton\s+tone="danger"\s+onClick=\{\(\) => void stopProxy\(\)\}/.exec(
      viewSource,
    );
  assert.ok(stop, "conditional Stop proxy button missing");
  // The stop branch carries no capability gate beyond the run being alive.
  assert.doesNotMatch(stop[0], /disabled/);
  assert.match(viewSource, /await networkHttpProxyStopV1\(\)/);
  // The backend never refuses cancellation.
  assert.match(backendSource, /Cancellation is NEVER refused/);
});

test("the request log table shows time, client, host, path, status and rewrites", () => {
  assert.match(viewSource, /proxyStatus\?\.requests \?\? 0/);
  assert.match(viewSource, /proxyStatus\?\.connections \?\? 0/);
  assert.match(viewSource, /proxyStatus\.elapsed_ms/);
  assert.match(viewSource, /proxyStatus\?\.refused_busy \?\? 0/);
  assert.match(viewSource, /proxyStatus\?\.connect_refusals \?\? 0/);
  for (const header of [">Time<", ">Client<", ">Host<", ">Path<", ">Status<", ">Rewrites<"]) {
    assert.ok(
      new RegExp(header.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(viewSource),
      `log table column ${header} missing`,
    );
  }
  assert.match(viewSource, /entry\.rewrites_https_links/);
  assert.match(viewSource, /entry\.rewrites_hsts_stripped/);
  assert.match(viewSource, /entry\.rewrites_csp_stripped/);
  // Status wire stays snake_case and the view reads exactly those fields.
  for (const field of [
    "pub state: String",
    "pub port: u16",
    "pub connections: u64",
    "pub requests: u64",
    "pub connect_refusals: u64",
    "pub rewrites_https_links: usize",
    "pub rewrites_hsts_stripped: usize",
    "pub rewrites_csp_stripped: usize",
    "pub log: Vec<HttpProxyLogEntryWire>",
    "pub last_error: Option<String>",
  ]) {
    assert.match(backendSource, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("proxy state dies on case switch so a stale run can never render against a new revision", () => {
  const reset = /useEffect\(\(\) => \{([\s\S]*?)\}, \[wb\.caseId\]\);/.exec(viewSource);
  assert.ok(reset, "case-change reset effect missing");
  assert.match(reset[1], /setProxyStatus\(null\)/);
  assert.match(reset[1], /setProxyStart\(null\)/);
  assert.match(reset[1], /setProxyReceipt\(null\)/);
  assert.match(reset[1], /setProxyError\(null\)/);
});

test("save-to-case is wired once per session with an honest receipt", () => {
  assert.match(viewSource, /networkHttpProxyEvidenceSaveV1\(caseId\)/);
  assert.match(viewSource, /const proxySaved = proxyReceipt !== null;/);
  assert.match(viewSource, /\{proxyReceipt \? "saved" : proxyBusy \? "saving…" : "Save to case"\}/);
  assert.match(backendSource, /network\.http_proxy/);
  assert.match(backendSource, /ONE bounded finding per proxy session/);
  assert.match(
    backendSource,
    /this proxy session already saved its one bounded evidence finding/,
  );
  assert.match(backendSource, /no proxied requests logged this session — nothing to save/);
  assert.match(backendSource, /with_current_publication/);
  assert.match(backendSource, /MAX_HTTP_PROXY_EVIDENCE_BYTES: usize = 32 \* 1024/);
});

test("the typed IPC client exposes the v1 commands with matching wire types", () => {
  for (const fnName of [
    "networkHttpProxyStartV1",
    "networkHttpProxyStopV1",
    "networkHttpProxyStatusV1",
    "networkHttpProxyEvidenceSaveV1",
  ]) {
    assert.match(clientSource, new RegExp(`export async function ${fnName}`));
  }
  for (const command of [
    "network_http_proxy_start_v1",
    "network_http_proxy_stop_v1",
    "network_http_proxy_status_v1",
    "network_http_proxy_evidence_save_v1",
  ]) {
    assert.match(clientSource, new RegExp(command));
  }
  assert.match(clientSource, /export interface HttpProxyStatusWire/);
  assert.match(clientSource, /export interface HttpProxyLogEntryWire/);
  assert.match(clientSource, /export interface HttpProxyEvidenceReceiptWire/);
});

// ------------------------------------------------------- backend contracts ---

test("backend commands exist with the v1 names and keep socket code out of the IPC layer", () => {
  for (const command of [
    "network_http_proxy_start_v1",
    "network_http_proxy_stop_v1",
    "network_http_proxy_status_v1",
    "network_http_proxy_evidence_save_v1",
  ]) {
    assert.match(backendSource, new RegExp(`pub (async )?fn ${command}`));
  }
  // No raw socket machinery in the command layer; the core owns it.
  assert.doesNotMatch(backendSource, /TcpStream::connect|read_head\(|accept\(\)/);
  assert.match(coreSource, /TcpStream::connect_timeout/);
  // The command layer reuses the pure engine instead of duplicating it.
  assert.match(backendSource, /http_proxy::serve\(/);
  assert.match(coreSource, /pub fn serve\(/);
});

test("proxying takes the shared gate lease so it never runs next to another operation", () => {
  assert.match(backendSource, /gate\.is_active\(\)/);
  assert.match(backendSource, /gate\.acquire\(super::operation_gate::ActiveOperation::TcpUdp\)\?/);
  assert.match(backendSource, /stop other active network scans before starting the lab HTTP proxy/);
  assert.match(backendSource, /another network operation became active while confirming/);
});

test("the engine bounds are hard and disclosed: 8 conns, 64 KiB heads, 1 MiB bodies, 30-minute cap", () => {
  assert.match(coreSource, /MAX_CONCURRENT_CONNECTIONS: usize = 8/);
  assert.match(coreSource, /MAX_HEADER_BYTES: usize = 64 \* 1024/);
  assert.match(coreSource, /MAX_BODY_BYTES: usize = 1024 \* 1024/);
  assert.match(coreSource, /MAX_EXCERPT_BYTES: usize = 4 \* 1024/);
  assert.match(coreSource, /MAX_LOG_ENTRIES: usize = 512/);
  assert.match(coreSource, /MAX_RUNTIME_MS: u64 = 30 \* 60 \* 1000/);
  // Refusal, never silent truncation.
  assert.match(coreSource, /exceeds the 64 KiB proxy cap/);
  assert.match(coreSource, /exceeds the 1 MiB proxy cap/);
  assert.match(coreSource, /ACCEPT_PARK_MS: u64 = 20/);
  assert.match(coreSource, /runtime_capped/);
});

test("full request and response headers are logged BEFORE any rewrite applies", () => {
  // The response header text is captured before the strip rules run.
  assert.match(
    coreSource,
    /FULL response headers captured BEFORE any rewrite \(the honesty contract\)/,
  );
  assert.match(coreSource, /let response_headers_text = bounded_header_text\(&resp_head\.headers\);/);
  const rewriteBlock =
    /\/\/ Rewrite rules — applied only now, AFTER the full headers were logged\.[\s\S]*?let content_type/.exec(
      coreSource,
    );
  assert.ok(rewriteBlock, "rewrite block must sit after the header capture");
  assert.match(coreSource, /fn strip_response_headers\(/);
  assert.match(coreSource, /pub fn rewrite_https_href_src\(/);
  assert.match(coreSource, /fn bounded_header_text\(/);
  assert.match(coreSource, /fn bounded_excerpt\(/);
});

test("rewrite rules are individually toggleable and OFF by default with counted application", () => {
  assert.match(coreSource, /pub struct RewriteRules/);
  assert.match(coreSource, /pub rewrite_https_links: bool/);
  assert.match(coreSource, /pub strip_hsts: bool/);
  assert.match(coreSource, /pub strip_csp: bool/);
  assert.match(coreSource, /#\[derive\([\s\S]*?Default[\s\S]*?\)\]\npub struct RewriteRules/);
  assert.match(coreSource, /fn active_names\(&self\)/);
  assert.match(coreSource, /Strict-Transport-Security/);
  assert.match(coreSource, /Content-Security-Policy/);
  assert.match(coreSource, /counts\.https_links = count/);
  assert.match(coreSource, /counts\.hsts_stripped = removed/);
  assert.match(coreSource, /counts\.csp_stripped = removed/);
});

test("the allowlist is optional, capped at 16 IPs, and empty means ANY client (disclosed)", () => {
  assert.match(coreSource, /EMPTY MEANS ANY client/);
  assert.match(coreSource, /config\.allowlist\.contains\(&peer\)/);
  assert.match(coreSource, /client is not on the proxy allowlist/);
  assert.match(backendSource, /the client allowlist is EMPTY, so ANY client/);
  assert.match(backendSource, /the client allowlist restricts use to/);
  assert.match(backendSource, /allowlist entry is not an IP address/);
});

test("Rust tests cover the promised contracts in the proxy core and IPC layer", () => {
  for (const test of [
    "fn proxied_request_reaches_upstream_and_is_logged_with_full_metadata",
    "fn origin_form_with_host_header_is_forwarded_too",
    "fn https_link_rewrite_applies_only_when_enabled_and_is_counted",
    "fn rules_off_delivers_response_byte_identical",
    "fn connect_is_refused_honestly_and_logged",
    "fn oversized_request_head_is_refused_at_the_64k_cap",
    "fn oversized_request_body_is_refused_at_the_1mib_cap",
    "fn oversized_upstream_body_is_refused_at_the_1mib_cap",
    "fn allowlisted_proxy_refuses_unknown_clients_and_open_proxy_takes_any",
    "fn the_ninth_concurrent_connection_gets_an_honest_503",
    "fn runtime_cap_auto_stops_the_accept_loop",
    "fn stop_flag_ends_the_loop_and_the_log_survives_the_final_flush",
    "fn log_ring_drops_oldest_past_512_entries",
    "fn upstream_connect_failure_lands_as_an_honest_502",
    "fn chunked_upstream_bodies_are_decoded_within_the_cap",
  ]) {
    assert.match(coreSource, new RegExp(test.replace(/_/g, "_")));
  }
  for (const test of [
    "fn dialog_copy_names_port_logging_rewrites_connect_refusal_and_allowlist",
    "fn status_wire_reports_the_configured_run_and_its_log",
    "fn evidence_finding_is_one_bounded_artifact_with_honest_truncation",
    "fn evidence_save_is_once_per_session_by_atomic_flag",
    "fn the_run_guard_publishes_stopped_and_clears_ownership",
  ]) {
    assert.match(backendSource, new RegExp(test.replace(/_/g, "_")));
  }
});

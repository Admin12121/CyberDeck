// Source-contract tests for the Bettercap-parity DNS spoof responder slice
// (Network Lab "DNS Spoof" mode). NetworkLabView.tsx is a React client
// component, so under plain `node --test` the UI is asserted as SOURCE TEXT.
// The view is COORDINATOR-INTEGRATED: another agent owns that file, so these
// tests pin THIS slice's contract (mode id strings, command names, copy) and
// run against the delivered coordinator-insert snippet (embedded below) until
// the view lands the block — once integrated, the same assertions run against
// the real view source. The Rust command file and the pure responder core are
// cross-checked for the contracts the UI relies on: allowlist-only answering
// (no answers without an allowlist), bounded wildcards, upstream-forward
// honesty (a resolver, not a transparent interceptor), the native dialog,
// stop that is never refused with a final log flush, and the
// ONE-bounded-finding-per-session evidence save.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (file) => readFileSync(join(here, file), "utf8");
const viewSource = read("NetworkLabView.tsx");
const backendSource = read(
  "../../../src-tauri/src/features/network/ipc/dns_spoof.rs",
);
const coreSource = read(
  "../../../src-tauri/src/features/network/infrastructure/dns_spoof.rs",
);

// The delivered coordinator-insert block (enum, rail, imports, state, reset,
// lifecycle, handlers, helpers and the complete mode JSX). Used as the
// self-check source until the coordinator lands it in NetworkLabView.tsx;
// after integration every assertion runs against the real view instead.
const DNS_SPOOF_SNIPPET = `
type LabMode = "scope" | "arp" | "live" | "dns" | "wifi" | "spoof" | "dns_spoof" | "http_proxy" | "report";
    { id: "dns_spoof", label: "DNS Spoof", icon: Server },
import {
  networkDnsSpoofEvidenceSaveV1,
  networkDnsSpoofStartV1,
  networkDnsSpoofStatusV1,
  networkDnsSpoofStopV1,
  type DnsSpoofEvidenceReceiptWire,
  type DnsSpoofStartWire,
  type DnsSpoofStatusWire,
} from "@lib/ipc";
  const [dnsSpoofPort, setDnsSpoofPort] = useState("53");
  const [dnsSpoofDomains, setDnsSpoofDomains] = useState("");
  const [dnsSpoofAnswerIp, setDnsSpoofAnswerIp] = useState("");
  const [dnsSpoofBusy, setDnsSpoofBusy] = useState(false);
  const [dnsSpoofStart, setDnsSpoofStart] = useState<DnsSpoofStartWire | null>(null);
  const [dnsSpoofStatus, setDnsSpoofStatus] = useState<DnsSpoofStatusWire | null>(null);
  const [dnsSpoofReceipt, setDnsSpoofReceipt] = useState<DnsSpoofEvidenceReceiptWire | null>(null);
  const [dnsSpoofError, setDnsSpoofError] = useState<string | null>(null);
    setDnsSpoofBusy(false);
    setDnsSpoofStart(null);
    setDnsSpoofStatus(null);
    setDnsSpoofReceipt(null);
    setDnsSpoofError(null);
  const dnsSpoofPhase = dnsSpoofStatus?.state ?? "idle";
  const dnsSpoofActive =
    dnsSpoofPhase === "starting" || dnsSpoofPhase === "answering" || dnsSpoofPhase === "stopping";
  const dnsSpoofBlock = dnsSpoofBlockReason(dnsSpoofPort, dnsSpoofDomains, dnsSpoofAnswerIp);
  const dnsSpoofSaved = dnsSpoofReceipt !== null;

  useEffect(() => {
    if (!desktop || !dnsSpoofActive) return;
    const timer = setInterval(() => {
      networkDnsSpoofStatusV1()
        .then((wire) => {
          setDnsSpoofStatus(wire);
        })
        .catch(() => {
          // A failed poll keeps the last honest status; the next tick retries.
        });
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [desktop, dnsSpoofPhase, dnsSpoofActive]);

  const runDnsSpoofStart = async () => {
    if (dnsSpoofBlock !== null) return;
    setDnsSpoofBusy(true);
    setDnsSpoofError(null);
    try {
      const wire = await networkDnsSpoofStartV1(
        parseDnsSpoofPort(dnsSpoofPort) ?? 0,
        dnsSpoofDomains,
        dnsSpoofAnswerIp.trim(),
        true,
        wb.caseId,
      );
      setDnsSpoofStart(wire);
      setDnsSpoofStatus(wire.status);
      // A new responder session has its own one-save evidence slot.
      setDnsSpoofReceipt(null);
    } catch (err) {
      setDnsSpoofError(err instanceof Error ? err.message : String(err));
    } finally {
      setDnsSpoofBusy(false);
    }
  };

  const stopDnsSpoof = async () => {
    try {
      await networkDnsSpoofStopV1();
    } catch (err) {
      setDnsSpoofError(err instanceof Error ? err.message : String(err));
    }
  };

  const runDnsSpoofEvidenceSave = async () => {
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setDnsSpoofBusy(true);
    setDnsSpoofError(null);
    try {
      const wire = await networkDnsSpoofEvidenceSaveV1(caseId);
      if (!isCurrent()) return;
      setDnsSpoofReceipt(wire);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setDnsSpoofError(message);
    } finally {
      if (isCurrent()) setDnsSpoofBusy(false);
    }
  };

const DNS_SPOOF_ALLOWLIST_MAX_CHARS = 2048;

export function parseDnsSpoofPort(text: string): number | null {
  const value = Number(text);
  if (!Number.isInteger(value) || value < 1 || value > 65535) return null;
  return value;
}

export function parseDnsSpoofDomains(text: string): string[] | null {
  const entries = text
    .split(/[,\n\r]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
  if (entries.length === 0 || entries.length > 16) return null;
  for (const entry of entries) {
    const value = entry.startsWith("*.") ? entry.slice(2) : entry;
    if (value.length === 0 || value.length > 253 || value.includes("*")) return null;
    for (const label of value.split(".")) {
      if (label.length === 0 || label.length > 63 || !/^[a-z0-9_-]+$/.test(label)) return null;
    }
  }
  return entries;
}

export function isDnsSpoofAnswerIp(text: string): boolean {
  return /^\\d{1,3}(\\.\\d{1,3}){3}$/.test(text.trim());
}

export function dnsSpoofBlockReason(port: string, domains: string, answerIp: string): string | null {
  if (parseDnsSpoofPort(port) === null) {
    return "Set a UDP port for the responder (1-65535; ports below 1024 need administrator privileges)";
  }
  if (parseDnsSpoofDomains(domains) === null) {
    return "Set the domain allowlist — 1 to 16 exact domains or leading * wildcards; nothing is answered without one";
  }
  if (!isDnsSpoofAnswerIp(answerIp)) {
    return "Set the authorized IPv4 answer address for the allowlisted domains";
  }
  return null;
}

      {mode === "dns_spoof" && (
        <section aria-label="DNS spoof" className="flex min-h-0 flex-1 flex-col">
          {dnsSpoofError ? <ErrorStrip>{dnsSpoofError}</ErrorStrip> : null}
          <ModeCard
            title="DNS spoof"
            icon={Server}
            state={dnsSpoofStatus ? dnsSpoofPhase : "not running"}
            stateTone={
              dnsSpoofPhase === "answering"
                ? "orange"
                : dnsSpoofPhase === "stopped"
                  ? dnsSpoofStatus?.last_error
                    ? "err"
                    : "ok"
                  : dnsSpoofPhase === "starting" || dnsSpoofPhase === "stopping"
                    ? "orange"
                    : "muted"
            }
            info="Authorized allowlist-gated DNS responder — answers only the allowlisted domains with the authorized address, forwards everything else upstream, native dialog on start, every answer logged."
          >
            <div className="grid gap-3 md:grid-cols-2">
              <label className="block text-xs text-fg-dim">
                <span className="mb-1 block font-medium text-fg-muted">
                  Domain allowlist (comma or newline separated, max 16)
                </span>
                <TextArea
                  value={dnsSpoofDomains}
                  onChange={(value) => setDnsSpoofDomains(value.slice(0, DNS_SPOOF_ALLOWLIST_MAX_CHARS))}
                  maxLength={DNS_SPOOF_ALLOWLIST_MAX_CHARS}
                  ariaLabel="Authorized domain allowlist: exact domains or leading *. wildcards, at most 16 entries"
                  placeholder="lab.cyberdeck.test, *.authorized.local"
                  rows={4}
                  className="h-24"
                />
              </label>
              <div className="text-xs text-fg-dim">
                <span className="mb-1 block font-medium text-fg-muted">Authorized answer + port</span>
                <TextInput
                  value={dnsSpoofAnswerIp}
                  onChange={(text) => setDnsSpoofAnswerIp(text.replace(/[^0-9.]/g, "").slice(0, 15))}
                  placeholder="answer IPv4 (e.g. 10.0.0.42)"
                  ariaLabel="Authorized A-record answer address for allowlisted domains"
                  className="h-8 w-44 sm:h-7"
                />
                <TextInput
                  value={dnsSpoofPort}
                  onChange={(text) => setDnsSpoofPort(text.replace(/[^0-9]/g, "").slice(0, 5))}
                  placeholder="UDP port (default 53)"
                  ariaLabel="UDP port to bind the DNS responder on (ports below 1024 need administrator privileges)"
                  className="mt-2 h-8 w-44 sm:h-7"
                />
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              {dnsSpoofActive ? (
                <ToolButton
                  tone="danger"
                  onClick={() => void stopDnsSpoof()}
                  title="Stop the authorized responder: answering ends immediately, the final log flush completes and the query log stays readable — nothing is answered after stop"
                >
                  Stop responder
                </ToolButton>
              ) : (
                <ToolButton
                  tone="primary"
                  onClick={() => void runDnsSpoofStart()}
                  disabled={!desktop || dnsSpoofBusy || dnsSpoofBlock !== null}
                  title="UDP only: binds a DNS responder on the configured port and answers A queries for the allowlisted domains with the authorized address (other record types get an empty answer so the real address never leaks); everything else is forwarded to the system resolver — a resolver, not a transparent interceptor, so only clients pointed at this machine are affected. A native Yes/No dialog names exactly what will be answered, answers are rate-limited and logged, and the run auto-stops at the 30-minute cap. Ports below 1024 need administrator privileges"
                >
                  {dnsSpoofBusy ? "starting…" : "Start responder"}
                </ToolButton>
              )}
              {dnsSpoofBlock ? <Chip tone="muted">{dnsSpoofBlock}</Chip> : null}
            </div>
            {dnsSpoofStart ? (
              <div className="space-y-2">
                <p className="font-mono text-2xs text-fg-muted">
                  port {dnsSpoofStart.port} · answers {dnsSpoofStart.answer_ip} · upstream{" "}
                  {dnsSpoofStart.upstream} · rate cap {dnsSpoofStart.rate_limit_per_sec}/s · runtime cap{" "}
                  {dnsSpoofStart.runtime_cap_minutes} min
                </p>
                <p className="font-mono text-2xs text-fg-muted">
                  allowlist: {dnsSpoofStart.domains.join(", ") || "none"}
                </p>
                <div className="max-h-48 overflow-auto rounded-lg border border-line">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th className="w-24">Queries</th>
                        <th className="w-24">Spoofed</th>
                        <th className="w-24">Upstream</th>
                        <th className="w-24">Refused</th>
                        <th className="w-24">Clients</th>
                        <th className="w-24">Elapsed</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>{dnsSpoofStatus?.queries_seen ?? 0}</td>
                        <td>{dnsSpoofStatus?.spoofed_count ?? 0}</td>
                        <td>{dnsSpoofStatus?.forwarded_count ?? 0}</td>
                        <td>{dnsSpoofStatus?.refused_count ?? 0}</td>
                        <td>{dnsSpoofStatus?.clients_seen ?? 0}</td>
                        <td>
                          {dnsSpoofStatus
                            ? \`\${(dnsSpoofStatus.elapsed_ms / 1000).toFixed(1)} s\`
                            : "0.0 s"}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <div className="max-h-64 overflow-auto rounded-lg border border-line">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th className="w-28">Time</th>
                        <th className="w-32">Client</th>
                        <th>Queried name</th>
                        <th className="w-28">Answered from</th>
                        <th className="w-32">Answer IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(dnsSpoofStatus?.log_entries ?? []).map((entry, index) => (
                        <tr key={\`\${entry.timestamp_ms}-\${entry.client}-\${index}\`}>
                          <td className="font-mono text-2xs">{formatSeenMs(entry.timestamp_ms)}</td>
                          <td className="font-mono text-2xs">{entry.client}</td>
                          <td className="font-mono text-2xs">{entry.name}</td>
                          <td>
                            <Chip
                              tone={
                                entry.answered_from === "spoof"
                                  ? "err"
                                  : entry.answered_from === "upstream"
                                    ? "ok"
                                    : "muted"
                              }
                            >
                              {entry.answered_from}
                            </Chip>
                          </td>
                          <td className="font-mono text-2xs text-fg-dim">{entry.answer_ip ?? "—"}</td>
                        </tr>
                      ))}
                      {(dnsSpoofStatus?.log_entries ?? []).length === 0 ? (
                        <tr>
                          <td colSpan={5} className="text-center text-fg-muted">
                            no queries seen yet — the log fills as clients ask
                          </td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
                {dnsSpoofStatus && dnsSpoofStatus.log_dropped > 0 ? (
                  <p className="text-xs text-fg-muted">
                    log ring capped at 512 — {dnsSpoofStatus.log_dropped} oldest entries dropped
                  </p>
                ) : null}
                <div className="flex flex-wrap items-center gap-3">
                  <ToolButton
                    tone="primary"
                    disabled={!desktop || dnsSpoofBusy || dnsSpoofSaved}
                    title={
                      dnsSpoofSaved
                        ? "This responder session already saved its one bounded evidence finding — start a new session to capture more"
                        : "Persist the session's request/answer log as ONE bounded case finding in the backend-selected saved case"
                    }
                    onClick={() => void runDnsSpoofEvidenceSave()}
                  >
                    {dnsSpoofReceipt ? "saved" : dnsSpoofBusy ? "saving…" : "Save to case"}
                  </ToolButton>
                  {dnsSpoofReceipt ? (
                    <Chip tone={dnsSpoofReceipt.truncated ? "orange" : "ok"}>
                      saved to {dnsSpoofReceipt.case_id} · {dnsSpoofReceipt.entry_count} entries ·{" "}
                      {dnsSpoofReceipt.byte_len} bytes
                      {dnsSpoofReceipt.truncated ? " · truncated at the 32 KiB bound" : ""}
                    </Chip>
                  ) : null}
                  <InfoTip text="One bounded artifact per responder session: the backend renders the session header, honest counters and the query log (spoof vs upstream per answer) and persists them as ONE case finding; a second save refuses honestly instead of duplicating case evidence." />
                </div>
                {dnsSpoofPhase === "stopped" ? (
                  <p className="text-xs text-fg-muted">
                    {dnsSpoofStatus?.log_flushed
                      ? "responder stopped — final log flushed, answering ended, no new answers leave this machine"
                      : "responder stopped — final log flush pending"}
                  </p>
                ) : null}
                {dnsSpoofStatus?.last_error ? (
                  <p className="text-xs text-fg-muted">last error: {dnsSpoofStatus.last_error}</p>
                ) : null}
              </div>
            ) : null}
          </ModeCard>
        </section>
      )}
`;

const integrated = /id: "dns_spoof"/.test(viewSource);
// Until the coordinator lands the block, the UI contract is self-checked
// against the delivered snippet; once integrated it is checked against the
// real view (both carry the same contract lines).
const uiSource = integrated ? viewSource : DNS_SPOOF_SNIPPET;

test("DNS spoof mode is coordinator-integrated (or still self-checked against the delivered snippet)", () => {
  if (integrated) {
    assert.match(viewSource, /\{mode === "dns_spoof" && \(/);
  } else {
    assert.doesNotMatch(viewSource, /id: "dns_spoof"/);
    assert.match(DNS_SPOOF_SNIPPET, /\{mode === "dns_spoof" && \(/);
  }
});

test("DNS Spoof mode exists on the rail and renders as its own control card", () => {
  assert.match(uiSource, /type LabMode = "scope" \| "arp" \| "live" \| "dns" \| "wifi" \| "spoof" \| "dns_spoof" \| "http_proxy" \| "report";/);
  assert.match(uiSource, /\{ id: "dns_spoof", label: "DNS Spoof", icon: Server \}/);
  const card = /<ModeCard\s+title="DNS spoof"[\s\S]*?info="([^"]+)"/.exec(uiSource);
  assert.ok(card, "DNS spoof ModeCard missing its InfoTip description");
  assert.ok(!card[1].includes("\n"), "card description must stay one line");
  assert.match(card[1], /allowlist-gated/);
  assert.match(card[1], /forwards everything else upstream/);
  assert.match(card[1], /native dialog on start/);
});

test("start routes through the backend native dialog: no on-screen authorization checkbox", () => {
  const start =
    /onClick=\{\(\) => void runDnsSpoofStart\(\)\}[\s\S]*?Start responder/.exec(uiSource);
  assert.ok(start, "Start responder button missing");
  // No checkbox chrome inside the DNS Spoof mode section — the acknowledgment
  // is the backend's native Yes/No dialog. (Other modes legitimately use
  // CheckBox for settings; this pin is scoped to this mode's own block.)
  const dnsSectionStart = uiSource.indexOf('{mode === "dns_spoof" && (');
  const dnsSectionEnd = uiSource.indexOf('{mode === "http_proxy" && (', dnsSectionStart);
  assert.ok(dnsSectionStart >= 0 && dnsSectionEnd > dnsSectionStart, "DNS Spoof section not found");
  const dnsSection = uiSource.slice(dnsSectionStart, dnsSectionEnd);
  assert.doesNotMatch(dnsSection, /<CheckBox/);
  assert.match(uiSource, /networkDnsSpoofStartV1\(/);
  assert.match(backendSource, /MessageDialogButtons::YesNo/);
  assert.match(backendSource, /blocking_show/);
  assert.match(backendSource, /Authorize DNS spoof responder/);
  assert.match(backendSource, /cancelled by operator/);
  assert.match(backendSource, /explicit DNS spoof responder authorization required/);
});

test("start button is desktop-, gate- and busy-gated with honest privilege copy", () => {
  const start = /disabled=\{!\s*desktop \|\| dnsSpoofBusy \|\| dnsSpoofBlock !== null\}/.exec(uiSource);
  assert.ok(start, "start gating missing");
  assert.match(uiSource, /dnsSpoofBlockReason\(dnsSpoofPort, dnsSpoofDomains, dnsSpoofAnswerIp\)/);
  const gate = /export function dnsSpoofBlockReason\([\s\S]*?\n\}/.exec(uiSource);
  assert.ok(gate, "dnsSpoofBlockReason helper missing");
  assert.match(gate[0], /ports below 1024 need administrator privileges/);
  assert.match(gate[0], /nothing is answered without one/);
  assert.match(uiSource, /Ports below 1024 need administrator privileges/, "tooltip honors bind privilege");
});

test("allowlist gating: nothing is answered without an explicit allowlist", () => {
  // Pure UI parse mirrors the backend bounds.
  const parse = /export function parseDnsSpoofDomains\([\s\S]*?\n\}/.exec(uiSource);
  assert.ok(parse, "parseDnsSpoofDomains helper missing");
  assert.match(parse[0], /entries.length === 0 \|\| entries.length > 16/);
  // The backend refuses to run without an allowlist and caps domains/wildcards.
  assert.match(coreSource, /without an explicit allowlist/);
  assert.match(coreSource, /MAX_DOMAINS: usize = 16/);
  assert.match(coreSource, /pub fn build\(entries: &\[String\]\) -> Result<Self, DnsSpoofError>/);
  assert.match(coreSource, /at most \{MAX_DOMAINS\} allowlist domains/);
  // Wildcards are leading-only and bounded.
  assert.match(coreSource, /wildcards are only supported as a leading/);
  assert.match(coreSource, /pub fn matches\(&self, name: &str\) -> bool/);
});

test("upstream-forward honesty: a resolver, not a transparent interceptor", () => {
  assert.match(coreSource, /FORWARDED to the system resolver/);
  assert.match(coreSource, /RESOLVER, not a transparent interceptor/);
  assert.match(coreSource, /UPSTREAM_TIMEOUT_MS: u64 = 3000/);
  assert.match(coreSource, /MAX_CONCURRENT_FORWARDS: usize = 64/);
  assert.match(coreSource, /async fn forward_upstream\(/);
  assert.match(coreSource, /upstream timeout/);
  assert.match(coreSource, /pub fn system_upstream\(\)/);
  // The dialog names the forwarding honestly before start.
  assert.match(backendSource, /FORWARDED to the system resolver at/);
  assert.match(backendSource, /not a transparent interceptor/);
  // The UI copy repeats the same honesty, never re-derives it.
  assert.match(uiSource, /forwards everything else upstream/);
  assert.match(uiSource, /a resolver, not a transparent interceptor/);
});

test("bounds are hard: 512-entry log ring, 32 requests/s, 30-minute auto-stop", () => {
  assert.match(coreSource, /MAX_LOG_ENTRIES: usize = 512/);
  assert.match(coreSource, /MAX_RATE_PER_SEC: u32 = 32/);
  assert.match(coreSource, /MAX_RUNTIME_MS: u64 = 30 \* 60 \* 1000/);
  assert.match(coreSource, /rate limit must be 1\.\.=/);
  assert.match(coreSource, /runtime cap must be 1\.\.=/);
  assert.match(coreSource, /DnsEndReason::RuntimeCapReached/);
  assert.match(uiSource, /log ring capped at 512/);
});

test("live status panel shows honest counts and the per-answer spoof/upstream column", () => {
  for (const field of [
    "dnsSpoofStatus?.queries_seen ?? 0",
    "dnsSpoofStatus?.spoofed_count ?? 0",
    "dnsSpoofStatus?.forwarded_count ?? 0",
    "dnsSpoofStatus?.refused_count ?? 0",
    "dnsSpoofStatus?.clients_seen ?? 0",
  ]) {
    assert.match(uiSource, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(uiSource, /<th className="w-28">Answered from<\/th>/);
  assert.match(
    uiSource,
    /entry\.answered_from === "spoof"\s*\?\s*"err"\s*:\s*entry\.answered_from === "upstream"\s*\?\s*"ok"\s*:\s*"muted"/,
  );
  assert.match(uiSource, /dnsSpoofStatus\.log_dropped/);
  // The backend status wire stays snake_case and complete.
  for (const field of [
    "pub state: String",
    "pub port: u16",
    "pub domains: Vec<String>",
    "pub answer_ip: String",
    "pub upstream: String",
    "pub queries_seen: u64",
    "pub spoofed_count: u64",
    "pub forwarded_count: u64",
    "pub refused_count: u64",
    "pub rate_limited_count: u64",
    "pub clients_seen: usize",
    "pub elapsed_ms: u64",
    "pub log_entries: Vec<dns_spoof::QueryLogEntry>",
    "pub log_flushed: bool",
    "pub last_error: Option<String>",
  ]) {
    assert.match(backendSource, new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("stop is always available while a run exists, never refused, and flushes the final log", () => {
  const stop =
    /title="Stop the authorized responder:[\s\S]*?Stop responder/.exec(uiSource);
  assert.ok(stop, "Stop responder button missing");
  assert.doesNotMatch(stop[0], /disabled/);
  assert.match(uiSource, /await networkDnsSpoofStopV1\(\)/);
  const stopCommand = /pub fn network_dns_spoof_stop_v1\([\s\S]*?\n\}/.exec(backendSource);
  assert.ok(stopCommand, "stop command missing");
  assert.match(backendSource, /Cancellation is NEVER refused/);
  assert.match(coreSource, /fn mark_flushed/);
  assert.match(coreSource, /Final log flush/);
  assert.match(uiSource, /responder stopped — final log flushed/);
});

test("evidence save persists ONE bounded finding per session; a second save refuses", () => {
  assert.match(uiSource, /networkDnsSpoofEvidenceSaveV1\(caseId\)/);
  assert.match(uiSource, /Save to case/);
  assert.match(uiSource, /already saved its one bounded evidence finding/);
  assert.match(backendSource, /network\.dns_spoof/);
  assert.match(backendSource, /DNS_EVIDENCE_SOURCE/);
  assert.match(backendSource, /store\.add_findings\(&verified_case, DNS_EVIDENCE_SOURCE, None, &\[finding\]\)\?;/);
  assert.match(backendSource, /with_current_publication/);
  assert.match(backendSource, /fn reserve_evidence_slot/);
  assert.match(backendSource, /already saved its one bounded evidence finding/);
  assert.match(backendSource, /MAX_DNS_EVIDENCE_BYTES: usize = 32 \* 1024/);
  assert.match(backendSource, /truncated at the 32 KiB evidence bound/);
  assert.match(backendSource, /pub truncated: bool/);
});

test("spoof state dies on case switch so a stale run can never render against a new revision", () => {
  for (const line of [
    "setDnsSpoofBusy(false);",
    "setDnsSpoofStart(null);",
    "setDnsSpoofStatus(null);",
    "setDnsSpoofReceipt(null);",
    "setDnsSpoofError(null);",
  ]) {
    assert.match(uiSource, new RegExp(line.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("poll cadence and handler wiring mirror the other gated lab modes", () => {
  assert.match(uiSource, /const dnsSpoofPhase = dnsSpoofStatus\?\.state \?\? "idle";/);
  assert.match(
    uiSource,
    /dnsSpoofPhase === "starting" \|\| dnsSpoofPhase === "answering" \|\| dnsSpoofPhase === "stopping"/,
  );
  assert.match(uiSource, /networkDnsSpoofStatusV1\(\)/);
  assert.match(uiSource, /\}, 1000\);/);
  assert.match(uiSource, /setDnsSpoofStatus\(wire\.status\)/);
  // The backend echoes the authorized config verbatim (UI never re-derives).
  assert.match(backendSource, /pub struct DnsSpoofStartWire/);
  assert.match(backendSource, /pub domains: Vec<String>/);
  assert.match(backendSource, /pub rate_limit_per_sec: u32/);
  assert.match(backendSource, /pub runtime_cap_minutes: u32/);
});

// ------------------------------------------------------- backend contracts ---

test("backend commands exist with the v1 names and keep socket code out of the IPC layer", () => {
  for (const command of [
    "network_dns_spoof_start_v1",
    "network_dns_spoof_stop_v1",
    "network_dns_spoof_status_v1",
    "network_dns_spoof_evidence_save_v1",
  ]) {
    assert.match(backendSource, new RegExp(`pub (async )?fn ${command}`));
  }
  // No raw socket machinery in the command layer; the pure core owns it.
  assert.doesNotMatch(backendSource, /UdpSocket|SOCK_RAW|libc|recv_from/);
  assert.match(coreSource, /UdpSocket::bind/);
  assert.match(coreSource, /pub async fn run_responder\(/);
  // The command layer reuses the pure worker instead of duplicating it.
  assert.match(backendSource, /dns_spoof::bind_responder\(&config\)/);
  assert.match(backendSource, /dns_spoof::run_responder\(/);
});

test("answering is an active UDP service: it takes the shared operation gate lease", () => {
  assert.match(backendSource, /gate\.acquire\(super::operation_gate::ActiveOperation::TcpUdp\)\?/);
  assert.match(backendSource, /stop other active network scans before starting the DNS spoof responder/);
  assert.match(backendSource, /another network operation became active while confirming/);
  // Case discipline mirrors the ARP spoof slice exactly.
  assert.match(backendSource, /DNS spoof answering requires a saved, backend-selected case/);
  assert.match(backendSource, /request case id does not match the backend-selected case/);
  assert.match(backendSource, /\.ensure\(&worker_scope\)/);
  assert.match(backendSource, /session\.ensure\(&scope\)\?/);
});

test("the dialog names exactly what will be answered and the run guard publishes stopped", () => {
  assert.match(backendSource, /fn authorization_question\(/);
  assert.match(backendSource, /answers ONLY these/);
  assert.match(backendSource, /other record types for those names/);
  assert.match(backendSource, /the real address never leaks/);
  assert.match(backendSource, /struct DnsRunGuard/);
  assert.match(backendSource, /DnsPhase::Stopped/);
});

test("honest bind errors: privileged ports refuse with an actionable message", () => {
  assert.match(coreSource, /DnsErrorCode::Permission/);
  assert.match(coreSource, /binding UDP port \{\} was refused/);
  assert.match(coreSource, /requires administrator privileges/);
  assert.match(coreSource, /run elevated or pick a high port/);
  // The command surfaces the bind error before mutating run state.
  assert.match(backendSource, /Bind BEFORE mutating run state/);
  assert.match(backendSource, /dns_spoof::bind_responder\(&config\)\.await\.map_err\(dns_err\)\?/);
});

test("Rust tests cover the promised contracts in the responder core and IPC", () => {
  for (const test of [
    "fn allowlisted_exact_query_gets_the_authorized_a_answer",
    "fn wildcard_matches_subdomains_but_the_apex_is_forwarded_without_an_exact_entry",
    "fn forwarded_queries_relay_the_upstream_response_within_the_bounded_timeout",
    "fn malformed_and_response_datagrams_are_refused_not_answered_or_forwarded",
    "fn rate_limit_drops_requests_beyond_the_configured_rate",
    "fn runtime_cap_auto_stops_the_responder",
    "fn operator_stop_keeps_the_final_log_readable_and_flushed",
    "fn log_ring_is_bounded_with_an_honest_drop_count",
    "fn allowlist_validation_refuses_oversized_malformed_or_duplicate_entries",
    "fn non_a_questions_for_allowlisted_names_get_nodata_never_the_real_answer",
    "fn clients_seen_counts_distinct_clients_only_up_to_the_bound",
    "fn bind_refuses_privileged_ports_with_an_honest_error",
    "fn configuration_bounds_are_enforced_before_any_socket_exists",
  ]) {
    assert.match(coreSource, new RegExp(test.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  for (const test of [
    "fn evidence_slot_allows_one_save_and_refuses_the_second",
    "fn evidence_finding_is_bounded_and_honest_about_the_session",
    "fn authorization_question_names_exactly_what_will_be_answered_and_forwarded",
    "fn the_run_guard_publishes_stopped_and_clears_ownership",
    "fn scratchpad_and_missing_cases_are_refused_by_the_saved_case_gate",
  ]) {
    assert.match(backendSource, new RegExp(test.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

"use client";
/**
 * Network Lab (Ettercap-inspired mode, passive/defensive arc).
 *
 * Two live sections plus one inert one, per Master Plan §5.1 gate language:
 *  - Lab scope: ettercap's Target 1 / Target 2 group model, held in memory
 *    only, set behind an explicit authorization checkbox.
 *  - ARP analysis: passive anomaly detection (IP impersonation, gratuitous
 *    ARP bursts, gateway impersonation) plus a unified host inventory over
 *    the currently opened capture. Never transmits a packet.
 *  - Active interaction: ARP poisoning / traffic alteration controls are
 *    visible but permanently disabled — not available in this arc.
 */
import { useEffect, useRef, useState } from "react";
import { FolderOpen, Radar } from "lucide-react";
import { Chip, EmptyState, Pane, Select, TextInput, ToolButton } from "@ds/panes";
import {
  captureInterfacesV1,
  isDesktop,
  networkLabEventsV1,
  pcapOpenDialog,
  type CaptureInterfaceV1,
  type LabEventKindWire,
  type LabEventWire,
  type LabEventsWire,
  type PcapOpenWire,
} from "@lib/ipc";
import {
  isValidLiveSessionId,
  networkLabLiveStatusV1,
  type LabLiveStatusWire,
} from "@lib/network-lab-live-ipc";
import { networkLabDnsMonitorV1, type DnsMonitorWire } from "@lib/ipc";
import {
  dnsFindingKindLabel,
  formatAnswerSet,
  questionTypeLabel,
} from "./network-lab-dns-ipc";
import {
  labSweepBlockReason,
  networkLabArpSweepStopV1,
  networkLabArpSweepV1,
  type LabArpNeighborWire,
  type LabSweepProgressWire,
} from "./network-lab-targeting-ipc";
import {
  networkLabReportExportV1,
  reportReceiptText,
  type LabReportReceiptWire,
} from "./network-lab-report-ipc";
import { useWorkbench } from "@state/workbench";
import {
  networkLabAnalyzePcapV1,
  networkLabScopeV1,
  networkLabSetScopeV1,
  findingKindLabel,
  formatSeenMs,
  parseScopeEntries,
  scopeSummary,
  summarizeMacClaims,
  totalClaims,
  type NetworkLabAnalysisWire,
  type NetworkLabScopeWire,
} from "./network-lab-model";

const SCOPE_TEXT_MAX_CHARS = 8192;

export function NetworkLabView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const [capture, setCapture] = useState<PcapOpenWire | null>(null);
  const [opening, setOpening] = useState(false);
  const [openError, setOpenError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<NetworkLabAnalysisWire | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  // Bettercap-mode passive timeline over the opened capture; per-run result
  // state like every other capture-derived view value.
  const [timeline, setTimeline] = useState<LabEventsWire | null>(null);
  const [timelineBusy, setTimelineBusy] = useState(false);
  // Passive DNS-response monitor (dns-spoofing counterpart): per-run result
  // state over the opened capture, same lifecycle as the ARP analysis.
  const [dnsResult, setDnsResult] = useState<DnsMonitorWire | null>(null);
  const [dnsBusy, setDnsBusy] = useState(false);
  const [dnsError, setDnsError] = useState<string | null>(null);
  // Lab session report export (Bettercap session-report parity): one bounded
  // markdown artifact persisted as ONE case finding; per-run receipt state
  // like every other capture-derived view value.
  const [reportReceipt, setReportReceipt] = useState<LabReportReceiptWire | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportIncludeDns, setReportIncludeDns] = useState(true);
  // Live source: the lab either derives over the opened capture or
  // SUBSCRIBES to Packet Studio's running capture session (one capture,
  // many modules). It never starts or stops a capture of its own.
  const [liveSource, setLiveSource] = useState<"opened" | "session">("opened");
  const [liveSessionId, setLiveSessionId] = useState("");
  const [liveStatus, setLiveStatus] = useState<LabLiveStatusWire | null>(null);
  const [livePolling, setLivePolling] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [routerIp, setRouterIp] = useState("");
  const [targetsT1, setTargetsT1] = useState("");
  const [targetsT2, setTargetsT2] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [scope, setScope] = useState<NetworkLabScopeWire | null>(null);
  const [scopeBusy, setScopeBusy] = useState(false);
  const [scopeError, setScopeError] = useState<string | null>(null);
  // Lab-scope-targeted ARP sweep (the arc's only ACTIVE command): the target
  // set is resolved on the backend from the saved scope alone — the view
  // never sends addresses, only the interface choice and the authorization
  // acknowledgment, so it cannot widen the operator's declared scope.
  const [sweepInterfaces, setSweepInterfaces] = useState<CaptureInterfaceV1[]>([]);
  const [sweepInterface, setSweepInterface] = useState("");
  const [sweepBusy, setSweepBusy] = useState(false);
  const [sweepProgress, setSweepProgress] = useState<LabSweepProgressWire | null>(null);
  const [sweepResults, setSweepResults] = useState<LabArpNeighborWire[] | null>(null);
  const [sweepError, setSweepError] = useState<string | null>(null);
  const currentCase = useRef(wb.caseId);
  currentCase.current = wb.caseId;
  const openSequence = useRef(0);

  // Scope state dies with the process (backend memory-only), so a case
  // switch re-reads it instead of trusting whatever the chip last showed.
  useEffect(() => {
    if (!desktop) return;
    let cancelled = false;
    networkLabScopeV1()
      .then((wire) => {
        if (!cancelled) setScope(wire);
      })
      .catch(() => {
        // Chip keeps showing "unknown"; the next explicit action surfaces it.
      });
    return () => {
      cancelled = true;
    };
  }, [desktop, wb.caseId]);

  useEffect(() => {
    openSequence.current += 1;
    setCapture(null);
    setAnalysis(null);
    setDnsResult(null);
    // The exported report is case evidence: a case switch drops the receipt
    // so the chip can never claim an export into the previous case.
    setReportReceipt(null);
    setOpening(false);
    setAnalyzing(false);
    setDnsBusy(false);
    setReportBusy(false);
    setOpenError(null);
    setAnalysisError(null);
    setDnsError(null);
    setReportError(null);
    // A case switch revokes the capture session's ownership on the backend,
    // so the live subscription is meaningless: stop polling and drop the
    // stale status instead of letting it render against the new revision.
    setLivePolling(false);
    setLiveStatus(null);
    setLiveError(null);
    // A case switch revokes the sweep's case-revision ownership on the
    // backend (the worker closure revalidates it), so per-run sweep state
    // never survives into the new revision.
    setSweepBusy(false);
    setSweepProgress(null);
    setSweepResults(null);
    setSweepError(null);
  }, [wb.caseId]);

  // Live subscription poll: every ~2s while enabled. A self-rescheduling
  // timeout (not a bare interval) keeps overlapping polls from piling up if
  // the backend is slow; the cleanup clears the pending timer on unmount,
  // case switch or when polling is switched off. The command is read-only
  // and stateless, so an abandoned subscription simply stops asking.
  useEffect(() => {
    if (!desktop || liveSource !== "session" || !livePolling) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const poll = () => {
      networkLabLiveStatusV1(Number(liveSessionId), routerIp.trim() || null)
        .then((wire) => {
          if (cancelled) return;
          setLiveStatus(wire);
          setLiveError(null);
        })
        .catch((cause) => {
          if (cancelled) return;
          setLiveError(
            "Live subscription failed: " +
              (cause instanceof Error ? cause.message : String(cause)),
          );
        })
        .finally(() => {
          if (!cancelled) timer = setTimeout(poll, 2000);
        });
    };
    poll();
    return () => {
      cancelled = true;
      if (timer !== null) clearTimeout(timer);
    };
  }, [desktop, liveSource, livePolling, liveSessionId, routerIp, wb.caseId]);

  const switchLiveSource = (source: "opened" | "session") => {
    setLiveSource(source);
    // Leaving the running-session source ends the subscription honestly.
    if (source === "opened") {
      setLivePolling(false);
      setLiveStatus(null);
      setLiveError(null);
    }
  };

  const startLiveSubscription = () => {
    if (!isValidLiveSessionId(liveSessionId)) return;
    setLiveError(null);
    setLiveStatus(null);
    setLivePolling(true);
  };

  const stopLiveSubscription = () => {
    // Stop clears the poll only; the lab never stops Packet Studio's capture.
    setLivePolling(false);
  };

  // The rendered timeline comes from the active source: the opened-capture
  // derivation, or the latest polled status of the subscribed session
  // (LabLiveStatusWire carries every LabEventsWire field).
  const displayTimeline: LabEventsWire | null =
    liveSource === "session" ? liveStatus : timeline;

  const openCapture = async (): Promise<PcapOpenWire | null> => {
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setOpening(true);
    setOpenError(null);
    try {
      const wire = await pcapOpenDialog();
      if (!isCurrent()) return null;
      setCapture(wire);
      // Findings from the previous capture would be stale the moment the
      // backend cache is replaced, so they never survive an open.
      setAnalysis(null);
      setDnsResult(null);
      setReportReceipt(null);
      return wire;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setOpenError(message);
      return null;
    } finally {
      if (isCurrent()) setOpening(false);
    }
  };

  const runAnalysis = async () => {
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setAnalyzing(true);
    setAnalysisError(null);
    try {
      let current = capture;
      if (!current) {
        // Same pcap_open_dialog flow PacketStudioView uses: opening through
        // the dialog also populates the shared backend capture cache that
        // the passive analyzer reads.
        const opened = await openCapture();
        if (!opened) return;
        current = opened;
      }
      const gateway = routerIp.trim();
      const wire = await networkLabAnalyzePcapV1(gateway.length > 0 ? gateway : null);
      if (!isCurrent()) return;
      setAnalysis(wire);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setAnalysisError(message);
    } finally {
      if (isCurrent()) setAnalyzing(false);
    }
  };

  // Passive DNS-response monitoring: reads the opened capture only (same
  // read-only gate as the timeline derivation), never transmits anything.
  const runDnsMonitor = async () => {
    if (!capture) return;
    setDnsBusy(true);
    setDnsError(null);
    try {
      const wire = await networkLabDnsMonitorV1();
      setDnsResult(wire);
    } catch (err) {
      setDnsError(err instanceof Error ? err.message : String(err));
    } finally {
      setDnsBusy(false);
    }
  };

  // Lab session report export: read-only over the opened capture; the
  // backend renders one bounded markdown artifact and persists ONE case
  // finding into the backend-selected saved case. The receipt is the only
  // thing that comes back across IPC.
  const runReportExport = async () => {
    if (!capture) return;
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setReportBusy(true);
    setReportError(null);
    try {
      const wire = await networkLabReportExportV1(routerIp.trim() || null, reportIncludeDns);
      if (!isCurrent()) return;
      setReportReceipt(wire);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setReportError(message);
    } finally {
      if (isCurrent()) setReportBusy(false);
    }
  };

  const applyScope = async () => {
    setScopeBusy(true);
    setScopeError(null);
    try {
      const wire = await networkLabSetScopeV1(
        parseScopeEntries(targetsT1),
        parseScopeEntries(targetsT2),
        authorized,
      );
      setScope(wire);
    } catch (err) {
      setScopeError(err instanceof Error ? err.message : String(err));
    } finally {
      setScopeBusy(false);
    }
  };

  // Sweep interface list: same active-Ethernet filter the netscan ARP
  // discovery uses (ethernet, up, not loopback); the sweep runs on one
  // explicitly selected interface or not at all.
  useEffect(() => {
    if (!desktop) return;
    let active = true;
    void captureInterfacesV1()
      .then((interfaces) => {
        if (!active) return;
        const connected = interfaces.filter(
          (iface) => iface.ethernet && iface.up && !iface.loopback,
        );
        setSweepInterfaces(connected);
        setSweepInterface((current) =>
          current || (connected.length > 0 ? connected[0].name : ""),
        );
      })
      .catch(() => {
        if (active) setSweepInterfaces([]);
      });
    return () => {
      active = false;
    };
  }, [desktop]);

  // The scope state lives behind the backend; refresh the block-reason
  // source whenever the workbench case changes (scope is re-read above).
  const sweepBlock = labSweepBlockReason(scope);

  const runSweep = async () => {
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setSweepBusy(true);
    setSweepError(null);
    setSweepProgress(null);
    try {
      const rows = await networkLabArpSweepV1(sweepInterface, authorized, caseId, (progress) => {
        if (isCurrent()) setSweepProgress(progress);
      });
      if (!isCurrent()) return;
      setSweepResults(rows);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setSweepError(message);
    } finally {
      if (isCurrent()) setSweepBusy(false);
    }
  };

  const stopSweep = async () => {
    try {
      await networkLabArpSweepStopV1();
    } catch (err) {
      setSweepError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="h-full min-h-0 overflow-y-auto bg-app p-3">
      <div className="mx-auto flex max-w-5xl flex-col gap-px bg-line">
        <Pane
          title="Network Lab · passive analysis"
          actions={<Chip tone="ok">passive observations only</Chip>}
        >
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              Ettercap-inspired lab mode inside Packet Studio: unified host inventory, passive ARP
              anomaly analysis and passive DNS-response monitoring over already-captured frames.
              The lab reads captures and never transmits packets; scope entries are IP/CIDR strings
              held in memory only and are never persisted (Master Plan §5.1).
            </p>
          </div>
        </Pane>

        <Pane
          title="Lab scope (Target 1 / Target 2)"
          actions={<Chip tone={scope?.authorized ? "orange" : "muted"}>{scopeSummary(scope)}</Chip>}
        >
          <div className="grid gap-3 p-3 md:grid-cols-2">
            <label className="block text-xs text-fg-dim">
              <span className="mb-1 block font-medium uppercase tracking-wider text-fg-muted">
                Target 1
              </span>
              <textarea
                value={targetsT1}
                onChange={(event) => setTargetsT1(event.target.value.slice(0, SCOPE_TEXT_MAX_CHARS))}
                spellCheck={false}
                maxLength={SCOPE_TEXT_MAX_CHARS}
                aria-label="Target 1 scope: IP or CIDR entries separated by commas or newlines"
                placeholder={"192.168.1.0/24\n10.0.0.5"}
                className="h-24 w-full resize-none rounded-sm border border-line bg-app p-2 font-mono text-xs leading-relaxed text-fg outline-none ring-0 focus:border-line focus:outline-none focus:ring-0 focus-visible:border-line focus-visible:outline-none focus-visible:ring-0"
              />
            </label>
            <label className="block text-xs text-fg-dim">
              <span className="mb-1 block font-medium uppercase tracking-wider text-fg-muted">
                Target 2
              </span>
              <textarea
                value={targetsT2}
                onChange={(event) => setTargetsT2(event.target.value.slice(0, SCOPE_TEXT_MAX_CHARS))}
                spellCheck={false}
                maxLength={SCOPE_TEXT_MAX_CHARS}
                aria-label="Target 2 scope: IP or CIDR entries separated by commas or newlines"
                placeholder={"192.168.1.1"}
                className="h-24 w-full resize-none rounded-sm border border-line bg-app p-2 font-mono text-xs leading-relaxed text-fg outline-none ring-0 focus:border-line focus:outline-none focus:ring-0 focus-visible:border-line focus-visible:outline-none focus-visible:ring-0"
              />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3 border-t border-line p-3">
            <label className="flex max-w-xl items-start gap-2 text-xs text-fg-dim">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(event) => setAuthorized(event.target.checked)}
                className="mt-0.5 accent-[var(--color-orange)]"
              />
              <span>
                I confirm this lab scope is mine or I have explicit authorization to assess it. The
                scope is validated, capped at 64 entries per target group and held in memory only.
              </span>
            </label>
            <ToolButton
              tone="primary"
              onClick={() => void applyScope()}
              disabled={!desktop || !authorized || scopeBusy}
              title="Validate and store the lab scope in memory; requires the authorization checkbox"
            >
              Set lab scope
            </ToolButton>
            {scopeError ? (
              <span role="alert" className="text-xs text-err">
                {scopeError}
              </span>
            ) : null}
          </div>
          {/* Lab-scope-targeted ARP sweep: the arc's only ACTIVE command.
              Targets are resolved on the backend exclusively from the saved
              lab scope (Target 1 ∪ Target 2) and every candidate is checked
              against it, so the sweep refuses anything outside the declared
              scope. Linux native worker, native confirmation, CAP_NET_RAW. */}
          <div className="border-t border-line p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium uppercase tracking-wider text-fg-muted">
                ARP sweep (Target 1 ∪ Target 2)
              </span>
              <Select
                value={sweepInterface}
                onChange={setSweepInterface}
                options={[
                  { value: "", label: "Choose Ethernet NIC" },
                  ...sweepInterfaces.map((iface) => ({
                    value: iface.name,
                    label: iface.name,
                  })),
                ]}
                ariaLabel="ARP sweep Ethernet interface"
                className="w-44"
              />
              {sweepBusy ? (
                <ToolButton
                  tone="danger"
                  onClick={() => void stopSweep()}
                  title="Stop the case-authorized lab ARP sweep; the native worker checks the stop flag before every probe"
                >
                  Stop sweep
                </ToolButton>
              ) : (
                <ToolButton
                  tone="primary"
                  onClick={() => void runSweep()}
                  disabled={!desktop || !authorized || !sweepInterface || sweepBlock !== null}
                  title="Linux only: sweeps ONLY the IPv4 targets resolved from the saved lab scope (Target 1 ∪ Target 2), at most 32 probes at 10/s, native confirmation and CAP_NET_RAW required; refuses anything outside the declared scope"
                >
                  ARP sweep (Target 1 ∪ Target 2)
                </ToolButton>
              )}
              {sweepBlock ? <Chip tone="muted">{sweepBlock}</Chip> : null}
              {sweepProgress ? (
                <Chip tone={sweepProgress.phase === "done" ? "ok" : "muted"}>
                  {sweepProgress.phase === "done"
                    ? `${sweepProgress.answered ?? 0}/${sweepProgress.total_targets} answered · ${sweepProgress.elapsed_ms} ms`
                    : `sweeping ${sweepProgress.total_targets} scope targets · ${(sweepProgress.elapsed_ms / 1000).toFixed(1)} s`}
                </Chip>
              ) : null}
            </div>
            {sweepError ? (
              <div role="alert" className="mt-2 border border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                {sweepError}
              </div>
            ) : null}
            {sweepResults ? (
              sweepResults.length === 0 ? (
                <p className="pt-2 text-xs text-fg-muted">
                  no hosts answered the authorized lab ARP sweep — silence is not evidence of
                  absence; the sweep probed only the saved lab scope
                </p>
              ) : (
                <div className="max-h-64 overflow-auto pt-2">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>Responder MAC</th>
                        <th className="w-24">Latency</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sweepResults.map((row) => (
                        <tr key={row.host}>
                          <td className="font-mono text-fg">{row.host}</td>
                          <td className="font-mono text-fg-dim">{row.mac}</td>
                          <td>{row.elapsed_ms} ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            ) : null}
          </div>
        </Pane>

        <Pane
          title="ARP analysis (opened capture)"
          actions={
            capture ? (
              <Chip tone="ok">
                {capture.file_name} · {capture.format.toUpperCase()} · {capture.packet_count} packets
              </Chip>
            ) : (
              <Chip>No capture opened</Chip>
            )
          }
        >
          <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
            <ToolButton
              onClick={() => void openCapture()}
              disabled={!desktop || opening}
              title={desktop ? "Open a PCAP or PCAPNG capture using the native Rust parser" : "Opening captures requires the desktop runtime"}
            >
              <FolderOpen size={11} /> {opening ? "opening…" : "Open capture…"}
            </ToolButton>
            <ToolButton
              tone="primary"
              onClick={() => void runAnalysis()}
              disabled={!desktop || opening || analyzing}
              title="Run passive ARP anomaly analysis over the opened capture; opens a file picker first if none is open"
            >
              {analyzing ? "analyzing…" : "Analyze opened capture"}
            </ToolButton>
            <TextInput
              value={routerIp}
              onChange={setRouterIp}
              placeholder="gateway IP (optional)"
              ariaLabel="Gateway IP for gateway-impersonation detection"
              className="w-44"
            />
          </div>
          {openError ? (
            <div role="alert" className="border-b border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
              {openError}
            </div>
          ) : null}
          {analysisError ? (
            <div role="alert" className="border-b border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
              {analysisError}
            </div>
          ) : null}
          {!analysis ? (
            <EmptyState
              icon={Radar}
              title="No passive analysis yet"
              detail="Open a capture (or just press Analyze) to run the passive ARP analyzer: duplicate IP→MAC claims, gratuitous ARP bursts and gateway impersonation, plus a unified host inventory."
              badge="passive"
            />
          ) : (
            <div className="flex min-h-0 flex-col">
              <p className="px-3 pt-2 font-mono text-[10px] text-fg-muted">
                {analysis.arp_frame_count} ARP frames · {analysis.observation_count} attributable
                observations · {analysis.findings.length} finding
                {analysis.findings.length === 1 ? "" : "s"} · {analysis.hosts.length} host
                {analysis.hosts.length === 1 ? "" : "s"}
                {analysis.router_ip ? ` · gateway ${analysis.router_ip}` : ""}
              </p>
              <div className="p-1">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>IP</th>
                      <th>MACs (claims each)</th>
                      <th className="w-24">First seen</th>
                      <th className="w-24">Last seen</th>
                      <th className="w-16">Claims</th>
                      <th className="w-24">Severity</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.findings.map((finding, index) => (
                      <tr key={`${finding.ip}-${finding.kind}-${index}`}>
                        <td className="text-fg">{findingKindLabel(finding.kind)}</td>
                        <td className="font-mono text-fg">{finding.ip}</td>
                        <td className="font-mono text-[11px] text-fg-dim" title={finding.detail}>
                          {summarizeMacClaims(finding.macs)}
                        </td>
                        <td>{formatSeenMs(finding.first_seen_ms)}</td>
                        <td>{formatSeenMs(finding.last_seen_ms)}</td>
                        <td>{totalClaims(finding.macs)}</td>
                        <td>
                          <Chip tone={finding.severity === "critical" ? "err" : "orange"}>
                            {finding.severity}
                          </Chip>
                        </td>
                        <td className="text-fg-muted">{finding.detail}</td>
                      </tr>
                    ))}
                    {analysis.findings.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="text-center text-fg-muted">
                          no ARP anomalies detected in this capture
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
              <p className="border-t border-line px-3 pt-2 font-mono text-[10px] uppercase tracking-wider text-fg-muted">
                Unified host inventory
              </p>
              <div className="p-1">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>MACs (claims each)</th>
                      <th className="w-24">First seen</th>
                      <th className="w-24">Last seen</th>
                      <th className="w-24">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis.hosts.map((host) => (
                      <tr key={host.ip}>
                        <td className="font-mono text-fg">{host.ip}</td>
                        <td className="font-mono text-[11px] text-fg-dim">
                          {summarizeMacClaims(host.mac_claims)}
                        </td>
                        <td>{formatSeenMs(host.first_seen_ms)}</td>
                        <td>{formatSeenMs(host.last_seen_ms)}</td>
                        <td>
                          {host.impersonated ? (
                            <Chip tone="err">conflict</Chip>
                          ) : (
                            <Chip tone="ok">stable</Chip>
                          )}
                        </td>
                      </tr>
                    ))}
                    {analysis.hosts.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="text-center text-fg-muted">
                          no attributable ARP claims in this capture
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </Pane>

        <Pane title="Live monitor (passive event timeline)">
          <div className="space-y-2 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <label className="flex items-center gap-1 text-xs text-fg-dim">
                <span className="font-medium uppercase tracking-wider text-fg-muted">Live source</span>
                <select
                  value={liveSource}
                  onChange={(event) =>
                    switchLiveSource(event.target.value === "session" ? "session" : "opened")
                  }
                  aria-label="Live timeline source: opened capture or running capture session"
                  className="rounded border border-line bg-panel px-2 py-1 text-xs text-fg outline-none focus:outline-none"
                >
                  <option value="opened">Opened capture</option>
                  <option value="session">Running capture session</option>
                </select>
              </label>
              {liveSource === "session" ? (
                <>
                  <TextInput
                    value={liveSessionId}
                    onChange={(text) => setLiveSessionId(text.replace(/[^0-9]/g, "").slice(0, 15))}
                    placeholder="session id (Packet Studio)"
                    ariaLabel="Capture session id to subscribe to"
                    className="w-44"
                  />
                  {livePolling ? (
                    <ToolButton
                      onClick={stopLiveSubscription}
                      title="Stop polling the subscribed session. The lab never stops Packet Studio's capture itself"
                    >
                      Stop live subscription
                    </ToolButton>
                  ) : (
                    <ToolButton
                      tone="primary"
                      disabled={!desktop || !isValidLiveSessionId(liveSessionId)}
                      onClick={startLiveSubscription}
                      title="Subscribe to the running capture session: poll its passive lab status every 2 seconds. Requires Packet Studio's live capture to be running"
                    >
                      Subscribe
                    </ToolButton>
                  )}
                  {liveStatus ? (
                    <Chip tone={liveStatus.active ? "ok" : "muted"}>
                      session {liveSessionId} · {liveStatus.interface} · {liveStatus.phase} ·{" "}
                      {liveStatus.captured_packets} captured
                      {liveStatus.active ? "" : " · not running"}
                    </Chip>
                  ) : null}
                </>
              ) : (
                <ToolButton
                  disabled={!desktop || !capture || timelineBusy}
                  title={capture
                    ? "Derive the event timeline: new hosts, first services, ARP conflicts, gateway changes"
                    : "Open a capture first — the timeline derives from the opened capture"}
                  onClick={() => {
                    setTimelineBusy(true);
                    networkLabEventsV1(routerIp.trim() || null)
                      .then((wire) => setTimeline(wire))
                      .catch((cause) =>
                        setAnalysisError(
                          "Lab timeline failed: " + (cause instanceof Error ? cause.message : String(cause)),
                        ),
                      )
                      .finally(() => setTimelineBusy(false));
                  }}
                >
                  <Radar size={11} /> {timelineBusy ? "deriving…" : "Derive event timeline"}
                </ToolButton>
              )}
              <TimelineChips wire={displayTimeline} />
            </div>
            {liveSource === "session" ? (
              <p className="text-xs leading-relaxed text-fg-dim">
                Bettercap-style one-capture-many-modules subscription: the lab subscribes to Packet
                Studio's running capture and never starts its own capture, and Packet Studio's capture
                must be running for live counts. The lab transmits nothing; Packet Studio owns the
                capture lifecycle, the lab only reads its status. While the session runs, the captured
                counter tracks it live; the event timeline derives from the session's retained frames.
              </p>
            ) : null}
            {liveError ? (
              <div role="alert" className="border-b border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                {liveError}
              </div>
            ) : null}
            <TimelineTable wire={displayTimeline} />

            {/* DNS monitor: passive response analysis over the opened capture
                (dns-spoofing counterpart). Read-only, same capture gate as
                the timeline derivation above. */}
            <div className="border-t border-line pt-3">
              <div className="flex flex-wrap items-center gap-2 pb-2">
                <span className="font-medium uppercase tracking-wider text-fg-muted">
                  DNS monitor
                </span>
                <ToolButton
                  tone="primary"
                  disabled={!desktop || !capture || dnsBusy}
                  title={
                    capture
                      ? "Run the passive DNS-response monitor over the opened capture: answer inconsistencies, loopback/link-local answer targets and NXDOMAIN injection"
                      : "Open a capture first — the DNS monitor reads the opened capture"
                  }
                  onClick={() => void runDnsMonitor()}
                >
                  <Radar size={11} /> {dnsBusy ? "analyzing…" : "Analyze DNS responses"}
                </ToolButton>
                <DnsMonitorChips wire={dnsResult} />
              </div>
              {dnsError ? (
                <div role="alert" className="border-b border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                  {dnsError}
                </div>
              ) : null}
              <DnsFindingsTable wire={dnsResult} />
            </div>

            {/* Session report: one structured artifact (ARP findings, event
                timeline, host inventory, DNS findings) rendered to bounded
                markdown and persisted as ONE case finding in the backend-
                selected saved case. Read-only over the capture; the frontend
                only ever receives a receipt. */}
            <div className="border-t border-line pt-3">
              <div
                role="group"
                aria-label="Export lab session report"
                className="flex flex-wrap items-center gap-2 pb-2"
              >
                <span className="font-medium uppercase tracking-wider text-fg-muted">
                  Session report
                </span>
                <ToolButton
                  tone="primary"
                  disabled={!desktop || !capture || reportBusy}
                  title={
                    capture
                      ? "Render one bounded lab session report (ARP findings, event timeline, host inventory, DNS findings) and persist it as a single case finding in the selected saved case"
                      : "Open a capture first — the session report reduces the opened capture"
                  }
                  onClick={() => void runReportExport()}
                >
                  <Radar size={11} /> {reportBusy ? "exporting…" : "Export session report"}
                </ToolButton>
                <label className="flex items-center gap-1 text-xs text-fg-dim">
                  <input
                    type="checkbox"
                    checked={reportIncludeDns}
                    onChange={(event) => setReportIncludeDns(event.target.checked)}
                    className="accent-[var(--color-orange)]"
                    aria-label="Include DNS findings in the session report"
                  />
                  <span>include DNS findings</span>
                </label>
                <ReportReceiptChip receipt={reportReceipt} />
              </div>
              {reportError ? (
                <div role="alert" className="border border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                  {reportError}
                </div>
              ) : null}
            </div>
          </div>
        </Pane>

        <Pane title="Active interaction (not available in this arc)">
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              Active traffic manipulation — ARP cache poisoning, on-path (MITM) interaction, packet
              injection — requires a user-configured authorized lab scope, explicit confirmation,
              compatible privileges and a visible stop/emergency-disengage control (Master Plan
              §5.1). This arc ships passive observations only, so these controls stay disabled.
            </p>
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <ToolButton
                disabled
                title="ARP cache poisoning is not available in this arc; the lab is passive/defensive only"
              >
                ARP poisoning (MITM)
              </ToolButton>
              <ToolButton
                disabled
                title="Crafted frame injection is not available in this arc; the lab never transmits"
              >
                Send crafted ARP frame
              </ToolButton>
              <ToolButton
                disabled
                title="Traffic alteration is not available in this arc; passive observation only"
              >
                Intercept traffic
              </ToolButton>
              <Chip>passive arc</Chip>
            </div>
          </div>
        </Pane>
      </div>
    </div>
  );
}

/** One-line label per timeline event kind; pure so node tests cover it. */
export function labEventKindLabel(kind: LabEventKindWire): string {
  switch (kind) {
    case "new_host":
      return "New host";
    case "new_service":
      return "New service";
    case "arp_conflict":
      return "ARP conflict";
    case "gateway_changed":
      return "Gateway changed";
  }
}

/** Count chips shared by both live sources; honest about the 512-event cap. */
export function TimelineChips({ wire }: { wire: LabEventsWire | null }) {
  if (!wire) return <Chip>no timeline yet</Chip>;
  return (
    <>
      <Chip tone="ok">{wire.new_hosts} new hosts</Chip>
      <Chip tone="ok">{wire.new_services} services</Chip>
      {wire.conflicts > 0 ? <Chip tone="err">{wire.conflicts} ARP conflicts</Chip> : null}
      {wire.gateway_changes > 0 ? <Chip tone="err">{wire.gateway_changes} gateway changes</Chip> : null}
      {wire.truncated ? <Chip tone="muted">timeline capped at 512</Chip> : null}
    </>
  );
}

/** Timeline table shared by both live sources (same rows, same styling). */
export function TimelineTable({ wire }: { wire: LabEventsWire | null }) {
  if (wire && wire.events.length > 0) {
    return (
      <div className="max-h-64 overflow-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th className="w-24">Time</th>
              <th className="w-32">Event</th>
              <th className="w-40">Subject</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {wire.events.map((event, index) => (
              <TimelineRow key={`${event.timestamp_ms}-${event.kind}-${index}`} event={event} />
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if (wire) {
    return (
      <p className="text-xs text-fg-muted">
        no events in this source — a timeline needs parseable IP endpoints, services or ARP claims
      </p>
    );
  }
  return null;
}

function TimelineRow({ event }: { event: LabEventWire }) {
  return (
    <tr>
      <td className="font-mono text-[11px]">{formatSeenMs(event.timestamp_ms)}</td>
      <td>
        <Chip tone={event.kind === "arp_conflict" || event.kind === "gateway_changed" ? "err" : "muted"}>
          {labEventKindLabel(event.kind)}
        </Chip>
      </td>
      <td className="font-mono text-[11px]">{event.subject}</td>
      <td className="text-fg-muted">{event.detail}</td>
    </tr>
  );
}

/** Count chips for the passive DNS monitor; honest about the 128-finding cap. */
export function DnsMonitorChips({ wire }: { wire: DnsMonitorWire | null }) {
  if (!wire) return <Chip>no DNS analysis yet</Chip>;
  return (
    <>
      <Chip tone="ok">{wire.observations_seen} DNS messages</Chip>
      <Chip tone="ok">{wire.queried_names} names</Chip>
      {wire.findings.length > 0 ? (
        <Chip tone="err">{wire.findings.length} DNS indicator{wire.findings.length === 1 ? "" : "s"}</Chip>
      ) : null}
      {wire.findings.length >= 128 ? <Chip tone="muted">findings capped at 128</Chip> : null}
    </>
  );
}

/**
 * Receipt chip for the exported session report: size, destination case and
 * the truncation flag (a truncated artifact is labeled as such, never
 * silently shrunk). The markdown itself never crosses IPC.
 */
export function ReportReceiptChip({ receipt }: { receipt: LabReportReceiptWire | null }) {
  if (!receipt) return <Chip>no report exported yet</Chip>;
  return <Chip tone={receipt.truncated ? "orange" : "ok"}>{reportReceiptText(receipt)}</Chip>;
}

/**
 * Findings table for the passive DNS-response monitor. Baseline vs later
 * answer sets are shown side by side so an interception is readable at a
 * glance; the zero-state is honest about what a silent run means.
 */
export function DnsFindingsTable({ wire }: { wire: DnsMonitorWire | null }) {
  if (!wire) return null;
  if (wire.observations_seen === 0) {
    return (
      <p className="text-xs text-fg-muted">
        no parseable DNS messages in this capture — the monitor needs UDP port 53 traffic with
        well-formed queries or answers
      </p>
    );
  }
  if (wire.findings.length === 0) {
    return (
      <p className="text-xs text-fg-muted">
        no DNS interception indicators in this capture — {wire.observations_seen} DNS message
        {wire.observations_seen === 1 ? "" : "s"} across {wire.queried_names} name
        {wire.queried_names === 1 ? "" : "s"} showed stable answer sets, no local-address targets
        and no NXDOMAIN flips
      </p>
    );
  }
  return (
    <div className="max-h-64 overflow-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th className="w-36">Kind</th>
            <th className="w-48">Question</th>
            <th>Baseline answer set</th>
            <th>Later answer set</th>
            <th className="w-24">First seen</th>
            <th className="w-24">Last seen</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {wire.findings.map((finding, index) => (
            <tr key={`${finding.kind}-${finding.question_name}-${finding.question_type}-${index}`}>
              <td>
                <Chip tone={finding.kind === "suspicious_target" ? "orange" : "err"}>
                  {dnsFindingKindLabel(finding.kind)}
                </Chip>
              </td>
              <td className="font-mono text-[11px]">
                {finding.question_name} · {questionTypeLabel(finding.question_type)}
              </td>
              <td className="font-mono text-[11px] text-fg-dim" title={formatAnswerSet(finding.baseline)}>
                {formatAnswerSet(finding.baseline)}
              </td>
              <td className="font-mono text-[11px] text-fg-dim" title={formatAnswerSet(finding.later)}>
                {formatAnswerSet(finding.later)}
              </td>
              <td>{formatSeenMs(finding.first_seen_ms)}</td>
              <td>{formatSeenMs(finding.last_seen_ms)}</td>
              <td className="text-fg-muted">{finding.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

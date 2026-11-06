"use client";
/**
 * Network Lab (Ettercap-inspired mode, passive/defensive arc).
 *
 * UX revision: a compact left-aligned icon-only pill rail (34px buttons,
 * tooltip = label, active = orange filled pill) switches between five modes —
 * Scope, ARP, Live, DNS, Report — and exactly ONE mode renders at a time.
 * Each mode is one `SectionHeader` line (single state chip + InfoTip) above a
 * compact h-8 toolbar row and the results table; long explanations live in
 * InfoTip tooltips instead of body text, and no separator lines separate
 * toolbar rows. The active-interaction gate is a single strip line under the
 * rail (disabled control + passive-arc chip + InfoTip).
 *
 * Gates (unchanged, Master Plan §5.1): scope entries are IP/CIDR strings held
 * in memory only behind an explicit authorization checkbox; ARP analysis, the
 * DNS monitor and the event timeline are passive reductions over the opened
 * capture or a subscribed Packet Studio session; the lab never transmits.
 */
import { useEffect, useRef, useState } from "react";
import { Ban, Crosshair, FileText, FolderOpen, Globe, Network, Radar } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Chip, EmptyState, Select, TextInput, ToolButton } from "@ds/panes";
import { IconButton, InfoTip, SectionHeader, StatusStrip } from "@ds/compact";
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

/** Rail modes: one visible at a time (icon-only pill rail navigation). */
type LabMode = "scope" | "arp" | "live" | "dns" | "report";

/** Shared toolbar-row layout: h-8 controls, consistent gap, no separators. */
const TOOLBAR_ROW = "flex flex-wrap items-center gap-2 px-3 py-2";

export function NetworkLabView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const [mode, setMode] = useState<LabMode>("scope");
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

  // Rail badges: only state that demands attention gets a count.
  const arpConflicts = analysis
    ? analysis.hosts.filter((host) => host.impersonated).length
    : undefined;
  const liveGatewayChanges =
    displayTimeline && displayTimeline.gateway_changes > 0
      ? displayTimeline.gateway_changes
      : undefined;
  const dnsFindings =
    dnsResult && dnsResult.findings.length > 0 ? dnsResult.findings.length : undefined;
  const railItems: { id: LabMode; label: string; icon: LucideIcon; badge?: number }[] = [
    { id: "scope", label: "Scope", icon: Crosshair },
    { id: "arp", label: "ARP", icon: Network, badge: arpConflicts },
    { id: "live", label: "Live", icon: Radar, badge: liveGatewayChanges },
    { id: "dns", label: "DNS", icon: Globe, badge: dnsFindings },
    { id: "report", label: "Report", icon: FileText },
  ];
  const dnsState = !dnsResult
    ? "no analysis"
    : dnsResult.findings.length > 0
      ? `${dnsResult.findings.length} finding${dnsResult.findings.length === 1 ? "" : "s"}`
      : "clean";
  const dnsStateTone = !dnsResult ? "muted" : dnsResult.findings.length > 0 ? "err" : "ok";
  const liveState =
    liveSource === "session"
      ? livePolling
        ? liveStatus?.active
          ? "live"
          : "idle"
        : "not subscribed"
      : timeline
        ? "derived"
        : "no timeline";
  const liveStateTone =
    liveSource === "session" && livePolling && liveStatus?.active ? "ok" : "muted";
  const liveStripItems = [
    liveSource === "session" && liveStatus
      ? {
          label: `session ${liveSessionId} · ${liveStatus.interface} · ${liveStatus.phase} · ${liveStatus.captured_packets} captured${liveStatus.active ? "" : " · not running"}`,
          tone: liveStatus.active ? ("ok" as const) : ("muted" as const),
        }
      : null,
    ...timelineStatusItems(displayTimeline),
  ];
  // The lab needs a saved, backend-selected case for the sweep and the
  // report export; case management itself lives in the Case section only.
  const needsSavedCase = wb.caseId === "scratchpad" || wb.caseId.trim().length === 0;

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
    <div className="flex h-full min-h-0 flex-col bg-app">
      {/* Icon-only pill rail: 34px square buttons, tooltip = label, active =
          orange filled pill. Left-aligned; no tab underline, no full-width
          stretch, no labels under the icons. */}
      <nav aria-label="Network Lab modes" className="flex shrink-0 items-center gap-1 px-3 pb-1 pt-2">
        {railItems.map((item) => {
          const Icon = item.icon;
          const activeMode = item.id === mode;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setMode(item.id)}
              aria-pressed={activeMode}
              aria-label={item.label}
              title={item.label}
              className={`relative inline-flex h-[34px] w-[34px] items-center justify-center rounded-full transition-colors focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring ${
                activeMode ? "bg-orange text-white" : "text-fg-muted hover:bg-line/60 hover:text-fg"
              }`}
            >
              <Icon size={16} strokeWidth={activeMode ? 2 : 1.5} />
              {item.badge !== undefined && item.badge > 0 ? (
                <span className="absolute -right-1.5 -top-1.5 min-w-3.5 rounded-full bg-err px-1 text-center font-mono text-[9px] leading-3.5 text-white">
                  {item.badge}
                </span>
              ) : null}
            </button>
          );
        })}
      </nav>
      {/* Active interaction gate: ONE strip line instead of a pane of three
          inert buttons. The full gate wording lives in the InfoTip. */}
      <div
        role="group"
        aria-label="Active interaction (not available in this arc)"
        className="flex shrink-0 items-center gap-2 px-3 pb-1"
      >
        <IconButton
          icon={Ban}
          disabled
          title="ARP cache poisoning (MITM), crafted frame injection and traffic alteration are not available in this arc; the lab is passive/defensive only and never transmits"
        />
        <Chip>passive arc</Chip>
        <InfoTip text="Active traffic manipulation — ARP cache poisoning, on-path (MITM) interaction, packet injection — requires a user-configured authorized lab scope, explicit confirmation, compatible privileges and a visible stop/emergency-disengage control (Master Plan §5.1). This arc ships passive observations only, so these controls stay disabled." />
        <span className="flex-1" />
        <Chip tone="ok">passive observations only</Chip>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {mode === "scope" && (
          <section aria-label="Lab scope" className="flex min-h-0 flex-col pb-6">
            <SectionHeader
              icon={Crosshair}
              title="Lab scope"
              state={scopeSummary(scope)}
              stateTone={scope?.authorized ? "orange" : "muted"}
              info="Ettercap-inspired lab mode inside Packet Studio: unified host inventory, passive ARP anomaly analysis and passive DNS-response monitoring over already-captured frames. The lab reads captures and never transmits packets; scope entries are IP/CIDR strings held in memory only and are never persisted (Master Plan §5.1)."
            />
            <div className="grid gap-3 px-3 pb-1 md:grid-cols-2">
              <label className="block text-xs text-fg-dim">
                <span className="mb-1 block font-medium text-fg-muted">Target 1</span>
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
                <span className="mb-1 block font-medium text-fg-muted">Target 2</span>
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
            <div className={TOOLBAR_ROW}>
              <label className="flex items-center gap-1.5 text-xs text-fg-dim">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(event) => setAuthorized(event.target.checked)}
                  className="accent-[var(--color-orange)]"
                />
                <span>I am authorized to assess this scope</span>
              </label>
              <InfoTip text="I confirm this lab scope is mine or I have explicit authorization to assess it. The scope is validated, capped at 64 entries per target group and held in memory only." />
              <ToolButton
                tone="primary"
                onClick={() => void applyScope()}
                disabled={!desktop || !authorized || scopeBusy}
                title="Validate and store the lab scope in memory; requires the authorization checkbox"
              >
                Set scope
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
            <div className="px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-medium text-fg-muted">ARP sweep</span>
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
                    title="Linux only: ARP sweep (Target 1 ∪ Target 2) probes ONLY the IPv4 targets resolved from the saved lab scope, at most 32 probes at 10/s, native confirmation and CAP_NET_RAW required; refuses anything outside the declared scope"
                  >
                    Sweep
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
              {needsSavedCase ? (
                <p className="pt-1 text-[10px] text-fg-muted">
                  Select a case in the Case section — lab ARP sweeps require a saved case.
                </p>
              ) : null}
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
          </section>
        )}

        {mode === "arp" && (
          <section aria-label="ARP analysis" className="flex min-h-0 flex-col pb-6">
            <SectionHeader
              icon={Network}
              title="ARP analysis"
              state={
                capture
                  ? `${capture.file_name} · ${capture.format.toUpperCase()} · ${capture.packet_count} packets`
                  : "no capture"
              }
              stateTone={capture ? "ok" : "muted"}
              info="Passive ARP anomaly analysis over the opened capture: duplicate IP→MAC claims, gratuitous ARP bursts and gateway impersonation, plus a unified host inventory. The analyzer never transmits a packet."
            />
            <div className={TOOLBAR_ROW}>
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
                {analyzing ? "analyzing…" : "Analyze"}
              </ToolButton>
              <TextInput
                value={routerIp}
                onChange={setRouterIp}
                placeholder="gateway IP (optional)"
                ariaLabel="Gateway IP for gateway-impersonation detection"
                className="h-8 w-44 sm:h-7"
              />
            </div>
            {openError ? (
              <div role="alert" className="mx-3 border border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                {openError}
              </div>
            ) : null}
            {analysisError ? (
              <div role="alert" className="mx-3 border border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                {analysisError}
              </div>
            ) : null}
            {!analysis ? (
              <EmptyState
                icon={Radar}
                title="No passive analysis yet"
                detail="Open a capture or press Analyze — the passive analyzer runs over the opened capture."
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
                <p className="px-3 pb-1 pt-3 text-[11px] font-semibold text-fg-muted">
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
          </section>
        )}

        {mode === "live" && (
          <section aria-label="Live monitor" className="flex min-h-0 flex-col pb-6">
            <SectionHeader
              icon={Radar}
              title="Live monitor"
              state={liveState}
              stateTone={liveStateTone}
              info="Bettercap-style one-capture-many-modules subscription: the lab subscribes to Packet Studio's running capture and never starts its own capture, and Packet Studio's capture must be running for live counts. The lab transmits nothing; Packet Studio owns the capture lifecycle, the lab only reads its status. While the session runs, the captured counter tracks it live; the event timeline derives from the session's retained frames."
            />
            <div className={TOOLBAR_ROW}>
              <label className="flex items-center gap-1.5 text-xs text-fg-dim">
                <span className="text-fg-muted">Source</span>
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
                    className="h-8 w-44 sm:h-7"
                  />
                  {livePolling ? (
                    <ToolButton
                      onClick={stopLiveSubscription}
                      title="Stop polling the subscribed session. The lab never stops Packet Studio's capture itself"
                    >
                      Stop
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
                  {timelineBusy ? "deriving…" : "Derive timeline"}
                </ToolButton>
              )}
            </div>
            {liveError ? (
              <div role="alert" className="mx-3 border border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                {liveError}
              </div>
            ) : null}
            <StatusStrip items={liveStripItems} />
            {!displayTimeline ? (
              <EmptyState
                icon={Radar}
                title="No timeline yet"
                detail="Derive from the opened capture or subscribe to a running session."
                badge="passive"
              />
            ) : null}
            <TimelineTable wire={displayTimeline} />
          </section>
        )}

        {mode === "dns" && (
          <section aria-label="DNS monitor" className="flex min-h-0 flex-col pb-6">
            <SectionHeader
              icon={Globe}
              title="DNS monitor"
              state={dnsState}
              stateTone={dnsStateTone}
              info="Passive DNS-response monitor over the opened capture (dns-spoofing counterpart): answer inconsistencies, loopback/link-local answer targets and NXDOMAIN injection. Read-only — the monitor reads the opened capture and never transmits anything."
            />
            <div className={TOOLBAR_ROW}>
              {!capture ? (
                <ToolButton
                  onClick={() => void openCapture()}
                  disabled={!desktop || opening}
                  title={desktop ? "Open a PCAP or PCAPNG capture using the native Rust parser" : "Opening captures requires the desktop runtime"}
                >
                  <FolderOpen size={11} /> Open capture…
                </ToolButton>
              ) : null}
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
                {dnsBusy ? "analyzing…" : "Analyze DNS"}
              </ToolButton>
            </div>
            {dnsError ? (
              <div role="alert" className="mx-3 border border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                {dnsError}
              </div>
            ) : null}
            <StatusStrip items={dnsStatusItems(dnsResult)} />
            {!dnsResult ? (
              <EmptyState
                icon={Globe}
                title="No DNS analysis yet"
                detail="Run the monitor over the opened capture."
                badge="passive"
              />
            ) : null}
            <DnsFindingsTable wire={dnsResult} />
          </section>
        )}

        {mode === "report" && (
          <section aria-label="Session report" className="flex min-h-0 flex-col pb-6">
            {/* lab-report-ui.test.mjs pins this span (exact className + text)
                and the border-t group wrapper below verbatim; the span doubles
                as this mode's one-line title, so the mode shows ONE label
                instead of a header plus a group-label pair. */}
            <div className="flex shrink-0 items-center gap-2 px-3 py-1.5">
              <FileText size={13} strokeWidth={1.5} className="shrink-0 text-fg-muted" />
              <span className="font-medium uppercase tracking-wider text-fg-muted">Session report</span>
              <InfoTip text="One structured artifact (ARP findings, event timeline, host inventory, DNS findings) rendered to bounded markdown and persisted as ONE case finding in the backend-selected saved case. Read-only over the capture; the frontend only ever receives a receipt." />
              <span className="flex-1" />
            </div>
            <div className="border-t border-line pt-3">
              <div
                role="group"
                aria-label="Export lab session report"
                className={TOOLBAR_ROW}
              >
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
                  {reportBusy ? "exporting…" : "Export session report"}
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
                <div role="alert" className="mx-3 border border-err/50 bg-err/10 px-3 py-1 font-mono text-[10px] text-err">
                  {reportError}
                </div>
              ) : null}
              {needsSavedCase ? (
                <p className="px-3 pb-2 text-[10px] text-fg-muted">
                  Select a case in the Case section — the report is persisted as case evidence.
                </p>
              ) : null}
            </div>
          </section>
        )}
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

/**
 * StatusStrip items shared by both live sources; honest about the 512-event
 * cap. Empty until a source has data — the section header carries the
 * "no timeline" state instead of a stray chip.
 */
export function timelineStatusItems(wire: LabEventsWire | null) {
  if (!wire) return [];
  return [
    { label: `${wire.new_hosts} new hosts`, tone: "ok" as const },
    { label: `${wire.new_services} services`, tone: "ok" as const },
    wire.conflicts > 0 ? { label: `${wire.conflicts} ARP conflicts`, tone: "err" as const } : null,
    wire.gateway_changes > 0
      ? { label: `${wire.gateway_changes} gateway changes`, tone: "err" as const }
      : null,
    wire.truncated ? { label: "timeline capped at 512", tone: "muted" as const } : null,
  ];
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
      <p className="px-3 text-xs text-fg-muted">
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

/**
 * Count items for the passive DNS monitor's StatusStrip; honest about the
 * 128-finding cap. Empty until a run exists — the section header carries the
 * "no analysis" state.
 */
export function dnsStatusItems(wire: DnsMonitorWire | null) {
  if (!wire) return [];
  return [
    { label: `${wire.observations_seen} DNS messages`, tone: "ok" as const },
    { label: `${wire.queried_names} names`, tone: "ok" as const },
    wire.findings.length > 0
      ? {
          label: `${wire.findings.length} DNS indicator${wire.findings.length === 1 ? "" : "s"}`,
          tone: "err" as const,
        }
      : null,
    wire.findings.length >= 128 ? { label: "findings capped at 128", tone: "muted" as const } : null,
  ];
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
      <p className="px-3 text-xs text-fg-muted">
        no parseable DNS messages in this capture — the monitor needs UDP port 53 traffic with
        well-formed queries or answers
      </p>
    );
  }
  if (wire.findings.length === 0) {
    return (
      <p className="px-3 text-xs text-fg-muted">
        no DNS interception indicators in this capture — {wire.observations_seen} DNS message
        {wire.observations_seen === 1 ? "" : "s"} across {wire.queried_names} name
        {wire.queried_names === 1 ? "" : "s"} showed stable answer sets, no local-address targets
        and no NXDOMAIN flips
      </p>
    );
  }
  return (
    <div className="max-h-64 overflow-auto px-3">
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

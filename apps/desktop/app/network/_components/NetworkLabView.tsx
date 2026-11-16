"use client";
/**
 * Network Lab (Ettercap-inspired mode, passive/defensive arc).
 *
 * UX revision: every mode renders through the shared WorkspaceShell — the
 * IconRail pill rail sits in the shell's rail slot (icon-only pills,
 * tooltip = label, active pill, no tab underline), per-mode controls move to
 * the toolbar slot once data exists, and status chips render in the
 * StatusStrip slot. Exactly one of Scope, ARP, Live, DNS, Spoof, Report
 * renders at a time. Scope is the exemplar: controls live INSIDE the shared
 * ModeCard (state chip header, InfoTip with the honesty wording, panel with
 * the controls); ARP, Live and DNS use the same shared ModeCard when idle and
 * switch to the shell toolbar row (only the still-needed controls) above
 * full-width result tables once data exists. The active-interaction gate
 * cluster lives only in the Scope mode. Long explanations are card InfoTips,
 * never body prose walls.
 *
 * Gates (unchanged, Master Plan §5.1): scope entries are IP/CIDR strings held
 * in memory only; the authorization acknowledgment happens through the
 * backend's native confirmation dialogs, not on-screen checkbox chrome; ARP
 * analysis, the DNS monitor and the event timeline are passive reductions
 * over the opened capture or a subscribed Packet Studio session. The two
 * ACTIVE exceptions are explicitly scoped and dialog-gated: the lab ARP sweep
 * and the Spoof mode (full-duplex ARP cache poisoning) transmit ONLY to
 * addresses the backend resolved from the saved lab scope, and nothing else
 * in this view ever transmits.
 */
import { useEffect, useRef, useState } from "react";
import { Ban, Crosshair, FileText, FolderOpen, Globe, Network, Radar } from "lucide-react";
import { Syringe } from "lucide-react";
import { Wifi } from "lucide-react";
import { Server, ArrowLeftRight } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { CheckBox, Chip, Select, TextArea, TextInput, ToolButton } from "@ds/panes";
import { ErrorStrip, IconRail, IconButton, InfoTip, ModeCard, StatusStrip, WorkspaceShell } from "@ds/compact";
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
import {
  networkLabSpoofStartV1,
  networkLabSpoofStopV1,
  networkLabSpoofStatusV1,
  type SpoofStartWire,
  type SpoofStatusWire,
} from "@lib/ipc";
import {
  networkWifiEvidenceSaveV1,
  networkWifiInterfacesV1,
  networkWifiMonitorStartV1,
  networkWifiMonitorStatusV1,
  networkWifiMonitorStopV1,
  type WifiEvidenceReceiptWire,
  type WifiInterfacesWire,
  type WifiStatusWire,
} from "@lib/ipc";
import {
  networkDnsSpoofEvidenceSaveV1,
  networkDnsSpoofStartV1,
  networkDnsSpoofStatusV1,
  networkDnsSpoofStopV1,
  type DnsSpoofEvidenceReceiptWire,
  type DnsSpoofStartWire,
  type DnsSpoofStatusWire,
} from "@lib/ipc";
import {
  networkHttpProxyEvidenceSaveV1,
  networkHttpProxyStartV1,
  networkHttpProxyStatusV1,
  networkHttpProxyStopV1,
  type HttpProxyEvidenceReceiptWire,
  type HttpProxyStartWire,
  type HttpProxyStatusWire,
} from "@lib/ipc";

const SCOPE_TEXT_MAX_CHARS = 8192;

/** Rail modes: one visible at a time (icon-only pill rail navigation). */
type LabMode = "scope" | "arp" | "live" | "dns" | "wifi" | "spoof" | "dns_spoof" | "http_proxy" | "report";

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
  // Bettercap-parity ARP spoof (the arc's second ACTIVE command, gated like
  // the sweep): the backend resolves targets from the saved scope alone, the
  // native dialog is the authorization, and the view only ever reads honest
  // status back — it never widens the scope.
  const [spoofGateway, setSpoofGateway] = useState("");
  const [spoofTargetCount, setSpoofTargetCount] = useState("1");
  const [spoofRate, setSpoofRate] = useState("1");
  const [spoofBusy, setSpoofBusy] = useState(false);
  const [spoofStart, setSpoofStart] = useState<SpoofStartWire | null>(null);
  const [spoofStatus, setSpoofStatus] = useState<SpoofStatusWire | null>(null);
  const [spoofError, setSpoofError] = useState<string | null>(null);
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

  const [proxyPort, setProxyPort] = useState("8080");
  const [proxyRewriteHttps, setProxyRewriteHttps] = useState(false);
  const [proxyStripHsts, setProxyStripHsts] = useState(false);
  const [proxyStripCsp, setProxyStripCsp] = useState(false);
  const [proxyAllowlist, setProxyAllowlist] = useState("");
  const [proxyBusy, setProxyBusy] = useState(false);
  const [proxyStart, setProxyStart] = useState<HttpProxyStartWire | null>(null);
  const [proxyStatus, setProxyStatus] = useState<HttpProxyStatusWire | null>(null);
  const [proxyReceipt, setProxyReceipt] = useState<HttpProxyEvidenceReceiptWire | null>(null);
  const [proxyError, setProxyError] = useState<string | null>(null);
  // Wifi monitor mode (the arc's passive 802.11 capture): the backend owns
  // the radio control (Linux nl80211), the native dialog is the
  // authorization, and the view only ever reads honest status back — it
  // never widens channels or invents platform support. The interface list
  // carries the honest platform status (monitor_supported, and Npcap
  // presence reported on Windows without pretending it is support).
  const [wifiInterfaces, setWifiInterfaces] = useState<WifiInterfacesWire | null>(null);
  const [wifiInterface, setWifiInterface] = useState("");
  const [wifiChannels, setWifiChannels] = useState("1,6,11");
  const [wifiBusy, setWifiBusy] = useState(false);
  const [wifiStatus, setWifiStatus] = useState<WifiStatusWire | null>(null);
  const [wifiReceipt, setWifiReceipt] = useState<WifiEvidenceReceiptWire | null>(null);
  const [wifiError, setWifiError] = useState<string | null>(null);
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
    // The spoof's case-revision ownership is revoked with the case too, so
    // per-run spoof state never survives into the new revision.
    setSpoofBusy(false);
    setSpoofStart(null);
    setSpoofStatus(null);
    setSpoofError(null);
    setDnsSpoofBusy(false);
    setDnsSpoofStart(null);
    setDnsSpoofStatus(null);
    setDnsSpoofReceipt(null);
    setDnsSpoofError(null);
    setProxyBusy(false);
    setProxyStart(null);
    setProxyStatus(null);
    setProxyReceipt(null);
    setProxyError(null);
    // The wifi monitor's capture session is case-owned on the backend (the
    // pump stops honestly on revocation), so per-run wifi state never
    // survives into the new revision either.
    setWifiBusy(false);
    setWifiStatus(null);
    setWifiReceipt(null);
    setWifiError(null);
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
  const wifiHandshakeBadge =
    wifiStatus && wifiStatus.handshakes_captured > 0 ? wifiStatus.handshakes_captured : undefined;
  const railItems: { id: LabMode; label: string; icon: LucideIcon; badge?: number }[] = [
    { id: "scope", label: "Scope", icon: Crosshair },
    { id: "arp", label: "ARP", icon: Network, badge: arpConflicts },
    { id: "live", label: "Live", icon: Radar, badge: liveGatewayChanges },
    { id: "dns", label: "DNS", icon: Globe, badge: dnsFindings },
    { id: "wifi", label: "Wifi", icon: Wifi, badge: wifiHandshakeBadge },
    { id: "spoof", label: "Spoof", icon: Syringe },
    { id: "dns_spoof", label: "DNS Spoof", icon: Server },
    { id: "http_proxy", label: "HTTP Proxy", icon: ArrowLeftRight },
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

  // Active interaction gate: ONE compact cluster, rendered only in the Scope
  // mode (where the gated sweep lives) — no repetition across mode rows. The
  // full Master Plan gate wording lives in the InfoTip.
  const gateCluster = (
    <>
      <IconButton
        icon={Ban}
        disabled
        title="ARP cache poisoning (MITM), crafted frame injection and traffic alteration are not available in this arc; the lab is passive/defensive only and never transmits"
      />
      <Chip>passive arc</Chip>
      <InfoTip text="Active traffic manipulation — ARP cache poisoning, on-path (MITM) interaction, packet injection — requires a user-configured authorized lab scope, explicit confirmation, compatible privileges and a visible stop/emergency-disengage control (Master Plan §5.1). This arc ships passive observations only, so these controls stay disabled." />
    </>
  );

  // ARP controls: shared by the idle control card and the data-state toolbar
  // (open a different capture, re-analyze, refine the gateway hint).
  const arpControls = (
    <>
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
    </>
  );

  // Live controls: shared by the idle control card and the data-state toolbar
  // (switch the source, re-derive, subscribe or stop the subscription).
  const liveControls = (
    <>
      <label className="flex items-center gap-1.5 text-xs text-fg-dim">
        <span className="text-fg-muted">Source</span>
        <Select
          value={liveSource}
          onChange={(value) =>
            switchLiveSource(value === "session" ? "session" : "opened")
          }
          ariaLabel="Live timeline source: opened capture or running capture session"
          options={[
            { value: "opened", label: "Opened capture" },
            { value: "session", label: "Running capture session" },
          ]}
          className="w-44 sm:h-7"
        />
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
    </>
  );

  // DNS controls: shared by the idle control card and the data-state toolbar.
  const dnsControls = (
    <>
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
    </>
  );

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
        true,
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
      const rows = await networkLabArpSweepV1(sweepInterface, true, caseId, (progress) => {
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

  // Spoof lifecycle: start → backend native dialog → poll honest counters
  // (1s) while starting/spoofing/stopping → stop (never refused) → stopped
  // state shows the backend-rendered restoration summary.
  const spoofPhase = spoofStatus?.state ?? "idle";
  const spoofActive =
    spoofPhase === "starting" || spoofPhase === "spoofing" || spoofPhase === "stopping";
  const spoofBlock = spoofBlockReason(scope);

  useEffect(() => {
    if (!desktop || !spoofActive) return;
    let cancelled = false;
    const timer = setInterval(() => {
      networkLabSpoofStatusV1()
        .then((wire) => {
          if (!cancelled) setSpoofStatus(wire);
        })
        .catch(() => {
          // A failed poll keeps the last honest status; the next tick retries.
        });
    }, 1000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [desktop, spoofPhase, spoofActive]);

  const runSpoofStart = async () => {
    const rate = parseSpoofRate(spoofRate);
    const count = parseSpoofTargetCount(spoofTargetCount);
    if (rate === null || count === null || !spoofGateway) return;
    setSpoofBusy(true);
    setSpoofError(null);
    try {
      const wire = await networkLabSpoofStartV1(
        sweepInterface,
        spoofGateway,
        count,
        rate,
        true,
        wb.caseId,
      );
      setSpoofStart(wire);
      setSpoofStatus(wire.status);
    } catch (err) {
      setSpoofError(err instanceof Error ? err.message : String(err));
    } finally {
      setSpoofBusy(false);
    }
  };

  const stopSpoof = async () => {
    try {
      await networkLabSpoofStopV1();
    } catch (err) {
      setSpoofError(err instanceof Error ? err.message : String(err));
    }
  };

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
        parseDnsSpoofDomains(dnsSpoofDomains) ?? [],
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

  const proxyEvidenceTicket = useRef(0);

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

  const proxyPhase = proxyStatus?.state ?? "idle";
  const proxyActive =
    proxyPhase === "starting" || proxyPhase === "serving" || proxyPhase === "stopping";
  const proxySaved = proxyReceipt !== null;

  useEffect(() => {
    if (!desktop || !proxyActive) return;
    const timer = setInterval(() => {
      networkHttpProxyStatusV1()
        .then((wire) => {
          setProxyStatus(wire);
        })
        .catch(() => {
          // A failed poll keeps the last honest status; the next tick retries.
        });
    }, 1000);
    return () => clearInterval(timer);
  }, [desktop, proxyPhase, proxyActive]);

  const runProxyStart = async () => {
    const port = parseProxyPort(proxyPort);
    const allowlist = parseProxyAllowlist(proxyAllowlist);
    if (port === null || allowlist === null || !desktop) return;
    setProxyBusy(true);
    setProxyError(null);
    try {
      const wire = await networkHttpProxyStartV1(
        port,
        proxyRewriteHttps,
        proxyStripHsts,
        proxyStripCsp,
        allowlist,
        true,
        wb.caseId,
      );
      setProxyStart(wire);
      setProxyStatus(wire.status);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setProxyError(message);
    } finally {
      setProxyBusy(false);
    }
  };

  const stopProxy = async () => {
    setProxyBusy(true);
    try {
      const wire = await networkHttpProxyStopV1();
      setProxyStatus(wire);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message !== "cancelled") setProxyError(message);
    } finally {
      setProxyBusy(false);
    }
  };

  const runProxyEvidenceSave = async () => {
    if (proxySaved || proxyBusy || !desktop) return;
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setProxyBusy(true);
    setProxyError(null);
    try {
      const wire = await networkHttpProxyEvidenceSaveV1(caseId);
      if (!isCurrent()) return;
      setProxyReceipt(wire);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setProxyError(message);
    } finally {
      if (isCurrent()) setProxyBusy(false);
    }
  };



const DNS_SPOOF_ALLOWLIST_MAX_CHARS = 2048;


  // Wifi monitor lifecycle: enumerate interfaces + honest platform status on
  // mount, start → backend native dialog → poll honest counters (1s) while
  // starting/monitoring/stopping → stop (never refused) → save the session's
  // hashcat 22000 lines as ONE bounded case finding.
  useEffect(() => {
    if (!desktop) return;
    let active = true;
    void networkWifiInterfacesV1()
      .then((wire) => {
        if (!active) return;
        setWifiInterfaces(wire);
        setWifiInterface((current) =>
          current || (wire.interfaces.length > 0 ? wire.interfaces[0].name : ""),
        );
      })
      .catch(() => {
        // The next explicit action surfaces the failure; the card keeps its
        // honest "unknown platform" state instead of inventing support.
        if (active) setWifiInterfaces(null);
      });
    return () => {
      active = false;
    };
  }, [desktop]);

  const wifiPhase = wifiStatus?.state ?? "idle";
  const wifiActive =
    wifiPhase === "starting" || wifiPhase === "monitoring" || wifiPhase === "stopping";
  const wifiBlock = wifiPlatformBlock(wifiInterfaces);
  const wifiSaved = wifiReceipt !== null;

  useEffect(() => {
    if (!desktop || !wifiActive) return;
    const timer = setInterval(() => {
      networkWifiMonitorStatusV1()
        .then((wire) => {
          setWifiStatus(wire);
        })
        .catch(() => {
          // A failed poll keeps the last honest status; the next tick retries.
        });
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [desktop, wifiPhase, wifiActive]);

  const runWifiStart = async () => {
    const channels = parseWifiChannels(wifiChannels);
    if (!wifiInterface || channels === null) return;
    setWifiBusy(true);
    setWifiError(null);
    try {
      const wire = await networkWifiMonitorStartV1(wifiInterface, wifiChannels, true, wb.caseId);
      setWifiStatus(wire.status);
      // A new capture session has its own one-save evidence slot.
      setWifiReceipt(null);
    } catch (err) {
      setWifiError(err instanceof Error ? err.message : String(err));
    } finally {
      setWifiBusy(false);
    }
  };

  const stopWifi = async () => {
    try {
      await networkWifiMonitorStopV1();
    } catch (err) {
      setWifiError(err instanceof Error ? err.message : String(err));
    }
  };

  const runWifiEvidenceSave = async () => {
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setWifiBusy(true);
    setWifiError(null);
    try {
      const wire = await networkWifiEvidenceSaveV1(caseId);
      if (!isCurrent()) return;
      setWifiReceipt(wire);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setWifiError(message);
    } finally {
      if (isCurrent()) setWifiBusy(false);
    }
  };

  // Shell toolbar row per mode: once a run exists the still-needed controls
  // move up here (the idle card holds them inside the shared ModeCard); the
  // trailing chip carries the run's state word.
  const toolbar =
    mode === "arp" && analysis ? (
      <>
        {arpControls}
        <span className="flex-1" />
        <Chip tone={capture ? "ok" : "muted"}>
          {capture
            ? `${capture.file_name} · ${capture.format.toUpperCase()} · ${capture.packet_count} packets`
            : "no capture"}
        </Chip>
      </>
    ) : mode === "live" && displayTimeline ? (
      <>
        {liveControls}
        <span className="flex-1" />
        <Chip tone={liveStateTone}>{liveState}</Chip>
      </>
    ) : mode === "dns" && dnsResult ? (
      <>
        {dnsControls}
        <span className="flex-1" />
        <Chip tone={dnsStateTone}>{dnsState}</Chip>
      </>
    ) : undefined;

  // Status chips row per mode (muted strip under the toolbar row); both
  // strips hide themselves while the mode has no run state to report.
  const status =
    mode === "live" ? (
      <StatusStrip items={liveStripItems} />
    ) : mode === "dns" ? (
      <StatusStrip items={dnsStatusItems(dnsResult)} />
    ) : undefined;

  return (
    <WorkspaceShell
      rail={
        <IconRail
          items={railItems}
          active={mode}
          onChange={(id) => setMode(id as LabMode)}
          ariaLabel="Network Lab modes"
        />
      }
      toolbar={toolbar}
      status={status}
      contentClassName="flex flex-col"
    >
      {mode === "scope" && (
        <section aria-label="Lab scope" className="flex min-h-0 flex-1 flex-col">
          <ModeCard
            title="Lab scope"
            icon={Crosshair}
            state={scopeSummary(scope)}
            stateTone={scope?.authorized ? "orange" : "muted"}
            info="Passive lab over already-captured frames — reads captures, never transmits packets; scope entries are held in memory only."
          >
            <div className="grid gap-3 md:grid-cols-2">
              <label className="block text-xs text-fg-dim">
                <span className="mb-1 block font-medium text-fg-muted">Target 1</span>
                <TextArea
                  value={targetsT1}
                  onChange={(value) => setTargetsT1(value.slice(0, SCOPE_TEXT_MAX_CHARS))}
                  maxLength={SCOPE_TEXT_MAX_CHARS}
                  ariaLabel="Target 1 scope: IP or CIDR entries separated by commas or newlines"
                  placeholder={"192.168.1.0/24\n10.0.0.5"}
                  rows={4}
                  className="h-24"
                />
              </label>
              <label className="block text-xs text-fg-dim">
                <span className="mb-1 block font-medium text-fg-muted">Target 2</span>
                <TextArea
                  value={targetsT2}
                  onChange={(value) => setTargetsT2(value.slice(0, SCOPE_TEXT_MAX_CHARS))}
                  maxLength={SCOPE_TEXT_MAX_CHARS}
                  ariaLabel="Target 2 scope: IP or CIDR entries separated by commas or newlines"
                  placeholder={"192.168.1.1"}
                  rows={4}
                  className="h-24"
                />
              </label>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <ToolButton
                tone="primary"
                onClick={() => void applyScope()}
                disabled={!desktop || scopeBusy}
                title="Validate and store the lab scope in memory (capped at 64 entries per target group, held in memory only)"
              >
                Set scope
              </ToolButton>
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
                  disabled={!desktop || !sweepInterface || sweepBlock !== null}
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
              {gateCluster}
            </div>
            {sweepError ? <ErrorStrip>{sweepError}</ErrorStrip> : null}
            {sweepResults ? (
              sweepResults.length === 0 ? (
                <p className="text-xs text-fg-muted">
                  no hosts answered the authorized lab ARP sweep — silence is not evidence of
                  absence; the sweep probed only the saved lab scope
                </p>
              ) : (
                <div className="max-h-64 overflow-auto rounded-lg border border-line">
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
          </ModeCard>
        </section>
      )}

      {mode === "arp" && (
        <section aria-label="ARP analysis" className="flex min-h-0 flex-1 flex-col">
          {openError ? <ErrorStrip>{openError}</ErrorStrip> : null}
          {analysisError ? <ErrorStrip>{analysisError}</ErrorStrip> : null}
          {!analysis ? (
            <ModeCard
              title="ARP analysis"
              icon={Network}
              state={
                capture
                  ? `${capture.file_name} · ${capture.format.toUpperCase()} · ${capture.packet_count} packets`
                  : "no capture"
              }
              stateTone={capture ? "ok" : "muted"}
              info="Passive ARP anomaly analysis over the opened capture — read-only, transmits nothing."
            >
              <div className="flex flex-wrap items-center gap-3">{arpControls}</div>
            </ModeCard>
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto pb-4">
              <p className="px-3 pt-2 font-mono text-3xs text-fg-muted">
                {analysis.arp_frame_count} ARP frames · {analysis.observation_count} attributable
                observations · {analysis.findings.length} finding
                {analysis.findings.length === 1 ? "" : "s"} · {analysis.hosts.length} host
                {analysis.hosts.length === 1 ? "" : "s"}
                {analysis.router_ip ? ` · gateway ${analysis.router_ip}` : ""}
              </p>
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
                      <td className="font-mono text-2xs text-fg-dim" title={finding.detail}>
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
              <p className="px-3 pb-1 pt-3 text-2xs font-semibold text-fg-muted">
                Unified host inventory
              </p>
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
                      <td className="font-mono text-2xs text-fg-dim">
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
          )}
        </section>
      )}

      {mode === "live" && (
        <section aria-label="Live monitor" className="flex min-h-0 flex-1 flex-col">
          {liveError ? <ErrorStrip>{liveError}</ErrorStrip> : null}
          {!displayTimeline ? (
            <ModeCard
              title="Live monitor"
              icon={Radar}
              state={liveState}
              stateTone={liveStateTone}
              info="Subscribe to Packet Studio's running capture — the lab transmits nothing; Packet Studio owns the capture lifecycle."
            >
              <div className="flex flex-wrap items-center gap-3">{liveControls}</div>
            </ModeCard>
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto pb-4">
              <TimelineTable wire={displayTimeline} />
            </div>
          )}
        </section>
      )}

      {mode === "dns" && (
        <section aria-label="DNS monitor (passive)" className="flex min-h-0 flex-1 flex-col">
          {dnsError ? <ErrorStrip>{dnsError}</ErrorStrip> : null}
          {!dnsResult ? (
            <ModeCard
              title="DNS monitor"
              icon={Globe}
              state={dnsState}
              stateTone={dnsStateTone}
              info="Passive DNS-response monitoring over the opened capture — read-only, the lab transmits nothing."
            >
              <div className="flex flex-wrap items-center gap-3">{dnsControls}</div>
            </ModeCard>
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto pb-4">
              <DnsFindingsTable wire={dnsResult} />
            </div>
          )}
        </section>
      )}

      {mode === "wifi" && (
        <section aria-label="Wifi monitor" className="flex min-h-0 flex-1 flex-col">
          {wifiError ? <ErrorStrip>{wifiError}</ErrorStrip> : null}
          <ModeCard
            title="Wifi monitor"
            icon={Wifi}
            state={
              wifiStatus
                ? wifiPhase
                : wifiInterfaces && !wifiInterfaces.monitor_supported
                  ? "unsupported here"
                  : "not running"
            }
            stateTone={
              wifiPhase === "monitoring"
                ? "orange"
                : wifiPhase === "stopped"
                  ? wifiStatus?.last_error
                    ? "err"
                    : "ok"
                  : wifiPhase === "stopping" || wifiPhase === "starting"
                    ? "orange"
                    : "muted"
            }
            info="Authorized monitor-mode 802.11 capture on Linux — passive receive-only, native dialog on start, EAPOL handshakes formatted as hashcat 22000 evidence."
          >
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-medium uppercase tracking-wider text-fg-muted">Wifi monitor</span>
              <Select
                value={wifiInterface}
                onChange={setWifiInterface}
                options={[
                  { value: "", label: "Choose wifi interface" },
                  ...(wifiInterfaces?.interfaces ?? []).map((iface) => ({
                    value: iface.name,
                    label: iface.name,
                  })),
                ]}
                ariaLabel="Wifi monitor wireless interface"
                className="w-44"
              />
              <TextInput
                value={wifiChannels}
                onChange={(text) => setWifiChannels(text.replace(/[^0-9,\s]/g, "").slice(0, 64))}
                placeholder="channels (1,6,11)"
                ariaLabel="Capture channels: 2.4/5 GHz channel numbers or explicit MHz frequencies, at most 16, comma separated"
                className="h-8 w-44 sm:h-7"
              />
              {wifiActive ? (
                <ToolButton
                  tone="danger"
                  onClick={() => void stopWifi()}
                  title="Stop the authorized monitor capture: the backend clears the stop flag before every read, so the pump exits at its next read boundary and the final counters stay pollable"
                >
                  Stop capture
                </ToolButton>
              ) : (
                <ToolButton
                  tone="primary"
                  onClick={() => void runWifiStart()}
                  disabled={
                    !desktop ||
                    !wifiInterface ||
                    parseWifiChannels(wifiChannels) === null ||
                    wifiBlock !== null ||
                    wifiBusy
                  }
                  title="Linux only: switches the selected interface to monitor mode over nl80211 and passively reads 802.11 frames for WPA handshake evidence (hashcat 22000 format); a native Yes/No dialog names exactly what will happen, nothing is transmitted, capture pins the first listed channel — no channel hopping is automated in this arc"
                >
                  {wifiBusy ? "starting…" : "Start capture"}
                </ToolButton>
              )}
              {wifiBlock ? <Chip tone="muted">{wifiBlock}</Chip> : null}
            </div>
            <p className="text-xs leading-relaxed text-fg-muted">
              {wifiPlatformNote(wifiInterfaces)}
            </p>
            {wifiStatus ? (
              <div className="space-y-2">
                <p className="font-mono text-2xs text-fg-muted">
                  interface {wifiStatus.interface || "unknown"} · pinned{" "}
                  {wifiStatus.channel_mhz || "—"} MHz of{" "}
                  {wifiStatus.channels.join(", ") || "none"} · no channel hopping is automated in
                  this arc
                </p>
                <div className="max-h-64 overflow-auto rounded-lg border border-line">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th className="w-24">Frames</th>
                        <th className="w-24">Beacons</th>
                        <th className="w-24">Clients</th>
                        <th className="w-32">Handshakes</th>
                        <th className="w-24">Elapsed</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>{wifiStatus.frames_seen}</td>
                        <td>{wifiStatus.beacons}</td>
                        <td>{wifiStatus.clients_seen}</td>
                        <td>
                          <Chip
                            tone={
                              wifiStatus.handshakes_captured > 0 ? "orange" : "muted"
                            }
                          >
                            {wifiStatus.handshakes_captured}
                          </Chip>
                        </td>
                        <td>
                          {wifiStatus ? `${(wifiStatus.elapsed_ms / 1000).toFixed(1)} s` : "0.0 s"}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                {wifiStatus.access_points.length > 0 ? (
                  <div className="max-h-48 overflow-auto rounded-lg border border-line">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th className="w-40">AP BSSID</th>
                          <th>ESSID</th>
                        </tr>
                      </thead>
                      <tbody>
                        {wifiStatus.access_points.map((ap) => (
                          <tr key={ap.bssid}>
                            <td className="font-mono text-fg">{ap.bssid}</td>
                            <td className="font-mono text-fg-dim">{ap.essid || "(hidden)"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {wifiStatus.hashcat_22000_lines.length > 0 ? (
                  <div className="space-y-1">
                    <p className="text-2xs font-semibold text-fg-muted">
                      Hashcat 22000 evidence ({wifiStatus.hashcat_22000_lines.length} line
                      {wifiStatus.hashcat_22000_lines.length === 1 ? "" : "s"})
                    </p>
                    <div className="max-h-40 overflow-auto rounded-lg border border-line bg-black/20 p-2">
                      {wifiStatus.hashcat_22000_lines.map((line, index) => (
                        <p key={`${index}-${line.slice(0, 24)}`} className="font-mono text-2xs break-all text-fg-dim">
                          {line}
                        </p>
                      ))}
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                      <ToolButton
                        tone="primary"
                        disabled={!desktop || wifiBusy || wifiSaved}
                        title={
                          wifiSaved
                            ? "This capture session already saved its one bounded evidence finding — start a new session to capture more"
                            : "Persist the session's hashcat 22000 lines as ONE bounded case finding in the backend-selected saved case"
                        }
                        onClick={() => void runWifiEvidenceSave()}
                      >
                        {wifiReceipt ? "saved" : wifiBusy ? "saving…" : "Save to case"}
                      </ToolButton>
                      {wifiReceipt ? (
                        <Chip tone={wifiReceipt.truncated ? "orange" : "ok"}>
                          saved to {wifiReceipt.case_id} · {wifiReceipt.line_count} line
                          {wifiReceipt.line_count === 1 ? "" : "s"} · {wifiReceipt.byte_len} bytes
                          {wifiReceipt.truncated ? " · truncated at the 32 KiB bound" : ""}
                        </Chip>
                      ) : null}
                      <InfoTip text="One bounded artifact per capture session: the backend renders a session header plus the hashcat 22000 lines and persists them as ONE case finding; a second save refuses honestly instead of duplicating case evidence." />
                    </div>
                  </div>
                ) : null}
                {wifiPhase === "stopped" && wifiStatus.last_error ? (
                  <p className="text-xs text-fg-muted">last error: {wifiStatus.last_error}</p>
                ) : null}
              </div>
            ) : null}
          </ModeCard>
        </section>
      )}

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
                            ? `${(dnsSpoofStatus.elapsed_ms / 1000).toFixed(1)} s`
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
                        <tr key={`${entry.timestamp_ms}-${entry.client}-${index}`}>
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
      {mode === "http_proxy" && (
        <section aria-label="HTTP proxy" className="flex min-h-0 flex-1 flex-col">
          {proxyError ? <ErrorStrip>{proxyError}</ErrorStrip> : null}
          <ModeCard
            title="HTTP proxy"
            icon={ArrowLeftRight}
            state={proxyStatus ? proxyPhase : "not running"}
            stateTone={
              proxyPhase === "serving"
                ? "orange"
                : proxyPhase === "stopped"
                  ? proxyStatus?.last_error
                    ? "err"
                    : "ok"
                  : proxyPhase === "starting" || proxyPhase === "stopping"
                    ? "orange"
                    : "muted"
            }
            info="Gated plain-HTTP forward proxy — every request logged (headers + 4 KiB excerpt), rewrite rules off by default; CONNECT is refused (TLS interception lives in the Web studio)."
          >
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-medium uppercase tracking-wider text-fg-muted">HTTP proxy</span>
              <TextInput
                value={proxyPort}
                onChange={(text) => setProxyPort(text.replace(/[^0-9]/g, "").slice(0, 5))}
                placeholder="port (8080)"
                ariaLabel="Proxy listen port (1024-65535, default 8080)"
                className="h-8 w-24 sm:h-7"
              />
              <CheckBox checked={proxyRewriteHttps} onChange={setProxyRewriteHttps}>
                <span>rewrite https:// links to http:// in HTML bodies (sslstrip-lite)</span>
              </CheckBox>
              <CheckBox checked={proxyStripHsts} onChange={setProxyStripHsts}>
                <span>strip Strict-Transport-Security response headers</span>
              </CheckBox>
              <CheckBox checked={proxyStripCsp} onChange={setProxyStripCsp}>
                <span>strip Content-Security-Policy response headers</span>
              </CheckBox>
              <TextInput
                value={proxyAllowlist}
                onChange={(text) => setProxyAllowlist(text.replace(/[^0-9.,\s]/g, "").slice(0, 200))}
                placeholder="allowlist IPs (empty = any client)"
                ariaLabel="Client allowlist: comma-separated IPs, at most 16; empty means any LAN client may use the proxy"
                className="h-8 w-52 sm:h-7"
              />
              {proxyActive ? (
                <ToolButton
                  tone="danger"
                  onClick={() => void stopProxy()}
                  title="Stop the authorized proxy: the backend ends the accept loop within ~20 ms, bounded in-flight connections drain, and the final counters and request log stay readable"
                >
                  Stop proxy
                </ToolButton>
              ) : (
                <ToolButton
                  tone="primary"
                  onClick={() => void runProxyStart()}
                  disabled={
                    !desktop ||
                    parseProxyPort(proxyPort) === null ||
                    parseProxyAllowlist(proxyAllowlist) === null ||
                    proxyBusy
                  }
                  title="Starts on 0.0.0.0 after a native Yes/No dialog naming the port, the logging (full request and response headers + 4 KiB excerpt), the active rewrites and the allowlist disclosure; CONNECT is refused: TLS interception lives in the Web studio — this proxy is plain HTTP; hard 30-minute runtime cap"
                >
                  {proxyBusy ? "starting…" : "Start proxy"}
                </ToolButton>
              )}
            </div>
            {proxyStart ? (
              <div className="space-y-2">
                <p className="font-mono text-2xs text-fg-muted">
                  port {proxyStart.port} · rules: {proxyStart.active_rules.join("; ") || "none — all OFF by default"} · allowlist {proxyStart.allowlist_count} · runtime cap {proxyStart.runtime_cap_minutes} min
                </p>
                <div className="max-h-40 overflow-auto rounded-lg border border-line">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Requests</th>
                        <th>Connections</th>
                        <th>CONNECT refusals</th>
                        <th>Busy refusals</th>
                        <th>Elapsed</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>{proxyStatus?.requests ?? 0}</td>
                        <td>{proxyStatus?.connections ?? 0}</td>
                        <td>{proxyStatus?.connect_refusals ?? 0}</td>
                        <td>{proxyStatus?.refused_busy ?? 0}</td>
                        <td>{proxyStatus ? `${(proxyStatus.elapsed_ms / 1000).toFixed(1)} s` : "0.0 s"}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <div className="max-h-64 overflow-auto rounded-lg border border-line">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th className="w-24">Time</th>
                        <th className="w-24">Client</th>
                        <th className="w-32">Host</th>
                        <th>Path</th>
                        <th className="w-16">Status</th>
                        <th className="w-40">Rewrites</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(proxyStatus?.log ?? []).map((entry, index) => (
                        <tr key={`${entry.ts_ms}-${index}`}>
                          <td className="font-mono text-2xs">{formatSeenMs(entry.ts_ms)}</td>
                          <td
                            className="font-mono text-2xs"
                            title={`${entry.request_headers}\n---\n${entry.response_headers}`}
                          >
                            {entry.client}
                          </td>
                          <td className="font-mono text-2xs">{entry.host}</td>
                          <td className="font-mono text-2xs text-fg-dim">{entry.path}</td>
                          <td>{entry.status}</td>
                          <td>
                            <Chip
                              tone={
                                entry.rewrites_https_links +
                                  entry.rewrites_hsts_stripped +
                                  entry.rewrites_csp_stripped >
                                0
                                  ? "orange"
                                  : "muted"
                              }
                            >
                              {`h2h ${entry.rewrites_https_links} · hsts ${entry.rewrites_hsts_stripped} · csp ${entry.rewrites_csp_stripped}`}
                            </Chip>
                          </td>
                        </tr>
                      ))}
                      {(proxyStatus?.log ?? []).length === 0 ? (
                        <tr>
                          <td colSpan={6} className="text-center text-fg-muted">
                            no proxied requests yet — the bounded 512-entry log fills as clients use the proxy
                          </td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
                {proxyStatus?.runtime_capped ? (
                  <p className="text-xs text-fg-muted">run ended at the 30-minute runtime cap</p>
                ) : null}
                {proxyStatus?.last_error ? (
                  <p className="text-xs text-fg-muted">last error: {proxyStatus.last_error}</p>
                ) : null}
                <div className="flex flex-wrap items-center gap-3">
                  <ToolButton
                    tone="primary"
                    disabled={!desktop || proxyBusy || proxySaved}
                    title={
                      proxySaved
                        ? "This proxy session already saved its one bounded evidence finding — start a new session to log more"
                        : "Persist the session's request log as ONE bounded case finding in the backend-selected saved case"
                    }
                    onClick={() => void runProxyEvidenceSave()}
                  >
                    {proxyReceipt ? "saved" : proxyBusy ? "saving…" : "Save to case"}
                  </ToolButton>
                  {proxyReceipt ? (
                    <Chip tone={proxyReceipt.truncated ? "orange" : "ok"}>
                      saved to {proxyReceipt.case_id} · {proxyReceipt.entry_count} request
                      {proxyReceipt.entry_count === 1 ? "" : "s"} · {proxyReceipt.byte_len} bytes
                      {proxyReceipt.truncated ? " · truncated at the 32 KiB bound" : ""}
                    </Chip>
                  ) : null}
                  <InfoTip text="One bounded artifact per proxy session: the backend renders a session header plus one line per logged request and persists it as ONE case finding under network.http_proxy; a second save refuses honestly instead of duplicating case evidence." />
                </div>
              </div>
            ) : null}
          </ModeCard>
        </section>
      )}
      {mode === "report" && (
        <section aria-label="Session report" className="flex min-h-0 flex-1 flex-col">
          {/* lab-report-ui.test.mjs pins the role="group" label, the muted
              uppercase span and the border-t wrapper verbatim — keep them
              INSIDE the shared ModeCard (the mode rail moved up to the
              WorkspaceShell rail slot, so the group no longer repeats it). */}
          <ModeCard
            title="Session report"
            icon={FileText}
            state={reportReceipt ? "exported" : "no report yet"}
            stateTone={reportReceipt ? "ok" : "muted"}
          >
            <div
              role="group"
              aria-label="Export lab session report"
              className="flex flex-wrap items-center gap-3 border-t border-line pt-3"
            >
              <span className="font-medium uppercase tracking-wider text-fg-muted">Session report</span>
              <ToolButton
                tone="primary"
                disabled={!desktop || !capture || reportBusy}
                title={
                  capture
                    ? "Export session report — render one bounded lab session report (ARP findings, event timeline, host inventory, DNS findings) and persist it as a single case finding in the selected saved case"
                    : "Open a capture first — the session report reduces the opened capture"
                }
                onClick={() => void runReportExport()}
              >
                {reportBusy ? "exporting…" : "Export"}
              </ToolButton>
              <CheckBox checked={reportIncludeDns} onChange={setReportIncludeDns}>
                <span>include DNS findings</span>
              </CheckBox>
              <ReportReceiptChip receipt={reportReceipt} />
              <InfoTip text="One structured artifact (ARP findings, event timeline, host inventory, DNS findings) rendered to bounded markdown and persisted as ONE case finding in the backend-selected saved case. Read-only over the capture; the frontend only ever receives a receipt." />
            </div>
            {reportError ? <ErrorStrip>{reportError}</ErrorStrip> : null}
            <p className="text-xs leading-relaxed text-fg-muted">
              Export the opened capture as one case finding.
            </p>
          </ModeCard>
        </section>
      )}

      {mode === "spoof" && (
        <section aria-label="ARP spoof" className="flex min-h-0 flex-1 flex-col">
          {spoofError ? <ErrorStrip>{spoofError}</ErrorStrip> : null}
          <ModeCard
            title="ARP spoof"
            icon={Syringe}
            state={spoofStatus ? spoofPhase : "not running"}
            stateTone={
              spoofPhase === "spoofing"
                ? "orange"
                : spoofPhase === "stopped"
                  ? spoofStatus?.last_error
                    ? "err"
                    : "ok"
                  : "muted"
            }
            info="Authorized full-duplex ARP cache poisoning against the saved lab scope only — native dialog on start, rate-limited, auto-restores real MACs on stop."
          >
            <div className="grid gap-3 md:grid-cols-2">
              <label className="block text-xs text-fg-dim">
                <span className="mb-1 block font-medium text-fg-muted">Gateway (from saved scope)</span>
                <Select
                  value={spoofGateway}
                  onChange={setSpoofGateway}
                  options={[
                    { value: "", label: "Choose gateway from scope" },
                    ...spoofGatewayCandidates(scope).map((ip) => ({ value: ip, label: ip })),
                  ]}
                  ariaLabel="Gateway IPv4 chosen from the saved lab scope"
                  className="w-44"
                />
              </label>
              <div className="text-xs text-fg-dim">
                <span className="mb-1 block font-medium text-fg-muted">Saved scope (read-only)</span>
                <p className="font-mono text-2xs leading-relaxed text-fg-muted">
                  {scopeSummary(scope)}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
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
                ariaLabel="ARP spoof Ethernet interface"
                className="w-44"
              />
              <TextInput
                value={spoofTargetCount}
                onChange={(text) => setSpoofTargetCount(text.replace(/[^0-9]/g, "").slice(0, 2))}
                placeholder="targets"
                ariaLabel="Targets to poison: first N IPv4 hosts resolved from the saved scope (1-32)"
                className="h-8 w-24 sm:h-7"
              />
              <TextInput
                value={spoofRate}
                onChange={(text) => setSpoofRate(text.replace(/[^0-9]/g, "").slice(0, 2))}
                placeholder="rounds/s"
                ariaLabel="Spoof rounds per second (1-10, default 1)"
                className="h-8 w-24 sm:h-7"
              />
              {spoofActive ? (
                <ToolButton
                  tone="danger"
                  onClick={() => void stopSpoof()}
                  title="Stop the authorized spoof: the backend ends poisoning and runs the restoration pass (real MACs re-announced both ways, unknowns reported) before publishing the result"
                >
                  Stop spoof
                </ToolButton>
              ) : (
                <ToolButton
                  tone="primary"
                  onClick={() => void runSpoofStart()}
                  disabled={
                    !desktop ||
                    !sweepInterface ||
                    spoofBlock !== null ||
                    !spoofGateway ||
                    parseSpoofRate(spoofRate) === null ||
                    parseSpoofTargetCount(spoofTargetCount) === null ||
                    spoofBusy
                  }
                  title="Linux only: unsolicited ARP replies claim the gateway's IPv4 with this machine's MAC toward the selected scope targets, and each target's IPv4 toward the gateway; a native Yes/No dialog names exactly what will be sent, the backend refuses anything outside the saved lab scope, 1-10 rounds/s, max 32 pairs, 30-minute hard runtime cap, restoration pass on stop"
                >
                  {spoofBusy ? "starting…" : "Start spoof"}
                </ToolButton>
              )}
              {spoofBlock ? <Chip tone="muted">{spoofBlock}</Chip> : null}
            </div>
            {spoofStart ? (
              <div className="space-y-2">
                <p className="font-mono text-2xs text-fg-muted">
                  gateway {spoofStart.gateway} · {spoofStart.rate_per_sec} round(s)/s · runtime
                  cap {spoofStart.runtime_cap_minutes} min
                </p>
                <p className="font-mono text-2xs text-fg-muted">
                  targets: {spoofStart.targets.join(", ") || "none resolved"}
                </p>
                <div className="max-h-64 overflow-auto rounded-lg border border-line">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th className="w-24">Pairs</th>
                        <th className="w-32">Frames sent</th>
                        <th className="w-24">Elapsed</th>
                        <th className="w-32">Restored</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>{spoofStatus?.pairs ?? 0}</td>
                        <td>{spoofStatus?.packets_sent ?? 0}</td>
                        <td>{spoofStatus ? `${(spoofStatus.elapsed_ms / 1000).toFixed(1)} s` : "0.0 s"}</td>
                        <td>{spoofStatus?.restored_targets ?? 0}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                {spoofPhase === "stopped" ? (
                  <p className="text-xs text-fg-muted">
                    {spoofStatus?.restoration_note ?? "restoration summary unavailable"} — the
                    spoof's own replies also appear as ARP conflicts in the lab timeline
                  </p>
                ) : null}
                {spoofStatus?.last_error ? (
                  <p className="text-xs text-fg-muted">last error: {spoofStatus.last_error}</p>
                ) : null}
              </div>
            ) : null}
          </ModeCard>
        </section>
      )}
    </WorkspaceShell>
  );
}

/**
 * Pinned IPv4 scope entries usable as spoof gateway candidates. CIDR and
 * IPv6 entries are excluded client-side only as a convenience — the backend
 * re-validates the gateway against the parsed scope either way.
 */
export function spoofGatewayCandidates(scope: NetworkLabScopeWire | null): string[] {
  if (!scope || !scope.authorized) return [];
  return [...scope.targets_t1, ...scope.targets_t2]
    .map((entry) => entry.trim())
    .filter((entry) => /^\d{1,3}(\.\d{1,3}){3}$/.test(entry));
}

/** Pure UI gate mirroring the backend's scope + gateway requirements. */
export function spoofBlockReason(scope: NetworkLabScopeWire | null): string | null {
  if (!scope || !scope.authorized) {
    return "No lab scope is set — set Target 1 / Target 2 first";
  }
  if (spoofGatewayCandidates(scope).length === 0) {
    return "The lab scope has no pinned IPv4 entry to use as the gateway — add an IPv4 address entry";
  }
  return null;
}

/** Parse the rounds-per-second input; null = not a usable rate (1-10). */
export function parseSpoofRate(text: string): number | null {
  const value = Number(text);
  if (!Number.isInteger(value) || value < 1 || value > 10) return null;
  return value;
}

/** Parse the target-count input; null = not a usable count (1-32). */
export function parseSpoofTargetCount(text: string): number | null {
  const value = Number(text);
  if (!Number.isInteger(value) || value < 1 || value > 32) return null;
  return value;
}

/**
 * Client-side mirror of the backend channel list bound: numeric tokens split
 * on commas/whitespace, at most 16, at least one. Channel numbers and explicit
 * MHz frequencies are both accepted here; the backend re-validates every
 * token and resolves the actual capture frequencies.
 */
export function parseWifiChannels(text: string): number[] | null {
  const tokens = text
    .split(/[,\s]+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
  if (tokens.length === 0 || tokens.length > 16) return null;
  const channels: number[] = [];
  for (const token of tokens) {
    if (!/^\d{1,5}$/.test(token)) return null;
    const value = Number(token);
    if (!Number.isInteger(value) || value < 1) return null;
    channels.push(value);
  }
  return channels;
}

/**
 * Pure UI gate mirroring the backend's platform honesty: monitor mode is
 * Linux-only this arc; Windows Npcap presence is reported but never treated
 * as support; a machine without a wireless interface refuses too.
 */
export function wifiPlatformBlock(wire: WifiInterfacesWire | null): string | null {
  if (!wire) {
    return "Wifi platform status unknown — the backend interface probe has not answered";
  }
  if (!wire.monitor_supported) {
    if (wire.npcap_detected) {
      return "Monitor mode requires Linux — Npcap detected, but no Windows monitor-mode control is wired in this arc";
    }
    return "Monitor mode requires Linux — monitor-mode capture is unsupported on this platform";
  }
  if (wire.interfaces.length === 0) {
    return "No wireless interface found on this machine — monitor capture needs a wifi NIC";
  }
  return null;
}

/** The backend's honest per-platform status note, rendered verbatim. */
export function wifiPlatformNote(wire: WifiInterfacesWire | null): string {
  if (!wire) {
    return "Wifi platform status unknown — the backend interface probe has not answered yet.";
  }
  return wire.platform_status;
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
 * cap. Empty until a source has data — the toolbar chip carries the
 * "no timeline" state instead of a stray chip row.
 */
/** Port parse for the lab HTTP proxy: integer 1024-65535, else null. */
export function parseProxyPort(text: string): number | null {
  const value = Number(text);
  if (!Number.isInteger(value) || value < 1024 || value > 65535) return null;
  return value;
}

/** Allowlist parse: comma/space separated IPv4 literals, at most 16, else null. */
export function parseProxyAllowlist(text: string): string[] | null {
  const tokens = text
    .split(/[,\s]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
  if (tokens.length > 16) return null;
  if (tokens.some((t) => !/^\d{1,3}(\.\d{1,3}){3}$/.test(t))) return null;
  return tokens;
}

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
      <td className="font-mono text-2xs">{formatSeenMs(event.timestamp_ms)}</td>
      <td>
        <Chip tone={event.kind === "arp_conflict" || event.kind === "gateway_changed" ? "err" : "muted"}>
          {labEventKindLabel(event.kind)}
        </Chip>
      </td>
      <td className="font-mono text-2xs">{event.subject}</td>
      <td className="text-fg-muted">{event.detail}</td>
    </tr>
  );
}

/**
 * Count items for the passive DNS monitor's StatusStrip; honest about the
 * 128-finding cap. Empty until a run exists — the toolbar chip carries the
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
              <td className="font-mono text-2xs">
                {finding.question_name} · {questionTypeLabel(finding.question_type)}
              </td>
              <td className="font-mono text-2xs text-fg-dim" title={formatAnswerSet(finding.baseline)}>
                {formatAnswerSet(finding.baseline)}
              </td>
              <td className="font-mono text-2xs text-fg-dim" title={formatAnswerSet(finding.later)}>
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

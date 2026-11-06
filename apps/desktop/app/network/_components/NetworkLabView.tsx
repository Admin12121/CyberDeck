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
import { Chip, EmptyState, Pane, TextInput, ToolButton } from "@ds/panes";
import {
  isDesktop,
  networkLabEventsV1,
  pcapOpenDialog,
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
    setOpening(false);
    setAnalyzing(false);
    setOpenError(null);
    setAnalysisError(null);
    // A case switch revokes the capture session's ownership on the backend,
    // so the live subscription is meaningless: stop polling and drop the
    // stale status instead of letting it render against the new revision.
    setLivePolling(false);
    setLiveStatus(null);
    setLiveError(null);
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

  return (
    <div className="h-full min-h-0 overflow-y-auto bg-app p-3">
      <div className="mx-auto flex max-w-5xl flex-col gap-px bg-line">
        <Pane
          title="Network Lab · passive analysis"
          actions={<Chip tone="ok">passive observations only</Chip>}
        >
          <div className="space-y-2 p-3 text-xs leading-relaxed text-fg-dim">
            <p>
              Ettercap-inspired lab mode inside Packet Studio: unified host inventory and passive
              ARP anomaly analysis over already-captured frames. The lab reads captures and never
              transmits packets; scope entries are IP/CIDR strings held in memory only and are never
              persisted (Master Plan §5.1).
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

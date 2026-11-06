"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronRight, CornerUpLeft, Download, FileDown, FolderOpen } from "lucide-react";
import { Chip, EmptyState, TextInput, ToolButton, WorkspaceTabs } from "@ds/panes";
import { IconButton } from "@ds/compact";
import { hexDump } from "@lib/hex";
import {
  isDesktop,
  pcapFollowStream,
  pcapOpenDialog,
  pcapPacketBytes,
  pcapOpenCaseV1,
  pcapCasePacketBytesV1,
  pcapCaseFollowStreamV1,
  captureOsHintsV1,
  type HexResponseWire,
  type OsHintsWire,
  type PcapOpenWire,
  type PcapPacketWire,
  type StreamTranscriptWire,
} from "@lib/ipc";
import { useWorkbench } from "@state/workbench";
import { useWorkspaceDraft } from "@state/workspace-sessions";
import {
  pcapExportViewNgV1,
  pcapExportViewV1,
  reassemblyBannerText,
  reassemblyOf,
  shortArtifactId,
  type PcapExportReceiptWire,
} from "./pcap-export-ipc";
import { LiveCaptureView } from "./LiveCaptureView";
import { PacketStartView } from "./PacketStartView";
import { PacketTable } from "./PacketTable";
import { PacketPaneSplit } from "./PacketPaneSplit";
import {
  PROTOCOL_COLORS,
  SAMPLE_PACKETS,
  conversationsOf,
  detailTree,
  endpointsOf,
  filterErrorOf,
  ioSeriesOf,
  matchesFilter,
  protocolHierarchy,
  protocolStats,
  sampleFrameBytes,
  type DetailNode,
  type HierarchyNode,
  type IoBucket,
} from "./model";

type DisplayPacket = PcapPacketWire & { sample?: boolean };

const SAMPLE_DISPLAY: DisplayPacket[] = SAMPLE_PACKETS.map((p, i) => ({
  index: i,
  time_ms: p.timeOffsetMs,
  source: p.source,
  destination: p.destination,
  protocol: p.protocol,
  length: p.length,
  info: p.info,
  color_hint: p.colorHint,
  stream_id: null,
  layers: [],
  sample: true,
}));

export function PacketStudioView() {
  return <ImportedCaptureView />;
}

function ImportedCaptureView() {
  const desktop = isDesktop();
  const wb = useWorkbench();
  const [capture, setCapture] = useState<PcapOpenWire | null>(null);
  const [savedArtifactId, setSavedArtifactId] = useState<string | null>(null);
  const [screen, setScreen] = useState<"welcome" | "offline" | "native">("welcome");
  const [showSample, setShowSample] = useState(false);
  const [openError, setOpenError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  // Export view -> case: receipt of the last successful backend export and
  // the dismissible reassembly banner visibility for the opened capture.
  const [exportResult, setExportResult] = useState<PcapExportReceiptWire | null>(null);
  const [exporting, setExporting] = useState(false);
  const [showReassembly, setShowReassembly] = useState(true);
  const [filter, setFilter] = useWorkspaceDraft(wb.caseId, "network", "packet-filter", "");
  const [packetScrollTop, setPacketScrollTop] = useState(0);
  const packetScrollRef = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState(0);
  const [tab, setTab] = useWorkspaceDraft<"packets" | "conversations" | "endpoints" | "hierarchy" | "io" | "statistics" | "streams" | "os-hints">(wb.caseId, "network", "packet-view", "packets");
  // Passive OS-family hints over the opened capture; per-run result state,
  // reset on case switch like every other capture-derived view state.
  const [osHints, setOsHints] = useState<OsHintsWire | null>(null);
  const [osHintsLoading, setOsHintsLoading] = useState(false);
  const [packetBytes, setPacketBytes] = useState<{ frameIndex: number; data: HexResponseWire } | null>(null);
  // null: details and bytes share the row evenly; dragging pins px.
  const [detailsWidth, setDetailsWidth] = useState<number | null>(null);
  const currentCase = useRef(wb.caseId);
  currentCase.current = wb.caseId;
  const openSequence = useRef(0);

  useEffect(() => {
    openSequence.current += 1;
    setCapture(null);
    setSavedArtifactId(null);
    setScreen("welcome");
    setShowSample(false);
    setSelected(0);
    setPacketBytes(null);
    setOpening(false);
    setOpenError(null);
    setExportResult(null);
    setShowReassembly(true);
    setOsHints(null);
    setOsHintsLoading(false);
  }, [wb.caseId]);

  // Mirrors ScanView: a case counts as saved-selected only when the native
  // session is ready for the workbench's current case id. Case artifact
  // exports are refused by the backend without one.
  const savedCaseReady = wb.caseSession.phase === "ready"
    && wb.caseSession.caseId === wb.caseId
    && wb.caseSession.revision !== null;

  const packets = capture?.packets ?? (showSample ? SAMPLE_DISPLAY : []);

  const openCapture = async () => {
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setOpening(true);
    setOpenError(null);
    try {
      const wire = await pcapOpenDialog();
      if (!isCurrent()) return;
      setCapture(wire);
      setSavedArtifactId(null);
      setScreen("offline");
      setShowSample(false);
      setSelected(0);
      setPacketBytes(null);
      setExportResult(null);
      setShowReassembly(true);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCurrent() && message !== "cancelled") setOpenError(message);
    } finally {
      if (isCurrent()) setOpening(false);
    }
  };


  const openSavedCase = async (artifactId: string) => {
    const caseId = wb.caseId;
    const ticket = ++openSequence.current;
    const isCurrent = () => currentCase.current === caseId && ticket === openSequence.current;
    setOpening(true);
    setOpenError(null);
    try {
      // Storage verifies same-descriptor SHA256, selected case revision and
      // original capture eligibility before any packet metadata is exposed.
      const wire = await pcapOpenCaseV1(artifactId);
      if (!isCurrent()) return;
      setSavedArtifactId(artifactId);
      setCapture(wire);
      setScreen("offline");
      setShowSample(false);
      setSelected(0);
      setPacketBytes(null);
      setExportResult(null);
      setShowReassembly(true);
    } catch (cause) {
      if (isCurrent()) setOpenError("Could not reopen verified case capture: " + String(cause));
    } finally {
      if (isCurrent()) setOpening(false);
    }
  };

  // Export the CURRENTLY FILTERED view back into the selected saved case.
  // The frontend only passes indices: the backend re-checks every index
  // against the opened capture cache, re-serializes the original frame bytes
  // as classic PCAP and commits them as an immutable case artifact through
  // the same path as a native capture save. No bytes or paths cross the UI.
  const exportView = async (format: "pcap" | "pcapng") => {
    if (!capture) return;
    setExporting(true);
    setOpenError(null);
    try {
      const indices = filtered.map((packet) => packet.index);
      const receipt = format === "pcapng"
        ? await pcapExportViewNgV1(indices)
        : await pcapExportViewV1(indices);
      setExportResult(receipt);
    } catch (cause) {
      setOpenError(
        "Export view → case failed: " + (cause instanceof Error ? cause.message : String(cause)),
      );
    } finally {
      setExporting(false);
    }
  };

  // §5.1: display-filter syntax is validated visibly. An invalid filter keeps
  // the unfiltered list on screen (Wireshark behavior) instead of emptying it
  // while the user is mid-edit.
  const filterProblem = useMemo(() => filterErrorOf(filter), [filter]);
  const filtered = useMemo(() => {
    const q = filter.trim();
    if (!q || filterProblem) return packets;
    return packets.filter((p) => matchesFilter(p, q));
  }, [packets, filter, filterProblem]);
  const endpoints = useMemo(() => endpointsOf(filtered), [filtered]);
  const hierarchy = useMemo(() => protocolHierarchy(filtered), [filtered]);
  const ioBuckets = useMemo(() => ioSeriesOf(filtered), [filtered]);
  const hierarchyBytes = useMemo(() => filtered.reduce((sum, item) => sum + item.length, 0), [filtered]);
  // Open-time fragment reassembly summary (additive wire field; null when the
  // capture held no fragment evidence worth surfacing).
  const reassembly = useMemo(() => (capture ? reassemblyOf(capture) : null), [capture]);

  const current = filtered.find((p) => p.index === selected) ?? filtered[0];
  // A bounded virtual window keeps large PCAPs responsive without dropping rows.
  const rowHeight = 26;
  const firstVisible = Math.max(0, Math.floor(packetScrollTop / rowHeight) - 16);
  const lastVisible = Math.min(filtered.length, firstVisible + 220);
  useEffect(() => {
    if (packetScrollRef.current) packetScrollRef.current.scrollTop = 0;
    setPacketScrollTop(0);
  }, [filter, capture, tab]);
  // Frame metadata, immutable capture bytes and Recipes handoff share one index.
  const currentIndex = current?.index ?? null;
  const currentBytes = packetBytes?.frameIndex === currentIndex ? packetBytes.data : null;
  useEffect(() => {
    if (!capture || currentIndex === null) return;
    let cancelled = false;
    const caseId = wb.caseId;
    setPacketBytes(null);
    (savedArtifactId ? pcapCasePacketBytesV1(savedArtifactId, currentIndex, 0, 512) : pcapPacketBytes(currentIndex, 0, 512))
      .then((data) => {
        if (!cancelled && currentCase.current === caseId) setPacketBytes({ frameIndex: currentIndex, data });
      })
      .catch((err) => {
        if (!cancelled && currentCase.current === caseId) {
          setOpenError("Could not inspect the selected frame: " + String(err));
        }
      });
    return () => { cancelled = true; };
  }, [capture, currentIndex, wb.caseId, savedArtifactId]);

  const sampleBytes = useMemo(
    () => (!capture && current ? sampleFrameBytes(current.index + 1, Math.min(current.length, 160)) : new Uint8Array()),
    [capture, current],
  );

  const inspectProtocol = (protocol: string) => {
    // Statistics are derived from actual dissected packet.protocol values.
    // The supported display-filter language accepts these protocol tokens.
    setFilter(protocol.toLowerCase());
    setTab("packets");
  };

  const timeLabel = (ms: number) => `${(ms / 1000).toFixed(6)}`;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className={screen === "offline" ? "hidden" : `flex min-h-0 flex-1 flex-col overflow-y-auto ${screen === "welcome" ? "bg-panel" : ""}`}>
        {screen === "welcome" && (
          <PacketStartView opening={opening} desktop={desktop}
            onOpen={() => void openCapture()}
            lastOpened={capture?.file_name ?? null}
            onResumeOpened={() => { if (capture) setScreen("offline"); }} />
        )}
        {screen === "welcome" && openError && (
          <p role="alert" className="mx-auto mb-3 w-full max-w-6xl px-6 text-xs text-err">{openError}</p>
        )}
        <div className={screen === "welcome" ? "mt-auto shrink-0 pt-2" : "min-h-0 flex-1"}>
          <LiveCaptureView presentation={screen === "welcome" ? "setup" : "full"}
            onCaptureStarted={() => setScreen("native")}
            onOpenSavedArtifact={(artifactId) => void openSavedCase(artifactId)}
            onOpenCaptureFile={() => void openCapture()}
            onReturnToStart={() => setScreen("welcome")} />
        </div>
      </div>
      <div className={screen === "offline" ? "flex min-h-0 flex-1 flex-col" : "hidden"}>
        <div className="cd-workspace-toolbar shrink-0 items-center gap-2 px-2">
        <IconButton icon={CornerUpLeft} onClick={() => setScreen("welcome")}
          title="Return to capture file and interface selection" />
        <IconButton icon={FolderOpen} onClick={() => void openCapture()} disabled={!desktop || opening}
          title={desktop ? "Open a PCAP or PCAPNG capture using the native Rust parser" : "Opening captures requires the desktop runtime"} />
        <IconButton icon={Download} onClick={() => void exportView("pcap")} disabled={!capture || exporting || !savedCaseReady}
          title={!capture
            ? "Export view → case (PCAP): open a capture first"
            : savedCaseReady
              ? "Export view → case (PCAP): persist the filtered packets as an immutable classic-PCAP case artifact"
              : "Export view → case (PCAP): select a saved case first"} />
        <IconButton icon={FileDown} onClick={() => void exportView("pcapng")} disabled={!capture || exporting || !savedCaseReady}
          title="Export view → case (PCAPNG): native writer, round-trips through the bundled reader" />
        {exportResult ? (
          <Chip tone="ok">
            {exportResult.packet_count} pkts → case · {shortArtifactId(exportResult.artifact_id)}
          </Chip>
        ) : null}

        <TextInput
          value={filter}
          onChange={setFilter}
          placeholder="display filter (tcp.port == 443)"
          ariaLabel="Display filter"
          className="min-w-0 flex-1"
        />
        {capture ? (
          <Chip tone="ok">{capture.file_name} · {capture.format.toUpperCase()} · {capture.packet_count} packets</Chip>
        ) : (
          <Chip>{showSample ? "DEMO: sample packets" : "No capture opened"}</Chip>
        )}
      </div>
      {openError ? (
        <div className="border-b border-err/50 bg-err/10 px-2 py-1 font-mono text-[10px] text-err">{openError}</div>
      ) : null}
      {filterProblem ? (
        <div className="border-b border-warn/40 bg-warn/10 px-2 py-1 font-mono text-[10px] text-warn" role="status" aria-label="Display filter syntax error">
          {"filter syntax: "}
          {filterProblem.message}
          {" · at character "}
          {filterProblem.position + 1}
        </div>
      ) : null}
      {capture?.malformed_tail ? (
        <div className="border-b border-warn/40 bg-warn/10 px-2 py-0.5 text-[10px] text-warn">
          malformed trailing record — earlier packets loaded
        </div>
      ) : null}
      {reassembly && showReassembly ? (
        <div
          className="flex items-center justify-between gap-2 border-b border-warn/40 bg-warn/10 px-2 py-1 font-mono text-[10px] text-warn"
          role="status"
          aria-label="Fragment reassembly summary"
        >
          <span className="truncate">{reassemblyBannerText(reassembly)}</span>
          <button
            type="button"
            className="shrink-0 px-1 font-mono text-[10px] text-warn hover:text-fg"
            aria-label="Dismiss reassembly summary"
            onClick={() => setShowReassembly(false)}
          >
            ×
          </button>
        </div>
      ) : null}

      <PacketPaneSplit
        list={        <div ref={packetScrollRef}
          onScroll={(event) => setPacketScrollTop(event.currentTarget.scrollTop)}
          className="h-full overflow-auto bg-panel">
          {tab === "packets" ? (
            <PacketTable
              rows={filtered.slice(firstVisible, lastVisible).map((p) => ({
                index: p.index, time: timeLabel(p.time_ms),
                source: p.source, destination: p.destination,
                protocol: p.protocol, length: p.length, info: p.info,
                protocolColor: PROTOCOL_COLORS[p.color_hint] ?? "text-fg-dim",
              }))}
              selectedIndex={current?.index ?? null}
              onSelect={setSelected}
              topSpacer={firstVisible * rowHeight}
              bottomSpacer={(filtered.length - lastVisible) * rowHeight}
              empty={showSample || capture ? "No packets match the display filter" : "No capture loaded"}
            />
          ) : tab === "conversations" ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Endpoint A</th>
                  <th>Endpoint B</th>
                  <th className="w-16">Packets</th>
                  <th className="w-24">Bytes</th>
                  <th>Protocols</th>
                </tr>
              </thead>
              <tbody>
                {conversationsOf(filtered).map((c) => (
                  <tr key={c.endpoints.join(" ")}>
                    <td className="text-fg">{c.endpoints[0]}</td>
                    <td className="text-fg">{c.endpoints[1]}</td>
                    <td>{c.packets}</td>
                    <td>{c.bytes}</td>
                    <td className="text-fg-muted">{c.protocols.join(", ")}</td>
                  </tr>
                ))}
                {conversationsOf(filtered).length === 0 ? (
                  <tr><td colSpan={5} className="text-center text-fg-muted">no conversations in the current view</td></tr>
                ) : null}
              </tbody>
            </table>
          ) : tab === "endpoints" ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Address</th>
                  <th className="w-24">Family</th>
                  <th className="w-16">Packets</th>
                  <th className="w-24">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((e) => (
                  <tr key={`${e.family}:${e.address}`}>
                    <td>
                      <button type="button"
                        className="w-full rounded-sm px-1 py-0.5 text-left font-mono text-[11px] hover:bg-selected focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring"
                        title={`Filter for address ${e.address}`}
                        aria-label={`Filter packets for address ${e.address}`}
                        onClick={() => {
                          if (e.family === "ip4") setFilter(`ip.addr == ${e.address}`);
                          else if (e.family === "ip6") setFilter(`ipv6.addr == ${e.address}`);
                          else setFilter(`eth.addr == ${e.address}`);
                          setTab("packets");
                        }}>
                        {e.address}
                      </button>
                    </td>
                    <td className="text-fg-muted">{e.family === "ip4" ? "IPv4" : e.family === "ip6" ? "IPv6" : "Ethernet"}</td>
                    <td>{e.packets}</td>
                    <td>{e.bytes}</td>
                  </tr>
                ))}
                {endpoints.length === 0 ? (
                  <tr><td colSpan={4} className="text-center text-fg-muted">no endpoints in the current view</td></tr>
                ) : null}
              </tbody>
            </table>
          ) : tab === "hierarchy" ? (
            <div className="p-1">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th className="w-16">Packets</th>
                    <th className="w-24">Bytes</th>
                    <th>Share of bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {hierarchy.map((node) => (
                    <HierarchyRows key={node.protocol} node={node} depth={0} totalBytes={hierarchyBytes} />
                  ))}
                  {hierarchy.length === 0 ? (
                    <tr><td colSpan={4} className="text-center text-fg-muted">no protocols in the current view</td></tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          ) : tab === "io" ? (
            <IoGraphView buckets={ioBuckets} />
          ) : tab === "statistics" ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-32">Protocol</th>
                  <th className="w-24">Packets</th>
                  <th className="w-28">Bytes</th>
                  <th>Share of bytes</th>
                </tr>
              </thead>
              <tbody>
                {protocolStats(filtered).map((stat) => {
                  const totalBytes = filtered.reduce((sum, item) => sum + item.length, 0) || 1;
                  return (
                    <tr key={stat.protocol}>
                      <td>
                        <button type="button"
                          className={`w-full rounded-sm px-1 py-0.5 text-left font-mono text-[11px] hover:bg-selected focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring ${PROTOCOL_COLORS[stat.protocol.toLowerCase()] ?? "text-fg-dim"}`}
                          title={`Filter packets by ${stat.protocol}`}
                          aria-label={`Show ${stat.protocol} packets`}
                          onClick={() => inspectProtocol(stat.protocol)}>
                          {stat.protocol}
                        </button>
                      </td>
                      <td>{stat.packets}</td>
                      <td>{stat.bytes}</td>
                      <td>
                        <div className="h-1.5 w-full max-w-48 border border-line bg-app">
                          <div className="h-full bg-orange" style={{ width: `${Math.round((stat.bytes / totalBytes) * 100)}%` }} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : tab === "os-hints" ? (
            <OsHintsView
              desktop={desktop}
              hints={osHints}
              loading={osHintsLoading}
              hasCapture={Boolean(capture)}
              onAnalyze={() => {
                setOsHintsLoading(true);
                captureOsHintsV1()
                  .then((wire) => setOsHints(wire))
                  .catch((cause) => setOpenError(
                    "OS hints analysis failed: "
                      + (cause instanceof Error ? cause.message : String(cause)),
                  ))
                  .finally(() => setOsHintsLoading(false));
              }}
            />
          ) : (
            <FollowStreamView packets={filtered} artifactId={savedArtifactId} />
          )}
        </div>
}
        detailTitle={`Packet details: ${current ? "frame " + (current.index + 1) : "no selection"}`}
        details={            <div className="min-h-0 flex-1 overflow-auto p-1">
              {current ? (
                capture ? (
                  current.layers.map((layer, i) => (
                    <DetailBranch key={i} node={{ label: layer.label, value: layer.value }} depth={0} />
                  ))
                ) : (
                  detailTree(SAMPLE_PACKETS[current.index]).map((node, i) => <DetailBranch key={i} node={node} depth={0} />)
                )
              ) : null}
            </div>}
        bytesTitle="Packet bytes (offset · hex · ASCII)"
        bytesActions={<ToolButton
  disabled={!capture || !current || !currentBytes || currentBytes.rows.length === 0}
  title="Transfer selected captured frame bytes to Recipes"
  onClick={() => {
    if (!capture || !current || !currentBytes) return;
    const hex = currentBytes.rows.map((row) => row.hex.replace(/[^0-9a-f]/gi, "")).join("");
    wb.sendToRecipes(hex, `${capture.file_name}: frame ${current.index + 1} (visible bytes)`,
      [{ opId: "from_hex", enabled: true }]);
  }}>Send to Recipes</ToolButton>}
        bytes={            <div className="min-h-0 flex-1 overflow-auto">
              {capture && currentBytes ? (
                <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
                  {currentBytes.rows.map((row) => (
                    <div key={row.offset}>
                      <span className="text-fg-muted">{row.offset.toString(16).padStart(4, "0")}</span>
                      {"  "}
                      {row.hex}
                      {"  "}
                      <span className="text-orange">{row.ascii}</span>
                    </div>
                  ))}
                </pre>
              ) : !capture ? (
                <pre className="p-1 font-mono text-[11px] leading-relaxed text-fg-dim">
                  {hexDump(sampleBytes).map((row) => (
                    <div key={row.offset}>
                      <span className="text-fg-muted">{row.offset.toString(16).padStart(4, "0")}</span>
                      {"  "}
                      {row.hex}
                      {"  "}
                      <span className="text-orange">{row.ascii}</span>
                    </div>
                  ))}
                </pre>
              ) : null}
            </div>}
      />
      <WorkspaceTabs items={["packets", "conversations", "endpoints", "hierarchy", "io", "statistics", "streams", "os-hints"] as const}
        active={tab} onChange={setTab} placement="bottom" ariaLabel="Packet investigation views" />
      </div>
    </div>
  );
}


// --------------------------------------------------------------- os hints ----

/**
 * Passive OS-family hints over TCP handshake segments of the opened capture.
 * Every row repeats the low-confidence contract: family hints come from a
 * handful of documented stack breakpoints, and "unknown" is the honest
 * majority case.
 */
function OsHintsView({ desktop, hints, loading, hasCapture, onAnalyze }: {
  desktop: boolean;
  hints: OsHintsWire | null;
  loading: boolean;
  hasCapture: boolean;
  onAnalyze: () => void;
}) {
  return (
    <div className="flex h-full min-h-0 flex-col p-2">
      <div className="mb-2 flex items-center gap-2">
        <ToolButton
          disabled={!desktop || !hasCapture || loading}
          title={hasCapture
            ? "Classify TCP handshake segments into coarse OS families (low-confidence hints only)"
            : "Open a capture first — hints analyze the currently opened capture"}
          onClick={onAnalyze}>
          {loading ? "analyzing…" : "Analyze OS hints (opened capture)"}
        </ToolButton>
        {hints ? (
          <Chip tone="ok">{hints.hints.length} of {hints.sampled} handshake segment(s) hinted</Chip>
        ) : (
          <Chip>no analysis yet</Chip>
        )}
      </div>
      <p className="mb-2 font-mono text-[10px] text-fg-muted">
        low-confidence hints from documented stack breakpoints (initial TTL, window scale, MSS,
        option order) — never verdicts, never versions; "unknown" is the expected result for
        hardened or uncommon stacks
      </p>
      {hints && hints.hints.length > 0 ? (
        <table className="data-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Destination</th>
              <th className="w-20">Segment</th>
              <th className="w-32">Family hint</th>
              <th className="w-24">Confidence</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {hints.hints.map((observation, index) => (
              <tr key={`${observation.source}-${observation.destination}-${index}`}>
                <td className="font-mono text-[11px]">{observation.source}</td>
                <td className="font-mono text-[11px]">{observation.destination}</td>
                <td>{observation.syn_ack ? <Chip>SYN/ACK</Chip> : <Chip>SYN</Chip>}</td>
                <td>
                  <Chip tone={observation.hint.family === "unknown" ? "muted" : "orange"}>
                    {observation.hint.family}
                  </Chip>
                </td>
                <td className="text-fg-muted">{observation.hint.confidence}</td>
                <td className="text-fg-muted">{observation.hint.evidence.join(" · ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : hints ? (
        <EmptyState
          title="No classifiable handshake segments"
          detail="The opened capture holds no TCP SYN or SYN/ACK frames with recoverable signature layers." />
      ) : (
        <EmptyState
          title="Not analyzed yet"
          detail="Run the analysis to classify handshake segments; the capture itself stays untouched." />
      )}
    </div>
  );
}

// ------------------------------------------------------ protocol hierarchy ---

/** One row per hierarchy node, indented by depth; children follow their parent. */
function HierarchyRows({ node, depth, totalBytes }: { node: HierarchyNode; depth: number; totalBytes: number }) {
  const share = totalBytes > 0 ? Math.round((node.bytes / totalBytes) * 100) : 0;
  return (
    <>
      <tr>
        <td>
          <span style={{ paddingLeft: depth * 14 }} className="font-mono text-[11px] text-fg">
            {depth > 0 ? "└ " : ""}{node.protocol}
          </span>
        </td>
        <td>{node.packets}</td>
        <td>{node.bytes}</td>
        <td>
          <div className="h-1.5 w-full max-w-48 border border-line bg-app">
            <div className="h-full bg-blue" style={{ width: `${share}%` }} />
          </div>
        </td>
      </tr>
      {node.children.map((child) => (
        <HierarchyRows key={`${node.protocol}/${child.protocol}`} node={child} depth={depth + 1} totalBytes={totalBytes} />
      ))}
    </>
  );
}

// --------------------------------------------------------------- io graph ----

/**
 * Time-bucketed packets-per-bucket bar chart over the current (filtered)
 * view. Pure CSS bars keep the Dark Matter palette; each bar carries a
 * tooltip with its window, packet count and byte volume.
 */
function IoGraphView({ buckets }: { buckets: IoBucket[] }) {
  if (buckets.length === 0) {
    return <EmptyState title="No packets to graph" detail="Open a capture or relax the display filter." />;
  }
  const maxPackets = Math.max(...buckets.map((b) => b.packets), 1);
  const span = Math.max(buckets[buckets.length - 1].fromMs - buckets[0].fromMs, 1);
  return (
    <div className="flex h-full min-h-0 flex-col p-2">
      <p className="mb-1 font-mono text-[10px] text-fg-muted">
        packets per bucket over {(span / 1000).toFixed(3)} s · peak {maxPackets} · total {buckets.reduce((s, b) => s + b.packets, 0)}
      </p>
      <div className="flex min-h-0 flex-1 items-end gap-px" role="img" aria-label="Packets per time bucket">
        {buckets.map((b, i) => (
          <div key={i}
            className="min-w-[2px] flex-1 bg-orange/80 hover:bg-orange"
            style={{ height: `${Math.max((b.packets / maxPackets) * 100, b.packets > 0 ? 3 : 0)}%` }}
            title={`t=+${(b.fromMs / 1000).toFixed(3)} s · ${b.packets} packets · ${b.bytes} bytes`} />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-fg-muted">
        <span>+{(buckets[0].fromMs / 1000).toFixed(3)} s</span>
        <span>+{((buckets[buckets.length - 1].fromMs + span / buckets.length) / 1000).toFixed(3)} s</span>
      </div>
    </div>
  );
}

function DetailBranch({ node, depth }: { node: DetailNode; depth: number }) {  const [open, setOpen] = useState(depth < 2);
  const hasChildren = Boolean(node.children?.length);
  return (
    <div style={{ paddingLeft: depth * 12 }}>
      <button
        type="button"
        onClick={() => hasChildren && setOpen((v) => !v)}
        className="flex w-full items-center gap-1 py-px text-left font-mono text-[11px] hover:bg-raised"
      >
        {hasChildren ? (
          <ChevronRight size={11} className={`shrink-0 text-fg-muted transition-transform ${open ? "rotate-90" : ""}`} />
        ) : (
          <span className="w-[11px] shrink-0" />
        )}
        <span className="text-fg">{node.label}</span>
        {node.value ? <span className="truncate text-fg-muted">: {node.value}</span> : null}
      </button>
      {open && hasChildren ? node.children!.map((child, i) => <DetailBranch key={i} node={child} depth={depth + 1} />) : null}
    </div>
  );
}

// ---------------------------------------------------------- follow stream ---

function FollowStreamView({ packets, artifactId }: { packets: DisplayPacket[]; artifactId?: string | null }) {
  const wb = useWorkbench();
  const desktop = isDesktop();
  const withStream = packets.filter((p) => p.stream_id);
  const [selected, setSelected] = useState<string | null>(null);
  const [transcript, setTranscript] = useState<StreamTranscriptWire | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);

  const sideHex = (dir: "A" | "B"): string => (transcript?.chunks ?? [])
    .filter((chunk) => chunk.dir === dir && (chunk.kind === "data" || chunk.kind === "datagram"))
    .map((chunk) => chunk.hex_data ?? "").join("");
  const canSend = (dir: "A" | "B"): boolean => {
    if (!transcript || transcript.gaps > 0 || transcript.truncated) return false;
    const hex = sideHex(dir);
    return hex.length > 0 && hex.length <= 256 * 1024;
  };
  const sendSide = (dir: "A" | "B") => {
    if (!canSend(dir) || !transcript || !selected) return;
    wb.sendToRecipes(
      sideHex(dir),
      "Captured packet stream " + selected + ", side " + dir + " (" + transcript.protocol + "; sequence ordered)",
      [{ opId: "from_hex", enabled: true }],
    );
  };
  const streams = useMemo(() => {
    const map = new Map<string, { id: string; label: string; packets: number }>();
    for (const p of withStream) {
      const entry = map.get(p.stream_id!);
      if (entry) entry.packets += 1;
      else map.set(p.stream_id!, { id: p.stream_id!, label: p.source + " <-> " + p.destination, packets: 1 });
    }
    return [...map.values()];
  }, [withStream]);

  useEffect(() => {
    setTranscript(null);
    setStreamError(null);
    if (!selected) return;
    let cancelled = false;
    (artifactId ? pcapCaseFollowStreamV1(artifactId, selected) : pcapFollowStream(selected))
      .then((data) => {
        if (!cancelled) setTranscript(data);
      })
      .catch((err) => {
        if (!cancelled) setStreamError(String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [selected, packets, artifactId]);

  if (!desktop) {
    return (
      <EmptyState title="Follow stream" detail="stream reassembly runs in the desktop runtime against opened captures" badge="follow stream" />
    );
  }
  if (streams.length === 0) {
    return (
      <EmptyState title="No TCP/UDP streams" detail="open a capture with TCP or UDP traffic; streams build from dissected ports" badge="follow stream" />
    );
  }
  return (
    <div className="flex h-full min-h-0">
      <div className="w-80 shrink-0 overflow-auto border-r border-line bg-sidebar p-1">
        {streams.map((stream) => (
          <button
            key={stream.id}
            type="button"
            onClick={() => setSelected(stream.id)}
            className={"block w-full truncate px-2 py-1 text-left font-mono text-[10px] " + (
              selected === stream.id ? "bg-orange-dim text-orange" : "text-fg-dim hover:bg-raised hover:text-fg"
            )}
          >
            {stream.label} · {stream.packets} pkt
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-2 font-mono text-[11px] leading-relaxed">
        {streamError ? (
          <div className="text-err">{streamError}</div>
        ) : transcript === null ? (
          <div className="text-fg-muted">select a stream…</div>
        ) : (
          <>
            <div className="mb-2 flex flex-wrap items-center gap-2 border-b border-line pb-2 text-fg-muted">
              <ToolButton onClick={() => sendSide("A")} disabled={!canSend("A")}
                title="Send side A into Recipes only if the capture has no missing sequences or truncation">
                A → Recipes
              </ToolButton>
              <ToolButton onClick={() => sendSide("B")} disabled={!canSend("B")}
                title="Send side B into Recipes only if the capture has no missing sequences or truncation">
                B → Recipes
              </ToolButton>
              {transcript.protocol} · {transcript.gaps} gap(s) · {transcript.retransmissions} retransmission(s)
              {transcript.truncated ? " · truncated at safe limits" : ""}
              {transcript.protocol === "TCP" ? " · sequence ordered per direction; not full TCP session tracking" : " · datagrams in capture order"}
            </div>
            {transcript.chunks.length === 0 ? (
              <div className="text-fg-muted">no payload bytes in this stream</div>
            ) : transcript.chunks.map((chunk, i) => (
              <div key={i} className={`whitespace-pre-wrap break-all ${chunk.kind === "gap" || chunk.kind === "notice" ? "my-1 text-warn" : ""}`}>
                <span className={chunk.dir === "A" ? "text-fg-dim" : "text-orange"}>[{chunk.dir}] </span>
                <span className={chunk.kind === "data" || chunk.kind === "datagram" ? "text-fg" : "text-warn"}>
                  {chunk.kind === "gap" ? "⚠ " : ""}{chunk.text}
                </span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

